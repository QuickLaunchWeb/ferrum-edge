//! Mesh runtime mode scaffolding.
//!
//! Phase C introduces the gated mesh data-plane mode. The runtime surface is
//! deliberately additive: existing gateway modes do not instantiate this module
//! unless `FERRUM_MODE=mesh`.

pub mod config_consumer;
pub mod hbone;
pub mod runtime;

use anyhow::Context as _;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::types::GatewayConfig;
use crate::config::{EnvConfig, MeshConfigSource};
use crate::dns::{DnsCache, DnsConfig};
use crate::proxy::{self, ProxyState};
use crate::startup::wait_for_start_signals;
use crate::tls::{self, TlsPolicy};

/// Run the mesh data-plane mode.
pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let runtime = runtime::MeshRuntimeConfig::from_env(&env_config);
    info!(
        topology = %runtime.topology,
        config_source = %runtime.config_source,
        inbound = %runtime.inbound_addr,
        outbound = %runtime.outbound_addr,
        hbone = ?runtime.hbone_addr,
        "Starting mesh runtime mode"
    );

    if runtime.config_source == MeshConfigSource::File {
        let path = env_config
            .file_config_path
            .as_deref()
            .context("FERRUM_FILE_CONFIG_PATH is required for file-backed mesh mode")?;
        let config = crate::config::file_loader::load_config_from_file(
            path,
            env_config.tls_cert_expiry_warning_days,
            &env_config.backend_allow_ips,
            &env_config.namespace,
        )?;
        if let Some(mesh) = config.mesh.as_ref() {
            let errors = mesh.validate();
            if !errors.is_empty() {
                return Err(anyhow::anyhow!(
                    "Mesh configuration validation failed: {}",
                    errors.join("; ")
                ));
            }
        }
        info!(
            proxies = config.proxies.len(),
            workloads = config.mesh.as_ref().map(|m| m.workloads.len()).unwrap_or(0),
            policies = config
                .mesh
                .as_ref()
                .map(|m| m.mesh_policies.len())
                .unwrap_or(0),
            "Loaded file-backed mesh config"
        );
        let config = runtime::prepare_gateway_config_for_mesh(config, &runtime)?;
        return serve(env_config, runtime, config, shutdown_tx).await;
    }

    let config = runtime::prepare_gateway_config_for_mesh(GatewayConfig::default(), &runtime)?;
    if let Some(cp_url) = env_config.resolved_dp_cp_grpc_urls().first().cloned() {
        match runtime.config_source {
            MeshConfigSource::Native => {
                let client_config = runtime.native_client_config(cp_url);
                info!(
                    node_id = %client_config.node_id,
                    namespace = %client_config.namespace,
                    "Prepared native MeshSubscribe consumer configuration"
                );
            }
            MeshConfigSource::Xds => {
                let client_config = runtime.xds_client_config(cp_url);
                info!(
                    node_id = %client_config.node_id,
                    namespace = %client_config.namespace,
                    "Prepared xDS consumer configuration"
                );
            }
            MeshConfigSource::File => {}
        }
    }
    info!(
        config_source = %runtime.config_source,
        "Mesh runtime started with an empty config; control-plane consumers will populate routes in later Phase C slices"
    );
    serve(env_config, runtime, config, shutdown_tx).await
}

async fn serve(
    env_config: EnvConfig,
    runtime: runtime::MeshRuntimeConfig,
    config: GatewayConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: env_config.dns_overrides.clone(),
        resolver_addresses: env_config.dns_resolver_address.clone(),
        hosts_file_path: env_config.dns_resolver_hosts_file.clone(),
        dns_order: env_config.dns_order.clone(),
        ttl_override_seconds: env_config.dns_ttl_override,
        min_ttl_seconds: env_config.dns_min_ttl,
        stale_ttl_seconds: env_config.dns_stale_ttl,
        error_ttl_seconds: env_config.dns_error_ttl,
        max_cache_size: env_config.dns_cache_max_size,
        warmup_concurrency: env_config.dns_warmup_concurrency,
        slow_threshold_ms: env_config.dns_slow_threshold_ms,
        refresh_threshold_percent: env_config.dns_refresh_threshold_percent,
        failed_retry_interval_seconds: env_config.dns_failed_retry_interval,
        try_tcp_on_error: env_config.dns_try_tcp_on_error,
        num_concurrent_reqs: env_config.dns_num_concurrent_reqs,
        max_active_requests: env_config.dns_max_active_requests,
        max_concurrent_refreshes: env_config.dns_max_concurrent_refreshes,
        backend_allow_ips: env_config.backend_allow_ips.clone(),
        shard_amount: env_config.pool_shard_amount,
    });

    let mut hostnames: Vec<_> = config
        .proxies
        .iter()
        .map(|p| {
            (
                p.backend_host.clone(),
                p.dns_override.clone(),
                p.dns_cache_ttl_seconds,
            )
        })
        .collect();
    for upstream in &config.upstreams {
        for target in &upstream.targets {
            hostnames.push((target.host.clone(), None, None));
        }
    }

    let tls_policy = TlsPolicy::from_env_config(&env_config)?;
    let crls = tls::load_crls(env_config.tls_crl_file_path.as_deref())?;
    let (proxy_state, health_check_handles) = ProxyState::new(
        config,
        dns_cache.clone(),
        env_config.clone(),
        Some(tls_policy.clone()),
        Some(shutdown_tx.subscribe()),
    )?;

    proxy_state
        .stream_listener_manager
        .set_global_shutdown_rx(shutdown_tx.subscribe());

    for host in proxy_state.plugin_cache.collect_warmup_hostnames() {
        hostnames.push((host, None, None));
    }
    dns_cache.warmup(hostnames).await;

    if env_config.pool_warmup_enabled {
        proxy_state.warmup_connection_pools().await;
    }
    proxy_state.start_backend_capability_refresh_task(
        !env_config.pool_warmup_enabled,
        Some(shutdown_tx.subscribe()),
    );
    proxy_state.start_service_discovery(Some(shutdown_tx.subscribe()));

    let dns_handle =
        dns_cache.start_background_refresh_with_shutdown(Some(shutdown_tx.subscribe()));
    let dns_retry_handle = dns_cache.start_failed_retry_task(Some(shutdown_tx.subscribe()));
    let per_ip_cleanup_handle =
        proxy_state.start_per_ip_cleanup_task(Some(shutdown_tx.subscribe()));
    let overload_handle = crate::overload::start_monitor(
        proxy_state.overload.clone(),
        env_config.overload_config(),
        env_config.max_connections,
        env_config.max_requests,
        shutdown_tx.subscribe(),
    );
    let metrics_handle = crate::metrics::start_metrics_monitor(
        proxy_state.request_count.clone(),
        proxy_state.status_counts.clone(),
        proxy_state.windowed_metrics.clone(),
        env_config.status_metrics_window_seconds,
        shutdown_tx.subscribe(),
    );

    let frontend_tls = load_frontend_tls(&env_config, &tls_policy, &crls)?;
    if let Some(ref tls_cfg) = frontend_tls {
        proxy_state
            .stream_listener_manager
            .set_frontend_tls_config(Some(tls_cfg.clone()))
            .await;
    }

    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    let mut startup_signals = Vec::new();
    for listener in runtime.listener_plan() {
        let tls_config = listener_tls_config(&listener, frontend_tls.clone());
        if tls_config.is_none()
            && matches!(
                listener.kind,
                runtime::MeshListenerKind::MtlsTermination | runtime::MeshListenerKind::HboneTunnel
            )
        {
            warn!(
                direction = ?listener.direction,
                addr = %listener.addr,
                "Mesh listener is running without frontend TLS because no mesh/frontend certificate is configured"
            );
        }
        let label = format!("{:?} mesh listener", listener.direction);
        let state = proxy_state.clone();
        let shutdown = shutdown_tx.subscribe();
        let addr = listener.addr;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            info!(
                direction = ?listener.direction,
                kind = ?listener.kind,
                addr = %addr,
                "Starting mesh listener"
            );
            if let Err(e) = proxy::start_proxy_listener_with_tls_and_signal(
                addr,
                state,
                shutdown,
                tls_config,
                Some(started_tx),
            )
            .await
            {
                error!(direction = ?listener.direction, addr = %addr, "Mesh listener error: {}", e);
            }
        });
        handles.push(handle);
        startup_signals.push((label, started_rx));
    }

    let startup_result: Result<(), anyhow::Error> = async {
        proxy_state.initial_reconcile_stream_listeners().await?;
        wait_for_start_signals(startup_signals, Duration::from_secs(10)).await?;
        proxy_state
            .stream_listener_manager
            .wait_until_started(Duration::from_secs(10))
            .await?;
        info!("Mesh runtime startup complete");
        Ok(())
    }
    .await;
    if let Err(e) = startup_result {
        warn!(
            "Mesh runtime startup failed after spawning tasks: {}; draining before returning",
            e
        );
        let _ = shutdown_tx.send(true);
        shutdown_and_join_mesh(
            proxy_state,
            handles,
            vec![dns_handle, overload_handle, metrics_handle],
            dns_retry_handle,
            per_ip_cleanup_handle,
            health_check_handles,
            env_config.shutdown_drain_seconds,
        )
        .await;
        return Err(e);
    }

    if handles.is_empty() {
        let mut shutdown_rx = shutdown_tx.subscribe();
        while !*shutdown_rx.borrow() {
            if shutdown_rx.changed().await.is_err() {
                break;
            }
        }
    } else {
        for handle in handles {
            handle.await?;
        }
    }

    shutdown_and_join_mesh(
        proxy_state,
        Vec::new(),
        vec![dns_handle, overload_handle, metrics_handle],
        dns_retry_handle,
        per_ip_cleanup_handle,
        health_check_handles,
        env_config.shutdown_drain_seconds,
    )
    .await;
    info!("Mesh runtime mode shutting down");
    Ok(())
}

fn load_frontend_tls(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &[rustls::pki_types::CertificateRevocationListDer<'static>],
) -> Result<Option<Arc<rustls::ServerConfig>>, anyhow::Error> {
    let (Some(cert_path), Some(key_path)) = (
        env_config.frontend_tls_cert_path.as_ref(),
        env_config.frontend_tls_key_path.as_ref(),
    ) else {
        return Ok(None);
    };

    let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.as_deref();
    let mut config = tls::load_tls_config_with_client_auth(
        cert_path,
        key_path,
        client_ca_bundle_path,
        env_config.tls_no_verify,
        tls_policy,
        env_config.tls_cert_expiry_warning_days,
        crls,
    )
    .map_err(|e| anyhow::anyhow!("Invalid mesh frontend TLS configuration: {}", e))?;
    tls::enable_early_data(&mut config, tls_policy);
    if env_config.ktls_enabled.could_be_enabled() {
        tls::enable_secret_extraction_for_ktls(&mut config);
    }
    Ok(Some(config))
}

fn listener_tls_config(
    listener: &runtime::MeshListener,
    frontend_tls: Option<Arc<rustls::ServerConfig>>,
) -> Option<Arc<rustls::ServerConfig>> {
    match listener.kind {
        runtime::MeshListenerKind::PlaintextCapture => None,
        runtime::MeshListenerKind::MtlsTermination | runtime::MeshListenerKind::HboneTunnel => {
            frontend_tls
        }
    }
}

async fn shutdown_and_join_mesh(
    proxy_state: ProxyState,
    listener_handles: Vec<JoinHandle<()>>,
    mut background_handles: Vec<JoinHandle<()>>,
    dns_retry_handle: Option<JoinHandle<()>>,
    per_ip_cleanup_handle: Option<JoinHandle<()>>,
    mut health_check_handles: Vec<JoinHandle<()>>,
    drain_seconds: u64,
) {
    for handle in listener_handles {
        let _ = handle.await;
    }

    proxy_state.stream_listener_manager.shutdown_all().await;
    crate::overload::begin_drain(&proxy_state.overload);
    if drain_seconds > 0 {
        crate::overload::wait_for_drain(&proxy_state.overload, Duration::from_secs(drain_seconds))
            .await;
    }

    if let Some(handle) = dns_retry_handle {
        background_handles.push(handle);
    }
    if let Some(handle) = per_ip_cleanup_handle {
        background_handles.push(handle);
    }
    health_check_handles.extend(proxy_state.health_checker.take_active_check_handles());
    background_handles.extend(health_check_handles);

    let bg_drain = async {
        for handle in background_handles {
            let _ = handle.await;
        }
    };
    if tokio::time::timeout(Duration::from_secs(5), bg_drain)
        .await
        .is_err()
    {
        warn!("Mesh runtime background tasks did not drain within 5s, proceeding with shutdown");
    }
}
