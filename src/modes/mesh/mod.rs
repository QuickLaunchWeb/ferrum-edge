//! Mesh runtime mode scaffolding.
//!
//! `FERRUM_MODE=mesh` data-plane mode.
//!
//! This module owns the mesh-specific runtime knobs and the config-consumer
//! boundary. It deliberately keeps the generic proxy/plugin chain unchanged so
//! existing plugins work in mesh context.

pub mod config_consumer;
pub mod hbone;
pub mod policy;
pub mod runtime;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::config::mesh::{EastWestGateway, MeshConfig};
use crate::config::types::{
    BackendScheme, BackendTlsConfig, GatewayConfig, PluginAssociation, PluginConfig, PluginScope,
    Proxy, ResponseBodyMode,
};
use crate::dns::{DnsCache, DnsConfig};
use crate::grpc::dp_client::{GrpcJwtSecret, build_dp_grpc_tls_config};
use crate::modes::mesh::config_consumer::native_client::NativeMeshClientConfig;
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::proxy::{self, ProxyState};
use crate::startup::wait_for_start_signals;
use crate::tls::{self, TlsPolicy};
use crate::xds::slice::{MeshSlice, MeshSliceRequest};

const DEFAULT_INBOUND_LISTEN_ADDR: &str = "0.0.0.0:15006";
const DEFAULT_OUTBOUND_LISTEN_ADDR: &str = "127.0.0.1:15001";
const DEFAULT_HBONE_LISTEN_ADDR: &str = "0.0.0.0:15008";
const DEFAULT_EAST_WEST_LISTEN_PORT: u16 = 15443;

pub const MESH_SPIFFE_IDENTITY_PLUGIN_ID: &str = "__mesh_spiffe_identity";
pub const MESH_AUTHZ_PLUGIN_ID: &str = "__mesh_authz";
pub const MESH_WORKLOAD_METRICS_PLUGIN_ID: &str = "__mesh_workload_metrics";
pub const MESH_ACCESS_LOG_PLUGIN_ID: &str = "__mesh_access_log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTrafficDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshListenerKind {
    PlaintextCapture,
    MtlsTermination,
    HboneTermination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshListener {
    pub direction: MeshTrafficDirection,
    pub kind: MeshListenerKind,
    pub addr: SocketAddr,
}

/// Mesh data-plane topology. Sidecar and ambient share the same runtime path;
/// ambient selects HBONE termination instead of sidecar inbound mTLS, and
/// east-west gateway delegates SNI passthrough to the stream listener manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTopology {
    Sidecar,
    Ambient,
    EastWestGateway,
}

impl MeshTopology {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sidecar" => Ok(Self::Sidecar),
            "ambient" => Ok(Self::Ambient),
            "east_west_gateway" | "east-west-gateway" => Ok(Self::EastWestGateway),
            other => Err(format!(
                "Invalid FERRUM_MESH_TOPOLOGY '{other}'. Expected: sidecar, ambient, or east_west_gateway"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Sidecar => "sidecar",
            Self::Ambient => "ambient",
            Self::EastWestGateway => "east_west_gateway",
        }
    }
}

/// Control-protocol source for mesh runtime config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConfigProtocol {
    Native,
    Xds,
}

impl MeshConfigProtocol {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "native" => Ok(Self::Native),
            "xds" => Ok(Self::Xds),
            other => Err(format!(
                "Invalid FERRUM_MESH_CONFIG_PROTOCOL '{other}'. Expected: native or xds"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Xds => "xds",
        }
    }
}

/// Parsed mesh runtime settings kept separate from `EnvConfig` so mesh mode
/// stays strictly additive and non-mesh deployments do not carry new fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRuntimeConfig {
    pub node_id: String,
    pub namespace: String,
    pub cp_urls: Vec<String>,
    pub config_protocol: MeshConfigProtocol,
    pub topology: MeshTopology,
    pub inbound_listen_addr: SocketAddr,
    pub outbound_listen_addr: SocketAddr,
    pub hbone_listen_addr: SocketAddr,
    pub east_west_listen_port: u16,
    pub workload_spiffe_id: Option<String>,
    /// Workload labels for this mesh data plane. Used by `mesh_authz`'s
    /// PolicyScope filter (and by `MeshSlice::from_gateway_config`'s
    /// WorkloadSelector matching) to decide which policies apply to this
    /// proxy's workload. Sourced from `FERRUM_MESH_WORKLOAD_LABELS`
    /// (`key1=val1,key2=val2`); empty when unset. The Kubernetes injector
    /// (Phase D) can populate this from pod labels via the downward API.
    pub workload_labels: std::collections::HashMap<String, String>,
}

impl MeshRuntimeConfig {
    pub fn from_env_config(env_config: &EnvConfig) -> Result<Self, String> {
        let cp_urls = env_config.resolved_dp_cp_grpc_urls();
        if cp_urls.is_empty() {
            return Err(
                "FERRUM_DP_CP_GRPC_URL or FERRUM_DP_CP_GRPC_URLS is required in mesh mode".into(),
            );
        }

        let node_id = resolve_ferrum_var("FERRUM_MESH_NODE_ID")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "ferrum-mesh-node".to_string());
        let config_protocol = MeshConfigProtocol::parse(&env_config.mesh_config_protocol)?;
        let topology = MeshTopology::parse(
            &resolve_ferrum_var("FERRUM_MESH_TOPOLOGY").unwrap_or_else(|| "sidecar".to_string()),
        )?;
        let inbound_listen_addr = parse_socket_addr(
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_INBOUND_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_INBOUND_LISTEN_ADDR),
        )?;
        let outbound_listen_addr = parse_socket_addr(
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_OUTBOUND_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_OUTBOUND_LISTEN_ADDR),
        )?;
        let hbone_listen_addr = parse_socket_addr(
            "FERRUM_MESH_HBONE_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_HBONE_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_HBONE_LISTEN_ADDR),
        )?;
        let east_west_port_raw = resolve_ferrum_var("FERRUM_MESH_EAST_WEST_LISTEN_PORT")
            .unwrap_or_else(|| DEFAULT_EAST_WEST_LISTEN_PORT.to_string());
        let east_west_listen_port =
            parse_port("FERRUM_MESH_EAST_WEST_LISTEN_PORT", &east_west_port_raw)?;
        let workload_spiffe_id = resolve_ferrum_var("FERRUM_MESH_WORKLOAD_SPIFFE_ID")
            .filter(|value| !value.trim().is_empty());
        let workload_labels =
            parse_workload_labels(resolve_ferrum_var("FERRUM_MESH_WORKLOAD_LABELS").as_deref())?;

        Ok(Self {
            node_id,
            namespace: env_config.namespace.clone(),
            cp_urls,
            config_protocol,
            topology,
            inbound_listen_addr,
            outbound_listen_addr,
            hbone_listen_addr,
            east_west_listen_port,
            workload_spiffe_id,
            workload_labels,
        })
    }

    fn native_client_config(&self) -> NativeMeshClientConfig {
        NativeMeshClientConfig {
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            labels: self.workload_labels.clone(),
        }
    }

    pub fn listener_plan(&self) -> Vec<MeshListener> {
        let (inbound_kind, inbound_addr) = match self.topology {
            MeshTopology::Sidecar => (MeshListenerKind::MtlsTermination, self.inbound_listen_addr),
            MeshTopology::Ambient => (MeshListenerKind::HboneTermination, self.hbone_listen_addr),
            MeshTopology::EastWestGateway => return Vec::new(),
        };

        vec![
            MeshListener {
                direction: MeshTrafficDirection::Outbound,
                kind: MeshListenerKind::PlaintextCapture,
                addr: self.outbound_listen_addr,
            },
            MeshListener {
                direction: MeshTrafficDirection::Inbound,
                kind: inbound_kind,
                addr: inbound_addr,
            },
        ]
    }

    #[allow(dead_code)] // Used by tests and future xDS bootstrap wiring.
    pub fn mesh_slice_request(&self) -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            labels: self
                .workload_labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }
}

/// Prepare a gateway snapshot for mesh-mode serving.
///
/// Mesh mode is the only caller. The mutation is cold-path: it runs before
/// `ProxyState` builds router/plugin caches, so non-mesh modes and ordinary
/// requests never pay for mesh plugin injection.
#[allow(dead_code)] // Used by tests and future xDS bootstrap wiring.
pub fn prepare_gateway_config_for_mesh(
    mut config: GatewayConfig,
    runtime: &MeshRuntimeConfig,
) -> Result<GatewayConfig, anyhow::Error> {
    config.normalize_fields();
    config.normalize_mesh_fields();
    let mesh_slice = MeshSlice::from_gateway_config(&config, runtime.mesh_slice_request());
    prepare_normalized_gateway_config_for_mesh(config, runtime, &mesh_slice)
}

fn prepare_gateway_config_for_native_slice(
    mut config: GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) -> Result<GatewayConfig, anyhow::Error> {
    config.normalize_fields();
    config.normalize_mesh_fields();
    prepare_normalized_gateway_config_for_mesh(config, runtime, mesh_slice)
}

fn prepare_normalized_gateway_config_for_mesh(
    mut config: GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) -> Result<GatewayConfig, anyhow::Error> {
    let mesh_errors = config.validate_mesh_fields();
    if !mesh_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "Mesh configuration validation failed: {}",
            mesh_errors.join("; ")
        ));
    }

    inject_mesh_global_plugins(&mut config, runtime, mesh_slice);
    materialize_east_west_gateway_proxies(&mut config, runtime);
    config.normalize_fields();
    Ok(config)
}

fn gateway_config_from_mesh_slice(
    slice: &MeshSlice,
    runtime: &MeshRuntimeConfig,
) -> Result<GatewayConfig, anyhow::Error> {
    let loaded_at = chrono::DateTime::parse_from_rfc3339(&slice.version)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: slice.workloads.clone(),
            services: slice.services.clone(),
            mesh_policies: slice.mesh_policies.clone(),
            peer_authentications: slice.peer_authentications.clone(),
            service_entries: slice.service_entries.clone(),
            trust_bundles: slice.trust_bundles.clone(),
            multi_cluster: slice.multi_cluster.clone(),
        })),
        loaded_at,
        ..GatewayConfig::default()
    };
    prepare_gateway_config_for_native_slice(config, runtime, slice)
}

async fn wait_for_initial_mesh_config(
    mesh_state: &MeshRuntimeState,
    runtime: &MeshRuntimeConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(GatewayConfig, MeshSlice), anyhow::Error> {
    let mut updates = mesh_state.subscribe();
    loop {
        if let Some(slice) = mesh_state.snapshot().as_ref().as_ref().cloned() {
            match gateway_config_from_mesh_slice(&slice, runtime) {
                Ok(config) => return Ok((config, slice)),
                Err(e) => {
                    warn!(
                        mesh_slice_version = %slice.version,
                        error = %e,
                        "Ignoring invalid initial mesh slice"
                    );
                }
            }
        }

        tokio::select! {
            changed = updates.changed() => {
                if changed.is_err() {
                    return Err(anyhow::anyhow!(
                        "mesh slice update channel closed before a valid initial slice arrived"
                    ));
                }
            }
            _ = wait_for_mesh_shutdown(&mut shutdown_rx) => {
                return Err(anyhow::anyhow!("shutdown requested"));
            }
        }
    }
}

async fn wait_for_mesh_shutdown(shutdown_rx: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

fn materialize_east_west_gateway_proxies(config: &mut GatewayConfig, runtime: &MeshRuntimeConfig) {
    if runtime.topology != MeshTopology::EastWestGateway {
        return;
    }

    let Some(mesh) = config.mesh.as_ref() else {
        warn!("east-west gateway topology has no mesh.multi_cluster configuration");
        return;
    };
    let Some(multi_cluster) = mesh.multi_cluster.as_ref() else {
        warn!("east-west gateway topology has no mesh.multi_cluster configuration");
        return;
    };

    for gateway in &multi_cluster.east_west_gateways {
        if gateway.namespace != runtime.namespace {
            continue;
        }

        let proxy = east_west_gateway_proxy(gateway, runtime.east_west_listen_port);

        if let Some(existing) = config
            .proxies
            .iter_mut()
            .find(|candidate| candidate.id == proxy.id)
        {
            *existing = proxy;
        } else {
            config.proxies.push(proxy);
        }
    }
}

fn east_west_gateway_proxy(gateway: &EastWestGateway, listen_port: u16) -> Proxy {
    let now = chrono::Utc::now();
    Proxy {
        id: mesh_east_west_proxy_id(&gateway.namespace, &gateway.name),
        name: Some(format!("mesh east-west {}", gateway.name)),
        namespace: gateway.namespace.clone(),
        hosts: gateway.sni_hosts.clone(),
        listen_path: None,
        backend_scheme: Some(BackendScheme::Tcp),
        dispatch_kind: Default::default(),
        backend_host: gateway.host.clone(),
        backend_port: gateway.port,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
        backend_connect_timeout_ms: 30_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        upstream_id: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: Some(listen_port),
        frontend_tls: false,
        passthrough: true,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

fn mesh_east_west_proxy_id(namespace: &str, name: &str) -> String {
    format!("__mesh-east-west-{namespace}-{name}").replace(['/', '.'], "-")
}

fn inject_mesh_global_plugins(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    ensure_global_plugin(
        config,
        MESH_SPIFFE_IDENTITY_PLUGIN_ID,
        "spiffe_identity",
        serde_json::json!({}),
        &runtime.namespace,
    );
    ensure_global_plugin(
        config,
        MESH_AUTHZ_PLUGIN_ID,
        "mesh_authz",
        serde_json::json!({ "mesh_slice": mesh_slice }),
        &runtime.namespace,
    );
    ensure_global_plugin(
        config,
        MESH_WORKLOAD_METRICS_PLUGIN_ID,
        "workload_metrics",
        serde_json::json!({
            "node_id": runtime.node_id.clone(),
            "topology": runtime.topology.as_str(),
            "namespace": mesh_slice.namespace.clone(),
            "workload_spiffe_id": mesh_slice.workload_spiffe_id.clone(),
            "labels": mesh_slice.labels.clone(),
        }),
        &runtime.namespace,
    );
    ensure_global_plugin(
        config,
        MESH_ACCESS_LOG_PLUGIN_ID,
        "access_log",
        serde_json::json!({}),
        &runtime.namespace,
    );
}

fn ensure_global_plugin(
    config: &mut GatewayConfig,
    id: &str,
    plugin_name: &str,
    plugin_config: serde_json::Value,
    namespace: &str,
) {
    if config.plugin_configs.iter().any(|plugin| {
        plugin.enabled && plugin.scope == PluginScope::Global && plugin.plugin_name == plugin_name
    }) {
        return;
    }

    let now = chrono::Utc::now();
    let mesh_plugin = PluginConfig {
        id: id.to_string(),
        plugin_name: plugin_name.to_string(),
        namespace: namespace.to_string(),
        config: plugin_config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };

    if let Some(existing) = config
        .plugin_configs
        .iter_mut()
        .find(|plugin| plugin.id == id)
    {
        *existing = mesh_plugin;
    } else {
        config.plugin_configs.push(mesh_plugin);
    }
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let runtime = MeshRuntimeConfig::from_env_config(&env_config)
        .map_err(|e| anyhow::anyhow!(e))
        .context("invalid mesh runtime configuration")?;
    ensure_runtime_config_protocol_supported(&runtime)?;

    info!(
        node_id = %runtime.node_id,
        namespace = %runtime.namespace,
        topology = runtime.topology.as_str(),
        config_protocol = runtime.config_protocol.as_str(),
        inbound = %runtime.inbound_listen_addr,
        outbound = %runtime.outbound_listen_addr,
        hbone = %runtime.hbone_listen_addr,
        east_west_listen_port = runtime.east_west_listen_port,
        cp_urls = runtime.cp_urls.len(),
        "Mesh mode starting"
    );

    let mesh_state = MeshRuntimeState::new();

    let jwt_secret = GrpcJwtSecret::with_issuer(
        env_config.cp_dp_grpc_jwt_secret.clone().ok_or_else(|| {
            anyhow::anyhow!("FERRUM_CP_DP_GRPC_JWT_SECRET is required in mesh mode")
        })?,
        env_config.cp_dp_grpc_jwt_issuer.clone(),
    );
    let grpc_tls = build_dp_grpc_tls_config(&env_config, &runtime.cp_urls, "Mesh")?;
    let mut background_handles = Vec::new();

    let client_config = runtime.native_client_config();
    let request = client_config.subscribe_request(crate::FERRUM_VERSION);
    let cp_urls = runtime.cp_urls.clone();
    let state = mesh_state.clone();
    let shutdown_rx = shutdown_tx.subscribe();
    let handle = tokio::spawn(
        config_consumer::native_client::start_native_mesh_client_with_shutdown(
            cp_urls,
            jwt_secret.clone(),
            client_config,
            state,
            shutdown_rx,
            grpc_tls.clone(),
        ),
    );
    background_handles.push(handle);
    info!(
        node_id = %request.node_id,
        namespace = %request.namespace,
        cp_urls = runtime.cp_urls.len(),
        has_first_slice = mesh_state.has_first_slice(),
        "Mesh mode initialized native MeshSubscribe consumer"
    );
    let (bootstrap_config, initial_applied_mesh_slice) =
        wait_for_initial_mesh_config(&mesh_state, &runtime, shutdown_tx.subscribe())
            .await
            .context("mesh runtime stopped before receiving a valid initial mesh slice")?;
    info!(
        mesh_global_plugins = bootstrap_config.plugin_configs.len(),
        mesh_slice_version = %initial_applied_mesh_slice.version,
        "Mesh global plugin chain prepared from initial native slice"
    );

    serve_mesh_runtime(
        env_config,
        runtime,
        bootstrap_config,
        shutdown_tx,
        mesh_state,
        Some(initial_applied_mesh_slice),
        background_handles,
    )
    .await
}

fn ensure_runtime_config_protocol_supported(
    runtime: &MeshRuntimeConfig,
) -> Result<(), anyhow::Error> {
    match runtime.config_protocol {
        MeshConfigProtocol::Native => Ok(()),
        MeshConfigProtocol::Xds => Err(anyhow::anyhow!(
            "FERRUM_MESH_CONFIG_PROTOCOL=xds is not supported by mesh runtime yet; \
             use FERRUM_MESH_CONFIG_PROTOCOL=native for Ferrum MeshSubscribe. \
             FERRUM_XDS_ENABLED only exposes CP ADS for Envoy-compatible clients."
        )),
    }
}

async fn serve_mesh_runtime(
    env_config: EnvConfig,
    runtime: MeshRuntimeConfig,
    config: GatewayConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    mesh_state: MeshRuntimeState,
    initial_applied_mesh_slice: Option<MeshSlice>,
    mesh_background_handles: Vec<JoinHandle<()>>,
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
        .map(|proxy| {
            (
                proxy.backend_host.clone(),
                proxy.dns_override.clone(),
                proxy.dns_cache_ttl_seconds,
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
    let mesh_apply_handle = start_mesh_slice_apply_task(
        mesh_state,
        proxy_state.clone(),
        runtime.clone(),
        initial_applied_mesh_slice,
        shutdown_tx.subscribe(),
    );

    let frontend_tls = load_frontend_tls(&env_config, &tls_policy, &crls)?;
    if let Some(ref tls_config) = frontend_tls {
        proxy_state
            .stream_listener_manager
            .set_frontend_tls_config(Some(tls_config.clone()))
            .await;
    }

    info!(
        listeners = runtime.listener_plan().len(),
        "Mesh listener plan prepared"
    );
    let mut listener_handles = Vec::new();
    let mut startup_signals = Vec::new();
    for listener in runtime.listener_plan() {
        let tls_config = listener_tls_config(&listener, frontend_tls.clone());
        if tls_config.is_none()
            && matches!(
                listener.kind,
                MeshListenerKind::MtlsTermination | MeshListenerKind::HboneTermination
            )
        {
            warn!(
                direction = ?listener.direction,
                addr = %listener.addr,
                "Mesh TLS listener is running without frontend TLS because no mesh/frontend certificate is configured"
            );
        }

        let label = format!("{:?} mesh listener", listener.direction);
        let state = proxy_state.clone();
        let shutdown = shutdown_tx.subscribe();
        let addr = listener.addr;
        let direction = listener.direction;
        let kind = listener.kind;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            info!(
                direction = ?direction,
                kind = ?kind,
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
                error!(
                    direction = ?direction,
                    kind = ?kind,
                    addr = %addr,
                    "Mesh listener error: {}",
                    e
                );
            }
        });
        listener_handles.push(handle);
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
        let _ =
            await_mesh_listener_handles(listener_handles, shutdown_tx.clone(), "startup failure")
                .await;
        shutdown_and_join_mesh(
            proxy_state,
            MeshBackgroundTasks {
                handles: vec![
                    dns_handle,
                    overload_handle,
                    metrics_handle,
                    mesh_apply_handle,
                ],
                dns_retry_handle,
                per_ip_cleanup_handle,
                health_check_handles,
                mesh_background_handles,
            },
            env_config.shutdown_drain_seconds,
        )
        .await;
        return Err(e);
    }

    let listener_result =
        await_mesh_listener_handles(listener_handles, shutdown_tx.clone(), "shutdown").await;

    shutdown_and_join_mesh(
        proxy_state,
        MeshBackgroundTasks {
            handles: vec![
                dns_handle,
                overload_handle,
                metrics_handle,
                mesh_apply_handle,
            ],
            dns_retry_handle,
            per_ip_cleanup_handle,
            health_check_handles,
            mesh_background_handles,
        },
        env_config.shutdown_drain_seconds,
    )
    .await;
    info!("Mesh runtime mode shutting down");
    listener_result?;
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
    listener: &MeshListener,
    frontend_tls: Option<Arc<rustls::ServerConfig>>,
) -> Option<Arc<rustls::ServerConfig>> {
    match listener.kind {
        MeshListenerKind::PlaintextCapture => None,
        MeshListenerKind::MtlsTermination | MeshListenerKind::HboneTermination => frontend_tls,
    }
}

fn start_mesh_slice_apply_task(
    mesh_state: MeshRuntimeState,
    proxy_state: ProxyState,
    runtime: MeshRuntimeConfig,
    initial_applied_mesh_slice: Option<MeshSlice>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut updates = mesh_state.subscribe();
        let mut last_applied_slice = initial_applied_mesh_slice;
        loop {
            if *shutdown_rx.borrow() {
                return;
            }

            if let Some(slice) = mesh_state.snapshot().as_ref().as_ref().cloned() {
                if mesh_slice_matches_last_applied(last_applied_slice.as_ref(), &slice) {
                    debug!(
                        mesh_slice_version = %slice.version,
                        "Skipping no-op mesh slice update"
                    );
                } else {
                    match gateway_config_from_mesh_slice(&slice, &runtime) {
                        Ok(config) => {
                            let applied = proxy_state.update_config(config);
                            record_mesh_slice_apply_result(
                                &mut last_applied_slice,
                                &slice,
                                applied,
                            );
                            if applied {
                                info!(
                                    mesh_slice_version = %slice.version,
                                    "Applied mesh slice to proxy runtime"
                                );
                            } else {
                                warn!(
                                    mesh_slice_version = %slice.version,
                                    "Mesh slice was not applied to proxy runtime; retaining last accepted slice"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                mesh_slice_version = %slice.version,
                                error = %e,
                                "Ignoring invalid mesh slice update"
                            );
                        }
                    }
                }
            }

            tokio::select! {
                changed = updates.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = wait_for_mesh_shutdown(&mut shutdown_rx) => return,
            }
        }
    })
}

fn mesh_slice_matches_last_applied(
    last_applied_slice: Option<&MeshSlice>,
    slice: &MeshSlice,
) -> bool {
    last_applied_slice.is_some_and(|applied| applied.content_eq(slice))
}

fn record_mesh_slice_apply_result(
    last_applied_slice: &mut Option<MeshSlice>,
    slice: &MeshSlice,
    applied: bool,
) {
    if applied {
        *last_applied_slice = Some(slice.clone());
    }
}

struct MeshBackgroundTasks {
    handles: Vec<JoinHandle<()>>,
    dns_retry_handle: Option<JoinHandle<()>>,
    per_ip_cleanup_handle: Option<JoinHandle<()>>,
    health_check_handles: Vec<JoinHandle<()>>,
    mesh_background_handles: Vec<JoinHandle<()>>,
}

async fn await_mesh_listener_handles(
    listener_handles: Vec<JoinHandle<()>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    reason: &str,
) -> Result<(), tokio::task::JoinError> {
    if listener_handles.is_empty() {
        let mut wait_shutdown = shutdown_tx.subscribe();
        while !*wait_shutdown.borrow() {
            if wait_shutdown.changed().await.is_err() {
                break;
            }
        }
        info!(
            reason,
            "Mesh runtime observed shutdown with no active listeners"
        );
        Ok(())
    } else {
        let shutdown_on_panic = move || {
            let _ = shutdown_tx.send(true);
        };
        crate::modes::file::await_listener_handles(listener_handles, shutdown_on_panic).await
    }
}

async fn shutdown_and_join_mesh(
    proxy_state: ProxyState,
    mut tasks: MeshBackgroundTasks,
    drain_seconds: u64,
) {
    proxy_state.stream_listener_manager.shutdown_all().await;
    crate::overload::begin_drain(&proxy_state.overload);
    if drain_seconds > 0 {
        crate::overload::wait_for_drain(&proxy_state.overload, Duration::from_secs(drain_seconds))
            .await;
    }

    if let Some(handle) = tasks.dns_retry_handle {
        tasks.handles.push(handle);
    }
    if let Some(handle) = tasks.per_ip_cleanup_handle {
        tasks.handles.push(handle);
    }
    tasks
        .health_check_handles
        .extend(proxy_state.health_checker.take_active_check_handles());
    tasks.handles.extend(tasks.health_check_handles);
    tasks.handles.extend(tasks.mesh_background_handles);

    crate::modes::file::join_background_handles(tasks.handles, Duration::from_secs(5)).await;
}

fn parse_socket_addr(key: &str, raw: &str) -> Result<SocketAddr, String> {
    raw.parse::<SocketAddr>()
        .map_err(|e| format!("{key} must be a socket address (got '{raw}'): {e}"))
}

/// Parse `FERRUM_MESH_WORKLOAD_LABELS` (`k1=v1,k2=v2`). Empty / `None` returns
/// an empty map. Whitespace around keys/values is trimmed; empty entries are
/// skipped (so a trailing `,` is harmless). Duplicate keys are rejected so the
/// operator catches a typo immediately.
fn parse_workload_labels(
    raw: Option<&str>,
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut labels = std::collections::HashMap::new();
    let Some(raw) = raw else {
        return Ok(labels);
    };
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            format!("FERRUM_MESH_WORKLOAD_LABELS entry '{entry}' must be in 'key=value' form")
        })?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            return Err(format!(
                "FERRUM_MESH_WORKLOAD_LABELS entry '{entry}' has an empty key"
            ));
        }
        if labels.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!(
                "FERRUM_MESH_WORKLOAD_LABELS contains duplicate key '{key}'"
            ));
        }
    }
    Ok(labels)
}

fn parse_port(key: &str, raw: &str) -> Result<u16, String> {
    let port = raw
        .parse::<u16>()
        .map_err(|e| format!("{key} must be a TCP port (got '{raw}'): {e}"))?;
    if port == 0 {
        Err(format!("{key} must be between 1 and 65535 (got 0)"))
    } else {
        Ok(port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EnvConfig;
    use crate::config::mesh::{
        AppProtocol, EastWestGateway, MeshConfig, MeshPolicy, MeshRule, MeshService,
        MultiClusterConfig, PolicyAction, PolicyScope, PrincipalMatch, Workload, WorkloadPort,
        WorkloadSelector,
    };
    use crate::config::types::PluginScope;
    use crate::dns::{DnsCache, DnsConfig};
    use crate::identity::{SpiffeId, TrustDomain};
    use std::collections::HashMap;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_mesh_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let keys = [
            "FERRUM_MODE",
            "FERRUM_NAMESPACE",
            "FERRUM_DP_CP_GRPC_URL",
            "FERRUM_DP_CP_GRPC_URLS",
            "FERRUM_CP_DP_GRPC_JWT_SECRET",
            "FERRUM_MESH_NODE_ID",
            "FERRUM_MESH_CONFIG_PROTOCOL",
            "FERRUM_MESH_TOPOLOGY",
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            "FERRUM_MESH_HBONE_LISTEN_ADDR",
            "FERRUM_MESH_EAST_WEST_LISTEN_PORT",
            "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
            "FERRUM_MESH_WORKLOAD_LABELS",
            "FERRUM_POOL_WARMUP_ENABLED",
            "FERRUM_SHUTDOWN_DRAIN_SECONDS",
        ];

        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
        for (key, value) in vars {
            unsafe { std::env::set_var(key, value) };
        }

        f();

        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn mesh_runtime_config_defaults_to_sidecar_native_ports() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.node_id, "node-a");
                assert_eq!(runtime.namespace, "ferrum");
                assert_eq!(runtime.cp_urls, vec!["http://cp:50051"]);
                assert_eq!(runtime.config_protocol, MeshConfigProtocol::Native);
                assert_eq!(runtime.topology, MeshTopology::Sidecar);
                assert_eq!(
                    runtime.inbound_listen_addr,
                    DEFAULT_INBOUND_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.outbound_listen_addr,
                    DEFAULT_OUTBOUND_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.hbone_listen_addr,
                    DEFAULT_HBONE_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(runtime.east_west_listen_port, DEFAULT_EAST_WEST_LISTEN_PORT);
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_native_ambient_overrides() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                (
                    "FERRUM_DP_CP_GRPC_URLS",
                    "https://cp1:50051,https://cp2:50051",
                ),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-b"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "native"),
                ("FERRUM_MESH_TOPOLOGY", "ambient"),
                ("FERRUM_MESH_INBOUND_LISTEN_ADDR", "127.0.0.1:16006"),
                ("FERRUM_MESH_OUTBOUND_LISTEN_ADDR", "127.0.0.1:16001"),
                ("FERRUM_MESH_HBONE_LISTEN_ADDR", "127.0.0.1:16008"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "16443"),
                (
                    "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                    "spiffe://cluster.local/ns/default/sa/api",
                ),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.config_protocol, MeshConfigProtocol::Native);
                assert_eq!(runtime.topology, MeshTopology::Ambient);
                assert_eq!(runtime.cp_urls.len(), 2);
                assert_eq!(
                    runtime.workload_spiffe_id.as_deref(),
                    Some("spiffe://cluster.local/ns/default/sa/api")
                );
                assert_eq!(
                    runtime.inbound_listen_addr,
                    "127.0.0.1:16006".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.outbound_listen_addr,
                    "127.0.0.1:16001".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.hbone_listen_addr,
                    "127.0.0.1:16008".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(runtime.east_west_listen_port, 16443);
            },
        );
    }

    #[test]
    fn mesh_runtime_rejects_xds_protocol_until_client_is_wired() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "xds"),
            ],
            || {
                let err = EnvConfig::from_env().expect_err(
                    "shared config validation should reject unsupported xDS mesh runtime",
                );

                assert!(err.contains("FERRUM_MESH_CONFIG_PROTOCOL=xds"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_east_west_gateway_topology() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "15444"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.topology, MeshTopology::EastWestGateway);
                assert_eq!(runtime.east_west_listen_port, 15444);
                assert!(runtime.listener_plan().is_empty());
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_workload_labels() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_WORKLOAD_LABELS", " app = api , version=v1 , ,"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.workload_labels.len(), 2);
                assert_eq!(
                    runtime.workload_labels.get("app").map(String::as_str),
                    Some("api")
                );
                assert_eq!(
                    runtime.workload_labels.get("version").map(String::as_str),
                    Some("v1")
                );
                let request = runtime.mesh_slice_request();
                assert_eq!(request.labels.get("app").map(String::as_str), Some("api"));
                assert_eq!(
                    request.labels.get("version").map(String::as_str),
                    Some("v1")
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_workload_label_without_equals() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_WORKLOAD_LABELS", "appapi"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_WORKLOAD_LABELS"));
                assert!(err.contains("key=value"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_duplicate_workload_label_key() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_WORKLOAD_LABELS", "app=api,app=worker"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("duplicate key"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_bad_topology() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "east-west"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_TOPOLOGY"));
            },
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_starts_listeners_and_shuts_down() {
        let env = EnvConfig {
            mode: crate::config::OperatingMode::Mesh,
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            accept_threads: 1,
            ..EnvConfig::default()
        };
        let runtime = MeshRuntimeConfig {
            node_id: "node-a".to_string(),
            namespace: "ferrum".to_string(),
            cp_urls: vec!["http://127.0.0.1:1".to_string()],
            config_protocol: MeshConfigProtocol::Native,
            topology: MeshTopology::Sidecar,
            inbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            outbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            hbone_listen_addr: "127.0.0.1:0".parse().unwrap(),
            east_west_listen_port: DEFAULT_EAST_WEST_LISTEN_PORT,
            workload_spiffe_id: None,
            workload_labels: HashMap::new(),
        };
        let config = prepare_gateway_config_for_mesh(GatewayConfig::default(), &runtime).unwrap();
        let mesh_state = MeshRuntimeState::new();
        mesh_state.install_slice(MeshSlice {
            version: chrono::Utc::now().to_rfc3339(),
            ..MeshSlice::default()
        });
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let task_shutdown = shutdown_tx.clone();
        let task = tokio::spawn(async move {
            serve_mesh_runtime(
                env,
                runtime,
                config,
                task_shutdown,
                mesh_state,
                None,
                Vec::new(),
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !task.is_finished(),
            "mesh runtime should keep serving until shutdown"
        );
        let _ = shutdown_tx.send(true);

        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("mesh runtime shut down before timeout")
            .expect("mesh runtime task joined");
        assert!(result.is_ok(), "mesh runtime returned error: {result:?}");
    }

    fn workload(name: &str, app: &str) -> Workload {
        let trust_domain = TrustDomain::new("cluster.local").unwrap();
        Workload {
            spiffe_id: SpiffeId::new(format!("spiffe://cluster.local/ns/default/sa/{name}"))
                .unwrap(),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), app.to_string())]),
                namespace: Some("default".to_string()),
            },
            service_name: name.to_string(),
            addresses: Vec::new(),
            ports: vec![WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain,
            namespace: "default".to_string(),
            network: None,
            cluster: None,
        }
    }

    fn test_mesh_runtime_config() -> MeshRuntimeConfig {
        MeshRuntimeConfig {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            cp_urls: vec!["http://127.0.0.1:1".to_string()],
            config_protocol: MeshConfigProtocol::Native,
            topology: MeshTopology::Sidecar,
            inbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            outbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            hbone_listen_addr: "127.0.0.1:0".parse().unwrap(),
            east_west_listen_port: DEFAULT_EAST_WEST_LISTEN_PORT,
            workload_spiffe_id: None,
            workload_labels: HashMap::new(),
        }
    }

    fn make_test_proxy_state(initial_config: GatewayConfig) -> ProxyState {
        ProxyState::new(
            initial_config,
            DnsCache::new(DnsConfig::default()),
            EnvConfig {
                pool_warmup_enabled: false,
                shutdown_drain_seconds: 0,
                ..EnvConfig::default()
            },
            None,
            None,
        )
        .expect("ProxyState construction should succeed in tests")
        .0
    }

    async fn wait_for_mesh_authz_label(proxy_state: &ProxyState, key: &str, expected: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let observed = proxy_state
                    .current_config()
                    .plugin_configs
                    .iter()
                    .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
                    .and_then(|plugin| {
                        plugin
                            .config
                            .pointer(&format!("/mesh_slice/labels/{key}"))
                            .and_then(|value| value.as_str())
                            .map(str::to_string)
                    });
                if observed.as_deref() == Some(expected) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("mesh_authz label {key} did not become {expected}"));
    }

    #[test]
    fn mesh_runtime_listener_plan_uses_sidecar_ports() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let plan = runtime.listener_plan();

                assert_eq!(plan.len(), 2);
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Outbound
                        && listener.kind == MeshListenerKind::PlaintextCapture
                        && listener.addr.port() == 15001
                }));
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Inbound
                        && listener.kind == MeshListenerKind::MtlsTermination
                        && listener.addr.port() == 15006
                }));
            },
        );
    }

    #[test]
    fn mesh_runtime_listener_plan_uses_ambient_hbone_port() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "ambient"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let plan = runtime.listener_plan();

                assert_eq!(plan.len(), 2);
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Outbound
                        && listener.kind == MeshListenerKind::PlaintextCapture
                        && listener.addr.port() == 15001
                }));
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Inbound
                        && listener.kind == MeshListenerKind::HboneTermination
                        && listener.addr.port() == 15008
                }));
            },
        );
    }

    #[test]
    fn mesh_runtime_prepares_east_west_passthrough_proxies() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "mesh-system"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "15443"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        multi_cluster: Some(MultiClusterConfig {
                            east_west_gateways: vec![EastWestGateway {
                                name: "remote-a".to_string(),
                                namespace: "mesh-system".to_string(),
                                host: "EastWest.Remote.Example".to_string(),
                                port: 443,
                                sni_hosts: vec!["API.Remote.Example".to_string()],
                                trust_domain: Some(TrustDomain::new("remote.test").unwrap()),
                                network: Some("network-a".to_string()),
                            }],
                            ..MultiClusterConfig::default()
                        }),
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let proxy = prepared
                    .proxies
                    .iter()
                    .find(|proxy| proxy.id == "__mesh-east-west-mesh-system-remote-a")
                    .expect("east-west proxy");

                assert_eq!(proxy.listen_port, Some(15443));
                assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
                assert_eq!(
                    proxy.dispatch_kind,
                    crate::config::types::DispatchKind::TcpRaw
                );
                assert!(proxy.passthrough);
                assert_eq!(proxy.backend_host, "eastwest.remote.example");
                assert_eq!(proxy.hosts, vec!["api.remote.example"]);
            },
        );
    }

    #[test]
    fn mesh_runtime_prepares_global_mesh_plugins_from_slice() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
                (
                    "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                    "spiffe://cluster.local/ns/default/sa/api",
                ),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let api_policy = MeshPolicy {
                    name: "api-only".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    rules: vec![MeshRule {
                        from: vec![PrincipalMatch {
                            spiffe_id_pattern: Some(
                                "spiffe://cluster.local/ns/default/sa/client".to_string(),
                            ),
                            namespace_pattern: None,
                            trust_domain: None,
                        }],
                        to: Vec::new(),
                        when: Vec::new(),
                        action: PolicyAction::Allow,
                    }],
                };
                let worker_policy = MeshPolicy {
                    name: "worker-only".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "worker".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    rules: Vec::new(),
                };
                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        workloads: vec![workload("api", "api"), workload("worker", "worker")],
                        mesh_policies: vec![api_policy, worker_policy],
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let by_id = |id: &str| {
                    prepared
                        .plugin_configs
                        .iter()
                        .find(|plugin| plugin.id == id)
                        .expect("mesh plugin injected")
                };

                assert_eq!(
                    by_id(MESH_SPIFFE_IDENTITY_PLUGIN_ID).plugin_name,
                    "spiffe_identity"
                );
                assert_eq!(by_id(MESH_AUTHZ_PLUGIN_ID).plugin_name, "mesh_authz");
                assert_eq!(
                    by_id(MESH_WORKLOAD_METRICS_PLUGIN_ID).plugin_name,
                    "workload_metrics"
                );
                assert_eq!(by_id(MESH_ACCESS_LOG_PLUGIN_ID).plugin_name, "access_log");
                assert!(
                    prepared
                        .plugin_configs
                        .iter()
                        .all(|plugin| plugin.scope == PluginScope::Global)
                );

                let mesh_slice = by_id(MESH_AUTHZ_PLUGIN_ID)
                    .config
                    .get("mesh_slice")
                    .expect("mesh_authz mesh_slice");
                let policies = mesh_slice
                    .get("mesh_policies")
                    .and_then(|policies| policies.as_array())
                    .expect("mesh policies array");
                assert_eq!(policies.len(), 1);
                assert_eq!(
                    policies[0].get("name").and_then(|name| name.as_str()),
                    Some("api-only")
                );
                assert_eq!(
                    mesh_slice
                        .pointer("/labels/app")
                        .and_then(|label| label.as_str()),
                    Some("api")
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_uses_native_slice_without_reslicing_policies() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let slice = MeshSlice {
                    node_id: "node-a".to_string(),
                    namespace: "default".to_string(),
                    labels: [("app".to_string(), "api".to_string())].into(),
                    version: chrono::Utc::now().to_rfc3339(),
                    mesh_policies: vec![MeshPolicy {
                        name: "api-only".to_string(),
                        namespace: "default".to_string(),
                        scope: PolicyScope::WorkloadSelector {
                            selector: WorkloadSelector {
                                labels: HashMap::from([("app".to_string(), "api".to_string())]),
                                namespace: Some("default".to_string()),
                            },
                        },
                        rules: vec![MeshRule {
                            from: vec![PrincipalMatch {
                                spiffe_id_pattern: Some(
                                    "spiffe://cluster.local/ns/default/sa/client".to_string(),
                                ),
                                namespace_pattern: None,
                                trust_domain: None,
                            }],
                            to: Vec::new(),
                            when: Vec::new(),
                            action: PolicyAction::Allow,
                        }],
                    }],
                    ..MeshSlice::default()
                };

                let prepared =
                    gateway_config_from_mesh_slice(&slice, &runtime).expect("native slice config");
                let mesh_authz = prepared
                    .plugin_configs
                    .iter()
                    .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
                    .expect("mesh_authz plugin");
                let plugin_slice = mesh_authz
                    .config
                    .get("mesh_slice")
                    .expect("mesh_authz mesh_slice");

                assert_eq!(
                    plugin_slice
                        .pointer("/labels/app")
                        .and_then(|label| label.as_str()),
                    Some("api")
                );
                let policies = plugin_slice
                    .get("mesh_policies")
                    .and_then(|policies| policies.as_array())
                    .expect("mesh policies array");
                assert_eq!(policies.len(), 1);
                assert_eq!(
                    policies[0].get("name").and_then(|name| name.as_str()),
                    Some("api-only")
                );
            },
        );
    }

    #[test]
    fn mesh_slice_rejection_does_not_advance_apply_dedupe_baseline() {
        let mut last_applied_slice = None;
        let rejected = MeshSlice {
            version: "bad-v1".to_string(),
            labels: [("app".to_string(), "api".to_string())].into(),
            ..MeshSlice::default()
        };
        record_mesh_slice_apply_result(&mut last_applied_slice, &rejected, false);
        assert!(last_applied_slice.is_none());
        assert!(!mesh_slice_matches_last_applied(
            last_applied_slice.as_ref(),
            &MeshSlice {
                version: "bad-v2".to_string(),
                labels: [("app".to_string(), "api".to_string())].into(),
                ..MeshSlice::default()
            }
        ));

        record_mesh_slice_apply_result(&mut last_applied_slice, &rejected, true);
        assert!(mesh_slice_matches_last_applied(
            last_applied_slice.as_ref(),
            &MeshSlice {
                version: "bad-v2".to_string(),
                labels: [("app".to_string(), "api".to_string())].into(),
                ..MeshSlice::default()
            }
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_apply_task_propagates_subsequent_native_slices() {
        let runtime = test_mesh_runtime_config();
        let mesh_state = MeshRuntimeState::new();
        let proxy_state = make_test_proxy_state(GatewayConfig::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let apply_task = start_mesh_slice_apply_task(
            mesh_state.clone(),
            proxy_state.clone(),
            runtime,
            None,
            shutdown_rx,
        );

        mesh_state.install_slice(MeshSlice {
            version: "slice-v1".to_string(),
            labels: [("app".to_string(), "api".to_string())].into(),
            ..MeshSlice::default()
        });
        wait_for_mesh_authz_label(&proxy_state, "app", "api").await;

        mesh_state.install_slice(MeshSlice {
            version: "slice-v2".to_string(),
            labels: [("app".to_string(), "worker".to_string())].into(),
            ..MeshSlice::default()
        });
        wait_for_mesh_authz_label(&proxy_state, "app", "worker").await;

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), apply_task)
            .await
            .expect("apply task should stop")
            .expect("apply task should join");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_waits_for_valid_initial_native_slice() {
        let runtime = test_mesh_runtime_config();
        let mesh_state = MeshRuntimeState::new();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let state = mesh_state.clone();

        let wait = tokio::spawn(async move {
            wait_for_initial_mesh_config(&state, &runtime, shutdown_rx).await
        });

        mesh_state.install_slice(MeshSlice {
            version: "bad-slice".to_string(),
            services: vec![MeshService {
                name: String::new(),
                namespace: "default".to_string(),
                ports: Vec::new(),
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!wait.is_finished());

        mesh_state.install_slice(MeshSlice {
            version: "good-slice".to_string(),
            ..MeshSlice::default()
        });

        let (config, slice) = wait
            .await
            .expect("wait task joins")
            .expect("valid slice is accepted");
        assert_eq!(slice.version, "good-slice");
        assert!(!config.plugin_configs.is_empty());
    }

    #[test]
    fn mesh_runtime_preserves_operator_global_mesh_plugin_override() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let existing = PluginConfig {
                    id: "operator-mesh-authz".to_string(),
                    plugin_name: "mesh_authz".to_string(),
                    namespace: "ferrum".to_string(),
                    config: serde_json::json!({ "mesh_slice": MeshSlice::default() }),
                    scope: PluginScope::Global,
                    proxy_id: None,
                    enabled: true,
                    priority_override: Some(2005),
                    api_spec_id: None,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                let config = GatewayConfig {
                    plugin_configs: vec![existing],
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let mesh_authz: Vec<_> = prepared
                    .plugin_configs
                    .iter()
                    .filter(|plugin| plugin.plugin_name == "mesh_authz")
                    .collect();

                assert_eq!(mesh_authz.len(), 1);
                assert_eq!(mesh_authz[0].id, "operator-mesh-authz");
                assert!(prepared.plugin_configs.iter().any(|plugin| {
                    plugin.id == MESH_SPIFFE_IDENTITY_PLUGIN_ID
                        && plugin.plugin_name == "spiffe_identity"
                }));
            },
        );
    }
}
