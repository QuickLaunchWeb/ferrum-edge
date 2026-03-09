use std::net::SocketAddr;
use tracing::{info, error};

use crate::config::types::GatewayConfig;
use crate::config::EnvConfig;
use crate::dns::DnsCache;
use crate::grpc::dp_client;
use crate::proxy::{self, ProxyState};
use crate::tls;

pub async fn run(env_config: EnvConfig, shutdown_tx: tokio::sync::watch::Sender<bool>) -> Result<(), anyhow::Error> {
    info!("DP mode: starting with empty config, waiting for CP");

    let dns_cache = DnsCache::new(
        env_config.dns_cache_ttl_seconds,
        env_config.dns_overrides.clone(),
    );

    // Start with empty config; CP will push the real one
    let proxy_state = ProxyState::new(GatewayConfig::default(), dns_cache, env_config.clone());

    // Load TLS configuration if provided
    let tls_config = if let (Some(cert_path), Some(key_path)) = (&env_config.proxy_tls_cert_path, &env_config.proxy_tls_key_path) {
        info!("Loading TLS configuration with client certificate verification...");
        let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.as_deref();
        match tls::load_tls_config_with_client_auth(cert_path, key_path, client_ca_bundle_path, env_config.backend_tls_no_verify) {
            Ok(config) => {
                if client_ca_bundle_path.is_some() {
                    info!("TLS configuration loaded with client certificate verification (HTTPS with mTLS available)");
                } else {
                    info!("TLS configuration loaded without client certificate verification (HTTPS available)");
                }
                Some(config)
            }
            Err(e) => {
                error!("TLS configuration validation failed: {}", e);
                return Err(anyhow::anyhow!("Invalid TLS configuration: {}", e));
            }
        }
    } else {
        info!("No TLS configuration provided (HTTP only)");
        None
    };

    // Start DP client to connect to CP
    let cp_url = env_config.dp_cp_grpc_url.clone().unwrap_or_default();
    let auth_token = env_config.dp_grpc_auth_token.clone().unwrap_or_default();
    let proxy_state_grpc = proxy_state.clone();
    tokio::spawn(async move {
        dp_client::start_dp_client(cp_url, auth_token, proxy_state_grpc).await;
    });

    // Start separate listeners for HTTP and HTTPS
    let mut handles = Vec::new();

    // HTTP listener (always enabled)
    let http_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_http_port).parse()?;
    let http_state = proxy_state.clone();
    let http_shutdown = shutdown_tx.subscribe();
    let http_handle = tokio::spawn(async move {
        info!("Starting HTTP proxy listener on {}", http_addr);
        if let Err(e) = proxy::start_proxy_listener(http_addr, http_state, http_shutdown).await {
            error!("HTTP proxy listener error: {}", e);
        }
    });
    handles.push(http_handle);

    // HTTPS listener (only if TLS is configured)
    if let Some(tls_config) = tls_config.clone() {
        let https_addr: SocketAddr = format!("0.0.0.0:{}", env_config.proxy_https_port).parse()?;
        let https_state = proxy_state.clone();
        let https_shutdown = shutdown_tx.subscribe();
        let https_handle = tokio::spawn(async move {
            info!("Starting HTTPS proxy listener on {}", https_addr);
            if let Err(e) = proxy::start_proxy_listener_with_tls(https_addr, https_state, https_shutdown, Some(tls_config)).await {
                error!("HTTPS proxy listener error: {}", e);
            }
        });
        handles.push(https_handle);
    } else {
        info!("TLS not configured - HTTPS listener disabled");
    }

    // Wait for all listeners to complete
    for handle in handles {
        handle.await?;
    }

    Ok(())
}
