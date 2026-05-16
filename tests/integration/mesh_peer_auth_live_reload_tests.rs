use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_mesh_inbound_tls_and_signal};
use ferrum_edge::tls::{MeshClientAuth, TlsPolicy, load_mesh_tls_config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::scaffolding::ports::reserve_port;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn test_env_config() -> EnvConfig {
    EnvConfig {
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        accept_threads: 1,
        frontend_tls_handshake_timeout_seconds: 1,
        ..EnvConfig::default()
    }
}

fn test_proxy_state(env: EnvConfig) -> ProxyState {
    ProxyState::new(
        GatewayConfig::default(),
        DnsCache::new(DnsConfig::default()),
        env,
        None,
        None,
    )
    .expect("proxy state")
    .0
}

fn strict_mesh_tls_config() -> Arc<rustls::ServerConfig> {
    ensure_crypto_provider();
    let env = test_env_config();
    let tls_policy = TlsPolicy::from_env_config(&env).expect("TLS policy");
    load_mesh_tls_config(
        "tests/certs/server.crt",
        "tests/certs/server.key",
        // Test fixture certificate is self-signed, so it doubles as the CA
        // anchor for client-certificate verification in this narrow test.
        Some("tests/certs/server.crt"),
        MeshClientAuth::Required,
        &tls_policy,
        env.tls_cert_expiry_warning_days,
        &[],
    )
    .expect("strict mesh TLS config")
}

async fn send_plain_http(addr: SocketAddr) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await;
    Ok(response)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_peer_auth_live_reload_listener_rejects_plaintext_after_strict_swap() {
    ensure_crypto_provider();
    let reservation = reserve_port().await.expect("reserve proxy port");
    let port = reservation.drop_and_take_port();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let state = test_proxy_state(test_env_config());
    let state_for_swap = state.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let listener = tokio::spawn(async move {
        start_proxy_listener_with_mesh_inbound_tls_and_signal(
            addr,
            state,
            shutdown_rx,
            Some(started_tx),
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("listener start signal")
        .expect("listener started");

    let plaintext_response = send_plain_http(addr).await.expect("plaintext request");
    assert!(
        plaintext_response.starts_with(b"HTTP/1.1 404"),
        "empty mesh TLS slot should run the listener as plaintext HTTP; response was {}",
        String::from_utf8_lossy(&plaintext_response)
    );

    state_for_swap
        .mesh_inbound_tls
        .store(Arc::new(Some(strict_mesh_tls_config())));

    let rejected_response = send_plain_http(addr)
        .await
        .expect("plaintext request after strict swap");
    assert!(
        !rejected_response.starts_with(b"HTTP/"),
        "strict mesh TLS slot must reject plaintext before HTTP routing; response was {}",
        String::from_utf8_lossy(&rejected_response)
    );
    assert!(
        rejected_response.is_empty() || rejected_response.len() < 64,
        "plaintext rejection should close during TLS admission, not return a routed response; got {} bytes",
        rejected_response.len()
    );

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(2), listener)
        .await
        .expect("listener should stop")
        .expect("listener task should join")
        .expect("listener should return cleanly");
}
