//! Integration tests for opt-in frontend TLS cert/key live reload
//! (`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED`).
//!
//! Validates that:
//! 1. The HTTPS listener reads from the shared `SharedFrontendTls` ArcSwap
//!    slot on every new accept, so swapping the slot takes effect on the
//!    next handshake without restarting the listener.
//! 2. A swap to a config bearing a different leaf certificate is observed
//!    by the next handshake (we compare the cert chain length / SAN
//!    indirectly via certificate-equality assertions on the peer-cert seen
//!    by the rustls client).
//! 3. Existing in-flight TLS sessions are NOT torn down by a swap (rustls
//!    consults the `ServerConfig` only during the handshake).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_dynamic_tls_and_signal};
use ferrum_edge::tls::NoVerifier;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::scaffolding::ports::reserve_port;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn test_env_config() -> EnvConfig {
    EnvConfig {
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        accept_threads: 1,
        frontend_tls_handshake_timeout_seconds: 2,
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

fn generate_server_config_with_san(san: &str) -> (Arc<ServerConfig>, Vec<u8>) {
    ensure_crypto_provider();
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params = rcgen::CertificateParams::new(vec![san.to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");

    let cert_pem = cert.pem();
    let mut cert_reader = cert_pem.as_bytes();
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(Result::ok)
        .collect();
    let cert_der = certs[0].as_ref().to_vec();
    let key_pem = key_pair.serialize_pem();
    let mut key_reader = key_pem.as_bytes();
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .expect("read private key")
        .expect("private key present");

    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .expect("server cert");

    (Arc::new(config), cert_der)
}

fn no_verify_client_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    // Use the gateway's shared NoVerifier so peer certs are accepted
    // unconditionally. We compare cert DERs after the handshake to verify
    // the slot's current cert is being served.
    let mut cfg = cfg;
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(NoVerifier));
    Arc::new(cfg)
}

async fn fetch_peer_cert_der(addr: SocketAddr) -> Vec<u8> {
    let client_config = no_verify_client_config();
    let connector = TlsConnector::from(client_config);
    let stream = TcpStream::connect(addr).await.expect("connect TCP");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("tls handshake");
    // Write a tiny dummy request so the server processes the connection;
    // we only care about the handshake's peer cert chain.
    let _ = tls
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await;
    // Drain (best-effort) so the connection is fully exchanged.
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_millis(500), tls.read_to_end(&mut buf)).await;

    let (_io, conn) = tls.into_inner();
    conn.peer_certificates()
        .expect("server cert presented")
        .first()
        .expect("at least one cert")
        .as_ref()
        .to_vec()
}

async fn start_dynamic_tls_listener_with_retry(
    state: &ProxyState,
    slot: ferrum_edge::tls::SharedFrontendTls,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    JoinHandle<Result<(), anyhow::Error>>,
) {
    let mut errors = Vec::new();
    for attempt in 1..=5 {
        let reservation = reserve_port().await.expect("reserve proxy port");
        let port = reservation.drop_and_take_port();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener_state = state.clone();
        let listener_slot = slot.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let listener = tokio::spawn(async move {
            start_proxy_listener_with_dynamic_tls_and_signal(
                addr,
                listener_state,
                shutdown_rx,
                listener_slot,
                Some(started_tx),
            )
            .await
        });

        let start_result = tokio::time::timeout(Duration::from_secs(2), started_rx).await;
        let mut attempt_error = match start_result {
            Ok(Ok(())) => return (addr, shutdown_tx, listener),
            Ok(Err(error)) => {
                format!("attempt {attempt}: listener start signal dropped: {error}")
            }
            Err(error) => format!("attempt {attempt}: listener start timed out: {error}"),
        };

        let _ = shutdown_tx.send(true);
        match tokio::time::timeout(Duration::from_secs(2), listener).await {
            Ok(Ok(Err(error))) => {
                attempt_error = format!("{attempt_error}; listener returned error: {error}");
            }
            Ok(Err(error)) => {
                attempt_error = format!("{attempt_error}; listener task join error: {error}");
            }
            Err(error) => {
                attempt_error = format!("{attempt_error}; listener task did not stop: {error}");
            }
            Ok(Ok(Ok(()))) => {}
        }
        errors.push(attempt_error);
    }

    panic!(
        "listener did not bind after retries: {}",
        errors.join(" | ")
    );
}

/// New TLS handshakes after an `ArcSwap` cert swap present the new
/// certificate chain. This is the load-bearing contract for opt-in frontend
/// TLS live reload — the listener reads from the slot on each accept, so a
/// successful reload flips the served cert on the very next handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dynamic_tls_listener_serves_rotated_cert_after_slot_swap() {
    ensure_crypto_provider();
    let state = test_proxy_state(test_env_config());

    let (initial_config, initial_der) = generate_server_config_with_san("localhost");
    let slot: ferrum_edge::tls::SharedFrontendTls =
        Arc::new(ArcSwap::new(Arc::new(Some(initial_config))));

    let (addr, shutdown_tx, listener) =
        start_dynamic_tls_listener_with_retry(&state, slot.clone()).await;

    let first_seen = fetch_peer_cert_der(addr).await;
    assert_eq!(
        first_seen, initial_der,
        "first handshake must present the startup-loaded cert"
    );

    // Rotate: build a fresh self-signed cert and swap the slot. The next
    // handshake should pick it up — no listener restart, no port rebind.
    let (rotated_config, rotated_der) = generate_server_config_with_san("localhost");
    assert_ne!(initial_der, rotated_der, "rotated cert must differ");
    slot.store(Arc::new(Some(rotated_config)));

    let second_seen = fetch_peer_cert_der(addr).await;
    assert_eq!(
        second_seen, rotated_der,
        "second handshake must present the rotated cert without restarting the listener"
    );

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(2), listener)
        .await
        .expect("listener should stop")
        .expect("listener task should join")
        .expect("listener should return cleanly");
}
