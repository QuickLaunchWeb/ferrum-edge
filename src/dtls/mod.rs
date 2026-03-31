//! DTLS 1.2/1.3 support for UDP stream proxies.
//!
//! Provides async wrappers around the `dimpl` Sans-IO DTLS state machine for:
//! - **Backend connections** (gateway → backend): `DtlsConnection` wraps a single
//!   client-role DTLS session over a connected `UdpSocket`.
//! - **Frontend termination** (client → gateway): `DtlsServer` demultiplexes
//!   incoming UDP datagrams by source address and manages per-client DTLS sessions.
//!
//! The `dimpl` crate supports DTLS 1.2 + 1.3 (RFC 9147) with ECDSA P-256/P-384 keys.
//! It uses a Sans-IO design where the caller drives the state machine via
//! `handle_packet()` / `poll_output()` / `handle_timeout()`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dimpl::{Config, Dtls, DtlsCertificate, Output};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::config::types::Proxy;

/// Default MTU for DTLS records. Conservative default that works over most networks.
#[allow(dead_code)]
const DEFAULT_MTU: usize = 1200;

/// Reusable output buffer size for `poll_output()`. Must be >= MTU + record overhead.
const OUTPUT_BUF_SIZE: usize = 2048;

/// Maximum datagrams to drain per `poll_output` loop before yielding.
const MAX_OUTPUTS_PER_DRAIN: usize = 64;

// ============================================================================
// Configuration Builders
// ============================================================================

/// Frontend DTLS server configuration (client → gateway).
pub struct FrontendDtlsConfig {
    pub dimpl_config: Arc<Config>,
    pub certificate: DtlsCertificate,
    pub require_client_cert: bool,
    /// DER-encoded trusted CA certificates for client cert validation.
    pub client_ca_certs: Vec<Vec<u8>>,
}

/// Build a DTLS client config for backend connections (gateway → backend).
///
/// Maps the proxy's `backend_tls_*` fields to dimpl `Config`:
/// - `backend_tls_server_ca_cert_path` → used for peer cert validation callback
/// - `backend_tls_client_cert_path` + `backend_tls_client_key_path` → client certificate
///
/// Returns `(config, certificate, trusted_ca_certs, skip_verify)`.
pub fn build_backend_dtls_config(
    proxy: &Proxy,
    _backend_host: &str,
    tls_no_verify: bool,
) -> Result<BackendDtlsParams, anyhow::Error> {
    let skip_verify = !proxy.backend_tls_verify_server_cert || tls_no_verify;

    // Load client certificate for mutual TLS, or generate an ephemeral one.
    let certificate = if let (Some(cert_path), Some(key_path)) = (
        &proxy.backend_tls_client_cert_path,
        &proxy.backend_tls_client_key_path,
    ) {
        load_dtls_certificate(cert_path, key_path)?
    } else {
        generate_ephemeral_cert()?
    };

    // Load root CAs for server cert verification
    let mut trusted_cas = Vec::new();
    if let Some(ca_path) = &proxy.backend_tls_server_ca_cert_path {
        trusted_cas = load_der_certs_from_pem(ca_path)?;
    }

    let config = Arc::new(Config::default());

    debug!(
        proxy_id = %proxy.id,
        skip_verify = skip_verify,
        "Built DTLS backend client config (dimpl)"
    );

    Ok(BackendDtlsParams {
        config,
        certificate,
        trusted_cas,
        skip_verify,
    })
}

/// Parameters for creating a backend DTLS connection.
pub struct BackendDtlsParams {
    pub config: Arc<Config>,
    pub certificate: DtlsCertificate,
    pub trusted_cas: Vec<Vec<u8>>,
    pub skip_verify: bool,
}

/// Build a DTLS server config for frontend termination (client → gateway).
///
/// Requires ECDSA P-256 or P-384 certificates.
pub fn build_frontend_dtls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_cert_path: Option<&str>,
) -> Result<FrontendDtlsConfig, anyhow::Error> {
    let certificate = load_dtls_certificate(cert_path, key_path)?;

    let (require_client_cert, client_ca_certs) = if let Some(ca_path) = client_ca_cert_path {
        let certs = load_der_certs_from_pem(ca_path)?;
        if certs.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid certificates found in DTLS client CA file: {}",
                ca_path
            ));
        }
        debug!(
            ca_path = %ca_path,
            "Frontend DTLS mTLS enabled: requiring and verifying client certificates"
        );
        (true, certs)
    } else {
        (false, Vec::new())
    };

    let mut config_builder = Config::builder();
    if require_client_cert {
        config_builder = config_builder.require_client_certificate(true);
    }
    let config = Arc::new(
        config_builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build DTLS config: {}", e))?,
    );

    Ok(FrontendDtlsConfig {
        dimpl_config: config,
        certificate,
        require_client_cert,
        client_ca_certs,
    })
}

// ============================================================================
// DtlsConnection — async wrapper for a single DTLS session (client role)
// ============================================================================

/// An async DTLS connection wrapping a connected `UdpSocket`.
///
/// Drives the dimpl Sans-IO state machine on a dedicated tokio task, exposing
/// simple `send()` / `recv()` / `close()` methods. Data is exchanged via channels
/// to avoid locking the state machine on the hot path.
pub struct DtlsConnection {
    /// Send application data to the DTLS engine for encryption + transmission.
    app_tx: mpsc::Sender<Vec<u8>>,
    /// Receive decrypted application data from the DTLS engine.
    app_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Signal the driver task to shut down.
    _shutdown_tx: mpsc::Sender<()>,
}

impl DtlsConnection {
    /// Perform a DTLS client handshake over the given connected socket and return
    /// an established `DtlsConnection`.
    pub async fn connect(
        socket: UdpSocket,
        params: BackendDtlsParams,
    ) -> Result<Self, anyhow::Error> {
        let socket = Arc::new(socket);
        let skip_verify = params.skip_verify;
        let trusted_cas = params.trusted_cas;
        let mut dtls = Dtls::new_auto(params.config, params.certificate, Instant::now());
        dtls.set_active(true); // client role

        // Drive handshake to completion
        let mut out_buf = vec![0u8; OUTPUT_BUF_SIZE];
        let mut recv_buf = vec![0u8; 65536];
        let mut next_timeout: Option<Instant> = None;

        // Kick off the handshake by draining initial outputs (ClientHello + Timeout)
        drain_handshake_outputs(
            &mut dtls,
            &mut out_buf,
            &socket,
            None,
            &mut next_timeout,
            skip_verify,
            &trusted_cas,
        )
        .await?;

        let handshake_deadline = Instant::now() + Duration::from_secs(10);

        loop {
            if Instant::now() > handshake_deadline {
                return Err(anyhow::anyhow!("DTLS handshake timed out"));
            }

            let sleep_dur = next_timeout
                .map(|t| t.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(1));

            tokio::select! {
                result = socket.recv(&mut recv_buf) => {
                    let len = result.map_err(|e| anyhow::anyhow!("UDP recv during handshake: {}", e))?;
                    if let Err(e) = dtls.handle_packet(&recv_buf[..len]) {
                        return Err(anyhow::anyhow!("DTLS handshake packet error: {}", e));
                    }
                }
                _ = tokio::time::sleep(sleep_dur) => {
                    if let Some(t) = next_timeout
                        && Instant::now() >= t
                    {
                        if let Err(e) = dtls.handle_timeout(Instant::now()) {
                            return Err(anyhow::anyhow!("DTLS handshake timeout error: {}", e));
                        }
                        next_timeout = None;
                    }
                }
            }

            // Drain outputs — check for Connected, validate peer cert
            let connected = drain_handshake_outputs(
                &mut dtls,
                &mut out_buf,
                &socket,
                None,
                &mut next_timeout,
                skip_verify,
                &trusted_cas,
            )
            .await?;

            if connected {
                return Ok(Self::spawn_driver(dtls, socket));
            }
        }
    }

    /// Spawn the background driver task and return the connection handle.
    fn spawn_driver(dtls: Dtls, socket: Arc<UdpSocket>) -> Self {
        // Channels: app data in/out, shutdown signal
        let (app_tx, mut driver_app_rx) = mpsc::channel::<Vec<u8>>(256);
        let (driver_app_tx, app_rx) = mpsc::channel::<Vec<u8>>(256);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        tokio::spawn(async move {
            let mut dtls = dtls;
            let mut out_buf = vec![0u8; OUTPUT_BUF_SIZE];
            let mut recv_buf = vec![0u8; 65536];
            let mut next_timeout: Option<Instant> = None;

            loop {
                let sleep_dur = next_timeout
                    .map(|t| t.saturating_duration_since(Instant::now()))
                    .unwrap_or(Duration::from_secs(60));

                tokio::select! {
                    // Incoming UDP datagram from peer
                    result = socket.recv(&mut recv_buf) => {
                        match result {
                            Ok(len) => {
                                if let Err(e) = dtls.handle_packet(&recv_buf[..len]) {
                                    trace!("DTLS handle_packet error: {}", e);
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    // Application data to send
                    Some(data) = driver_app_rx.recv() => {
                        if let Err(e) = dtls.send_application_data(&data) {
                            trace!("DTLS send_application_data error: {}", e);
                            break;
                        }
                    }
                    // Timer fired
                    _ = tokio::time::sleep(sleep_dur) => {
                        if let Some(t) = next_timeout
                            && Instant::now() >= t
                        {
                            if let Err(e) = dtls.handle_timeout(Instant::now()) {
                                trace!("DTLS handle_timeout error: {}", e);
                                break;
                            }
                            next_timeout = None;
                        }
                    }
                    // Shutdown requested
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }

                // Drain all pending outputs (break on Timeout — it repeats forever)
                for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                    match dtls.poll_output(&mut out_buf) {
                        Output::Packet(data) => {
                            let _ = socket.send(data).await;
                        }
                        Output::Timeout(t) => {
                            next_timeout = Some(t);
                            break;
                        }
                        Output::ApplicationData(data) => {
                            if driver_app_tx.send(data.to_vec()).await.is_err() {
                                return; // receiver dropped
                            }
                        }
                        Output::Connected | Output::PeerCert(_) => {
                            // Already handled during handshake
                        }
                        _ => break,
                    }
                }
            }
        });

        Self {
            app_tx,
            app_rx: tokio::sync::Mutex::new(app_rx),
            _shutdown_tx: shutdown_tx,
        }
    }

    /// Send application data through the DTLS tunnel.
    pub async fn send(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.app_tx
            .send(data.to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("DTLS connection closed"))
    }

    /// Receive decrypted application data from the DTLS tunnel.
    pub async fn recv(&self) -> Result<Vec<u8>, anyhow::Error> {
        let mut rx = self.app_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("DTLS connection closed"))
    }

    /// Gracefully shut down the DTLS connection.
    pub async fn close(&self) {
        // Dropping _shutdown_tx signals the driver to stop
        // (it will exit when the channel closes)
    }
}

// ============================================================================
// DtlsServer — frontend DTLS session demuxer
// ============================================================================

/// A DTLS server that manages multiple client sessions on a single UDP socket.
///
/// Demultiplexes incoming UDP datagrams by source address, creating a new `Dtls`
/// state machine for each new client. Accepted connections are delivered via
/// a channel as `DtlsServerConn` instances.
pub struct DtlsServer {
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
    certificate: DtlsCertificate,
    sessions: Arc<DashMap<SocketAddr, DtlsSessionState>>,
    /// Channel to deliver accepted (post-handshake) connections.
    accept_tx: mpsc::Sender<(DtlsServerConn, SocketAddr)>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<(DtlsServerConn, SocketAddr)>>,
    require_client_cert: bool,
    client_ca_certs: Arc<Vec<Vec<u8>>>,
}

/// State for a server-side DTLS session being managed by the DtlsServer.
struct DtlsSessionState {
    /// Send incoming UDP data to this session's driver task.
    incoming_tx: mpsc::Sender<Vec<u8>>,
}

/// A server-side DTLS connection for a single accepted client.
///
/// Provides `send()` / `recv()` / `close()` similar to `DtlsConnection`.
/// The send side is cloneable (via `clone_sender()`) so bidirectional forwarding
/// tasks can each hold a sender.
pub struct DtlsServerConn {
    /// Send application data to the DTLS engine for encryption.
    app_tx: mpsc::Sender<Vec<u8>>,
    /// Receive decrypted application data.
    app_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
}

/// A cloneable sender half of a `DtlsServerConn`, used to send data back to
/// the DTLS client from a separate task (e.g., backend→client forwarding).
pub struct DtlsServerSender {
    app_tx: mpsc::Sender<Vec<u8>>,
}

impl DtlsServerSender {
    /// Send application data through the DTLS tunnel to this client.
    pub async fn send(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.app_tx
            .send(data.to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("DTLS server connection closed"))
    }
}

impl DtlsServerConn {
    /// Send application data through the DTLS tunnel to this client.
    #[allow(dead_code)]
    pub async fn send(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.app_tx
            .send(data.to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("DTLS server connection closed"))
    }

    /// Receive decrypted application data from this client.
    pub async fn recv(&self) -> Result<Vec<u8>, anyhow::Error> {
        let mut rx = self.app_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("DTLS server connection closed"))
    }

    /// Get a cloneable sender for this connection, allowing another task
    /// to send data back to the client independently.
    pub fn clone_sender(&self) -> DtlsServerSender {
        DtlsServerSender {
            app_tx: self.app_tx.clone(),
        }
    }

    /// Close this client's DTLS connection.
    pub async fn close(&self) {
        // Dropping app_tx causes the driver to see channel closed and exit
    }
}

impl DtlsServer {
    /// Create a new DTLS server bound to the given address.
    pub async fn bind(
        addr: SocketAddr,
        frontend_config: FrontendDtlsConfig,
    ) -> Result<Self, anyhow::Error> {
        let socket = Arc::new(
            UdpSocket::bind(addr)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to bind DTLS server on {}: {}", addr, e))?,
        );

        let (accept_tx, accept_rx) = mpsc::channel(256);

        Ok(Self {
            socket,
            config: frontend_config.dimpl_config,
            certificate: frontend_config.certificate,
            sessions: Arc::new(DashMap::new()),
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            require_client_cert: frontend_config.require_client_cert,
            client_ca_certs: Arc::new(frontend_config.client_ca_certs),
        })
    }

    /// Get the local address this server is bound to.
    #[allow(dead_code)] // Used by integration tests
    pub fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .expect("DTLS server socket has no local address")
    }

    /// Accept the next fully-handshaked DTLS client connection.
    ///
    /// Returns the connection handle and the client's socket address.
    pub async fn accept(&self) -> Result<(DtlsServerConn, SocketAddr), anyhow::Error> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("DTLS server shut down"))
    }

    /// Run the DTLS server recv loop. Call this in a spawned task.
    ///
    /// Reads UDP datagrams, demuxes by source address, and drives per-client
    /// DTLS state machines. New clients are delivered via `accept()`.
    pub async fn run(&self) -> Result<(), anyhow::Error> {
        let mut buf = vec![0u8; 65536];
        loop {
            let (len, peer_addr) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("DTLS server recv error: {}", e))?;

            let data = buf[..len].to_vec();

            if let Some(session) = self.sessions.get(&peer_addr) {
                // Existing session — forward packet to its driver
                if session.incoming_tx.send(data).await.is_err() {
                    // Driver task exited — remove stale session
                    drop(session);
                    self.sessions.remove(&peer_addr);
                }
            } else {
                // New client — spawn a session driver
                self.spawn_session(peer_addr, data);
            }
        }
    }

    /// Spawn a driver task for a new client session.
    fn spawn_session(&self, peer_addr: SocketAddr, initial_packet: Vec<u8>) {
        let (incoming_tx, mut incoming_rx) = mpsc::channel::<Vec<u8>>(256);
        let (app_out_tx, app_out_rx) = mpsc::channel::<Vec<u8>>(256);
        let mut app_out_rx = Some(app_out_rx);
        let (app_in_tx, mut app_in_rx) = mpsc::channel::<Vec<u8>>(256);

        self.sessions.insert(
            peer_addr,
            DtlsSessionState {
                incoming_tx: incoming_tx.clone(),
            },
        );

        let socket = self.socket.clone();
        let config = self.config.clone();
        let certificate = self.certificate.clone();
        let accept_tx = self.accept_tx.clone();
        let sessions = self.sessions.clone();
        let require_client_cert = self.require_client_cert;
        let client_ca_certs = self.client_ca_certs.clone();

        tokio::spawn(async move {
            let mut dtls = Dtls::new_12(config, certificate, Instant::now());
            // Server role (default — is_active=false)
            // Initialize server state (random, etc.) — required before handle_packet.
            // Drain the resulting Timeout outputs so they don't interfere with the
            // post-ClientHello drain.
            let _ = dtls.handle_timeout(Instant::now());

            let mut out_buf = vec![0u8; OUTPUT_BUF_SIZE];
            let mut next_timeout: Option<Instant> = None;
            let mut connected = false;

            // Drain init outputs (just Timeout from handle_timeout)
            for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                if let Output::Timeout(t) = dtls.poll_output(&mut out_buf) {
                    next_timeout = Some(t);
                    break;
                }
            }

            // Process the initial ClientHello packet
            if let Err(e) = dtls.handle_packet(&initial_packet) {
                warn!(client = %peer_addr, "DTLS initial packet error: {}", e);
                sessions.remove(&peer_addr);
                return;
            }

            // Drain initial handshake outputs (ServerHello, etc.)
            match drain_server_outputs(
                &mut dtls,
                &mut out_buf,
                &socket,
                peer_addr,
                &mut next_timeout,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    warn!(client = %peer_addr, "DTLS initial drain error: {}", e);
                    sessions.remove(&peer_addr);
                    return;
                }
            }

            loop {
                let sleep_dur = next_timeout
                    .map(|t| t.saturating_duration_since(Instant::now()))
                    .unwrap_or(Duration::from_secs(60));

                tokio::select! {
                    // Incoming UDP packet from this client (demuxed by the server)
                    Some(data) = incoming_rx.recv() => {
                        if let Err(e) = dtls.handle_packet(&data) {
                            trace!(client = %peer_addr, "DTLS handle_packet error: {}", e);
                            break;
                        }
                    }
                    // Application data to send back to this client
                    Some(data) = app_in_rx.recv(), if connected => {
                        if let Err(e) = dtls.send_application_data(&data) {
                            trace!(client = %peer_addr, "DTLS send error: {}", e);
                            break;
                        }
                    }
                    // Timer fired
                    _ = tokio::time::sleep(sleep_dur) => {
                        if let Some(t) = next_timeout
                            && Instant::now() >= t
                        {
                            if let Err(e) = dtls.handle_timeout(Instant::now()) {
                                trace!(client = %peer_addr, "DTLS timeout error: {}", e);
                                break;
                            }
                            next_timeout = None;
                        }
                    }
                }

                // Drain all pending outputs. After Connected, skip one Timeout
                // to capture final flight packets (dimpl emits Connected before
                // flushing CCS+Finished).
                let mut just_connected = false;
                for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                    match dtls.poll_output(&mut out_buf) {
                        Output::Packet(data) => {
                            let _ = socket.send_to(data, peer_addr).await;
                        }
                        Output::Timeout(t) => {
                            next_timeout = Some(t);
                            if just_connected {
                                just_connected = false;
                                continue;
                            }
                            break;
                        }
                        Output::Connected => {
                            just_connected = true;
                            connected = true;
                            // Deliver accepted connection (take app_out_rx — only happens once)
                            let Some(rx) = app_out_rx.take() else {
                                continue; // Already connected — should not happen
                            };
                            let conn = DtlsServerConn {
                                app_tx: app_in_tx.clone(),
                                app_rx: tokio::sync::Mutex::new(rx),
                            };
                            if accept_tx.send((conn, peer_addr)).await.is_err() {
                                // Server shut down
                                sessions.remove(&peer_addr);
                                return;
                            }
                        }
                        Output::PeerCert(der) => {
                            if require_client_cert
                                && let Err(e) = validate_peer_cert(der, &client_ca_certs)
                            {
                                warn!(client = %peer_addr, "Client cert validation failed: {}", e);
                                sessions.remove(&peer_addr);
                                return;
                            }
                        }
                        Output::ApplicationData(data) => {
                            if app_out_tx.send(data.to_vec()).await.is_err() {
                                // Application receiver dropped
                                break;
                            }
                        }
                        _ => {
                            // KeyingMaterial or future variants — continue draining
                        }
                    }
                }
            }

            sessions.remove(&peer_addr);
        });
    }

    /// Shut down the server (close underlying socket).
    pub async fn close(&self) {
        // Dropping the DtlsServer will clean up — sessions will see channel closures
    }
}

// ============================================================================
// Certificate Loading
// ============================================================================

/// Load a DTLS certificate from PEM files and convert to DER for dimpl.
///
/// Supports ECDSA P-256 and P-384 private keys. Ed25519 is NOT supported
/// by dimpl for DTLS signatures (unlike the previous webrtc-dtls library).
fn load_dtls_certificate(
    cert_path: &str,
    key_path: &str,
) -> Result<DtlsCertificate, anyhow::Error> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("Failed to read DTLS cert {}: {}", cert_path, e))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to read DTLS key {}: {}", key_path, e))?;

    // Parse PEM to DER
    let cert_der = rustls_pemfile::certs(&mut &cert_pem[..])
        .next()
        .ok_or_else(|| anyhow::anyhow!("No certificate found in {}", cert_path))?
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate PEM: {}", e))?;

    let key_der = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| anyhow::anyhow!("Failed to parse private key PEM: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;

    Ok(DtlsCertificate {
        certificate: cert_der.to_vec(),
        private_key: key_der.secret_der().to_vec(),
    })
}

/// Load DER-encoded certificates from a PEM file (for CA trust stores).
fn load_der_certs_from_pem(pem_path: &str) -> Result<Vec<Vec<u8>>, anyhow::Error> {
    let pem_data = std::fs::read(pem_path)
        .map_err(|e| anyhow::anyhow!("Failed to read PEM file {}: {}", pem_path, e))?;
    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut &pem_data[..])
        .filter_map(|r| r.ok())
        .map(|c| c.to_vec())
        .collect();
    Ok(certs)
}

/// Generate an ephemeral self-signed certificate for DTLS clients that don't
/// need client authentication (the common case for backend connections).
fn generate_ephemeral_cert() -> Result<DtlsCertificate, anyhow::Error> {
    dimpl::certificate::generate_self_signed_certificate()
        .map_err(|e| anyhow::anyhow!("Failed to generate ephemeral DTLS cert: {}", e))
}

/// Generate a self-signed DTLS certificate for testing.
#[allow(dead_code)]
pub fn generate_self_signed_cert() -> Result<DtlsCertificate, anyhow::Error> {
    generate_ephemeral_cert()
}

// ============================================================================
// Certificate Validation
// ============================================================================

/// Validate a peer's DER-encoded leaf certificate against trusted CA certs.
///
/// This is a basic fingerprint-based validation: the peer cert must match one
/// of the trusted CA certificates. For production mTLS, you may want full
/// chain validation using webpki.
fn validate_peer_cert(peer_der: &[u8], trusted_cas: &[Vec<u8>]) -> Result<(), anyhow::Error> {
    if trusted_cas.is_empty() {
        // No trusted CAs configured — accept any cert (skip_verify mode)
        return Ok(());
    }

    // Check if the peer cert matches any trusted CA cert directly
    // (self-signed or direct trust model)
    for ca in trusted_cas {
        if peer_der == ca.as_slice() {
            return Ok(());
        }
    }

    // Issuer-based validation using x509-parser: check if the peer cert's issuer
    // matches any trusted CA's subject. The cryptographic signature verification
    // happens at the DTLS handshake layer (dimpl validates the cert chain internally
    // when a CryptoProvider is configured).
    let (_, peer_cert) = x509_parser::parse_x509_certificate(peer_der)
        .map_err(|e| anyhow::anyhow!("Failed to parse peer certificate: {}", e))?;

    for ca_der in trusted_cas {
        if let Ok((_, ca_cert)) = x509_parser::parse_x509_certificate(ca_der)
            && peer_cert.issuer() == ca_cert.subject()
        {
            return Ok(());
        }
    }

    Err(anyhow::anyhow!(
        "Peer certificate not signed by any trusted CA"
    ))
}

// ============================================================================
// Sans-IO Helpers
// ============================================================================

/// Drain `poll_output()` during a client-side handshake. Sends packets via
/// a connected socket, captures the retransmit timeout, validates peer cert.
/// Returns `true` when `Output::Connected` is observed (handshake complete).
///
/// **Important dimpl behavior**: `poll_output()` returns `Timeout` repeatedly
/// once all actionable outputs are drained, so we normally break on the first
/// `Timeout`. However, dimpl emits `Connected` from a local event queue BEFORE
/// flushing the final handshake flight packets (CCS+Finished). So after seeing
/// `Connected`, we must skip one Timeout and keep draining to capture those
/// final packets.
async fn drain_handshake_outputs(
    dtls: &mut Dtls,
    out_buf: &mut [u8],
    socket: &UdpSocket,
    peer: Option<SocketAddr>,
    next_timeout: &mut Option<Instant>,
    skip_verify: bool,
    trusted_cas: &[Vec<u8>],
) -> Result<bool, anyhow::Error> {
    let mut connected = false;
    let mut saw_timeout_after_connected = false;
    for _ in 0..MAX_OUTPUTS_PER_DRAIN {
        match dtls.poll_output(out_buf) {
            Output::Packet(data) => {
                if let Some(addr) = peer {
                    socket
                        .send_to(data, addr)
                        .await
                        .map_err(|e| anyhow::anyhow!("UDP send_to: {}", e))?;
                } else {
                    socket
                        .send(data)
                        .await
                        .map_err(|e| anyhow::anyhow!("UDP send: {}", e))?;
                }
            }
            Output::Timeout(t) => {
                *next_timeout = Some(t);
                // After Connected, dimpl may emit Timeout before final flight
                // packets. Skip one Timeout, then break on the next.
                if connected && !saw_timeout_after_connected {
                    saw_timeout_after_connected = true;
                    continue;
                }
                break;
            }
            Output::Connected => {
                connected = true;
            }
            Output::PeerCert(der) => {
                if !skip_verify {
                    validate_peer_cert(der, trusted_cas)?;
                }
            }
            Output::ApplicationData(_) => {
                // Unexpected during handshake but not fatal
            }
            _ => {
                // KeyingMaterial or future non_exhaustive variants — continue draining
            }
        }
    }
    Ok(connected)
}

/// Drain `poll_output()` and send packets to a specific peer address (for server-side).
/// Captures the retransmit timeout. Returns `true` on `Connected`.
/// Same Timeout-skipping logic as `drain_handshake_outputs` for post-Connected packets.
async fn drain_server_outputs(
    dtls: &mut Dtls,
    out_buf: &mut [u8],
    socket: &UdpSocket,
    peer: SocketAddr,
    next_timeout: &mut Option<Instant>,
) -> Result<bool, anyhow::Error> {
    let mut connected = false;
    let mut saw_timeout_after_connected = false;
    for _ in 0..MAX_OUTPUTS_PER_DRAIN {
        match dtls.poll_output(out_buf) {
            Output::Packet(data) => {
                socket
                    .send_to(data, peer)
                    .await
                    .map_err(|e| anyhow::anyhow!("UDP send_to: {}", e))?;
            }
            Output::Timeout(t) => {
                *next_timeout = Some(t);
                if connected && !saw_timeout_after_connected {
                    saw_timeout_after_connected = true;
                    continue;
                }
                break;
            }
            Output::Connected => {
                connected = true;
            }
            Output::PeerCert(_) | Output::ApplicationData(_) => {}
            _ => {
                // KeyingMaterial or future variants — continue draining
            }
        }
    }
    Ok(connected)
}
