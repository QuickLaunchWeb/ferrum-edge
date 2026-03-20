//! gRPC reverse proxy handler using hyper's HTTP/2 client directly.
//!
//! Unlike the standard HTTP proxy path (which uses reqwest and may drop trailers),
//! this module uses hyper's HTTP/2 client to get:
//! - HTTP/2 trailer forwarding (`grpc-status`, `grpc-message`)
//! - h2c (cleartext HTTP/2) via prior knowledge handshake
//! - Proper gRPC error responses when the backend is unavailable
//!
//! gRPC metadata maps to HTTP/2 headers, so existing auth plugins work unchanged.

use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::BodyExt;
use hyper::Request;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, error, warn};

use crate::config::types::{BackendProtocol, Proxy};
use crate::dns::DnsCache;

/// gRPC-specific HTTP/2 connection pool.
///
/// Manages reusable HTTP/2 connections to gRPC backends. Unlike the reqwest-based
/// `ConnectionPool`, this uses hyper's HTTP/2 client directly to support h2c
/// (cleartext HTTP/2) and trailer forwarding.
pub struct GrpcConnectionPool {
    /// Cached sender handles keyed by `host:port:tls`
    senders: DashMap<String, http2::SendRequest<Incoming>>,
}

impl Default for GrpcConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl GrpcConnectionPool {
    pub fn new() -> Self {
        Self {
            senders: DashMap::new(),
        }
    }

    fn pool_key(proxy: &Proxy) -> String {
        let tls = matches!(proxy.backend_protocol, BackendProtocol::Grpcs);
        format!("{}:{}:{}", proxy.backend_host, proxy.backend_port, tls)
    }

    /// Get or create an HTTP/2 connection to the gRPC backend.
    pub async fn get_sender(
        &self,
        proxy: &Proxy,
        dns_cache: &DnsCache,
    ) -> Result<http2::SendRequest<Incoming>, GrpcProxyError> {
        let key = Self::pool_key(proxy);

        // Try to reuse existing connection
        if let Some(sender) = self.senders.get(&key) {
            if !sender.is_closed() {
                return Ok(sender.clone());
            }
            // Connection is closed, remove it
            drop(sender);
            self.senders.remove(&key);
        }

        // Create a new connection
        let sender = self.create_connection(proxy, dns_cache).await?;
        self.senders.insert(key, sender.clone());
        Ok(sender)
    }

    async fn create_connection(
        &self,
        proxy: &Proxy,
        dns_cache: &DnsCache,
    ) -> Result<http2::SendRequest<Incoming>, GrpcProxyError> {
        let host = &proxy.backend_host;
        let port = proxy.backend_port;

        // Resolve backend hostname via DNS cache
        let target_host = match dns_cache
            .resolve(
                host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
            .await
        {
            Ok(ip) => ip.to_string(),
            Err(_) => host.clone(),
        };

        let addr = format!("{}:{}", target_host, port);
        let tcp = TcpStream::connect(&addr).await.map_err(|e| {
            warn!("gRPC: failed to connect to backend {}: {}", addr, e);
            GrpcProxyError::BackendUnavailable(format!("Connection refused: {}", e))
        })?;

        // Disable Nagle for lower latency
        let _ = tcp.set_nodelay(true);

        let use_tls = matches!(proxy.backend_protocol, BackendProtocol::Grpcs);

        if use_tls {
            self.create_tls_connection(tcp, host, proxy).await
        } else {
            self.create_h2c_connection(tcp).await
        }
    }

    /// Create an h2c (cleartext HTTP/2) connection using prior knowledge.
    async fn create_h2c_connection(
        &self,
        tcp: TcpStream,
    ) -> Result<http2::SendRequest<Incoming>, GrpcProxyError> {
        let io = TokioIo::new(tcp);
        let (sender, conn) = http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| {
                GrpcProxyError::BackendUnavailable(format!("h2c handshake failed: {}", e))
            })?;

        // Spawn the connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("gRPC h2c connection closed: {}", e);
            }
        });

        Ok(sender)
    }

    /// Create an h2 (TLS) connection with ALPN negotiation.
    async fn create_tls_connection(
        &self,
        tcp: TcpStream,
        host: &str,
        proxy: &Proxy,
    ) -> Result<http2::SendRequest<Incoming>, GrpcProxyError> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();

        // Force HTTP/2 via ALPN
        tls_config.alpn_protocols = vec![b"h2".to_vec()];

        if !proxy.backend_tls_verify_server_cert {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification));
        }

        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
            GrpcProxyError::BackendUnavailable(format!("Invalid server name: {}", e))
        })?;

        let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
            GrpcProxyError::BackendUnavailable(format!("TLS handshake failed: {}", e))
        })?;

        let io = TokioIo::new(tls_stream);
        let (sender, conn) = http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| {
                GrpcProxyError::BackendUnavailable(format!("h2 handshake failed: {}", e))
            })?;

        // Spawn the connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("gRPC h2 TLS connection closed: {}", e);
            }
        });

        Ok(sender)
    }
}

/// Dangerous: skip TLS certificate verification (for testing or self-signed certs).
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Errors specific to gRPC proxying.
#[derive(Debug)]
pub enum GrpcProxyError {
    BackendUnavailable(String),
    BackendTimeout(String),
    Internal(String),
}

/// gRPC status codes for gateway-generated errors.
#[allow(dead_code)]
pub mod grpc_status {
    pub const OK: u32 = 0;
    pub const DEADLINE_EXCEEDED: u32 = 4;
    pub const RESOURCE_EXHAUSTED: u32 = 8;
    pub const UNIMPLEMENTED: u32 = 12;
    pub const UNAVAILABLE: u32 = 14;
    pub const UNAUTHENTICATED: u32 = 16;
}

/// Build a gRPC error response with proper Trailers-Only encoding.
///
/// gRPC errors use HTTP 200 with `grpc-status` and `grpc-message` as headers
/// (Trailers-Only responses pack trailers into the header block).
pub fn build_grpc_error_response(
    status: u32,
    message: &str,
) -> hyper::Response<http_body_util::Full<Bytes>> {
    hyper::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("grpc-status", status.to_string())
        .header("grpc-message", message)
        .body(http_body_util::Full::new(Bytes::new()))
        .unwrap()
}

/// Collected gRPC response with body and trailers.
pub struct GrpcResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    /// Trailers (grpc-status, grpc-message, etc.) forwarded from backend
    pub trailers: HashMap<String, String>,
}

/// Proxy a gRPC request to the backend using hyper's HTTP/2 client.
///
/// Collects the response body and trailers from the backend, returning them
/// in a `GrpcResponse` that the caller can pack into the final HTTP/2 response
/// with trailers forwarded as headers (Trailers-Only encoding).
pub async fn proxy_grpc_request(
    req: Request<Incoming>,
    proxy: &Proxy,
    backend_url: &str,
    grpc_pool: &GrpcConnectionPool,
    dns_cache: &DnsCache,
    proxy_headers: &HashMap<String, String>,
) -> Result<GrpcResponse, GrpcProxyError> {
    // Get or create HTTP/2 connection to backend
    let mut sender = grpc_pool.get_sender(proxy, dns_cache).await?;

    // If the cached sender is closed, remove and reconnect
    if sender.is_closed() {
        let key = GrpcConnectionPool::pool_key(proxy);
        grpc_pool.senders.remove(&key);
        sender = grpc_pool.get_sender(proxy, dns_cache).await?;
    }

    // Parse the backend URL to extract path and authority
    let uri: hyper::Uri = backend_url
        .parse()
        .map_err(|e| GrpcProxyError::Internal(format!("Invalid backend URL: {}", e)))?;

    // Build the backend request preserving method, path, and gRPC headers
    let (mut parts, body) = req.into_parts();

    // Set the full URI including scheme and authority for HTTP/2 pseudo-headers
    parts.uri = uri;

    // Clear hop-by-hop headers
    parts.headers.remove("connection");
    parts.headers.remove("transfer-encoding");

    // Apply proxy headers from the plugin pipeline (before_proxy transformations)
    for (k, v) in proxy_headers {
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            parts.headers.insert(name, val);
        }
    }

    let backend_req = Request::from_parts(parts, body);

    // Send to backend
    let response = sender.send_request(backend_req).await.map_err(|e| {
        error!("gRPC: backend request failed: {}", e);
        if e.is_timeout() {
            GrpcProxyError::BackendTimeout(format!("Backend timeout: {}", e))
        } else {
            GrpcProxyError::BackendUnavailable(format!("Backend error: {}", e))
        }
    })?;

    // Extract response status and headers
    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (k, v) in response.headers() {
        if let Ok(vs) = v.to_str() {
            headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }

    // Collect body and extract trailers
    let mut body_bytes = Vec::new();
    let mut trailers = HashMap::new();

    let mut body = response.into_body();
    while let Some(frame_result) = body.frame().await {
        match frame_result {
            Ok(frame) => {
                if let Some(data) = frame.data_ref() {
                    body_bytes.extend_from_slice(data);
                } else if let Ok(trailer_map) = frame.into_trailers() {
                    for (k, v) in &trailer_map {
                        if let Ok(vs) = v.to_str() {
                            trailers.insert(k.as_str().to_string(), vs.to_string());
                        }
                    }
                }
            }
            Err(e) => {
                warn!("gRPC: error reading backend response frame: {}", e);
                break;
            }
        }
    }

    Ok(GrpcResponse {
        status,
        headers,
        body: body_bytes,
        trailers,
    })
}

/// Check if a request is a gRPC request based on content-type.
pub fn is_grpc_request(req: &Request<Incoming>) -> bool {
    is_grpc_content_type(req.headers())
}

/// Check if headers indicate a gRPC request (content-type starts with "application/grpc").
pub fn is_grpc_content_type(headers: &hyper::HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/grpc"))
}
