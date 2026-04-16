//! Unit tests for the HTTP/2-pool and HTTP/3 error classifiers introduced to
//! close audit gaps #2 and #3. These ensure operators see a populated
//! `error_class` in the transaction log for failures on both backend paths.

use ferrum_edge::proxy::http2_pool::{Http2PoolError, classify_http2_pool_error};
use ferrum_edge::retry::ErrorClass;

// ── HTTP/2 pool classifier ───────────────────────────────────────────────

#[test]
fn test_h2_pool_backend_timeout_connect() {
    let err = Http2PoolError::BackendTimeout("Connect timeout after 5s".to_string());
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionTimeout
    );
}

#[test]
fn test_h2_pool_backend_timeout_read() {
    let err = Http2PoolError::BackendTimeout("Read timed out".to_string());
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ReadWriteTimeout
    );
}

#[test]
fn test_h2_pool_backend_unavailable_port_exhaustion() {
    let err =
        Http2PoolError::BackendUnavailable("bind: address not available (os error 49)".to_string());
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::PortExhaustion);
}

#[test]
fn test_h2_pool_backend_unavailable_dns() {
    let err =
        Http2PoolError::BackendUnavailable("DNS resolution failed for api.example.com".to_string());
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::DnsLookupError);
}

#[test]
fn test_h2_pool_backend_unavailable_tls() {
    let err =
        Http2PoolError::BackendUnavailable("TLS handshake failed: unknown certificate".to_string());
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::TlsError);
}

#[test]
fn test_h2_pool_backend_unavailable_refused() {
    let err = Http2PoolError::BackendUnavailable("connection refused".to_string());
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionRefused
    );
}

#[test]
fn test_h2_pool_backend_unavailable_reset() {
    let err = Http2PoolError::BackendUnavailable("connection reset by peer".to_string());
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::ConnectionReset);
}

#[test]
fn test_h2_pool_backend_unavailable_broken_pipe() {
    let err = Http2PoolError::BackendUnavailable("broken pipe".to_string());
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionClosed
    );
}

#[test]
fn test_h2_pool_backend_unavailable_goaway() {
    let err = Http2PoolError::BackendUnavailable("received GOAWAY frame".to_string());
    assert_eq!(classify_http2_pool_error(&err), ErrorClass::ProtocolError);
}

#[test]
fn test_h2_pool_internal_unknown() {
    let err = Http2PoolError::Internal("unclassifiable internal pool state".to_string());
    assert_eq!(
        classify_http2_pool_error(&err),
        ErrorClass::ConnectionPoolError
    );
}

// ── HTTP/3 classifier ────────────────────────────────────────────────────

use ferrum_edge::http3::client::classify_http3_error;

#[test]
fn test_h3_quinn_timeout() {
    let err = quinn::ConnectionError::TimedOut;
    assert_eq!(classify_http3_error(&err), ErrorClass::ConnectionTimeout);
}

#[test]
fn test_h3_quinn_reset() {
    let err = quinn::ConnectionError::Reset;
    assert_eq!(classify_http3_error(&err), ErrorClass::ConnectionReset);
}

#[test]
fn test_h3_quinn_locally_closed() {
    let err = quinn::ConnectionError::LocallyClosed;
    assert_eq!(classify_http3_error(&err), ErrorClass::ConnectionClosed);
}

#[test]
fn test_h3_quinn_version_mismatch() {
    let err = quinn::ConnectionError::VersionMismatch;
    assert_eq!(classify_http3_error(&err), ErrorClass::ProtocolError);
}

#[test]
fn test_h3_quinn_cids_exhausted() {
    let err = quinn::ConnectionError::CidsExhausted;
    assert_eq!(classify_http3_error(&err), ErrorClass::ConnectionPoolError);
}

#[test]
fn test_h3_fallback_string_tls() {
    // Simulate an anyhow-wrapped h3 error with a TLS message, which won't
    // downcast to a typed quinn variant — classifier should fall back to
    // string heuristics.
    let err: Box<dyn std::error::Error + Send + Sync> =
        "rustls handshake failed: bad certificate".into();
    assert_eq!(classify_http3_error(err.as_ref()), ErrorClass::TlsError);
}

#[test]
fn test_h3_fallback_string_timeout() {
    let err: Box<dyn std::error::Error + Send + Sync> = "read timed out waiting for frame".into();
    assert_eq!(
        classify_http3_error(err.as_ref()),
        ErrorClass::ReadWriteTimeout
    );
}

#[test]
fn test_h3_fallback_string_goaway() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "received GOAWAY from server, closing stream".into();
    assert_eq!(
        classify_http3_error(err.as_ref()),
        ErrorClass::ProtocolError
    );
}

#[test]
fn test_h3_fallback_string_port_exhaustion() {
    let err: Box<dyn std::error::Error + Send + Sync> =
        "bind: address not available (os error 99)".into();
    assert_eq!(
        classify_http3_error(err.as_ref()),
        ErrorClass::PortExhaustion
    );
}
