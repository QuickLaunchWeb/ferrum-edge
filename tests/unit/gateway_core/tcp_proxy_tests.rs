use ferrum_edge::_test_support::{bidirectional_copy_for_test, classify_stream_error};
use ferrum_edge::plugins::Direction;
use ferrum_edge::retry::ErrorClass;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[test]
fn test_classify_stream_error_preserves_tls_failures() {
    let error =
        anyhow::anyhow!("Backend TLS handshake failed to 127.0.0.1:443: invalid peer certificate");
    assert_eq!(classify_stream_error(&error), ErrorClass::TlsError);
}

#[test]
fn test_classify_stream_error_preserves_dns_failures() {
    let error = anyhow::anyhow!("DNS resolution failed for backend.local: no record found");
    assert_eq!(classify_stream_error(&error), ErrorClass::DnsLookupError);
}

// ── Test helpers for bidirectional_copy direction tracking ───────────────────

/// Stream wrapper that returns `io::ErrorKind::ConnectionReset` on the first
/// `poll_read`. Writes are accepted (discarded).
struct ResetOnReadStream;

impl AsyncRead for ResetOnReadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "simulated read reset",
        )))
    }
}

impl AsyncWrite for ResetOnReadStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ── bidirectional_copy direction tests ───────────────────────────────────────

#[tokio::test]
async fn test_bidirectional_copy_client_read_error_marks_client_to_backend() {
    let client = ResetOnReadStream;
    let (backend, _peer) = tokio::io::duplex(1024);

    let result = bidirectional_copy_for_test(client, backend, None, 8 * 1024).await;

    let (dir, class) = result
        .first_failure
        .as_ref()
        .expect("first_failure should be set when client read errors");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ConnectionReset);
}

#[tokio::test]
async fn test_bidirectional_copy_backend_read_error_marks_backend_to_client() {
    let (client, _peer) = tokio::io::duplex(1024);
    let backend = ResetOnReadStream;

    let result = bidirectional_copy_for_test(client, backend, None, 8 * 1024).await;

    let (dir, class) = result
        .first_failure
        .as_ref()
        .expect("first_failure should be set when backend read errors");
    assert_eq!(*dir, Direction::BackendToClient);
    assert_eq!(*class, ErrorClass::ConnectionReset);
}

#[tokio::test]
async fn test_bidirectional_copy_clean_close_no_failure() {
    let (client, client_peer) = tokio::io::duplex(1024);
    let (backend, backend_peer) = tokio::io::duplex(1024);

    drop(client_peer);
    drop(backend_peer);

    let result = bidirectional_copy_for_test(client, backend, None, 8 * 1024).await;

    assert!(
        result.first_failure.is_none(),
        "clean close must leave first_failure == None, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, 0);
    assert_eq!(result.bytes_backend_to_client, 0);
}

#[tokio::test]
async fn test_bidirectional_copy_preserves_bytes_across_errors() {
    let (client, mut client_peer) = tokio::io::duplex(1024);
    let backend = ResetOnReadStream;

    let payload = b"hello-world-42";
    tokio::spawn(async move {
        let _ = client_peer.write_all(payload).await;
        let _ = client_peer.shutdown().await;
    });

    let result = bidirectional_copy_for_test(client, backend, None, 8 * 1024).await;

    let (dir, _class) = result
        .first_failure
        .as_ref()
        .expect("first_failure should be set — backend read half errored");
    assert_eq!(*dir, Direction::BackendToClient);

    assert_eq!(result.bytes_backend_to_client, 0);
    // c2b counter must never exceed the payload (key invariant — no zeroing).
    assert!(
        result.bytes_client_to_backend <= payload.len() as u64,
        "c2b bytes must not exceed payload size, got {}",
        result.bytes_client_to_backend
    );
}

#[tokio::test]
async fn test_bidirectional_copy_c2b_bytes_preserved_on_clean_close() {
    let (client, mut client_peer) = tokio::io::duplex(4096);
    let (backend, mut backend_peer) = tokio::io::duplex(4096);

    let payload: Vec<u8> = (0..512u16).map(|i| (i & 0xFF) as u8).collect();
    let payload_clone = payload.clone();

    tokio::spawn(async move {
        let _ = client_peer.write_all(&payload_clone).await;
        let _ = client_peer.shutdown().await;
    });

    tokio::spawn(async move {
        let mut sink = Vec::new();
        let _ = backend_peer.read_to_end(&mut sink).await;
    });

    let result =
        bidirectional_copy_for_test(client, backend, Some(Duration::from_secs(5)), 8 * 1024).await;

    assert!(
        result.first_failure.is_none(),
        "both halves EOF cleanly → first_failure should be None, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, payload.len() as u64);
    assert_eq!(result.bytes_backend_to_client, 0);
}
