//! Tests for `plugins::utils::response_body` bounded readers.
//!
//! Verifies that `read_response_body_bounded` and
//! `measure_response_body_bounded` enforce their cap by streaming the body
//! and aborting as soon as the running total exceeds the limit, instead of
//! buffering the full payload before checking. Stops a misbehaving sink from
//! exhausting gateway memory.

use ferrum_edge::plugins::utils::response_body::{
    BoundedReadError, measure_response_body_bounded, read_response_body_bounded,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// 2 KiB body against a 1 KiB limit must error and must NOT allocate the full
/// 2 KiB.
#[tokio::test]
async fn test_read_response_body_bounded_exceeds_limit() {
    let server = MockServer::start().await;
    let body = vec![b'A'; 2048];
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let result = read_response_body_bounded(resp, 1024).await;

    match result {
        Err(BoundedReadError::LimitExceeded {
            max_bytes,
            read_so_far,
        }) => {
            assert_eq!(max_bytes, 1024);
            assert!(
                read_so_far > 1024,
                "read_so_far should be > limit when triggering the error, got {}",
                read_so_far
            );
            assert!(
                read_so_far <= 2048,
                "should not exceed total body size, got {}",
                read_so_far
            );
        }
        other => panic!("Expected LimitExceeded, got {:?}", other),
    }
}

/// Body within the limit returns Ok with the expected bytes.
#[tokio::test]
async fn test_read_response_body_bounded_within_limit() {
    let server = MockServer::start().await;
    let body = vec![b'B'; 512];
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let buf = read_response_body_bounded(resp, 1024)
        .await
        .expect("body within limit should succeed");
    assert_eq!(buf.len(), 512);
    assert_eq!(buf, body);
}

/// Empty body (204) returns Ok with empty bytes.
#[tokio::test]
async fn test_read_response_body_bounded_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let buf = read_response_body_bounded(resp, 1024).await.unwrap();
    assert!(buf.is_empty());
}

/// Exactly-at-limit body succeeds (the check is `>`, not `>=`).
#[tokio::test]
async fn test_read_response_body_bounded_exactly_at_limit() {
    let server = MockServer::start().await;
    let body = vec![b'C'; 1024];
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let buf = read_response_body_bounded(resp, 1024).await.unwrap();
    assert_eq!(buf.len(), 1024);
    assert_eq!(buf, body);
}

/// `measure_response_body_bounded` returns the size for an in-limit body.
#[tokio::test]
async fn test_measure_response_body_bounded_within_limit() {
    let server = MockServer::start().await;
    let body = vec![b'D'; 512];
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let n = measure_response_body_bounded(resp, 1024).await.unwrap();
    assert_eq!(n, 512);
}

/// `measure_response_body_bounded` aborts when the running total exceeds the
/// limit.
#[tokio::test]
async fn test_measure_response_body_bounded_exceeds_limit() {
    let server = MockServer::start().await;
    let body = vec![b'E'; 4096];
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let resp = reqwest::get(server.uri()).await.unwrap();
    let result = measure_response_body_bounded(resp, 1024).await;
    match result {
        Err(BoundedReadError::LimitExceeded {
            max_bytes,
            read_so_far,
        }) => {
            assert_eq!(max_bytes, 1024);
            assert!(read_so_far > 1024);
        }
        other => panic!("Expected LimitExceeded, got {:?}", other),
    }
}
