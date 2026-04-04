use ferrum_edge::proxy::{check_protocol_headers, is_valid_websocket_key};
use hyper::header::HeaderValue;

// ============================================================================
// check_protocol_headers tests
// ============================================================================

// --- Content-Length + Transfer-Encoding conflict (HTTP/1.1 smuggling) ---

#[test]
fn http11_rejects_cl_and_te_together() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(
        result
            .unwrap()
            .contains("Content-Length and Transfer-Encoding")
    );
}

#[test]
fn http10_rejects_cl_and_te_together() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_10);
    assert!(result.is_some());
    assert!(
        result
            .unwrap()
            .contains("Content-Length and Transfer-Encoding")
    );
}

#[test]
fn http2_allows_cl_and_te_trailers() {
    // HTTP/2 doesn't use Transfer-Encoding, but if somehow present,
    // the CL+TE check only applies to HTTP/1.x
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    // HTTP/2 skips the CL+TE check (it's a protocol-level concern for HTTP/1.x)
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    // Should not trigger the CL+TE error (but may trigger TE validation)
    assert!(
        result.is_none()
            || !result
                .unwrap()
                .contains("Content-Length and Transfer-Encoding")
    );
}

#[test]
fn http11_allows_cl_only() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("42"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn http11_allows_te_only() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

// --- Multiple Content-Length with mismatched values ---

#[test]
fn rejects_conflicting_content_length_values() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("content-length", HeaderValue::from_static("42"));
    headers.append("content-length", HeaderValue::from_static("99"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("conflicting values"));
}

#[test]
fn allows_duplicate_content_length_same_value() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("content-length", HeaderValue::from_static("42"));
    headers.append("content-length", HeaderValue::from_static("42"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn conflicting_content_length_checked_on_http2() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("content-length", HeaderValue::from_static("10"));
    headers.append("content-length", HeaderValue::from_static("20"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("conflicting values"));
}

#[test]
fn conflicting_content_length_checked_on_http3() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("content-length", HeaderValue::from_static("100"));
    headers.append("content-length", HeaderValue::from_static("200"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_3);
    assert!(result.is_some());
    assert!(result.unwrap().contains("conflicting values"));
}

// --- Multiple Host headers (HTTP/1.1) ---

#[test]
fn http11_rejects_multiple_host_headers() {
    let mut headers = hyper::HeaderMap::new();
    headers.append("host", HeaderValue::from_static("evil.com"));
    headers.append("host", HeaderValue::from_static("real.com"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_11);
    assert!(result.is_some());
    assert!(result.unwrap().contains("multiple Host"));
}

#[test]
fn http11_allows_single_host() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("example.com"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn http2_allows_multiple_host_headers() {
    // HTTP/2 uses :authority, not Host — multiple Host headers are not a routing concern
    let mut headers = hyper::HeaderMap::new();
    headers.append("host", HeaderValue::from_static("a.com"));
    headers.append("host", HeaderValue::from_static("b.com"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

// --- TE header validation (HTTP/2) ---

#[test]
fn http2_allows_te_trailers() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("trailers"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

#[test]
fn http2_allows_te_trailers_case_insensitive() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("Trailers"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

#[test]
fn http2_rejects_te_chunked() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("chunked"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("TE header"));
}

#[test]
fn http2_rejects_te_gzip() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("gzip"));
    let result = check_protocol_headers(&headers, hyper::Version::HTTP_2);
    assert!(result.is_some());
    assert!(result.unwrap().contains("TE header"));
}

#[test]
fn http2_allows_no_te() {
    let headers = hyper::HeaderMap::new();
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

#[test]
fn http11_allows_any_te_value() {
    // TE header restrictions only apply to HTTP/2
    let mut headers = hyper::HeaderMap::new();
    headers.insert("te", HeaderValue::from_static("gzip, chunked"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

// --- Clean requests pass validation ---

#[test]
fn clean_http11_request_passes() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("example.com"));
    headers.insert("content-length", HeaderValue::from_static("100"));
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
}

#[test]
fn clean_http2_request_passes() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("100"));
    headers.insert("te", HeaderValue::from_static("trailers"));
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
}

#[test]
fn empty_headers_pass() {
    let headers = hyper::HeaderMap::new();
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_11).is_none());
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_2).is_none());
    assert!(check_protocol_headers(&headers, hyper::Version::HTTP_3).is_none());
}

// ============================================================================
// is_valid_websocket_key tests
// ============================================================================

#[test]
fn valid_websocket_key_16_bytes_base64() {
    // 16 random bytes base64-encoded = 24 characters
    assert!(is_valid_websocket_key("dGhlIHNhbXBsZSBub25jZQ=="));
}

#[test]
fn valid_websocket_key_all_zeros() {
    // 16 zero bytes = "AAAAAAAAAAAAAAAAAAAAAA=="
    assert!(is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAAAA=="));
}

#[test]
fn invalid_websocket_key_too_short() {
    // Only 4 bytes worth of base64
    assert!(!is_valid_websocket_key("AAAA"));
}

#[test]
fn invalid_websocket_key_too_long() {
    // 32 bytes base64-encoded
    assert!(!is_valid_websocket_key(
        "dGhlIHNhbXBsZSBub25jZSB0aGUgc2FtcGxlIG5vbmNl"
    ));
}

#[test]
fn invalid_websocket_key_not_base64() {
    assert!(!is_valid_websocket_key("not-valid-base64!!!!"));
}

#[test]
fn invalid_websocket_key_empty() {
    assert!(!is_valid_websocket_key(""));
}

#[test]
fn invalid_websocket_key_15_bytes() {
    // 15 bytes base64 = "AAAAAAAAAAAAAAAAAAAA" (20 chars)
    assert!(!is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAA"));
}

#[test]
fn invalid_websocket_key_17_bytes() {
    // 17 bytes base64 = "AAAAAAAAAAAAAAAAAAAAAA==" wait that's 16.
    // Let me compute: 17 bytes = ceil(17*4/3) = 24 chars with padding
    // Actually base64 of 17 bytes = 24 chars. Let me use a real 17-byte value.
    // b"\x00" * 17 = "AAAAAAAAAAAAAAAAAAAAAAA=" (23 chars + padding)
    assert!(!is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAAAAA="));
}
