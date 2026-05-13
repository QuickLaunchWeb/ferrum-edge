//! Unit tests for RFC 9220 (Bootstrapping WebSockets with HTTP/3
//! Extended CONNECT) support.
//!
//! These tests cover the request-classification surface that decides
//! whether an incoming H3 request enters the WebSocket bridge in
//! `crate::http3::websocket::handle_h3_websocket`. End-to-end
//! frame-relay coverage is tracked as follow-up work because the tree
//! does not yet ship a reusable WebSocket-over-H3 capable client.

use ferrum_edge::config::types::HttpFlavor;
use ferrum_edge::proxy::backend_dispatch::detect_http_flavor;

/// Construct an HTTP request with the given method, version, and
/// optional `:protocol` extension. Used to drive
/// `detect_http_flavor`, which is the shared classifier the H3 server
/// runs on every incoming request.
fn build_test_request(
    method: &str,
    version: hyper::Version,
    protocol: Option<&'static str>,
) -> hyper::Request<()> {
    let mut req = hyper::Request::builder()
        .method(method)
        .version(version)
        .uri("https://example.com/ws")
        .body(())
        .unwrap();
    if let Some(proto) = protocol {
        req.extensions_mut()
            .insert(hyper::ext::Protocol::from_static(proto));
    }
    req
}

// ============================================================================
// RFC 9220: H3 Extended CONNECT classification
// ============================================================================

#[test]
fn h3_connect_with_websocket_protocol_classifies_as_websocket() {
    let req = build_test_request("CONNECT", hyper::Version::HTTP_3, Some("websocket"));
    assert_eq!(
        detect_http_flavor(&req),
        HttpFlavor::WebSocket,
        "RFC 9220 Extended CONNECT must surface as HttpFlavor::WebSocket so \
         handle_h3_websocket can bridge it to a backend WebSocket"
    );
}

#[test]
fn h3_connect_with_websocket_protocol_case_insensitive() {
    let req = build_test_request("CONNECT", hyper::Version::HTTP_3, Some("WebSocket"));
    assert_eq!(
        detect_http_flavor(&req),
        HttpFlavor::WebSocket,
        "Case-insensitive matching mirrors RFC 8441 / RFC 9220 — the \
         :protocol value 'websocket' is matched as ASCII case-insensitive"
    );
}

#[test]
fn h3_connect_with_uppercase_websocket_protocol_classifies_as_websocket() {
    let req = build_test_request("CONNECT", hyper::Version::HTTP_3, Some("WEBSOCKET"));
    assert_eq!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

#[test]
fn h3_connect_without_protocol_extension_is_not_websocket() {
    // An H3 CONNECT with no `:protocol` is non-WebSocket and must be
    // rejected by the H3 dispatcher (handled by the `method == "CONNECT"
    // && !is_websocket` 405 path in `handle_h3_request`). The classifier
    // must therefore not surface it as WebSocket flavor.
    let req = build_test_request("CONNECT", hyper::Version::HTTP_3, None);
    assert_ne!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

#[test]
fn h3_connect_with_wrong_protocol_is_not_websocket() {
    // The :protocol registry defines other values (connect-udp,
    // webtransport, masque, etc.). None of them should classify as
    // WebSocket — the H3 dispatcher rejects them as non-WebSocket
    // CONNECT requests.
    let req = build_test_request("CONNECT", hyper::Version::HTTP_3, Some("connect-udp"));
    assert_ne!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

#[test]
fn h3_connect_with_unknown_protocol_is_not_websocket() {
    let req = build_test_request("CONNECT", hyper::Version::HTTP_3, Some("mqtt"));
    assert_ne!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

#[test]
fn h3_get_with_websocket_protocol_is_not_websocket() {
    // Extended CONNECT requires the CONNECT method. A GET request
    // carrying a `:protocol` extension (e.g., from a buggy client)
    // must NOT enter the WebSocket bridge.
    let req = build_test_request("GET", hyper::Version::HTTP_3, Some("websocket"));
    assert_ne!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

#[test]
fn h3_post_with_websocket_protocol_is_not_websocket() {
    let req = build_test_request("POST", hyper::Version::HTTP_3, Some("websocket"));
    assert_ne!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

#[test]
fn h3_options_with_websocket_protocol_is_not_websocket() {
    let req = build_test_request("OPTIONS", hyper::Version::HTTP_3, Some("websocket"));
    assert_ne!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

// ============================================================================
// Symmetry with RFC 8441 (H2) — same classifier must accept both versions
// ============================================================================

#[test]
fn h2_and_h3_extended_connect_websocket_classify_identically() {
    // The same classifier (`detect_http_flavor`) must surface both
    // RFC 8441 (H2) and RFC 9220 (H3) Extended CONNECT as
    // `HttpFlavor::WebSocket`. Without this symmetry, H2 clients see
    // WebSocket-over-Extended-CONNECT working while H3 clients see a
    // 405 (because the non-WebSocket CONNECT filter would reject).
    let h2 = build_test_request("CONNECT", hyper::Version::HTTP_2, Some("websocket"));
    let h3 = build_test_request("CONNECT", hyper::Version::HTTP_3, Some("websocket"));
    assert_eq!(detect_http_flavor(&h2), detect_http_flavor(&h3));
    assert_eq!(detect_http_flavor(&h2), HttpFlavor::WebSocket);
}

// ============================================================================
// Non-Extended-CONNECT paths still classify correctly
// ============================================================================

#[test]
fn h3_plain_get_is_plain_flavor() {
    let req = build_test_request("GET", hyper::Version::HTTP_3, None);
    assert_eq!(detect_http_flavor(&req), HttpFlavor::Plain);
}

#[test]
fn http11_websocket_upgrade_is_still_websocket_flavor() {
    // RFC 6455 HTTP/1.1 Upgrade-based WebSocket detection must keep
    // working — the H3 RFC 9220 additions are purely additive.
    let req = hyper::Request::builder()
        .method("GET")
        .version(hyper::Version::HTTP_11)
        .uri("/chat")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .body(())
        .unwrap();
    assert_eq!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

// ============================================================================
// FERRUM_HTTP3_WEBSOCKET_ENABLED env-config plumbing
// ============================================================================

#[test]
fn http3_websocket_enabled_defaults_to_true() {
    // The env var defaults to enabled — operators who run an H3
    // listener want WebSocket-over-H3 to "just work" out of the box,
    // matching the H2 default (`enable_connect_protocol()` is
    // unconditionally called on the H2 builder). Operators who want
    // to disable can set `FERRUM_HTTP3_WEBSOCKET_ENABLED=false`.
    let config = ferrum_edge::config::env_config::EnvConfig::default();
    assert!(
        config.http3_websocket_enabled,
        "FERRUM_HTTP3_WEBSOCKET_ENABLED must default to true so the H3 \
         listener advertises SETTINGS_ENABLE_CONNECT_PROTOCOL and the \
         WebSocket bridge is reachable without explicit opt-in"
    );
}

// ============================================================================
// Vendored h3 patch — Protocol::WEB_SOCKET (RFC 9220 :protocol value)
// ============================================================================

#[test]
fn h3_protocol_websocket_constant_is_accessible() {
    // Sanity check on patch 002 in
    // `docs/upstream-h3-patches/002-extended-connect-websocket-protocol/`.
    // Without `Protocol::WEB_SOCKET` (and the `"websocket"` arm in
    // `Protocol::FromStr`), the h3 HEADERS-frame decoder rejects
    // `:protocol = "websocket"` as `HeaderError::invalid_value` and
    // the gateway never sees the CONNECT request. This test would
    // fail to compile if the patch were dropped.
    let p = h3::ext::Protocol::WEB_SOCKET;
    assert_eq!(p.as_str(), "websocket");
}

#[test]
fn h3_protocol_websocket_parses_from_str() {
    // RFC 9220 mirrors RFC 8441's H2 Extended CONNECT — the wire
    // representation is the lowercase ASCII string `"websocket"`. The
    // `:protocol` header parser in h3's `proto/headers.rs::try_value`
    // routes through `FromStr`, so this round-trip is what determines
    // whether incoming H3 CONNECT requests with `:protocol=websocket`
    // surface to the application or get rejected.
    let parsed: h3::ext::Protocol = match "websocket".parse() {
        Ok(p) => p,
        Err(_) => panic!("h3 must accept 'websocket' as a :protocol value"),
    };
    assert_eq!(parsed.as_str(), "websocket");
    assert_eq!(parsed, h3::ext::Protocol::WEB_SOCKET);
}

#[test]
fn h3_protocol_existing_values_unaffected() {
    // Patch 002 must not regress the other registered :protocol values.
    let wt: h3::ext::Protocol = match "webtransport".parse() {
        Ok(p) => p,
        Err(_) => panic!("h3 must accept 'webtransport'"),
    };
    assert_eq!(wt, h3::ext::Protocol::WEB_TRANSPORT);

    let cu: h3::ext::Protocol = match "connect-udp".parse() {
        Ok(p) => p,
        Err(_) => panic!("h3 must accept 'connect-udp'"),
    };
    assert_eq!(cu, h3::ext::Protocol::CONNECT_UDP);
}
