use ferrum_edge::config::types::HttpFlavor;
use ferrum_edge::proxy::backend_dispatch::detect_http_flavor;
use http::Request;

#[test]
fn detect_http_flavor_classifies_http3_extended_connect_websocket_as_websocket() {
    let mut req = Request::builder()
        .method("CONNECT")
        .uri("https://example.com/socket")
        .version(hyper::Version::HTTP_3)
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));

    assert_eq!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}

#[test]
fn detect_http_flavor_keeps_non_websocket_http3_connect_plain() {
    let mut req = Request::builder()
        .method("CONNECT")
        .uri("https://example.com/socket")
        .version(hyper::Version::HTTP_3)
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("connect-udp"));

    assert_eq!(detect_http_flavor(&req), HttpFlavor::Plain);
}

#[test]
fn detect_http_flavor_still_classifies_http2_extended_connect_websocket_as_websocket() {
    let mut req = Request::builder()
        .method("CONNECT")
        .uri("https://example.com/socket")
        .version(hyper::Version::HTTP_2)
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));

    assert_eq!(detect_http_flavor(&req), HttpFlavor::WebSocket);
}
