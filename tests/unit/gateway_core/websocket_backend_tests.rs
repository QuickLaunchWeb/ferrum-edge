use ferrum_edge::_test_support::connect_websocket_backend_for_test;
use ferrum_edge::config::types::Proxy;
use serde_json::json;

#[tokio::test]
async fn connect_websocket_backend_sets_tcp_nodelay() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    let server = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = tokio_tungstenite::accept_async(stream).await;
        }
    });

    let proxy: Proxy = serde_json::from_value(json!({
        "backend_host": addr.ip().to_string(),
        "backend_port": addr.port(),
        "backend_scheme": "http",
        "backend_connect_timeout_ms": 2000u64,
    }))
    .expect("proxy deserialize");

    let url = format!("ws://{addr}/");
    let ws_stream = connect_websocket_backend_for_test(&url, &proxy)
        .await
        .expect("backend connect succeeds");

    match ws_stream.get_ref() {
        tokio_tungstenite::MaybeTlsStream::Plain(tcp) => {
            assert!(
                tcp.nodelay().expect("nodelay getsockopt"),
                "backend WS TcpStream must have TCP_NODELAY set"
            );
        }
        _ => panic!("expected plain TCP backend"),
    }

    drop(ws_stream);
    let _ = server.await;
}
