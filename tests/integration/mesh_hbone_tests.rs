use bytes::Bytes;
use chrono::Utc;
use hyper::{Method, Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_bound_listener};

fn create_mesh_proxy(backend_port: u16) -> Proxy {
    Proxy {
        id: "mesh-hbone".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Mesh HBONE".to_string()),
        api_spec_id: None,
        hosts: vec!["orders.default.svc.cluster.local".to_string()],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_mesh_proxy_state(proxy: Proxy) -> ProxyState {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        mesh: None,
    };
    let env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        log_level: "error".to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        ..EnvConfig::default()
    };
    ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("proxy state")
    .0
}

async fn start_gateway(state: ProxyState) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway local addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener(listener, state, shutdown_rx, None).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

async fn start_echo_backend() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo backend");
    let addr = listener.local_addr().expect("echo backend local addr");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let mut received = Vec::new();
        if stream.read_to_end(&mut received).await.is_ok() {
            let _ = stream.write_all(b"echo:").await;
            let _ = stream.write_all(&received).await;
            let _ = stream.shutdown().await;
        }
    });
    (addr, handle)
}

async fn start_idle_backend() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind idle backend");
    let addr = listener.local_addr().expect("idle backend local addr");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let mut buf = [0_u8; 16];
        let _ = stream.read(&mut buf).await;
    });
    (addr, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn hbone_connect_relays_data_frames_to_tcp_backend() {
    let (backend_addr, backend_handle) = start_echo_backend().await;
    let state = create_mesh_proxy_state(create_mesh_proxy(backend_addr.port()));
    let (gateway_addr, shutdown_tx) = start_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr)
        .await
        .expect("connect gateway");
    let _ = stream.set_nodelay(true);
    let (mut sender, conn) = h2::client::handshake(stream).await.expect("h2 handshake");
    let conn_task = tokio::spawn(conn);

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri("orders.default.svc.cluster.local:8080")
        .body(())
        .expect("connect request");
    let (response_fut, mut request_body) = sender.send_request(req, false).expect("send CONNECT");
    request_body
        .send_data(Bytes::from_static(b"mesh-bytes"), true)
        .expect("send CONNECT data");
    let resp = response_fut.await.expect("CONNECT response");
    assert_eq!(resp.status(), StatusCode::OK);

    let mut response_body = resp.into_body();
    let body = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut body = Vec::new();
        while let Some(chunk) = response_body.data().await {
            let chunk = chunk.expect("CONNECT response chunk");
            let _ = response_body.flow_control().release_capacity(chunk.len());
            body.extend_from_slice(&chunk);
        }
        body
    })
    .await
    .expect("collect CONNECT response");
    assert_eq!(&body[..], b"echo:mesh-bytes");

    shutdown_tx.send(true).expect("shutdown gateway");
    backend_handle.await.expect("backend task");
    conn_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn hbone_connect_closes_idle_tunnel() {
    let (backend_addr, backend_handle) = start_idle_backend().await;
    let mut proxy = create_mesh_proxy(backend_addr.port());
    proxy.tcp_idle_timeout_seconds = Some(1);
    proxy.backend_read_timeout_ms = 0;
    proxy.backend_write_timeout_ms = 0;
    let state = create_mesh_proxy_state(proxy);
    let (gateway_addr, shutdown_tx) = start_gateway(state).await;

    let stream = tokio::net::TcpStream::connect(gateway_addr)
        .await
        .expect("connect gateway");
    let _ = stream.set_nodelay(true);
    let (mut sender, conn) = h2::client::handshake(stream).await.expect("h2 handshake");
    let conn_task = tokio::spawn(conn);

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri("orders.default.svc.cluster.local:8080")
        .body(())
        .expect("connect request");
    let (response_fut, _request_body) = sender.send_request(req, false).expect("send CONNECT");
    let resp = response_fut.await.expect("CONNECT response");
    assert_eq!(resp.status(), StatusCode::OK);

    let mut response_body = resp.into_body();
    let idle_close = tokio::time::timeout(std::time::Duration::from_secs(4), response_body.data())
        .await
        .expect("idle tunnel should close");
    match idle_close {
        None => {}
        Some(Err(_)) => {}
        Some(Ok(chunk)) if chunk.is_empty() => {}
        Some(Ok(chunk)) => panic!("idle tunnel returned unexpected data: {chunk:?}"),
    }

    shutdown_tx.send(true).expect("shutdown gateway");
    backend_handle.await.expect("backend task");
    conn_task.abort();
}
