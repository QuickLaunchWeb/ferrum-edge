//! Integration tests for the dimpl-based DTLS module.

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Raw dimpl handshake test — no wrappers, just state machines and UDP sockets.
/// This validates that dimpl itself works before testing our async wrappers.
#[tokio::test]
async fn test_dimpl_raw_handshake() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let server_cert =
        dimpl::certificate::generate_self_signed_certificate().expect("generate server cert");
    let client_cert =
        dimpl::certificate::generate_self_signed_certificate().expect("generate client cert");

    let config = Arc::new(
        dimpl::Config::builder()
            .use_server_cookie(false)
            .build()
            .expect("build config"),
    );

    // Bind sockets
    let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(server_addr).await.unwrap();
    let _client_addr = client_socket.local_addr().unwrap();

    // Create state machines
    let mut server = dimpl::Dtls::new_12(config.clone(), server_cert, Instant::now());
    // The server needs handle_timeout called to initialize its random/state
    let _ = server.handle_timeout(Instant::now());
    let mut client = dimpl::Dtls::new_auto(config, client_cert, Instant::now());
    client.set_active(true);

    let mut buf = vec![0u8; 4096];
    let mut udp_buf = vec![0u8; 65536];

    // ---- Client: produce ClientHello ----
    let mut client_timeout = None;
    loop {
        match client.poll_output(&mut buf) {
            dimpl::Output::Packet(data) => {
                eprintln!("[CLIENT] -> Packet {} bytes", data.len());
                client_socket.send(data).await.unwrap();
            }
            dimpl::Output::Timeout(t) => {
                eprintln!(
                    "[CLIENT] Timeout at +{:?}",
                    t.duration_since(Instant::now())
                );
                client_timeout = Some(t);
                break; // Timeout signals "no more outputs right now"
            }
            _ => break,
        }
    }

    // ---- Handshake loop ----
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut client_connected = false;
    let mut server_connected = false;

    while Instant::now() < deadline && !(client_connected && server_connected) {
        // Server: try to recv
        if let Ok(Ok((len, from))) = tokio::time::timeout(
            Duration::from_millis(200),
            server_socket.recv_from(&mut udp_buf),
        )
        .await
        {
            eprintln!("[SERVER] <- Recv {} bytes from {}", len, from);
            match server.handle_packet(&udp_buf[..len]) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("[SERVER] handle_packet ERROR: {}", e);
                }
            }
            // Drain server outputs — after Connected, skip one Timeout then
            // drain more to capture final flight packets (CCS + Finished).
            let mut saw_connected = false;
            let mut skipped_timeout = false;
            for drain_round in 0..128 {
                match server.poll_output(&mut buf) {
                    dimpl::Output::Packet(data) => {
                        eprintln!(
                            "[SERVER] -> Packet {} bytes to {} (drain {})",
                            data.len(),
                            from,
                            drain_round
                        );
                        server_socket.send_to(data, from).await.unwrap();
                    }
                    dimpl::Output::Connected => {
                        eprintln!("[SERVER] CONNECTED! (drain {})", drain_round);
                        server_connected = true;
                        saw_connected = true;
                    }
                    dimpl::Output::PeerCert(der) => {
                        eprintln!(
                            "[SERVER] PeerCert {} bytes (drain {})",
                            der.len(),
                            drain_round
                        );
                    }
                    dimpl::Output::Timeout(t) => {
                        eprintln!(
                            "[SERVER] Timeout +{:?} (drain {}, saw_connected={}, skipped={})",
                            t.duration_since(Instant::now()),
                            drain_round,
                            saw_connected,
                            skipped_timeout
                        );
                        if saw_connected && !skipped_timeout {
                            skipped_timeout = true;
                            continue;
                        }
                        break;
                    }
                    dimpl::Output::ApplicationData(_) => {}
                    dimpl::Output::KeyingMaterial(_, _) => {
                        eprintln!("[SERVER] KeyingMaterial (drain {})", drain_round);
                    }
                    _ => {
                        eprintln!("[SERVER] Unknown output (drain {})", drain_round);
                    }
                }
            }
        }

        // Client: try to recv
        match tokio::time::timeout(Duration::from_millis(200), client_socket.recv(&mut udp_buf))
            .await
        {
            Ok(Ok(len)) => {
                eprintln!("[CLIENT] <- Recv {} bytes", len);
                match client.handle_packet(&udp_buf[..len]) {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("[CLIENT] handle_packet ERROR: {}", e);
                    }
                }
                // Drain client outputs
                loop {
                    match client.poll_output(&mut buf) {
                        dimpl::Output::Packet(data) => {
                            eprintln!("[CLIENT] -> Packet {} bytes", data.len());
                            client_socket.send(data).await.unwrap();
                        }
                        dimpl::Output::Connected => {
                            eprintln!("[CLIENT] CONNECTED!");
                            client_connected = true;
                        }
                        dimpl::Output::PeerCert(der) => {
                            eprintln!("[CLIENT] PeerCert {} bytes", der.len());
                        }
                        dimpl::Output::Timeout(t) => {
                            eprintln!("[CLIENT] Timeout +{:?}", t.duration_since(Instant::now()));
                            client_timeout = Some(t);
                            break;
                        }
                        _ => break,
                    }
                }
            }
            _ => {
                // Check client retransmit timer
                if let Some(t) = client_timeout
                    && Instant::now() >= t
                {
                    eprintln!("[CLIENT] handle_timeout");
                    let _ = client.handle_timeout(Instant::now());
                    client_timeout = None;
                    loop {
                        match client.poll_output(&mut buf) {
                            dimpl::Output::Packet(data) => {
                                eprintln!("[CLIENT] -> Retransmit {} bytes", data.len());
                                client_socket.send(data).await.unwrap();
                            }
                            dimpl::Output::Timeout(t) => {
                                client_timeout = Some(t);
                                break;
                            }
                            _ => break,
                        }
                    }
                }
            }
        }
    }

    assert!(client_connected, "Client should have connected");
    assert!(server_connected, "Server should have connected");

    // ---- Test application data ----
    client.send_application_data(b"hello").unwrap();
    // Drain client -> send encrypted packet
    while let dimpl::Output::Packet(data) = client.poll_output(&mut buf) {
        client_socket.send(data).await.unwrap();
    }

    // Server: recv encrypted, get app data
    let (len, _) = server_socket.recv_from(&mut udp_buf).await.unwrap();
    server.handle_packet(&udp_buf[..len]).unwrap();
    let mut received = Vec::new();
    while let dimpl::Output::ApplicationData(data) = server.poll_output(&mut buf) {
        received.extend_from_slice(data);
    }
    assert_eq!(received, b"hello", "Server should receive app data");
    eprintln!("Application data exchange OK!");
}

/// Test the async DtlsConnection + DtlsServer wrappers.
#[tokio::test]
async fn test_dtls_client_server_handshake_and_echo() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let server_cert =
        dimpl::certificate::generate_self_signed_certificate().expect("generate server cert");

    let server_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_config = dimpl::Config::builder()
        .build()
        .expect("build server config");
    let frontend_config = ferrum_edge::dtls::FrontendDtlsConfig {
        dimpl_config: Arc::new(server_config),
        certificate: server_cert,
        require_client_cert: false,
        client_ca_certs: Vec::new(),
    };

    let server = Arc::new(
        ferrum_edge::dtls::DtlsServer::bind(server_addr, frontend_config)
            .await
            .expect("bind server"),
    );
    let actual_addr = server.local_addr();

    // Spawn server recv loop
    let server_runner = server.clone();
    tokio::spawn(async move {
        let _ = server_runner.run().await;
    });

    // Spawn echo handler
    let server_acceptor = server.clone();
    tokio::spawn(async move {
        while let Ok((conn, _addr)) = server_acceptor.accept().await {
            tokio::spawn(async move {
                loop {
                    match conn.recv().await {
                        Ok(data) if !data.is_empty() => {
                            if conn.send(&data).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client");
    client_socket
        .connect(actual_addr)
        .await
        .expect("connect client");

    let client_config = dimpl::Config::builder()
        .build()
        .expect("build client config");
    let params = ferrum_edge::dtls::BackendDtlsParams {
        config: Arc::new(client_config),
        certificate: dimpl::certificate::generate_self_signed_certificate()
            .expect("generate client cert"),
        trusted_cas: Vec::new(),
        skip_verify: true,
    };

    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        ferrum_edge::dtls::DtlsConnection::connect(client_socket, params),
    )
    .await
    .expect("handshake timeout")
    .expect("handshake error");

    let msg = b"Hello DTLS!";
    conn.send(msg).await.expect("send");

    let reply = tokio::time::timeout(Duration::from_secs(5), conn.recv())
        .await
        .expect("recv timeout")
        .expect("recv error");

    assert_eq!(&reply, msg, "Echo should match");

    conn.close().await;
}

/// Test using PEM-loaded certificates (same path as the gateway binary).
/// This catches issues with `build_frontend_dtls_config` and PEM parsing.
#[tokio::test]
async fn test_dtls_pem_cert_handshake() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // Generate ECDSA P-256 cert via rcgen and write to temp PEM files
    let temp_dir = tempfile::TempDir::new().unwrap();
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

    // Build config via the production code path
    let frontend_config = ferrum_edge::dtls::build_frontend_dtls_config(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        None,
    )
    .expect("build frontend config");

    let server_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = Arc::new(
        ferrum_edge::dtls::DtlsServer::bind(server_addr, frontend_config)
            .await
            .expect("bind server"),
    );
    let actual_addr = server.local_addr();

    let server_runner = server.clone();
    tokio::spawn(async move {
        let _ = server_runner.run().await;
    });

    let server_acceptor = server.clone();
    tokio::spawn(async move {
        while let Ok((conn, _addr)) = server_acceptor.accept().await {
            tokio::spawn(async move {
                loop {
                    match conn.recv().await {
                        Ok(data) if !data.is_empty() => {
                            if conn.send(&data).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(actual_addr).await.unwrap();

    let client_config = dimpl::Config::builder().build().expect("client config");
    let params = ferrum_edge::dtls::BackendDtlsParams {
        config: Arc::new(client_config),
        certificate: dimpl::certificate::generate_self_signed_certificate().unwrap(),
        trusted_cas: Vec::new(),
        skip_verify: true,
    };

    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        ferrum_edge::dtls::DtlsConnection::connect(client_socket, params),
    )
    .await
    .expect("PEM cert handshake timeout")
    .expect("PEM cert handshake error");

    let msg = b"PEM cert test!";
    conn.send(msg).await.expect("send");

    let reply = tokio::time::timeout(Duration::from_secs(5), conn.recv())
        .await
        .expect("recv timeout")
        .expect("recv error");

    assert_eq!(&reply, msg);
    conn.close().await;
}
