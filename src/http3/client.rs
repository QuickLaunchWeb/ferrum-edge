//! HTTP/3 client for proxying requests to HTTP/3 backends

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;
use http::Request;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::debug;

use crate::config::types::Proxy;

/// HTTP/3 client for connecting to backend services over QUIC.
#[derive(Clone)]
pub struct Http3Client {
    endpoint: quinn::Endpoint,
}

impl Http3Client {
    /// Create a new HTTP/3 client with the given TLS configuration.
    pub fn new(tls_config: Arc<rustls::ClientConfig>) -> Result<Self, anyhow::Error> {
        // Bind to any available local UDP port
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;

        let mut client_tls_config = (*tls_config).clone();
        client_tls_config.alpn_protocols = vec![b"h3".to_vec()];

        let quic_client_config = QuicClientConfig::try_from(client_tls_config)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC client config: {}", e))?;

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .map_err(|e| anyhow::anyhow!("Invalid timeout: {}", e))?,
        ));

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport));

        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Send an HTTP/3 request to the specified backend.
    pub async fn request(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: Vec<(http::header::HeaderName, http::header::HeaderValue)>,
        body: bytes::Bytes,
    ) -> Result<(u16, Vec<u8>, std::collections::HashMap<String, String>), anyhow::Error> {
        // Parse URL to get host and port
        let uri: http::Uri = backend_url.parse()
            .map_err(|e| anyhow::anyhow!("Invalid backend URL: {}", e))?;
        
        let host = uri.host().unwrap_or(&proxy.backend_host);
        let port = uri.port_u16().unwrap_or(proxy.backend_port);
        let _path = uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let addr = match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
            Ok(addrs) => addrs.into_iter().next().unwrap_or_else(|| {
                let ip: std::net::IpAddr = host.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
                SocketAddr::new(ip, port)
            }),
            Err(_) => {
                let ip: std::net::IpAddr = host.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
                SocketAddr::new(ip, port)
            }
        };

        let server_name = host.to_string();

        debug!(
            "HTTP/3 client connecting to {}:{} ({})",
            server_name, port, addr
        );

        // Establish QUIC connection
        let connection = self
            .endpoint
            .connect(addr, &server_name)?
            .await
            .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;

        // Create HTTP/3 connection
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;

        // Drive the connection in background
        tokio::spawn(async move {
            let _err = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("HTTP/3 connection driver closed");
        });

        // Build the request
        let req_method = match method {
            "GET" => http::Method::GET,
            "POST" => http::Method::POST,
            "PUT" => http::Method::PUT,
            "DELETE" => http::Method::DELETE,
            "PATCH" => http::Method::PATCH,
            "HEAD" => http::Method::HEAD,
            "OPTIONS" => http::Method::OPTIONS,
            _ => http::Method::GET,
        };

        let mut req_builder = Request::builder().method(req_method).uri(backend_url);

        // Add headers
        for (name, value) in headers {
            req_builder = req_builder.header(name, value);
        }

        let req = req_builder.body(())?;

        // Send request
        let mut stream = send_request.send_request(req).await?;

        // Send body if present
        if !body.is_empty() {
            stream.send_data(body).await?;
        }
        stream.finish().await?;

        // Receive response
        let response = stream.recv_response().await?;
        let status = response.status().as_u16();

        // Collect response headers
        let mut response_headers = std::collections::HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                response_headers.insert(name.as_str().to_string(), value_str.to_string());
            }
        }

        // Collect response body
        let mut response_body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            response_body.extend_from_slice(&chunk.chunk());
        }

        Ok((status, response_body, response_headers))
    }
}
