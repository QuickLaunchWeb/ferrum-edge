//! Stub ambient-sidecar HBONE listener.
//!
//! Behaviour:
//! 1. Bind a TCP listener on `--listen` (default 127.0.0.1:15008).
//! 2. For each connection: terminate mTLS (requires + verifies client cert
//!    against `--ca`).
//! 3. Run an HTTP/2 server; accept exactly one `CONNECT` request per stream.
//! 4. For the CONNECT, dial `--backend-host:--backend-port` and pipe bytes
//!    bidirectionally over the H2 stream's `recv_stream` / `send_response` body.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use clap::Parser;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{Method, Response, StatusCode};
use mesh_hbone_e2e_perf::tls::make_sidecar_server_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:15008")]
    listen: SocketAddr,

    #[arg(long)]
    cert: PathBuf,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    ca: PathBuf,

    #[arg(long, default_value = "127.0.0.1")]
    backend_host: String,
    #[arg(long)]
    backend_port: u16,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();

    let cli = Cli::parse();
    let server_cfg = make_sidecar_server_config(&cli.cert, &cli.key, &cli.ca)?;
    let acceptor = TlsAcceptor::from(server_cfg);

    let listener = TcpListener::bind(cli.listen).await?;
    let bound = listener.local_addr()?;
    println!("hbone_sidecar listening on {bound}");

    let backend = (cli.backend_host.clone(), cli.backend_port);

    loop {
        let (tcp, _peer) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let backend = backend.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(tcp, acceptor, backend).await {
                tracing::debug!("hbone_sidecar conn: {e:#}");
            }
        });
    }
}

async fn handle_conn(tcp: TcpStream, acceptor: TlsAcceptor, backend: (String, u16)) -> Result<()> {
    let tls = acceptor
        .accept(tcp)
        .await
        .context("server-side TLS handshake")?;

    let mut h2_conn = h2::server::handshake(tls).await.context("h2 handshake")?;

    while let Some(stream) = h2_conn.accept().await {
        let (req, respond) = stream.context("accepting h2 stream")?;
        let backend = backend.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(req, respond, backend).await {
                tracing::debug!("hbone_sidecar stream: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_stream(
    req: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    backend: (String, u16),
) -> Result<()> {
    if req.method() != Method::CONNECT {
        let resp = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(())
            .unwrap();
        let _ = respond.send_response(resp, true);
        return Err(anyhow!("non-CONNECT request: {}", req.method()));
    }

    let (_parts, recv) = req.into_parts();

    let backend_stream = TcpStream::connect((backend.0.as_str(), backend.1))
        .await
        .context("dialing backend from sidecar")?;
    let _ = backend_stream.set_nodelay(true);

    let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
    let send = respond
        .send_response(resp, false)
        .context("sending CONNECT 200")?;

    relay(recv, send, backend_stream).await
}

async fn relay(
    mut recv: RecvStream,
    mut send: SendStream<Bytes>,
    backend: TcpStream,
) -> Result<()> {
    let (mut br, mut bw) = backend.into_split();

    // Tunnel → backend (read H2 DATA frames, write to backend).
    let client_to_backend = async move {
        while let Some(chunk) = recv.data().await {
            let chunk = chunk.map_err(|e| anyhow!("h2 recv: {e}"))?;
            let _ = recv.flow_control().release_capacity(chunk.len());
            bw.write_all(&chunk).await?;
        }
        let _ = bw.shutdown().await;
        Ok::<_, anyhow::Error>(())
    };

    // Backend → tunnel (read backend, await H2 capacity, send DATA frames).
    let backend_to_client = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = br.read(&mut buf).await?;
            if n == 0 {
                send.send_data(Bytes::new(), true)
                    .map_err(|e| anyhow!("h2 send EOS: {e}"))?;
                break;
            }
            let mut remaining = Bytes::copy_from_slice(&buf[..n]);
            while !remaining.is_empty() {
                send.reserve_capacity(remaining.len());
                let cap = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(c)) => c,
                    Some(Err(e)) => return Err(anyhow!("h2 poll_capacity: {e}")),
                    None => return Err(anyhow!("h2 stream closed")),
                };
                let to_take = std::cmp::min(cap, remaining.len());
                let chunk = remaining.split_to(to_take);
                send.send_data(chunk, false)
                    .map_err(|e| anyhow!("h2 send_data: {e}"))?;
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(client_to_backend, backend_to_client)?;
    Ok(())
}
