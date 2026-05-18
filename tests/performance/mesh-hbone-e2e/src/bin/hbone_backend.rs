//! Plaintext HTTP/1.1 echo backend.
//!
//! Listens on a TCP port; each request gets `200 OK` with the request body echoed
//! back. Logs `listening on 127.0.0.1:<port>` once bound so `run.sh` can capture
//! the ephemeral port.

use std::net::SocketAddr;

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let cli = Cli::parse();
    let listener = TcpListener::bind(cli.listen).await?;
    let bound = listener.local_addr()?;
    println!("listening on {bound}");
    eprintln!("hbone_backend listening on {bound}");

    loop {
        let (stream, _) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(handle);
            if let Err(e) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!("connection: {e}");
            }
        });
    }
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    let path = req.uri().path().to_string();
    let body = req.into_body().collect().await?.to_bytes();
    if path == "/health" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from_static(b"ok")))
            .unwrap());
    }
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-length", body.len().to_string())
        .body(Full::new(body))
        .unwrap())
}
