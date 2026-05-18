//! Minimal MeshConfigSync gRPC server for perf-harness use.
//!
//! Returns a pre-baked `MeshConfigUpdate` (built by `slice::build_synthetic_slice`)
//! on every `MeshSubscribe` request, then idles the stream open until the
//! client disconnects. JWT validation is intentionally permissive — the
//! gateway-side issuer/secret check is the real boundary; this stub just
//! emits the synthetic slice.

use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use mesh_dns_e2e_perf::STUB_SLICE_VERSION;
use mesh_dns_e2e_perf::proto::mesh_config_sync_server::{MeshConfigSync, MeshConfigSyncServer};
use mesh_dns_e2e_perf::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use mesh_dns_e2e_perf::slice::build_synthetic_slice;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

#[derive(Parser, Debug)]
#[command(about = "Minimal native MeshConfigSync CP stub for the DNS proxy perf harness")]
struct Args {
    /// Listen address for the gRPC server.
    #[arg(long, default_value = "127.0.0.1:17070")]
    listen: String,

    /// Ferrum version string echoed back to the gateway. Must match the
    /// gateway binary's major.minor or the DP rejects it.
    #[arg(long, default_value = "0.9.0")]
    ferrum_version: String,

    /// Namespace echoed back into the slice.
    #[arg(long, default_value = "default")]
    namespace: String,
}

type SubscribeStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<MeshConfigUpdate, Status>> + Send>>;

struct StubMeshServer {
    ferrum_version: String,
    namespace: String,
}

#[tonic::async_trait]
impl MeshConfigSync for StubMeshServer {
    type MeshSubscribeStream = SubscribeStream;

    async fn mesh_subscribe(
        &self,
        request: Request<MeshSubscribeRequest>,
    ) -> Result<Response<SubscribeStream>, Status> {
        let inner = request.into_inner();
        let node_id = if inner.node_id.is_empty() {
            "mesh-perf-node".to_string()
        } else {
            inner.node_id
        };
        let slice = build_synthetic_slice(&node_id, &self.namespace, STUB_SLICE_VERSION);
        let mesh_slice_json = serde_json::to_string(&slice)
            .map_err(|e| Status::internal(format!("slice serialize: {e}")))?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let update = MeshConfigUpdate {
            version: STUB_SLICE_VERSION.to_string(),
            timestamp,
            mesh_slice_json,
            ferrum_version: self.ferrum_version.clone(),
            heartbeat: false,
        };

        // Send the initial slice, then keep the stream alive so the gateway's
        // native client doesn't reconnect-loop. `tx.closed().await` resolves
        // when the receiver is dropped (client disconnect or stream cancel),
        // so the holder task exits with the subscription instead of leaking.
        let (tx, rx) = mpsc::channel::<Result<MeshConfigUpdate, Status>>(4);
        if tx.send(Ok(update)).await.is_err() {
            return Err(Status::cancelled("client gone before initial slice"));
        }
        tokio::spawn(async move {
            tx.closed().await;
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let addr: std::net::SocketAddr = args.listen.parse()?;

    let server = StubMeshServer {
        ferrum_version: args.ferrum_version.clone(),
        namespace: args.namespace.clone(),
    };

    eprintln!(
        "[mesh_cp_stub] listening on {addr} (ferrum_version={}, namespace={})",
        args.ferrum_version, args.namespace
    );

    Server::builder()
        .add_service(MeshConfigSyncServer::new(server))
        .serve(addr)
        .await?;
    Ok(())
}
