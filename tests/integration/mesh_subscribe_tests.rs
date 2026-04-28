//! Tests for the new native `MeshSubscribe` RPC. Verifies the
//! per-workload slice is delivered, that an unknown workload is
//! rejected, and that updates flow through.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ferrum_edge::config::mesh::{
    AppProtocol, MeshService, MeshSlice, ServicePort, Workload, WorkloadPort, WorkloadSelector,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::cp_server::CpGrpcServer;
use ferrum_edge::grpc::proto::MeshSubscribeRequest;
use ferrum_edge::grpc::proto::config_sync_client::ConfigSyncClient;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Server};

const TEST_SECRET: &str = "test-grpc-secret-key-thirty-two-bytes!";

#[derive(Serialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
}

fn make_jwt() -> String {
    let claims = Claims {
        sub: "test-dp".into(),
        iat: chrono::Utc::now().timestamp(),
        exp: chrono::Utc::now().timestamp() + 3600,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
    )
    .unwrap()
}

fn workload(spiffe: &str, ns: &str) -> Workload {
    Workload {
        spiffe_id: SpiffeId::from_str(spiffe).unwrap(),
        selector: WorkloadSelector::default(),
        service_name: "x".into(),
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: None,
        }],
        trust_domain: TrustDomain::new("prod").unwrap(),
        namespace: ns.into(),
    }
}

fn service(name: &str, ns: &str, port: u16) -> MeshService {
    MeshService {
        name: name.into(),
        namespace: ns.into(),
        ports: vec![ServicePort {
            port,
            protocol: AppProtocol::Http,
            name: None,
        }],
        workloads: vec![],
        protocol_overrides: HashMap::new(),
    }
}

async fn start_test_server(
    config: GatewayConfig,
) -> (
    std::net::SocketAddr,
    Arc<ArcSwap<GatewayConfig>>,
    tokio::sync::broadcast::Sender<ferrum_edge::grpc::proto::ConfigUpdate>,
    tokio::task::JoinHandle<()>,
) {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (server, update_tx) = CpGrpcServer::new(config_arc.clone(), TEST_SECRET.to_string());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("CP server failed");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, config_arc, update_tx, handle)
}

async fn make_client(addr: std::net::SocketAddr) -> ConfigSyncClient<Channel> {
    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    ConfigSyncClient::new(channel)
}

fn auth_request<R>(req: R) -> tonic::Request<R> {
    let mut request = tonic::Request::new(req);
    let bearer = format!("Bearer {}", make_jwt());
    request
        .metadata_mut()
        .insert("authorization", bearer.parse().unwrap());
    request
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_subscribe_returns_per_workload_slice() {
    let mut cfg = GatewayConfig::default();
    cfg.workloads
        .push(workload("spiffe://prod/ns/billing/sa/api", "billing"));
    cfg.services.push(service("billing", "billing", 80));
    let (addr, _config_arc, _update_tx, _handle) = start_test_server(cfg).await;
    let mut client = make_client(addr).await;

    let req = MeshSubscribeRequest {
        node_id: "test-dp".into(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "billing".into(),
        spiffe_id: "spiffe://prod/ns/billing/sa/api".into(),
        trust_domain: "prod".into(),
    };
    let resp = client
        .mesh_subscribe(auth_request(req))
        .await
        .expect("MeshSubscribe should succeed");
    let mut stream = resp.into_inner();
    let initial = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(initial.update_type, 0); // FULL_SNAPSHOT
    let slice: MeshSlice = serde_json::from_str(&initial.mesh_slice_json).unwrap();
    assert_eq!(
        slice.workload.spiffe_id.to_string(),
        "spiffe://prod/ns/billing/sa/api"
    );
    assert_eq!(slice.services.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_subscribe_unknown_workload_is_not_found() {
    let mut cfg = GatewayConfig::default();
    cfg.workloads
        .push(workload("spiffe://prod/ns/billing/sa/api", "billing"));
    let (addr, _config_arc, _update_tx, _handle) = start_test_server(cfg).await;
    let mut client = make_client(addr).await;

    let req = MeshSubscribeRequest {
        node_id: "test-dp".into(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "billing".into(),
        spiffe_id: "spiffe://prod/ns/billing/sa/missing".into(),
        trust_domain: "prod".into(),
    };
    let result = client.mesh_subscribe(auth_request(req)).await;
    assert!(result.is_err());
    let status = result.err().unwrap();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_subscribe_invalid_spiffe_id_is_invalid_argument() {
    let cfg = GatewayConfig::default();
    let (addr, _config_arc, _update_tx, _handle) = start_test_server(cfg).await;
    let mut client = make_client(addr).await;

    let req = MeshSubscribeRequest {
        node_id: "test-dp".into(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "billing".into(),
        spiffe_id: "this-is-not-a-spiffe-id".into(),
        trust_domain: "prod".into(),
    };
    let result = client.mesh_subscribe(auth_request(req)).await;
    assert!(result.is_err());
    let status = result.err().unwrap();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_subscribe_emits_delta_after_config_change() {
    let mut cfg = GatewayConfig::default();
    cfg.workloads
        .push(workload("spiffe://prod/ns/billing/sa/api", "billing"));
    cfg.services.push(service("billing", "billing", 80));
    let (addr, config_arc, update_tx, _handle) = start_test_server(cfg).await;
    let mut client = make_client(addr).await;

    let req = MeshSubscribeRequest {
        node_id: "test-dp".into(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "billing".into(),
        spiffe_id: "spiffe://prod/ns/billing/sa/api".into(),
        trust_domain: "prod".into(),
    };
    let resp = client.mesh_subscribe(auth_request(req)).await.unwrap();
    let mut stream = resp.into_inner();

    // Initial FULL_SNAPSHOT
    let _initial = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    // Mutate config + broadcast
    let mut new_cfg = (**config_arc.load()).clone();
    new_cfg.services.push(service("payments", "billing", 8081));
    config_arc.store(Arc::new(new_cfg.clone()));
    CpGrpcServer::broadcast_update(&update_tx, &new_cfg);

    let next = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let slice: MeshSlice = serde_json::from_str(&next.mesh_slice_json).unwrap();
    assert_eq!(
        slice.services.len(),
        2,
        "delta after broadcast should include the new service"
    );
}

/// Ensures the existing `Subscribe` RPC is unchanged on the wire after
/// the proto extension. Smoke check.
#[tokio::test(flavor = "multi_thread")]
async fn existing_subscribe_rpc_still_works_unchanged() {
    let cfg = GatewayConfig::default();
    let (addr, _config_arc, _update_tx, _handle) = start_test_server(cfg).await;
    let mut client = make_client(addr).await;

    use ferrum_edge::grpc::proto::SubscribeRequest;
    let req = SubscribeRequest {
        node_id: "test-dp".into(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        namespace: "ferrum".into(),
    };
    let resp = client.subscribe(auth_request(req)).await.unwrap();
    let mut stream = resp.into_inner();
    let initial = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // FULL_SNAPSHOT, version_info populated, etc — the existing
    // contract is preserved.
    assert_eq!(initial.update_type, 0);
    assert!(!initial.config_json.is_empty());
}
