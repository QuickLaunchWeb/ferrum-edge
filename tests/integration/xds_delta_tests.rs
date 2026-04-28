//! Delta xDS end-to-end test.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use envoy_types::pb::envoy::config::core::v3::Node;
use envoy_types::pb::envoy::service::discovery::v3::DeltaDiscoveryRequest;
use envoy_types::pb::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use ferrum_edge::config::mesh::{
    AppProtocol, MeshService, ServicePort, Workload, WorkloadPort, WorkloadSelector,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::xds::{FerrumXdsServer, XdsRefreshSignal, XdsSnapshotCache, XdsState};
use std::collections::HashMap;
use std::str::FromStr;
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Server};

const CDS_TYPE: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

fn make_workload() -> Workload {
    Workload {
        spiffe_id: SpiffeId::from_str("spiffe://prod/ns/billing/sa/api").unwrap(),
        selector: WorkloadSelector::default(),
        service_name: "api".into(),
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: None,
        }],
        trust_domain: TrustDomain::new("prod").unwrap(),
        namespace: "billing".into(),
    }
}

fn make_service(port: u16) -> MeshService {
    MeshService {
        name: "billing".into(),
        namespace: "billing".into(),
        ports: vec![ServicePort {
            port,
            protocol: AppProtocol::Http,
            name: None,
        }],
        workloads: vec![],
        protocol_overrides: HashMap::new(),
    }
}

fn istio_node() -> Node {
    use envoy_types::pb::google::protobuf::{Struct, Value, value::Kind};
    let mut fields = HashMap::new();
    fields.insert(
        "SPIFFE_ID".into(),
        Value {
            kind: Some(Kind::StringValue("spiffe://prod/ns/billing/sa/api".into())),
        },
    );
    fields.insert(
        "NAMESPACE".into(),
        Value {
            kind: Some(Kind::StringValue("billing".into())),
        },
    );
    Node {
        id: "sidecar~10.0.0.1~api~billing".into(),
        metadata: Some(Struct { fields }),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn xds_delta_initial_subscribe_returns_clusters() {
    let mut cfg = GatewayConfig::default();
    cfg.workloads.push(make_workload());
    cfg.services.push(make_service(80));
    let config_arc = Arc::new(ArcSwap::new(Arc::new(cfg)));

    let snapshots = XdsSnapshotCache::new();
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<XdsRefreshSignal>(64);
    let xds_state = Arc::new(XdsState {
        config: config_arc.clone(),
        snapshots,
        broadcast: broadcast_tx,
    });
    let server = FerrumXdsServer::new(xds_state, None, false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let _server_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("xds server failed");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = AggregatedDiscoveryServiceClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel::<DeltaDiscoveryRequest>(8);
    tx.send(DeltaDiscoveryRequest {
        node: Some(istio_node()),
        type_url: CDS_TYPE.to_string(),
        ..Default::default()
    })
    .await
    .unwrap();

    let resp_stream = client
        .delta_aggregated_resources(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap();
    let mut stream = resp_stream.into_inner();
    let resp = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(resp.type_url, CDS_TYPE);
    assert!(!resp.resources.is_empty());
    assert!(!resp.nonce.is_empty());
    assert!(resp.removed_resources.is_empty());
    drop(tx);
}

#[tokio::test(flavor = "multi_thread")]
async fn xds_delta_emits_removed_when_service_dropped() {
    let mut cfg = GatewayConfig::default();
    cfg.workloads.push(make_workload());
    cfg.services.push(make_service(80));
    let config_arc = Arc::new(ArcSwap::new(Arc::new(cfg)));

    let snapshots = XdsSnapshotCache::new();
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<XdsRefreshSignal>(64);
    let xds_state = Arc::new(XdsState {
        config: config_arc.clone(),
        snapshots,
        broadcast: broadcast_tx.clone(),
    });
    let server = FerrumXdsServer::new(xds_state.clone(), None, false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let _server_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("xds server failed");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = AggregatedDiscoveryServiceClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel::<DeltaDiscoveryRequest>(8);
    tx.send(DeltaDiscoveryRequest {
        node: Some(istio_node()),
        type_url: CDS_TYPE.to_string(),
        ..Default::default()
    })
    .await
    .unwrap();

    let resp_stream = client
        .delta_aggregated_resources(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap();
    let mut stream = resp_stream.into_inner();

    let resp1 = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!resp1.resources.is_empty());

    // ACK
    tx.send(DeltaDiscoveryRequest {
        node: Some(istio_node()),
        type_url: CDS_TYPE.to_string(),
        response_nonce: resp1.nonce.clone(),
        ..Default::default()
    })
    .await
    .unwrap();

    // Drop the service from the config and signal a refresh.
    let mut new_cfg = (**config_arc.load()).clone();
    new_cfg.services.clear();
    config_arc.store(Arc::new(new_cfg));

    let _ = xds_state.snapshots.recompute_all(&config_arc.load_full());
    let _ = broadcast_tx.send(XdsRefreshSignal {
        node_id: "sidecar~10.0.0.1~api~billing".into(),
        version: 2,
    });

    // Wait for the delta with a removed_resources entry.
    let resp2 = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        !resp2.removed_resources.is_empty(),
        "delta after service removal should report removed_resources, got: {:?}",
        resp2
    );
    drop(tx);
}
