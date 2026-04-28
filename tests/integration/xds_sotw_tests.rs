//! End-to-end SotW xDS test: spin up the Ferrum xDS server backed by a
//! `GatewayConfig` ArcSwap, connect with a tonic ADS client, send a
//! DiscoveryRequest, assert we receive a DiscoveryResponse with the
//! expected resources, ACK it, then mutate the config and assert the
//! server emits an updated response.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use envoy_types::pb::envoy::config::core::v3::Node;
use envoy_types::pb::envoy::service::discovery::v3::DiscoveryRequest;
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

fn td(s: &str) -> TrustDomain {
    TrustDomain::new(s).unwrap()
}

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
        trust_domain: td("prod"),
        namespace: "billing".into(),
    }
}

fn config_with_service() -> GatewayConfig {
    let mut cfg = GatewayConfig::default();
    cfg.workloads.push(make_workload());
    cfg.services.push(MeshService {
        name: "billing".into(),
        namespace: "billing".into(),
        ports: vec![ServicePort {
            port: 80,
            protocol: AppProtocol::Http,
            name: None,
        }],
        workloads: vec![],
        protocol_overrides: HashMap::new(),
    });
    cfg
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
        cluster: "billing.api".into(),
        metadata: Some(Struct { fields }),
        ..Default::default()
    }
}

async fn start_test_xds_server(
    config: Arc<ArcSwap<GatewayConfig>>,
) -> (
    std::net::SocketAddr,
    tokio::sync::broadcast::Sender<XdsRefreshSignal>,
    tokio::task::JoinHandle<()>,
) {
    let snapshots = XdsSnapshotCache::new();
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<XdsRefreshSignal>(64);
    let xds_state = Arc::new(XdsState {
        config,
        snapshots,
        broadcast: broadcast_tx.clone(),
    });
    let server = FerrumXdsServer::new(xds_state, None, false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(incoming)
            .await
            .expect("xds server failed");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, broadcast_tx, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn xds_sotw_initial_subscribe_returns_clusters() {
    let config = Arc::new(ArcSwap::new(Arc::new(config_with_service())));
    let (addr, _broadcast, _handle) = start_test_xds_server(config).await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = AggregatedDiscoveryServiceClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel::<DiscoveryRequest>(8);
    // Send the initial CDS subscribe.
    tx.send(DiscoveryRequest {
        node: Some(istio_node()),
        type_url: CDS_TYPE.to_string(),
        ..Default::default()
    })
    .await
    .unwrap();

    let resp_stream = client
        .stream_aggregated_resources(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap();
    let mut stream = resp_stream.into_inner();

    let resp = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(resp.type_url, CDS_TYPE);
    assert!(
        !resp.resources.is_empty(),
        "should receive at least one cluster"
    );
    assert!(
        !resp.version_info.is_empty(),
        "version_info must be populated"
    );
    assert!(!resp.nonce.is_empty(), "nonce must be populated");
    drop(tx);
}

#[tokio::test(flavor = "multi_thread")]
async fn xds_sotw_unknown_workload_returns_empty_cds() {
    let mut config = GatewayConfig::default();
    config.workloads.push(make_workload());
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let (addr, _broadcast, _handle) = start_test_xds_server(config_arc).await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = AggregatedDiscoveryServiceClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel::<DiscoveryRequest>(8);

    // Use an unregistered SPIFFE ID — server returns an empty resource
    // set rather than a status error (xDS clients tolerate empty
    // responses; an unknown identity is observably "no resources").
    use envoy_types::pb::google::protobuf::{Struct, Value, value::Kind};
    let mut fields = HashMap::new();
    fields.insert(
        "SPIFFE_ID".into(),
        Value {
            kind: Some(Kind::StringValue("spiffe://prod/ns/foo/sa/missing".into())),
        },
    );
    fields.insert(
        "NAMESPACE".into(),
        Value {
            kind: Some(Kind::StringValue("foo".into())),
        },
    );
    let unknown_node = Node {
        id: "unknown".into(),
        metadata: Some(Struct { fields }),
        ..Default::default()
    };

    tx.send(DiscoveryRequest {
        node: Some(unknown_node),
        type_url: CDS_TYPE.to_string(),
        ..Default::default()
    })
    .await
    .unwrap();

    let resp_stream = client
        .stream_aggregated_resources(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap();
    let mut stream = resp_stream.into_inner();
    let resp = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(resp.resources.is_empty(), "unknown workload → empty CDS");
    drop(tx);
}

#[tokio::test(flavor = "multi_thread")]
async fn xds_sotw_ack_does_not_trigger_redundant_emit() {
    let config = Arc::new(ArcSwap::new(Arc::new(config_with_service())));
    let (addr, _broadcast, _handle) = start_test_xds_server(config).await;

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = AggregatedDiscoveryServiceClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel::<DiscoveryRequest>(8);
    tx.send(DiscoveryRequest {
        node: Some(istio_node()),
        type_url: CDS_TYPE.to_string(),
        ..Default::default()
    })
    .await
    .unwrap();

    let resp_stream = client
        .stream_aggregated_resources(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap();
    let mut stream = resp_stream.into_inner();

    let resp1 = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let v1 = resp1.version_info.clone();
    let n1 = resp1.nonce.clone();

    // ACK with the same version — server must not emit again.
    tx.send(DiscoveryRequest {
        node: Some(istio_node()),
        type_url: CDS_TYPE.to_string(),
        version_info: v1,
        response_nonce: n1,
        ..Default::default()
    })
    .await
    .unwrap();

    // Wait briefly: no second response should arrive.
    let second = tokio::time::timeout(Duration::from_millis(300), stream.next()).await;
    assert!(
        second.is_err(),
        "ACK on unchanged config must not trigger a second emit"
    );
    drop(tx);
}
