//! Verifies the per-node snapshot isolation security boundary at the
//! protocol level: two nodes connecting concurrently to the same xDS
//! server receive different resource sets when they have different
//! workload identities.

use std::collections::HashMap;
use std::str::FromStr;
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
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Server};

const CDS_TYPE: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

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

fn istio_node(spiffe: &str, ns: &str, id: &str) -> Node {
    use envoy_types::pb::google::protobuf::{Struct, Value, value::Kind};
    let mut fields = HashMap::new();
    fields.insert(
        "SPIFFE_ID".into(),
        Value {
            kind: Some(Kind::StringValue(spiffe.into())),
        },
    );
    fields.insert(
        "NAMESPACE".into(),
        Value {
            kind: Some(Kind::StringValue(ns.into())),
        },
    );
    Node {
        id: id.into(),
        metadata: Some(Struct { fields }),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_with_different_namespaces_get_disjoint_clusters() {
    let mut cfg = GatewayConfig::default();
    // Workloads
    cfg.workloads
        .push(workload("spiffe://prod/ns/a/sa/api", "a"));
    cfg.workloads
        .push(workload("spiffe://prod/ns/b/sa/api", "b"));
    // Services per namespace
    cfg.services.push(service("a-svc", "a", 80));
    cfg.services.push(service("b-svc", "b", 80));
    let config_arc = Arc::new(ArcSwap::new(Arc::new(cfg)));

    let snapshots = XdsSnapshotCache::new();
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<XdsRefreshSignal>(64);
    let xds_state = Arc::new(XdsState {
        config: config_arc,
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

    // Open two streams with different identities.
    async fn fetch_clusters(
        addr: std::net::SocketAddr,
        node: Node,
    ) -> Vec<envoy_types::pb::google::protobuf::Any> {
        let channel = Channel::from_shared(format!("http://{}", addr))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = AggregatedDiscoveryServiceClient::new(channel);

        let (tx, rx) = tokio::sync::mpsc::channel::<DiscoveryRequest>(4);
        tx.send(DiscoveryRequest {
            node: Some(node),
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
        drop(tx);
        resp.resources
    }

    let resources_a =
        fetch_clusters(addr, istio_node("spiffe://prod/ns/a/sa/api", "a", "node-a")).await;
    let resources_b =
        fetch_clusters(addr, istio_node("spiffe://prod/ns/b/sa/api", "b", "node-b")).await;

    // Each node should see exactly its namespace's cluster — no leak.
    let extract_names = |anys: &[envoy_types::pb::google::protobuf::Any]| -> Vec<String> {
        use envoy_types::pb::envoy::config::cluster::v3::Cluster;
        use prost::Message;
        anys.iter()
            .filter_map(|any| Cluster::decode(any.value.as_slice()).ok().map(|c| c.name))
            .collect()
    };
    let names_a = extract_names(&resources_a);
    let names_b = extract_names(&resources_b);

    assert!(
        names_a.iter().any(|n| n.contains("a-svc")),
        "node A should see a-svc cluster, got: {:?}",
        names_a
    );
    assert!(
        !names_a.iter().any(|n| n.contains("b-svc")),
        "node A must NOT see b-svc cluster (per-node isolation breach), got: {:?}",
        names_a
    );
    assert!(
        names_b.iter().any(|n| n.contains("b-svc")),
        "node B should see b-svc cluster, got: {:?}",
        names_b
    );
    assert!(
        !names_b.iter().any(|n| n.contains("a-svc")),
        "node B must NOT see a-svc cluster (per-node isolation breach), got: {:?}",
        names_b
    );
}
