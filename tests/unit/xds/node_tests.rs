//! Tests for `crate::xds::node::ParsedNode`. Public API only — the
//! inline tests in `src/xds/node.rs` cover private metadata-extraction
//! paths.

use envoy_types::pb::envoy::config::core::v3::Node;
use envoy_types::pb::google::protobuf::{Struct, Value, value::Kind};
use ferrum_edge::xds::node::{NodeError, ParsedNode};

fn metadata(entries: &[(&str, &str)]) -> Struct {
    let mut fields = std::collections::HashMap::new();
    for (k, v) in entries {
        fields.insert(
            (*k).to_string(),
            Value {
                kind: Some(Kind::StringValue((*v).to_string())),
            },
        );
    }
    Struct { fields }
}

#[test]
fn rejects_node_with_empty_id() {
    let n = Node::default();
    assert_eq!(ParsedNode::from_envoy(&n), Err(NodeError::MissingId));
}

#[test]
fn parses_minimal_node() {
    let n = Node {
        id: "router~1.2.3.4~web~prod".into(),
        ..Default::default()
    };
    let p = ParsedNode::from_envoy(&n).unwrap();
    assert_eq!(p.id, "router~1.2.3.4~web~prod");
}

#[test]
fn parses_node_with_full_istio_metadata() {
    let n = Node {
        id: "sidecar~10.0.0.5~payments~production".into(),
        cluster: "payments.production".into(),
        metadata: Some(metadata(&[
            ("SPIFFE_ID", "spiffe://prod/ns/production/sa/payments"),
            ("NAMESPACE", "production"),
            ("WORKLOAD_NAME", "payments"),
        ])),
        ..Default::default()
    };
    let p = ParsedNode::from_envoy(&n).unwrap();
    assert_eq!(p.cluster, "payments.production");
    assert_eq!(
        p.spiffe_id.unwrap().to_string(),
        "spiffe://prod/ns/production/sa/payments"
    );
    assert_eq!(p.namespace, "production");
    assert_eq!(p.workload_name.as_deref(), Some("payments"));
}

#[test]
fn malformed_spiffe_id_does_not_break_parsing() {
    let n = Node {
        id: "n".into(),
        metadata: Some(metadata(&[("SPIFFE_ID", "garbage")])),
        ..Default::default()
    };
    let p = ParsedNode::from_envoy(&n).unwrap();
    assert!(p.spiffe_id.is_none());
}
