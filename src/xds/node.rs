//! xDS Node parsing.
//!
//! Every xDS request carries a `Node` message identifying the requesting
//! sidecar. We extract:
//! - `node.id` — sidecar identity (typically `sidecar~<pod-ip>~<workload>~<ns>`
//!   in Istio's pilot-agent, but any non-empty string is accepted).
//! - `node.cluster` — Istio puts the workload's logical service here.
//! - `node.metadata` — used by Istio for things like `MESH_ID`,
//!   `ISTIO_VERSION`, and crucially `WORKLOAD_NAME` / `NAMESPACE`.
//!
//! The node identity is the security boundary: per-node snapshots ensure
//! workload A never receives workload B's config. The xDS server maps
//! the node's identity into a SPIFFE ID so the canonical mesh model in
//! `crate::config::mesh` can scope the slice. When `node.metadata` carries
//! a `SPIFFE_ID` field (Istio convention) we use it directly; otherwise
//! we attempt to derive it from the workload + namespace metadata.

use envoy_types::pb::envoy::config::core::v3::Node;

use crate::identity::spiffe::SpiffeId;
use std::str::FromStr;

/// A parsed view of an xDS `Node` message — only the fields the Ferrum
/// xDS server reads from. Cheap to clone (mostly `String` clones).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNode {
    /// Sidecar identity. Used as the snapshot-cache key.
    pub id: String,
    /// Cluster (Istio: the logical service). Optional.
    pub cluster: String,
    /// SPIFFE ID, if the node metadata carried one. Used to compute the
    /// per-node `MeshSlice`.
    pub spiffe_id: Option<SpiffeId>,
    /// Namespace, if present in metadata. Falls back to `default`.
    pub namespace: String,
    /// Workload name from metadata (Istio: `WORKLOAD_NAME`).
    pub workload_name: Option<String>,
}

impl ParsedNode {
    /// Parse the xDS node message. Returns an error only when the node
    /// lacks an `id` — a malformed metadata SPIFFE-ID is non-fatal (we
    /// log it and proceed without identity-aware slicing).
    pub fn from_envoy(node: &Node) -> Result<Self, NodeError> {
        if node.id.is_empty() {
            return Err(NodeError::MissingId);
        }
        let metadata = node
            .metadata
            .as_ref()
            .map(|m| &m.fields)
            .cloned()
            .unwrap_or_default();

        let metadata_str = |key: &str| {
            metadata.get(key).and_then(|v| match &v.kind {
                Some(envoy_types::pb::google::protobuf::value::Kind::StringValue(s)) => {
                    Some(s.clone())
                }
                _ => None,
            })
        };

        // Istio puts the SPIFFE ID in `metadata.SPIFFE_ID` for sidecars.
        // We also accept lower-case `spiffe_id` for flexibility.
        let spiffe_str = metadata_str("SPIFFE_ID").or_else(|| metadata_str("spiffe_id"));
        let spiffe_id = spiffe_str
            .as_deref()
            .and_then(|s| SpiffeId::from_str(s).ok());

        let namespace = metadata_str("NAMESPACE")
            .or_else(|| metadata_str("namespace"))
            .unwrap_or_else(|| crate::config::types::DEFAULT_NAMESPACE.to_string());

        let workload_name = metadata_str("WORKLOAD_NAME").or_else(|| metadata_str("workload"));

        Ok(ParsedNode {
            id: node.id.clone(),
            cluster: node.cluster.clone(),
            spiffe_id,
            namespace,
            workload_name,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NodeError {
    #[error("xDS Node.id is empty — required to identify the sidecar")]
    MissingId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_types::pb::envoy::config::core::v3::Node;
    use envoy_types::pb::google::protobuf::{Struct, Value, value::Kind};

    fn struct_with(entries: &[(&str, &str)]) -> Struct {
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
    fn missing_id_is_an_error() {
        let node = Node::default();
        assert_eq!(ParsedNode::from_envoy(&node), Err(NodeError::MissingId));
    }

    #[test]
    fn id_only_node_uses_default_namespace() {
        let node = Node {
            id: "sidecar~10.0.0.1~web~default".into(),
            ..Default::default()
        };
        let parsed = ParsedNode::from_envoy(&node).unwrap();
        assert_eq!(parsed.id, "sidecar~10.0.0.1~web~default");
        assert!(parsed.spiffe_id.is_none());
        assert_eq!(parsed.namespace, "ferrum");
        assert_eq!(parsed.cluster, "");
        assert_eq!(parsed.workload_name, None);
    }

    #[test]
    fn istio_style_metadata_is_extracted() {
        let node = Node {
            id: "sidecar~10.0.0.1~web~production".into(),
            cluster: "web.production".into(),
            metadata: Some(struct_with(&[
                ("SPIFFE_ID", "spiffe://prod/ns/production/sa/web"),
                ("NAMESPACE", "production"),
                ("WORKLOAD_NAME", "web"),
            ])),
            ..Default::default()
        };
        let parsed = ParsedNode::from_envoy(&node).unwrap();
        assert_eq!(parsed.cluster, "web.production");
        assert_eq!(
            parsed.spiffe_id.as_ref().unwrap().to_string(),
            "spiffe://prod/ns/production/sa/web"
        );
        assert_eq!(parsed.namespace, "production");
        assert_eq!(parsed.workload_name.as_deref(), Some("web"));
    }

    #[test]
    fn malformed_spiffe_id_is_silently_ignored() {
        let node = Node {
            id: "n1".into(),
            metadata: Some(struct_with(&[("SPIFFE_ID", "not-a-spiffe-id")])),
            ..Default::default()
        };
        let parsed = ParsedNode::from_envoy(&node).unwrap();
        assert_eq!(parsed.id, "n1");
        assert!(
            parsed.spiffe_id.is_none(),
            "malformed spiffe_id must NOT halt parsing — node.id is the security key"
        );
    }
}
