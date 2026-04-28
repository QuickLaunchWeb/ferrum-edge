//! Delta xDS resource diffing.
//!
//! Delta xDS responses ship only what changed: added/modified resources
//! plus a list of removed names. This module computes the diff between
//! two snapshot versions for one resource type.
//!
//! ## Why delta is mandatory at scale
//!
//! State-of-the-world (SotW) responses contain every tracked resource
//! every time. For a sidecar tracking 5000 endpoints, a single endpoint
//! flap forces re-emitting all 5000 ClusterLoadAssignments. Delta
//! solves this by emitting just the one that changed.
//!
//! Phase B implements per-snapshot diffing — when the snapshot bumps,
//! the server compares old/new resource sets per type and emits only
//! the changes. Per-resource versioning is conservative (every
//! resource gets the snapshot's version), which is correct but loses
//! some efficiency. Phase C may refine to per-resource hashes.

use std::collections::HashSet;

use envoy_types::pb::envoy::service::discovery::v3::Resource as DeltaResource;
use envoy_types::pb::google::protobuf::Any;
use prost::Message;
use prost::Name;

use super::ResourceType;
use super::snapshot::XdsSnapshot;

/// Result of diffing two snapshots for one resource type.
#[derive(Debug, Default)]
pub struct DeltaDiff {
    /// New or changed resources, ready to drop into
    /// `DeltaDiscoveryResponse.resources`.
    pub added_or_modified: Vec<DeltaResource>,
    /// Names of removed resources, ready to drop into
    /// `DeltaDiscoveryResponse.removed_resources`.
    pub removed: Vec<String>,
}

impl DeltaDiff {
    pub fn is_empty(&self) -> bool {
        self.added_or_modified.is_empty() && self.removed.is_empty()
    }
}

/// Diff `prev` against `curr` for resource type `ty`. Returns the set
/// of added / modified / removed resources.
///
/// `prev` is `None` on the first emission for a stream (everything is
/// "new"). `subscribed` may scope the diff to a subset of resource
/// names (delta xDS allows clients to track a curated list); pass
/// `None` to emit all resources.
pub fn diff(
    prev: Option<&XdsSnapshot>,
    curr: &XdsSnapshot,
    ty: ResourceType,
    subscribed: Option<&HashSet<String>>,
) -> DeltaDiff {
    let prev_names: HashSet<String> = prev
        .map(|s| s.resource_names_sorted(ty).into_iter().collect())
        .unwrap_or_default();
    let curr_names: HashSet<String> = curr.resource_names_sorted(ty).into_iter().collect();

    let mut added_or_modified = Vec::new();
    let mut removed = Vec::new();

    // Names the client doesn't care about are filtered out — but only
    // for added/modified. Removed names are always emitted because the
    // client may have subscribed to a specific name that we just
    // dropped (delta semantics: an unsubscribed-then-resubscribed
    // resource still needs to be re-sent).
    let in_scope = |name: &str| -> bool { subscribed.map(|s| s.contains(name)).unwrap_or(true) };

    for name in &curr_names {
        if !in_scope(name) {
            continue;
        }
        // For Phase B foundation we treat "in curr but not in prev" as
        // added, and "in both" as potentially modified. The version
        // comparison happens at the snapshot level: every snapshot bump
        // marks every resource as changed (conservative). The Phase B
        // delta machinery is correct; the optimisation to per-resource
        // hashing lives in a follow-up.
        if let Some(any) = serialise_resource(curr, ty, name) {
            added_or_modified.push(DeltaResource {
                name: name.clone(),
                version: format!("{}", curr.version),
                resource: Some(any),
                ..Default::default()
            });
        }
    }

    for name in prev_names.difference(&curr_names) {
        removed.push(name.clone());
    }

    DeltaDiff {
        added_or_modified,
        removed,
    }
}

/// Pack the named resource of type `ty` from `snap` as a `google.protobuf.Any`.
fn serialise_resource(snap: &XdsSnapshot, ty: ResourceType, name: &str) -> Option<Any> {
    use envoy_types::pb::envoy::config::cluster::v3::Cluster;
    use envoy_types::pb::envoy::config::endpoint::v3::ClusterLoadAssignment;
    use envoy_types::pb::envoy::config::listener::v3::Listener;
    use envoy_types::pb::envoy::config::route::v3::RouteConfiguration;
    use envoy_types::pb::envoy::extensions::transport_sockets::tls::v3::Secret;

    fn pack<T: Message + Name>(msg: &T) -> Any {
        Any {
            type_url: T::type_url(),
            value: msg.encode_to_vec(),
        }
    }

    match ty {
        ResourceType::Listener => snap.listeners.get(name).map(pack::<Listener>),
        ResourceType::Route => snap.routes.get(name).map(pack::<RouteConfiguration>),
        ResourceType::Cluster => snap.clusters.get(name).map(pack::<Cluster>),
        ResourceType::Endpoint => snap.endpoints.get(name).map(pack::<ClusterLoadAssignment>),
        ResourceType::Secret => snap.secrets.get(name).map(pack::<Secret>),
    }
}

/// Pack the full set of resources of type `ty` from `snap` as a
/// `Vec<google.protobuf.Any>` for inclusion in a SotW
/// `DiscoveryResponse.resources`.
pub fn pack_all(snap: &XdsSnapshot, ty: ResourceType) -> Vec<Any> {
    let mut out = Vec::new();
    for name in snap.resource_names_sorted(ty) {
        if let Some(any) = serialise_resource(snap, ty, &name) {
            out.push(any);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xds::snapshot::{NodeIdentity, XdsSnapshot};
    use crate::xds::translate::*;

    fn make_snapshot(version: u64, listeners: ListenerSet, clusters: ClusterSet) -> XdsSnapshot {
        XdsSnapshot {
            version,
            listeners,
            routes: RouteSet::new(),
            clusters,
            endpoints: EndpointSet::new(),
            secrets: SecretSet::new(),
            identity: NodeIdentity {
                node_id: "n".into(),
                namespace: "default".into(),
                spiffe_id: None,
            },
        }
    }

    #[test]
    fn diff_returns_all_resources_when_prev_is_none() {
        let mut clusters = ClusterSet::new();
        clusters.insert(
            "c1".into(),
            envoy_types::pb::envoy::config::cluster::v3::Cluster {
                name: "c1".into(),
                ..Default::default()
            },
        );
        let snap = make_snapshot(1, ListenerSet::new(), clusters);
        let d = diff(None, &snap, ResourceType::Cluster, None);
        assert_eq!(d.added_or_modified.len(), 1);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn diff_emits_removed_for_dropped_resources() {
        let mut prev_clusters = ClusterSet::new();
        prev_clusters.insert(
            "c1".into(),
            envoy_types::pb::envoy::config::cluster::v3::Cluster {
                name: "c1".into(),
                ..Default::default()
            },
        );
        let prev = make_snapshot(1, ListenerSet::new(), prev_clusters);
        let curr = make_snapshot(2, ListenerSet::new(), ClusterSet::new());
        let d = diff(Some(&prev), &curr, ResourceType::Cluster, None);
        assert!(d.added_or_modified.is_empty());
        assert_eq!(d.removed, vec!["c1".to_string()]);
    }

    #[test]
    fn diff_subscribed_filter_only_affects_added() {
        let mut clusters = ClusterSet::new();
        clusters.insert(
            "c1".into(),
            envoy_types::pb::envoy::config::cluster::v3::Cluster {
                name: "c1".into(),
                ..Default::default()
            },
        );
        clusters.insert(
            "c2".into(),
            envoy_types::pb::envoy::config::cluster::v3::Cluster {
                name: "c2".into(),
                ..Default::default()
            },
        );
        let snap = make_snapshot(1, ListenerSet::new(), clusters);
        let mut subs = HashSet::new();
        subs.insert("c1".to_string());
        let d = diff(None, &snap, ResourceType::Cluster, Some(&subs));
        assert_eq!(d.added_or_modified.len(), 1);
        assert_eq!(d.added_or_modified[0].name, "c1");
    }

    #[test]
    fn pack_all_returns_anys_for_every_listener() {
        let mut listeners = ListenerSet::new();
        listeners.insert(
            "l1".into(),
            envoy_types::pb::envoy::config::listener::v3::Listener {
                name: "l1".into(),
                ..Default::default()
            },
        );
        let snap = make_snapshot(1, listeners, ClusterSet::new());
        let anys = pack_all(&snap, ResourceType::Listener);
        assert_eq!(anys.len(), 1);
        assert!(
            anys[0]
                .type_url
                .contains("envoy.config.listener.v3.Listener")
        );
    }
}
