//! Public-API tests for the per-node snapshot cache.

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::SpiffeId;
use ferrum_edge::xds::snapshot::{NodeIdentity, XdsSnapshotCache};
use std::str::FromStr;

fn identity(node: &str) -> NodeIdentity {
    NodeIdentity {
        node_id: node.into(),
        namespace: "ferrum".into(),
        spiffe_id: None,
    }
}

#[test]
fn first_snapshot_for_node_starts_at_version_one() {
    let cache = XdsSnapshotCache::new();
    let (snap, changed) = cache.ensure_snapshot(identity("a"), &GatewayConfig::default());
    assert!(changed);
    assert_eq!(snap.version, 1);
    assert_eq!(cache.len(), 1);
}

#[test]
fn unchanged_config_does_not_bump_version() {
    let cache = XdsSnapshotCache::new();
    let (snap1, _) = cache.ensure_snapshot(identity("a"), &GatewayConfig::default());
    let (snap2, changed) = cache.ensure_snapshot(identity("a"), &GatewayConfig::default());
    assert!(!changed);
    assert_eq!(snap1.version, snap2.version);
}

#[test]
fn different_nodes_have_independent_snapshots() {
    let cache = XdsSnapshotCache::new();
    let _ = cache.ensure_snapshot(identity("a"), &GatewayConfig::default());
    let (snap_b, _) = cache.ensure_snapshot(identity("b"), &GatewayConfig::default());
    assert_eq!(snap_b.identity.node_id, "b");
    assert_eq!(cache.len(), 2);
}

#[test]
fn evict_drops_node() {
    let cache = XdsSnapshotCache::new();
    let _ = cache.ensure_snapshot(identity("a"), &GatewayConfig::default());
    cache.evict("a");
    assert!(cache.get("a").is_none());
    assert_eq!(cache.len(), 0);
}

#[test]
fn snapshots_for_workload_with_no_spiffe_id_emit_empty_resources() {
    // No SPIFFE ID + empty config → empty translation outputs (the
    // snapshot fields are still allocated so xDS clients can subscribe
    // to types that exist).
    let cache = XdsSnapshotCache::new();
    let (snap, _) = cache.ensure_snapshot(identity("anon"), &GatewayConfig::default());
    assert!(snap.listeners.is_empty());
    assert!(snap.routes.is_empty());
    assert!(snap.clusters.is_empty());
    assert!(snap.endpoints.is_empty());
    // SDS always emits the two named secrets even with no slice.
    assert_eq!(snap.secrets.len(), 2);
}

#[test]
fn recompute_all_only_returns_changed_nodes() {
    let cache = XdsSnapshotCache::new();
    let _ = cache.ensure_snapshot(identity("a"), &GatewayConfig::default());
    let _ = cache.ensure_snapshot(identity("b"), &GatewayConfig::default());
    let changed = cache.recompute_all(&GatewayConfig::default());
    // No actual config change → no node sees a version bump.
    assert!(changed.is_empty());
}

#[test]
fn snapshot_carries_identity_for_later_recompute() {
    let cache = XdsSnapshotCache::new();
    let id = NodeIdentity {
        node_id: "wl".into(),
        namespace: "ns".into(),
        spiffe_id: SpiffeId::from_str("spiffe://prod/ns/ns/sa/wl").ok(),
    };
    let (snap, _) = cache.ensure_snapshot(id.clone(), &GatewayConfig::default());
    assert_eq!(snap.identity, id);
}
