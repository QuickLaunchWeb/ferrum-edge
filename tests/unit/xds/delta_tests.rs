//! Tests for delta xDS resource diffing.

use envoy_types::pb::envoy::config::cluster::v3::Cluster;
use envoy_types::pb::envoy::config::listener::v3::Listener;
use ferrum_edge::xds::ResourceType;
use ferrum_edge::xds::delta;
use ferrum_edge::xds::snapshot::{NodeIdentity, XdsSnapshot};
use ferrum_edge::xds::translate::{ClusterSet, EndpointSet, ListenerSet, RouteSet, SecretSet};
use std::collections::HashSet;

fn snapshot(version: u64, listeners: ListenerSet, clusters: ClusterSet) -> XdsSnapshot {
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
fn first_diff_returns_everything() {
    let mut clusters = ClusterSet::new();
    clusters.insert(
        "c1".into(),
        Cluster {
            name: "c1".into(),
            ..Default::default()
        },
    );
    let snap = snapshot(1, ListenerSet::new(), clusters);
    let d = delta::diff(None, &snap, ResourceType::Cluster, None);
    assert_eq!(d.added_or_modified.len(), 1);
    assert!(d.removed.is_empty());
    assert_eq!(d.added_or_modified[0].name, "c1");
    assert!(d.added_or_modified[0].resource.is_some());
}

#[test]
fn diff_marks_dropped_resources_as_removed() {
    let mut prev_clusters = ClusterSet::new();
    prev_clusters.insert(
        "c1".into(),
        Cluster {
            name: "c1".into(),
            ..Default::default()
        },
    );
    let prev = snapshot(1, ListenerSet::new(), prev_clusters);
    let curr = snapshot(2, ListenerSet::new(), ClusterSet::new());
    let d = delta::diff(Some(&prev), &curr, ResourceType::Cluster, None);
    assert_eq!(d.removed, vec!["c1".to_string()]);
    assert!(d.added_or_modified.is_empty());
}

#[test]
fn diff_skips_unsubscribed_added() {
    let mut clusters = ClusterSet::new();
    clusters.insert(
        "c1".into(),
        Cluster {
            name: "c1".into(),
            ..Default::default()
        },
    );
    clusters.insert(
        "c2".into(),
        Cluster {
            name: "c2".into(),
            ..Default::default()
        },
    );
    let snap = snapshot(1, ListenerSet::new(), clusters);
    let mut subs = HashSet::new();
    subs.insert("c1".to_string());
    let d = delta::diff(None, &snap, ResourceType::Cluster, Some(&subs));
    assert_eq!(d.added_or_modified.len(), 1);
    assert_eq!(d.added_or_modified[0].name, "c1");
}

#[test]
fn pack_all_serializes_each_resource_to_any() {
    let mut listeners = ListenerSet::new();
    listeners.insert(
        "l1".into(),
        Listener {
            name: "l1".into(),
            ..Default::default()
        },
    );
    listeners.insert(
        "l2".into(),
        Listener {
            name: "l2".into(),
            ..Default::default()
        },
    );
    let snap = snapshot(1, listeners, ClusterSet::new());
    let anys = delta::pack_all(&snap, ResourceType::Listener);
    assert_eq!(anys.len(), 2);
    for any in &anys {
        assert!(any.type_url.contains("envoy.config.listener.v3.Listener"));
        assert!(!any.value.is_empty());
    }
}

#[test]
fn empty_snapshot_diff_is_empty() {
    let prev = snapshot(1, ListenerSet::new(), ClusterSet::new());
    let curr = snapshot(2, ListenerSet::new(), ClusterSet::new());
    let d = delta::diff(Some(&prev), &curr, ResourceType::Cluster, None);
    assert!(d.is_empty());
}
