//! Per-node xDS snapshot cache.
//!
//! ## Snapshot lifecycle
//!
//! 1. Sidecar connects → server calls
//!    [`XdsSnapshotCache::ensure_snapshot`] which slices the live
//!    `GatewayConfig` for that node's identity and caches the result.
//! 2. `GatewayConfig` reloads → CP calls
//!    [`XdsSnapshotCache::recompute_all`] which re-slices for every
//!    cached node, bumps the per-node `version` if the slice changed,
//!    and publishes a [`XdsRefreshSignal`] on the broadcast channel.
//! 3. Sidecar disconnects → snapshot stays in the cache until
//!    [`XdsSnapshotCache::evict`] runs (called from the gRPC stream
//!    drop path or periodic GC).
//!
//! ## Lock-freeness
//!
//! Snapshots are held as `Arc<XdsSnapshot>` in `DashMap<NodeId, Slot>`
//! where `Slot` is `Arc<ArcSwap<Arc<XdsSnapshot>>>`. The hot path
//! (`stream_aggregated_resources`) does:
//!
//! ```ignore
//! let slot = self.snapshots.get(&node_id);
//! let snap = slot.load_full();
//! // emit response from snap …
//! ```
//!
//! Both reads (`get`, `load_full`) are lock-free atomic loads. Reload
//! takes `DashMap::entry` for the slot creation race only; the actual
//! slice swap is an `ArcSwap::store`.
//!
//! ## ACK/NACK state
//!
//! [`StreamSubscription`] carries the per-stream subscription state
//! across multiple ADS messages on the same gRPC stream — last-acked
//! version, last-sent nonce, and any error_detail on NACK. The server
//! reads these to decide whether the next snapshot warrants emission.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use super::ResourceType;
use super::translate::{ClusterSet, EndpointSet, ListenerSet, RouteSet, SecretSet};
use crate::config::types::GatewayConfig;

/// Per-node snapshot. One `Arc<XdsSnapshot>` is built per (node, config-
/// reload) pair. The version is monotonic per node so xDS clients can
/// ACK/NACK it.
#[derive(Debug, Clone)]
pub struct XdsSnapshot {
    /// Monotonic per-node version. ACK / NACK state on the wire echoes
    /// this back as `version_info`.
    pub version: u64,
    /// LDS resources (Listener) keyed by listener name.
    pub listeners: ListenerSet,
    /// RDS resources keyed by route configuration name.
    pub routes: RouteSet,
    /// CDS resources keyed by cluster name.
    pub clusters: ClusterSet,
    /// EDS resources keyed by cluster name (one EDS entry per cluster).
    pub endpoints: EndpointSet,
    /// SDS resources keyed by secret name.
    pub secrets: SecretSet,
    /// Identity used to compute this snapshot. Stored so the snapshot
    /// cache can re-slice on reload without re-reading the originating
    /// request. The server reads this through
    /// [`XdsSnapshotCache::recompute_all`].
    #[allow(dead_code)]
    pub identity: NodeIdentity,
}

impl XdsSnapshot {
    /// Number of resources of `ty` in this snapshot.
    #[allow(dead_code)]
    pub fn resource_count(&self, ty: ResourceType) -> usize {
        match ty {
            ResourceType::Listener => self.listeners.len(),
            ResourceType::Route => self.routes.len(),
            ResourceType::Cluster => self.clusters.len(),
            ResourceType::Endpoint => self.endpoints.len(),
            ResourceType::Secret => self.secrets.len(),
        }
    }

    /// Resource names of type `ty` in this snapshot, sorted for stable
    /// output (helps deterministic delta diffs in tests).
    pub fn resource_names_sorted(&self, ty: ResourceType) -> Vec<String> {
        let mut names: Vec<String> = match ty {
            ResourceType::Listener => self.listeners.keys().cloned().collect(),
            ResourceType::Route => self.routes.keys().cloned().collect(),
            ResourceType::Cluster => self.clusters.keys().cloned().collect(),
            ResourceType::Endpoint => self.endpoints.keys().cloned().collect(),
            ResourceType::Secret => self.secrets.keys().cloned().collect(),
        };
        names.sort();
        names
    }

    /// Per-resource versions for delta xDS — one entry per resource.
    /// The current implementation uses the snapshot's monotonic version
    /// for every resource, which is conservative (every snapshot bump
    /// signals every resource as changed). A finer-grained per-resource
    /// version is a Phase B optimisation tracked in `delta.rs`.
    #[allow(dead_code)]
    pub fn versions_for(&self, ty: ResourceType) -> HashMap<String, u64> {
        self.resource_names_sorted(ty)
            .into_iter()
            .map(|n| (n, self.version))
            .collect()
    }
}

/// Identity carried by an xDS subscription. Used to compute the per-node
/// `MeshSlice` the snapshot is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// xDS Node.id — the snapshot-cache key.
    pub node_id: String,
    /// Namespace from node metadata (or default).
    pub namespace: String,
    /// SPIFFE ID derived from node metadata when present. None means the
    /// node hasn't supplied an identity, in which case the slice falls
    /// back to namespace-wide visibility.
    pub spiffe_id: Option<crate::identity::spiffe::SpiffeId>,
}

/// Per-node snapshot cache. Internal mutability via `DashMap`.
#[derive(Debug, Default)]
pub struct XdsSnapshotCache {
    by_node: DashMap<String, Arc<ArcSwap<XdsSnapshot>>>,
    /// Monotonic global counter, used to mint new per-node versions.
    /// Each node also has its own counter so concurrent reloads on
    /// different nodes don't share a single hot atomic.
    next_version_seed: AtomicU64,
}

impl XdsSnapshotCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the snapshot for `node_id`. Returns `None` if no snapshot
    /// has been built for the node yet.
    #[allow(dead_code)]
    pub fn get(&self, node_id: &str) -> Option<Arc<ArcSwap<XdsSnapshot>>> {
        self.by_node.get(node_id).map(|r| r.value().clone())
    }

    /// Build (or rebuild) the snapshot for `identity` from `config`.
    /// Returns the new snapshot and a flag indicating whether the slice
    /// actually changed since the previous version (for `ACK`/`NACK`
    /// version-bump suppression).
    pub fn ensure_snapshot(
        &self,
        identity: NodeIdentity,
        config: &GatewayConfig,
    ) -> (Arc<XdsSnapshot>, bool) {
        let next_version = self.next_version_seed.fetch_add(1, Ordering::Relaxed) + 1;
        let mut snapshot = build_snapshot(&identity, config, next_version);

        let changed;
        let stored = match self.by_node.entry(identity.node_id.clone()) {
            dashmap::Entry::Occupied(e) => {
                let slot = e.get().clone();
                let prev = slot.load_full();
                if snapshots_equal(&prev, &snapshot) {
                    // No actual change — keep prev (preserves the prev
                    // version_info on the wire).
                    changed = false;
                    return (prev, changed);
                }
                changed = true;
                // Inherit prev version + 1 for monotonic per-node ordering.
                snapshot.version = prev.version + 1;
                let new = Arc::new(snapshot);
                slot.store(new.clone());
                new
            }
            dashmap::Entry::Vacant(v) => {
                changed = true;
                snapshot.version = 1;
                let new = Arc::new(snapshot);
                let slot = Arc::new(ArcSwap::from(new.clone()));
                v.insert(slot);
                new
            }
        };
        (stored, changed)
    }

    /// Recompute snapshots for every cached node. Called when
    /// `GatewayConfig` reloads. Returns the set of node IDs whose snapshot
    /// actually changed.
    ///
    /// The CP integration in `modes/control_plane.rs` (Phase B foundation)
    /// drives this through the broadcast channel rather than calling
    /// directly; the public API here is for integration tests + Phase C.
    #[allow(dead_code)]
    pub fn recompute_all(&self, config: &GatewayConfig) -> HashSet<String> {
        let mut changed = HashSet::new();
        let identities: Vec<NodeIdentity> = self
            .by_node
            .iter()
            .map(|e| e.value().load_full().identity.clone())
            .collect();
        for identity in identities {
            let node_id = identity.node_id.clone();
            let (_, did_change) = self.ensure_snapshot(identity, config);
            if did_change {
                changed.insert(node_id);
            }
        }
        changed
    }

    /// Drop the snapshot for `node_id` (called when a sidecar
    /// disconnects).
    pub fn evict(&self, node_id: &str) {
        self.by_node.remove(node_id);
    }

    /// Number of cached snapshots (for metrics / admin introspection).
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.by_node.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.by_node.is_empty()
    }

    /// Snapshot of all currently-cached node IDs (for admin
    /// introspection / debug endpoints).
    #[allow(dead_code)]
    pub fn node_ids(&self) -> Vec<String> {
        self.by_node.iter().map(|e| e.key().clone()).collect()
    }
}

fn snapshots_equal(a: &XdsSnapshot, b: &XdsSnapshot) -> bool {
    // Compare the resource sets, not the version (which is bumped
    // independently). Resource sets compare on the proto-message
    // representation we already built.
    a.listeners == b.listeners
        && a.routes == b.routes
        && a.clusters == b.clusters
        && a.endpoints == b.endpoints
        && a.secrets == b.secrets
}

/// Build a fresh snapshot from `config` for the given `identity`.
///
/// The version provided is a placeholder; the cache machinery may bump
/// or preserve it before storing.
pub fn build_snapshot(
    identity: &NodeIdentity,
    config: &GatewayConfig,
    candidate_version: u64,
) -> XdsSnapshot {
    use super::translate;

    // If we have a SPIFFE ID, slice the mesh model. Otherwise emit an
    // empty slice — translation pipelines all tolerate empty inputs.
    let slice = if let Some(spiffe_id) = identity.spiffe_id.as_ref() {
        crate::grpc::cp_server::build_slice(config, &identity.namespace, spiffe_id)
    } else {
        None
    };

    let listeners = translate::lds::translate(slice.as_ref(), identity);
    let routes = translate::rds::translate(slice.as_ref(), identity);
    let clusters = translate::cds::translate(slice.as_ref(), identity);
    let endpoints = translate::eds::translate(slice.as_ref(), identity);
    let secrets = translate::sds::translate(slice.as_ref(), identity, config);

    XdsSnapshot {
        version: candidate_version,
        listeners,
        routes,
        clusters,
        endpoints,
        secrets,
        identity: identity.clone(),
    }
}

// ── Per-stream subscription state ─────────────────────────────────────

/// Per-(stream, type_url) subscription state. Tracks the last
/// version/nonce we sent and the last ACK/NACK we received.
///
/// ADS multiplexes multiple type_urls on one gRPC stream, so the server
/// keeps one of these per type per stream.
#[derive(Debug, Clone, Default)]
pub struct StreamSubscription {
    /// The last `version_info` we sent.
    pub last_sent_version: Option<String>,
    /// The last nonce we minted.
    pub last_sent_nonce: Option<String>,
    /// Last ACK'd version (matches `last_sent_version` after a successful
    /// reply from the client).
    pub last_acked_version: Option<String>,
    /// True if the most recent client message was a NACK; `error_detail`
    /// carries the message.
    pub last_was_nack: bool,
    pub last_error_detail: Option<String>,
    /// Resource names the client has subscribed to. `None` means "all"
    /// (per xDS semantics, an empty `resource_names` = wildcard for LDS
    /// and CDS).
    pub subscribed: Option<HashSet<String>>,
}

impl StreamSubscription {
    /// Should we emit a response for this type given the new snapshot
    /// version? Suppresses redundant pushes when nothing changed.
    pub fn should_emit(&self, new_version: &str) -> bool {
        match self.last_sent_version.as_deref() {
            Some(prev) => prev != new_version,
            None => true,
        }
    }

    /// Apply an ACK (or NACK) from the client.
    pub fn record_client_message(
        &mut self,
        response_nonce: Option<&str>,
        client_version: &str,
        error: Option<String>,
    ) {
        // ACK: nonce matches what we sent; version matches what we sent
        // (or is empty on the very first request).
        if let Some(nonce) = response_nonce
            && self.last_sent_nonce.as_deref() != Some(nonce)
        {
            // Nonce mismatch — the client is responding to an older
            // message. Ignore. (xDS spec §"Nonce Behavior".)
            return;
        }
        if error.is_some() {
            self.last_was_nack = true;
            self.last_error_detail = error;
        } else {
            self.last_was_nack = false;
            self.last_error_detail = None;
            self.last_acked_version = Some(client_version.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_identity(node: &str) -> NodeIdentity {
        NodeIdentity {
            node_id: node.into(),
            namespace: "default".into(),
            spiffe_id: None,
        }
    }

    fn empty_config() -> GatewayConfig {
        GatewayConfig::default()
    }

    #[test]
    fn first_ensure_snapshot_assigns_version_one() {
        let cache = XdsSnapshotCache::new();
        let (snap, changed) = cache.ensure_snapshot(empty_identity("a"), &empty_config());
        assert!(changed);
        assert_eq!(snap.version, 1);
    }

    #[test]
    fn rebuilding_unchanged_config_does_not_bump_version() {
        let cache = XdsSnapshotCache::new();
        let (snap1, _) = cache.ensure_snapshot(empty_identity("a"), &empty_config());
        let (snap2, changed) = cache.ensure_snapshot(empty_identity("a"), &empty_config());
        assert!(!changed, "no slice change → no version bump");
        assert_eq!(snap1.version, snap2.version);
    }

    #[test]
    fn evict_drops_node_snapshot() {
        let cache = XdsSnapshotCache::new();
        let _ = cache.ensure_snapshot(empty_identity("a"), &empty_config());
        assert_eq!(cache.len(), 1);
        cache.evict("a");
        assert_eq!(cache.len(), 0);
        assert!(cache.get("a").is_none());
    }

    #[test]
    fn recompute_all_visits_every_node() {
        let cache = XdsSnapshotCache::new();
        let _ = cache.ensure_snapshot(empty_identity("a"), &empty_config());
        let _ = cache.ensure_snapshot(empty_identity("b"), &empty_config());
        // Empty config → empty config → no changes.
        let changed = cache.recompute_all(&empty_config());
        assert!(changed.is_empty());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn subscription_emit_logic() {
        let mut sub = StreamSubscription::default();
        assert!(sub.should_emit("v1"));
        sub.last_sent_version = Some("v1".into());
        assert!(!sub.should_emit("v1"));
        assert!(sub.should_emit("v2"));
    }

    #[test]
    fn subscription_records_ack_and_nack() {
        let mut sub = StreamSubscription {
            last_sent_nonce: Some("n1".into()),
            ..Default::default()
        };
        sub.record_client_message(Some("n1"), "v1", None);
        assert_eq!(sub.last_acked_version.as_deref(), Some("v1"));
        assert!(!sub.last_was_nack);

        sub.record_client_message(Some("n1"), "v1", Some("oh no".into()));
        assert!(sub.last_was_nack);
        assert_eq!(sub.last_error_detail.as_deref(), Some("oh no"));
    }

    #[test]
    fn subscription_ignores_stale_nonce() {
        let mut sub = StreamSubscription {
            last_sent_nonce: Some("n2".into()),
            ..Default::default()
        };
        sub.record_client_message(Some("n1"), "v1", None);
        assert!(sub.last_acked_version.is_none(), "stale nonce → ignored");
    }
}
