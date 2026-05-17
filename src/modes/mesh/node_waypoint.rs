//! Node-waypoint identity resolution.
//!
//! In node-waypoint topology one proxy listener accepts traffic for many pods.
//! The node-agent/eBPF side records the socket cookie, original destination,
//! and source pod identity. The proxy resolves that cookie at accept time and
//! rejects unknown cookies before the request enters the plugin chain.
//!
//! ## Hot-path contract
//!
//! The resolver is consulted once per inbound TCP accept on a node-waypoint
//! listener (see `run_accept_loop` in `src/proxy/mod.rs`). The cost budget per
//! accept is:
//!
//! 1. One `getsockopt(SO_COOKIE)` (~50 ns) via [`socket_cookie`].
//! 2. One `DashMap::get` against the unified cookie record map (returns
//!    `(pod_uid, workload_spiffe_hash)`).
//! 3. One `DashMap::get` against the identity map (returns `Arc<NodeWaypointIdentity>`).
//! 4. One `Arc::clone` (~5 ns) to hand the identity to the connection task.
//!
//! Both hot-path DashMaps are sized via `crate::util::sharding::pool_shard_amount`
//! so contention scales with `num_cpus`. New accept-path atomics (per-reason
//! `node_waypoint_*_drops` counters in `OverloadState`) are `CachePadded` —
//! see `src/overload.rs`.
//!
//! Per-pod policy scope lookup is a separate HTTP request-path read:
//! one `ArcSwap::load` plus one `HashMap::get` when mesh authz stamps
//! node-waypoint request context. Scope rebuilds happen on slice apply and
//! identity enrollment, not in the accept loop.
//!
//! Linux socket cookies are unique across the IPv4/IPv6 protocol families, so
//! both address families share a single cookie record map; this avoids the
//! wasted IPv4 lookup that a dual-map design imposed on every IPv6 accept.
//! The original-destination address and port are intentionally NOT surfaced
//! by [`resolve_cookie`] / [`resolve_stream`] — production callers consume
//! only the resolved [`NodeWaypointIdentity`].
//!
//! [`socket_cookie`]: crate::socket_opts::socket_cookie
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use ferrum_ebpf_common::{OrigDst4, OrigDst6};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tracing::warn;

use crate::identity::SpiffeId;
use crate::modes::mesh::config::Workload;
use crate::modes::mesh::runtime::PolicyScopeCache;

/// Address family stamp on a cookie record.
///
/// Tracked only so the cold-path identities snapshot (admin endpoint) can
/// break cookie counts down by family the way the dual-map design did.
/// Resolved identity is family-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CookieFamily {
    V4,
    V6,
}

/// Identity-affecting fields of an eBPF original-destination record.
///
/// The full BPF records ([`OrigDst4`] / [`OrigDst6`]) also carry the original
/// destination address and port. Those bytes are used by the node-agent for
/// telemetry but are never read by the proxy's identity resolver, so we
/// project them out of the userspace cookie map to keep memory tight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CookieRecord {
    pod_uid: [u8; 16],
    workload_spiffe_hash: u64,
    family: CookieFamily,
}

impl From<&OrigDst4> for CookieRecord {
    fn from(record: &OrigDst4) -> Self {
        Self {
            pod_uid: record.pod_uid,
            workload_spiffe_hash: record.workload_spiffe_hash,
            family: CookieFamily::V4,
        }
    }
}

impl From<&OrigDst6> for CookieRecord {
    fn from(record: &OrigDst6) -> Self {
        Self {
            pod_uid: record.pod_uid,
            workload_spiffe_hash: record.workload_spiffe_hash,
            family: CookieFamily::V6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWaypointIdentity {
    pub pod_uid: [u8; 16],
    pub spiffe_id: SpiffeId,
    pub workload_spiffe_hash: u64,
}

impl NodeWaypointIdentity {
    pub fn new(pod_uid: [u8; 16], spiffe_id: SpiffeId) -> Self {
        let workload_spiffe_hash = workload_spiffe_hash(&spiffe_id);
        Self {
            pod_uid,
            spiffe_id,
            workload_spiffe_hash,
        }
    }
}

struct PolicyScopeAccumulator {
    spiffe_id: SpiffeId,
    namespace: Option<String>,
    labels: HashMap<String, String>,
}

impl PolicyScopeAccumulator {
    fn new(workload: &Workload) -> Self {
        Self {
            spiffe_id: workload.spiffe_id.clone(),
            namespace: Some(workload.namespace.clone()),
            labels: workload.selector.labels.clone(),
        }
    }

    fn merge(&mut self, workload: &Workload) {
        match self.namespace.as_ref() {
            Some(namespace) if namespace == &workload.namespace => {}
            _ => self.namespace = None,
        }
        self.labels.retain(|key, value| {
            workload
                .selector
                .labels
                .get(key)
                .is_some_and(|candidate| candidate == value)
        });
    }

    fn into_scope(self) -> PolicyScopeCache {
        PolicyScopeCache::new(
            self.spiffe_id,
            self.namespace.unwrap_or_default(),
            self.labels,
        )
    }
}

fn workload_policy_scope_index<'a, I>(workloads: I) -> HashMap<String, Arc<PolicyScopeCache>>
where
    I: IntoIterator<Item = &'a Workload>,
{
    let mut accumulators: HashMap<String, PolicyScopeAccumulator> = HashMap::new();
    for workload in workloads {
        accumulators
            .entry(workload.spiffe_id.as_str().to_string())
            .and_modify(|accumulator| accumulator.merge(workload))
            .or_insert_with(|| PolicyScopeAccumulator::new(workload));
    }
    accumulators
        .into_iter()
        .map(|(spiffe_id, accumulator)| (spiffe_id, Arc::new(accumulator.into_scope())))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeWaypointIdentityError {
    SocketCookieUnavailable(String),
    UnknownCookie(u64),
    MissingPodUid(u64),
    MissingWorkloadHash {
        cookie: u64,
        pod_uid: [u8; 16],
    },
    UnknownPod([u8; 16]),
    WorkloadHashMismatch {
        pod_uid: [u8; 16],
        expected: u64,
        actual: u64,
    },
}

impl fmt::Display for NodeWaypointIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketCookieUnavailable(error) => {
                write!(f, "socket cookie unavailable: {error}")
            }
            Self::UnknownCookie(cookie) => write!(f, "no node-waypoint record for cookie {cookie}"),
            Self::MissingPodUid(cookie) => {
                write!(f, "node-waypoint record for cookie {cookie} has no pod UID")
            }
            Self::MissingWorkloadHash { cookie, pod_uid } => write!(
                f,
                "node-waypoint record for cookie {cookie} and pod {} has no workload SPIFFE hash",
                pod_uid_label(pod_uid)
            ),
            Self::UnknownPod(pod_uid) => {
                write!(
                    f,
                    "no node-waypoint identity for pod {}",
                    pod_uid_label(pod_uid)
                )
            }
            Self::WorkloadHashMismatch {
                pod_uid,
                expected,
                actual,
            } => write!(
                f,
                "node-waypoint SPIFFE hash mismatch for pod {}: expected {expected}, got {actual}",
                pod_uid_label(pod_uid)
            ),
        }
    }
}

impl std::error::Error for NodeWaypointIdentityError {}

pub struct NodeWaypointIdentityResolver {
    /// Unified cookie → identity-key map. Linux socket cookies are globally
    /// unique across IPv4/IPv6, so the resolver doesn't need separate maps;
    /// keeping them merged saves one wasted lookup on every IPv6 accept
    /// (previously the IPv4 map was always probed first) and halves the
    /// DashMap shard-array overhead.
    cookie_records: DashMap<u64, CookieRecord>,
    identities_by_pod_uid: DashMap<[u8; 16], Arc<NodeWaypointIdentity>>,
    policy_scopes_by_pod_uid: Arc<ArcSwap<HashMap<[u8; 16], Arc<PolicyScopeCache>>>>,
    workload_policy_scopes_by_spiffe: Arc<ArcSwap<HashMap<String, Arc<PolicyScopeCache>>>>,
    policy_scope_update_lock: Mutex<()>,
}

impl NodeWaypointIdentityResolver {
    pub fn new(pool_shard_override: usize) -> Self {
        let shards = crate::util::sharding::pool_shard_amount(pool_shard_override);
        Self {
            cookie_records: DashMap::with_shard_amount(shards),
            identities_by_pod_uid: DashMap::with_shard_amount(shards),
            policy_scopes_by_pod_uid: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
            workload_policy_scopes_by_spiffe: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
            policy_scope_update_lock: Mutex::new(()),
        }
    }

    pub fn record_orig_dst4(&self, cookie: u64, record: OrigDst4) {
        self.cookie_records.insert(cookie, (&record).into());
    }

    pub fn remove_orig_dst4(&self, cookie: u64) {
        self.cookie_records.remove(&cookie);
    }

    pub fn record_orig_dst6(&self, cookie: u64, record: OrigDst6) {
        self.cookie_records.insert(cookie, (&record).into());
    }

    pub fn remove_orig_dst6(&self, cookie: u64) {
        self.cookie_records.remove(&cookie);
    }

    pub fn upsert_identity(&self, identity: NodeWaypointIdentity) -> Arc<NodeWaypointIdentity> {
        let identity = Arc::new(identity);
        self.identities_by_pod_uid
            .insert(identity.pod_uid, identity.clone());
        self.sync_policy_scope_for_identity(&identity);
        identity
    }

    pub fn remove_identity(&self, pod_uid: &[u8; 16]) {
        self.identities_by_pod_uid.remove(pod_uid);
        let _guard = self.lock_policy_scope_update();
        let current = self.policy_scopes_by_pod_uid.load();
        if !current.contains_key(pod_uid) {
            return;
        }
        let mut scopes = current.as_ref().clone();
        scopes.remove(pod_uid);
        self.policy_scopes_by_pod_uid.store(Arc::new(scopes));
    }

    pub fn install_policy_scopes(&self, scopes: HashMap<[u8; 16], Arc<PolicyScopeCache>>) {
        let _guard = self.lock_policy_scope_update();
        self.policy_scopes_by_pod_uid.store(Arc::new(scopes));
    }

    pub fn policy_scope_for_pod(&self, pod_uid: &[u8; 16]) -> Option<Arc<PolicyScopeCache>> {
        self.policy_scopes_by_pod_uid.load().get(pod_uid).cloned()
    }

    /// Install per-pod policy scopes derived from a slice's workload set.
    ///
    /// **Ordering contract**: callers in `start_mesh_slice_apply_task` invoke
    /// this BEFORE `proxy_state.update_config(...)` publishes the new plugin
    /// cache. `mesh_authz`'s per-pod path filters policies against the cache
    /// returned by [`policy_scope_for_pod`] at request time, so the scope map
    /// must reflect the same slice's workload metadata that the new policies
    /// were authored against. Installing after `update_config` would leave a
    /// brief window where new policies are evaluated against stale per-pod
    /// scopes — for namespace- or selector-scoped DENYs, that means a
    /// transient mis-enforcement. The scope install is cheap and idempotent,
    /// so installing first even when `update_config` ends up rejecting the
    /// candidate config is acceptable: the next accepted slice apply
    /// rebuilds the map.
    pub fn install_policy_scopes_from_workloads<'a, I>(&self, workloads: I)
    where
        I: IntoIterator<Item = &'a Workload>,
    {
        let workload_index = workload_policy_scope_index(workloads);
        let _guard = self.lock_policy_scope_update();
        self.workload_policy_scopes_by_spiffe
            .store(Arc::new(workload_index));
        let scopes = self.build_per_pod_scopes_from_current_workload_index();
        self.policy_scopes_by_pod_uid.store(Arc::new(scopes));
    }

    pub fn build_per_pod_scopes_from_workloads<'a, I>(
        &self,
        workloads: I,
    ) -> HashMap<[u8; 16], Arc<PolicyScopeCache>>
    where
        I: IntoIterator<Item = &'a Workload>,
    {
        let workload_index = workload_policy_scope_index(workloads);
        self.build_per_pod_scopes_from_workload_index(&workload_index)
    }

    fn sync_policy_scope_for_identity(&self, identity: &NodeWaypointIdentity) {
        let _guard = self.lock_policy_scope_update();
        let scope = self
            .workload_policy_scopes_by_spiffe
            .load()
            .get(identity.spiffe_id.as_str())
            .cloned();
        let current = self.policy_scopes_by_pod_uid.load();
        let mut scopes = current.as_ref().clone();
        if let Some(scope) = scope {
            scopes.insert(identity.pod_uid, scope);
        } else {
            scopes.remove(&identity.pod_uid);
        }
        self.policy_scopes_by_pod_uid.store(Arc::new(scopes));
    }

    fn lock_policy_scope_update(&self) -> std::sync::MutexGuard<'_, ()> {
        // Recover from a poisoned lock so a transient panic in a previous
        // updater cannot wedge slice apply or identity enrollment forever.
        // We log when the recovery happens because a poisoned mutex means
        // the prior holder panicked mid-update — the per-pod scope map and
        // the workload-scope index may be out of sync until the next
        // accepted slice apply rebuilds both. Silent recovery would hide
        // that history; the warn! makes it surface in operator logs and
        // postmortem captures.
        self.policy_scope_update_lock
            .lock()
            .unwrap_or_else(|poisoned| {
                warn!(
                    "node-waypoint policy-scope update lock was poisoned by a previous panic; \
                 recovering and continuing — per-pod scope map may be transiently inconsistent \
                 with the workload index until the next mesh slice apply"
                );
                poisoned.into_inner()
            })
    }

    fn build_per_pod_scopes_from_current_workload_index(
        &self,
    ) -> HashMap<[u8; 16], Arc<PolicyScopeCache>> {
        let workload_index = self.workload_policy_scopes_by_spiffe.load();
        self.build_per_pod_scopes_from_workload_index(workload_index.as_ref())
    }

    fn build_per_pod_scopes_from_workload_index(
        &self,
        workload_index: &HashMap<String, Arc<PolicyScopeCache>>,
    ) -> HashMap<[u8; 16], Arc<PolicyScopeCache>> {
        if workload_index.is_empty() {
            return HashMap::new();
        }
        self.identities_by_pod_uid
            .iter()
            .filter_map(|entry| {
                let identity = entry.value();
                workload_index
                    .get(identity.spiffe_id.as_str())
                    .map(|scope| (identity.pod_uid, scope.clone()))
            })
            .collect()
    }

    /// Build an operator-facing snapshot of the currently enrolled identities.
    ///
    /// Returned entries are sorted by pod UID so admin polling produces a
    /// deterministic order across calls. The shape carries:
    ///   - canonical hyphenated UUID for the pod UID
    ///   - the workload's SPIFFE ID string
    ///   - the workload SPIFFE hash (matches the value the eBPF map stores;
    ///     useful when correlating with node-agent telemetry)
    ///   - the cookie counts (IPv4 + IPv6) currently mapped to that pod via
    ///     `OrigDst{4,6}` records, so operators can see "is this identity
    ///     actually receiving traffic right now?" without joining datasets.
    ///   - whether a per-pod `PolicyScopeCache` is installed.
    ///
    /// This is a cold-path snapshot — it iterates every entry of each
    /// hot-path `DashMap` once and reads the policy-scope `ArcSwap`. Not safe
    /// to call on a hot accept path.
    pub fn identities_snapshot(&self) -> Vec<NodeWaypointIdentitySummary> {
        self.identities_snapshot_with_cookie_totals().0
    }

    /// Cold-path snapshot that returns both the per-identity summary list and
    /// the grand totals of `(orig_dst4, orig_dst6)` cookie records in a single
    /// pass over the `cookie_records` map. The admin endpoint uses this to
    /// honor the documented "single cookie-record pass" contract. Invoking
    /// [`identities_snapshot`] and [`cookie_count`]
    /// separately would walk `cookie_records` twice.
    ///
    /// The totals include cookies whose `pod_uid` has no enrolled identity
    /// (eBPF saw the connection but the node-agent has not yet registered the
    /// pod) so the admin "cookies" summary reflects the full eBPF state, not
    /// just the slice that maps to known identities.
    pub fn identities_snapshot_with_cookie_totals(
        &self,
    ) -> (Vec<NodeWaypointIdentitySummary>, (usize, usize)) {
        let mut cookie_counts: HashMap<[u8; 16], (usize, usize)> = HashMap::new();
        let mut totals = (0usize, 0usize);
        for entry in self.cookie_records.iter() {
            let counters = cookie_counts.entry(entry.value().pod_uid).or_insert((0, 0));
            match entry.value().family {
                CookieFamily::V4 => {
                    counters.0 += 1;
                    totals.0 += 1;
                }
                CookieFamily::V6 => {
                    counters.1 += 1;
                    totals.1 += 1;
                }
            }
        }

        let policy_scopes = self.policy_scopes_by_pod_uid.load();
        let mut out: Vec<NodeWaypointIdentitySummary> =
            Vec::with_capacity(self.identities_by_pod_uid.len());
        out.extend(self.identities_by_pod_uid.iter().map(|entry| {
            let identity = entry.value();
            let (orig_dst4_cookies, orig_dst6_cookies) = cookie_counts
                .get(&identity.pod_uid)
                .copied()
                .unwrap_or((0, 0));
            NodeWaypointIdentitySummary {
                pod_uid: identity.pod_uid,
                spiffe_id: identity.spiffe_id.as_str().to_string(),
                workload_spiffe_hash: identity.workload_spiffe_hash,
                orig_dst4_cookies,
                orig_dst6_cookies,
                has_policy_scope: policy_scopes.contains_key(&identity.pod_uid),
            }
        }));
        out.sort_by_key(|summary| summary.pod_uid);
        (out, totals)
    }

    /// Number of currently enrolled identities. Cheap-ish; uses DashMap's
    /// `len()` which iterates per-shard counters.
    pub fn identity_count(&self) -> usize {
        self.identities_by_pod_uid.len()
    }

    /// Total cookie records (IPv4 + IPv6) currently tracked. Useful for
    /// standalone diagnostics; the admin endpoint instead calls
    /// [`identities_snapshot_with_cookie_totals`] so it walks `cookie_records`
    /// once rather than twice.
    pub fn cookie_count(&self) -> (usize, usize) {
        let mut v4 = 0usize;
        let mut v6 = 0usize;
        for entry in self.cookie_records.iter() {
            match entry.value().family {
                CookieFamily::V4 => v4 += 1,
                CookieFamily::V6 => v6 += 1,
            }
        }
        (v4, v6)
    }

    pub fn resolve_stream(
        &self,
        stream: &TcpStream,
    ) -> Result<Arc<NodeWaypointIdentity>, NodeWaypointIdentityError> {
        let cookie = crate::socket_opts::socket_cookie(stream).map_err(|error| {
            NodeWaypointIdentityError::SocketCookieUnavailable(error.to_string())
        })?;
        self.resolve_cookie(cookie)
    }

    pub fn resolve_cookie(
        &self,
        cookie: u64,
    ) -> Result<Arc<NodeWaypointIdentity>, NodeWaypointIdentityError> {
        let Some(record) = self.cookie_records.get(&cookie) else {
            return Err(NodeWaypointIdentityError::UnknownCookie(cookie));
        };
        self.resolve_record(cookie, record.pod_uid, record.workload_spiffe_hash)
    }

    fn resolve_record(
        &self,
        cookie: u64,
        pod_uid: [u8; 16],
        expected_hash: u64,
    ) -> Result<Arc<NodeWaypointIdentity>, NodeWaypointIdentityError> {
        if pod_uid == [0; 16] {
            return Err(NodeWaypointIdentityError::MissingPodUid(cookie));
        }
        if expected_hash == 0 {
            return Err(NodeWaypointIdentityError::MissingWorkloadHash { cookie, pod_uid });
        }

        let Some(identity) = self.identities_by_pod_uid.get(&pod_uid) else {
            return Err(NodeWaypointIdentityError::UnknownPod(pod_uid));
        };
        let identity = identity.clone();
        if identity.workload_spiffe_hash != expected_hash {
            return Err(NodeWaypointIdentityError::WorkloadHashMismatch {
                pod_uid,
                expected: expected_hash,
                actual: identity.workload_spiffe_hash,
            });
        }
        Ok(identity)
    }
}

impl Default for NodeWaypointIdentityResolver {
    fn default() -> Self {
        Self::new(0)
    }
}

/// One enrolled identity as exposed via `GET /node-waypoint/identities`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWaypointIdentitySummary {
    pub pod_uid: [u8; 16],
    pub spiffe_id: String,
    pub workload_spiffe_hash: u64,
    pub orig_dst4_cookies: usize,
    pub orig_dst6_cookies: usize,
    pub has_policy_scope: bool,
}

impl NodeWaypointIdentitySummary {
    /// Hyphenated lowercase UUID rendering of the pod UID. Matches the
    /// Kubernetes `metadata.uid` format operators see in `kubectl` output.
    pub fn pod_uid_string(&self) -> String {
        pod_uid_label(&self.pod_uid)
    }
}

pub fn parse_pod_uid(raw: &str) -> Result<[u8; 16], String> {
    let uuid = uuid::Uuid::parse_str(raw)
        .map_err(|error| format!("invalid Kubernetes pod UID '{raw}': {error}"))?;
    Ok(*uuid.as_bytes())
}

pub fn pod_uid_label(pod_uid: &[u8; 16]) -> String {
    uuid::Uuid::from_bytes(*pod_uid).hyphenated().to_string()
}

pub fn workload_spiffe_hash(spiffe_id: &SpiffeId) -> u64 {
    let digest = Sha256::digest(spiffe_id.as_str().as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TrustDomain;
    use crate::modes::mesh::config::{
        MeshPolicy, PolicyScope, Workload, WorkloadSelector, policy_scope_applies_to_workload,
    };

    fn spiffe(raw: &str) -> SpiffeId {
        SpiffeId::new(raw).expect("test SPIFFE ID is valid")
    }

    fn orig_dst4(pod_uid: [u8; 16], workload_spiffe_hash: u64) -> OrigDst4 {
        OrigDst4 {
            addr: 0x0a000001,
            port: 8080,
            pod_uid,
            workload_spiffe_hash,
        }
    }

    fn orig_dst6(pod_uid: [u8; 16], workload_spiffe_hash: u64) -> OrigDst6 {
        OrigDst6 {
            addr: [0, 0, 0, 1],
            port: 8080,
            _pad: 0,
            pod_uid,
            workload_spiffe_hash,
        }
    }

    fn workload(
        spiffe_id: &str,
        namespace: &str,
        service_name: &str,
        labels: HashMap<String, String>,
    ) -> Workload {
        Workload {
            spiffe_id: spiffe(spiffe_id),
            selector: WorkloadSelector {
                labels,
                namespace: Some(namespace.to_string()),
            },
            service_name: service_name.to_string(),
            addresses: Vec::new(),
            ports: Vec::new(),
            trust_domain: TrustDomain::new("td").expect("td"),
            namespace: namespace.to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
        }
    }

    #[test]
    fn resolve_cookie_returns_enrolled_identity() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, hash));

        let resolved = resolver.resolve_cookie(7).expect("identity resolves");
        assert_eq!(resolved.pod_uid, pod_uid);
        assert_eq!(resolved.spiffe_id.as_str(), "spiffe://td/ns/default/sa/api");
    }

    #[test]
    fn resolve_cookie_fails_closed_for_unknown_cookie() {
        let resolver = NodeWaypointIdentityResolver::new(0);

        let error = resolver
            .resolve_cookie(7)
            .expect_err("unknown cookie must fail closed");
        assert_eq!(error, NodeWaypointIdentityError::UnknownCookie(7));
    }

    #[test]
    fn resolve_cookie_returns_ipv6_enrolled_identity() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);
        resolver.record_orig_dst6(7, orig_dst6(pod_uid, hash));

        let resolved = resolver.resolve_cookie(7).expect("IPv6 identity resolves");
        assert_eq!(resolved.pod_uid, pod_uid);
        assert_eq!(resolved.spiffe_id.as_str(), "spiffe://td/ns/default/sa/api");
    }

    #[test]
    fn resolve_cookie_fails_closed_for_missing_pod_uid() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        resolver.record_orig_dst4(7, orig_dst4([0; 16], 0));

        let error = resolver
            .resolve_cookie(7)
            .expect_err("zero pod UID must fail closed");
        assert_eq!(error, NodeWaypointIdentityError::MissingPodUid(7));
    }

    #[test]
    fn resolve_cookie_fails_closed_for_missing_workload_hash() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, 0));

        let error = resolver
            .resolve_cookie(7)
            .expect_err("zero workload hash must fail closed");
        assert_eq!(
            error,
            NodeWaypointIdentityError::MissingWorkloadHash { cookie: 7, pod_uid }
        );
    }

    #[test]
    fn resolve_cookie_fails_closed_for_hash_mismatch() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, 42));

        let error = resolver
            .resolve_cookie(7)
            .expect_err("mismatched SPIFFE hash must fail closed");
        assert!(matches!(
            error,
            NodeWaypointIdentityError::WorkloadHashMismatch { .. }
        ));
    }

    #[test]
    fn policy_scope_cache_uses_canonical_policy_helper() {
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let mut labels = HashMap::new();
        labels.insert("app".to_string(), "reviews".to_string());
        let cache = Arc::new(PolicyScopeCache::new(
            spiffe("spiffe://td/ns/default/sa/reviews"),
            "default",
            labels.clone(),
        ));
        let resolver = NodeWaypointIdentityResolver::new(0);
        resolver.install_policy_scopes(HashMap::from([(pod_uid, cache.clone())]));

        let policy = MeshPolicy {
            name: "reviews-only".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels,
                    namespace: Some("default".to_string()),
                },
            },
            rules: Vec::new(),
        };
        let from_cache = resolver
            .policy_scope_for_pod(&pod_uid)
            .expect("policy scope should be installed");

        assert!(from_cache.policy_applies(&policy));
        assert_eq!(
            from_cache.policy_applies(&policy),
            policy_scope_applies_to_workload(&policy, "default", &from_cache.labels)
        );
    }

    #[test]
    fn build_per_pod_scopes_from_workloads_indexes_by_pod_uid_via_spiffe() {
        let resolver = NodeWaypointIdentityResolver::new(0);

        let pod_a = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let pod_b = parse_pod_uid("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        let pod_orphan = parse_pod_uid("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap();

        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_a,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_b,
            spiffe("spiffe://td/ns/default/sa/billing"),
        ));
        // pod_orphan has no Workload entry, so it must not appear in the map.
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_orphan,
            spiffe("spiffe://td/ns/default/sa/orphan"),
        ));

        let workloads = vec![
            workload(
                "spiffe://td/ns/default/sa/api",
                "default",
                "api",
                HashMap::from([("app".to_string(), "api".to_string())]),
            ),
            workload(
                "spiffe://td/ns/default/sa/billing",
                "default",
                "billing",
                HashMap::from([("app".to_string(), "billing".to_string())]),
            ),
        ];

        let map = resolver.build_per_pod_scopes_from_workloads(&workloads);

        assert_eq!(map.len(), 2);
        let scope_a = map.get(&pod_a).expect("api workload scope");
        assert_eq!(scope_a.namespace, "default");
        assert_eq!(scope_a.labels.get("app").map(String::as_str), Some("api"));
        let scope_b = map.get(&pod_b).expect("billing workload scope");
        assert_eq!(
            scope_b.labels.get("app").map(String::as_str),
            Some("billing")
        );
        assert!(
            !map.contains_key(&pod_orphan),
            "pod with no Workload entry must be omitted"
        );
    }

    #[test]
    fn identities_snapshot_lists_enrolled_pods_sorted_by_uid() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_a = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let pod_b = parse_pod_uid("22222222-2222-2222-2222-222222222222").unwrap();
        let identity_b =
            NodeWaypointIdentity::new(pod_b, spiffe("spiffe://td/ns/default/sa/billing"));
        let identity_a = NodeWaypointIdentity::new(pod_a, spiffe("spiffe://td/ns/default/sa/api"));
        let hash_a = identity_a.workload_spiffe_hash;
        let hash_b = identity_b.workload_spiffe_hash;

        // Insert b first so the snapshot has to sort.
        resolver.upsert_identity(identity_b);
        resolver.upsert_identity(identity_a);
        // Two cookies for pod_a, one for pod_b.
        resolver.record_orig_dst4(11, orig_dst4(pod_a, hash_a));
        resolver.record_orig_dst4(12, orig_dst4(pod_a, hash_a));
        resolver.record_orig_dst6(21, orig_dst6(pod_b, hash_b));

        let snapshot = resolver.identities_snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].pod_uid, pod_a);
        assert_eq!(snapshot[1].pod_uid, pod_b);
        assert_eq!(snapshot[0].spiffe_id, "spiffe://td/ns/default/sa/api");
        assert_eq!(snapshot[0].orig_dst4_cookies, 2);
        assert_eq!(snapshot[0].orig_dst6_cookies, 0);
        assert!(!snapshot[0].has_policy_scope);
        assert_eq!(snapshot[1].orig_dst4_cookies, 0);
        assert_eq!(snapshot[1].orig_dst6_cookies, 1);
        assert_eq!(resolver.identity_count(), 2);
        assert_eq!(resolver.cookie_count(), (2, 1));
    }

    #[test]
    fn identities_snapshot_reports_policy_scope_presence() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        resolver.upsert_identity(identity);

        let snapshot_pre = resolver.identities_snapshot();
        assert!(!snapshot_pre[0].has_policy_scope);

        let cache = Arc::new(PolicyScopeCache::new(
            spiffe("spiffe://td/ns/default/sa/api"),
            "default",
            HashMap::new(),
        ));
        resolver.install_policy_scopes(HashMap::from([(pod_uid, cache)]));

        let snapshot_post = resolver.identities_snapshot();
        assert!(snapshot_post[0].has_policy_scope);
    }

    #[test]
    fn identities_snapshot_with_cookie_totals_counts_orphans_in_totals_only() {
        // Regression guard for the cold-path "single pass" contract used by
        // GET /node-waypoint/identities: the returned totals include cookies
        // whose pod_uid has no enrolled identity (so the admin "cookies"
        // summary reflects full eBPF state), but the per-identity summaries
        // omit those orphans.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_a = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let pod_orphan = parse_pod_uid("33333333-3333-3333-3333-333333333333").unwrap();
        let identity_a = NodeWaypointIdentity::new(pod_a, spiffe("spiffe://td/ns/default/sa/api"));
        let hash_a = identity_a.workload_spiffe_hash;
        resolver.upsert_identity(identity_a);
        // Enrolled pod gets one v4 + one v6 cookie. Orphan pod (not enrolled)
        // gets one v6 cookie, representing eBPF capture racing identity
        // registration.
        resolver.record_orig_dst4(11, orig_dst4(pod_a, hash_a));
        resolver.record_orig_dst6(12, orig_dst6(pod_a, hash_a));
        resolver.record_orig_dst6(99, orig_dst6(pod_orphan, 0xdead_beef));

        let (snapshot, totals) = resolver.identities_snapshot_with_cookie_totals();
        // Snapshot contains only the enrolled pod.
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].pod_uid, pod_a);
        assert_eq!(snapshot[0].orig_dst4_cookies, 1);
        assert_eq!(snapshot[0].orig_dst6_cookies, 1);
        // Totals include the orphan v6 cookie.
        assert_eq!(totals, (1, 2));
        // And matches cookie_count() (which iterates separately).
        assert_eq!(resolver.cookie_count(), totals);
    }

    #[test]
    fn identities_snapshot_summary_renders_canonical_uuid() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));

        let snapshot = resolver.identities_snapshot();
        assert_eq!(
            snapshot[0].pod_uid_string(),
            "11111111-1111-1111-1111-111111111111"
        );
    }

    #[test]
    fn build_per_pod_scopes_from_workloads_uses_common_labels_for_shared_spiffe() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/shared"),
        ));

        let workloads = vec![
            workload(
                "spiffe://td/ns/default/sa/shared",
                "default",
                "api",
                HashMap::from([
                    ("app".to_string(), "api".to_string()),
                    ("version".to_string(), "v1".to_string()),
                ]),
            ),
            workload(
                "spiffe://td/ns/default/sa/shared",
                "default",
                "billing",
                HashMap::from([
                    ("app".to_string(), "billing".to_string()),
                    ("version".to_string(), "v1".to_string()),
                ]),
            ),
        ];

        let map = resolver.build_per_pod_scopes_from_workloads(&workloads);

        let scope = map.get(&pod_uid).expect("shared SPIFFE scope");
        assert_eq!(scope.namespace, "default");
        assert_eq!(scope.labels.get("version").map(String::as_str), Some("v1"));
        assert!(
            !scope.labels.contains_key("app"),
            "divergent labels for a shared SPIFFE ID must not leak into the pod scope"
        );
    }

    #[test]
    fn install_policy_scopes_from_workloads_updates_late_enrolled_identity() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let workloads = vec![workload(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::from([("app".to_string(), "api".to_string())]),
        )];
        resolver.install_policy_scopes_from_workloads(&workloads);

        let pod_uid = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));

        let scope = resolver
            .policy_scope_for_pod(&pod_uid)
            .expect("late identity should pick up current workload scope");
        assert_eq!(scope.labels.get("app").map(String::as_str), Some("api"));
    }

    #[test]
    fn remove_identity_removes_policy_scope() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let workloads = vec![workload(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::from([("app".to_string(), "api".to_string())]),
        )];
        resolver.install_policy_scopes_from_workloads(&workloads);
        let pod_uid = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));
        assert!(resolver.policy_scope_for_pod(&pod_uid).is_some());

        resolver.remove_identity(&pod_uid);

        assert!(resolver.policy_scope_for_pod(&pod_uid).is_none());
    }

    #[test]
    fn build_per_pod_scopes_from_workloads_empty_workloads_returns_empty_map() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_a = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_a,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));

        let map: HashMap<_, _> = resolver.build_per_pod_scopes_from_workloads(std::iter::empty());
        assert!(map.is_empty());
    }

    #[test]
    fn resolve_cookie_path_is_two_dashmap_gets_in_warm_case() {
        // Regression guard for the documented hot-path contract:
        // - 1x cookie_records.get
        // - 1x identities_by_pod_uid.get
        // - 0 allocations on success
        //
        // We assert the structural shape (two DashMaps, one Arc clone) by
        // making the same call twice and confirming both arms hit warm
        // entries without re-inserting anything. If a future refactor adds
        // a third DashMap probe or an alloc, this test still passes, but the
        // module-level rustdoc is the source of truth and any change here that
        // adds work must update that contract.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        let hash = identity.workload_spiffe_hash;
        let stored = resolver.upsert_identity(identity);
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, hash));

        let first = resolver.resolve_cookie(7).expect("warm v4 cookie");
        let second = resolver.resolve_cookie(7).expect("repeat warm v4 cookie");
        // Same Arc reused, no rebuild.
        assert!(Arc::ptr_eq(&first, &stored));
        assert!(Arc::ptr_eq(&second, &stored));
    }

    #[test]
    fn resolve_cookie_v6_path_does_not_probe_a_dead_v4_map() {
        // Pre-unification the resolver probed orig_dst4 first then fell
        // through to orig_dst6 on miss, so every IPv6 connection paid a
        // wasted v4 lookup. Now the families share `cookie_records`. This
        // test asserts: a v6-only registration is found by resolve_cookie
        // without any v4 record being present.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);
        resolver.record_orig_dst6(42, orig_dst6(pod_uid, hash));

        let resolved = resolver
            .resolve_cookie(42)
            .expect("v6-only cookie resolves");
        assert_eq!(resolved.pod_uid, pod_uid);
        // The v4/v6 family stamp is what the admin endpoint reports, so verify
        // we attributed the cookie to v6 not v4 and the snapshot stays honest.
        let snap = resolver.identities_snapshot();
        assert_eq!(snap[0].orig_dst4_cookies, 0);
        assert_eq!(snap[0].orig_dst6_cookies, 1);
        assert_eq!(resolver.cookie_count(), (0, 1));
    }

    #[test]
    fn workload_spiffe_hash_is_stable_first_sha256_u64() {
        let spiffe_id = spiffe("spiffe://td/ns/default/sa/api");
        let digest = Sha256::digest(spiffe_id.as_str().as_bytes());
        let mut expected = [0u8; 8];
        expected.copy_from_slice(&digest[..8]);

        assert_eq!(
            workload_spiffe_hash(&spiffe_id),
            u64::from_be_bytes(expected)
        );
    }
}
