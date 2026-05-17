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
//! Linux socket cookies are unique across the IPv4/IPv6 protocol families, so
//! both address families share a single cookie record map; this avoids the
//! wasted IPv4 lookup that a dual-map design imposed on every IPv6 accept.
//! The original-destination address and port are intentionally NOT surfaced
//! by [`resolve_cookie`] / [`resolve_stream`] — production callers consume
//! only the resolved [`NodeWaypointIdentity`].
//!
//! [`socket_cookie`]: crate::socket_opts::socket_cookie
//!
//! ## Cgroup-inode lifecycle binding (GAP-2M.5)
//!
//! Pods get evicted, restarted, or rescheduled all the time. The kubelet
//! creates a fresh cgroup directory for every pod instance, so a pod restart
//! is observable as a cgroup-inode change at the same path. The resolver
//! optionally binds each enrolled identity to a cgroup v2 path captured at
//! enrollment time (`upsert_identity_with_cgroup`). Enrollment stores the
//! inode plus a small metadata fingerprint so inode reuse does not mask pod
//! restarts. A periodic sweep task (driven by
//! `FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS`) re-stats those
//! paths and evicts identities whose fingerprint no longer matches (pod
//! restarted under the same UID) or whose path is gone (pod removed), so a
//! fresh enrollment from the control plane / eBPF side is required before
//! traffic for the new pod instance is honoured. Identities enrolled without
//! a cgroup path are kept indefinitely — the sweep is a best-effort
//! garbage-collection pass, not a security invariant. The fail-closed
//! invariant on the accept path is unchanged: an unknown cookie or pod is
//! still rejected before traffic enters the plugin chain.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use ferrum_ebpf_common::{OrigDst4, OrigDst6};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, info, warn};

use crate::identity::SpiffeId;
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
    /// Filesystem path to the pod's cgroup v2 directory captured at
    /// enrollment. `None` when the enrollment source didn't supply a cgroup
    /// path — sweep treats such identities as opt-out and never evicts them.
    pub cgroup_path: Option<PathBuf>,
    /// Inode of `cgroup_path` at enrollment time. Pod restart yields a new
    /// inode at the same path; the sweep task evicts the identity when the
    /// current inode no longer matches this value. `None` when
    /// `cgroup_path` is `None`, or on platforms / filesystems where the
    /// inode cannot be read (`stat` returned an error at enrollment) —
    /// see `upsert_identity_with_cgroup`'s caller for the warning path.
    pub cgroup_inode: Option<u64>,
    /// Full Unix metadata fingerprint captured with the inode. Some
    /// filesystems can reuse inode numbers after a directory is deleted, so
    /// sweep compares this fingerprint when available and falls back to
    /// inode-only matching for identities built through `with_cgroup`.
    pub cgroup_fingerprint: Option<CgroupFingerprint>,
}

/// `ctime` (inode-metadata change time) is used rather than `mtime` because
/// kubelet writes to files *inside* the cgroup directory (`cgroup.procs`,
/// thresholds, etc.) update the directory's `mtime` without indicating a
/// new pod incarnation. `ctime` only advances when the directory's own
/// metadata changes — which for a kubelet-managed cgroup means
/// creation/replacement, exactly the signal the sweep needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupFingerprint {
    pub device: u64,
    pub inode: u64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
}

impl NodeWaypointIdentity {
    pub fn new(pod_uid: [u8; 16], spiffe_id: SpiffeId) -> Self {
        let workload_spiffe_hash = workload_spiffe_hash(&spiffe_id);
        Self {
            pod_uid,
            spiffe_id,
            workload_spiffe_hash,
            cgroup_path: None,
            cgroup_inode: None,
            cgroup_fingerprint: None,
        }
    }

    pub fn with_cgroup(mut self, path: PathBuf, inode: u64) -> Self {
        self.cgroup_path = Some(path);
        self.cgroup_inode = Some(inode);
        self.cgroup_fingerprint = None;
        self
    }

    pub fn with_cgroup_fingerprint(
        mut self,
        path: PathBuf,
        fingerprint: CgroupFingerprint,
    ) -> Self {
        self.cgroup_path = Some(path);
        self.cgroup_inode = Some(fingerprint.inode);
        self.cgroup_fingerprint = Some(fingerprint);
        self
    }
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
    // Sweep counters below are intentionally NOT `CachePadded` (unlike the
    // accept-path `node_waypoint_*_drops` atomics in `OverloadState`). They
    // are written at most once per sweep tick (default 30s) on a single
    // background task and read only via cold-path admin endpoints, so no
    // hot writer/reader pair can land on the same cache line.
    /// Monotonic count of identities evicted because their cgroup path was
    /// gone at sweep time. Operator/admin endpoints can read this to
    /// surface pod-churn signal.
    cgroup_sweep_path_missing: AtomicU64,
    /// Monotonic count of identities evicted because the cgroup inode at
    /// the same path no longer matches the enrolled value (pod restarted
    /// under the same UID).
    cgroup_sweep_inode_changed: AtomicU64,
    /// Sweep-pass counter — increments once per sweep tick regardless of
    /// whether anything was evicted. Useful for "is the sweep task alive"
    /// liveness diagnostics.
    cgroup_sweep_passes: AtomicU64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CgroupSweepReport {
    pub evicted_inode_changed: usize,
    pub evicted_path_missing: usize,
}

impl CgroupSweepReport {
    pub fn total_evicted(&self) -> usize {
        self.evicted_inode_changed + self.evicted_path_missing
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupSweepSnapshot {
    pub passes: u64,
    pub inode_changed_total: u64,
    pub path_missing_total: u64,
}

impl NodeWaypointIdentityResolver {
    pub fn new(pool_shard_override: usize) -> Self {
        let shards = crate::util::sharding::pool_shard_amount(pool_shard_override);
        Self {
            cookie_records: DashMap::with_shard_amount(shards),
            identities_by_pod_uid: DashMap::with_shard_amount(shards),
            policy_scopes_by_pod_uid: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
            cgroup_sweep_path_missing: AtomicU64::new(0),
            cgroup_sweep_inode_changed: AtomicU64::new(0),
            cgroup_sweep_passes: AtomicU64::new(0),
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
        identity
    }

    /// Enroll an identity that is lifecycle-bound to a cgroup v2 directory.
    /// Reads the inode and metadata fingerprint of `cgroup_path` once and
    /// stores them on the identity. A subsequent sweep evicts the identity
    /// if the path is gone or the fingerprint changed (pod restart yields a
    /// fresh cgroup at the same path, even when the inode number is reused).
    ///
    /// On stat error the identity is still inserted but without inode
    /// binding — sweep treats it like a non-cgroup enrollment (kept until
    /// explicit removal). The recorded `cgroup_path` in that case is
    /// informational only: with `cgroup_inode == None` and
    /// `cgroup_fingerprint == None` the sweep's candidate filter rejects
    /// the entry and never re-stats the path. The caller decides whether
    /// to warn; a control plane that requires lifecycle binding can check
    /// the returned identity's `cgroup_inode` and reject when `None`.
    pub fn upsert_identity_with_cgroup(
        &self,
        mut identity: NodeWaypointIdentity,
        cgroup_path: PathBuf,
    ) -> Arc<NodeWaypointIdentity> {
        match read_cgroup_fingerprint(&cgroup_path) {
            Ok(fingerprint) => {
                identity.cgroup_path = Some(cgroup_path);
                identity.cgroup_inode = Some(fingerprint.inode);
                identity.cgroup_fingerprint = Some(fingerprint);
            }
            Err(error) => {
                warn!(
                    pod_uid = %pod_uid_label(&identity.pod_uid),
                    cgroup_path = %cgroup_path.display(),
                    %error,
                    "Enrolling node-waypoint identity without cgroup-inode lifecycle binding (stat failed)"
                );
                identity.cgroup_path = Some(cgroup_path);
                identity.cgroup_inode = None;
                identity.cgroup_fingerprint = None;
            }
        }
        self.upsert_identity(identity)
    }

    pub fn remove_identity(&self, pod_uid: &[u8; 16]) {
        self.identities_by_pod_uid.remove(pod_uid);
        self.remove_policy_scopes_for_pods(&[*pod_uid]);
    }

    /// Iterate every enrolled identity and re-check its cgroup binding.
    /// Identities whose `cgroup_path` is gone or whose current inode no
    /// longer matches the enrolled value are removed. Identities without
    /// cgroup binding (`cgroup_path: None` OR `cgroup_inode: None`) are
    /// always kept — the sweep is opt-in per identity.
    ///
    /// Also clears policy scope entries for evicted pods so a stale
    /// PolicyScopeCache from a previous incarnation cannot apply to a
    /// newly enrolled pod with the same UID.
    pub fn sweep_cgroup_stale_identities(&self) -> CgroupSweepReport {
        #[derive(Clone, Copy)]
        enum CgroupExpectation {
            Fingerprint(CgroupFingerprint),
            Inode(u64),
        }

        impl CgroupExpectation {
            fn inode(self) -> u64 {
                match self {
                    Self::Fingerprint(fingerprint) => fingerprint.inode,
                    Self::Inode(inode) => inode,
                }
            }

            fn matches(self, current: CgroupFingerprint) -> bool {
                match self {
                    Self::Fingerprint(fingerprint) => fingerprint == current,
                    Self::Inode(inode) => inode == current.inode,
                }
            }

            fn still_attached_to(self, identity: &NodeWaypointIdentity) -> bool {
                match self {
                    Self::Fingerprint(fingerprint) => {
                        identity.cgroup_fingerprint == Some(fingerprint)
                    }
                    Self::Inode(inode) => {
                        identity.cgroup_inode == Some(inode)
                            && identity.cgroup_fingerprint.is_none()
                    }
                }
            }
        }

        enum EvictionReason {
            BindingChanged { current_inode: u64 },
            PathMissing { error: String },
        }

        let mut report = CgroupSweepReport::default();
        let mut evicted_pod_uids: Vec<[u8; 16]> = Vec::new();

        // Snapshot cgroup bindings first so filesystem metadata calls don't
        // hold DashMap shard locks used by accept-time identity resolution.
        let candidates: Vec<([u8; 16], PathBuf, CgroupExpectation)> = self
            .identities_by_pod_uid
            .iter()
            .filter_map(|entry| {
                let identity = entry.value();
                let expectation = identity
                    .cgroup_fingerprint
                    .map(CgroupExpectation::Fingerprint)
                    .or_else(|| identity.cgroup_inode.map(CgroupExpectation::Inode))?;
                Some((
                    *entry.key(),
                    identity.cgroup_path.as_ref()?.clone(),
                    expectation,
                ))
            })
            .collect();

        for (pod_uid, path, expectation) in candidates {
            let Some(reason) = (match read_cgroup_fingerprint(&path) {
                Ok(current) if expectation.matches(current) => None,
                Ok(current) => Some(EvictionReason::BindingChanged {
                    current_inode: current.inode,
                }),
                Err(error) => Some(EvictionReason::PathMissing {
                    error: error.to_string(),
                }),
            }) else {
                continue;
            };

            let removed = self
                .identities_by_pod_uid
                .remove_if(&pod_uid, |_, identity| {
                    expectation.still_attached_to(identity)
                        && identity.cgroup_path.as_deref() == Some(path.as_path())
                });
            if removed.is_none() {
                continue;
            }

            match reason {
                EvictionReason::BindingChanged { current_inode } => {
                    info!(
                        pod_uid = %pod_uid_label(&pod_uid),
                        expected_inode = expectation.inode(),
                        current_inode,
                        cgroup_path = %path.display(),
                        "Evicting node-waypoint identity (cgroup binding changed)"
                    );
                    report.evicted_inode_changed += 1;
                }
                EvictionReason::PathMissing { error } => {
                    debug!(
                        pod_uid = %pod_uid_label(&pod_uid),
                        cgroup_path = %path.display(),
                        %error,
                        "Evicting node-waypoint identity (cgroup path missing)"
                    );
                    report.evicted_path_missing += 1;
                }
            }

            evicted_pod_uids.push(pod_uid);
        }

        if !evicted_pod_uids.is_empty() {
            self.remove_policy_scopes_for_pods(&evicted_pod_uids);
        }
        self.cgroup_sweep_passes.fetch_add(1, Ordering::Relaxed);
        if report.evicted_inode_changed > 0 {
            self.cgroup_sweep_inode_changed
                .fetch_add(report.evicted_inode_changed as u64, Ordering::Relaxed);
        }
        if report.evicted_path_missing > 0 {
            self.cgroup_sweep_path_missing
                .fetch_add(report.evicted_path_missing as u64, Ordering::Relaxed);
        }
        report
    }

    pub fn cgroup_sweep_snapshot(&self) -> CgroupSweepSnapshot {
        CgroupSweepSnapshot {
            passes: self.cgroup_sweep_passes.load(Ordering::Relaxed),
            inode_changed_total: self.cgroup_sweep_inode_changed.load(Ordering::Relaxed),
            path_missing_total: self.cgroup_sweep_path_missing.load(Ordering::Relaxed),
        }
    }

    fn remove_policy_scopes_for_pods(&self, pod_uids: &[[u8; 16]]) {
        if pod_uids.is_empty() {
            return;
        }

        self.policy_scopes_by_pod_uid.rcu(|current| {
            if !pod_uids.iter().any(|pod_uid| current.contains_key(pod_uid)) {
                return Arc::clone(current);
            }

            let mut scopes = current.as_ref().clone();
            for pod_uid in pod_uids {
                scopes.remove(pod_uid);
            }
            Arc::new(scopes)
        });
    }

    pub fn install_policy_scopes(&self, scopes: HashMap<[u8; 16], Arc<PolicyScopeCache>>) {
        self.policy_scopes_by_pod_uid.store(Arc::new(scopes));
    }

    pub fn policy_scope_for_pod(&self, pod_uid: &[u8; 16]) -> Option<Arc<PolicyScopeCache>> {
        self.policy_scopes_by_pod_uid.load().get(pod_uid).cloned()
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
    /// `DashMap` once. Not safe to call on a hot accept path.
    pub fn identities_snapshot(&self) -> Vec<NodeWaypointIdentitySummary> {
        self.identities_snapshot_with_cookie_totals().0
    }

    /// Cold-path snapshot that returns both the per-identity summary list and
    /// the grand totals of `(orig_dst4, orig_dst6)` cookie records in a single
    /// pass over the `cookie_records` map. The admin endpoint uses this to
    /// honor the documented "iterates each shard of three `DashMap`s once"
    /// contract — invoking [`identities_snapshot`] and [`cookie_count`]
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

#[cfg(unix)]
fn read_cgroup_fingerprint(path: &Path) -> std::io::Result<CgroupFingerprint> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    Ok(CgroupFingerprint {
        device: meta.dev(),
        inode: meta.ino(),
        ctime_seconds: meta.ctime(),
        ctime_nanoseconds: meta.ctime_nsec(),
    })
}

#[cfg(not(unix))]
fn read_cgroup_fingerprint(_path: &Path) -> std::io::Result<CgroupFingerprint> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "cgroup-inode lifecycle binding is Linux/Unix-only",
    ))
}

/// Spawn a periodic sweep task that re-stats every enrolled cgroup path
/// and evicts stale identities. `interval_secs == 0` disables the sweep
/// and returns `None` so callers don't need to track an unused task
/// handle. The task exits when `shutdown` is notified.
pub fn spawn_cgroup_sweep_task(
    resolver: Arc<NodeWaypointIdentityResolver>,
    interval_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if interval_secs == 0 {
        info!(
            "Node-waypoint cgroup sweep disabled (FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS=0)"
        );
        return None;
    }
    let period = Duration::from_secs(interval_secs);
    let handle = tokio::spawn(async move {
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(interval_secs, "Node-waypoint cgroup sweep task started");
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let report = resolver.sweep_cgroup_stale_identities();
                    if report.total_evicted() > 0 {
                        info!(
                            evicted_inode_changed = report.evicted_inode_changed,
                            evicted_path_missing = report.evicted_path_missing,
                            "Node-waypoint cgroup sweep evicted stale identities"
                        );
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        info!("Node-waypoint cgroup sweep task shutting down");
                        return;
                    }
                }
            }
        }
    });
    Some(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::mesh::config::{
        MeshPolicy, PolicyScope, WorkloadSelector, policy_scope_applies_to_workload,
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

    #[cfg(unix)]
    #[test]
    fn upsert_with_cgroup_captures_inode_and_sweep_keeps_identity_when_inode_unchanged() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cgroup_path = tmp.path().join("pod.scope");
        std::fs::create_dir(&cgroup_path).expect("create cgroup dir");

        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let arc = resolver.upsert_identity_with_cgroup(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api")),
            cgroup_path.clone(),
        );
        assert!(
            arc.cgroup_inode.is_some(),
            "successful enrollment must record inode"
        );
        assert!(
            arc.cgroup_fingerprint.is_some(),
            "successful enrollment must record full cgroup fingerprint"
        );

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.total_evicted(), 0);
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));
        let snapshot = resolver.cgroup_sweep_snapshot();
        assert_eq!(snapshot.passes, 1);
        assert_eq!(snapshot.inode_changed_total, 0);
        assert_eq!(snapshot.path_missing_total, 0);
    }

    #[cfg(unix)]
    #[test]
    fn sweep_evicts_identity_when_cgroup_path_disappears() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cgroup_path = tmp.path().join("pod.scope");
        std::fs::create_dir(&cgroup_path).expect("create cgroup dir");

        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity_with_cgroup(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api")),
            cgroup_path.clone(),
        );

        // Pre-populate a policy scope cache so the sweep clears it too.
        let scope_cache = Arc::new(PolicyScopeCache::new(
            spiffe("spiffe://td/ns/default/sa/api"),
            "default",
            HashMap::new(),
        ));
        resolver.install_policy_scopes(HashMap::from([(pod_uid, scope_cache)]));

        // Simulate pod removal: delete the cgroup dir.
        std::fs::remove_dir_all(&cgroup_path).expect("remove cgroup dir");

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.evicted_path_missing, 1);
        assert_eq!(report.evicted_inode_changed, 0);
        assert!(!resolver.identities_by_pod_uid.contains_key(&pod_uid));
        assert!(
            resolver.policy_scope_for_pod(&pod_uid).is_none(),
            "policy scope must be evicted with identity"
        );
        let snapshot = resolver.cgroup_sweep_snapshot();
        assert_eq!(snapshot.path_missing_total, 1);
    }

    #[cfg(unix)]
    #[test]
    fn sweep_evicts_identity_when_cgroup_inode_changes() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cgroup_path = tmp.path().join("pod.scope");
        std::fs::create_dir(&cgroup_path).expect("create cgroup dir");
        let current_fingerprint =
            read_cgroup_fingerprint(&cgroup_path).expect("read cgroup fingerprint");
        let stale_inode = current_fingerprint.inode.wrapping_add(1);

        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"))
                .with_cgroup(cgroup_path.clone(), stale_inode),
        );

        // Simulate a restart with a stale enrolled inode. Recreate-based tests
        // are flaky because filesystems may reuse the removed directory's inode.
        assert_ne!(stale_inode, current_fingerprint.inode);

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.evicted_inode_changed, 1);
        assert_eq!(report.evicted_path_missing, 0);
        assert!(
            !resolver.identities_by_pod_uid.contains_key(&pod_uid),
            "stale identity for pod-restart UID must be evicted"
        );
        let snapshot = resolver.cgroup_sweep_snapshot();
        assert_eq!(snapshot.inode_changed_total, 1);
    }

    #[cfg(unix)]
    #[test]
    fn sweep_evicts_identity_when_cgroup_fingerprint_changes_even_if_inode_matches() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cgroup_path = tmp.path().join("pod.scope");
        std::fs::create_dir(&cgroup_path).expect("create cgroup dir");
        let current_fingerprint =
            read_cgroup_fingerprint(&cgroup_path).expect("read cgroup fingerprint");
        let stale_fingerprint = CgroupFingerprint {
            ctime_nanoseconds: current_fingerprint.ctime_nanoseconds.wrapping_add(1),
            ..current_fingerprint
        };

        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"))
                .with_cgroup_fingerprint(cgroup_path.clone(), stale_fingerprint),
        );

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.evicted_inode_changed, 1);
        assert_eq!(report.evicted_path_missing, 0);
        assert!(
            !resolver.identities_by_pod_uid.contains_key(&pod_uid),
            "stale identity must be evicted even if the inode number was reused"
        );
    }

    #[test]
    fn remove_identity_clears_policy_scope_cache() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));
        let scope_cache = Arc::new(PolicyScopeCache::new(
            spiffe("spiffe://td/ns/default/sa/api"),
            "default",
            HashMap::new(),
        ));
        resolver.install_policy_scopes(HashMap::from([(pod_uid, scope_cache)]));

        resolver.remove_identity(&pod_uid);

        assert!(!resolver.identities_by_pod_uid.contains_key(&pod_uid));
        assert!(
            resolver.policy_scope_for_pod(&pod_uid).is_none(),
            "explicit identity removal must clear stale policy scope too"
        );
    }

    #[test]
    fn remove_identity_clears_policy_scope_cache_when_identity_already_missing() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let scope_cache = Arc::new(PolicyScopeCache::new(
            spiffe("spiffe://td/ns/default/sa/api"),
            "default",
            HashMap::new(),
        ));
        resolver.install_policy_scopes(HashMap::from([(pod_uid, scope_cache)]));

        resolver.remove_identity(&pod_uid);

        assert!(
            resolver.policy_scope_for_pod(&pod_uid).is_none(),
            "explicit identity removal must clear orphaned policy scope too"
        );
    }

    #[test]
    fn sweep_keeps_identities_without_cgroup_binding() {
        // Identities enrolled via the legacy upsert path (no cgroup) must
        // be left in place — the sweep is opt-in per identity, not a
        // global GC of every enrolled pod.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("22222222-2222-2222-2222-222222222222").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/legacy"),
        ));

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.total_evicted(), 0);
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));
    }

    #[cfg(unix)]
    #[test]
    fn upsert_with_cgroup_records_none_inode_on_stat_failure() {
        // Missing path: enrollment still inserts the identity (so a control
        // plane that doesn't yet provide a cgroup path is not blocked), but
        // marks `cgroup_inode = None` and the sweep ignores it.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("33333333-3333-3333-3333-333333333333").unwrap();
        let missing = PathBuf::from("/this/path/does/not/exist/ferrum-test");

        let identity = resolver.upsert_identity_with_cgroup(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api")),
            missing,
        );
        assert!(
            identity.cgroup_inode.is_none(),
            "stat failure must leave cgroup_inode unset"
        );
        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(
            report.total_evicted(),
            0,
            "sweep ignores identities without a recorded inode"
        );
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));
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
        // gets one v6 cookie — represents an eBPF capture racing identity
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
    fn resolve_cookie_path_is_two_dashmap_gets_in_warm_case() {
        // Regression guard for the documented hot-path contract:
        // - 1× cookie_records.get
        // - 1× identities_by_pod_uid.get
        // - 0 allocations on success
        //
        // We assert the structural shape (two DashMaps, one Arc clone) by
        // making the same call twice and confirming both arms hit warm
        // entries without re-inserting anything. If a future refactor adds
        // a third DashMap probe or an alloc, this test still passes — but
        // the module-level rustdoc is the source of truth and any change
        // here that adds work must update that contract.
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
        // The v4/v6 family stamp is what the admin endpoint reports — verify
        // we attributed the cookie to v6 not v4 so the snapshot stays honest.
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
