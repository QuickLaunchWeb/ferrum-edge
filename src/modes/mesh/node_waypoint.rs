//! Node-waypoint identity resolution.
//!
//! In node-waypoint topology one proxy listener accepts traffic for many pods.
//! The node-agent/eBPF side records the socket cookie, original destination,
//! and source pod identity. The proxy resolves that cookie at accept time and
//! rejects unknown cookies before the request enters the plugin chain.
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

use crate::identity::SpiffeId;
use crate::modes::mesh::config::Workload;
use crate::modes::mesh::runtime::PolicyScopeCache;

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
    orig_dst4_by_cookie: DashMap<u64, OrigDst4>,
    orig_dst6_by_cookie: DashMap<u64, OrigDst6>,
    identities_by_pod_uid: DashMap<[u8; 16], Arc<NodeWaypointIdentity>>,
    policy_scopes_by_pod_uid: Arc<ArcSwap<HashMap<[u8; 16], Arc<PolicyScopeCache>>>>,
    workload_policy_scopes_by_spiffe: Arc<ArcSwap<HashMap<String, Arc<PolicyScopeCache>>>>,
    policy_scope_update_lock: Mutex<()>,
}

impl NodeWaypointIdentityResolver {
    pub fn new(pool_shard_override: usize) -> Self {
        let shards = crate::util::sharding::pool_shard_amount(pool_shard_override);
        Self {
            orig_dst4_by_cookie: DashMap::with_shard_amount(shards),
            orig_dst6_by_cookie: DashMap::with_shard_amount(shards),
            identities_by_pod_uid: DashMap::with_shard_amount(shards),
            policy_scopes_by_pod_uid: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
            workload_policy_scopes_by_spiffe: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
            policy_scope_update_lock: Mutex::new(()),
        }
    }

    pub fn record_orig_dst4(&self, cookie: u64, record: OrigDst4) {
        self.orig_dst4_by_cookie.insert(cookie, record);
    }

    pub fn remove_orig_dst4(&self, cookie: u64) {
        self.orig_dst4_by_cookie.remove(&cookie);
    }

    pub fn record_orig_dst6(&self, cookie: u64, record: OrigDst6) {
        self.orig_dst6_by_cookie.insert(cookie, record);
    }

    pub fn remove_orig_dst6(&self, cookie: u64) {
        self.orig_dst6_by_cookie.remove(&cookie);
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
        let _guard = self
            .policy_scope_update_lock
            .lock()
            .expect("node-waypoint policy-scope update lock poisoned");
        let current = self.policy_scopes_by_pod_uid.load();
        if !current.contains_key(pod_uid) {
            return;
        }
        let mut scopes = current.as_ref().clone();
        scopes.remove(pod_uid);
        self.policy_scopes_by_pod_uid.store(Arc::new(scopes));
    }

    pub fn install_policy_scopes(&self, scopes: HashMap<[u8; 16], Arc<PolicyScopeCache>>) {
        let _guard = self
            .policy_scope_update_lock
            .lock()
            .expect("node-waypoint policy-scope update lock poisoned");
        self.policy_scopes_by_pod_uid.store(Arc::new(scopes));
    }

    pub fn policy_scope_for_pod(&self, pod_uid: &[u8; 16]) -> Option<Arc<PolicyScopeCache>> {
        self.policy_scopes_by_pod_uid.load().get(pod_uid).cloned()
    }

    pub fn install_policy_scopes_from_workloads<'a, I>(&self, workloads: I)
    where
        I: IntoIterator<Item = &'a Workload>,
    {
        let workload_index = workload_policy_scope_index(workloads);
        let _guard = self
            .policy_scope_update_lock
            .lock()
            .expect("node-waypoint policy-scope update lock poisoned");
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
        let _guard = self
            .policy_scope_update_lock
            .lock()
            .expect("node-waypoint policy-scope update lock poisoned");
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
        let Some(record) = self.orig_dst4_by_cookie.get(&cookie) else {
            if let Some(record) = self.orig_dst6_by_cookie.get(&cookie) {
                return self.resolve_record(cookie, record.pod_uid, record.workload_spiffe_hash);
            }
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
