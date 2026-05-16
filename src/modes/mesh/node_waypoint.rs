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

use arc_swap::ArcSwap;
use dashmap::DashMap;
use ferrum_ebpf_common::OrigDst4;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;

use crate::identity::SpiffeId;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeWaypointIdentityError {
    SocketCookieUnavailable(String),
    UnknownCookie(u64),
    MissingPodUid(u64),
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
    identities_by_pod_uid: DashMap<[u8; 16], Arc<NodeWaypointIdentity>>,
    policy_scopes_by_pod_uid: Arc<ArcSwap<HashMap<[u8; 16], Arc<PolicyScopeCache>>>>,
}

impl NodeWaypointIdentityResolver {
    pub fn new(pool_shard_override: usize) -> Self {
        let shards = crate::util::sharding::pool_shard_amount(pool_shard_override);
        Self {
            orig_dst4_by_cookie: DashMap::with_shard_amount(shards),
            identities_by_pod_uid: DashMap::with_shard_amount(shards),
            policy_scopes_by_pod_uid: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
        }
    }

    pub fn record_orig_dst4(&self, cookie: u64, record: OrigDst4) {
        self.orig_dst4_by_cookie.insert(cookie, record);
    }

    pub fn remove_orig_dst4(&self, cookie: u64) {
        self.orig_dst4_by_cookie.remove(&cookie);
    }

    pub fn upsert_identity(&self, identity: NodeWaypointIdentity) -> Arc<NodeWaypointIdentity> {
        let identity = Arc::new(identity);
        self.identities_by_pod_uid
            .insert(identity.pod_uid, identity.clone());
        identity
    }

    pub fn remove_identity(&self, pod_uid: &[u8; 16]) {
        self.identities_by_pod_uid.remove(pod_uid);
    }

    pub fn install_policy_scopes(&self, scopes: HashMap<[u8; 16], Arc<PolicyScopeCache>>) {
        self.policy_scopes_by_pod_uid.store(Arc::new(scopes));
    }

    pub fn policy_scope_for_pod(&self, pod_uid: &[u8; 16]) -> Option<Arc<PolicyScopeCache>> {
        self.policy_scopes_by_pod_uid.load().get(pod_uid).cloned()
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
            return Err(NodeWaypointIdentityError::UnknownCookie(cookie));
        };
        let pod_uid = record.pod_uid;
        let expected_hash = record.workload_spiffe_hash;
        drop(record);

        if pod_uid == [0; 16] {
            return Err(NodeWaypointIdentityError::MissingPodUid(cookie));
        }

        let Some(identity) = self.identities_by_pod_uid.get(&pod_uid) else {
            return Err(NodeWaypointIdentityError::UnknownPod(pod_uid));
        };
        let identity = identity.clone();
        if expected_hash != 0 && identity.workload_spiffe_hash != expected_hash {
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
    fn resolve_cookie_fails_closed_for_missing_pod_uid() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        resolver.record_orig_dst4(7, orig_dst4([0; 16], 0));

        let error = resolver
            .resolve_cookie(7)
            .expect_err("zero pod UID must fail closed");
        assert_eq!(error, NodeWaypointIdentityError::MissingPodUid(7));
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
