//! Shared mesh runtime state.
//!
//! Phase C keeps the live per-node [`MeshSlice`] in an `ArcSwap` slot so
//! listener and plugin paths can read the latest mesh view without locks.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use serde::Serialize;
use tokio::sync::{Notify, watch};
use tracing::{info, warn};

use crate::identity::SpiffeId;
use crate::modes::mesh::config::{MeshPolicy, Workload, policy_scope_applies_to_workload};
use crate::modes::mesh::slice::{MeshEgressScopeSnapshot, MeshSlice};
use crate::plugins::mesh::outbound_registry::OutboundRegistry;

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct MeshEgressScopeHealth {
    pub sidecar_admitted_services: u64,
    pub sidecar_denied_services: u64,
}

/// Per-runtime operator surface for the active mesh egress scope.
///
/// Hangs off [`MeshRuntimeState`] so tests get isolated state. Updated only
/// when a mesh slice is installed, never from the request path.
pub struct MeshEgressScopeState {
    current: Arc<ArcSwap<Option<MeshEgressScopeSnapshot>>>,
    /// Cached `OutboundRegistry` built from the installed snapshot's
    /// `known_destinations`. Rebuilt only when a new slice is installed so
    /// `POST /mesh/egress-scope/test` does not re-normalise the registry on
    /// every admin call.
    test_registry: Arc<ArcSwap<Option<Arc<OutboundRegistry>>>>,
    sidecar_admitted_services: AtomicU64,
    sidecar_denied_services: AtomicU64,
    dry_run_denials_active: AtomicBool,
}

impl MeshEgressScopeState {
    fn new() -> Self {
        Self {
            current: Arc::new(ArcSwap::new(Arc::new(None))),
            test_registry: Arc::new(ArcSwap::new(Arc::new(None))),
            sidecar_admitted_services: AtomicU64::new(0),
            sidecar_denied_services: AtomicU64::new(0),
            dry_run_denials_active: AtomicBool::new(false),
        }
    }

    pub fn snapshot(&self) -> Option<MeshEgressScopeSnapshot> {
        self.current.load_full().as_ref().clone()
    }

    pub fn health(&self) -> MeshEgressScopeHealth {
        MeshEgressScopeHealth {
            sidecar_admitted_services: self.sidecar_admitted_services.load(Ordering::Relaxed),
            sidecar_denied_services: self.sidecar_denied_services.load(Ordering::Relaxed),
        }
    }

    /// Returns the memoised `OutboundRegistry` matching the current snapshot
    /// for admin-side dry-run lookups, or `None` if no slice has been installed
    /// yet (or the build failed).
    pub fn test_registry(&self) -> Option<Arc<OutboundRegistry>> {
        self.test_registry.load_full().as_ref().clone()
    }

    pub fn install_from_slice(&self, slice: &MeshSlice) {
        let snapshot = slice.sidecar_egress_scope.clone();
        let admitted = snapshot
            .as_ref()
            .map(|scope| scope.sidecar_admitted_services as u64)
            .unwrap_or(0);
        let denied = snapshot
            .as_ref()
            .map(|scope| scope.sidecar_denied_services as u64)
            .unwrap_or(0);
        self.sidecar_admitted_services
            .store(admitted, Ordering::Relaxed);
        self.sidecar_denied_services
            .store(denied, Ordering::Relaxed);

        let dry_run_denied = snapshot
            .as_ref()
            .is_some_and(|scope| scope.dry_run && scope.sidecar_denied_services > 0);
        let was_active = self
            .dry_run_denials_active
            .swap(dry_run_denied, Ordering::AcqRel);
        if dry_run_denied && !was_active {
            warn!(
                sidecar_admitted_services = admitted,
                sidecar_denied_services = denied,
                "Sidecar egress dry-run would deny services; traffic is still admitted"
            );
        } else if !dry_run_denied && was_active {
            info!("Sidecar egress dry-run denials recovered");
        }

        // Rebuild the test-side OutboundRegistry on each slice install. Cold
        // path; per-request admin handlers reuse the resulting Arc.
        let registry = snapshot.as_ref().and_then(|scope| {
            match OutboundRegistry::new(&serde_json::json!({
                "registry": &scope.known_destinations,
            })) {
                Ok(registry) => Some(Arc::new(registry)),
                Err(err) => {
                    warn!(
                        error = %err,
                        "Failed to rebuild mesh egress-scope test registry from installed slice"
                    );
                    None
                }
            }
        });
        self.test_registry.store(Arc::new(registry));

        self.current.store(Arc::new(snapshot));
    }
}

/// Pre-computed per-pod policy scope identity used by node-waypoint mode.
///
/// Node-waypoint accepts traffic for many pods through one listener, so policy
/// scope selection has to be keyed by the source pod identity. This cache keeps
/// the workload namespace/labels next to the SPIFFE ID and delegates matching
/// to the canonical mesh helper to avoid drift from sidecar and plugin paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyScopeCache {
    pub spiffe_id: SpiffeId,
    pub namespace: String,
    pub labels: HashMap<String, String>,
}

impl PolicyScopeCache {
    pub fn new(
        spiffe_id: SpiffeId,
        namespace: impl Into<String>,
        labels: HashMap<String, String>,
    ) -> Self {
        Self {
            spiffe_id,
            namespace: namespace.into(),
            labels,
        }
    }

    pub fn from_workload(workload: &Workload) -> Self {
        Self {
            spiffe_id: workload.spiffe_id.clone(),
            namespace: workload.namespace.clone(),
            labels: workload.selector.labels.clone(),
        }
    }

    pub fn policy_applies(&self, policy: &MeshPolicy) -> bool {
        policy_scope_applies_to_workload(policy, &self.namespace, &self.labels)
    }
}

/// Lock-free holder for the current Layer 2 mesh slice.
#[derive(Clone)]
pub struct MeshRuntimeState {
    current: Arc<ArcSwap<Option<MeshSlice>>>,
    first_ready: Arc<Notify>,
    has_first: Arc<AtomicBool>,
    revision_tx: Arc<watch::Sender<u64>>,
    egress_scope: Arc<MeshEgressScopeState>,
}

impl MeshRuntimeState {
    pub fn new() -> Self {
        let (revision_tx, _) = watch::channel(0u64);
        Self {
            current: Arc::new(ArcSwap::new(Arc::new(None))),
            first_ready: Arc::new(Notify::new()),
            has_first: Arc::new(AtomicBool::new(false)),
            revision_tx: Arc::new(revision_tx),
            egress_scope: Arc::new(MeshEgressScopeState::new()),
        }
    }

    /// Return the latest mesh slice snapshot.
    pub fn snapshot(&self) -> Arc<Option<MeshSlice>> {
        self.current.load_full()
    }

    /// True once at least one mesh slice has been installed.
    pub fn has_first_slice(&self) -> bool {
        self.has_first.load(Ordering::Acquire)
    }

    /// Subscribe to every slice installation.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }

    /// Operator surface for the active mesh egress scope. Updated only when a
    /// new slice is installed.
    pub fn egress_scope_state(&self) -> &MeshEgressScopeState {
        &self.egress_scope
    }

    /// Hot-swap the live mesh slice and notify waiters on the first install.
    pub fn install_slice(&self, slice: MeshSlice) {
        self.egress_scope.install_from_slice(&slice);
        self.current.store(Arc::new(Some(slice)));
        self.revision_tx.send_modify(|revision| *revision += 1);
        let was_first = self.has_first.swap(true, Ordering::AcqRel);
        if !was_first {
            self.first_ready.notify_waiters();
        }
    }

    /// Resolve once the initial mesh slice is available.
    ///
    /// Race-free against concurrent installs: the waiter is registered before
    /// checking the flag, so a first install cannot be missed between load and
    /// await.
    pub async fn wait_for_first_slice(&self) {
        let notified = self.first_ready.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if self.has_first.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

impl Default for MeshRuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::mesh::config::{PolicyScope, WorkloadSelector};

    #[tokio::test]
    async fn wait_for_first_slice_resolves_after_install() {
        let state = MeshRuntimeState::new();
        let waiter = {
            let state = state.clone();
            tokio::spawn(async move {
                state.wait_for_first_slice().await;
                state
                    .snapshot()
                    .as_ref()
                    .as_ref()
                    .map(|slice| slice.version.clone())
            })
        };

        tokio::task::yield_now().await;
        state.install_slice(MeshSlice {
            version: "v1".to_string(),
            ..MeshSlice::default()
        });

        let observed = waiter.await.expect("waiter task should complete");
        assert_eq!(observed.as_deref(), Some("v1"));
    }

    #[tokio::test]
    async fn wait_for_first_slice_returns_immediately_when_already_installed() {
        let state = MeshRuntimeState::new();
        state.install_slice(MeshSlice {
            version: "v1".to_string(),
            ..MeshSlice::default()
        });

        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            state.wait_for_first_slice(),
        )
        .await
        .expect("already-installed slice should not block");
    }

    #[test]
    fn policy_scope_cache_delegates_to_canonical_helper() {
        let mut labels = HashMap::new();
        labels.insert("app".to_string(), "reviews".to_string());
        let cache = PolicyScopeCache::new(
            SpiffeId::new("spiffe://td/ns/default/sa/reviews").expect("test SPIFFE ID is valid"),
            "default",
            labels.clone(),
        );
        let policy = MeshPolicy {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels,
                    namespace: Some("default".to_string()),
                },
            },
            rules: Vec::new(),
        };

        assert!(cache.policy_applies(&policy));
        assert_eq!(
            cache.policy_applies(&policy),
            policy_scope_applies_to_workload(&policy, "default", &cache.labels)
        );
    }
}
