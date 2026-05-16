//! Shared mesh runtime state.
//!
//! Phase C keeps the live per-node [`MeshSlice`] in an `ArcSwap` slot so
//! listener and plugin paths can read the latest mesh view without locks.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use serde::Serialize;
use tokio::sync::{Notify, watch};
use tracing::{info, warn};

use crate::modes::mesh::slice::{MeshEgressScopeSnapshot, MeshSlice};

static MESH_EGRESS_SCOPE_STATE: OnceLock<MeshEgressScopeState> = OnceLock::new();

pub fn mesh_egress_scope_state() -> &'static MeshEgressScopeState {
    MESH_EGRESS_SCOPE_STATE.get_or_init(MeshEgressScopeState::new)
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct MeshEgressScopeHealth {
    pub sidecar_admitted_services: u64,
    pub sidecar_denied_services: u64,
}

/// Process-local operator surface for the active mesh egress scope.
///
/// Updated only when a mesh slice is installed, never from the request path.
pub struct MeshEgressScopeState {
    current: Arc<ArcSwap<Option<MeshEgressScopeSnapshot>>>,
    sidecar_admitted_services: AtomicU64,
    sidecar_denied_services: AtomicU64,
    dry_run_denials_active: AtomicBool,
}

impl MeshEgressScopeState {
    fn new() -> Self {
        Self {
            current: Arc::new(ArcSwap::new(Arc::new(None))),
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

        self.current.store(Arc::new(snapshot));
    }
}

/// Lock-free holder for the current Layer 2 mesh slice.
#[derive(Clone)]
pub struct MeshRuntimeState {
    current: Arc<ArcSwap<Option<MeshSlice>>>,
    first_ready: Arc<Notify>,
    has_first: Arc<AtomicBool>,
    revision_tx: Arc<watch::Sender<u64>>,
}

impl MeshRuntimeState {
    pub fn new() -> Self {
        let (revision_tx, _) = watch::channel(0u64);
        Self {
            current: Arc::new(ArcSwap::new(Arc::new(None))),
            first_ready: Arc::new(Notify::new()),
            has_first: Arc::new(AtomicBool::new(false)),
            revision_tx: Arc::new(revision_tx),
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

    /// Hot-swap the live mesh slice and notify waiters on the first install.
    pub fn install_slice(&self, slice: MeshSlice) {
        mesh_egress_scope_state().install_from_slice(&slice);
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
}
