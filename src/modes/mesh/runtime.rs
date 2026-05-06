//! Shared mesh runtime state.
//!
//! Phase C keeps the live per-node [`MeshSlice`] in an `ArcSwap` slot so
//! listener and plugin paths can read the latest mesh view without locks.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use tokio::sync::Notify;

use crate::xds::slice::MeshSlice;

/// Lock-free holder for the current Layer 2 mesh slice.
#[derive(Clone)]
pub struct MeshRuntimeState {
    current: Arc<ArcSwap<Option<MeshSlice>>>,
    first_ready: Arc<Notify>,
    has_first: Arc<AtomicBool>,
}

impl MeshRuntimeState {
    pub fn new() -> Self {
        Self {
            current: Arc::new(ArcSwap::new(Arc::new(None))),
            first_ready: Arc::new(Notify::new()),
            has_first: Arc::new(AtomicBool::new(false)),
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

    /// Hot-swap the live mesh slice and notify waiters on the first install.
    pub fn install_slice(&self, slice: MeshSlice) {
        self.current.store(Arc::new(Some(slice)));
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
