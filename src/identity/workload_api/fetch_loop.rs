//! Long-lived background task that keeps a `Workload API` client connected
//! and hot-swaps each fresh [`SvidBundle`] into a shared [`ArcSwap`].
//!
//! Consumers (the `build_spiffe_inbound_config` / `build_spiffe_outbound_config`
//! TLS builders) read from the `ArcSwap` on every connection. The swap is
//! lock-free; readers see either the old bundle or the new one, never a
//! partial.
//!
//! The fetch loop also exposes a `wait_for_first_svid()` future so callers
//! can synchronise on "first SVID is ready" before binding listeners.

use arc_swap::ArcSwap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::sleep;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use super::client::WorkloadApiClient;
use crate::identity::SvidBundle;

/// Handle returned by [`spawn_fetch_loop`]. Holds the shared `ArcSwap` and
/// the "first SVID arrived" notifier.
#[derive(Clone)]
pub struct SvidFetchHandle {
    pub current: Arc<ArcSwap<Option<SvidBundle>>>,
    first_ready: Arc<Notify>,
    has_first: Arc<std::sync::atomic::AtomicBool>,
}

impl SvidFetchHandle {
    pub fn new() -> Self {
        Self {
            current: Arc::new(ArcSwap::new(Arc::new(None))),
            first_ready: Arc::new(Notify::new()),
            has_first: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Snapshot of the current SVID bundle. Returns `None` until the first
    /// bundle arrives.
    pub fn snapshot(&self) -> Arc<Option<SvidBundle>> {
        self.current.load_full()
    }

    /// Resolves once the first SVID has been observed. If a bundle is
    /// already present, resolves immediately.
    pub async fn wait_for_first_svid(&self) {
        if self.has_first.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        self.first_ready.notified().await;
    }

    fn install(&self, bundle: SvidBundle) {
        self.current.store(Arc::new(Some(bundle)));
        let was_first = self
            .has_first
            .swap(true, std::sync::atomic::Ordering::AcqRel);
        if !was_first {
            self.first_ready.notify_waiters();
        }
    }
}

impl Default for SvidFetchHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for the fetch loop.
#[derive(Debug, Clone)]
pub struct FetchLoopConfig {
    /// Path to the SPIRE agent socket.
    pub socket_path: String,
    /// Backoff between connection attempts when the agent is unreachable.
    pub reconnect_backoff: Duration,
    /// Maximum backoff cap. Backoff doubles up to this value.
    pub max_reconnect_backoff: Duration,
}

impl Default for FetchLoopConfig {
    fn default() -> Self {
        Self {
            socket_path: super::client::DEFAULT_WORKLOAD_API_SOCKET.to_string(),
            reconnect_backoff: Duration::from_secs(1),
            max_reconnect_backoff: Duration::from_secs(30),
        }
    }
}

/// Spawn the fetch loop and return a handle. The task runs until cancelled
/// (drop the returned `JoinHandle`).
pub fn spawn_fetch_loop(config: FetchLoopConfig) -> (SvidFetchHandle, tokio::task::JoinHandle<()>) {
    let handle = SvidFetchHandle::new();
    let task_handle = handle.clone();
    let join = tokio::spawn(async move { fetch_loop_main(config, task_handle).await });
    (handle, join)
}

async fn fetch_loop_main(config: FetchLoopConfig, handle: SvidFetchHandle) {
    let mut backoff = config.reconnect_backoff;
    loop {
        match WorkloadApiClient::connect(&config.socket_path).await {
            Ok(mut client) => match client.fetch_x509_svid_stream().await {
                Ok((mut stream, _first_signal)) => {
                    info!(socket = %config.socket_path, "SVID fetch stream established");
                    backoff = config.reconnect_backoff;
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(bundle) => {
                                debug!(
                                    spiffe_id = %bundle.spiffe_id,
                                    "received fresh SVID from Workload API"
                                );
                                handle.install(bundle);
                            }
                            Err(e) => {
                                warn!(error = %e, "SVID fetch stream error — reconnecting");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "Workload API stream RPC failed");
                }
            },
            Err(e) => {
                error!(error = %e, "failed to connect to Workload API agent");
            }
        }

        sleep(backoff).await;
        backoff = (backoff * 2).min(config.max_reconnect_backoff);
    }
}

/// Convenience for unit tests / call sites that want to install an SVID
/// without round-tripping through the agent. Not intended for production
/// flows.
pub fn install_test_bundle(handle: &SvidFetchHandle, bundle: SvidBundle) {
    handle.install(bundle);
}

/// Required by the rotation module: convert a bundle's notAfter into a
/// duration-from-now. Returns `Duration::ZERO` for already-expired bundles.
#[allow(dead_code)]
pub(crate) fn time_until_expiry(bundle: &SvidBundle) -> Duration {
    use chrono::Utc;
    use x509_parser::prelude::*;
    let leaf = match bundle.cert_chain_der.first() {
        Some(d) => d,
        None => return Duration::ZERO,
    };
    let parsed = match X509Certificate::from_der(leaf) {
        Ok((_, c)) => c,
        Err(_) => return Duration::ZERO,
    };
    let not_after_ts = parsed.validity().not_after.timestamp();
    let now_ts = Utc::now().timestamp();
    if not_after_ts <= now_ts {
        Duration::ZERO
    } else {
        Duration::from_secs((not_after_ts - now_ts) as u64)
    }
}

// `WorkloadApiClientError` is re-exported here for callers wiring custom
// connection logic.
pub use super::client::WorkloadApiClientError as FetchLoopError;
