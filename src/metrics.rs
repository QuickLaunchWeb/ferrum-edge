//! Windowed rate metrics computed from cumulative counters.
//!
//! A background task snapshots `ProxyState.request_count` and
//! `ProxyState.status_counts` every `window_seconds` and stores the
//! per-second averages in [`WindowedMetrics`].  The admin `/status`
//! endpoint reads these with a single `AtomicU64::load(Relaxed)` per
//! field — zero contention with the proxy hot path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;

/// Per-second rate averages over a configurable window.
///
/// Written exclusively by [`start_metrics_monitor`]; read by
/// `admin::build_metrics()`.  All fields use `Ordering::Relaxed` —
/// eventual consistency is fine for admin/observability data.
pub struct WindowedMetrics {
    /// Average requests per second over the last completed window.
    pub requests_per_second: AtomicU64,
    /// Average per-second rate of each HTTP status code over the last window.
    pub status_codes_per_second: DashMap<u16, AtomicU64>,
    /// Window size in seconds (exposed in the JSON response for transparency).
    pub window_seconds: u64,
}

impl WindowedMetrics {
    pub fn new(window_seconds: u64) -> Self {
        Self {
            requests_per_second: AtomicU64::new(0),
            status_codes_per_second: DashMap::new(),
            window_seconds,
        }
    }
}

/// Spawn a background task that computes windowed per-second rates.
///
/// The task snapshots the cumulative counters every `window_seconds`,
/// computes `(current - previous) / window_seconds`, and stores the
/// result in `windowed`.  Exits cleanly when `shutdown_rx` fires.
pub fn start_metrics_monitor(
    request_count: Arc<AtomicU64>,
    status_counts: Arc<DashMap<u16, AtomicU64>>,
    windowed: Arc<WindowedMetrics>,
    window_seconds: u64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_secs(window_seconds);

        // Take the initial snapshot.
        let mut prev_requests = request_count.load(Ordering::Relaxed);
        let mut prev_status: std::collections::HashMap<u16, u64> = status_counts
            .iter()
            .map(|entry| (*entry.key(), entry.value().load(Ordering::Relaxed)))
            .collect();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown_rx.changed() => break,
            }

            // Snapshot current values.
            let curr_requests = request_count.load(Ordering::Relaxed);
            let delta_requests = curr_requests.saturating_sub(prev_requests);
            windowed
                .requests_per_second
                .store(delta_requests / window_seconds, Ordering::Relaxed);
            prev_requests = curr_requests;

            // Status codes — iterate current counters, compute deltas.
            for entry in status_counts.iter() {
                let code = *entry.key();
                let curr = entry.value().load(Ordering::Relaxed);
                let prev = prev_status.get(&code).copied().unwrap_or(0);
                let rate = curr.saturating_sub(prev) / window_seconds;

                // Update or insert the per-second rate.
                if let Some(existing) = windowed.status_codes_per_second.get(&code) {
                    existing.value().store(rate, Ordering::Relaxed);
                } else {
                    windowed
                        .status_codes_per_second
                        .insert(code, AtomicU64::new(rate));
                }

                prev_status.insert(code, curr);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[test]
    fn windowed_metrics_new_initializes_correctly() {
        let m = WindowedMetrics::new(10);
        assert_eq!(m.window_seconds, 10);
        assert_eq!(m.requests_per_second.load(Ordering::Relaxed), 0);
        assert!(m.status_codes_per_second.is_empty());
    }

    #[tokio::test]
    async fn monitor_computes_rate_after_window() {
        let request_count = Arc::new(AtomicU64::new(0));
        let status_counts: Arc<DashMap<u16, AtomicU64>> = Arc::new(DashMap::new());
        let windowed = Arc::new(WindowedMetrics::new(1));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = start_metrics_monitor(
            request_count.clone(),
            status_counts.clone(),
            windowed.clone(),
            1,
            shutdown_rx,
        );

        // Wait for the monitor to take its initial snapshot (happens immediately on spawn)
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now simulate 100 requests arriving AFTER the initial snapshot
        request_count.store(100, Ordering::Relaxed);

        // Wait for the monitor to compute the first window delta
        tokio::time::sleep(Duration::from_millis(1200)).await;

        let rps = windowed.requests_per_second.load(Ordering::Relaxed);
        assert_eq!(rps, 100, "Should compute 100 requests / 1 second = 100 rps");

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn monitor_tracks_status_code_rates() {
        let request_count = Arc::new(AtomicU64::new(0));
        let status_counts: Arc<DashMap<u16, AtomicU64>> = Arc::new(DashMap::new());
        status_counts.insert(200, AtomicU64::new(0));
        status_counts.insert(404, AtomicU64::new(0));
        let windowed = Arc::new(WindowedMetrics::new(1));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = start_metrics_monitor(
            request_count.clone(),
            status_counts.clone(),
            windowed.clone(),
            1,
            shutdown_rx,
        );

        // Wait for the initial snapshot to be taken
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Simulate status code counts AFTER initial snapshot
        status_counts
            .get(&200)
            .unwrap()
            .store(50, Ordering::Relaxed);
        status_counts
            .get(&404)
            .unwrap()
            .store(10, Ordering::Relaxed);

        // Wait for the monitor to compute the window
        tokio::time::sleep(Duration::from_millis(1200)).await;

        let rate_200 = windowed
            .status_codes_per_second
            .get(&200)
            .map(|e| e.value().load(Ordering::Relaxed))
            .unwrap_or(0);
        let rate_404 = windowed
            .status_codes_per_second
            .get(&404)
            .map(|e| e.value().load(Ordering::Relaxed))
            .unwrap_or(0);
        assert_eq!(rate_200, 50);
        assert_eq!(rate_404, 10);

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn monitor_shuts_down_on_signal() {
        let request_count = Arc::new(AtomicU64::new(0));
        let status_counts: Arc<DashMap<u16, AtomicU64>> = Arc::new(DashMap::new());
        let windowed = Arc::new(WindowedMetrics::new(60)); // Long window — won't tick naturally
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = start_metrics_monitor(request_count, status_counts, windowed, 60, shutdown_rx);

        // Send shutdown immediately
        shutdown_tx.send(true).unwrap();

        // Handle should complete promptly
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "Monitor should shut down within 2 seconds");
    }

    /// window_seconds=0 causes a division by zero. This test documents the bug.
    /// The monitor divides by window_seconds: `delta / window_seconds`.
    /// With window_seconds=0, tokio::time::sleep(Duration::from_secs(0)) returns
    /// immediately, and the division panics.
    #[tokio::test]
    async fn monitor_zero_window_panics() {
        let request_count = Arc::new(AtomicU64::new(100));
        let status_counts: Arc<DashMap<u16, AtomicU64>> = Arc::new(DashMap::new());
        let windowed = Arc::new(WindowedMetrics::new(0));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = start_metrics_monitor(
            request_count,
            status_counts,
            windowed,
            0, // BUG: will cause division by zero
            shutdown_rx,
        );

        // The spawned task should panic due to divide-by-zero
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        match result {
            Ok(Ok(())) => panic!("Expected panic from zero window, but task completed normally"),
            Ok(Err(e)) => {
                assert!(e.is_panic(), "Task should have panicked: {:?}", e);
            }
            Err(_) => panic!("Timed out waiting for zero-window panic"),
        }
    }
}
