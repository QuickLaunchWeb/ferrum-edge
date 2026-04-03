//! UDP Datagram Rate Limiting Plugin
//!
//! Rate limits UDP datagrams per client IP using a fixed-window algorithm
//! with atomic counters. Protects backend services from UDP flood attacks
//! by silently dropping excess datagrams — standard UDP behavior.
//!
//! Unlike the HTTP `rate_limiting` plugin which operates on HTTP requests,
//! this plugin operates on individual UDP datagrams before they are forwarded
//! to the backend. Each client IP gets its own independent rate window.
//!
//! Two independent limits can be configured (either or both):
//! - `datagrams_per_second`: maximum datagrams per window
//! - `bytes_per_second`: maximum bytes per window
//!
//! Config:
//! ```json
//! {
//!   "datagrams_per_second": 1000,
//!   "bytes_per_second": 1048576,
//!   "window_seconds": 1
//! }
//! ```
//!
//! At least one of `datagrams_per_second` or `bytes_per_second` must be set.
//! If `window_seconds` is not set, it defaults to 1.

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::warn;

use super::{Plugin, ProxyProtocol, UDP_ONLY_PROTOCOLS, UdpDatagramContext, UdpDatagramVerdict};

/// Maximum tracked client IPs before triggering forced eviction.
const MAX_STATE_ENTRIES: usize = 100_000;

/// Interval between periodic eviction sweeps (every N datagram checks).
/// At 10k datagrams/sec, this triggers roughly every 10 seconds.
const EVICTION_CHECK_INTERVAL: u64 = 100_000;

/// Per-client-IP rate window state.
///
/// Uses a fixed-window approach with atomic operations for lock-free
/// per-datagram checking. Window transitions are handled via CAS on
/// the `window_epoch` field.
struct WindowState {
    /// Datagram count in the current window.
    count: AtomicU64,
    /// Byte count in the current window.
    bytes: AtomicU64,
    /// Window epoch (monotonic instant divided by window duration).
    /// When the current epoch exceeds this, the counters are reset.
    window_epoch: AtomicU64,
    /// Last check time for staleness detection during eviction.
    last_check: std::sync::Mutex<Instant>,
}

impl WindowState {
    fn new(epoch: u64) -> Self {
        Self {
            count: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            window_epoch: AtomicU64::new(epoch),
            last_check: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Check if this entry has been inactive for longer than the eviction threshold.
    fn is_stale(&self, now: Instant, max_idle_secs: f64) -> bool {
        let last = self.last_check.lock().unwrap_or_else(|e| e.into_inner());
        now.duration_since(*last).as_secs_f64() > max_idle_secs
    }
}

pub struct UdpRateLimiting {
    datagrams_per_window: Option<u64>,
    bytes_per_window: Option<u64>,
    window_seconds: u64,
    /// Per-client-IP window state.
    state: DashMap<String, WindowState>,
    /// Monotonic datagram counter for periodic eviction.
    check_counter: AtomicU64,
    /// Startup instant used to compute window epochs from Instant::now().
    epoch_base: Instant,
}

impl UdpRateLimiting {
    pub fn new(config: &Value) -> Result<Self, String> {
        let datagrams_per_second = config["datagrams_per_second"].as_u64();
        let bytes_per_second = config["bytes_per_second"].as_u64();

        if datagrams_per_second.is_none() && bytes_per_second.is_none() {
            return Err(
                "udp_rate_limiting: at least one of 'datagrams_per_second' or 'bytes_per_second' must be set"
                    .to_string(),
            );
        }

        let window_seconds = config["window_seconds"].as_u64().unwrap_or(1).max(1);

        let datagrams_per_window = datagrams_per_second.map(|d| d * window_seconds);
        let bytes_per_window = bytes_per_second.map(|b| b * window_seconds);

        Ok(Self {
            datagrams_per_window,
            bytes_per_window,
            window_seconds,
            state: DashMap::new(),
            check_counter: AtomicU64::new(0),
            epoch_base: Instant::now(),
        })
    }

    /// Compute the current window epoch as a monotonic counter.
    fn current_epoch(&self) -> u64 {
        let elapsed = Instant::now().duration_since(self.epoch_base).as_secs();
        elapsed / self.window_seconds
    }

    /// Evict stale entries to prevent unbounded memory growth.
    fn maybe_evict(&self) {
        let count = self.check_counter.fetch_add(1, Ordering::Relaxed);

        let over_capacity = self.state.len() > MAX_STATE_ENTRIES;
        let periodic =
            count > 0 && count.is_multiple_of(EVICTION_CHECK_INTERVAL) && !self.state.is_empty();

        if over_capacity || periodic {
            let now = Instant::now();
            // Evict entries idle for more than 2x the window duration (minimum 10s).
            let max_idle = (self.window_seconds as f64 * 2.0).max(10.0);
            self.state.retain(|_, v| !v.is_stale(now, max_idle));
        }
    }
}

#[async_trait]
impl Plugin for UdpRateLimiting {
    fn name(&self) -> &str {
        "udp_rate_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::UDP_RATE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        UDP_ONLY_PROTOCOLS
    }

    fn requires_udp_datagram_hooks(&self) -> bool {
        true
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.state.len())
    }

    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext) -> UdpDatagramVerdict {
        self.maybe_evict();

        let current_epoch = self.current_epoch();
        let key = &ctx.client_ip;

        let entry = self
            .state
            .entry(key.clone())
            .or_insert_with(|| WindowState::new(current_epoch));
        let state = entry.value();

        // Check if we've moved to a new window — reset counters via CAS.
        let stored_epoch = state.window_epoch.load(Ordering::Relaxed);
        if current_epoch > stored_epoch
            && state
                .window_epoch
                .compare_exchange(
                    stored_epoch,
                    current_epoch,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            state.count.store(0, Ordering::Relaxed);
            state.bytes.store(0, Ordering::Relaxed);
        }

        // Update last-check time for staleness tracking.
        if let Ok(mut last) = state.last_check.lock() {
            *last = Instant::now();
        }

        // Increment counters.
        let new_count = state.count.fetch_add(1, Ordering::Relaxed) + 1;
        let new_bytes = state
            .bytes
            .fetch_add(ctx.datagram_size as u64, Ordering::Relaxed)
            + ctx.datagram_size as u64;

        // Check limits.
        if let Some(max_datagrams) = self.datagrams_per_window
            && new_count > max_datagrams
        {
            warn!(
                plugin = "udp_rate_limiting",
                proxy_id = %ctx.proxy_id,
                client_ip = %ctx.client_ip,
                count = new_count,
                limit = max_datagrams,
                "UDP datagram rate exceeded, dropping"
            );
            return UdpDatagramVerdict::Drop;
        }

        if let Some(max_bytes) = self.bytes_per_window
            && new_bytes > max_bytes
        {
            warn!(
                plugin = "udp_rate_limiting",
                proxy_id = %ctx.proxy_id,
                client_ip = %ctx.client_ip,
                bytes = new_bytes,
                limit = max_bytes,
                "UDP byte rate exceeded, dropping"
            );
            return UdpDatagramVerdict::Drop;
        }

        UdpDatagramVerdict::Forward
    }
}
