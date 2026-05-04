//! Overload manager with resource monitors and progressive load shedding.
//!
//! Runs a background task that periodically checks resource pressure (file
//! descriptors, connection semaphore saturation, event loop latency) and sets
//! atomic action flags that the proxy hot path reads with a single
//! `AtomicBool::load(Relaxed)` (~1ns, zero contention).
//!
//! Also provides graceful shutdown draining: after SIGTERM, tracks in-flight
//! connections and waits up to a configurable drain period for them to complete.

use crossbeam_utils::CachePadded;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Scale factor for RED (Random Early Detection) drop probability.
///
/// The probability is stored as an integer in [0, RED_PROBABILITY_SCALE] where
/// `RED_PROBABILITY_SCALE` represents 100% drop.  The value 1024 matches the
/// 10-bit hash range produced by `>> 54` (which yields [0, 1023]), so
/// comparisons are exact with no precision bias.
pub const RED_PROBABILITY_SCALE: u32 = 1024;

/// Overload pressure level reported via the admin `/overload` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OverloadLevel {
    Normal,
    Pressure,
    Critical,
}

/// Atomic overload state read by the proxy hot path.
///
/// The background monitor writes these flags; request threads only read.
/// All fields use `Ordering::Relaxed` — eventual consistency is acceptable
/// for overload signals (a few ms of stale state is harmless).
///
/// Hot-path atomics (`disable_keepalive`, `reject_new_connections`,
/// `reject_new_requests`, `active_connections`, `active_requests`,
/// `red_drop_probability`, `red_request_counter`) are wrapped in
/// [`CachePadded`] to prevent false sharing across cores: at 1M conn/sec
/// churn, an unpadded layout puts the read-mostly action flags on the same
/// cache line as the `fetch_add`/`fetch_sub` counters, causing the line to
/// ping-pong between cores and turning every accept into a coherence stall.
/// Snapshot fields (`fd_current`, `conn_current`, etc.), `draining`, and
/// `port_exhaustion_events` are NOT padded — they are written ≤ once/sec or
/// only on rare events, so contention does not justify the memory cost.
/// `CachePadded<T>` derefs to `T`, so all existing
/// `.load()` / `.fetch_add()` call sites compile unchanged.
pub struct OverloadState {
    // ── Action flags (hot-path reads) ──────────────────────────────────
    /// When true, responses include `Connection: close` to drain idle keepalives.
    pub disable_keepalive: CachePadded<AtomicBool>,
    /// When true, new connections are rejected with 503 before routing.
    pub reject_new_connections: CachePadded<AtomicBool>,
    /// When true, new requests/streams are rejected with 503 before processing.
    /// Independent of `reject_new_connections` — connections track sockets,
    /// requests track multiplexed H2/H3/gRPC streams.
    pub reject_new_requests: CachePadded<AtomicBool>,

    // ── Graceful shutdown drain ────────────────────────────────────────
    /// Set to true when SIGTERM/SIGINT is received to begin the drain phase.
    pub draining: AtomicBool,
    /// In-flight connection counter. Incremented on accept, decremented on drop
    /// via [`ConnectionGuard`].
    pub active_connections: CachePadded<AtomicU64>,
    /// In-flight request/stream counter. Incremented on request start, decremented
    /// on drop via [`RequestGuard`]. Tracks H1 requests, H2/gRPC streams, and H3
    /// streams independently of connections.
    pub active_requests: CachePadded<AtomicU64>,
    /// Notified each time `active_connections` or `active_requests` reaches zero
    /// during drain. The drain waiter re-checks both counters in a loop.
    pub drain_complete: tokio::sync::Notify,

    // ── RED adaptive load shedding ────────────────────────────────────
    /// RED (Random Early Detection) drop probability (0–[`RED_PROBABILITY_SCALE`] scale,
    /// where [`RED_PROBABILITY_SCALE`] = 100%).  Matches the 10-bit hash range
    /// (`>> 54` produces [0, 1023]) so comparisons are exact with no precision bias.
    /// When in the pressure zone (between pressure and critical thresholds), responses
    /// are probabilistically marked with Connection: close based on this value.
    /// The hot path reads this with a single AtomicU32::load(Relaxed).
    pub red_drop_probability: CachePadded<AtomicU32>,
    /// Monotonic request counter used as per-request entropy for RED decisions.
    /// Incremented by `fetch_add(1, Relaxed)` on each `should_disable_keepalive_red()` call.
    red_request_counter: CachePadded<AtomicU64>,

    // ── Snapshot for admin endpoint (written by monitor, read by admin) ─
    pub fd_current: AtomicU64,
    pub fd_max: AtomicU64,
    pub conn_current: AtomicU64,
    pub conn_max: AtomicU64,
    pub req_current: AtomicU64,
    pub req_max: AtomicU64,
    pub loop_latency_us: AtomicU64,

    // ── Port exhaustion tracking ─────────────────────────────────────
    /// Monotonic count of EADDRNOTAVAIL errors (ephemeral port exhaustion).
    /// Incremented from error classification sites; never reset.
    pub port_exhaustion_events: AtomicU64,
}

impl Default for OverloadState {
    fn default() -> Self {
        Self::new()
    }
}

impl OverloadState {
    pub fn new() -> Self {
        Self {
            disable_keepalive: CachePadded::new(AtomicBool::new(false)),
            reject_new_connections: CachePadded::new(AtomicBool::new(false)),
            reject_new_requests: CachePadded::new(AtomicBool::new(false)),
            draining: AtomicBool::new(false),
            active_connections: CachePadded::new(AtomicU64::new(0)),
            active_requests: CachePadded::new(AtomicU64::new(0)),
            drain_complete: tokio::sync::Notify::new(),
            red_drop_probability: CachePadded::new(AtomicU32::new(0)),
            red_request_counter: CachePadded::new(AtomicU64::new(0)),
            fd_current: AtomicU64::new(0),
            fd_max: AtomicU64::new(0),
            conn_current: AtomicU64::new(0),
            conn_max: AtomicU64::new(0),
            req_current: AtomicU64::new(0),
            req_max: AtomicU64::new(0),
            loop_latency_us: AtomicU64::new(0),
            port_exhaustion_events: AtomicU64::new(0),
        }
    }

    /// Current overload level derived from the action flags.
    pub fn level(&self) -> OverloadLevel {
        if self.reject_new_connections.load(Ordering::Relaxed)
            || self.reject_new_requests.load(Ordering::Relaxed)
        {
            OverloadLevel::Critical
        } else if self.disable_keepalive.load(Ordering::Relaxed) {
            OverloadLevel::Pressure
        } else {
            OverloadLevel::Normal
        }
    }

    /// Returns true if this response should have keepalive disabled based on RED probability.
    /// Uses a monotonic per-request counter with golden-ratio hashing for uniform distribution.
    /// Cost: one AtomicU32::load + one AtomicU64::fetch_add(Relaxed) + one multiply + one comparison.
    pub fn should_disable_keepalive_red(&self) -> bool {
        let prob = self.red_drop_probability.load(Ordering::Relaxed);
        if prob == 0 {
            return false;
        }
        if prob >= RED_PROBABILITY_SCALE {
            return true;
        }
        // Monotonic counter ensures each call gets a unique input, producing
        // true per-response probabilistic shedding even when active_connections
        // is stable.
        let counter = self.red_request_counter.fetch_add(1, Ordering::Relaxed);
        // Golden-ratio hash: multiply and take high bits for 0-1023 range.
        // Both the hash output and probability scale use [0, RED_PROBABILITY_SCALE)
        // so the comparison is exact — no precision bias.
        let hash = counter.wrapping_mul(0x9E3779B97F4A7C15) >> 54;
        (hash as u32) < prob
    }

    /// Record an ephemeral port exhaustion event (EADDRNOTAVAIL).
    /// Called from error classification sites when a connect failure is
    /// identified as port exhaustion.
    pub fn record_port_exhaustion(&self) {
        self.port_exhaustion_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Build a JSON-serializable snapshot for the admin endpoint.
    pub fn snapshot(&self) -> OverloadSnapshot {
        let fd_current = self.fd_current.load(Ordering::Relaxed);
        let fd_max = self.fd_max.load(Ordering::Relaxed);
        let conn_current = self.conn_current.load(Ordering::Relaxed);
        let conn_max = self.conn_max.load(Ordering::Relaxed);
        let req_current = self.req_current.load(Ordering::Relaxed);
        let req_max = self.req_max.load(Ordering::Relaxed);
        OverloadSnapshot {
            level: self.level(),
            draining: self.draining.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            active_requests: self.active_requests.load(Ordering::Relaxed),
            red_drop_probability_pct: self.red_drop_probability.load(Ordering::Relaxed) as f64
                / (RED_PROBABILITY_SCALE as f64 / 100.0),
            port_exhaustion_events: self.port_exhaustion_events.load(Ordering::Relaxed),
            pressure: PressureSnapshot {
                file_descriptors: FdPressure {
                    current: fd_current,
                    max: fd_max,
                    ratio: if fd_max > 0 {
                        fd_current as f64 / fd_max as f64
                    } else {
                        0.0
                    },
                },
                connections: ConnPressure {
                    current: conn_current,
                    max: conn_max,
                    ratio: if conn_max > 0 {
                        conn_current as f64 / conn_max as f64
                    } else {
                        0.0
                    },
                },
                requests: ReqPressure {
                    current: req_current,
                    max: req_max,
                    ratio: if req_max > 0 {
                        req_current as f64 / req_max as f64
                    } else {
                        0.0
                    },
                },
                event_loop_latency_us: self.loop_latency_us.load(Ordering::Relaxed),
            },
            actions: ActionSnapshot {
                disable_keepalive: self.disable_keepalive.load(Ordering::Relaxed),
                reject_new_connections: self.reject_new_connections.load(Ordering::Relaxed),
                reject_new_requests: self.reject_new_requests.load(Ordering::Relaxed),
            },
        }
    }
}

/// RAII guard that decrements [`OverloadState::active_connections`] on drop.
///
/// Created for every accepted connection. Cost: one `fetch_add(Relaxed)` on
/// construction, one `fetch_sub(Relaxed)` on drop (~5ns each, no contention).
pub struct ConnectionGuard {
    state: Arc<OverloadState>,
}

impl ConnectionGuard {
    pub fn new(state: &Arc<OverloadState>) -> Self {
        state.active_connections.fetch_add(1, Ordering::Relaxed);
        Self {
            state: state.clone(),
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let prev = self
            .state
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        // If this was the last connection and we are draining, notify the waiter.
        if prev == 1 && self.state.draining.load(Ordering::Relaxed) {
            self.state.drain_complete.notify_one();
        }
    }
}

/// RAII guard that decrements [`OverloadState::active_requests`] on drop.
///
/// Created for every accepted request/stream (H1 requests, H2/gRPC streams,
/// H3 streams). Cost: one `fetch_add(Relaxed)` on construction, one
/// `fetch_sub(Relaxed)` on drop (~5ns each, no contention).
pub struct RequestGuard {
    state: Arc<OverloadState>,
}

impl RequestGuard {
    pub fn new(state: &Arc<OverloadState>) -> Self {
        state.active_requests.fetch_add(1, Ordering::Relaxed);
        Self {
            state: state.clone(),
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let prev = self.state.active_requests.fetch_sub(1, Ordering::Relaxed);
        // If this was the last request and we are draining, notify the waiter.
        // The drain waiter re-checks both active_connections and active_requests,
        // so spurious wakes from one counter reaching zero are harmless.
        if prev == 1 && self.state.draining.load(Ordering::Relaxed) {
            self.state.drain_complete.notify_one();
        }
    }
}

// ── Serializable snapshot types ──────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct OverloadSnapshot {
    pub level: OverloadLevel,
    pub draining: bool,
    pub active_connections: u64,
    pub active_requests: u64,
    pub red_drop_probability_pct: f64,
    pub port_exhaustion_events: u64,
    pub pressure: PressureSnapshot,
    pub actions: ActionSnapshot,
}

#[derive(Debug, serde::Serialize)]
pub struct PressureSnapshot {
    pub file_descriptors: FdPressure,
    pub connections: ConnPressure,
    pub requests: ReqPressure,
    pub event_loop_latency_us: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct FdPressure {
    pub current: u64,
    pub max: u64,
    pub ratio: f64,
}

#[derive(Debug, serde::Serialize)]
pub struct ConnPressure {
    pub current: u64,
    pub max: u64,
    pub ratio: f64,
}

#[derive(Debug, serde::Serialize)]
pub struct ReqPressure {
    pub current: u64,
    pub max: u64,
    pub ratio: f64,
}

#[derive(Debug, serde::Serialize)]
pub struct ActionSnapshot {
    pub disable_keepalive: bool,
    pub reject_new_connections: bool,
    pub reject_new_requests: bool,
}

// ── Overload manager configuration ──────────────────────────────────────

/// Configuration for the overload manager, parsed from env vars.
#[derive(Debug, Clone)]
pub struct OverloadConfig {
    /// How often the monitor checks resource pressure (default: 1000ms).
    pub check_interval_ms: u64,
    /// FD ratio above which keepalive is disabled (default: 0.80).
    pub fd_pressure_threshold: f64,
    /// FD ratio above which new connections are rejected (default: 0.95).
    pub fd_critical_threshold: f64,
    /// Connection semaphore usage above which keepalive is disabled (default: 0.85).
    pub conn_pressure_threshold: f64,
    /// Connection semaphore usage above which new connections are rejected (default: 0.95).
    pub conn_critical_threshold: f64,
    /// Request usage above which keepalive is disabled (default: 0.85).
    pub req_pressure_threshold: f64,
    /// Request usage above which new requests are rejected (default: 0.95).
    pub req_critical_threshold: f64,
    /// Event loop latency (μs) above which a warning is logged (default: 10_000 = 10ms).
    pub loop_warn_us: u64,
    /// Event loop latency (μs) above which new connections are rejected (default: 500_000 = 500ms).
    pub loop_critical_us: u64,
}

impl Default for OverloadConfig {
    fn default() -> Self {
        Self {
            check_interval_ms: 1000,
            fd_pressure_threshold: 0.80,
            fd_critical_threshold: 0.95,
            conn_pressure_threshold: 0.85,
            conn_critical_threshold: 0.95,
            req_pressure_threshold: 0.85,
            req_critical_threshold: 0.95,
            loop_warn_us: 10_000,
            loop_critical_us: 500_000,
        }
    }
}

// ── Resource monitors ───────────────────────────────────────────────────

/// Count open file descriptors for the current process.
#[cfg(target_os = "linux")]
fn count_open_fds() -> u64 {
    // On Linux, /proc/self/fd is the canonical way to count open FDs.
    std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count() as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn count_open_fds() -> u64 {
    // On macOS, use proc_pidinfo via the libc FFI constants.
    // PROC_PIDLISTFDS = 1, sizeof(proc_fdinfo) = 8
    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_FDINFO_SIZE: u64 = 8; // sizeof(proc_fdinfo) = u32 + u32
    let pid = std::process::id() as i32;
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut std::ffi::c_void,
            buffersize: i32,
        ) -> i32;
    }
    let buffer_size = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if buffer_size <= 0 {
        return 0;
    }
    (buffer_size as u64) / PROC_FDINFO_SIZE
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn count_open_fds() -> u64 {
    0 // FD monitoring not available on this platform
}

/// Platform constant for `RLIMIT_NOFILE` (the rlimit resource selector for the
/// per-process open-file-descriptor cap). Linux puts it at 7, the BSD lineage
/// (macOS, FreeBSD, etc.) at 8 — see `<sys/resource.h>`.
#[cfg(target_os = "linux")]
const RLIMIT_NOFILE: i32 = 7;
#[cfg(target_os = "macos")]
const RLIMIT_NOFILE: i32 = 8;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const RLIMIT_NOFILE: i32 = 8; // BSD default

/// Recommended floor for the FD hard cap on production hosts. 65,536 covers
/// 30K+ inbound TCP conns + their amortized outbound pool entries + the
/// runtime/CRT FDs without the gateway tripping its own 95% critical
/// threshold. Below this we emit a `warn!` at startup so operators see the
/// signal in their log pipeline rather than discovering it at the EMFILE.
pub const FD_HARD_LIMIT_PRODUCTION_FLOOR: u64 = 65_536;

/// Outcome of the startup attempt to raise the soft FD cap to the hard cap.
/// Reported by [`raise_fd_limit`] for logging and tests.
#[derive(Debug, Clone, Copy)]
pub struct RaiseFdLimitResult {
    /// Soft limit observed before the call (0 on non-Unix or if `getrlimit` failed).
    pub soft_before: u64,
    /// Soft limit after the call. Equal to `soft_before` if `setrlimit` was a
    /// no-op or failed; equal to `hard` on success.
    pub soft_after: u64,
    /// Hard limit (unchanged by this call — we never attempt to raise it).
    pub hard: u64,
    /// True when `setrlimit` actually moved the soft cap upward.
    pub raised: bool,
}

/// Get the maximum file descriptor limit (soft limit) via getrlimit.
fn get_fd_limit() -> u64 {
    #[cfg(unix)]
    {
        // rlimit struct: two u64 fields (rlim_cur, rlim_max) on 64-bit platforms
        let mut rlim: [u64; 2] = [0, 0];
        unsafe extern "C" {
            fn getrlimit(resource: i32, rlim: *mut [u64; 2]) -> i32;
        }
        let result = unsafe { getrlimit(RLIMIT_NOFILE, &mut rlim) };
        if result == 0 { rlim[0] } else { 0 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Read both rlimit fields (soft, hard) at once. Returns `(0, 0)` on
/// non-Unix or if the syscall fails. Used by [`raise_fd_limit`] so it can
/// report `(before, after, hard)` in a single result struct.
#[cfg(unix)]
fn get_fd_rlimit_pair() -> (u64, u64) {
    let mut rlim: [u64; 2] = [0, 0];
    unsafe extern "C" {
        fn getrlimit(resource: i32, rlim: *mut [u64; 2]) -> i32;
    }
    let result = unsafe { getrlimit(RLIMIT_NOFILE, &mut rlim) };
    if result == 0 {
        (rlim[0], rlim[1])
    } else {
        (0, 0)
    }
}

/// Raise the soft FD limit (`RLIMIT_NOFILE.rlim_cur`) to the hard limit.
///
/// Called once at startup. Conservative by design — we never attempt to raise
/// the hard cap, so this never asks for privileges the process does not already
/// have. If `setrlimit` fails (sandboxed container, seccomp filter, or the
/// kernel rejects the value), the call is a no-op and the gateway continues
/// with whatever soft cap it inherited.
///
/// On non-Unix platforms this is a no-op that returns zeros.
///
/// Operators running production workloads should make sure the *hard* cap is
/// at least [`FD_HARD_LIMIT_PRODUCTION_FLOOR`] (set via `LimitNOFILE=` in
/// systemd, `--ulimit nofile=` in Docker, or `/etc/security/limits.conf`) —
/// when it is below that floor, [`raise_fd_limit`] only emits a structured
/// `warn!` at startup; it does not fail. The caller (typically `main.rs`) is
/// responsible for logging the result.
pub fn raise_fd_limit() -> RaiseFdLimitResult {
    #[cfg(unix)]
    {
        let (soft_before, hard) = get_fd_rlimit_pair();
        if soft_before == 0 && hard == 0 {
            // getrlimit failed — bail out without an unsafe second syscall.
            return RaiseFdLimitResult {
                soft_before: 0,
                soft_after: 0,
                hard: 0,
                raised: false,
            };
        }

        if soft_before >= hard {
            // Already at the hard cap — nothing to do.
            return RaiseFdLimitResult {
                soft_before,
                soft_after: soft_before,
                hard,
                raised: false,
            };
        }

        unsafe extern "C" {
            fn setrlimit(resource: i32, rlim: *const [u64; 2]) -> i32;
        }
        let new_rlim: [u64; 2] = [hard, hard];
        let result = unsafe { setrlimit(RLIMIT_NOFILE, &new_rlim) };
        if result == 0 {
            RaiseFdLimitResult {
                soft_before,
                soft_after: hard,
                hard,
                raised: true,
            }
        } else {
            // setrlimit refused the bump — keep running with the old soft cap.
            RaiseFdLimitResult {
                soft_before,
                soft_after: soft_before,
                hard,
                raised: false,
            }
        }
    }
    #[cfg(not(unix))]
    {
        RaiseFdLimitResult {
            soft_before: 0,
            soft_after: 0,
            hard: 0,
            raised: false,
        }
    }
}

/// Measure event loop latency by yielding and measuring the scheduling delay.
async fn measure_event_loop_latency() -> Duration {
    let start = std::time::Instant::now();
    tokio::task::yield_now().await;
    start.elapsed()
}

// ── Background monitor task ─────────────────────────────────────────────

/// Start the overload monitor background task.
///
/// Returns a `JoinHandle` that the caller should await during shutdown.
/// The task exits cleanly when `shutdown_rx` fires.
pub fn start_monitor(
    state: Arc<OverloadState>,
    config: OverloadConfig,
    max_connections: usize,
    max_requests: usize,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_millis(config.check_interval_ms);
        let fd_limit = get_fd_limit();

        // Store limits once (don't change during runtime)
        state.fd_max.store(fd_limit, Ordering::Relaxed);
        state
            .conn_max
            .store(max_connections as u64, Ordering::Relaxed);
        state.req_max.store(max_requests as u64, Ordering::Relaxed);

        info!(
            "Overload monitor started (interval={}ms, fd_limit={}, max_conn={}, max_req={})",
            config.check_interval_ms, fd_limit, max_connections, max_requests
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown_rx.changed() => {
                    debug!("Overload monitor shutting down");
                    return;
                }
            }

            // ── FD pressure ──
            let fd_current = count_open_fds();
            state.fd_current.store(fd_current, Ordering::Relaxed);

            let fd_ratio = if fd_limit > 0 {
                fd_current as f64 / fd_limit as f64
            } else {
                0.0
            };

            // ── Connection pressure ──
            // Uses the active_connections counter maintained by ConnectionGuard
            // (covers HTTP/1.1, H2, H3, gRPC, and stream proxy connections).
            let conn_used = state.active_connections.load(Ordering::Relaxed);
            state.conn_current.store(conn_used, Ordering::Relaxed);
            let conn_ratio = if max_connections > 0 {
                conn_used as f64 / max_connections as f64
            } else {
                0.0
            };

            // ── Request pressure ──
            let req_used = state.active_requests.load(Ordering::Relaxed);
            state.req_current.store(req_used, Ordering::Relaxed);
            let req_ratio = if max_requests > 0 {
                req_used as f64 / max_requests as f64
            } else {
                0.0 // unlimited — never triggers pressure
            };

            // ── Event loop latency ──
            let loop_latency = measure_event_loop_latency().await;
            let loop_us = loop_latency.as_micros() as u64;
            state.loop_latency_us.store(loop_us, Ordering::Relaxed);

            // ── Evaluate thresholds and set action flags ──
            let should_disable_keepalive = fd_ratio >= config.fd_pressure_threshold
                || conn_ratio >= config.conn_pressure_threshold
                || (max_requests > 0 && req_ratio >= config.req_pressure_threshold);

            let should_reject = fd_ratio >= config.fd_critical_threshold
                || conn_ratio >= config.conn_critical_threshold
                || loop_us >= config.loop_critical_us;

            // Request-level rejection is independent — only triggers when
            // FERRUM_MAX_REQUESTS is configured (non-zero).
            let should_reject_requests =
                max_requests > 0 && req_ratio >= config.req_critical_threshold;

            // ── RED-style smooth ramp between pressure and critical thresholds ──
            // For BOTH fd and connection pressure, compute probability independently
            // and take the max. This gives a smooth ramp from 0% at the pressure
            // threshold to 100% at the critical threshold.
            let fd_red_prob = if fd_ratio >= config.fd_critical_threshold {
                RED_PROBABILITY_SCALE // 100% drop
            } else if fd_ratio >= config.fd_pressure_threshold {
                let range = config.fd_critical_threshold - config.fd_pressure_threshold;
                let position = fd_ratio - config.fd_pressure_threshold;
                ((position / range) * RED_PROBABILITY_SCALE as f64) as u32
            } else {
                0
            };
            let conn_red_prob = if conn_ratio >= config.conn_critical_threshold {
                RED_PROBABILITY_SCALE // 100% drop
            } else if conn_ratio >= config.conn_pressure_threshold {
                let range = config.conn_critical_threshold - config.conn_pressure_threshold;
                let position = conn_ratio - config.conn_pressure_threshold;
                ((position / range) * RED_PROBABILITY_SCALE as f64) as u32
            } else {
                0
            };
            let req_red_prob = if max_requests > 0 {
                if req_ratio >= config.req_critical_threshold {
                    RED_PROBABILITY_SCALE
                } else if req_ratio >= config.req_pressure_threshold {
                    let range = config.req_critical_threshold - config.req_pressure_threshold;
                    let position = req_ratio - config.req_pressure_threshold;
                    ((position / range) * RED_PROBABILITY_SCALE as f64) as u32
                } else {
                    0
                }
            } else {
                0
            };
            state.red_drop_probability.store(
                fd_red_prob.max(conn_red_prob).max(req_red_prob),
                Ordering::Relaxed,
            );

            // Transition logging — only log when state changes
            let was_rejecting = state.reject_new_connections.load(Ordering::Relaxed);
            let was_rejecting_requests = state.reject_new_requests.load(Ordering::Relaxed);
            let was_keepalive_disabled = state.disable_keepalive.load(Ordering::Relaxed);

            state
                .disable_keepalive
                .store(should_disable_keepalive, Ordering::Relaxed);
            state
                .reject_new_connections
                .store(should_reject, Ordering::Relaxed);
            state
                .reject_new_requests
                .store(should_reject_requests, Ordering::Relaxed);

            if should_reject && !was_rejecting {
                warn!(
                    level = "critical",
                    action = "reject_connections",
                    fd_current = fd_current,
                    fd_max = fd_limit,
                    fd_pct = format_args!("{:.1}", fd_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    conn_pct = format_args!("{:.1}", conn_ratio * 100.0),
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    loop_latency_us = loop_us,
                    "Overload CRITICAL: rejecting new connections",
                );
            } else if !should_reject && was_rejecting {
                info!(
                    level = "normal",
                    action = "accept_connections",
                    fd_current = fd_current,
                    fd_max = fd_limit,
                    fd_pct = format_args!("{:.1}", fd_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    conn_pct = format_args!("{:.1}", conn_ratio * 100.0),
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    loop_latency_us = loop_us,
                    "Overload recovered: accepting new connections",
                );
            }

            if should_reject_requests && !was_rejecting_requests {
                warn!(
                    level = "critical",
                    action = "reject_requests",
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    "Overload CRITICAL: rejecting new requests",
                );
            } else if !should_reject_requests && was_rejecting_requests {
                info!(
                    level = "normal",
                    action = "accept_requests",
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    "Overload recovered: accepting new requests",
                );
            }

            if should_disable_keepalive && !was_keepalive_disabled {
                warn!(
                    level = "pressure",
                    action = "disable_keepalive",
                    fd_current = fd_current,
                    fd_max = fd_limit,
                    fd_pct = format_args!("{:.1}", fd_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    conn_pct = format_args!("{:.1}", conn_ratio * 100.0),
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    loop_latency_us = loop_us,
                    "Overload pressure: disabling keepalive",
                );
            } else if !should_disable_keepalive && was_keepalive_disabled && !should_reject {
                info!(
                    level = "normal",
                    action = "enable_keepalive",
                    fd_current = fd_current,
                    fd_max = fd_limit,
                    fd_pct = format_args!("{:.1}", fd_ratio * 100.0),
                    conn_current = conn_used,
                    conn_max = max_connections,
                    conn_pct = format_args!("{:.1}", conn_ratio * 100.0),
                    req_current = req_used,
                    req_max = max_requests,
                    req_pct = format_args!("{:.1}", req_ratio * 100.0),
                    loop_latency_us = loop_us,
                    "Overload pressure recovered: re-enabling keepalive",
                );
            }

            // Event loop latency warning (independent of action thresholds)
            if loop_us >= config.loop_warn_us && loop_us < config.loop_critical_us {
                warn!(
                    loop_latency_us = loop_us,
                    threshold_us = config.loop_warn_us,
                    "Tokio event loop delayed — possible thread starvation",
                );
            }
        }
    })
}

/// Wait for all in-flight connections and requests to drain, up to the
/// configured timeout.
///
/// Called after the accept loops have exited. Returns `true` if all connections
/// and requests drained within the timeout, `false` if the timeout expired.
pub async fn wait_for_drain(state: &Arc<OverloadState>, timeout: Duration) -> bool {
    state.draining.store(true, Ordering::Relaxed);

    let active_conns = state.active_connections.load(Ordering::Relaxed);
    let active_reqs = state.active_requests.load(Ordering::Relaxed);
    if active_conns == 0 && active_reqs == 0 {
        info!(
            phase = "drain",
            "No active connections or requests to drain"
        );
        return true;
    }

    info!(
        phase = "drain",
        active_connections = active_conns,
        active_requests = active_reqs,
        timeout_seconds = timeout.as_secs(),
        "Draining active connections and requests",
    );

    match tokio::time::timeout(timeout, async {
        loop {
            if state.active_connections.load(Ordering::Relaxed) == 0
                && state.active_requests.load(Ordering::Relaxed) == 0
            {
                break;
            }
            state.drain_complete.notified().await;
        }
    })
    .await
    {
        Ok(()) => {
            info!(
                phase = "drain",
                result = "complete",
                "All connections and requests drained successfully"
            );
            true
        }
        Err(_) => {
            let remaining_conns = state.active_connections.load(Ordering::Relaxed);
            let remaining_reqs = state.active_requests.load(Ordering::Relaxed);
            warn!(
                phase = "drain",
                result = "timeout",
                remaining_connections = remaining_conns,
                remaining_requests = remaining_reqs,
                "Drain timeout expired — force closing",
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn fd_limit_is_nonzero() {
        assert!(get_fd_limit() > 0, "FD limit should be > 0 on Unix");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fd_count_is_nonzero() {
        let count = count_open_fds();
        assert!(count > 0, "Process should have at least some open FDs");
    }

    /// `raise_fd_limit` must never return a soft cap above the hard cap, must
    /// never lower the soft cap, and must accurately report whether it
    /// actually moved the limit. Sandboxed/seccomp test runners are still
    /// expected to satisfy these invariants because the call is a silent
    /// no-op when `setrlimit` is denied.
    #[cfg(unix)]
    #[test]
    fn raise_fd_limit_respects_invariants() {
        let result = raise_fd_limit();
        assert!(
            result.soft_after >= result.soft_before,
            "soft cap must never decrease: before={} after={}",
            result.soft_before,
            result.soft_after,
        );
        assert!(
            result.soft_after <= result.hard,
            "soft cap must never exceed hard cap: soft_after={} hard={}",
            result.soft_after,
            result.hard,
        );
        // `raised` must be consistent with the before/after delta.
        if result.raised {
            assert!(
                result.soft_after > result.soft_before,
                "raised=true requires soft_after > soft_before",
            );
        }
    }

    /// `raise_fd_limit` is idempotent — calling it a second time after the
    /// first run reaches the hard cap must report `raised=false` and leave
    /// the cap untouched. This protects against accidental double-call from
    /// a future test or a CLI subcommand also wiring the helper into its
    /// startup.
    #[cfg(unix)]
    #[test]
    fn raise_fd_limit_is_idempotent() {
        let first = raise_fd_limit();
        let second = raise_fd_limit();
        assert_eq!(
            first.soft_after, second.soft_after,
            "second call must not change the soft cap",
        );
        assert!(
            !second.raised,
            "second call must report raised=false; got soft_before={} soft_after={}",
            second.soft_before, second.soft_after,
        );
    }

    /// `CachePadded<T>` must occupy at least one cache line so that two
    /// adjacent atomics in `OverloadState` do not share a line. The exact
    /// alignment is platform-specific (64 B on x86-64, 128 B on aarch64),
    /// but `crossbeam_utils` guarantees `>= 64`. This test catches a future
    /// dep update that silently regresses the padding contract.
    #[test]
    fn cache_padded_atomic_u64_is_at_least_one_cache_line() {
        let size = std::mem::size_of::<CachePadded<AtomicU64>>();
        assert!(
            size >= 64,
            "CachePadded<AtomicU64> should be >= 64 bytes (one cache line); got {}",
            size,
        );
    }

    /// The hot atomics on `OverloadState` are intentionally on separate
    /// cache lines from each other — verify the read-mostly action flag and
    /// the write-heavy connection counter are not co-located. Address
    /// distance >= 64 on x86-64 is sufficient evidence.
    #[test]
    fn hot_atomics_do_not_share_cache_line() {
        let state = OverloadState::new();
        let reject_addr = &*state.reject_new_connections as *const AtomicBool as usize;
        let active_addr = &*state.active_connections as *const AtomicU64 as usize;
        let distance = reject_addr.abs_diff(active_addr);
        assert!(
            distance >= 64,
            "reject_new_connections and active_connections should be on different cache lines; distance={}",
            distance,
        );
    }

    /// Verify that the RED shedding rate matches the configured probability
    /// within tight tolerance. The hash range [0, RED_PROBABILITY_SCALE) and
    /// probability scale [0, RED_PROBABILITY_SCALE] are aligned, so there
    /// should be no systematic bias.
    #[test]
    fn red_shedding_precision_no_bias() {
        let state = OverloadState::new();
        let samples = 102_400;
        let half = RED_PROBABILITY_SCALE / 2;

        // Test at 50% (prob = half the scale)
        state.red_drop_probability.store(half, Ordering::Relaxed);
        let mut triggered = 0u64;
        for _ in 0..samples {
            if state.should_disable_keepalive_red() {
                triggered += 1;
            }
        }
        let actual_rate = triggered as f64 / samples as f64;
        let expected_rate = half as f64 / RED_PROBABILITY_SCALE as f64;
        assert!(
            (actual_rate - expected_rate).abs() < 0.01,
            "50% probability: expected {:.4}, got {:.4}",
            expected_rate,
            actual_rate
        );

        // Test at ~99.9% (prob = RED_PROBABILITY_SCALE - 1)
        let near_max = RED_PROBABILITY_SCALE - 1;
        state
            .red_drop_probability
            .store(near_max, Ordering::Relaxed);
        triggered = 0;
        for _ in 0..samples {
            if state.should_disable_keepalive_red() {
                triggered += 1;
            }
        }
        let actual_rate = triggered as f64 / samples as f64;
        let expected_rate = near_max as f64 / RED_PROBABILITY_SCALE as f64;
        assert!(
            (actual_rate - expected_rate).abs() < 0.01,
            "99.9% probability: expected {:.4}, got {:.4}",
            expected_rate,
            actual_rate
        );
    }
}
