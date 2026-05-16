//! Shared counter store for the `__mesh_bpf_metrics` plugin.
//!
//! The eBPF `BPF_PROG_TYPE_SOCK_OPS` program publishes per-event records
//! (Connect, AcceptEstablished, RstSent/Received, FinSent/Received, RttSample,
//! drop-reason hits) over a per-CPU ringbuf. The userspace consumer
//! (`event_consumer.rs`) drains the ringbuf and increments the counters here;
//! the [`crate::plugins::mesh::bpf_metrics`] plugin reads from the same state
//! and emits Prometheus metrics. This decoupling means the plugin's
//! hot/cold path doesn't touch the BPF maps directly and doesn't need
//! `aya` linked into every build.
//!
//! ## Concurrency
//!
//! All counters are `AtomicU64` with `Ordering::Relaxed` — these are
//! cumulative monotonically-increasing counters with no causal ordering
//! across counters, matching the same shape as `OverloadState` snapshot
//! fields. Atomics on the event-consumer hot path are wrapped in
//! `crossbeam_utils::CachePadded` so per-CPU consumer threads don't
//! coherence-traffic each other through a shared cache line.
//!
//! ## Ringbuf overrun handling
//!
//! [`BpfMetricsState::record_ringbuf_overrun`] increments `ringbuf_overruns`
//! AND tracks a one-shot state-transition so the consumer can emit a
//! `warn!` exactly once when the system enters an overrun regime and an
//! `info!` exactly once when it recovers — mirroring the overload manager
//! pattern (warn enter, info recover, no per-event spam). This is the
//! "silent drops would be a regression" guard from the GAP-SC3 plan.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crossbeam_utils::CachePadded;

/// One BPF drop reason from the data path. Each variant maps to a
/// kernel-side decision the SOCK_OPS program logged before redirecting (or
/// not) the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfDropReason {
    /// Connection bypassed because the source UID was in the bypass set
    /// (typically the proxy's own UID — recursion prevention).
    BypassUidHit,
    /// Connection bypassed because the destination IP fell into an
    /// operator-configured exclude CIDR.
    ExcludeCidrHit,
    /// Connection bypassed because the source IP wasn't in the include CIDR
    /// (sidecarless capture is opt-in per CIDR).
    NotInIncludeCidr,
    /// Connection bypassed because the destination port was in the
    /// operator-configured port exclude set.
    ExcludePortHit,
}

impl BpfDropReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::BypassUidHit => "bypass_uid_hit",
            Self::ExcludeCidrHit => "exclude_cidr_hit",
            Self::NotInIncludeCidr => "not_in_include_cidr",
            Self::ExcludePortHit => "exclude_port_hit",
        }
    }
}

/// Operator-visible counters published by the SOCK_OPS event consumer.
///
/// Held inside an `Arc` so the consumer task and the plugin can share
/// access without cloning. All fields are read concurrently with writes,
/// hence the `CachePadded` wrapping on the consumer-hot ones (`connect`,
/// `accept_established`, `rtt_sample` are the highest-volume events).
#[derive(Default)]
pub struct BpfMetricsState {
    // Connection lifecycle counters
    pub connect: CachePadded<AtomicU64>,
    pub accept_established: CachePadded<AtomicU64>,
    pub rst_sent: AtomicU64,
    pub rst_received: AtomicU64,
    pub fin_sent: AtomicU64,
    pub fin_received: AtomicU64,

    // Latency samples (TCP-layer only).
    //
    // We track sum + count so the plugin can emit a derived mean without
    // doing per-sample work. Histogram-style buckets are a future
    // follow-up; for now operators correlate `mean = srtt_sum_us /
    // srtt_count` against an alerting threshold.
    pub srtt_sample_us_sum: AtomicU64,
    pub srtt_count: CachePadded<AtomicU64>,
    pub syn_to_ack_us_sum: AtomicU64,
    pub syn_to_ack_count: AtomicU64,
    pub accept_to_first_byte_us_sum: AtomicU64,
    pub accept_to_first_byte_count: AtomicU64,

    // BPF drop-reason counters — one bin per reason. These were
    // previously invisible to operators; the GAP-SC3 plan calls them out
    // explicitly as a key win.
    pub drop_bypass_uid_hit: AtomicU64,
    pub drop_exclude_cidr_hit: AtomicU64,
    pub drop_not_in_include_cidr: AtomicU64,
    pub drop_exclude_port_hit: AtomicU64,

    // Ringbuf health
    pub ringbuf_events_consumed: AtomicU64,
    pub ringbuf_overruns: AtomicU64,
    /// True while we believe we're in an overrun regime. The consumer
    /// flips this on the first overrun and back off only after the
    /// recovery threshold is met. Used to suppress per-event log spam.
    in_overrun_regime: AtomicBool,
}

impl BpfMetricsState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_connect(&self) {
        self.connect.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_accept_established(&self) {
        self.accept_established.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rst(&self, direction: TcpDirection) {
        match direction {
            TcpDirection::Sent => self.rst_sent.fetch_add(1, Ordering::Relaxed),
            TcpDirection::Received => self.rst_received.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn record_fin(&self, direction: TcpDirection) {
        match direction {
            TcpDirection::Sent => self.fin_sent.fetch_add(1, Ordering::Relaxed),
            TcpDirection::Received => self.fin_received.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn record_srtt_sample(&self, srtt_us: u64) {
        self.srtt_sample_us_sum
            .fetch_add(srtt_us, Ordering::Relaxed);
        self.srtt_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_syn_to_ack(&self, us: u64) {
        self.syn_to_ack_us_sum.fetch_add(us, Ordering::Relaxed);
        self.syn_to_ack_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_accept_to_first_byte(&self, us: u64) {
        self.accept_to_first_byte_us_sum
            .fetch_add(us, Ordering::Relaxed);
        self.accept_to_first_byte_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_drop(&self, reason: BpfDropReason) {
        let target = match reason {
            BpfDropReason::BypassUidHit => &self.drop_bypass_uid_hit,
            BpfDropReason::ExcludeCidrHit => &self.drop_exclude_cidr_hit,
            BpfDropReason::NotInIncludeCidr => &self.drop_not_in_include_cidr,
            BpfDropReason::ExcludePortHit => &self.drop_exclude_port_hit,
        };
        target.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ringbuf_event(&self) {
        self.ringbuf_events_consumed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment ringbuf-overrun counter and report whether this is the
    /// first overrun in the current regime (call this once per detected
    /// overrun event from the consumer task). Returns `true` exactly once
    /// per entry into an overrun regime, allowing the caller to emit a
    /// single `warn!` line.
    pub fn record_ringbuf_overrun(&self) -> bool {
        self.ringbuf_overruns.fetch_add(1, Ordering::Relaxed);
        // compare_exchange returns Ok if we successfully flipped false→true,
        // i.e., we just entered the overrun regime.
        self.in_overrun_regime
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Reset the overrun regime flag. Returns `true` exactly once per
    /// recovery (i.e., when the flag flips true→false), allowing the
    /// caller to emit a single `info!` recovery line.
    pub fn mark_ringbuf_recovered(&self) -> bool {
        self.in_overrun_regime
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// `true` while at least one overrun has been recorded and the
    /// consumer hasn't observed recovery yet.
    pub fn is_in_overrun_regime(&self) -> bool {
        self.in_overrun_regime.load(Ordering::Acquire)
    }

    /// Cold-path snapshot used by the plugin to emit Prometheus metrics.
    pub fn snapshot(&self) -> BpfMetricsSnapshot {
        BpfMetricsSnapshot {
            connect: self.connect.load(Ordering::Relaxed),
            accept_established: self.accept_established.load(Ordering::Relaxed),
            rst_sent: self.rst_sent.load(Ordering::Relaxed),
            rst_received: self.rst_received.load(Ordering::Relaxed),
            fin_sent: self.fin_sent.load(Ordering::Relaxed),
            fin_received: self.fin_received.load(Ordering::Relaxed),
            srtt_sample_us_sum: self.srtt_sample_us_sum.load(Ordering::Relaxed),
            srtt_count: self.srtt_count.load(Ordering::Relaxed),
            syn_to_ack_us_sum: self.syn_to_ack_us_sum.load(Ordering::Relaxed),
            syn_to_ack_count: self.syn_to_ack_count.load(Ordering::Relaxed),
            accept_to_first_byte_us_sum: self.accept_to_first_byte_us_sum.load(Ordering::Relaxed),
            accept_to_first_byte_count: self.accept_to_first_byte_count.load(Ordering::Relaxed),
            drop_bypass_uid_hit: self.drop_bypass_uid_hit.load(Ordering::Relaxed),
            drop_exclude_cidr_hit: self.drop_exclude_cidr_hit.load(Ordering::Relaxed),
            drop_not_in_include_cidr: self.drop_not_in_include_cidr.load(Ordering::Relaxed),
            drop_exclude_port_hit: self.drop_exclude_port_hit.load(Ordering::Relaxed),
            ringbuf_events_consumed: self.ringbuf_events_consumed.load(Ordering::Relaxed),
            ringbuf_overruns: self.ringbuf_overruns.load(Ordering::Relaxed),
            in_overrun_regime: self.in_overrun_regime.load(Ordering::Acquire),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpDirection {
    Sent,
    Received,
}

/// Cold-path snapshot of [`BpfMetricsState`]. Cheaper to pass around than
/// the live state when emitting metrics so that the plugin doesn't hold
/// `Arc<BpfMetricsState>` across an await.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfMetricsSnapshot {
    pub connect: u64,
    pub accept_established: u64,
    pub rst_sent: u64,
    pub rst_received: u64,
    pub fin_sent: u64,
    pub fin_received: u64,
    pub srtt_sample_us_sum: u64,
    pub srtt_count: u64,
    pub syn_to_ack_us_sum: u64,
    pub syn_to_ack_count: u64,
    pub accept_to_first_byte_us_sum: u64,
    pub accept_to_first_byte_count: u64,
    pub drop_bypass_uid_hit: u64,
    pub drop_exclude_cidr_hit: u64,
    pub drop_not_in_include_cidr: u64,
    pub drop_exclude_port_hit: u64,
    pub ringbuf_events_consumed: u64,
    pub ringbuf_overruns: u64,
    pub in_overrun_regime: bool,
}

impl BpfMetricsSnapshot {
    pub fn drop_by_reason(&self, reason: BpfDropReason) -> u64 {
        match reason {
            BpfDropReason::BypassUidHit => self.drop_bypass_uid_hit,
            BpfDropReason::ExcludeCidrHit => self.drop_exclude_cidr_hit,
            BpfDropReason::NotInIncludeCidr => self.drop_not_in_include_cidr,
            BpfDropReason::ExcludePortHit => self.drop_exclude_port_hit,
        }
    }

    pub fn drop_reasons(&self) -> [(BpfDropReason, u64); 4] {
        [
            (BpfDropReason::BypassUidHit, self.drop_bypass_uid_hit),
            (BpfDropReason::ExcludeCidrHit, self.drop_exclude_cidr_hit),
            (
                BpfDropReason::NotInIncludeCidr,
                self.drop_not_in_include_cidr,
            ),
            (BpfDropReason::ExcludePortHit, self.drop_exclude_port_hit),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero() {
        let state = BpfMetricsState::new();
        let snap = state.snapshot();
        assert_eq!(snap.connect, 0);
        assert_eq!(snap.ringbuf_overruns, 0);
        assert!(!snap.in_overrun_regime);
    }

    #[test]
    fn record_connect_and_accept_increment_counters() {
        let state = BpfMetricsState::new();
        state.record_connect();
        state.record_connect();
        state.record_accept_established();
        let snap = state.snapshot();
        assert_eq!(snap.connect, 2);
        assert_eq!(snap.accept_established, 1);
    }

    #[test]
    fn drop_reasons_route_to_dedicated_bins() {
        let state = BpfMetricsState::new();
        state.record_drop(BpfDropReason::BypassUidHit);
        state.record_drop(BpfDropReason::ExcludeCidrHit);
        state.record_drop(BpfDropReason::ExcludeCidrHit);
        let snap = state.snapshot();
        assert_eq!(snap.drop_bypass_uid_hit, 1);
        assert_eq!(snap.drop_exclude_cidr_hit, 2);
        assert_eq!(snap.drop_not_in_include_cidr, 0);
        assert_eq!(snap.drop_exclude_port_hit, 0);
    }

    #[test]
    fn ringbuf_overrun_fires_warn_once_per_regime_entry() {
        let state = BpfMetricsState::new();

        // First overrun → returns true (fire the warn).
        assert!(state.record_ringbuf_overrun());
        // Subsequent overruns in the same regime → returns false (no spam).
        assert!(!state.record_ringbuf_overrun());
        assert!(!state.record_ringbuf_overrun());
        assert_eq!(state.snapshot().ringbuf_overruns, 3);

        // Recovery resets the flag and returns true exactly once.
        assert!(state.mark_ringbuf_recovered());
        assert!(!state.mark_ringbuf_recovered());

        // After recovery, the next overrun fires again.
        assert!(state.record_ringbuf_overrun());
    }

    #[test]
    fn rtt_and_other_histograms_track_sum_and_count() {
        let state = BpfMetricsState::new();
        state.record_srtt_sample(100);
        state.record_srtt_sample(300);
        state.record_syn_to_ack(50);
        state.record_accept_to_first_byte(500);
        let snap = state.snapshot();
        assert_eq!(snap.srtt_sample_us_sum, 400);
        assert_eq!(snap.srtt_count, 2);
        assert_eq!(snap.syn_to_ack_us_sum, 50);
        assert_eq!(snap.syn_to_ack_count, 1);
        assert_eq!(snap.accept_to_first_byte_us_sum, 500);
        assert_eq!(snap.accept_to_first_byte_count, 1);
    }
}
