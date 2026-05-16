//! Userspace consumer for the SOCK_OPS ringbuf.
//!
//! The kernel-side `BPF_PROG_TYPE_SOCK_OPS` program emits one record per
//! TCP-layer event (Connect, AcceptEstablished, RstSent/Received,
//! FinSent/Received, RttSample) plus a record per BPF drop-reason hit.
//! Userspace polls the per-CPU ringbuf, decodes the records, and updates
//! the shared [`BpfMetricsState`].
//!
//! ## Scaffolding state (GAP-SC3 first sub-PR)
//!
//! This module currently ships the **dispatch surface only**: the trait
//! that maps decoded event records into counter updates, the threshold
//! state machine for ringbuf-overrun logging, and a test-friendly
//! [`SockOpsConsumer`] that drives the dispatch from in-memory events.
//! The kernel-side BPF program and the `aya::maps::RingBuf::poll_async`
//! integration land in a follow-up PR — keeping the scaffolding here
//! lets the `__mesh_bpf_metrics` plugin, its tests, and the
//! auto-injection logic all build and exercise the contract today.
//!
//! When the BPF program lands, the production consumer task will:
//!   1. Open the pinned `FERRUM_SOCK_OPS_EVENTS` ringbuf via aya.
//!   2. For each CPU, spawn a tokio task that calls
//!      [`SockOpsEvent::decode`] on the raw record bytes and feeds the
//!      result through [`SockOpsConsumer::handle_event`].
//!   3. On a `RingBuf::poll_async` error indicating overrun (the kernel
//!      drops events when the userspace consumer can't keep up),
//!      [`SockOpsConsumer::record_overrun`] handles the warn/recover
//!      state machine so the log line never spams.

#![allow(dead_code)]

use std::sync::Arc;

use tracing::{info, warn};

use crate::ebpf::bpf_metrics::{BpfDropReason, BpfMetricsState, TcpDirection};

/// One decoded SOCK_OPS event.
///
/// This enum is intentionally minimal — the kernel program emits records
/// keyed by `event_type` plus a small payload. The userspace decoder maps
/// those records into this shape so the counter logic stays decoupled
/// from the BPF wire format. When the wire format evolves, only
/// `SockOpsEvent::decode` (separate module, lands with the BPF program)
/// has to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockOpsEvent {
    Connect,
    AcceptEstablished,
    Rst { direction: TcpDirection },
    Fin { direction: TcpDirection },
    RttSample { srtt_us: u64 },
    SynToAckLatency { us: u64 },
    AcceptToFirstByteLatency { us: u64 },
    DropReason(BpfDropReason),
}

/// Decoded ringbuf consumption outcome reported by a single poll cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// Polled events that fit in the ringbuf and got handed to the
    /// dispatch table.
    Drained { events: u32 },
    /// Kernel side reported overrun (ringbuf full before userspace could
    /// drain) — operator-visible regression.
    Overrun,
}

/// Userspace SOCK_OPS event consumer.
///
/// Wraps the shared [`BpfMetricsState`] with the dispatch logic that
/// routes decoded events into counter increments and manages the
/// ringbuf-overrun state machine. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct SockOpsConsumer {
    metrics: Arc<BpfMetricsState>,
}

impl SockOpsConsumer {
    pub fn new(metrics: Arc<BpfMetricsState>) -> Self {
        Self { metrics }
    }

    pub fn metrics(&self) -> Arc<BpfMetricsState> {
        self.metrics.clone()
    }

    /// Apply a decoded event to the metrics state. Called once per
    /// successfully-decoded ringbuf record.
    pub fn handle_event(&self, event: SockOpsEvent) {
        self.metrics.record_ringbuf_event();
        match event {
            SockOpsEvent::Connect => self.metrics.record_connect(),
            SockOpsEvent::AcceptEstablished => self.metrics.record_accept_established(),
            SockOpsEvent::Rst { direction } => self.metrics.record_rst(direction),
            SockOpsEvent::Fin { direction } => self.metrics.record_fin(direction),
            SockOpsEvent::RttSample { srtt_us } => self.metrics.record_srtt_sample(srtt_us),
            SockOpsEvent::SynToAckLatency { us } => self.metrics.record_syn_to_ack(us),
            SockOpsEvent::AcceptToFirstByteLatency { us } => {
                self.metrics.record_accept_to_first_byte(us)
            }
            SockOpsEvent::DropReason(reason) => self.metrics.record_drop(reason),
        }
    }

    /// Drive the warn-on-enter / info-on-recover state machine after
    /// observing a ringbuf overrun. Suppresses per-event log spam.
    pub fn record_overrun(&self) {
        if self.metrics.record_ringbuf_overrun() {
            warn!(
                target: "ferrum::ebpf::sock_ops",
                "BPF sock_ops ringbuf overrun: userspace consumer fell behind. \
                 Some TCP-layer events were dropped on the kernel side. \
                 Increase FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES or reduce event rate."
            );
        }
    }

    /// Indicate that the consumer caught up and successive `record_overrun`
    /// calls would fire a fresh warn. The caller decides when "caught up"
    /// means — typically: N consecutive poll cycles with `Drained { .. }`
    /// outcomes after the last overrun. Once the recovery threshold is
    /// met, call this once to flip the state and emit a single info line.
    pub fn record_recovery(&self) {
        if self.metrics.mark_ringbuf_recovered() {
            info!(
                target: "ferrum::ebpf::sock_ops",
                "BPF sock_ops ringbuf recovered from overrun regime"
            );
        }
    }

    /// Apply a polled outcome to the state machine. Convenience wrapper
    /// around `record_overrun` / `record_recovery` with a configurable
    /// recovery threshold: once `recovery_threshold` consecutive
    /// `Drained` outcomes are observed after an overrun, the regime is
    /// considered recovered. Returns the regime state *after* this call.
    pub fn observe_poll(
        &self,
        outcome: PollOutcome,
        consecutive_drained: &mut u32,
        recovery_threshold: u32,
    ) -> bool {
        match outcome {
            PollOutcome::Drained { events: _ } => {
                if self.metrics.is_in_overrun_regime() {
                    *consecutive_drained = consecutive_drained.saturating_add(1);
                    if *consecutive_drained >= recovery_threshold {
                        self.record_recovery();
                        *consecutive_drained = 0;
                    }
                }
            }
            PollOutcome::Overrun => {
                *consecutive_drained = 0;
                self.record_overrun();
            }
        }
        self.metrics.is_in_overrun_regime()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(consumer: &SockOpsConsumer) -> crate::ebpf::bpf_metrics::BpfMetricsSnapshot {
        consumer.metrics().snapshot()
    }

    #[test]
    fn handle_event_routes_each_variant_to_its_counter() {
        let consumer = SockOpsConsumer::new(BpfMetricsState::new());
        consumer.handle_event(SockOpsEvent::Connect);
        consumer.handle_event(SockOpsEvent::AcceptEstablished);
        consumer.handle_event(SockOpsEvent::AcceptEstablished);
        consumer.handle_event(SockOpsEvent::Rst {
            direction: TcpDirection::Sent,
        });
        consumer.handle_event(SockOpsEvent::Rst {
            direction: TcpDirection::Received,
        });
        consumer.handle_event(SockOpsEvent::Fin {
            direction: TcpDirection::Received,
        });
        consumer.handle_event(SockOpsEvent::RttSample { srtt_us: 250 });
        consumer.handle_event(SockOpsEvent::SynToAckLatency { us: 60 });
        consumer.handle_event(SockOpsEvent::AcceptToFirstByteLatency { us: 800 });
        consumer.handle_event(SockOpsEvent::DropReason(BpfDropReason::BypassUidHit));

        let s = snap(&consumer);
        assert_eq!(s.connect, 1);
        assert_eq!(s.accept_established, 2);
        assert_eq!(s.rst_sent, 1);
        assert_eq!(s.rst_received, 1);
        assert_eq!(s.fin_sent, 0);
        assert_eq!(s.fin_received, 1);
        assert_eq!(s.srtt_sample_us_sum, 250);
        assert_eq!(s.srtt_count, 1);
        assert_eq!(s.syn_to_ack_us_sum, 60);
        assert_eq!(s.accept_to_first_byte_us_sum, 800);
        assert_eq!(s.drop_bypass_uid_hit, 1);
        // Every handled event also bumps the consumed-events counter.
        assert_eq!(s.ringbuf_events_consumed, 10);
    }

    #[test]
    fn observe_poll_state_machine_warns_once_per_regime() {
        let consumer = SockOpsConsumer::new(BpfMetricsState::new());
        let mut consecutive = 0u32;
        // Initial drained: nothing happens (we weren't in overrun yet).
        let in_regime =
            consumer.observe_poll(PollOutcome::Drained { events: 5 }, &mut consecutive, 3);
        assert!(!in_regime);

        // Overrun: flips into overrun regime.
        let in_regime = consumer.observe_poll(PollOutcome::Overrun, &mut consecutive, 3);
        assert!(in_regime);
        assert_eq!(consecutive, 0);
        assert_eq!(snap(&consumer).ringbuf_overruns, 1);

        // 2 drained polls — not yet at the recovery threshold of 3.
        consumer.observe_poll(PollOutcome::Drained { events: 1 }, &mut consecutive, 3);
        let in_regime =
            consumer.observe_poll(PollOutcome::Drained { events: 2 }, &mut consecutive, 3);
        assert!(in_regime);
        assert_eq!(consecutive, 2);

        // 3rd consecutive drained — recovery threshold met, regime clears.
        let in_regime =
            consumer.observe_poll(PollOutcome::Drained { events: 1 }, &mut consecutive, 3);
        assert!(!in_regime);
        assert_eq!(consecutive, 0);

        // Subsequent overrun re-enters the regime (fresh warn would fire).
        let in_regime = consumer.observe_poll(PollOutcome::Overrun, &mut consecutive, 3);
        assert!(in_regime);
        assert_eq!(snap(&consumer).ringbuf_overruns, 2);
    }
}
