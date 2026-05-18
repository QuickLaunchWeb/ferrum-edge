//! sock_ops — TCP-layer event capture for node-waypoint observability.
//!
//! Attached once at the cgroup root by the node-agent. Hooks:
//!
//! | BPF_SOCK_OPS op            | Userspace event             |
//! |----------------------------|-----------------------------|
//! | `TCP_CONNECT_CB`           | `Connect` + connect-ts stash |
//! | `ACTIVE_ESTABLISHED_CB`    | `SynToAckLatency` (when ts present) |
//! | `PASSIVE_ESTABLISHED_CB`   | `AcceptEstablished`         |
//! | `STATE_CB` (FIN_WAIT1)     | `Fin { Sent }`              |
//! | `STATE_CB` (CLOSE_WAIT)    | `Fin { Received }`          |
//! | `STATE_CB` (* → CLOSE)     | `Rst { Received }` (heuristic — see below) |
//! | `RTT_CB`                   | `RttSample { srtt_us }`     |
//!
//! Records are written to the `FERRUM_SOCK_OPS_EVENTS` ringbuf. When the
//! ringbuf is full, `__sync_fetch_and_add` bumps
//! `FERRUM_SOCK_OPS_STATS[SOCK_OPS_STATS_EVENTS_DROPPED]` so the userspace
//! consumer can detect overrun without per-event log spam.
//!
//! ## RST attribution caveat
//!
//! `BPF_SOCK_OPS_STATE_CB` reports state transitions but does not directly
//! distinguish RST-sent vs RST-received. For the first cut we treat every
//! transition into `TCP_CLOSE` that did NOT go through the FIN_WAIT /
//! LAST_ACK / CLOSING ladder as a received RST. Refining via
//! `bpf_skc_to_tcp_sock(sk)->sk_err == ECONNRESET` is a future-work item.

use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::sock_ops;
use aya_ebpf::programs::SockOpsContext;
use aya_ebpf::EbpfContext;
use ferrum_ebpf_common::{
    SockOpsRecord, SOCK_OPS_DIRECTION_RECEIVED, SOCK_OPS_DIRECTION_SENT,
    SOCK_OPS_EVENT_ACCEPT_ESTABLISHED, SOCK_OPS_EVENT_CONNECT, SOCK_OPS_EVENT_FIN,
    SOCK_OPS_EVENT_RST, SOCK_OPS_EVENT_RTT_SAMPLE, SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY,
    SOCK_OPS_STATS_EVENTS_DROPPED,
};

use crate::maps::{FERRUM_SOCK_OPS_CONNECT_TS, FERRUM_SOCK_OPS_EVENTS, FERRUM_SOCK_OPS_STATS};

// Operation discriminants — values from `include/uapi/linux/bpf.h`
// (`bpf_sock_ops_op`). aya-ebpf does not re-export these, so we mirror them
// here. Stable since 4.13; only additive changes have happened.
const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: u32 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: u32 = 5;
const BPF_SOCK_OPS_STATE_CB: u32 = 10;
const BPF_SOCK_OPS_RTT_CB: u32 = 12;

// TCP states — values from `include/net/tcp_states.h`. Used to interpret
// `STATE_CB` arguments.
const TCP_ESTABLISHED: u32 = 1;
const TCP_FIN_WAIT1: u32 = 4;
const TCP_CLOSE: u32 = 7;
const TCP_CLOSE_WAIT: u32 = 8;

// `BPF_SOCK_OPS_STATE_CB_FLAG` and `BPF_SOCK_OPS_RTT_CB_FLAG` from
// `bpf_sock_ops_cb_flags`. We OR them into the sock-op callback flags so
// STATE_CB and RTT_CB actually fire.
const BPF_SOCK_OPS_STATE_CB_FLAG: i32 = 1 << 2;
const BPF_SOCK_OPS_RTT_CB_FLAG: i32 = 1 << 3;
const ALL_SOCK_OPS_CB_FLAGS: i32 = BPF_SOCK_OPS_STATE_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG;

#[sock_ops]
pub fn ferrum_sock_ops(ctx: SockOpsContext) -> u32 {
    handle_sock_ops(&ctx);
    // Sock-ops return value is opaque to the verifier; 1 is the standard
    // "ok, continue" value used by every example program we ship.
    1
}

#[inline(always)]
fn handle_sock_ops(ctx: &SockOpsContext) {
    let op = ctx.op();
    match op {
        BPF_SOCK_OPS_TCP_CONNECT_CB => {
            // Enable the optional callbacks so STATE_CB / RTT_CB fire for
            // this socket. set_cb_flags only mutates the per-socket flags
            // attached to *this* `tcp_sock` — no global side effect.
            let _ = ctx.set_cb_flags(ALL_SOCK_OPS_CB_FLAGS);
            stash_connect_ts(ctx);
            emit(SockOpsRecord {
                event_type: SOCK_OPS_EVENT_CONNECT,
                direction: 0,
                drop_reason: 0,
                _pad: 0,
                value: 0,
            });
        }
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => {
            let _ = ctx.set_cb_flags(ALL_SOCK_OPS_CB_FLAGS);
            if let Some(syn_to_ack_us) = drain_connect_ts(ctx) {
                emit(SockOpsRecord {
                    event_type: SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY,
                    direction: 0,
                    drop_reason: 0,
                    _pad: 0,
                    value: syn_to_ack_us,
                });
            }
        }
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            // Server side accepted the connection; enable callbacks so we
            // capture FIN/RST/RTT for inbound connections too.
            let _ = ctx.set_cb_flags(ALL_SOCK_OPS_CB_FLAGS);
            emit(SockOpsRecord {
                event_type: SOCK_OPS_EVENT_ACCEPT_ESTABLISHED,
                direction: 0,
                drop_reason: 0,
                _pad: 0,
                value: 0,
            });
        }
        BPF_SOCK_OPS_STATE_CB => {
            // args[0] = new_state, args[1] = old_state. Apply the
            // transition table.
            let new_state = ctx.arg(0);
            let old_state = ctx.arg(1);
            emit_state_transition(old_state, new_state);
        }
        BPF_SOCK_OPS_RTT_CB => {
            // args[0] = SRTT (microseconds) in modern kernels.
            // args[1] = RTT variance (unused here).
            let srtt_us = ctx.arg(0) as u64;
            if srtt_us > 0 {
                emit(SockOpsRecord {
                    event_type: SOCK_OPS_EVENT_RTT_SAMPLE,
                    direction: 0,
                    drop_reason: 0,
                    _pad: 0,
                    value: srtt_us,
                });
            }
        }
        _ => {
            // Other ops (TIMEOUT_INIT, RWND_INIT, NEEDS_ECN, …) are not
            // observability events; ignore.
        }
    }
}

#[inline(always)]
fn emit_state_transition(old_state: u32, new_state: u32) {
    match new_state {
        TCP_FIN_WAIT1 => {
            // Local close — we sent the FIN.
            emit(SockOpsRecord {
                event_type: SOCK_OPS_EVENT_FIN,
                direction: SOCK_OPS_DIRECTION_SENT,
                drop_reason: 0,
                _pad: 0,
                value: 0,
            });
        }
        TCP_CLOSE_WAIT => {
            // Peer closed first — we received the FIN.
            emit(SockOpsRecord {
                event_type: SOCK_OPS_EVENT_FIN,
                direction: SOCK_OPS_DIRECTION_RECEIVED,
                drop_reason: 0,
                _pad: 0,
                value: 0,
            });
        }
        TCP_CLOSE => {
            // ESTABLISHED → CLOSE without traversing the FIN ladder is
            // treated as an abnormal close (RST). FIN-ladder transitions
            // (FIN_WAIT1, FIN_WAIT2, CLOSING, TIME_WAIT, LAST_ACK,
            // CLOSE_WAIT) always pass through ESTABLISHED first, then go
            // to a non-ESTABLISHED state before reaching CLOSE — so the
            // ESTABLISHED check is sufficient. Without inspecting
            // `tcp_sock->sk_err`, sent-vs-received is unknown; surface
            // as Received per first-cut heuristic (refining via
            // `bpf_skc_to_tcp_sock` is future work, called out in the
            // module-level comment).
            if old_state == TCP_ESTABLISHED {
                emit(SockOpsRecord {
                    event_type: SOCK_OPS_EVENT_RST,
                    direction: SOCK_OPS_DIRECTION_RECEIVED,
                    drop_reason: 0,
                    _pad: 0,
                    value: 0,
                });
            }
        }
        _ => {}
    }
}

#[inline(always)]
fn socket_cookie(ctx: &SockOpsContext) -> u64 {
    // Safety: `bpf_get_socket_cookie` is a BPF helper that is safe to call
    // on any sock context; the verifier checks the context type. The
    // pointer comes from `EbpfContext::as_ptr`, which is the sock_ops
    // context the program runs on.
    unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) }
}

#[inline(always)]
fn stash_connect_ts(ctx: &SockOpsContext) {
    let cookie = socket_cookie(ctx);
    let now_ns = unsafe { bpf_ktime_get_ns() };
    // LRU insert is best-effort; loss is acceptable (only blanks the
    // SynToAck sample for that socket).
    let _ = FERRUM_SOCK_OPS_CONNECT_TS.insert(&cookie, &now_ns, 0);
}

#[inline(always)]
fn drain_connect_ts(ctx: &SockOpsContext) -> Option<u64> {
    let cookie = socket_cookie(ctx);
    let started_ns = unsafe { FERRUM_SOCK_OPS_CONNECT_TS.get(&cookie).copied()? };
    // Best-effort delete — if it fails the LRU will reclaim.
    let _ = FERRUM_SOCK_OPS_CONNECT_TS.remove(&cookie);
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let delta_ns = now_ns.saturating_sub(started_ns);
    // Convert ns → us. Drop measurements >1 hour to keep the histogram
    // sane in the unlikely event of clock skew or socket reuse.
    let delta_us = delta_ns / 1_000;
    if delta_us == 0 || delta_us > 3_600_000_000 {
        None
    } else {
        Some(delta_us)
    }
}

#[inline(always)]
fn emit(record: SockOpsRecord) {
    match FERRUM_SOCK_OPS_EVENTS.reserve::<SockOpsRecord>(0) {
        Some(mut entry) => {
            entry.write(record);
            entry.submit(0);
        }
        None => {
            // Ringbuf full — bump the per-CPU kernel-side dropped counter
            // so the userspace consumer can flip into the overrun regime.
            // PerCpuArray slots are CPU-local, so a non-atomic increment
            // is safe (no other CPU touches this slot until userspace
            // reads). Userspace sums across CPUs when polling.
            if let Some(slot) = FERRUM_SOCK_OPS_STATS.get_ptr_mut(SOCK_OPS_STATS_EVENTS_DROPPED) {
                // Safety: `slot` points into a per-CPU array slot the
                // verifier already proved valid for the current CPU.
                unsafe {
                    *slot = (*slot).wrapping_add(1);
                }
            }
        }
    }
}
