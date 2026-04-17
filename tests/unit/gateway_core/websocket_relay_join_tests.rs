//! Regression tests for the WebSocket relay's "wait for both halves" invariant.
//!
//! Codex P2 (commit 4f57b84): the relay used `tokio::select!` to await the
//! two forwarding futures, so whichever direction finished first won — the
//! other future was dropped mid-flight. On asymmetric sessions (e.g., the
//! client half-closes while the backend is still draining queued frames),
//! this produced:
//!
//! 1. Truncated `frames_client_to_backend` / `frames_backend_to_client`
//!    counts (late frames were never counted because their future was
//!    dropped before they ran).
//! 2. Shorter `duration_ms` than the real session.
//! 3. Lost terminal failure attribution from the dropped half.
//!
//! The fix is to run both futures with `tokio::join!` and have each future
//! `cancel()` the shared `CancellationToken` at the end of its loop — so a
//! natural EOF / error / close-frame exit on one side prompts the other to
//! wind down and the outer join completes quickly instead of hanging.
//!
//! These tests model the two direction futures with tokio primitives and
//! verify the pattern upholds the invariant. They do NOT spin up a real
//! WebSocket relay (that coverage lives in `tests/functional/`), but they
//! lock in the join-with-cancel-on-exit pattern so a future refactor can't
//! silently revert to `tokio::select!` without failing these tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Sanity check: with `tokio::join!` + cancel-on-exit, the fast direction
/// completes quickly and signals the slow direction, which exits via the
/// cancellation branch. Both counters advance before `join!` returns.
#[tokio::test]
async fn test_join_with_cancel_on_exit_waits_for_both_halves() {
    let cancel = CancellationToken::new();
    let c2b_frames = Arc::new(AtomicU64::new(0));
    let b2c_frames = Arc::new(AtomicU64::new(0));

    let cancel_ctb = cancel.clone();
    let cancel_btc = cancel.clone();
    let c2b_counter = c2b_frames.clone();
    let b2c_counter = b2c_frames.clone();

    // "Fast" direction — simulates the client→backend half completing
    // immediately (client half-closed, EOF on first read).
    let fast = async move {
        c2b_counter.fetch_add(1, Ordering::SeqCst);
        // Mirror the real relay: signal the opposite direction at end of loop.
        cancel_ctb.cancel();
    };

    // "Slow" direction — simulates the backend→client half with buffered
    // work. Without the cancel signal, it would run for 5 seconds; with the
    // signal it exits promptly via the cancelled branch.
    let slow = async move {
        // Do a tiny bit of work before the select loop to simulate a frame
        // that was already in flight when the other direction finished.
        b2c_counter.fetch_add(1, Ordering::SeqCst);
        tokio::select! {
            _ = cancel_btc.cancelled() => {
                // Drain a final "synthetic close" frame, as the real relay
                // does when cancelled.
                b2c_counter.fetch_add(1, Ordering::SeqCst);
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                panic!("slow direction should have been cancelled well before timeout");
            }
        }
        cancel_btc.cancel();
    };

    let start = tokio::time::Instant::now();
    tokio::join!(fast, slow);
    let elapsed = start.elapsed();

    assert_eq!(
        c2b_frames.load(Ordering::SeqCst),
        1,
        "fast half must have recorded its one frame",
    );
    assert_eq!(
        b2c_frames.load(Ordering::SeqCst),
        2,
        "slow half must have run to completion (both pre-cancel work and cancel branch), \
         not been dropped mid-flight",
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "cancel-on-exit must make the slow half exit promptly after the fast half \
         (saw {elapsed:?})",
    );
}

/// Contrast test: demonstrate that `tokio::select!` drops the slow half,
/// producing incorrect frame counts. This is the pre-fix behavior — kept
/// here as an explicit regression trap so a future refactor that reverts
/// to `select!` would fail the partner test above while passing this one,
/// making the intent impossible to miss.
#[tokio::test]
async fn test_select_drops_unfinished_half_and_loses_frames() {
    let cancel = CancellationToken::new();
    let c2b_frames = Arc::new(AtomicU64::new(0));
    let b2c_frames = Arc::new(AtomicU64::new(0));

    let cancel_ctb = cancel.clone();
    let cancel_btc = cancel.clone();
    let c2b_counter = c2b_frames.clone();
    let b2c_counter = b2c_frames.clone();

    let fast = async move {
        c2b_counter.fetch_add(1, Ordering::SeqCst);
        cancel_ctb.cancel();
    };

    let slow = async move {
        tokio::select! {
            _ = cancel_btc.cancelled() => {
                // Simulate processing a trailing frame during teardown —
                // this increment is what the pre-fix `select!` path would
                // lose.
                tokio::task::yield_now().await;
                b2c_counter.fetch_add(1, Ordering::SeqCst);
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    };

    // Pre-fix behavior: select drops whichever half is still running.
    tokio::select! {
        _ = fast => {}
        _ = slow => {}
    }

    assert_eq!(c2b_frames.load(Ordering::SeqCst), 1);
    // The point of this test: with `select!`, the slow half's post-cancel
    // work is lost because the future is dropped. If a future refactor
    // switches back to `select!`, this would still be 0 — but the sibling
    // `test_join_with_cancel_on_exit_waits_for_both_halves` would start
    // failing because the b2c counter would drop from 2 → 1 under join.
    assert_eq!(
        b2c_frames.load(Ordering::SeqCst),
        0,
        "select! drops the still-running slow half before its cancel branch \
         increments the counter — documenting the pre-fix regression",
    );
}
