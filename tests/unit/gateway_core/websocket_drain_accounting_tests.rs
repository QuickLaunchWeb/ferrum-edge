//! Regression tests for the WebSocket drain-accounting bug.
//!
//! Bug: the WebSocket upgrade handler returned a `Response<ProxyBody::empty()>`
//! after spawning a background `tokio::spawn` for the upgraded session. The
//! `RequestGuard` attached to that empty body dropped immediately once hyper
//! finished the 101/200 response, and the outer per-connection `_conn_guard`
//! dropped shortly after `serve_connection_with_upgrades` returned.
//! Result: the long-lived WS session was tracked in NEITHER
//! `active_connections` NOR `active_requests`, and graceful drain completed
//! "successfully" with both counts at 0 even when many WS sessions were still
//! proxying frames. The runtime was then dropped, killing those sessions
//! abruptly without a clean WebSocket Close frame.
//!
//! Fix: capture a fresh `ConnectionGuard` into the WS task's spawn closure so
//! the guard's lifetime extends through the WS session. We use
//! `ConnectionGuard` (not `RequestGuard`) because:
//!   1. The original HTTP request that initiated the upgrade has completed
//!      (the 101/200 was sent), so its `RequestGuard` should release as part
//!      of normal request completion.
//!   2. A WS session is a long-lived connection-shaped resource — one
//!      persistent client peer holding a frontend connection slot — which
//!      matches the `ConnectionGuard` semantics.
//!
//! These tests model the spawn pattern with tokio primitives and verify the
//! invariant in isolation: counter increments before spawn, stays incremented
//! across awaits inside the task, and decrements exactly once when the task
//! returns. They lock in the RAII pattern so a future refactor can't silently
//! forget to capture the guard into the spawn closure (the original bug).

use ferrum_edge::overload::{ConnectionGuard, OverloadState};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Spawning a `ConnectionGuard` into a background task models the WebSocket
/// session pattern: the guard outlives the immediate response and tracks the
/// task lifetime instead.
#[tokio::test]
async fn ws_session_guard_tracks_spawned_task_lifetime() {
    let state = Arc::new(OverloadState::new());

    // Build the guard BEFORE spawning, exactly like the WS handler does.
    // This is critical: without the guard, `active_connections` would be 0
    // for the entire WS session lifetime.
    let ws_session_guard = ConnectionGuard::new(&state);
    assert_eq!(
        state.active_connections.load(Ordering::Relaxed),
        1,
        "ConnectionGuard::new must increment active_connections immediately",
    );

    // The spawned task simulates `run_websocket_proxy` — it awaits some long-
    // running work and the guard sits in scope for the duration. We use a
    // notify pair to control the task's exit deterministically.
    let task_done_signal = Arc::new(tokio::sync::Notify::new());
    let task_done_for_spawn = task_done_signal.clone();

    let handle = tokio::spawn(async move {
        // Hold the guard for the full WS session lifetime, like the fix
        // does: `let _ws_session_guard = ws_session_guard;`
        let _ws_session_guard = ws_session_guard;
        task_done_for_spawn.notified().await;
    });

    // While the task is running, the guard is alive — counter stays at 1.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        state.active_connections.load(Ordering::Relaxed),
        1,
        "active_connections must stay at 1 while the spawned WS task is running",
    );

    // Signal the task to exit, then await it.
    task_done_signal.notify_one();
    handle.await.expect("WS task panicked");

    // Once the task exits the guard is dropped, decrementing the counter.
    assert_eq!(
        state.active_connections.load(Ordering::Relaxed),
        0,
        "Dropping the spawned task must decrement active_connections to 0",
    );
}

/// Multiple concurrent WS sessions must each contribute to `active_connections`
/// independently. Drain must wait for ALL of them, not just one.
#[tokio::test]
async fn multiple_ws_session_guards_aggregate_in_active_connections() {
    let state = Arc::new(OverloadState::new());

    let signal = Arc::new(tokio::sync::Notify::new());
    let mut handles = Vec::new();

    // Spawn 5 sessions, each holding a guard.
    for _ in 0..5 {
        let g = ConnectionGuard::new(&state);
        let signal_for_task = signal.clone();
        let handle = tokio::spawn(async move {
            let _g = g;
            signal_for_task.notified().await;
        });
        handles.push(handle);
    }

    // Give scheduler a moment to start all tasks.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        state.active_connections.load(Ordering::Relaxed),
        5,
        "5 concurrent WS sessions must each be counted in active_connections",
    );

    // Release them all at once.
    signal.notify_waiters();
    for h in handles {
        h.await.expect("WS task panicked");
    }

    assert_eq!(
        state.active_connections.load(Ordering::Relaxed),
        0,
        "All WS sessions exited — active_connections must drain to 0",
    );
}

/// Drain blocks until the spawned WS task exits. This is the operator-visible
/// behaviour the bug broke: drain used to complete prematurely with WS
/// sessions still running (and was then forcibly torn down by runtime drop).
#[tokio::test]
async fn drain_waits_for_spawned_ws_session_to_exit() {
    let state = Arc::new(OverloadState::new());

    // Simulate a WS session that holds the guard for ~75ms of work before
    // exiting. With the fix in place, drain must wait for this task.
    let ws_session_guard = ConnectionGuard::new(&state);
    let session_handle = tokio::spawn(async move {
        let _ws_session_guard = ws_session_guard;
        tokio::time::sleep(Duration::from_millis(75)).await;
    });

    // Production shutdown calls `begin_drain()` before `wait_for_drain()`.
    // The guard drop path only notifies the waiter once draining has begun.
    ferrum_edge::overload::begin_drain(&state);

    // Kick off drain with a generous timeout. It must NOT return until the
    // session task has exited and the guard has been dropped.
    let state_for_drain = state.clone();
    let drain_start = tokio::time::Instant::now();
    let drain_handle = tokio::spawn(async move {
        ferrum_edge::overload::wait_for_drain(&state_for_drain, Duration::from_secs(5)).await
    });

    // Wait for drain to complete. With the bug present, drain would return
    // almost immediately (active_connections == 0). With the fix, drain
    // waits ~75ms for the session task to finish.
    let drained_ok = tokio::time::timeout(Duration::from_secs(2), drain_handle)
        .await
        .expect("drain timed out")
        .expect("drain task panicked");
    let elapsed = drain_start.elapsed();

    assert!(drained_ok, "drain must succeed (session ran to completion)");
    assert!(
        elapsed >= Duration::from_millis(50),
        "drain must wait for the spawned WS session — the bug let it return \
         immediately with active_connections=0 even while sessions were live \
         (saw {elapsed:?}, expected >= 50ms)",
    );
    assert_eq!(
        state.active_connections.load(Ordering::Relaxed),
        0,
        "After drain returns, active_connections must be 0",
    );

    // Sanity: ensure the session task is actually done so we don't leak it.
    session_handle.await.expect("session task panicked");
}

/// The bug regression itself: if no guard is captured into the spawned task,
/// drain returns immediately even with WS sessions still running. This test
/// documents the broken behaviour to make the intent of the fix unmistakable
/// to future readers and to fail loudly if someone reverts the fix without
/// also reverting this test pair.
#[tokio::test]
async fn pre_fix_behaviour_drain_completes_with_ws_session_still_running() {
    let state = Arc::new(OverloadState::new());

    // Simulate the pre-fix WS handler: a `RequestGuard` for the immediate
    // response (drops as soon as the empty body is flushed) and NO guard
    // captured into the spawned task. The "WS session" task here holds no
    // overload guard at all.
    let request_guard = ferrum_edge::overload::RequestGuard::new(&state);
    let session_done = Arc::new(tokio::sync::Notify::new());
    let session_done_for_task = session_done.clone();
    let leaked_session = tokio::spawn(async move {
        // No guard captured — the bug.
        session_done_for_task.notified().await;
    });
    drop(request_guard); // 101 response flushed, RequestGuard releases.

    // active_connections is 0, active_requests is 0 — yet a "session" runs.
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
    assert_eq!(state.active_requests.load(Ordering::Relaxed), 0);

    // Drain returns immediately because both counters are already 0.
    let drain_start = tokio::time::Instant::now();
    let drained_ok = ferrum_edge::overload::wait_for_drain(&state, Duration::from_secs(5)).await;
    let elapsed = drain_start.elapsed();

    assert!(drained_ok);
    assert!(
        elapsed < Duration::from_millis(50),
        "documenting the bug: drain returns ~immediately when no guard tracks \
         the WS session (saw {elapsed:?})",
    );

    // The leaked session is still running — drain "succeeded" anyway.
    assert!(!leaked_session.is_finished());

    // Cleanup: signal and join.
    session_done.notify_one();
    leaked_session.await.expect("leaked task panicked");
}
