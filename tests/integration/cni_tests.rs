//! Integration tests for the CNI plugin → node-agent UDS path.
//!
//! These tests exercise the full wire round-trip end-to-end:
//!
//!     ferrum-cni client      ──▶  UDS  ──▶      node-agent CNI server
//!     (blocking sync client)        (length-prefixed JSON)
//!
//! Instead of running the standalone `ferrum-cni` binary (which would
//! require `assert_cmd` plumbing for every test variant), we drive the
//! same `cni::client::send_rpc` API the binary uses. That keeps the
//! tests fast (no process spawn) while still proving every byte the
//! kubelet eventually sees is the byte the server emits.
//!
//! Each test:
//! 1. Builds a tokio runtime + a single oneshot worker that drains the
//!    server's `mpsc<CniWorkItem>` queue with a deterministic
//!    [`CniRpcResponse`].
//! 2. Spawns the [`spawn_cni_listener`] task on a temp UDS.
//! 3. Sends one or more synthetic CNI RPC requests via the blocking
//!    client from a spawn-blocking task (so we don't block the tokio
//!    runtime), and asserts the responses and the queued items.
//!
//! We exercise both `ferrum-cni` happy paths (ADD / DEL idempotent
//! round-trips) and one error path (server replies with `Error` →
//! `send_rpc` decodes it correctly).

use std::sync::Arc;
use std::time::Duration;

use tempfile::tempdir;
use tokio::sync::watch;

use ferrum_edge::cni::client::send_rpc;
use ferrum_edge::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
use ferrum_edge::ebpf::NodeAgentMetrics;
use ferrum_edge::modes::node_agent_cni_server::{cni_work_channel, spawn_cni_listener};

/// Build a minimal RPC request with the given verb and a stable pod
/// identity so tests don't repeat 6 fields each.
fn build_request(verb: RpcVerb) -> CniRpcRequest {
    CniRpcRequest {
        verb,
        pod_namespace: "demo".to_string(),
        pod_name: "alpha".to_string(),
        pod_uid: Some("uid-1".to_string()),
        container_id: "ctr-1".to_string(),
        netns_path: Some("/var/run/netns/cni-1".to_string()),
        args: std::collections::HashMap::new(),
    }
}

/// Drive one synthetic CNI ADD round-trip: client sends the framed
/// request, listener task accepts the connection, work item arrives in
/// the queue, a stub "main loop" replies `Ok`, response wire-encodes
/// back through the same socket.
#[tokio::test]
async fn cni_add_round_trip_returns_ok() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Stand-in "main loop": drain one work item, reply `Ok`, then exit.
    // This mirrors `process_cni_work_item` in `node_agent.rs` without
    // dragging in the full EbpfBackend.
    let drained = tokio::spawn(async move {
        let work = work_rx.recv().await.expect("work item arrives");
        assert_eq!(work.request.verb, RpcVerb::Add);
        assert_eq!(work.request.pod_namespace, "demo");
        assert_eq!(work.request.pod_name, "alpha");
        assert_eq!(work.request.pod_uid.as_deref(), Some("uid-1"));
        let _ = work.respond.send(CniRpcResponse::Ok);
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    // Give the listener a moment to bind. The binary client is
    // blocking, so we drive it on a spawn-blocking thread to keep the
    // tokio runtime free for the listener / drainer tasks.
    let resp = tokio::task::spawn_blocking(move || {
        // Tight retry loop: listener task is async; the socket file
        // appears milliseconds after `spawn_cni_listener` returns.
        let mut last_err = None;
        for _ in 0..50 {
            match send_rpc(
                &socket_path_str,
                &build_request(RpcVerb::Add),
                Duration::from_secs(2),
            ) {
                Ok(resp) => return Ok::<_, String>(resp),
                Err(err) => {
                    last_err = Some(format!("{err}"));
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "no error captured".to_string()))
    })
    .await
    .expect("blocking task joined")
    .expect("client RPC eventually succeeds");
    assert_eq!(resp, CniRpcResponse::Ok);

    drained.await.expect("drainer joined");
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

/// CNI DEL idempotency: send DEL twice; both round-trips return Ok and
/// the listener delivers two distinct work items to the queue.
#[tokio::test]
async fn cni_del_round_trip_is_idempotent() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Drain two work items, reply Ok to both — that is the contract for
    // an idempotent DEL (kubelet may retry).
    let drained = tokio::spawn(async move {
        for expected_idx in 0..2 {
            let work = work_rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("work item #{expected_idx} missing"));
            assert_eq!(work.request.verb, RpcVerb::Del);
            let _ = work.respond.send(CniRpcResponse::Ok);
        }
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    let socket_for_client = socket_path_str.clone();
    let responses = tokio::task::spawn_blocking(move || {
        let mut out = Vec::with_capacity(2);
        for _ in 0..2 {
            // Same retry approach as the ADD test — listener bind is
            // asynchronous relative to the client.
            let mut last_err = None;
            let mut sent = None;
            for _ in 0..50 {
                match send_rpc(
                    &socket_for_client,
                    &build_request(RpcVerb::Del),
                    Duration::from_secs(2),
                ) {
                    Ok(resp) => {
                        sent = Some(resp);
                        break;
                    }
                    Err(err) => {
                        last_err = Some(format!("{err}"));
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
            out.push(
                sent.ok_or_else(|| last_err.unwrap_or_else(|| "no error captured".to_string()))?,
            );
        }
        Ok::<_, String>(out)
    })
    .await
    .expect("blocking task joined")
    .expect("client RPCs succeed");
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0], CniRpcResponse::Ok);
    assert_eq!(responses[1], CniRpcResponse::Ok);

    drained.await.expect("drainer joined");
    // The CNI server records `success` outcomes for both ADD/DEL
    // verbs — this proves the metric wiring is reachable end-to-end,
    // not just unit-test stubbed.
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.cni_calls[ferrum_edge::ebpf::CniCallVerb::Del as usize]
            [ferrum_edge::ebpf::CniCallOutcome::Success as usize],
        2,
        "expected two DEL successes in metrics; got snapshot {snapshot:?}"
    );
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}

/// Error path: stub main loop replies with an `Error` variant — the
/// blocking client decodes it and surfaces it to the binary, which the
/// binary maps to CNI exit code 12.
#[tokio::test]
async fn cni_round_trip_surfaces_main_loop_error() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");
    let socket_path_str = socket_path.to_string_lossy().to_string();
    let metrics = Arc::new(NodeAgentMetrics::default());
    let (work_tx, mut work_rx) = cni_work_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let drained = tokio::spawn(async move {
        let work = work_rx.recv().await.expect("work item arrives");
        let _ = work.respond.send(CniRpcResponse::Error {
            reason: "backend exploded".to_string(),
        });
    });

    let listener = spawn_cni_listener(
        socket_path_str.clone(),
        work_tx,
        metrics.clone(),
        shutdown_rx,
    );

    let resp = tokio::task::spawn_blocking(move || {
        let mut last_err = None;
        for _ in 0..50 {
            match send_rpc(
                &socket_path_str,
                &build_request(RpcVerb::Check),
                Duration::from_secs(2),
            ) {
                Ok(resp) => return Ok::<_, String>(resp),
                Err(err) => {
                    last_err = Some(format!("{err}"));
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "no error captured".to_string()))
    })
    .await
    .expect("blocking task joined")
    .expect("client RPC eventually succeeds");
    match resp {
        CniRpcResponse::Error { reason } => assert!(
            reason.contains("backend exploded"),
            "expected pass-through error reason, got: {reason}"
        ),
        other => panic!("expected Error variant, got {other:?}"),
    }

    drained.await.expect("drainer joined");
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.cni_calls[ferrum_edge::ebpf::CniCallVerb::Check as usize]
            [ferrum_edge::ebpf::CniCallOutcome::Error as usize],
        1,
        "expected one CHECK error in metrics"
    );
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), listener).await;
}
