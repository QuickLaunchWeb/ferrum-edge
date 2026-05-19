//! Unix-domain-socket server that services CNI plugin RPCs against the
//! node-agent's existing enrollment state.
//!
//! Architecture:
//! - The CNI binary (`bin/ferrum-cni`) is invoked by kubelet during pod
//!   sandbox setup. It hands the call (ADD/DEL/CHECK + pod identity) to us
//!   over a Unix socket using the length-prefixed JSON wire format in
//!   [`crate::cni::rpc`].
//! - This server runs as a tokio task spawned from
//!   [`crate::modes::node_agent::run_with_backend`]. It accepts one
//!   connection per RPC (CNI is short-lived; no pooling), parses the
//!   request, and forwards a [`CniWorkItem`] to the main node-agent loop
//!   via an `mpsc` channel. The main loop is the single owner of the
//!   `EbpfBackend` and the `pod_states` `DashMap`, so we never need a
//!   `Mutex` around either.
//! - The work item carries a `oneshot::Sender<CniRpcResponse>` so the main
//!   loop can answer back. The server then writes the response on the
//!   same connection and closes it.
//!
//! Fallback semantics: when the CNI plugin is the primary enrollment path,
//! the kube-rs watcher in `node_agent.rs` still runs and reconciles any
//! pods the CNI hook missed (CNI install not rolled out yet, CNI plugin
//! chain rejected, etc.). The CNI hook is an OPTIMIZATION — it gets us
//! deterministic per-pod enrollment at sandbox-setup time, vs the watcher
//! which races kubelet to see the pod after it is already starting.
//!
//! Trust model: the UDS lives at a host-path mount that only the node-
//! agent and the `ferrum-cni` binary (running as root from the kubelet)
//! can reach. Permissions on the socket are 0660 by default; the Helm
//! chart installs both endpoints under directories the operator pre-
//! creates. We do not authenticate individual CNI calls — anyone who
//! can write the socket can already enroll pods at the cgroup level.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::cni::rpc::{
    CniRpcRequest, CniRpcResponse, LENGTH_PREFIX_BYTES, MAX_RPC_BYTES, RpcOutcome, RpcVerb,
    decode_body, encode_frame,
};
use crate::ebpf::{CniCallOutcome, CniCallVerb, NodeAgentMetrics};

/// One unit of work queued from the CNI server to the main node-agent loop.
///
/// The `respond` channel is consumed exactly once by the main loop and the
/// server task awaits it with a tight timeout — if the main loop is wedged
/// or shutting down, the CNI client sees an IPC error and kubelet retries
/// (or the kube-rs watcher reconciles when the node-agent recovers).
pub struct CniWorkItem {
    pub request: CniRpcRequest,
    pub respond: oneshot::Sender<CniRpcResponse>,
}

/// Sender half of the CNI work queue.
pub type CniWorkSender = mpsc::Sender<CniWorkItem>;
/// Receiver half consumed by the main node-agent loop.
pub type CniWorkReceiver = mpsc::Receiver<CniWorkItem>;

/// Build a bounded queue between the CNI server and the main loop.
///
/// Capacity of 64 is intentional: the main loop processes one request per
/// tokio `select!` iteration, so a deeper queue would just buffer work
/// during scheduling bursts. If the queue fills, the server returns an
/// error and kubelet retries — that is the back-pressure signal we want.
pub fn cni_work_channel() -> (CniWorkSender, CniWorkReceiver) {
    mpsc::channel(64)
}

/// Tight bound on how long the CNI server waits for the main loop to
/// answer a single RPC. Shorter than the CNI binary's own timeout so the
/// binary sees a structured error rather than the kubelet killing it.
const MAIN_LOOP_REPLY_TIMEOUT: Duration = Duration::from_secs(3);

/// Spawn the CNI Unix-socket listener.
///
/// The task takes ownership of the socket path and runs until shutdown is
/// signaled. On every accept it forwards the parsed request to the main
/// node-agent loop and pipes the answer back to the client.
///
/// Pre-existing socket file at `socket_path` is removed before bind (we
/// just restarted; an old socket file from a previous instance would
/// make bind fail). Parent directory is created with mode 0755 if
/// missing — installs that pre-create the dir do not change anything.
pub fn spawn_cni_listener(
    socket_path: String,
    work_sender: CniWorkSender,
    metrics: Arc<NodeAgentMetrics>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = prepare_socket_path(&socket_path).await {
            error!(
                socket_path = %socket_path,
                error = %err,
                "Failed to prepare node-agent CNI socket path; CNI plugin path will fall back to kube-rs watcher"
            );
            return;
        }

        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(err) => {
                error!(
                    socket_path = %socket_path,
                    error = %err,
                    "Failed to bind node-agent CNI socket; CNI plugin path will fall back to kube-rs watcher"
                );
                return;
            }
        };
        if let Err(err) = set_socket_perms(&socket_path) {
            warn!(
                socket_path = %socket_path,
                error = %err,
                "Failed to chmod node-agent CNI socket to 0660; continuing with default perms"
            );
        }
        info!(
            socket_path = %socket_path,
            "Node-agent CNI listener bound; ferrum-cni binary may now forward ADD/DEL/CHECK calls"
        );

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            let work_sender = work_sender.clone();
                            let metrics = metrics.clone();
                            tokio::spawn(async move {
                                handle_one_connection(stream, work_sender, metrics).await;
                            });
                        }
                        Err(err) => {
                            warn!(error = %err, "Node-agent CNI listener accept failed");
                        }
                    }
                }
            }
        }

        info!(
            socket_path = %socket_path,
            "Node-agent CNI listener shutting down; removing socket file"
        );
        if let Err(err) = tokio::fs::remove_file(&socket_path).await
            && err.kind() != std::io::ErrorKind::NotFound
        {
            warn!(socket_path = %socket_path, error = %err, "Failed to remove CNI socket file on shutdown");
        }
    })
}

async fn prepare_socket_path(socket_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(socket_path).parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    match tokio::fs::remove_file(socket_path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn set_socket_perms(socket_path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o660);
    std::fs::set_permissions(socket_path, perms)
}

#[cfg(not(unix))]
fn set_socket_perms(_socket_path: &str) -> std::io::Result<()> {
    Ok(())
}

/// Read one RPC, ship it to the main loop, write the response.
///
/// Connection is closed after one round-trip. Any error before we have a
/// response logs a `warn!`, increments the `error` outcome counter, and
/// returns — the client side reports the IPC error to kubelet and the
/// kube-rs watcher reconciliation path is unaffected.
async fn handle_one_connection(
    mut stream: tokio::net::UnixStream,
    work_sender: CniWorkSender,
    metrics: Arc<NodeAgentMetrics>,
) {
    let request = match read_request_frame(&mut stream).await {
        Ok(req) => req,
        Err(err) => {
            warn!(error = %err, "Failed to read CNI RPC request");
            // We cannot attribute to a specific verb because parsing failed;
            // bump the "error" outcome on each verb? Instead, log only —
            // bad framing means a misconfigured client, not a node-agent
            // signal worth alerting on.
            return;
        }
    };
    let verb = request.verb;
    let metric_verb = match verb {
        RpcVerb::Add => CniCallVerb::Add,
        RpcVerb::Del => CniCallVerb::Del,
        RpcVerb::Check => CniCallVerb::Check,
    };

    let (resp_tx, resp_rx) = oneshot::channel();
    let work = CniWorkItem {
        request,
        respond: resp_tx,
    };
    if let Err(err) = work_sender.try_send(work) {
        warn!(
            verb = ?verb,
            error = %err,
            "Failed to enqueue CNI work; main loop may be saturated or shutting down"
        );
        metrics.record_cni_call(metric_verb, CniCallOutcome::Error);
        let _ = write_response_frame(
            &mut stream,
            &CniRpcResponse::Error {
                reason: "node-agent work queue saturated; retry".to_string(),
            },
        )
        .await;
        return;
    }

    let response = match timeout(MAIN_LOOP_REPLY_TIMEOUT, resp_rx).await {
        Ok(Ok(response)) => response,
        Ok(Err(_canceled)) => {
            warn!(verb = ?verb, "Main loop dropped CNI work item without replying");
            CniRpcResponse::Error {
                reason: "node-agent did not reply".to_string(),
            }
        }
        Err(_elapsed) => {
            warn!(verb = ?verb, "Main loop did not reply to CNI work item within timeout");
            CniRpcResponse::Error {
                reason: "node-agent reply timed out".to_string(),
            }
        }
    };
    let outcome = match response.outcome() {
        RpcOutcome::Success => CniCallOutcome::Success,
        RpcOutcome::Rejected => CniCallOutcome::Rejected,
        RpcOutcome::Error => CniCallOutcome::Error,
    };
    metrics.record_cni_call(metric_verb, outcome);
    debug!(
        verb = ?verb,
        outcome = outcome.label(),
        "Served CNI RPC"
    );
    if let Err(err) = write_response_frame(&mut stream, &response).await {
        warn!(error = %err, "Failed to write CNI RPC response");
    }
}

async fn read_request_frame(stream: &mut tokio::net::UnixStream) -> Result<CniRpcRequest, String> {
    let mut len_buf = [0u8; LENGTH_PREFIX_BYTES];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("read length prefix: {e}"))?;
    let body_len = u32::from_be_bytes(len_buf) as usize;
    if body_len == 0 || body_len > MAX_RPC_BYTES {
        return Err(format!("invalid frame length {body_len}"));
    }
    let mut body = vec![0u8; body_len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| format!("read body: {e}"))?;
    decode_body(&body)
}

async fn write_response_frame(
    stream: &mut tokio::net::UnixStream,
    response: &CniRpcResponse,
) -> Result<(), String> {
    let frame = encode_frame(response).map_err(|e| format!("encode response: {e}"))?;
    stream
        .write_all(&frame)
        .await
        .map_err(|e| format!("write response: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("flush response: {e}"))?;
    Ok(())
}

/// Translate a CNI RPC request into a `PodEvent` the existing
/// [`crate::modes::node_agent::handle_pod_added`] path can consume.
///
/// The CNI plugin doesn't have rich pod metadata (no labels, no
/// annotations, no pod IP — those come from the K8s API after the
/// sandbox is created), so the event we emit is intentionally
/// minimal. Result: the CNI ADD reserves the pod's BPF state and
/// the kube-rs watcher's subsequent `Apply` reconciles in the
/// real labels/annotations/IP. This is the same pattern Istio's
/// ambient `istio-cni` uses.
pub fn pod_event_from_request<'a>(
    request: &'a CniRpcRequest,
    labels: &'a HashMap<String, String>,
    annotations: &'a HashMap<String, String>,
) -> crate::modes::node_agent::PodEvent<'a> {
    crate::modes::node_agent::PodEvent {
        pod_uid: request.pod_uid.as_deref().unwrap_or(""),
        pod_name: request.pod_name.as_str(),
        namespace: request.pod_namespace.as_str(),
        labels,
        annotations,
        pod_ip_str: None,
        pod_pid: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cni::rpc::{CniRpcRequest, RpcVerb};
    use std::collections::HashMap;

    #[test]
    fn pod_event_from_request_strips_optional_fields() {
        let request = CniRpcRequest {
            verb: RpcVerb::Add,
            pod_namespace: "demo".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: Some("uid-1".to_string()),
            container_id: "ctr-1".to_string(),
            netns_path: Some("/var/run/netns/cni-1".to_string()),
            args: HashMap::new(),
        };
        let labels = HashMap::new();
        let annotations = HashMap::new();
        let event = pod_event_from_request(&request, &labels, &annotations);
        assert_eq!(event.pod_uid, "uid-1");
        assert_eq!(event.pod_name, "alpha");
        assert_eq!(event.namespace, "demo");
        assert!(event.pod_ip_str.is_none());
        assert!(event.pod_pid.is_none());
    }

    #[test]
    fn pod_event_handles_missing_pod_uid_with_empty_string() {
        let request = CniRpcRequest {
            verb: RpcVerb::Del,
            pod_namespace: "demo".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "ctr-1".to_string(),
            netns_path: None,
            args: HashMap::new(),
        };
        let labels = HashMap::new();
        let annotations = HashMap::new();
        let event = pod_event_from_request(&request, &labels, &annotations);
        assert_eq!(
            event.pod_uid, "",
            "missing pod_uid should map to empty string so callers can short-circuit"
        );
    }

    #[tokio::test]
    async fn channel_capacity_back_pressures_on_overflow() {
        let (tx, mut rx) = cni_work_channel();
        // Fill the channel beyond capacity — `try_send` should fail with
        // `TrySendError::Full` once the bounded queue is saturated.
        let cap = 64;
        for _ in 0..cap {
            let (_resp, _) = oneshot::channel();
            let item = CniWorkItem {
                request: CniRpcRequest {
                    verb: RpcVerb::Add,
                    pod_namespace: "demo".to_string(),
                    pod_name: "alpha".to_string(),
                    pod_uid: None,
                    container_id: "c".to_string(),
                    netns_path: None,
                    args: HashMap::new(),
                },
                respond: _resp,
            };
            assert!(tx.try_send(item).is_ok(), "queue should accept up to cap");
        }
        let (resp_tx, _resp_rx) = oneshot::channel();
        let overflow = CniWorkItem {
            request: CniRpcRequest {
                verb: RpcVerb::Add,
                pod_namespace: "demo".to_string(),
                pod_name: "overflow".to_string(),
                pod_uid: None,
                container_id: "c".to_string(),
                netns_path: None,
                args: HashMap::new(),
            },
            respond: resp_tx,
        };
        assert!(
            tx.try_send(overflow).is_err(),
            "queue should reject once full"
        );
        // Drain to keep the receiver alive until end of test.
        rx.close();
    }
}
