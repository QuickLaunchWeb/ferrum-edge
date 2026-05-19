//! Node-agent RPC: the thin JSON request/response the CNI binary speaks to
//! the long-lived node-agent over a Unix domain socket.
//!
//! Why a custom shape rather than reusing the on-the-wire CNI JSON? The CNI
//! binary is intentionally cheap to spawn (kubelet may invoke it dozens of
//! times per node-boot during a fast scheduling burst). Forwarding the
//! original CNI JSON would force the node-agent to re-parse `CNI_ARGS`,
//! re-derive the K8s pod identity, and re-route on `CNI_COMMAND`. The CNI
//! binary already did all of that to decide what verb to call — passing
//! the normalized identity directly keeps the node-agent simple and tight.
//!
//! Wire format: one length-prefixed JSON object per request, one
//! length-prefixed JSON object per response. The length is a 4-byte
//! big-endian `u32` of the JSON byte count, capped at `MAX_RPC_BYTES`
//! (4 KiB; even a maxed-out pod metadata payload is <1 KiB in practice).
//! No persistent connections, no pipelining — the CNI binary opens, sends,
//! reads, closes. Cost is dominated by `fork+exec`, not by the socket.

use serde::{Deserialize, Serialize};

/// Hard cap on a single RPC message. We never expect to be near this; the
/// cap exists so a misbehaving caller cannot make the node-agent allocate
/// unbounded buffer. A real CNI ADD payload runs ~300 bytes.
pub const MAX_RPC_BYTES: usize = 4096;

/// Length-prefix size in bytes (big-endian `u32` of the JSON body length).
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// The verb the CNI binary is asking the node-agent to perform. Mirrors
/// the CNI `ADD`/`DEL`/`CHECK` lifecycle one-for-one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RpcVerb {
    Add,
    Del,
    Check,
}

impl RpcVerb {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Del => "del",
            Self::Check => "check",
        }
    }
}

/// Outcome label for `ferrum_node_agent_cni_calls_total{verb,outcome}`.
/// Closed set so the metric cardinality is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcOutcome {
    Success,
    Rejected,
    Error,
}

impl RpcOutcome {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Rejected => "rejected",
            Self::Error => "error",
        }
    }
}

/// One CNI invocation, normalized for the node-agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CniRpcRequest {
    pub verb: RpcVerb,
    pub pod_namespace: String,
    pub pod_name: String,
    /// Optional because not every CRI surfaces `K8S_POD_UID`. When absent
    /// the node-agent reconciles via the kube-rs watcher; this just
    /// means the CNI hot path may be a no-op for that pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_uid: Option<String>,
    pub container_id: String,
    /// Path to the pod network namespace. Absent on DEL when the sandbox
    /// is already gone — the node-agent treats absence as "best-effort
    /// teardown by pod identity".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netns_path: Option<String>,
    /// Pre-parsed CNI ARGS, exposed for future use (e.g., reading
    /// non-K8s_* keys). Empty by default.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub args: std::collections::HashMap<String, String>,
}

/// Node-agent response shape. We never echo back pod payload — `Ok` or
/// `Rejected` is enough for kubelet, and the CNI binary translates either
/// into a CNI spec result. `details` is optional and surfaces in CNI
/// error JSON for operator debugging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum CniRpcResponse {
    Ok,
    Rejected { reason: String },
    Error { reason: String },
}

impl CniRpcResponse {
    pub fn outcome(&self) -> RpcOutcome {
        match self {
            Self::Ok => RpcOutcome::Success,
            Self::Rejected { .. } => RpcOutcome::Rejected,
            Self::Error { .. } => RpcOutcome::Error,
        }
    }
}

/// Encode an RPC message as length-prefixed JSON ready for socket write.
///
/// Returns an error when the body exceeds [`MAX_RPC_BYTES`]; in practice
/// this is unreachable for a well-formed CNI payload but we enforce it
/// symmetrically with the read side so we never end up writing a frame
/// that the peer would reject.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(value).map_err(|e| format!("serialize rpc: {e}"))?;
    if body.len() > MAX_RPC_BYTES {
        return Err(format!(
            "rpc body {} bytes exceeds cap {MAX_RPC_BYTES}",
            body.len()
        ));
    }
    let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + body.len());
    let len = u32::try_from(body.len()).map_err(|_| "rpc body too large for u32 prefix")?;
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Parse a body byte slice as an RPC message. Length-prefix framing is
/// handled by the caller (`client.rs` and the node-agent CNI server).
pub fn decode_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, String> {
    serde_json::from_slice(body).map_err(|e| format!("decode rpc: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_verb_round_trips_through_json() {
        for verb in [RpcVerb::Add, RpcVerb::Del, RpcVerb::Check] {
            let json = serde_json::to_string(&verb).expect("serialize");
            let back: RpcVerb = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(verb, back);
        }
    }

    #[test]
    fn rpc_request_optional_fields_skip_serializing_when_none() {
        let req = CniRpcRequest {
            verb: RpcVerb::Add,
            pod_namespace: "demo".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "abc".to_string(),
            netns_path: None,
            args: std::collections::HashMap::new(),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(!json.contains("pod_uid"));
        assert!(!json.contains("netns_path"));
        assert!(!json.contains("args"));
    }

    #[test]
    fn rpc_response_tag_round_trip() {
        let ok = CniRpcResponse::Ok;
        let json = serde_json::to_string(&ok).expect("serialize");
        assert_eq!(json, r#"{"status":"ok"}"#);
        let rejected = CniRpcResponse::Rejected {
            reason: "excluded namespace".to_string(),
        };
        let json = serde_json::to_string(&rejected).expect("serialize");
        let back: CniRpcResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, rejected);
        let err = CniRpcResponse::Error {
            reason: "backend exploded".to_string(),
        };
        assert_eq!(err.outcome(), RpcOutcome::Error);
        assert_eq!(rejected.outcome(), RpcOutcome::Rejected);
        assert_eq!(ok.outcome(), RpcOutcome::Success);
    }

    #[test]
    fn encode_frame_includes_length_prefix() {
        let req = CniRpcRequest {
            verb: RpcVerb::Del,
            pod_namespace: "demo".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "abc".to_string(),
            netns_path: None,
            args: std::collections::HashMap::new(),
        };
        let frame = encode_frame(&req).expect("encode");
        assert!(frame.len() > LENGTH_PREFIX_BYTES);
        let len_bytes: [u8; 4] = frame[..LENGTH_PREFIX_BYTES]
            .try_into()
            .expect("prefix slice");
        let prefix_len = u32::from_be_bytes(len_bytes) as usize;
        assert_eq!(prefix_len + LENGTH_PREFIX_BYTES, frame.len());
        let body = &frame[LENGTH_PREFIX_BYTES..];
        let decoded: CniRpcRequest = decode_body(body).expect("decode body");
        assert_eq!(decoded, req);
    }

    #[test]
    fn encode_frame_rejects_oversized_payload() {
        let huge_value = "x".repeat(MAX_RPC_BYTES + 1);
        let req = CniRpcRequest {
            verb: RpcVerb::Add,
            pod_namespace: huge_value,
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "abc".to_string(),
            netns_path: None,
            args: std::collections::HashMap::new(),
        };
        let err = encode_frame(&req).expect_err("oversized payload should reject");
        assert!(
            err.contains("exceeds cap"),
            "expected size-cap error, got: {err}"
        );
    }

    #[test]
    fn rpc_verb_metric_labels_are_lowercase() {
        assert_eq!(RpcVerb::Add.metric_label(), "add");
        assert_eq!(RpcVerb::Del.metric_label(), "del");
        assert_eq!(RpcVerb::Check.metric_label(), "check");
    }

    #[test]
    fn rpc_outcome_metric_labels_form_closed_set() {
        assert_eq!(RpcOutcome::Success.metric_label(), "success");
        assert_eq!(RpcOutcome::Rejected.metric_label(), "rejected");
        assert_eq!(RpcOutcome::Error.metric_label(), "error");
    }
}
