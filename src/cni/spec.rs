//! Minimal CNI specification types (stdin JSON + `CNI_*` env vars + stdout
//! JSON).
//!
//! We implement the CNI spec on the wire directly rather than vendoring a
//! library because Ferrum's CNI surface is intentionally narrow — we chain
//! behind the cluster's primary CNI (which already does IP allocation,
//! interface setup, etc.) and only need the ADD/DEL/CHECK lifecycle hook
//! so the node-agent can enroll pods into eBPF capture deterministically
//! at sandbox setup time, instead of racing the kube-rs watcher.
//!
//! Spec reference: <https://github.com/containernetworking/cni/blob/main/SPEC.md>
//! (we target v0.4.0+ which is what every modern kubelet speaks).

use std::collections::HashMap;
use std::env;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The CNI command verb supplied via the `CNI_COMMAND` environment variable.
///
/// Ferrum implements the three pod-lifecycle verbs (ADD/DEL/CHECK). The
/// spec also defines VERSION (negotiation handshake — handled inline by the
/// binary) and GC (CNI 1.1+, optional, not implemented). Unknown verbs map
/// to [`CniCommand::Unsupported`] so the binary can emit a structured
/// error result and exit with code 4 ("Try again later") per the spec's
/// error-code table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CniCommand {
    Add,
    Del,
    Check,
    Version,
    Unsupported,
}

impl CniCommand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "ADD",
            Self::Del => "DEL",
            Self::Check => "CHECK",
            Self::Version => "VERSION",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

impl FromStr for CniCommand {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_uppercase().as_str() {
            "ADD" => Self::Add,
            "DEL" => Self::Del,
            "CHECK" => Self::Check,
            "VERSION" => Self::Version,
            _ => Self::Unsupported,
        })
    }
}

/// Parsed CNI invocation environment as defined by SPEC §2.1 (Parameters).
///
/// The kubelet sets each of these per invocation; we read them all up front
/// so the rest of the CNI binary works on a normalized in-memory shape
/// instead of poking `std::env` repeatedly. `cni_args` is the raw
/// semicolon-separated form (e.g. `K8S_POD_NAMESPACE=foo;K8S_POD_NAME=bar`)
/// — see [`parse_cni_args`] for the parsed map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniInvocation {
    pub command: CniCommand,
    pub container_id: String,
    pub netns: Option<String>,
    pub ifname: Option<String>,
    pub args: Option<String>,
    pub path: Option<String>,
}

impl CniInvocation {
    /// Read the CNI invocation from `std::env`.
    ///
    /// Empty `CNI_NETNS` is normalized to `None`; the spec allows DEL to
    /// pass an empty netns when the sandbox is already gone, and treating
    /// `""` and unset identically here saves the node-agent server from
    /// having to do the same dance.
    pub fn from_env() -> Result<Self, CniError> {
        let command = env::var("CNI_COMMAND")
            .map_err(|_| CniError::missing_env("CNI_COMMAND"))?
            .parse::<CniCommand>()
            .map_err(|_| CniError::missing_env("CNI_COMMAND"))?;
        let container_id =
            env::var("CNI_CONTAINERID").map_err(|_| CniError::missing_env("CNI_CONTAINERID"))?;
        if container_id.trim().is_empty() {
            return Err(CniError::missing_env("CNI_CONTAINERID"));
        }
        let netns = env::var("CNI_NETNS")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let ifname = env::var("CNI_IFNAME")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let args = env::var("CNI_ARGS").ok().filter(|v| !v.trim().is_empty());
        let path = env::var("CNI_PATH").ok().filter(|v| !v.trim().is_empty());
        Ok(Self {
            command,
            container_id,
            netns,
            ifname,
            args,
            path,
        })
    }
}

/// Parse `CNI_ARGS` into a key/value map.
///
/// The wire format is `K=V;K=V;...`. Tokens with no `=` are skipped (the
/// spec is loose about that); empty values are kept (kubelet sometimes
/// passes `IgnoreUnknown=1;K8S_POD_NAME=`). Keys are normalized to
/// uppercase so `K8S_POD_NAMESPACE` and `k8s_pod_namespace` collapse to
/// the same entry — kubelets in the wild are inconsistent.
pub fn parse_cni_args(raw: &str) -> HashMap<String, String> {
    raw.split(';')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            let key = k.trim().to_ascii_uppercase();
            if key.is_empty() {
                return None;
            }
            Some((key, v.trim().to_string()))
        })
        .collect()
}

/// Extracted Kubernetes pod identity from CNI_ARGS.
///
/// kubelet always supplies `K8S_POD_NAMESPACE`, `K8S_POD_NAME`,
/// `K8S_POD_UID`, and `K8S_POD_INFRA_CONTAINER_ID` per CNI conventions.
/// `K8S_POD_UID` was added later than the others and is occasionally
/// missing on older CRIs; the wire surface to the node-agent treats it as
/// optional so older clusters still get a working ADD/DEL round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct K8sPodIdentity {
    pub namespace: String,
    pub name: String,
    pub pod_uid: Option<String>,
    pub infra_container_id: Option<String>,
}

impl K8sPodIdentity {
    /// Pull pod identity out of a parsed `CNI_ARGS` map. Returns `None` when
    /// the namespace+name pair is missing (we cannot enroll a pod whose
    /// identity we don't know).
    pub fn from_args(args: &HashMap<String, String>) -> Option<Self> {
        let namespace = args.get("K8S_POD_NAMESPACE")?.clone();
        let name = args.get("K8S_POD_NAME")?.clone();
        if namespace.is_empty() || name.is_empty() {
            return None;
        }
        let pod_uid = args
            .get("K8S_POD_UID")
            .cloned()
            .filter(|v| !v.is_empty());
        let infra_container_id = args
            .get("K8S_POD_INFRA_CONTAINER_ID")
            .cloned()
            .filter(|v| !v.is_empty());
        Some(Self {
            namespace,
            name,
            pod_uid,
            infra_container_id,
        })
    }
}

/// CNI network configuration JSON passed on stdin.
///
/// We accept the full shape but only inspect the fields we care about
/// (cniVersion, type, name, prevResult). `prevResult` is the chained
/// CNI's output from the previous plugin in the conflist — Ferrum
/// passes it through verbatim on ADD so the next plugin (if any) sees
/// the same shape, and so the kubelet sees the IP/interface allocation
/// the primary CNI made. We do NOT mutate prevResult.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniNetConfig {
    #[serde(rename = "cniVersion", default = "default_cni_version")]
    pub cni_version: String,
    pub name: String,
    #[serde(rename = "type")]
    pub plugin_type: String,
    #[serde(rename = "prevResult", default, skip_serializing_if = "Option::is_none")]
    pub prev_result: Option<serde_json::Value>,
    /// Optional Ferrum-specific tuning carried on the conflist entry.
    /// Defaults to `Default` when missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ferrum: Option<FerrumCniOptions>,
    /// Pass-through for any conflist fields we don't model explicitly
    /// (chained plugins may add fields kubelet round-trips). Preserving
    /// them keeps Ferrum invisible to neighbour plugins.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

fn default_cni_version() -> String {
    "0.4.0".to_string()
}

/// Plugin-specific options the operator may set on the chained conflist
/// entry. Kept narrow on purpose — the Helm chart writes a Ferrum-owned
/// conflist that the operator generally should not edit; this exists so
/// downstream operators chaining Ferrum manually can override the UDS
/// path without rebuilding the binary.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FerrumCniOptions {
    /// Override the default Unix socket path the node-agent listens on.
    /// When unset the binary falls back to
    /// [`crate::ebpf::DEFAULT_NODE_AGENT_SOCKET_PATH`]'s sibling
    /// `node-agent-cni.sock`. Operators rarely need to set this.
    #[serde(rename = "socketPath", default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
}

/// CNI result returned on stdout for ADD/CHECK.
///
/// Ferrum is a chained "meta-plugin" that does NOT allocate IPs or
/// interfaces of its own — those come from the primary CNI (Calico,
/// Cilium, etc.). On ADD we pass `prevResult` through verbatim so the
/// kubelet sees the same allocation. On a fresh (non-chained) conflist
/// where `prevResult` is absent, we emit a minimal valid `Result` with
/// just `cniVersion` — kubelet tolerates that for meta-plugins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniSuccessResult {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    #[serde(flatten)]
    pub prev_result: HashMap<String, serde_json::Value>,
}

impl CniSuccessResult {
    pub fn passthrough(cni_version: &str, prev_result: Option<&serde_json::Value>) -> Self {
        let prev_result = match prev_result {
            Some(serde_json::Value::Object(map)) => {
                map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            }
            _ => HashMap::new(),
        };
        Self {
            cni_version: cni_version.to_string(),
            prev_result,
        }
    }
}

/// CNI error JSON result, written to stdout on failure. The process also
/// exits non-zero — kubelet inspects both. See SPEC §5.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniErrorResult {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub code: u32,
    pub msg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Closed set of CNI errors the binary returns. Codes 1-99 are reserved
/// for plugin-specific errors per the spec; 1-7 are the spec-defined
/// values we map onto.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CniError {
    #[error("required environment variable {0} is missing or invalid")]
    MissingEnv(String),
    #[error("network configuration JSON is invalid: {0}")]
    BadConfig(String),
    #[error("unsupported CNI version negotiation")]
    UnsupportedVersion,
    #[error("node-agent IPC failed: {0}")]
    IpcFailed(String),
    #[error("node-agent rejected the request: {0}")]
    Rejected(String),
    #[error("unsupported CNI command")]
    UnsupportedCommand,
}

impl CniError {
    pub fn missing_env(var: &str) -> Self {
        Self::MissingEnv(var.to_string())
    }

    /// CNI spec error code per §5.2 of the reference container spec.
    pub fn code(&self) -> u32 {
        match self {
            Self::MissingEnv(_) | Self::UnsupportedCommand => 4,
            Self::BadConfig(_) => 7,
            Self::UnsupportedVersion => 1,
            Self::IpcFailed(_) => 11,
            Self::Rejected(_) => 12,
        }
    }
}

/// Build the response payload for a failure. The CNI binary writes this
/// to stdout AND exits non-zero so both contracts are satisfied.
pub fn build_error_result(cni_version: &str, err: &CniError) -> CniErrorResult {
    CniErrorResult {
        cni_version: cni_version.to_string(),
        code: err.code(),
        msg: err.to_string(),
        details: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cni_command_accepts_known_verbs() {
        assert_eq!(CniCommand::from_str("ADD"), Ok(CniCommand::Add));
        assert_eq!(CniCommand::from_str("del"), Ok(CniCommand::Del));
        assert_eq!(CniCommand::from_str("Check"), Ok(CniCommand::Check));
        assert_eq!(CniCommand::from_str("VERSION"), Ok(CniCommand::Version));
    }

    #[test]
    fn parse_cni_command_unknown_maps_to_unsupported() {
        assert_eq!(CniCommand::from_str("STATUS"), Ok(CniCommand::Unsupported));
        assert_eq!(CniCommand::from_str("GC"), Ok(CniCommand::Unsupported));
    }

    #[test]
    fn parse_cni_args_decodes_kv_pairs() {
        let args = parse_cni_args(
            "IgnoreUnknown=1;K8S_POD_NAMESPACE=demo;K8S_POD_NAME=alpha;K8S_POD_UID=abc-123",
        );
        assert_eq!(args.get("IGNOREUNKNOWN").map(String::as_str), Some("1"));
        assert_eq!(
            args.get("K8S_POD_NAMESPACE").map(String::as_str),
            Some("demo")
        );
        assert_eq!(args.get("K8S_POD_NAME").map(String::as_str), Some("alpha"));
        assert_eq!(
            args.get("K8S_POD_UID").map(String::as_str),
            Some("abc-123")
        );
    }

    #[test]
    fn parse_cni_args_ignores_malformed_tokens() {
        let args = parse_cni_args("=value;onlykey;=;K8S_POD_NAME=ok");
        assert_eq!(args.len(), 1, "only valid k=v pair should remain");
        assert_eq!(args.get("K8S_POD_NAME").map(String::as_str), Some("ok"));
    }

    #[test]
    fn k8s_identity_requires_namespace_and_name() {
        let mut args = HashMap::new();
        assert!(K8sPodIdentity::from_args(&args).is_none());
        args.insert("K8S_POD_NAMESPACE".to_string(), "demo".to_string());
        assert!(K8sPodIdentity::from_args(&args).is_none());
        args.insert("K8S_POD_NAME".to_string(), "alpha".to_string());
        let id = K8sPodIdentity::from_args(&args).expect("identity should parse");
        assert_eq!(id.namespace, "demo");
        assert_eq!(id.name, "alpha");
        assert!(id.pod_uid.is_none());
        assert!(id.infra_container_id.is_none());

        args.insert("K8S_POD_UID".to_string(), "uid-1".to_string());
        args.insert(
            "K8S_POD_INFRA_CONTAINER_ID".to_string(),
            "infra-1".to_string(),
        );
        let id = K8sPodIdentity::from_args(&args).expect("identity should parse with extras");
        assert_eq!(id.pod_uid.as_deref(), Some("uid-1"));
        assert_eq!(id.infra_container_id.as_deref(), Some("infra-1"));
    }

    #[test]
    fn k8s_identity_skips_empty_optional_fields() {
        let mut args = HashMap::new();
        args.insert("K8S_POD_NAMESPACE".to_string(), "demo".to_string());
        args.insert("K8S_POD_NAME".to_string(), "alpha".to_string());
        args.insert("K8S_POD_UID".to_string(), "".to_string());
        let id = K8sPodIdentity::from_args(&args).expect("identity should parse");
        assert!(
            id.pod_uid.is_none(),
            "empty K8S_POD_UID should normalize to None"
        );
    }

    #[test]
    fn net_config_deserializes_minimal_shape() {
        let raw = serde_json::json!({
            "cniVersion": "0.4.0",
            "name": "ferrum-mesh",
            "type": "ferrum-cni",
        });
        let cfg: CniNetConfig = serde_json::from_value(raw).expect("net config should parse");
        assert_eq!(cfg.cni_version, "0.4.0");
        assert_eq!(cfg.name, "ferrum-mesh");
        assert_eq!(cfg.plugin_type, "ferrum-cni");
        assert!(cfg.prev_result.is_none());
        assert!(cfg.ferrum.is_none());
    }

    #[test]
    fn net_config_passes_through_prev_result_and_ferrum_options() {
        let raw = serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "ferrum-mesh",
            "type": "ferrum-cni",
            "prevResult": {"interfaces": [], "ips": []},
            "ferrum": {"socketPath": "/tmp/x.sock"},
            "extra-key": "value",
        });
        let cfg: CniNetConfig = serde_json::from_value(raw).expect("net config should parse");
        assert!(cfg.prev_result.is_some());
        assert_eq!(
            cfg.ferrum.as_ref().and_then(|f| f.socket_path.as_deref()),
            Some("/tmp/x.sock")
        );
        assert!(cfg.extra.contains_key("extra-key"));
    }

    #[test]
    fn passthrough_result_inlines_prev_result_fields() {
        let prev = serde_json::json!({
            "interfaces": [{"name": "eth0"}],
            "ips": [{"address": "10.0.0.1/24"}],
        });
        let result = CniSuccessResult::passthrough("0.4.0", Some(&prev));
        assert_eq!(result.cni_version, "0.4.0");
        assert_eq!(result.prev_result.len(), 2);
        let json = serde_json::to_string(&result).expect("serializes");
        assert!(json.contains("\"interfaces\""));
        assert!(json.contains("\"ips\""));
    }

    #[test]
    fn passthrough_result_emits_minimal_shape_without_prev() {
        let result = CniSuccessResult::passthrough("0.4.0", None);
        assert_eq!(result.cni_version, "0.4.0");
        assert!(result.prev_result.is_empty());
        let json = serde_json::to_string(&result).expect("serializes");
        assert_eq!(json, r#"{"cniVersion":"0.4.0"}"#);
    }

    #[test]
    fn cni_error_codes_match_spec_buckets() {
        assert_eq!(CniError::missing_env("x").code(), 4);
        assert_eq!(CniError::UnsupportedCommand.code(), 4);
        assert_eq!(CniError::BadConfig("x".to_string()).code(), 7);
        assert_eq!(CniError::UnsupportedVersion.code(), 1);
        assert_eq!(CniError::IpcFailed("x".to_string()).code(), 11);
        assert_eq!(CniError::Rejected("x".to_string()).code(), 12);
    }

    #[test]
    fn build_error_result_includes_code_and_msg() {
        let err = CniError::IpcFailed("connect refused".to_string());
        let payload = build_error_result("0.4.0", &err);
        assert_eq!(payload.code, 11);
        assert!(payload.msg.contains("connect refused"));
    }
}
