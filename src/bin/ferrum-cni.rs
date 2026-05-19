//! `ferrum-cni` — minimal CNI plugin that forwards each ADD / DEL / CHECK
//! invocation to the long-lived node-agent over a Unix domain socket.
//!
//! Wire contract: kubelet invokes us per the CNI spec with stdin JSON
//! (the chained network configuration) and the `CNI_*` environment
//! variables (command verb, container id, netns path, args, plugin
//! search path). We parse those, extract the K8s pod identity from
//! `CNI_ARGS`, send a [`CniRpcRequest`] to the node-agent, and
//! translate the response back into CNI-spec JSON on stdout.
//!
//! Why this is in `src/bin/` and not its own crate:
//! - The CNI binary needs the same `cni::spec` / `cni::rpc` /
//!   `cni::client` modules as the node-agent server, so sharing the
//!   library crate avoids code duplication.
//! - Both binaries live in the same docker image. Helm's install
//!   init-container copies `ferrum-cni` out of `/usr/local/bin/`
//!   on the node-agent image into the host's `/opt/cni/bin/`.
//! - cargo's `[[bin]]` targets compile against the parent crate's
//!   `lib.rs`, so this file is intentionally tiny.
//!
//! Stub on non-Linux: CNI is a Linux concept. macOS/Windows builds
//! print an error and exit 1 so the binary target compiles in the CI
//! matrix without requiring conditional compilation in `Cargo.toml`.

#[cfg(unix)]
mod cni_main {
    use std::io::{Read, Write};
    use std::process::ExitCode;
    use std::time::Duration;

    use ferrum_edge::cni::client::{DEFAULT_RPC_TIMEOUT, send_rpc};
    use ferrum_edge::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
    use ferrum_edge::cni::spec::{
        CniCommand, CniError, CniInvocation, CniNetConfig, CniSuccessResult, K8sPodIdentity,
        build_error_result, parse_cni_args,
    };

    /// Default socket path the binary connects to when the chained CNI
    /// conflist does not override it via `ferrum.socketPath`. Must agree
    /// with the `FERRUM_NODE_AGENT_CNI_SOCKET_PATH` default in
    /// `src/config/env_config.rs`; the Helm install renders both from the
    /// same value.
    const DEFAULT_CNI_SOCKET_PATH: &str = "/var/run/ferrum/node-agent-cni.sock";

    pub fn run() -> ExitCode {
        let mut stdin_buf = String::new();
        if let Err(err) = std::io::stdin().read_to_string(&mut stdin_buf) {
            return emit_error("0.4.0", &CniError::BadConfig(format!("read stdin: {err}")));
        }
        let net_config: CniNetConfig = match serde_json::from_str(&stdin_buf) {
            Ok(cfg) => cfg,
            Err(err) => return emit_error("0.4.0", &CniError::BadConfig(err.to_string())),
        };
        let cni_version = net_config.cni_version.clone();

        let invocation = match CniInvocation::from_env() {
            Ok(inv) => inv,
            Err(err) => return emit_error(&cni_version, &err),
        };

        match invocation.command {
            CniCommand::Version => emit_version(&cni_version),
            CniCommand::Unsupported => emit_error(&cni_version, &CniError::UnsupportedCommand),
            verb @ (CniCommand::Add | CniCommand::Del | CniCommand::Check) => {
                handle_verb(verb, &net_config, &invocation)
            }
        }
    }

    fn handle_verb(
        command: CniCommand,
        net_config: &CniNetConfig,
        invocation: &CniInvocation,
    ) -> ExitCode {
        let cni_version = net_config.cni_version.clone();
        let args_map = invocation
            .args
            .as_deref()
            .map(parse_cni_args)
            .unwrap_or_default();
        let identity = match K8sPodIdentity::from_args(&args_map) {
            Some(id) => id,
            None => {
                return emit_error(
                    &cni_version,
                    &CniError::BadConfig(
                        "CNI_ARGS missing K8S_POD_NAMESPACE / K8S_POD_NAME".to_string(),
                    ),
                );
            }
        };

        let verb = match command {
            CniCommand::Add => RpcVerb::Add,
            CniCommand::Del => RpcVerb::Del,
            CniCommand::Check => RpcVerb::Check,
            _ => return emit_error(&cni_version, &CniError::UnsupportedCommand),
        };

        let socket_path = net_config
            .ferrum
            .as_ref()
            .and_then(|f| f.socket_path.clone())
            .unwrap_or_else(|| DEFAULT_CNI_SOCKET_PATH.to_string());

        let request = CniRpcRequest {
            verb,
            pod_namespace: identity.namespace,
            pod_name: identity.name,
            pod_uid: identity.pod_uid,
            container_id: invocation.container_id.clone(),
            netns_path: invocation.netns.clone(),
            args: args_map,
        };

        match send_rpc(&socket_path, &request, rpc_timeout()) {
            Ok(CniRpcResponse::Ok) => match command {
                CniCommand::Del => emit_empty_success(),
                _ => emit_success(&cni_version, net_config.prev_result.as_ref()),
            },
            Ok(CniRpcResponse::Rejected { reason }) => {
                eprintln!("ferrum-cni: node-agent rejected enrollment: {reason}");
                match command {
                    CniCommand::Del => emit_empty_success(),
                    _ => emit_success(&cni_version, net_config.prev_result.as_ref()),
                }
            }
            Ok(CniRpcResponse::Error { reason }) => {
                emit_error(&cni_version, &CniError::Rejected(reason))
            }
            Err(err) => emit_error(&cni_version, &err),
        }
    }

    fn rpc_timeout() -> Duration {
        DEFAULT_RPC_TIMEOUT
    }

    fn emit_version(cni_version: &str) -> ExitCode {
        let payload = serde_json::json!({
            "cniVersion": cni_version,
            "supportedVersions": ["0.3.0", "0.3.1", "0.4.0", "1.0.0"],
        });
        write_stdout(&payload);
        ExitCode::SUCCESS
    }

    fn emit_success(cni_version: &str, prev_result: Option<&serde_json::Value>) -> ExitCode {
        let result = CniSuccessResult::passthrough(cni_version, prev_result);
        match serde_json::to_string(&result) {
            Ok(json) => {
                let _ = std::io::stdout().write_all(json.as_bytes());
                let _ = std::io::stdout().write_all(b"\n");
            }
            Err(_err) => return ExitCode::from(1),
        }
        ExitCode::SUCCESS
    }

    fn emit_empty_success() -> ExitCode {
        ExitCode::SUCCESS
    }

    fn emit_error(cni_version: &str, err: &CniError) -> ExitCode {
        let payload = build_error_result(cni_version, err);
        match serde_json::to_string(&payload) {
            Ok(json) => {
                let _ = std::io::stdout().write_all(json.as_bytes());
                let _ = std::io::stdout().write_all(b"\n");
            }
            Err(serde_err) => {
                let _ = std::io::stderr().write_all(
                    format!("ferrum-cni: failed to serialize CNI error result: {serde_err}\n")
                        .as_bytes(),
                );
                let _ = std::io::stdout().write_all(
                    br#"{"cniVersion":"0.4.0","code":11,"msg":"internal serialization failure"}"#,
                );
                let _ = std::io::stdout().write_all(b"\n");
            }
        }
        ExitCode::from(1)
    }

    fn write_stdout(payload: &serde_json::Value) {
        if let Ok(json) = serde_json::to_string(payload) {
            let _ = std::io::stdout().write_all(json.as_bytes());
            let _ = std::io::stdout().write_all(b"\n");
        }
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    cni_main::run()
}

/// On macOS / Windows the binary still compiles so the CI matrix is uniform,
/// but invoking it as a CNI plugin makes no sense. Print a short message
/// and exit 1 — kubelet only ever runs this binary on Linux nodes.
#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "ferrum-cni: CNI plugins run on Linux only; this is a non-Unix build for matrix parity"
    );
    std::process::ExitCode::from(1)
}
