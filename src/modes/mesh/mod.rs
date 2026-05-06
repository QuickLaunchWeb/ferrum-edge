//! Mesh runtime mode scaffolding.
//!
//! Phase C turns `FERRUM_MODE=mesh` into a real data-plane mode. This module
//! owns the mesh-specific runtime knobs and the config-consumer boundary that
//! later listener code uses; it deliberately keeps the generic proxy/plugin
//! chain unchanged so existing plugins work in mesh context.

pub mod config_consumer;
pub mod hbone;
pub mod policy;
pub mod runtime;

use std::net::SocketAddr;

use anyhow::Context as _;
use tracing::{info, warn};

use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::config::types::{GatewayConfig, PluginConfig, PluginScope};
use crate::grpc::dp_client::{GrpcJwtSecret, build_dp_grpc_tls_config};
use crate::modes::mesh::config_consumer::native_client::NativeMeshClientConfig;
use crate::modes::mesh::config_consumer::xds_client::{XdsClientConfig, XdsConfigConsumer};
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::xds::slice::{MeshSlice, MeshSliceRequest};

const DEFAULT_INBOUND_LISTEN_ADDR: &str = "0.0.0.0:15006";
const DEFAULT_OUTBOUND_LISTEN_ADDR: &str = "127.0.0.1:15001";

pub const MESH_SPIFFE_IDENTITY_PLUGIN_ID: &str = "__mesh_spiffe_identity";
pub const MESH_AUTHZ_PLUGIN_ID: &str = "__mesh_authz";
pub const MESH_WORKLOAD_METRICS_PLUGIN_ID: &str = "__mesh_workload_metrics";
pub const MESH_ACCESS_LOG_PLUGIN_ID: &str = "__mesh_access_log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTrafficDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshListenerKind {
    PlaintextCapture,
    MtlsTermination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshListener {
    pub direction: MeshTrafficDirection,
    pub kind: MeshListenerKind,
    pub addr: SocketAddr,
}

/// Mesh data-plane topology. Phase C wires both values through the same
/// runtime path; ambient operator-visible behavior materializes later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTopology {
    Sidecar,
    Ambient,
}

impl MeshTopology {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sidecar" => Ok(Self::Sidecar),
            "ambient" => Ok(Self::Ambient),
            other => Err(format!(
                "Invalid FERRUM_MESH_TOPOLOGY '{other}'. Expected: sidecar or ambient"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Sidecar => "sidecar",
            Self::Ambient => "ambient",
        }
    }
}

/// Control-protocol source for mesh runtime config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConfigProtocol {
    Native,
    Xds,
}

impl MeshConfigProtocol {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "native" => Ok(Self::Native),
            "xds" => Ok(Self::Xds),
            other => Err(format!(
                "Invalid FERRUM_MESH_CONFIG_PROTOCOL '{other}'. Expected: native or xds"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Xds => "xds",
        }
    }
}

/// Parsed mesh runtime settings kept separate from `EnvConfig` so Phase C
/// stays strictly additive and non-mesh deployments do not carry new fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRuntimeConfig {
    pub node_id: String,
    pub namespace: String,
    pub cp_urls: Vec<String>,
    pub config_protocol: MeshConfigProtocol,
    pub topology: MeshTopology,
    pub inbound_listen_addr: SocketAddr,
    pub outbound_listen_addr: SocketAddr,
    pub workload_spiffe_id: Option<String>,
}

impl MeshRuntimeConfig {
    pub fn from_env_config(env_config: &EnvConfig) -> Result<Self, String> {
        let cp_urls = env_config.resolved_dp_cp_grpc_urls();
        if cp_urls.is_empty() {
            return Err(
                "FERRUM_DP_CP_GRPC_URL or FERRUM_DP_CP_GRPC_URLS is required in mesh mode".into(),
            );
        }

        let node_id = resolve_ferrum_var("FERRUM_MESH_NODE_ID")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "ferrum-mesh-node".to_string());
        let config_protocol = MeshConfigProtocol::parse(
            &resolve_ferrum_var("FERRUM_MESH_CONFIG_PROTOCOL")
                .unwrap_or_else(|| "native".to_string()),
        )?;
        let topology = MeshTopology::parse(
            &resolve_ferrum_var("FERRUM_MESH_TOPOLOGY").unwrap_or_else(|| "sidecar".to_string()),
        )?;
        let inbound_listen_addr = parse_socket_addr(
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_INBOUND_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_INBOUND_LISTEN_ADDR),
        )?;
        let outbound_listen_addr = parse_socket_addr(
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_OUTBOUND_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_OUTBOUND_LISTEN_ADDR),
        )?;
        let workload_spiffe_id = resolve_ferrum_var("FERRUM_MESH_WORKLOAD_SPIFFE_ID")
            .filter(|value| !value.trim().is_empty());

        Ok(Self {
            node_id,
            namespace: env_config.namespace.clone(),
            cp_urls,
            config_protocol,
            topology,
            inbound_listen_addr,
            outbound_listen_addr,
            workload_spiffe_id,
        })
    }

    fn native_client_config(&self) -> NativeMeshClientConfig {
        NativeMeshClientConfig {
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            labels: Default::default(),
        }
    }

    fn xds_client_config(&self) -> XdsClientConfig {
        XdsClientConfig {
            cp_url: self.cp_urls[0].clone(),
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
        }
    }

    pub fn listener_plan(&self) -> Vec<MeshListener> {
        vec![
            MeshListener {
                direction: MeshTrafficDirection::Outbound,
                kind: MeshListenerKind::PlaintextCapture,
                addr: self.outbound_listen_addr,
            },
            MeshListener {
                direction: MeshTrafficDirection::Inbound,
                kind: match self.topology {
                    MeshTopology::Sidecar => MeshListenerKind::MtlsTermination,
                    MeshTopology::Ambient => MeshListenerKind::PlaintextCapture,
                },
                addr: self.inbound_listen_addr,
            },
        ]
    }

    pub fn mesh_slice_request(&self) -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            labels: Default::default(),
        }
    }
}

/// Prepare a gateway snapshot for mesh-mode serving.
///
/// Mesh mode is the only caller. The mutation is cold-path: it runs before
/// `ProxyState` builds router/plugin caches, so non-mesh modes and ordinary
/// requests never pay for mesh plugin injection.
pub fn prepare_gateway_config_for_mesh(
    mut config: GatewayConfig,
    runtime: &MeshRuntimeConfig,
) -> Result<GatewayConfig, anyhow::Error> {
    config.normalize_fields();
    let mesh_errors = config.validate_mesh_fields();
    if !mesh_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "Mesh configuration validation failed: {}",
            mesh_errors.join("; ")
        ));
    }

    let mesh_slice = MeshSlice::from_gateway_config(&config, runtime.mesh_slice_request());
    inject_mesh_global_plugins(&mut config, runtime, &mesh_slice);
    Ok(config)
}

fn inject_mesh_global_plugins(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    ensure_global_plugin(
        config,
        MESH_SPIFFE_IDENTITY_PLUGIN_ID,
        "spiffe_identity",
        serde_json::json!({}),
        &runtime.namespace,
    );
    ensure_global_plugin(
        config,
        MESH_AUTHZ_PLUGIN_ID,
        "mesh_authz",
        serde_json::json!({ "mesh_slice": mesh_slice }),
        &runtime.namespace,
    );
    ensure_global_plugin(
        config,
        MESH_WORKLOAD_METRICS_PLUGIN_ID,
        "workload_metrics",
        serde_json::json!({
            "node_id": runtime.node_id.clone(),
            "topology": runtime.topology.as_str(),
            "namespace": mesh_slice.namespace.clone(),
            "workload_spiffe_id": mesh_slice.workload_spiffe_id.clone(),
            "labels": mesh_slice.labels.clone(),
        }),
        &runtime.namespace,
    );
    ensure_global_plugin(
        config,
        MESH_ACCESS_LOG_PLUGIN_ID,
        "access_log",
        serde_json::json!({}),
        &runtime.namespace,
    );
}

fn ensure_global_plugin(
    config: &mut GatewayConfig,
    id: &str,
    plugin_name: &str,
    plugin_config: serde_json::Value,
    namespace: &str,
) {
    if config.plugin_configs.iter().any(|plugin| {
        plugin.enabled && plugin.scope == PluginScope::Global && plugin.plugin_name == plugin_name
    }) {
        return;
    }

    let now = chrono::Utc::now();
    let mesh_plugin = PluginConfig {
        id: id.to_string(),
        plugin_name: plugin_name.to_string(),
        namespace: namespace.to_string(),
        config: plugin_config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        created_at: now,
        updated_at: now,
    };

    if let Some(existing) = config
        .plugin_configs
        .iter_mut()
        .find(|plugin| plugin.id == id)
    {
        *existing = mesh_plugin;
    } else {
        config.plugin_configs.push(mesh_plugin);
    }
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let runtime = MeshRuntimeConfig::from_env_config(&env_config)
        .map_err(|e| anyhow::anyhow!(e))
        .context("invalid mesh runtime configuration")?;

    info!(
        node_id = %runtime.node_id,
        namespace = %runtime.namespace,
        topology = runtime.topology.as_str(),
        config_protocol = runtime.config_protocol.as_str(),
        inbound = %runtime.inbound_listen_addr,
        outbound = %runtime.outbound_listen_addr,
        cp_urls = runtime.cp_urls.len(),
        "Mesh mode starting"
    );

    let mesh_state = MeshRuntimeState::new();
    let bootstrap_config = prepare_gateway_config_for_mesh(GatewayConfig::default(), &runtime)
        .context("failed to prepare mesh plugin bootstrap config")?;
    info!(
        mesh_global_plugins = bootstrap_config.plugin_configs.len(),
        "Mesh global plugin chain prepared"
    );

    let jwt_secret = GrpcJwtSecret::with_issuer(
        env_config.cp_dp_grpc_jwt_secret.clone().ok_or_else(|| {
            anyhow::anyhow!("FERRUM_CP_DP_GRPC_JWT_SECRET is required in mesh mode")
        })?,
        env_config.cp_dp_grpc_jwt_issuer.clone(),
    );
    let grpc_tls = build_dp_grpc_tls_config(&env_config, &runtime.cp_urls, "Mesh")?;
    let mut background_handles = Vec::new();

    match runtime.config_protocol {
        MeshConfigProtocol::Native => {
            let client_config = runtime.native_client_config();
            let request = client_config.subscribe_request(crate::FERRUM_VERSION);
            let cp_urls = runtime.cp_urls.clone();
            let state = mesh_state.clone();
            let shutdown_rx = shutdown_tx.subscribe();
            let handle = tokio::spawn(
                config_consumer::native_client::start_native_mesh_client_with_shutdown(
                    cp_urls,
                    jwt_secret.clone(),
                    client_config,
                    state,
                    shutdown_rx,
                    grpc_tls.clone(),
                ),
            );
            background_handles.push(handle);
            info!(
                node_id = %request.node_id,
                namespace = %request.namespace,
                cp_urls = runtime.cp_urls.len(),
                has_first_slice = mesh_state.has_first_slice(),
                "Mesh mode initialized native MeshSubscribe consumer"
            );
        }
        MeshConfigProtocol::Xds => {
            let consumer = XdsConfigConsumer::new(runtime.xds_client_config(), mesh_state.clone());
            info!(
                node_id = %consumer.config().node_id,
                namespace = %consumer.config().namespace,
                cp_url = %consumer.config().cp_url,
                has_first_slice = consumer.state().has_first_slice(),
                "Mesh mode initialized xDS config consumer"
            );
        }
    }

    let listener_plan = runtime.listener_plan();
    info!(
        listeners = listener_plan.len(),
        "Mesh listener plan prepared; accept loops attach in the serving slice"
    );

    let mut shutdown_rx = shutdown_tx.subscribe();
    if *shutdown_rx.borrow() {
        return Ok(());
    }
    let _ = shutdown_rx.changed().await;
    for handle in background_handles {
        if let Err(e) = handle.await {
            warn!("Mesh background task exited with join error: {}", e);
        }
    }
    Ok(())
}

fn parse_socket_addr(key: &str, raw: &str) -> Result<SocketAddr, String> {
    raw.parse::<SocketAddr>()
        .map_err(|e| format!("{key} must be a socket address (got '{raw}'): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EnvConfig;
    use crate::config::mesh::{
        AppProtocol, MeshConfig, MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch,
        Workload, WorkloadPort, WorkloadSelector,
    };
    use crate::config::types::PluginScope;
    use crate::identity::{SpiffeId, TrustDomain};
    use std::collections::HashMap;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_mesh_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let keys = [
            "FERRUM_MODE",
            "FERRUM_NAMESPACE",
            "FERRUM_DP_CP_GRPC_URL",
            "FERRUM_DP_CP_GRPC_URLS",
            "FERRUM_CP_DP_GRPC_JWT_SECRET",
            "FERRUM_MESH_NODE_ID",
            "FERRUM_MESH_CONFIG_PROTOCOL",
            "FERRUM_MESH_TOPOLOGY",
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
        ];

        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
        for (key, value) in vars {
            unsafe { std::env::set_var(key, value) };
        }

        f();

        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn mesh_runtime_config_defaults_to_sidecar_native_ports() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.node_id, "node-a");
                assert_eq!(runtime.namespace, "ferrum");
                assert_eq!(runtime.cp_urls, vec!["http://cp:50051"]);
                assert_eq!(runtime.config_protocol, MeshConfigProtocol::Native);
                assert_eq!(runtime.topology, MeshTopology::Sidecar);
                assert_eq!(
                    runtime.inbound_listen_addr,
                    DEFAULT_INBOUND_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.outbound_listen_addr,
                    DEFAULT_OUTBOUND_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_xds_ambient_overrides() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                (
                    "FERRUM_DP_CP_GRPC_URLS",
                    "https://cp1:50051,https://cp2:50051",
                ),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-b"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "xds"),
                ("FERRUM_MESH_TOPOLOGY", "ambient"),
                ("FERRUM_MESH_INBOUND_LISTEN_ADDR", "127.0.0.1:16006"),
                ("FERRUM_MESH_OUTBOUND_LISTEN_ADDR", "127.0.0.1:16001"),
                (
                    "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                    "spiffe://cluster.local/ns/default/sa/api",
                ),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.config_protocol, MeshConfigProtocol::Xds);
                assert_eq!(runtime.topology, MeshTopology::Ambient);
                assert_eq!(runtime.cp_urls.len(), 2);
                assert_eq!(
                    runtime.workload_spiffe_id.as_deref(),
                    Some("spiffe://cluster.local/ns/default/sa/api")
                );
                assert_eq!(
                    runtime.inbound_listen_addr,
                    "127.0.0.1:16006".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.outbound_listen_addr,
                    "127.0.0.1:16001".parse::<SocketAddr>().unwrap()
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_bad_topology() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "east-west"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_TOPOLOGY"));
            },
        );
    }

    fn workload(name: &str, app: &str) -> Workload {
        let trust_domain = TrustDomain::new("cluster.local").unwrap();
        Workload {
            spiffe_id: SpiffeId::new(format!("spiffe://cluster.local/ns/default/sa/{name}"))
                .unwrap(),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), app.to_string())]),
                namespace: Some("default".to_string()),
            },
            service_name: name.to_string(),
            ports: vec![WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain,
            namespace: "default".to_string(),
        }
    }

    #[test]
    fn mesh_runtime_listener_plan_uses_sidecar_ports() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let plan = runtime.listener_plan();

                assert_eq!(plan.len(), 2);
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Outbound
                        && listener.kind == MeshListenerKind::PlaintextCapture
                        && listener.addr.port() == 15001
                }));
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Inbound
                        && listener.kind == MeshListenerKind::MtlsTermination
                        && listener.addr.port() == 15006
                }));
            },
        );
    }

    #[test]
    fn mesh_runtime_prepares_global_mesh_plugins_from_slice() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
                (
                    "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                    "spiffe://cluster.local/ns/default/sa/api",
                ),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let api_policy = MeshPolicy {
                    name: "api-only".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    rules: vec![MeshRule {
                        from: vec![PrincipalMatch {
                            spiffe_id_pattern: Some(
                                "spiffe://cluster.local/ns/default/sa/client".to_string(),
                            ),
                            namespace_pattern: None,
                            trust_domain: None,
                        }],
                        to: Vec::new(),
                        when: Vec::new(),
                        action: PolicyAction::Allow,
                    }],
                };
                let worker_policy = MeshPolicy {
                    name: "worker-only".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "worker".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    rules: Vec::new(),
                };
                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        workloads: vec![workload("api", "api"), workload("worker", "worker")],
                        mesh_policies: vec![api_policy, worker_policy],
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let by_id = |id: &str| {
                    prepared
                        .plugin_configs
                        .iter()
                        .find(|plugin| plugin.id == id)
                        .expect("mesh plugin injected")
                };

                assert_eq!(
                    by_id(MESH_SPIFFE_IDENTITY_PLUGIN_ID).plugin_name,
                    "spiffe_identity"
                );
                assert_eq!(by_id(MESH_AUTHZ_PLUGIN_ID).plugin_name, "mesh_authz");
                assert_eq!(
                    by_id(MESH_WORKLOAD_METRICS_PLUGIN_ID).plugin_name,
                    "workload_metrics"
                );
                assert_eq!(by_id(MESH_ACCESS_LOG_PLUGIN_ID).plugin_name, "access_log");
                assert!(
                    prepared
                        .plugin_configs
                        .iter()
                        .all(|plugin| plugin.scope == PluginScope::Global)
                );

                let mesh_slice = by_id(MESH_AUTHZ_PLUGIN_ID)
                    .config
                    .get("mesh_slice")
                    .expect("mesh_authz mesh_slice");
                let policies = mesh_slice
                    .get("mesh_policies")
                    .and_then(|policies| policies.as_array())
                    .expect("mesh policies array");
                assert_eq!(policies.len(), 1);
                assert_eq!(
                    policies[0].get("name").and_then(|name| name.as_str()),
                    Some("api-only")
                );
                assert_eq!(
                    mesh_slice
                        .pointer("/labels/app")
                        .and_then(|label| label.as_str()),
                    Some("api")
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_preserves_operator_global_mesh_plugin_override() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let existing = PluginConfig {
                    id: "operator-mesh-authz".to_string(),
                    plugin_name: "mesh_authz".to_string(),
                    namespace: "ferrum".to_string(),
                    config: serde_json::json!({ "mesh_slice": MeshSlice::default() }),
                    scope: PluginScope::Global,
                    proxy_id: None,
                    enabled: true,
                    priority_override: Some(2005),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                let config = GatewayConfig {
                    plugin_configs: vec![existing],
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let mesh_authz: Vec<_> = prepared
                    .plugin_configs
                    .iter()
                    .filter(|plugin| plugin.plugin_name == "mesh_authz")
                    .collect();

                assert_eq!(mesh_authz.len(), 1);
                assert_eq!(mesh_authz[0].id, "operator-mesh-authz");
                assert!(prepared.plugin_configs.iter().any(|plugin| {
                    plugin.id == MESH_SPIFFE_IDENTITY_PLUGIN_ID
                        && plugin.plugin_name == "spiffe_identity"
                }));
            },
        );
    }
}
