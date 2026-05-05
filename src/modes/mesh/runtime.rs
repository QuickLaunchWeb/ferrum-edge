//! Mesh runtime planning.
//!
//! The listener plan is a cold-start artifact for `FERRUM_MODE=mesh`. It keeps
//! topology decisions out of the proxy hot path and gives Phase C a small,
//! testable boundary before the capture/HBONE accept loops grow more capable.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::config::types::{GatewayConfig, PluginConfig, PluginScope};
use crate::config::{EnvConfig, MeshConfigSource, MeshTopology};

use super::config_consumer::native_client::NativeMeshClientConfig;
use super::config_consumer::xds_client::XdsClientConfig;

pub const MESH_SPIFFE_IDENTITY_PLUGIN_ID: &str = "__mesh_spiffe_identity";
pub const MESH_AUTHZ_PLUGIN_ID: &str = "__mesh_authz";
pub const MESH_WORKLOAD_METRICS_PLUGIN_ID: &str = "__mesh_workload_metrics";
pub const MESH_ACCESS_LOG_PLUGIN_ID: &str = "__mesh_access_log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTrafficDirection {
    Inbound,
    Outbound,
    Hbone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshListenerKind {
    PlaintextCapture,
    MtlsTermination,
    HboneTunnel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshListener {
    pub direction: MeshTrafficDirection,
    pub kind: MeshListenerKind,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRuntimeConfig {
    pub topology: MeshTopology,
    pub config_source: MeshConfigSource,
    pub node_id: String,
    pub namespace: String,
    pub workload_spiffe_id: Option<String>,
    pub labels: HashMap<String, String>,
    pub inbound_addr: SocketAddr,
    pub outbound_addr: SocketAddr,
    pub hbone_addr: Option<SocketAddr>,
}

impl MeshRuntimeConfig {
    pub fn from_env(env: &EnvConfig) -> Self {
        Self {
            topology: env.mesh_topology,
            config_source: env.mesh_config_source,
            node_id: env.mesh_node_id.clone(),
            namespace: env.namespace.clone(),
            workload_spiffe_id: env.mesh_workload_spiffe_id.clone(),
            labels: env.mesh_labels.clone(),
            inbound_addr: env.mesh_socket_addr(env.mesh_inbound_port),
            outbound_addr: env.mesh_socket_addr(env.mesh_outbound_port),
            hbone_addr: env
                .mesh_hbone_enabled
                .then(|| env.mesh_socket_addr(env.mesh_hbone_port)),
        }
    }

    pub fn listener_plan(&self) -> Vec<MeshListener> {
        let mut listeners = Vec::with_capacity(3);
        listeners.push(MeshListener {
            direction: MeshTrafficDirection::Outbound,
            kind: MeshListenerKind::PlaintextCapture,
            addr: self.outbound_addr,
        });
        listeners.push(MeshListener {
            direction: MeshTrafficDirection::Inbound,
            kind: match self.topology {
                MeshTopology::Sidecar => MeshListenerKind::MtlsTermination,
                MeshTopology::Ambient => MeshListenerKind::PlaintextCapture,
            },
            addr: self.inbound_addr,
        });
        if let Some(addr) = self.hbone_addr {
            listeners.push(MeshListener {
                direction: MeshTrafficDirection::Hbone,
                kind: MeshListenerKind::HboneTunnel,
                addr,
            });
        }
        listeners
    }

    pub fn native_client_config(&self, cp_url: String) -> NativeMeshClientConfig {
        NativeMeshClientConfig {
            cp_url,
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            labels: self.labels.clone(),
        }
    }

    pub fn xds_client_config(&self, cp_url: String) -> XdsClientConfig {
        XdsClientConfig {
            cp_url,
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
        }
    }
}

/// Prepare a gateway snapshot for mesh-mode serving.
///
/// Mesh mode is the only caller. The mutation is intentionally cold-path:
/// it happens once before [`crate::proxy::ProxyState`] builds the router and
/// plugin caches, so ordinary gateway modes and non-mesh requests pay no cost.
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

    inject_mesh_global_plugins(&mut config, runtime);
    Ok(config)
}

fn inject_mesh_global_plugins(config: &mut GatewayConfig, runtime: &MeshRuntimeConfig) {
    ensure_global_plugin(
        config,
        MESH_SPIFFE_IDENTITY_PLUGIN_ID,
        "spiffe_identity",
        serde_json::json!({}),
        &runtime.namespace,
    );

    let policies = config
        .mesh
        .as_ref()
        .map(|mesh| mesh.mesh_policies.clone())
        .unwrap_or_default();
    let peer_authentications = config
        .mesh
        .as_ref()
        .map(|mesh| mesh.peer_authentications.clone())
        .unwrap_or_default();
    ensure_global_plugin(
        config,
        MESH_AUTHZ_PLUGIN_ID,
        "mesh_authz",
        serde_json::json!({
            "policies": policies,
            "peer_authentications": peer_authentications,
        }),
        &runtime.namespace,
    );

    ensure_global_plugin(
        config,
        MESH_WORKLOAD_METRICS_PLUGIN_ID,
        "workload_metrics",
        serde_json::json!({
            "node_id": runtime.node_id,
            "topology": runtime.topology.to_string(),
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
    if config
        .plugin_configs
        .iter()
        .any(|pc| pc.enabled && pc.scope == PluginScope::Global && pc.plugin_name == plugin_name)
    {
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

    if let Some(existing) = config.plugin_configs.iter_mut().find(|pc| pc.id == id) {
        *existing = mesh_plugin;
    } else {
        config.plugin_configs.push(mesh_plugin);
    }
}
