//! Mesh runtime planning.
//!
//! The listener plan is a cold-start artifact for `FERRUM_MODE=mesh`. It keeps
//! topology decisions out of the proxy hot path and gives Phase C a small,
//! testable boundary before the capture/HBONE accept loops grow more capable.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::config::{EnvConfig, MeshConfigSource, MeshTopology};

use super::config_consumer::native_client::NativeMeshClientConfig;
use super::config_consumer::xds_client::XdsClientConfig;

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
