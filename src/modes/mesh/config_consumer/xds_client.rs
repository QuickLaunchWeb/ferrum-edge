#![allow(dead_code)]

use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::xds::slice::MeshSlice;

/// Phase B shell for an xDS-backed mesh config consumer.
///
/// Not wired into the mesh runtime yet; retained for the Phase B/C xDS data
/// plane client implementation once `FERRUM_MESH_CONFIG_PROTOCOL=xds` is
/// enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdsClientConfig {
    pub cp_url: String,
    pub node_id: String,
    pub namespace: String,
}

#[derive(Clone)]
pub struct XdsConfigConsumer {
    config: XdsClientConfig,
    state: MeshRuntimeState,
}

impl XdsConfigConsumer {
    pub fn new(config: XdsClientConfig, state: MeshRuntimeState) -> Self {
        Self { config, state }
    }

    pub fn config(&self) -> &XdsClientConfig {
        &self.config
    }

    pub fn state(&self) -> &MeshRuntimeState {
        &self.state
    }

    pub fn apply_slice(&self, slice: MeshSlice) {
        self.state.install_slice(slice);
    }
}
