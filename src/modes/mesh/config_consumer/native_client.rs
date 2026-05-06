#![allow(dead_code)]

use std::collections::HashMap;

use crate::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::xds::slice::MeshSlice;

/// Phase B shell for Ferrum-native MeshSubscribe consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeMeshClientConfig {
    pub cp_url: String,
    pub node_id: String,
    pub namespace: String,
    pub workload_spiffe_id: Option<String>,
    pub labels: HashMap<String, String>,
}

impl NativeMeshClientConfig {
    pub fn subscribe_request(&self, ferrum_version: &str) -> MeshSubscribeRequest {
        MeshSubscribeRequest {
            node_id: self.node_id.clone(),
            ferrum_version: ferrum_version.to_string(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone().unwrap_or_default(),
            labels: self.labels.clone(),
        }
    }
}

/// Applies native `MeshSubscribe` updates into the shared mesh runtime state.
#[derive(Clone)]
pub struct NativeMeshConfigConsumer {
    state: MeshRuntimeState,
}

impl NativeMeshConfigConsumer {
    pub fn new(state: MeshRuntimeState) -> Self {
        Self { state }
    }

    pub fn state(&self) -> &MeshRuntimeState {
        &self.state
    }

    pub fn apply_update(&self, update: MeshConfigUpdate) -> Result<MeshSlice, String> {
        let slice = serde_json::from_str::<MeshSlice>(&update.mesh_slice_json)
            .map_err(|e| format!("invalid MeshSubscribe slice JSON: {e}"))?;
        self.state.install_slice(slice.clone());
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_update_installs_mesh_slice() {
        let state = MeshRuntimeState::new();
        let consumer = NativeMeshConfigConsumer::new(state.clone());
        let update = MeshConfigUpdate {
            version: "v1".to_string(),
            timestamp: 1,
            mesh_slice_json: serde_json::to_string(&MeshSlice {
                node_id: "node-a".to_string(),
                version: "v1".to_string(),
                ..MeshSlice::default()
            })
            .expect("mesh slice serializes"),
            ferrum_version: crate::FERRUM_VERSION.to_string(),
        };

        let slice = consumer.apply_update(update).expect("update applies");

        assert_eq!(slice.node_id, "node-a");
        assert!(state.has_first_slice());
        assert_eq!(
            state
                .snapshot()
                .as_ref()
                .as_ref()
                .map(|slice| slice.version.as_str()),
            Some("v1")
        );
    }
}
