#![allow(dead_code)]

use std::collections::HashMap;

use crate::grpc::proto::MeshSubscribeRequest;

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
