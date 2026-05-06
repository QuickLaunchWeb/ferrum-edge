use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::config::mesh::{
    MeshPolicy, MeshService, PeerAuthentication, PolicyScope, ServiceEntry, TrustBundleSet,
    Workload, WorkloadSelector,
};
use crate::config::types::GatewayConfig;

/// Node/workload selector used by both ADS and native `MeshSubscribe`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshSliceRequest {
    pub node_id: String,
    pub namespace: String,
    pub workload_spiffe_id: Option<String>,
    pub labels: BTreeMap<String, String>,
}

impl MeshSliceRequest {
    pub fn from_native(
        node_id: String,
        namespace: String,
        workload_spiffe_id: String,
        labels: HashMap<String, String>,
    ) -> Self {
        Self {
            node_id,
            namespace,
            workload_spiffe_id: non_empty(workload_spiffe_id),
            labels: labels.into_iter().collect(),
        }
    }

    pub fn from_xds_node(node_id: String, namespace: String) -> Self {
        let workload_spiffe_id = if node_id.starts_with("spiffe://") {
            Some(node_id.clone())
        } else {
            None
        };
        Self {
            node_id,
            namespace,
            workload_spiffe_id,
            labels: BTreeMap::new(),
        }
    }
}

/// Canonical per-node mesh view. This is the common source for both xDS
/// translators and native ConfigSync mesh subscribers.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshSlice {
    pub node_id: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_spiffe_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    pub version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<Workload>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<MeshService>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mesh_policies: Vec<MeshPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_authentications: Vec<PeerAuthentication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_entries: Vec<ServiceEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundles: Option<TrustBundleSet>,
}

impl MeshSlice {
    pub fn from_gateway_config(config: &GatewayConfig, request: MeshSliceRequest) -> Self {
        let version = config.loaded_at.to_rfc3339();
        let Some(mesh) = config.mesh.as_ref() else {
            return Self {
                node_id: request.node_id,
                namespace: request.namespace,
                workload_spiffe_id: request.workload_spiffe_id,
                labels: request.labels,
                version,
                ..Self::default()
            };
        };

        let namespace = request.namespace.clone();
        let workloads: Vec<Workload> = mesh
            .workloads
            .iter()
            .filter(|w| w.namespace == namespace)
            .cloned()
            .collect();
        let selected_workload = request.workload_spiffe_id.as_ref().and_then(|spiffe_id| {
            workloads
                .iter()
                .find(|workload| workload.spiffe_id.as_str() == spiffe_id)
        });
        let effective_namespace = selected_workload
            .map(|workload| workload.namespace.as_str())
            .unwrap_or(namespace.as_str());
        let effective_labels = if request.labels.is_empty() {
            selected_workload
                .map(|workload| labels_to_btree(&workload.selector.labels))
                .unwrap_or_default()
        } else {
            request.labels.clone()
        };

        let services: Vec<MeshService> = mesh
            .services
            .iter()
            .filter(|service| service.namespace == namespace)
            .cloned()
            .collect();
        let mesh_policies: Vec<MeshPolicy> = mesh
            .mesh_policies
            .iter()
            .filter(|policy| {
                policy.namespace == namespace
                    && policy_applies(policy, effective_namespace, &effective_labels)
            })
            .cloned()
            .collect();
        let peer_authentications: Vec<PeerAuthentication> = mesh
            .peer_authentications
            .iter()
            .filter(|peer_auth| {
                peer_auth.namespace == namespace
                    && peer_auth.selector.as_ref().is_none_or(|selector| {
                        selector_matches(selector, effective_namespace, &effective_labels)
                    })
            })
            .cloned()
            .collect();
        let service_entries: Vec<ServiceEntry> = mesh
            .service_entries
            .iter()
            .filter(|entry| entry.namespace == namespace)
            .cloned()
            .collect();

        Self {
            node_id: request.node_id,
            namespace: request.namespace,
            workload_spiffe_id: request.workload_spiffe_id,
            labels: effective_labels,
            version,
            workloads,
            services,
            mesh_policies,
            peer_authentications,
            service_entries,
            trust_bundles: mesh.trust_bundles.clone(),
        }
    }
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn labels_to_btree(labels: &HashMap<String, String>) -> BTreeMap<String, String> {
    labels
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn policy_applies(policy: &MeshPolicy, namespace: &str, labels: &BTreeMap<String, String>) -> bool {
    match &policy.scope {
        PolicyScope::MeshWide => true,
        PolicyScope::Namespace {
            namespace: policy_namespace,
        } => policy_namespace == namespace,
        PolicyScope::WorkloadSelector { selector } => selector_matches(selector, namespace, labels),
    }
}

fn selector_matches(
    selector: &WorkloadSelector,
    namespace: &str,
    labels: &BTreeMap<String, String>,
) -> bool {
    if let Some(selector_namespace) = selector.namespace.as_ref()
        && selector_namespace != namespace
    {
        return false;
    }
    selector
        .labels
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
}
