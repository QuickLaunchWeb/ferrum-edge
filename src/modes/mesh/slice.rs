use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::config::types::GatewayConfig;
use crate::modes::mesh::config::{
    MeshDestinationRule, MeshPolicy, MeshProxyConfig, MeshRequestAuthentication, MeshService,
    MeshTelemetryResource, MtlsMode, MultiClusterConfig, OutboundTrafficPolicy, PeerAuthentication,
    PolicyScope, ServiceEntry, TrustBundleSet, Workload, WorkloadLabels,
    policy_scope_applies_to_workload, proxy_config_applies_to_workload, scope_applies_to_workload,
    service_entry_applies_to_workload, workload_selector_matches,
};

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_authentications: Vec<MeshRequestAuthentication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub telemetry_resources: Vec<MeshTelemetryResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_rules: Vec<MeshDestinationRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_configs: Vec<MeshProxyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundles: Option<TrustBundleSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_cluster: Option<MultiClusterConfig>,
    /// Mesh-wide outbound traffic policy. `None` keeps the legacy
    /// `AllowAny` behavior. When `Some(RegistryOnly)`, the slice-apply
    /// path auto-injects the `mesh_outbound_registry` plugin with a
    /// registry built from `services` ∪ `service_entries` ∪
    /// `workloads.addresses`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_traffic_policy: Option<OutboundTrafficPolicy>,
}

impl MeshSlice {
    /// Compare mesh-slice content while ignoring the transport version stamp.
    ///
    /// MeshSubscribe uses this to suppress no-op updates. Keep the comparison
    /// beside the struct so future fields are considered when the model grows.
    pub fn content_eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
            && self.namespace == other.namespace
            && self.workload_spiffe_id == other.workload_spiffe_id
            && self.labels == other.labels
            && self.workloads == other.workloads
            && self.services == other.services
            && self.mesh_policies == other.mesh_policies
            && self.peer_authentications == other.peer_authentications
            && self.service_entries == other.service_entries
            && self.request_authentications == other.request_authentications
            && self.telemetry_resources == other.telemetry_resources
            && self.destination_rules == other.destination_rules
            && self.proxy_configs == other.proxy_configs
            && self.trust_bundles == other.trust_bundles
            && self.multi_cluster == other.multi_cluster
            && self.outbound_traffic_policy == other.outbound_traffic_policy
    }

    /// Build the set of known mesh destinations from this slice. Used by
    /// the auto-injected `mesh_outbound_registry` plugin when
    /// `outbound_traffic_policy == RegistryOnly`. Includes:
    ///   - `services.{name}.{namespace}.svc.cluster.local` and bare
    ///     `{name}.{namespace}` and `{name}` forms with their declared ports
    ///   - `service_entries.hosts` with their declared ports
    ///   - `workloads.addresses`
    ///
    /// Returned entries are alphabetically sorted so the plugin config is
    /// deterministic across reloads (preventing spurious slice-update
    /// re-broadcasts via `content_eq`).
    pub fn build_known_destinations(&self, cluster_domain: &str) -> Vec<String> {
        let mut entries: std::collections::HashSet<String> = std::collections::HashSet::new();
        for service in &self.services {
            let fqdn = format!(
                "{}.{}.svc.{}",
                service.name, service.namespace, cluster_domain
            );
            entries.insert(fqdn.to_ascii_lowercase());
            entries.insert(format!("{}.{}", service.name, service.namespace).to_ascii_lowercase());
            entries.insert(service.name.to_ascii_lowercase());
            for port in &service.ports {
                entries.insert(format!("{}:{}", fqdn, port.port).to_ascii_lowercase());
                entries.insert(
                    format!("{}.{}:{}", service.name, service.namespace, port.port)
                        .to_ascii_lowercase(),
                );
            }
        }
        for entry in &self.service_entries {
            for host in &entry.hosts {
                let host_lc = host.to_ascii_lowercase();
                entries.insert(host_lc.clone());
                for port in &entry.ports {
                    entries.insert(format!("{}:{}", host_lc, port.port));
                }
            }
        }
        for workload in &self.workloads {
            for addr in &workload.addresses {
                entries.insert(addr.to_ascii_lowercase());
                for port in &workload.ports {
                    entries.insert(format!("{}:{}", addr.to_ascii_lowercase(), port.port));
                }
            }
        }
        let mut sorted: Vec<String> = entries.into_iter().collect();
        sorted.sort();
        sorted
    }

    /// Resolve the effective mTLS mode for a given port on this workload.
    ///
    /// PeerAuthentication scope precedence (highest wins):
    ///   1. WorkloadSelector-scoped (has `selector` with labels matching this workload)
    ///   2. Namespace-scoped (no selector, same namespace)
    ///   3. Mesh-wide (root namespace, no selector — carried via `peer_authentications`
    ///      which is already pre-filtered by `from_gateway_config`)
    ///
    /// Within the winning policy, a port-level override for `port` takes
    /// precedence over the policy's top-level `mtls_mode`.
    ///
    /// When no PeerAuthentication applies, returns `MtlsMode::Permissive`
    /// (Istio default).
    pub fn resolve_effective_mtls_mode(&self, port: u16) -> MtlsMode {
        resolve_effective_mtls_mode(
            &self.peer_authentications,
            &self.namespace,
            &self.labels,
            port,
        )
    }

    /// Returns the most-specific applicable [`MeshProxyConfig`] for this slice's
    /// workload, or `None` when no `ProxyConfig` applies.
    ///
    /// Specificity ordering mirrors Istio's `PolicyScope` tiers:
    /// `WorkloadSelector` > `Namespace` > `MeshWide`. Among same-tier
    /// matches the ASCII-smallest `name` wins — deterministic tiebreaker
    /// that mirrors the accumulator's `(namespace, name)` sort so consumers
    /// see a stable choice regardless of informer delivery order.
    ///
    /// Slice construction in [`Self::from_gateway_config`] already filters
    /// `proxy_configs` down to those visible to the current node, so this
    /// method just resolves specificity among matched entries.
    pub fn resolved_proxy_config(&self) -> Option<&MeshProxyConfig> {
        self.proxy_configs.iter().min_by(|a, b| {
            // Higher tier first (reverse cmp), then smaller name first.
            // `min_by` picks the comparator's smallest, so:
            //   - WorkloadSelector (2) < Namespace (1) < MeshWide (0) after reverse
            //   - within same tier, the ASCII-smallest name wins
            proxy_config_scope_tier(b)
                .cmp(&proxy_config_scope_tier(a))
                .then_with(|| a.name.as_str().cmp(b.name.as_str()))
        })
    }

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
                    && policy_scope_applies_to_workload(
                        policy,
                        effective_namespace,
                        &effective_labels,
                    )
            })
            .cloned()
            .collect();
        let peer_authentications: Vec<PeerAuthentication> = mesh
            .peer_authentications
            .iter()
            .filter(|peer_auth| {
                peer_auth_applies_to_workload(peer_auth, effective_namespace, &effective_labels)
            })
            .cloned()
            .collect();
        let service_entries: Vec<ServiceEntry> = mesh
            .service_entries
            .iter()
            .filter(|entry| {
                service_entry_applies_to_workload(entry, effective_namespace, &effective_labels)
            })
            .cloned()
            .collect();
        let request_authentications: Vec<MeshRequestAuthentication> = mesh
            .request_authentications
            .iter()
            .filter(|ra| {
                scope_applies_to_workload(&ra.scope, effective_namespace, &effective_labels)
            })
            .cloned()
            .collect();
        let telemetry_resources: Vec<MeshTelemetryResource> = mesh
            .telemetry_resources
            .iter()
            .filter(|t| scope_applies_to_workload(&t.scope, effective_namespace, &effective_labels))
            .cloned()
            .collect();
        let destination_rules: Vec<MeshDestinationRule> = mesh
            .destination_rules
            .iter()
            .filter(|dr| dr.namespace == namespace)
            .cloned()
            .collect();
        let proxy_configs: Vec<MeshProxyConfig> = mesh
            .proxy_configs
            .iter()
            .filter(|pc| {
                proxy_config_applies_to_workload(pc, effective_namespace, &effective_labels)
            })
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
            request_authentications,
            telemetry_resources,
            destination_rules,
            proxy_configs,
            trust_bundles: mesh.trust_bundles.clone(),
            multi_cluster: mesh.multi_cluster.clone(),
            outbound_traffic_policy: mesh.outbound_traffic_policy,
        }
    }
}

/// Scope tier used for PeerAuthentication precedence ranking.
///
/// Discriminant order is load-bearing: `Ord` derive uses it, and the
/// resolution loop picks the highest-valued tier. Istio semantics:
/// WorkloadSelector > Namespace > MeshWide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PeerAuthScope {
    MeshWide = 0,
    Namespace = 1,
    WorkloadSelector = 2,
}

/// Classify a [`MeshProxyConfig`]'s [`PolicyScope`] into a `u8` tier for
/// precedence ordering. Higher = more specific. Mirrors `PeerAuthScope`'s
/// `WorkloadSelector > Namespace > MeshWide` ordering so `MeshProxyConfig`
/// resolution stays byte-identical to PeerAuthentication semantics.
#[inline]
fn proxy_config_scope_tier(pc: &MeshProxyConfig) -> u8 {
    match pc.scope {
        PolicyScope::MeshWide => 0,
        PolicyScope::Namespace { .. } => 1,
        PolicyScope::WorkloadSelector { .. } => 2,
    }
}

/// Classify a [`PeerAuthentication`] into a scope tier for precedence ordering.
fn classify_peer_auth_scope(pa: &PeerAuthentication) -> PeerAuthScope {
    if let Some(scope) = &pa.scope {
        return match scope {
            PolicyScope::MeshWide => PeerAuthScope::MeshWide,
            PolicyScope::Namespace { .. } => PeerAuthScope::Namespace,
            PolicyScope::WorkloadSelector { .. } => PeerAuthScope::WorkloadSelector,
        };
    }

    match &pa.selector {
        Some(selector) if !selector.labels.is_empty() => PeerAuthScope::WorkloadSelector,
        _ => PeerAuthScope::Namespace,
    }
}

fn peer_auth_applies_to_workload<L: WorkloadLabels + ?Sized>(
    pa: &PeerAuthentication,
    namespace: &str,
    labels: &L,
) -> bool {
    if let Some(scope) = &pa.scope {
        return scope_applies_to_workload(scope, namespace, labels);
    }

    pa.namespace == namespace
        && pa
            .selector
            .as_ref()
            .is_none_or(|selector| workload_selector_matches(selector, namespace, labels))
}

/// Resolve the effective mTLS mode for a given port from a set of
/// PeerAuthentication policies.
///
/// This is the canonical resolution function. The `MeshSlice` convenience
/// method delegates here.
pub fn resolve_effective_mtls_mode<L: WorkloadLabels + ?Sized>(
    peer_auths: &[PeerAuthentication],
    namespace: &str,
    labels: &L,
    port: u16,
) -> MtlsMode {
    let mut best: Option<(PeerAuthScope, &PeerAuthentication)> = None;

    for pa in peer_auths {
        if !peer_auth_applies_to_workload(pa, namespace, labels) {
            continue;
        }

        let scope = classify_peer_auth_scope(pa);
        let dominated = best
            .as_ref()
            .is_none_or(|(current_scope, _)| scope > *current_scope);
        if dominated {
            best = Some((scope, pa));
        }
    }

    match best {
        Some((_, pa)) => {
            // Port-level override within the winning policy.
            pa.port_overrides
                .get(&port)
                .copied()
                .unwrap_or(pa.mtls_mode)
        }
        None => MtlsMode::Permissive,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::GatewayConfig;
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
    use crate::modes::mesh::config::{
        AppProtocol, MeshAccessLoggingConfig, MeshConfig, MeshPolicy, MeshProxyConfig,
        MeshRequestAuthentication, MeshRule, MeshService, MeshTelemetryConfig,
        MeshTelemetryResource, MtlsMode, MultiClusterConfig, PeerAuthentication, PolicyAction,
        PolicyScope, RemoteCluster, ServiceEntry, ServiceEntryLocation, ServicePort, TrustBundle,
        TrustBundleSet, Workload, WorkloadPort, WorkloadSelector,
    };
    use std::collections::HashMap;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn td() -> TrustDomain {
        TrustDomain::new("test.local").unwrap()
    }

    fn make_workload(namespace: &str, service: &str, labels: HashMap<String, String>) -> Workload {
        let td = td();
        let path = format!("ns/{namespace}/sa/{service}");
        Workload {
            spiffe_id: SpiffeId::from_parts(&td, &path).unwrap(),
            selector: WorkloadSelector {
                labels,
                namespace: Some(namespace.into()),
            },
            service_name: service.into(),
            addresses: vec!["10.0.0.1".into()],
            ports: vec![WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: None,
            }],
            trust_domain: td,
            namespace: namespace.into(),
            network: None,
            cluster: None,
        }
    }

    fn make_service(namespace: &str, name: &str) -> MeshService {
        MeshService {
            name: name.into(),
            namespace: namespace.into(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: None,
            }],
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }
    }

    fn make_policy(name: &str, namespace: &str, scope: PolicyScope) -> MeshPolicy {
        MeshPolicy {
            name: name.into(),
            namespace: namespace.into(),
            scope,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: Vec::new(),
                when: Vec::new(),
                request_principals: Vec::new(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }
    }

    fn make_peer_auth(
        name: &str,
        namespace: &str,
        selector: Option<WorkloadSelector>,
    ) -> PeerAuthentication {
        PeerAuthentication {
            name: name.into(),
            namespace: namespace.into(),
            scope: None,
            selector,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }
    }

    fn make_service_entry(name: &str, namespace: &str, export_to: Vec<String>) -> ServiceEntry {
        ServiceEntry {
            name: name.into(),
            namespace: namespace.into(),
            hosts: vec!["external.example.com".into()],
            endpoints: Vec::new(),
            resolution: crate::modes::mesh::config::Resolution::None,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 443,
                protocol: AppProtocol::Http2,
                name: None,
            }],
            export_to,
            workload_selector: None,
        }
    }

    fn make_request_auth(
        name: &str,
        namespace: &str,
        scope: PolicyScope,
    ) -> MeshRequestAuthentication {
        MeshRequestAuthentication {
            name: name.into(),
            namespace: namespace.into(),
            scope,
            jwt_rules: Vec::new(),
        }
    }

    fn make_telemetry(name: &str, namespace: &str, scope: PolicyScope) -> MeshTelemetryResource {
        MeshTelemetryResource {
            name: name.into(),
            namespace: namespace.into(),
            scope,
            config: MeshTelemetryConfig {
                tracing: None,
                metrics: None,
                access_logging: Some(MeshAccessLoggingConfig {
                    enabled: true,
                    filter: None,
                }),
            },
        }
    }

    fn make_trust_bundle_set() -> TrustBundleSet {
        TrustBundleSet {
            local: TrustBundle {
                trust_domain: td(),
                x509_authorities: Vec::new(),
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        }
    }

    fn make_multi_cluster() -> MultiClusterConfig {
        MultiClusterConfig {
            local_cluster: Some("cluster-a".into()),
            federation_endpoint: None,
            remote_clusters: vec![RemoteCluster {
                name: "cluster-b".into(),
                trust_domain: td(),
                network: None,
                control_plane_url: None,
                federation_endpoint: None,
            }],
            east_west_gateways: Vec::new(),
        }
    }

    fn slice_request(namespace: &str) -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: namespace.into(),
            workload_spiffe_id: None,
            labels: BTreeMap::new(),
        }
    }

    fn slice_request_with_labels(
        namespace: &str,
        labels: BTreeMap<String, String>,
    ) -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: namespace.into(),
            workload_spiffe_id: None,
            labels,
        }
    }

    fn config_with_mesh(mesh: MeshConfig) -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(mesh)),
            ..GatewayConfig::default()
        }
    }

    // ── content_eq tests ────────────────────────────────────────────────

    #[test]
    fn content_eq_identical_slices() {
        let slice = MeshSlice {
            node_id: "n1".into(),
            namespace: "ns".into(),
            workload_spiffe_id: Some("spiffe://td/ns/x/sa/y".into()),
            labels: BTreeMap::from([("app".into(), "web".into())]),
            version: "v1".into(),
            workloads: vec![make_workload("ns", "web", HashMap::new())],
            services: vec![make_service("ns", "web")],
            mesh_policies: vec![make_policy("p1", "ns", PolicyScope::MeshWide)],
            peer_authentications: vec![make_peer_auth("pa1", "ns", None)],
            service_entries: vec![make_service_entry("se1", "ns", vec!["*".into()])],
            destination_rules: Vec::new(),
            proxy_configs: Vec::new(),
            request_authentications: vec![make_request_auth("ra1", "ns", PolicyScope::MeshWide)],
            telemetry_resources: vec![make_telemetry("t1", "ns", PolicyScope::MeshWide)],
            trust_bundles: Some(make_trust_bundle_set()),
            multi_cluster: Some(make_multi_cluster()),
            outbound_traffic_policy: None,
        };
        assert!(slice.content_eq(&slice.clone()));
    }

    #[test]
    fn content_eq_ignores_version_difference() {
        let mut a = MeshSlice {
            node_id: "n1".into(),
            namespace: "ns".into(),
            version: "2024-01-01T00:00:00Z".into(),
            workloads: vec![make_workload("ns", "api", HashMap::new())],
            ..MeshSlice::default()
        };
        let mut b = a.clone();
        b.version = "2024-06-15T12:00:00Z".into();
        assert!(a.content_eq(&b), "version difference should be ignored");

        // Verify PartialEq does NOT ignore version (sanity check).
        assert_ne!(a, b);

        // Both empty versions also equal.
        a.version = String::new();
        b.version = String::new();
        assert!(a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_workloads_change() {
        let a = MeshSlice {
            workloads: vec![make_workload("ns", "api", HashMap::new())],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_services_change() {
        let a = MeshSlice {
            services: vec![make_service("ns", "svc")],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_mesh_policies_change() {
        let a = MeshSlice {
            mesh_policies: vec![make_policy("p", "ns", PolicyScope::MeshWide)],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_peer_auth_change() {
        let a = MeshSlice {
            peer_authentications: vec![make_peer_auth("pa", "ns", None)],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_service_entries_change() {
        let a = MeshSlice {
            service_entries: vec![make_service_entry("se", "ns", vec![])],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_request_auth_change() {
        let a = MeshSlice {
            request_authentications: vec![make_request_auth("ra", "ns", PolicyScope::MeshWide)],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_telemetry_change() {
        let a = MeshSlice {
            telemetry_resources: vec![make_telemetry("t", "ns", PolicyScope::MeshWide)],
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_trust_bundles_change() {
        let a = MeshSlice {
            trust_bundles: Some(make_trust_bundle_set()),
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_multi_cluster_change() {
        let a = MeshSlice {
            multi_cluster: Some(make_multi_cluster()),
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_node_id_change() {
        let a = MeshSlice {
            node_id: "node-a".into(),
            ..MeshSlice::default()
        };
        let b = MeshSlice {
            node_id: "node-b".into(),
            ..MeshSlice::default()
        };
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_namespace_change() {
        let a = MeshSlice {
            namespace: "ns-a".into(),
            ..MeshSlice::default()
        };
        let b = MeshSlice {
            namespace: "ns-b".into(),
            ..MeshSlice::default()
        };
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_labels_change() {
        let a = MeshSlice {
            labels: BTreeMap::from([("app".into(), "web".into())]),
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_detects_spiffe_id_change() {
        let a = MeshSlice {
            workload_spiffe_id: Some("spiffe://td/ns/x/sa/y".into()),
            ..MeshSlice::default()
        };
        let b = MeshSlice::default();
        assert!(!a.content_eq(&b));
    }

    #[test]
    fn content_eq_empty_defaults() {
        let a = MeshSlice::default();
        let b = MeshSlice::default();
        assert!(a.content_eq(&b));
    }

    // ── from_gateway_config tests ───────────────────────────────────────

    #[test]
    fn from_gateway_config_no_mesh_returns_empty_slice() {
        let config = GatewayConfig::default();
        let slice = MeshSlice::from_gateway_config(&config, slice_request("default"));
        assert!(slice.workloads.is_empty());
        assert!(slice.services.is_empty());
        assert!(slice.mesh_policies.is_empty());
        assert!(slice.peer_authentications.is_empty());
        assert!(slice.service_entries.is_empty());
        assert!(slice.request_authentications.is_empty());
        assert!(slice.telemetry_resources.is_empty());
        assert!(slice.trust_bundles.is_none());
        assert!(slice.multi_cluster.is_none());
        assert_eq!(slice.node_id, "node-1");
        assert_eq!(slice.namespace, "default");
    }

    #[test]
    fn from_gateway_config_empty_mesh_returns_empty_collections() {
        let config = config_with_mesh(MeshConfig::default());
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert!(slice.workloads.is_empty());
        assert!(slice.services.is_empty());
        assert!(slice.mesh_policies.is_empty());
    }

    #[test]
    fn from_gateway_config_filters_workloads_by_namespace() {
        let mesh = MeshConfig {
            workloads: vec![
                make_workload("alpha", "svc-a", HashMap::new()),
                make_workload("beta", "svc-b", HashMap::new()),
                make_workload("alpha", "svc-c", HashMap::new()),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.workloads.len(), 2);
        assert!(slice.workloads.iter().all(|w| w.namespace == "alpha"));
    }

    #[test]
    fn from_gateway_config_filters_services_by_namespace() {
        let mesh = MeshConfig {
            services: vec![
                make_service("alpha", "svc-a"),
                make_service("beta", "svc-b"),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "svc-a");
    }

    #[test]
    fn from_gateway_config_policy_mesh_wide_included_for_any_namespace() {
        let mesh = MeshConfig {
            mesh_policies: vec![make_policy("global", "alpha", PolicyScope::MeshWide)],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "global");
    }

    #[test]
    fn from_gateway_config_policy_mesh_wide_excluded_when_policy_namespace_differs() {
        // MeshWide scope applies to any workload, but the policy's own
        // namespace field must match the request namespace to be included.
        let mesh = MeshConfig {
            mesh_policies: vec![make_policy("global", "other-ns", PolicyScope::MeshWide)],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert!(
            slice.mesh_policies.is_empty(),
            "policy from a different namespace should not be included"
        );
    }

    #[test]
    fn from_gateway_config_policy_namespace_scope_matching() {
        let mesh = MeshConfig {
            mesh_policies: vec![
                make_policy(
                    "ns-match",
                    "alpha",
                    PolicyScope::Namespace {
                        namespace: "alpha".into(),
                    },
                ),
                make_policy(
                    "ns-nomatch",
                    "alpha",
                    PolicyScope::Namespace {
                        namespace: "beta".into(),
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "ns-match");
    }

    #[test]
    fn from_gateway_config_policy_workload_selector_with_labels() {
        let labels = BTreeMap::from([("app".into(), "web".into()), ("env".into(), "prod".into())]);
        let mesh = MeshConfig {
            mesh_policies: vec![
                make_policy(
                    "match-labels",
                    "alpha",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".into(), "web".into())]),
                            namespace: None,
                        },
                    },
                ),
                make_policy(
                    "nomatch-labels",
                    "alpha",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".into(), "backend".into())]),
                            namespace: None,
                        },
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice =
            MeshSlice::from_gateway_config(&config, slice_request_with_labels("alpha", labels));
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "match-labels");
    }

    #[test]
    fn from_gateway_config_policy_workload_selector_empty_labels_matches_all() {
        let mesh = MeshConfig {
            mesh_policies: vec![make_policy(
                "empty-selector",
                "alpha",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::new(),
                        namespace: None,
                    },
                },
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.mesh_policies.len(), 1);
    }

    #[test]
    fn from_gateway_config_peer_auth_filtered_by_namespace() {
        let mesh = MeshConfig {
            peer_authentications: vec![
                make_peer_auth("pa-alpha", "alpha", None),
                make_peer_auth("pa-beta", "beta", None),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.peer_authentications.len(), 1);
        assert_eq!(slice.peer_authentications[0].name, "pa-alpha");
    }

    #[test]
    fn from_gateway_config_peer_auth_with_selector_filters_on_labels() {
        let labels = BTreeMap::from([("tier".into(), "frontend".into())]);
        let mesh = MeshConfig {
            peer_authentications: vec![
                make_peer_auth(
                    "match",
                    "alpha",
                    Some(WorkloadSelector {
                        labels: HashMap::from([("tier".into(), "frontend".into())]),
                        namespace: None,
                    }),
                ),
                make_peer_auth(
                    "nomatch",
                    "alpha",
                    Some(WorkloadSelector {
                        labels: HashMap::from([("tier".into(), "backend".into())]),
                        namespace: None,
                    }),
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice =
            MeshSlice::from_gateway_config(&config, slice_request_with_labels("alpha", labels));
        assert_eq!(slice.peer_authentications.len(), 1);
        assert_eq!(slice.peer_authentications[0].name, "match");
    }

    #[test]
    fn from_gateway_config_peer_auth_no_selector_always_included() {
        let mesh = MeshConfig {
            peer_authentications: vec![make_peer_auth("global-pa", "ns", None)],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert_eq!(slice.peer_authentications.len(), 1);
    }

    #[test]
    fn from_gateway_config_service_entry_export_to_star() {
        let mesh = MeshConfig {
            service_entries: vec![make_service_entry("se", "infra", vec!["*".into()])],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("app"));
        assert_eq!(slice.service_entries.len(), 1);
    }

    #[test]
    fn from_gateway_config_service_entry_export_to_specific_namespace() {
        let mesh = MeshConfig {
            service_entries: vec![
                make_service_entry("se-match", "infra", vec!["app".into()]),
                make_service_entry("se-nomatch", "infra", vec!["other".into()]),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("app"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "se-match");
    }

    #[test]
    fn from_gateway_config_service_entry_export_to_dot_means_same_namespace() {
        let mesh = MeshConfig {
            service_entries: vec![
                make_service_entry("se-same", "alpha", vec![".".into()]),
                make_service_entry("se-other", "beta", vec![".".into()]),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "se-same");
    }

    #[test]
    fn from_gateway_config_service_entry_empty_export_to_is_namespace_local() {
        let mesh = MeshConfig {
            service_entries: vec![
                make_service_entry("se-local", "alpha", vec![]),
                make_service_entry("se-other", "beta", vec![]),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.service_entries.len(), 1);
        assert_eq!(slice.service_entries[0].name, "se-local");
    }

    #[test]
    fn from_gateway_config_request_auth_mesh_wide_included() {
        let mesh = MeshConfig {
            request_authentications: vec![make_request_auth(
                "ra-global",
                "ns",
                PolicyScope::MeshWide,
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert_eq!(slice.request_authentications.len(), 1);
    }

    #[test]
    fn from_gateway_config_request_auth_namespace_scope() {
        let mesh = MeshConfig {
            request_authentications: vec![
                make_request_auth(
                    "ra-match",
                    "ns",
                    PolicyScope::Namespace {
                        namespace: "alpha".into(),
                    },
                ),
                make_request_auth(
                    "ra-nomatch",
                    "ns",
                    PolicyScope::Namespace {
                        namespace: "beta".into(),
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.request_authentications.len(), 1);
        assert_eq!(slice.request_authentications[0].name, "ra-match");
    }

    #[test]
    fn from_gateway_config_request_auth_workload_selector() {
        let labels = BTreeMap::from([("role".into(), "gateway".into())]);
        let mesh = MeshConfig {
            request_authentications: vec![
                make_request_auth(
                    "ra-selector-match",
                    "ns",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("role".into(), "gateway".into())]),
                            namespace: None,
                        },
                    },
                ),
                make_request_auth(
                    "ra-selector-nomatch",
                    "ns",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("role".into(), "worker".into())]),
                            namespace: None,
                        },
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice =
            MeshSlice::from_gateway_config(&config, slice_request_with_labels("alpha", labels));
        assert_eq!(slice.request_authentications.len(), 1);
        assert_eq!(slice.request_authentications[0].name, "ra-selector-match");
    }

    #[test]
    fn from_gateway_config_telemetry_mesh_wide_included() {
        let mesh = MeshConfig {
            telemetry_resources: vec![make_telemetry("tel", "ns", PolicyScope::MeshWide)],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert_eq!(slice.telemetry_resources.len(), 1);
    }

    #[test]
    fn from_gateway_config_telemetry_namespace_scope() {
        let mesh = MeshConfig {
            telemetry_resources: vec![
                make_telemetry(
                    "tel-match",
                    "ns",
                    PolicyScope::Namespace {
                        namespace: "alpha".into(),
                    },
                ),
                make_telemetry(
                    "tel-nomatch",
                    "ns",
                    PolicyScope::Namespace {
                        namespace: "beta".into(),
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("alpha"));
        assert_eq!(slice.telemetry_resources.len(), 1);
        assert_eq!(slice.telemetry_resources[0].name, "tel-match");
    }

    #[test]
    fn from_gateway_config_telemetry_workload_selector() {
        let labels = BTreeMap::from([("team".into(), "platform".into())]);
        let mesh = MeshConfig {
            telemetry_resources: vec![
                make_telemetry(
                    "tel-match",
                    "ns",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("team".into(), "platform".into())]),
                            namespace: None,
                        },
                    },
                ),
                make_telemetry(
                    "tel-nomatch",
                    "ns",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("team".into(), "infra".into())]),
                            namespace: None,
                        },
                    },
                ),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice =
            MeshSlice::from_gateway_config(&config, slice_request_with_labels("alpha", labels));
        assert_eq!(slice.telemetry_resources.len(), 1);
        assert_eq!(slice.telemetry_resources[0].name, "tel-match");
    }

    #[test]
    fn from_gateway_config_trust_bundles_and_multi_cluster_propagated() {
        let mesh = MeshConfig {
            trust_bundles: Some(make_trust_bundle_set()),
            multi_cluster: Some(make_multi_cluster()),
            outbound_traffic_policy: None,
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert!(slice.trust_bundles.is_some());
        assert!(slice.multi_cluster.is_some());
        assert_eq!(
            slice.multi_cluster.as_ref().unwrap().local_cluster,
            Some("cluster-a".into())
        );
    }

    #[test]
    fn from_gateway_config_version_set_from_loaded_at() {
        let config = config_with_mesh(MeshConfig::default());
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns"));
        assert_eq!(slice.version, config.loaded_at.to_rfc3339());
    }

    #[test]
    fn from_gateway_config_multiple_namespaces_only_requested_included() {
        let mesh = MeshConfig {
            workloads: vec![
                make_workload("ns-a", "svc-1", HashMap::new()),
                make_workload("ns-b", "svc-2", HashMap::new()),
                make_workload("ns-c", "svc-3", HashMap::new()),
            ],
            services: vec![
                make_service("ns-a", "svc-1"),
                make_service("ns-b", "svc-2"),
                make_service("ns-c", "svc-3"),
            ],
            peer_authentications: vec![
                make_peer_auth("pa-a", "ns-a", None),
                make_peer_auth("pa-b", "ns-b", None),
            ],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&config, slice_request("ns-b"));
        assert_eq!(slice.workloads.len(), 1);
        assert_eq!(slice.workloads[0].namespace, "ns-b");
        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].namespace, "ns-b");
        assert_eq!(slice.peer_authentications.len(), 1);
        assert_eq!(slice.peer_authentications[0].name, "pa-b");
    }

    #[test]
    fn from_gateway_config_spiffe_id_resolves_workload_labels() {
        let td = td();
        let spiffe_id = SpiffeId::from_parts(&td, "ns/alpha/sa/web").unwrap();
        let workload_labels = HashMap::from([
            ("app".into(), "web".into()),
            ("tier".into(), "frontend".into()),
        ]);
        let mesh = MeshConfig {
            workloads: vec![make_workload("alpha", "web", workload_labels)],
            mesh_policies: vec![make_policy(
                "selector-policy",
                "alpha",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".into(), "web".into())]),
                        namespace: None,
                    },
                },
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        // Request has no labels but carries SPIFFE ID matching the workload.
        let request = MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: "alpha".into(),
            workload_spiffe_id: Some(spiffe_id.to_string()),
            labels: BTreeMap::new(),
        };
        let slice = MeshSlice::from_gateway_config(&config, request);
        // The slice should inherit labels from the matched workload.
        assert_eq!(slice.labels.get("app"), Some(&"web".to_string()));
        assert_eq!(slice.labels.get("tier"), Some(&"frontend".to_string()));
        // The workload-selector policy should match via inherited labels.
        assert_eq!(slice.mesh_policies.len(), 1);
        assert_eq!(slice.mesh_policies[0].name, "selector-policy");
    }

    #[test]
    fn from_gateway_config_explicit_labels_override_workload_labels() {
        let td = td();
        let spiffe_id = SpiffeId::from_parts(&td, "ns/alpha/sa/web").unwrap();
        let workload_labels = HashMap::from([("app".into(), "web".into())]);
        let mesh = MeshConfig {
            workloads: vec![make_workload("alpha", "web", workload_labels)],
            mesh_policies: vec![make_policy(
                "explicit-labels-policy",
                "alpha",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("custom".into(), "value".into())]),
                        namespace: None,
                    },
                },
            )],
            ..MeshConfig::default()
        };
        let config = config_with_mesh(mesh);
        // Request carries explicit labels that differ from the workload's.
        let request = MeshSliceRequest {
            node_id: "node-1".into(),
            namespace: "alpha".into(),
            workload_spiffe_id: Some(spiffe_id.to_string()),
            labels: BTreeMap::from([("custom".into(), "value".into())]),
        };
        let slice = MeshSlice::from_gateway_config(&config, request);
        // Explicit labels should be used, not the workload's labels.
        assert_eq!(slice.labels.get("custom"), Some(&"value".to_string()));
        assert!(!slice.labels.contains_key("app"));
        assert_eq!(slice.mesh_policies.len(), 1);
    }

    // ── MeshSliceRequest helper tests ───────────────────────────────────

    #[test]
    fn mesh_slice_request_from_native_with_empty_spiffe_id() {
        let req = MeshSliceRequest::from_native(
            "node".into(),
            "ns".into(),
            String::new(),
            HashMap::new(),
        );
        assert!(req.workload_spiffe_id.is_none());
    }

    #[test]
    fn mesh_slice_request_from_native_with_nonempty_spiffe_id() {
        let req = MeshSliceRequest::from_native(
            "node".into(),
            "ns".into(),
            "spiffe://td/ns/foo/sa/bar".into(),
            HashMap::from([("k".into(), "v".into())]),
        );
        assert_eq!(
            req.workload_spiffe_id,
            Some("spiffe://td/ns/foo/sa/bar".into())
        );
        assert_eq!(req.labels.get("k"), Some(&"v".to_string()));
    }

    #[test]
    fn mesh_slice_request_from_xds_node_with_spiffe_prefix() {
        let req = MeshSliceRequest::from_xds_node("spiffe://td/ns/foo/sa/bar".into(), "ns".into());
        assert_eq!(
            req.workload_spiffe_id,
            Some("spiffe://td/ns/foo/sa/bar".into())
        );
    }

    #[test]
    fn mesh_slice_request_from_xds_node_without_spiffe_prefix() {
        let req = MeshSliceRequest::from_xds_node("my-node-id".into(), "ns".into());
        assert!(req.workload_spiffe_id.is_none());
        assert!(req.labels.is_empty());
    }

    // ── Private helper tests ────────────────────────────────────────────

    #[test]
    fn non_empty_returns_none_for_empty_string() {
        assert_eq!(non_empty(String::new()), None);
    }

    #[test]
    fn non_empty_returns_some_for_nonempty_string() {
        assert_eq!(non_empty("hello".into()), Some("hello".into()));
    }

    #[test]
    fn labels_to_btree_preserves_all_entries() {
        let hm = HashMap::from([("a".into(), "1".into()), ("b".into(), "2".into())]);
        let bt = labels_to_btree(&hm);
        assert_eq!(bt.len(), 2);
        assert_eq!(bt.get("a"), Some(&"1".to_string()));
        assert_eq!(bt.get("b"), Some(&"2".to_string()));
    }

    #[test]
    fn labels_to_btree_empty_map() {
        let bt = labels_to_btree(&HashMap::new());
        assert!(bt.is_empty());
    }

    // ── DestinationRule slice filtering ──────────────────────────────────

    #[test]
    fn from_gateway_config_filters_destination_rules_by_namespace() {
        use crate::modes::mesh::config::MeshDestinationRule;

        let mesh = MeshConfig {
            destination_rules: vec![
                MeshDestinationRule {
                    name: "in-ns".into(),
                    namespace: "ns".into(),
                    host: "reviews.ns.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "other-ns".into(),
                    namespace: "other".into(),
                    host: "reviews.other.svc.cluster.local".into(),
                    traffic_policy: None,
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let slice = MeshSlice::from_gateway_config(&cfg, slice_request("ns"));

        assert_eq!(slice.destination_rules.len(), 1);
        assert_eq!(slice.destination_rules[0].namespace, "ns");
        assert_eq!(slice.destination_rules[0].name, "in-ns");
    }

    fn pa(
        name: &str,
        namespace: &str,
        selector: Option<WorkloadSelector>,
        mode: MtlsMode,
        port_overrides: HashMap<u16, MtlsMode>,
    ) -> PeerAuthentication {
        PeerAuthentication {
            name: name.to_string(),
            namespace: namespace.to_string(),
            scope: None,
            selector,
            mtls_mode: mode,
            port_overrides,
        }
    }

    fn pa_with_scope(
        name: &str,
        namespace: &str,
        scope: PolicyScope,
        mode: MtlsMode,
    ) -> PeerAuthentication {
        let selector = match &scope {
            PolicyScope::WorkloadSelector { selector } => Some(selector.clone()),
            PolicyScope::MeshWide | PolicyScope::Namespace { .. } => None,
        };
        PeerAuthentication {
            name: name.to_string(),
            namespace: namespace.to_string(),
            scope: Some(scope),
            selector,
            mtls_mode: mode,
            port_overrides: HashMap::new(),
        }
    }

    // ── MeshProxyConfig slice/resolution tests ──────────────────────────

    fn make_proxy_config(
        name: &str,
        namespace: &str,
        selector_labels: HashMap<String, String>,
        tracing_sampling: Option<f64>,
    ) -> MeshProxyConfig {
        let scope = if selector_labels.is_empty() {
            PolicyScope::Namespace {
                namespace: namespace.into(),
            }
        } else {
            PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: selector_labels,
                    namespace: Some(namespace.into()),
                },
            }
        };
        MeshProxyConfig {
            name: name.into(),
            namespace: namespace.into(),
            scope,
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling,
        }
    }

    fn make_mesh_wide_proxy_config(
        name: &str,
        namespace: &str,
        tracing_sampling: Option<f64>,
    ) -> MeshProxyConfig {
        MeshProxyConfig {
            name: name.into(),
            namespace: namespace.into(),
            scope: PolicyScope::MeshWide,
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling,
        }
    }

    fn make_mesh_wide_selector_proxy_config(
        name: &str,
        namespace: &str,
        labels: HashMap<String, String>,
        tracing_sampling: Option<f64>,
    ) -> MeshProxyConfig {
        MeshProxyConfig {
            name: name.into(),
            namespace: namespace.into(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels,
                    namespace: None,
                },
            },
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling,
        }
    }

    #[test]
    fn no_peer_auth_defaults_to_permissive() {
        let mode =
            resolve_effective_mtls_mode(&[], "default", &HashMap::<String, String>::new(), 8080);
        assert_eq!(mode, MtlsMode::Permissive);
    }

    #[test]
    fn single_namespace_scoped_policy() {
        let policies = vec![pa(
            "ns-strict",
            "default",
            None,
            MtlsMode::Strict,
            HashMap::new(),
        )];
        let mode = resolve_effective_mtls_mode(
            &policies,
            "default",
            &HashMap::<String, String>::new(),
            8080,
        );
        assert_eq!(mode, MtlsMode::Strict);
    }

    #[test]
    fn workload_selector_beats_namespace_scope() {
        let policies = vec![
            pa(
                "ns-strict",
                "default",
                None,
                MtlsMode::Strict,
                HashMap::new(),
            ),
            pa(
                "wl-permissive",
                "default",
                Some(WorkloadSelector {
                    labels: HashMap::from([("app".into(), "web".into())]),
                    namespace: None,
                }),
                MtlsMode::Permissive,
                HashMap::new(),
            ),
        ];
        let labels = HashMap::from([("app".to_string(), "web".to_string())]);
        let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
        assert_eq!(mode, MtlsMode::Permissive);
    }

    #[test]
    fn namespace_scope_beats_mesh_wide_when_both_selector_none() {
        let policies = vec![
            pa_with_scope(
                "mesh-wide",
                "istio-system",
                PolicyScope::MeshWide,
                MtlsMode::Disable,
            ),
            pa_with_scope(
                "ns-strict",
                "default",
                PolicyScope::Namespace {
                    namespace: "default".to_string(),
                },
                MtlsMode::Strict,
            ),
        ];
        let mode = resolve_effective_mtls_mode(
            &policies,
            "default",
            &HashMap::<String, String>::new(),
            8080,
        );
        assert_eq!(mode, MtlsMode::Strict);
    }

    #[test]
    fn mesh_slice_carries_mesh_wide_peer_auth_to_workload_namespace() {
        let mut config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                peer_authentications: vec![pa_with_scope(
                    "mesh-strict",
                    "istio-system",
                    PolicyScope::MeshWide,
                    MtlsMode::Strict,
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        config.loaded_at = chrono::Utc::now();

        let slice = MeshSlice::from_gateway_config(
            &config,
            MeshSliceRequest {
                node_id: "node-a".to_string(),
                namespace: "default".to_string(),
                workload_spiffe_id: None,
                labels: BTreeMap::new(),
            },
        );

        assert_eq!(slice.peer_authentications.len(), 1);
        assert_eq!(slice.resolve_effective_mtls_mode(8080), MtlsMode::Strict);
    }

    #[test]
    fn port_override_within_winning_policy() {
        let policies = vec![pa(
            "ns-strict",
            "default",
            None,
            MtlsMode::Strict,
            HashMap::from([(8080, MtlsMode::Disable)]),
        )];
        // Port 8080 has an override to Disable.
        let mode = resolve_effective_mtls_mode(
            &policies,
            "default",
            &HashMap::<String, String>::new(),
            8080,
        );
        assert_eq!(mode, MtlsMode::Disable);

        // Port 443 uses the top-level mode.
        let mode = resolve_effective_mtls_mode(
            &policies,
            "default",
            &HashMap::<String, String>::new(),
            443,
        );
        assert_eq!(mode, MtlsMode::Strict);
    }

    #[test]
    fn port_override_only_applies_to_winning_policy() {
        // Namespace policy has port override, but workload-selector policy
        // wins and has no override for the port.
        let policies = vec![
            pa(
                "ns-policy",
                "default",
                None,
                MtlsMode::Strict,
                HashMap::from([(8080, MtlsMode::Disable)]),
            ),
            pa(
                "wl-policy",
                "default",
                Some(WorkloadSelector {
                    labels: HashMap::from([("app".into(), "api".into())]),
                    namespace: None,
                }),
                MtlsMode::Permissive,
                HashMap::new(),
            ),
        ];
        let labels = HashMap::from([("app".to_string(), "api".to_string())]);
        // Workload selector wins; port 8080 has no override in winning policy.
        let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
        assert_eq!(mode, MtlsMode::Permissive);
    }

    #[test]
    fn wrong_namespace_is_ignored() {
        let policies = vec![pa(
            "other-ns",
            "production",
            None,
            MtlsMode::Strict,
            HashMap::new(),
        )];
        let mode = resolve_effective_mtls_mode(
            &policies,
            "default",
            &HashMap::<String, String>::new(),
            8080,
        );
        assert_eq!(mode, MtlsMode::Permissive);
    }

    #[test]
    fn selector_labels_must_match() {
        let policies = vec![pa(
            "wl-strict",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "web".into())]),
                namespace: None,
            }),
            MtlsMode::Strict,
            HashMap::new(),
        )];
        // Labels don't match.
        let labels = HashMap::from([("app".to_string(), "api".to_string())]);
        let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
        assert_eq!(mode, MtlsMode::Permissive);
    }

    #[test]
    fn mesh_slice_resolve_delegates_correctly() {
        let slice = MeshSlice {
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "web".to_string())]),
            peer_authentications: vec![
                pa(
                    "ns-disable",
                    "default",
                    None,
                    MtlsMode::Disable,
                    HashMap::new(),
                ),
                pa(
                    "wl-strict",
                    "default",
                    Some(WorkloadSelector {
                        labels: HashMap::from([("app".into(), "web".into())]),
                        namespace: None,
                    }),
                    MtlsMode::Strict,
                    HashMap::from([(443, MtlsMode::Permissive)]),
                ),
            ],
            ..MeshSlice::default()
        };
        // Workload selector wins (Strict), port 8080 has no override.
        assert_eq!(slice.resolve_effective_mtls_mode(8080), MtlsMode::Strict);
        // Port 443 has an override to Permissive in the winning policy.
        assert_eq!(slice.resolve_effective_mtls_mode(443), MtlsMode::Permissive);
    }

    #[test]
    fn classify_peer_auth_scope_ordering() {
        assert!(PeerAuthScope::WorkloadSelector > PeerAuthScope::Namespace);
        assert!(PeerAuthScope::Namespace > PeerAuthScope::MeshWide);
    }

    #[test]
    fn proxy_configs_filter_by_namespace_and_selector() {
        let mesh = MeshConfig {
            proxy_configs: vec![
                // In-namespace, no selector — applies to any workload in ns
                make_proxy_config("ns-default", "ns", HashMap::new(), Some(10.0)),
                // In-namespace, selector matches
                make_proxy_config(
                    "api-only",
                    "ns",
                    HashMap::from([("app".into(), "api".into())]),
                    Some(50.0),
                ),
                // In-namespace, selector does NOT match
                make_proxy_config(
                    "worker-only",
                    "ns",
                    HashMap::from([("app".into(), "worker".into())]),
                    Some(75.0),
                ),
                // Different namespace — filtered out
                make_proxy_config("other-ns", "other", HashMap::new(), Some(99.0)),
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request =
            slice_request_with_labels("ns", BTreeMap::from([("app".into(), "api".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert_eq!(slice.proxy_configs.len(), 2);
        let names: Vec<&str> = slice
            .proxy_configs
            .iter()
            .map(|pc| pc.name.as_str())
            .collect();
        assert!(names.contains(&"ns-default"));
        assert!(names.contains(&"api-only"));
    }

    #[test]
    fn resolved_proxy_config_prefers_workload_selector_over_namespace_default() {
        let mesh = MeshConfig {
            proxy_configs: vec![
                make_proxy_config("ns-default", "ns", HashMap::new(), Some(10.0)),
                make_proxy_config(
                    "api-only",
                    "ns",
                    HashMap::from([("app".into(), "api".into())]),
                    Some(50.0),
                ),
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request =
            slice_request_with_labels("ns", BTreeMap::from([("app".into(), "api".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(resolved.name, "api-only");
        assert_eq!(resolved.tracing_sampling, Some(50.0));
    }

    #[test]
    fn resolved_proxy_config_returns_none_when_no_match() {
        let mesh = MeshConfig {
            proxy_configs: vec![make_proxy_config(
                "api-only",
                "ns",
                HashMap::from([("app".into(), "api".into())]),
                Some(50.0),
            )],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request =
            slice_request_with_labels("ns", BTreeMap::from([("app".into(), "worker".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert!(slice.proxy_configs.is_empty());
        assert!(slice.resolved_proxy_config().is_none());
    }

    #[test]
    fn resolved_proxy_config_ascii_smallest_name_breaks_tie() {
        // Two workload-scoped ProxyConfigs that both match: tiebreaker must
        // be deterministic on the ASCII-smallest name.
        let mesh = MeshConfig {
            proxy_configs: vec![
                make_proxy_config(
                    "zzz-late",
                    "ns",
                    HashMap::from([("app".into(), "api".into())]),
                    Some(99.0),
                ),
                make_proxy_config(
                    "aaa-early",
                    "ns",
                    HashMap::from([("app".into(), "api".into())]),
                    Some(5.0),
                ),
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request =
            slice_request_with_labels("ns", BTreeMap::from([("app".into(), "api".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        // Both apply.
        assert_eq!(slice.proxy_configs.len(), 2);
        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(resolved.name, "aaa-early");
        assert_eq!(resolved.tracing_sampling, Some(5.0));
    }

    #[test]
    fn content_eq_detects_proxy_configs_change() {
        let a = MeshSlice {
            proxy_configs: vec![make_proxy_config("p1", "ns", HashMap::new(), Some(10.0))],
            ..MeshSlice::default()
        };
        let mut b = a.clone();
        b.proxy_configs
            .push(make_proxy_config("p2", "ns", HashMap::new(), Some(50.0)));
        assert!(
            !a.content_eq(&b),
            "proxy_configs difference should be detected"
        );
    }

    #[test]
    fn mesh_wide_proxy_config_applies_across_namespaces() {
        // A MeshWide ProxyConfig (Istio root-namespace pattern with no
        // selector) must apply to workloads in any namespace, not just
        // the resource's own namespace.
        let mesh = MeshConfig {
            proxy_configs: vec![make_mesh_wide_proxy_config(
                "mesh-default",
                "istio-system",
                Some(10.0),
            )],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        // Workload lives in "team-a", not the resource's "istio-system".
        let request = slice_request_with_labels("team-a", BTreeMap::new());
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert_eq!(slice.proxy_configs.len(), 1);
        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(resolved.tracing_sampling, Some(10.0));
    }

    #[test]
    fn mesh_wide_selector_proxy_config_applies_across_namespaces() {
        // A root-namespace ProxyConfig with a selector applies to matching
        // workloads in any namespace (PolicyScope::WorkloadSelector with
        // namespace=None).
        let mesh = MeshConfig {
            proxy_configs: vec![make_mesh_wide_selector_proxy_config(
                "mesh-api",
                "istio-system",
                HashMap::from([("app".into(), "api".into())]),
                Some(80.0),
            )],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        // Workload in "team-a" with matching label.
        let request =
            slice_request_with_labels("team-a", BTreeMap::from([("app".into(), "api".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert_eq!(slice.proxy_configs.len(), 1);
        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(resolved.tracing_sampling, Some(80.0));
    }

    #[test]
    fn namespace_scoped_proxy_config_overrides_mesh_wide_default() {
        // Workload-applicable Namespace-scoped ProxyConfig must outrank a
        // MeshWide default when both apply (specificity ordering).
        let mesh = MeshConfig {
            proxy_configs: vec![
                make_mesh_wide_proxy_config("zzz-mesh-default", "istio-system", Some(10.0)),
                make_proxy_config("ns-override", "ns", HashMap::new(), Some(50.0)),
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request = slice_request_with_labels("ns", BTreeMap::new());
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert_eq!(slice.proxy_configs.len(), 2);
        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(
            resolved.name, "ns-override",
            "Namespace-scoped must outrank MeshWide default"
        );
        assert_eq!(resolved.tracing_sampling, Some(50.0));
    }

    #[test]
    fn workload_selector_outranks_mesh_wide_default() {
        // WorkloadSelector beats MeshWide even when both match.
        let mesh = MeshConfig {
            proxy_configs: vec![
                make_mesh_wide_proxy_config("aaa-mesh-default", "istio-system", Some(10.0)),
                make_proxy_config(
                    "zzz-workload",
                    "ns",
                    HashMap::from([("app".into(), "api".into())]),
                    Some(90.0),
                ),
            ],
            ..MeshConfig::default()
        };
        let cfg = config_with_mesh(mesh);
        let request =
            slice_request_with_labels("ns", BTreeMap::from([("app".into(), "api".into())]));
        let slice = MeshSlice::from_gateway_config(&cfg, request);

        assert_eq!(slice.proxy_configs.len(), 2);
        let resolved = slice.resolved_proxy_config().expect("resolved present");
        assert_eq!(resolved.name, "zzz-workload");
        assert_eq!(resolved.tracing_sampling, Some(90.0));
    }

    // ── Outbound registry builder ─────────────────────────────────────────

    #[test]
    fn build_known_destinations_emits_service_forms_and_ports() {
        use crate::modes::mesh::config::AppProtocol;

        let slice = MeshSlice {
            services: vec![MeshService {
                name: "reviews".into(),
                namespace: "default".into(),
                ports: vec![crate::modes::mesh::config::ServicePort {
                    port: 8080,
                    protocol: AppProtocol::Http,
                    name: Some("http".into()),
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("cluster.local");
        assert!(entries.contains(&"reviews".to_string()));
        assert!(entries.contains(&"reviews.default".to_string()));
        assert!(entries.contains(&"reviews.default.svc.cluster.local".to_string()));
        assert!(entries.contains(&"reviews.default.svc.cluster.local:8080".to_string()));
        assert!(entries.contains(&"reviews.default:8080".to_string()));
    }

    #[test]
    fn build_known_destinations_includes_service_entries() {
        use crate::modes::mesh::config::{
            AppProtocol, MeshEndpoint, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
        };

        let slice = MeshSlice {
            service_entries: vec![ServiceEntry {
                name: "external-api".into(),
                namespace: "default".into(),
                hosts: vec!["api.example.com".into()],
                endpoints: vec![MeshEndpoint {
                    address: "10.0.0.1".into(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                }],
                resolution: Resolution::Static,
                location: ServiceEntryLocation::MeshExternal,
                ports: vec![ServicePort {
                    port: 443,
                    protocol: AppProtocol::Tls,
                    name: Some("https".into()),
                }],
                export_to: Vec::new(),
                workload_selector: None,
            }],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("cluster.local");
        assert!(entries.contains(&"api.example.com".to_string()));
        assert!(entries.contains(&"api.example.com:443".to_string()));
    }

    #[test]
    fn build_known_destinations_is_sorted_and_deduplicated() {
        use crate::modes::mesh::config::{AppProtocol, ServicePort};

        let slice = MeshSlice {
            services: vec![
                MeshService {
                    name: "zzz".into(),
                    namespace: "default".into(),
                    ports: vec![ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: None,
                    }],
                    workloads: Vec::new(),
                    protocol_overrides: HashMap::new(),
                },
                MeshService {
                    name: "aaa".into(),
                    namespace: "default".into(),
                    ports: vec![ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: None,
                    }],
                    workloads: Vec::new(),
                    protocol_overrides: HashMap::new(),
                },
            ],
            ..MeshSlice::default()
        };

        let entries = slice.build_known_destinations("cluster.local");
        let aaa_idx = entries.iter().position(|e| e == "aaa").expect("aaa");
        let zzz_idx = entries.iter().position(|e| e == "zzz").expect("zzz");
        assert!(aaa_idx < zzz_idx, "entries must be sorted alphabetically");
        // No duplicates (HashSet → Vec)
        let mut dedup = entries.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), entries.len());
    }
}
