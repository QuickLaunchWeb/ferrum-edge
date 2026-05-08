//! Internal mesh data model (Layer 2 of the mesh expansion).
//!
//! These types deliberately mirror Istio CRD vocabulary so the Phase B/C
//! translation layer can be near-1:1. Every type carries `#[serde(default)]`
//! on optional collections and `skip_serializing_if` on `Option`/`Vec` so
//! that a non-mesh `GatewayConfig` round-trips byte-identical (no extra
//! keys appear in the serialised JSON / YAML).
//!
//! All types are namespace-scoped (`namespace: String`) — same convention
//! as `Proxy`, `Consumer`, `Upstream` in [`crate::config::types`]. The
//! mesh subsystem will share the same `FERRUM_NAMESPACE` mechanism so a
//! single gateway instance only loads its own namespace's mesh resources.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::identity::spiffe::{SpiffeId, TrustDomain};
use crate::identity::{JwtAuthority as IdentityJwtAuthority, TrustBundle as IdentityTrustBundle};

/// Application-layer protocol classification for mesh ports.
///
/// Mirrors Istio's `appProtocol` field on `Service` ports + endpoints. Phase
/// A serialises lowercase ("http", "http2", "grpc", "tcp", "tls", "mongo",
/// "redis", "mysql", "postgres", "unknown").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppProtocol {
    Http,
    Http2,
    Grpc,
    Tcp,
    Tls,
    Mongo,
    Redis,
    Mysql,
    Postgres,
    #[default]
    Unknown,
}

// ── Workload ──────────────────────────────────────────────────────────────

/// A single workload registered with the mesh.
///
/// `Workload` is the unit of identity — every SVID is issued to one workload.
/// The `selector` describes how the workload is matched at attestation time
/// (K8s labels, VM tags, or static), the `service_name` is the logical
/// service it participates in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Workload {
    pub spiffe_id: SpiffeId,
    pub selector: WorkloadSelector,
    pub service_name: String,
    /// Workload IPs or DNS names. Istio `WorkloadEntry.address` maps here;
    /// K8s pod IPs land here once the reconciler wires pod watching.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<WorkloadPort>,
    pub trust_domain: TrustDomain,
    pub namespace: String,
    /// Istio network label for multi-network routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Cluster name for CP-to-CP exchange and VM workloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}

/// A port advertised by a workload.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadPort {
    pub port: u16,
    #[serde(default)]
    pub protocol: AppProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Selector for workload matching. Empty `labels` matches any workload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadSelector {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

// ── MeshService ───────────────────────────────────────────────────────────

/// A logical service. Workloads are referenced by SPIFFE ID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshService {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ServicePort>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<WorkloadRef>,
    /// Per-port overrides for service-level protocol classification.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub protocol_overrides: HashMap<u16, AppProtocol>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServicePort {
    pub port: u16,
    #[serde(default)]
    pub protocol: AppProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadRef {
    pub spiffe_id: SpiffeId,
}

// ── MeshPolicy ────────────────────────────────────────────────────────────

/// Identity-based authorization policy. Mirrors Istio AuthorizationPolicy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshPolicy {
    pub name: String,
    pub namespace: String,
    pub scope: PolicyScope,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<MeshRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyScope {
    WorkloadSelector { selector: WorkloadSelector },
    Namespace { namespace: String },
    MeshWide,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshRule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<PrincipalMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<RequestMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<ConditionMatch>,
    /// Synthetic marker for rules that should affect policy accounting but
    /// never match traffic, e.g. Istio ALLOW-without-rules allow-nothing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub never_matches: bool,
    #[serde(default)]
    pub action: PolicyAction,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    #[default]
    Allow,
    Deny,
    Audit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalMatch {
    /// Glob pattern over SPIFFE IDs, e.g. `spiffe://prod/ns/foo/sa/*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id_pattern: Option<String>,
    /// Glob pattern over workload namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_pattern: Option<String>,
    /// Restrict matches to a specific trust domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TrustDomain>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RequestMatch {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Glob path patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Glob host patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Header name → glob value pattern.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Glob port patterns, used for Istio string-match ports such as "*".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConditionMatch {
    pub key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_values: Vec<String>,
}

/// Abstraction over per-workload label maps.
///
/// `mesh_authz` carries labels in a `BTreeMap<String, String>` (the
/// canonical [`crate::modes::mesh::slice::MeshSlice`] form), the Kubernetes injector
/// keeps them in a `HashMap`, and tests freely build either. This trait lets
/// the scope-matching helpers below accept any of those without copying.
pub trait WorkloadLabels {
    fn lookup(&self, key: &str) -> Option<&str>;
}

impl<S: ::std::hash::BuildHasher> WorkloadLabels for HashMap<String, String, S> {
    #[inline]
    fn lookup(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

impl WorkloadLabels for ::std::collections::BTreeMap<String, String> {
    #[inline]
    fn lookup(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

/// Returns `true` when `policy.scope` applies to a workload whose namespace is
/// `proxy_namespace` and whose labels are `proxy_labels`.
///
/// This is the **single canonical scope-matching helper** used by both the
/// xDS / native MeshSubscribe slice builder ([`crate::modes::mesh::slice::MeshSlice::from_gateway_config`])
/// and the `mesh_authz` plugin's per-policy filter so that scope semantics
/// stay byte-identical across the two surfaces.
///
/// Semantics:
/// - [`PolicyScope::MeshWide`] — applies to every workload.
/// - [`PolicyScope::Namespace`] — applies iff `proxy_namespace == policy.scope.namespace`.
/// - [`PolicyScope::WorkloadSelector`] — applies iff (a) the selector's
///   namespace is unset or equal to `proxy_namespace` AND (b) every
///   `(key, value)` in `selector.labels` is present in `proxy_labels` with the
///   same value (subset match — empty selector labels means "any workload in
///   the optional namespace").
pub fn policy_scope_applies_to_workload<L: WorkloadLabels + ?Sized>(
    policy: &MeshPolicy,
    proxy_namespace: &str,
    proxy_labels: &L,
) -> bool {
    match &policy.scope {
        PolicyScope::MeshWide => true,
        PolicyScope::Namespace {
            namespace: policy_namespace,
        } => policy_namespace == proxy_namespace,
        PolicyScope::WorkloadSelector { selector } => {
            workload_selector_matches(selector, proxy_namespace, proxy_labels)
        }
    }
}

/// Returns `true` when a [`WorkloadSelector`] matches a workload whose
/// namespace is `proxy_namespace` and whose labels are `proxy_labels`. Same
/// shape as [`policy_scope_applies_to_workload`]; lifted so PeerAuthentication
/// selector matching shares the same predicate.
pub fn workload_selector_matches<L: WorkloadLabels + ?Sized>(
    selector: &WorkloadSelector,
    proxy_namespace: &str,
    proxy_labels: &L,
) -> bool {
    if let Some(selector_namespace) = selector.namespace.as_ref()
        && selector_namespace != proxy_namespace
    {
        return false;
    }
    selector
        .labels
        .iter()
        .all(|(key, value)| proxy_labels.lookup(key) == Some(value.as_str()))
}

// ── PeerAuthentication ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerAuthentication {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<WorkloadSelector>,
    #[serde(default)]
    pub mtls_mode: MtlsMode,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub port_overrides: HashMap<u16, MtlsMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MtlsMode {
    Strict,
    #[default]
    Permissive,
    Disable,
}

// ── ServiceEntry ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    pub namespace: String,
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<MeshEndpoint>,
    #[serde(default)]
    pub resolution: Resolution,
    #[serde(default)]
    pub location: ServiceEntryLocation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ServicePort>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Dns,
    Static,
    #[default]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceEntryLocation {
    #[default]
    MeshExternal,
    MeshInternal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshEndpoint {
    pub address: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub ports: HashMap<String, u16>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

// ── Trust bundles ─────────────────────────────────────────────────────────

/// Full trust-bundle set carried in `GatewayConfig`. Mirrors
/// [`crate::identity::TrustBundleSet`] in shape, but uses serialisable
/// representations so the config can be persisted to file/DB.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustBundleSet {
    pub local: TrustBundle,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub federated: Vec<TrustBundle>,
}

/// Persistable trust bundle. `x509_authorities` is a list of base64-encoded
/// DER blobs; `jwt_authorities` is a flat list. Both are intentionally
/// serialisation-friendly (no `Vec<u8>` raw bytes) so YAML/JSON output
/// stays human-readable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustBundle {
    pub trust_domain: TrustDomain,
    /// Base64-encoded DER certificates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x509_authorities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jwt_authorities: Vec<JwtAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_hint_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtAuthority {
    pub key_id: String,
    pub public_key_pem: String,
}

impl TrustBundle {
    /// Decode the base64 authorities into raw DER, suitable for handing to
    /// the runtime [`crate::identity::TrustBundle`]. Returns the list of
    /// bytes or an error on the first malformed entry.
    pub fn decode_x509_authorities(&self) -> Result<Vec<Vec<u8>>, String> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        self.x509_authorities
            .iter()
            .enumerate()
            .map(|(i, s)| {
                engine
                    .decode(s.as_bytes())
                    .map_err(|e| format!("x509_authorities[{}]: invalid base64: {}", i, e))
            })
            .collect()
    }

    /// Convert this serialisable bundle into a runtime
    /// [`crate::identity::TrustBundle`] (DER-decoded).
    pub fn to_runtime(&self) -> Result<IdentityTrustBundle, String> {
        Ok(IdentityTrustBundle {
            trust_domain: self.trust_domain.clone(),
            x509_authorities: self.decode_x509_authorities()?,
            jwt_authorities: self
                .jwt_authorities
                .iter()
                .map(|a| IdentityJwtAuthority {
                    key_id: a.key_id.clone(),
                    public_key_pem: a.public_key_pem.clone(),
                })
                .collect(),
            refresh_hint_seconds: self.refresh_hint_seconds,
        })
    }
}

impl TrustBundleSet {
    /// Convenience: build a runtime [`crate::identity::TrustBundleSet`].
    pub fn to_runtime(&self) -> Result<crate::identity::TrustBundleSet, String> {
        let local = self.local.to_runtime()?;
        let mut federated = std::collections::HashMap::new();
        for tb in &self.federated {
            let runtime = tb.to_runtime()?;
            federated.insert(runtime.trust_domain.clone(), runtime);
        }
        Ok(crate::identity::TrustBundleSet { local, federated })
    }
}

// ── Multi-cluster ────────────────────────────────────────────────────────

/// Layer-10 multi-cluster mesh settings.
///
/// This is intentionally control-plane neutral. Istio CRDs, Gateway API,
/// native ConfigSync, xDS, file mode, and future CP-to-CP exchange all carry
/// the same canonical shape instead of talking past Layer 2.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MultiClusterConfig {
    /// Operator-facing name for the local cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_cluster: Option<String>,
    /// SPIFFE federation endpoint served by this control plane, when Ferrum
    /// is publishing bundles to remote clusters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_endpoint: Option<String>,
    /// Remote clusters whose services/workloads/bundles may be exchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_clusters: Vec<RemoteCluster>,
    /// SNI-routed east-west gateway backends. Mesh mode materializes these as
    /// passthrough TCP proxies only when topology is `east_west_gateway`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub east_west_gateways: Vec<EastWestGateway>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteCluster {
    pub name: String,
    pub trust_domain: TrustDomain,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_endpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EastWestGateway {
    pub name: String,
    pub namespace: String,
    /// Backend host to which the east-west gateway forwards matched SNI.
    pub host: String,
    /// Backend port on `host`.
    pub port: u16,
    /// TLS SNI hosts routed through this gateway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sni_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TrustDomain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

// ── Top-level mesh config container ───────────────────────────────────────

/// All mesh-specific configuration, kept in a single container so the
/// core `GatewayConfig` struct stays lean for non-mesh deployments.
/// Stored as `Option<Box<MeshConfig>>` on `GatewayConfig` — `None` when
/// the operator has no mesh resources, zero cost in that case.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshConfig {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_cluster: Option<MultiClusterConfig>,
}

impl MeshConfig {
    pub fn validate(&self) -> Vec<String> {
        validate_mesh_config_internal(
            &self.workloads,
            &self.services,
            &self.mesh_policies,
            &self.peer_authentications,
            &self.service_entries,
            self.trust_bundles.as_ref(),
            self.multi_cluster.as_ref(),
        )
    }

    pub fn normalize(&mut self) {
        normalize_mesh_fields_internal(
            &mut self.service_entries,
            &mut self.workloads,
            &mut self.mesh_policies,
            self.multi_cluster.as_mut(),
        );
    }
}

// ── Validation ────────────────────────────────────────────────────────────

/// Validate the mesh portion of a [`crate::config::types::GatewayConfig`].
///
/// Errors are returned as a flat `Vec<String>` so the file/DB/DP modes can
/// dispatch them per their own error-handling policy (file = fatal, DB =
/// warn, DP = reject update).
pub fn validate_mesh_config(
    workloads: &[Workload],
    services: &[MeshService],
    policies: &[MeshPolicy],
    peer_auths: &[PeerAuthentication],
    service_entries: &[ServiceEntry],
    trust_bundles: Option<&TrustBundleSet>,
) -> Vec<String> {
    validate_mesh_config_internal(
        workloads,
        services,
        policies,
        peer_auths,
        service_entries,
        trust_bundles,
        None,
    )
}

fn validate_mesh_config_internal(
    workloads: &[Workload],
    services: &[MeshService],
    policies: &[MeshPolicy],
    peer_auths: &[PeerAuthentication],
    service_entries: &[ServiceEntry],
    trust_bundles: Option<&TrustBundleSet>,
    multi_cluster: Option<&MultiClusterConfig>,
) -> Vec<String> {
    let mut errors = Vec::new();

    // Workloads
    for wl in workloads {
        if wl.spiffe_id.trust_domain() != &wl.trust_domain {
            errors.push(format!(
                "Workload '{}': spiffe_id trust domain '{}' does not match \
                 workload's trust_domain '{}'",
                wl.spiffe_id,
                wl.spiffe_id.trust_domain(),
                wl.trust_domain
            ));
        }
        if wl.namespace.is_empty() {
            errors.push(format!(
                "Workload '{}': namespace must not be empty",
                wl.spiffe_id
            ));
        }
        if wl.service_name.is_empty() {
            errors.push(format!(
                "Workload '{}': service_name must not be empty",
                wl.spiffe_id
            ));
        }
        for (i, address) in wl.addresses.iter().enumerate() {
            if address.trim().is_empty() {
                errors.push(format!(
                    "Workload '{}'.addresses[{}]: address must not be empty",
                    wl.spiffe_id, i
                ));
            }
        }
        if wl
            .network
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "Workload '{}': network must not be empty when set",
                wl.spiffe_id
            ));
        }
        if wl
            .cluster
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "Workload '{}': cluster must not be empty when set",
                wl.spiffe_id
            ));
        }
    }

    // Services
    for svc in services {
        if svc.name.is_empty() {
            errors.push("MeshService: name must not be empty".to_string());
        }
        if svc.namespace.is_empty() {
            errors.push(format!(
                "MeshService '{}': namespace must not be empty",
                svc.name
            ));
        }
    }

    // Policies
    for policy in policies {
        if policy.name.is_empty() {
            errors.push("MeshPolicy: name must not be empty".to_string());
        }
        for (i, rule) in policy.rules.iter().enumerate() {
            for (j, principal) in rule.from.iter().enumerate() {
                if principal.spiffe_id_pattern.is_none()
                    && principal.namespace_pattern.is_none()
                    && principal.trust_domain.is_none()
                {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].from[{}]: at least one \
                         of spiffe_id_pattern/namespace_pattern/trust_domain \
                         must be set",
                        policy.name, i, j
                    ));
                }
                if let Some(pat) = principal.spiffe_id_pattern.as_ref()
                    && let Err(e) = glob::Pattern::new(pat)
                {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].from[{}].spiffe_id_pattern \
                         '{}' is not a valid glob: {}",
                        policy.name, i, j, pat, e
                    ));
                }
                if let Some(pat) = principal.namespace_pattern.as_ref()
                    && let Err(e) = glob::Pattern::new(pat)
                {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].from[{}].namespace_pattern \
                         '{}' is not a valid glob: {}",
                        policy.name, i, j, pat, e
                    ));
                }
            }
            for (j, request) in rule.to.iter().enumerate() {
                let any_method = !request.methods.is_empty();
                let any_path = !request.paths.is_empty();
                let any_host = !request.hosts.is_empty();
                let any_header = !request.headers.is_empty();
                let any_port = !request.ports.is_empty() || !request.port_patterns.is_empty();
                if !(any_method || any_path || any_host || any_header || any_port) {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].to[{}]: at least one of \
                         methods/paths/hosts/headers/ports must be non-empty",
                        policy.name, i, j
                    ));
                }
                for (k, host) in request.hosts.iter().enumerate() {
                    if !is_valid_request_match_host_pattern(host) {
                        errors.push(format!(
                            "MeshPolicy '{}'.rules[{}].to[{}].hosts[{}] \
                             '{}' is not a valid host pattern \
                             (expected hostname, [ipv6], or host:port/host:* \
                             with u16 numeric or '*' port)",
                            policy.name, i, j, k, host
                        ));
                    }
                }
                for (k, pattern) in request.port_patterns.iter().enumerate() {
                    if !is_valid_request_match_port_pattern(pattern) {
                        errors.push(format!(
                            "MeshPolicy '{}'.rules[{}].to[{}].port_patterns[{}] \
                             '{}' is not a valid port pattern \
                             (expected '*', '<digits>*', or '*<digits>')",
                            policy.name, i, j, k, pattern
                        ));
                    }
                }
            }
        }
    }

    // PeerAuthentications
    for pa in peer_auths {
        if pa.name.is_empty() {
            errors.push("PeerAuthentication: name must not be empty".to_string());
        }
        if pa.namespace.is_empty() {
            errors.push(format!(
                "PeerAuthentication '{}': namespace must not be empty",
                pa.name
            ));
        }
    }

    // ServiceEntries
    for se in service_entries {
        if se.name.is_empty() {
            errors.push("ServiceEntry: name must not be empty".to_string());
        }
        if se.hosts.is_empty() {
            errors.push(format!(
                "ServiceEntry '{}': hosts must not be empty",
                se.name
            ));
        }
        if se.resolution != Resolution::Static && !se.endpoints.is_empty() {
            errors.push(format!(
                "ServiceEntry '{}': endpoints are only valid when resolution=static",
                se.name
            ));
        }
    }

    // Trust bundles
    if let Some(tb_set) = trust_bundles {
        if tb_set.local.x509_authorities.is_empty() && tb_set.local.jwt_authorities.is_empty() {
            errors.push(format!(
                "TrustBundleSet.local for trust domain '{}' has no authorities",
                tb_set.local.trust_domain
            ));
        }
        if let Err(e) = tb_set.local.decode_x509_authorities() {
            errors.push(format!("TrustBundleSet.local: {e}"));
        }
        let mut seen_trust_domains = HashSet::from([tb_set.local.trust_domain.clone()]);
        for fed in &tb_set.federated {
            if !seen_trust_domains.insert(fed.trust_domain.clone()) {
                errors.push(format!(
                    "TrustBundleSet.federated[{}]: duplicate trust domain",
                    fed.trust_domain
                ));
            }
            if fed.x509_authorities.is_empty() && fed.jwt_authorities.is_empty() {
                errors.push(format!(
                    "TrustBundleSet.federated[{}]: no authorities",
                    fed.trust_domain
                ));
            }
            if let Err(e) = fed.decode_x509_authorities() {
                errors.push(format!(
                    "TrustBundleSet.federated[{}]: {e}",
                    fed.trust_domain
                ));
            }
        }
    }

    if let Some(multi_cluster) = multi_cluster {
        validate_multi_cluster(multi_cluster, trust_bundles, &mut errors);
    }

    errors
}

fn validate_multi_cluster(
    multi_cluster: &MultiClusterConfig,
    trust_bundles: Option<&TrustBundleSet>,
    errors: &mut Vec<String>,
) {
    if multi_cluster
        .local_cluster
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        errors.push("MultiClusterConfig.local_cluster must not be empty when set".to_string());
    }
    if multi_cluster
        .federation_endpoint
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        errors
            .push("MultiClusterConfig.federation_endpoint must not be empty when set".to_string());
    }

    let mut seen_cluster_names = HashSet::new();
    for remote in &multi_cluster.remote_clusters {
        if remote.name.trim().is_empty() {
            errors.push("RemoteCluster: name must not be empty".to_string());
        } else if !seen_cluster_names.insert(remote.name.as_str()) {
            errors.push(format!("RemoteCluster '{}': duplicate name", remote.name));
        }
        if remote
            .network
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "RemoteCluster '{}': network must not be empty when set",
                remote.name
            ));
        }
        if remote
            .control_plane_url
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "RemoteCluster '{}': control_plane_url must not be empty when set",
                remote.name
            ));
        }
        if remote
            .federation_endpoint
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "RemoteCluster '{}': federation_endpoint must not be empty when set",
                remote.name
            ));
        }

        if let Some(tb_set) = trust_bundles
            && remote.trust_domain != tb_set.local.trust_domain
            && !tb_set
                .federated
                .iter()
                .any(|bundle| bundle.trust_domain == remote.trust_domain)
        {
            errors.push(format!(
                "RemoteCluster '{}': trust domain '{}' has no matching federated trust bundle",
                remote.name, remote.trust_domain
            ));
        }
    }

    let mut seen_sni_routes: HashSet<String> = HashSet::new();
    for gateway in &multi_cluster.east_west_gateways {
        if gateway.name.trim().is_empty() {
            errors.push("EastWestGateway: name must not be empty".to_string());
        }
        if gateway.namespace.trim().is_empty() {
            errors.push(format!(
                "EastWestGateway '{}': namespace must not be empty",
                gateway.name
            ));
        }
        if gateway.host.trim().is_empty() {
            errors.push(format!(
                "EastWestGateway '{}': host must not be empty",
                gateway.name
            ));
        }
        if gateway.port == 0 {
            errors.push(format!(
                "EastWestGateway '{}': port must be between 1 and 65535",
                gateway.name
            ));
        }
        if gateway.sni_hosts.is_empty() {
            errors.push(format!(
                "EastWestGateway '{}': sni_hosts must not be empty",
                gateway.name
            ));
        }
        if gateway
            .network
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "EastWestGateway '{}': network must not be empty when set",
                gateway.name
            ));
        }
        for sni in &gateway.sni_hosts {
            if sni.trim().is_empty() {
                errors.push(format!(
                    "EastWestGateway '{}': sni_hosts must not contain empty entries",
                    gateway.name
                ));
                continue;
            }
            if !seen_sni_routes.insert(sni.to_ascii_lowercase()) {
                errors.push(format!(
                    "EastWestGateway '{}': duplicate SNI host '{}'",
                    gateway.name, sni
                ));
            }
        }
    }
}

/// Lower-case in-place hostname normalisation for mesh entries — matches
/// the existing `normalize_fields()` pattern used elsewhere in
/// [`crate::config::types`]. Idempotent.
pub fn normalize_mesh_fields(service_entries: &mut [ServiceEntry], workloads: &mut [Workload]) {
    normalize_mesh_fields_internal(service_entries, workloads, &mut [], None);
}

fn normalize_mesh_fields_internal(
    service_entries: &mut [ServiceEntry],
    workloads: &mut [Workload],
    policies: &mut [MeshPolicy],
    multi_cluster: Option<&mut MultiClusterConfig>,
) {
    for se in service_entries {
        for host in &mut se.hosts {
            host.make_ascii_lowercase();
        }
        for ep in &mut se.endpoints {
            ep.address.make_ascii_lowercase();
        }
    }
    for workload in workloads {
        for address in &mut workload.addresses {
            address.make_ascii_lowercase();
        }
    }
    normalize_mesh_policy_fields(policies);
    if let Some(multi_cluster) = multi_cluster {
        for gateway in &mut multi_cluster.east_west_gateways {
            gateway.host.make_ascii_lowercase();
            for sni in &mut gateway.sni_hosts {
                sni.make_ascii_lowercase();
            }
        }
    }
}

fn normalize_mesh_policy_fields(policies: &mut [MeshPolicy]) {
    for policy in policies {
        for rule in &mut policy.rules {
            for request in &mut rule.to {
                for host in &mut request.hosts {
                    *host = normalize_request_match_host_pattern(host);
                }
                for pattern in &mut request.port_patterns {
                    let trimmed = pattern.trim();
                    if trimmed.len() != pattern.len() {
                        *pattern = trimmed.to_string();
                    }
                }
                normalize_mesh_policy_header_map(&mut request.headers);
            }
        }
    }
}

/// Normalise a `RequestMatch.hosts` glob pattern at config-load time so the
/// authorization hot path never re-normalises on every request.
///
/// Mirrors `normalize_match_host` for inbound request authorities so a pattern
/// `Example.COM:8443` and a request `example.com:8443` produce equal strings.
/// Lower-cases ASCII, strips a trailing dot from the host portion, and
/// preserves any explicit `:port` (or `:*`) suffix.
pub(crate) fn normalize_request_match_host_pattern(pattern: &str) -> String {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern.starts_with('[') {
        return pattern;
    }
    if let Some((name, port)) = pattern.rsplit_once(':')
        && !name.contains(':')
    {
        let name = name.strip_suffix('.').unwrap_or(name);
        return format!("{name}:{port}");
    }
    pattern
        .strip_suffix('.')
        .map(ToOwned::to_owned)
        .unwrap_or(pattern)
}

/// True when `pattern` is one of the three Istio-allowed port wildcard forms:
/// `*`, `<digits>*`, or `*<digits>`. Mirrors `is_istio_port_pattern` in the
/// Istio translator so direct-config and translated configs validate
/// identically.
pub(crate) fn is_valid_request_match_port_pattern(pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return !prefix.is_empty() && prefix.bytes().all(|byte| byte.is_ascii_digit());
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit());
    }
    false
}

/// True when `pattern` is a syntactically valid `RequestMatch.hosts` entry.
///
/// Accepts:
///   - bare hostname / glob (any chars except `:`, `@`)
///   - bracketed IPv6 literal `[...]`, optionally followed by `:port` or `:*`
///   - `host:port` or `host:*` where `host` has no other `:`
///
/// Rejects:
///   - empty / `@`-bearing values
///   - `host:abc` / `host:` (port is neither digits nor `*`)
///   - multiple `:` outside an IPv6 bracket
fn is_valid_request_match_host_pattern(pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern.contains('@') {
        return false;
    }
    if let Some(rest) = pattern.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return false;
        };
        if close == 0 {
            return false;
        }
        let suffix = &rest[close + 1..];
        return suffix.is_empty()
            || suffix
                .strip_prefix(':')
                .is_some_and(is_request_match_host_port_token);
    }
    match pattern.rsplit_once(':') {
        Some((name, port)) => {
            !name.is_empty() && !name.contains(':') && is_request_match_host_port_token(port)
        }
        None => true,
    }
}

fn is_request_match_host_port_token(token: &str) -> bool {
    if token == "*" {
        return true;
    }
    token.parse::<u16>().is_ok()
}

pub(crate) fn normalize_mesh_policy_header_map(headers: &mut HashMap<String, String>) {
    if headers
        .keys()
        .all(|key| key.bytes().all(|byte| !byte.is_ascii_uppercase()))
    {
        return;
    }

    let mut lowered = HashSet::with_capacity(headers.len());
    if headers
        .keys()
        .any(|key| !lowered.insert(key.to_ascii_lowercase()))
    {
        return;
    }

    *headers = headers
        .drain()
        .map(|(key, value)| (key.to_ascii_lowercase(), value))
        .collect();
}
