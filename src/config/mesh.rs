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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<WorkloadPort>,
    pub trust_domain: TrustDomain,
    pub namespace: String,
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
    #[serde(default)]
    pub action: PolicyAction,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConditionMatch {
    pub key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_values: Vec<String>,
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
                let any_port = !request.ports.is_empty();
                if !(any_method || any_path || any_host || any_header || any_port) {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].to[{}]: at least one of \
                         methods/paths/hosts/headers/ports must be non-empty",
                        policy.name, i, j
                    ));
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
        for fed in &tb_set.federated {
            if let Err(e) = fed.decode_x509_authorities() {
                errors.push(format!(
                    "TrustBundleSet.federated[{}]: {e}",
                    fed.trust_domain
                ));
            }
        }
    }

    errors
}

/// Lower-case in-place hostname normalisation for mesh entries — matches
/// the existing `normalize_fields()` pattern used elsewhere in
/// [`crate::config::types`]. Idempotent.
pub fn normalize_mesh_fields(service_entries: &mut [ServiceEntry], workloads: &mut [Workload]) {
    for se in service_entries {
        for host in &mut se.hosts {
            host.make_ascii_lowercase();
        }
        for ep in &mut se.endpoints {
            ep.address.make_ascii_lowercase();
        }
    }
    // Workloads carry a service_name (logical) — case kept as-is per Istio
    // semantics; namespaces stay case-sensitive too. Nothing to lower-case
    // here today; placeholder for Phase B when we may add hostname-bearing
    // workload fields.
    let _ = workloads;
}
