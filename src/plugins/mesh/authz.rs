//! Mesh authorization plugin.
//!
//! Evaluates Layer 2 `MeshPolicy` rules against the SPIFFE identity extracted
//! by `spiffe_identity` or, for ambient HBONE streams, the identity carried in
//! the HBONE baggage metadata.
//!
//! ## PolicyScope enforcement
//!
//! Each [`crate::modes::mesh::config::MeshPolicy`] carries a [`crate::modes::mesh::config::PolicyScope`]
//! that determines which workloads it applies to. Applying every policy to
//! every workload is a security correctness gap — a namespace-scoped DENY in
//! namespace `A` would deny traffic for workloads in namespace `B`, and a
//! namespace-scoped ALLOW in `A` would raise the implicit-deny floor for
//! unrelated namespaces.
//!
//! In normal mesh topologies, the plugin pre-filters `slice.mesh_policies` at
//! construction time using
//! [`crate::modes::mesh::config::policy_scope_applies_to_workload`]. The hot
//! path ([`evaluate_mesh_authorization`]) then sees only the policies that
//! apply to **this** proxy's workload, so the per-request cost stays at the same
//! O(policies × rules) it was before — minus any policies the scope filter
//! discarded. Filtering is keyed on `(proxy_namespace, proxy_labels)` supplied
//! either by the embedded `mesh_slice` (mesh mode injection) or by explicit
//! `namespace` / `labels` config fields (direct-config / test).
//!
//! Node-waypoint mode is different because one proxy instance handles many
//! pods. When `per_pod_policy_scoping` is enabled, construction-time filtering
//! is skipped and the request path evaluates the `PolicyScopeCache` attached to
//! `RequestContext::node_waypoint_policy_scope`. If the pod has no installed
//! scope yet, only mesh-wide policies are retained; namespace and selector
//! scoped policies are withheld until the resolver has the pod's workload
//! metadata.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

use crate::identity::{SpiffeId, TrustDomain};
use crate::modes::mesh::config::{MeshPolicy, PolicyScope, policy_scope_applies_to_workload};
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, HboneIdentity};
use crate::modes::mesh::policy::{
    MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization,
    evaluate_mesh_authorization_policies, mesh_policies_have_header_rules,
    normalize_mesh_policy_header_names,
};
use crate::modes::mesh::slice::MeshSlice;
use crate::plugins::{
    ALL_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, StreamConnectionContext,
    priority,
};

pub struct MeshAuthz {
    slice: MeshSlice,
    has_header_rules: bool,
    /// Additional SPIFFE trust domains accepted as equivalent to the peer
    /// cert's trust domain when authorising HBONE baggage `source.principal`.
    /// Default empty: strict same-trust-domain match.
    trust_domain_aliases: Vec<TrustDomain>,
    /// Identity-asserting infrastructure SVIDs that are trusted to rewrite the
    /// authz principal via HBONE baggage `source.principal`. Any
    /// authenticated HBONE peer outside this set has its baggage identity
    /// dropped and is authorised under its own peer SPIFFE ID. Default
    /// `["ztunnel", "waypoint"]` (Istio ambient convention). See the
    /// `TrustedAssertor` variants for matching semantics.
    trusted_hbone_assertors: Vec<TrustedAssertor>,
    /// When `true`, the construction-time slice-level scope filter is
    /// skipped and policies are filtered per-request using
    /// [`RequestContext::node_waypoint_policy_scope`] instead. Used in
    /// node-waypoint topology where one listener serves many pods and a
    /// single proxy-identity filter doesn't fit. Default `false`
    /// preserves the existing sidecar/ambient/east-west/egress-gateway
    /// behaviour (slice-level filter at construction).
    per_pod_policy_scoping: bool,
}

/// Matching rule for the [`MeshAuthz::trusted_hbone_assertors`] allow-list.
///
/// Operators may supply either a bare service-account name (the Istio default
/// for ztunnel and waypoints), or a full SPIFFE ID to pin a specific
/// assertor identity, trust domain, and namespace.
#[derive(Debug, Clone)]
enum TrustedAssertor {
    /// Match any peer whose SPIFFE-ID path encodes this Kubernetes service
    /// account per the Istio convention `ns/<ns>/sa/<sa>`.
    ServiceAccount(String),
    /// Match a specific SPIFFE-ID exactly.
    Spiffe(SpiffeId),
}

impl TrustedAssertor {
    fn matches(&self, peer: &SpiffeId) -> bool {
        match self {
            Self::ServiceAccount(name) => peer.service_account() == Some(name.as_str()),
            Self::Spiffe(id) => id == peer,
        }
    }
}

/// Default trusted-assertor allow-list used when the plugin config does not
/// supply one. Matches Istio ambient's `ztunnel` and `waypoint` service
/// accounts. Operators with custom waypoint SA names (Gateway-managed
/// waypoints often use `<gateway-name>` or `<gateway-name>-istio`) must
/// override this list to add their names.
const DEFAULT_TRUSTED_HBONE_ASSERTOR_SA_NAMES: &[&str] = &["ztunnel", "waypoint"];

impl MeshAuthz {
    pub fn new(config: &Value) -> Result<Self, String> {
        let mut slice = if let Some(value) = config.get("mesh_slice") {
            serde_json::from_value::<MeshSlice>(value.clone())
                .map_err(|e| format!("mesh_authz: invalid mesh_slice: {e}"))?
        } else if let Some(value) = config.get("mesh_policies") {
            let mesh_policies = serde_json::from_value::<Vec<MeshPolicy>>(value.clone())
                .map_err(|e| format!("mesh_authz: invalid mesh_policies: {e}"))?;
            MeshSlice {
                mesh_policies,
                ..MeshSlice::default()
            }
        } else {
            MeshSlice::default()
        };
        let trust_domain_aliases = parse_trust_domain_aliases(config)?;
        let trusted_hbone_assertors = parse_trusted_hbone_assertors(config)?;

        // Allow explicit identity overrides on top of the slice-embedded
        // namespace/labels — useful when `mesh_policies` is supplied directly
        // (no slice context) or to override what the slice carried. These
        // fields drive the construction-time scope filter below; when
        // `per_pod_policy_scoping` is true (node-waypoint topology) the
        // filter is skipped and these writes are unused, but the parsing
        // still runs so the on-disk config shape is identical across
        // topologies and validation errors (bad type / malformed labels)
        // surface uniformly.
        if let Some(value) = config.get("namespace") {
            let namespace = value
                .as_str()
                .ok_or_else(|| "mesh_authz: namespace must be a string".to_string())?;
            slice.namespace = namespace.to_string();
        }
        if let Some(value) = config.get("labels") {
            let labels = serde_json::from_value::<BTreeMap<String, String>>(value.clone())
                .map_err(|e| format!("mesh_authz: invalid labels: {e}"))?;
            slice.labels = labels;
        }

        let per_pod_policy_scoping = config
            .get("per_pod_policy_scoping")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if !per_pod_policy_scoping {
            validate_scope_filter_identity(&slice)?;

            // Pre-filter the slice's mesh_policies down to those whose `scope`
            // applies to this proxy's workload identity. Done once at
            // construction (cold path); the request hot path then iterates a
            // smaller list. Skipped in node-waypoint mode because one listener
            // serves many pods — filtering happens per request using the
            // pod-scoped cache set on RequestContext.
            let proxy_namespace = slice.namespace.clone();
            let proxy_labels = slice.labels.clone();
            slice.mesh_policies.retain(|policy| {
                policy_scope_applies_to_workload(policy, &proxy_namespace, &proxy_labels)
            });
        }

        for policy in &mut slice.mesh_policies {
            normalize_mesh_policy_header_names(policy);
        }
        let has_header_rules = mesh_policies_have_header_rules(&slice.mesh_policies);
        Ok(Self {
            slice,
            has_header_rules,
            trust_domain_aliases,
            trusted_hbone_assertors,
            per_pod_policy_scoping,
        })
    }

    /// Predicate used by [`MeshAuthz::authorize`] to decide whether a
    /// configured policy applies to the request's source pod when
    /// per-pod policy scoping is enabled.
    ///
    /// Missing scope retains only mesh-wide policies — namespace- and
    /// selector-scoped policies are withheld because we cannot prove they
    /// apply to this source pod yet (typically a race between accept-time
    /// pod resolution and the resolver enrolling the pod's workload scope).
    fn policy_applies_to_pod(
        policy: &MeshPolicy,
        scope: Option<&crate::modes::mesh::runtime::PolicyScopeCache>,
    ) -> bool {
        match scope {
            Some(scope) => scope.policy_applies(policy),
            None => matches!(policy.scope, PolicyScope::MeshWide),
        }
    }

    fn decision_to_result(
        &self,
        decision: MeshAuthzDecision,
        metadata: &mut HashMap<String, String>,
    ) -> PluginResult {
        match decision {
            MeshAuthzDecision::Allow => PluginResult::Continue,
            MeshAuthzDecision::Audit { policy } => {
                metadata.insert("mesh_authz.audit_policy".to_string(), policy);
                PluginResult::Continue
            }
            MeshAuthzDecision::Deny { policy } => {
                metadata.insert("mesh_authz.deny_policy".to_string(), policy);
                PluginResult::Reject {
                    status_code: 403,
                    body: r#"{"error":"Mesh authorization denied"}"#.into(),
                    headers: HashMap::new(),
                }
            }
        }
    }
}

fn validate_scope_filter_identity(slice: &MeshSlice) -> Result<(), String> {
    let has_proxy_namespace = !slice.namespace.trim().is_empty();
    let has_proxy_labels = !slice.labels.is_empty();

    for policy in &slice.mesh_policies {
        match &policy.scope {
            PolicyScope::MeshWide => {}
            PolicyScope::Namespace { .. } => {
                if !has_proxy_namespace {
                    return Err(format!(
                        "mesh_authz: policy '{}' uses namespace scope but no proxy namespace is configured; set mesh_slice.namespace or namespace",
                        policy.name
                    ));
                }
            }
            PolicyScope::WorkloadSelector { selector } => {
                if let Some(selector_namespace) = selector.namespace.as_ref() {
                    if !has_proxy_namespace {
                        return Err(format!(
                            "mesh_authz: policy '{}' uses workload selector namespace '{}' but no proxy namespace is configured; set mesh_slice.namespace or namespace",
                            policy.name, selector_namespace
                        ));
                    }
                    if selector_namespace != &slice.namespace {
                        continue;
                    }
                }

                if !selector.labels.is_empty() && !has_proxy_labels {
                    return Err(format!(
                        "mesh_authz: policy '{}' uses workload selector labels but no proxy labels are configured; set mesh_slice.labels or labels",
                        policy.name
                    ));
                }
            }
        }
    }

    Ok(())
}

#[async_trait]
impl Plugin for MeshAuthz {
    fn name(&self) -> &str {
        "mesh_authz"
    }

    fn priority(&self) -> u16 {
        priority::MESH_AUTHZ
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        let unauthenticated_hbone_baggage = is_hbone_request(ctx)
            && has_baggage_header_from_request(ctx)
            && !is_authenticated_hbone_request(ctx);
        if unauthenticated_hbone_baggage {
            record_ignored_baggage_reason(&mut ctx.metadata, "unauthenticated_hbone");
            ctx.metadata.insert(
                "mesh_authz.ignored_baggage.unauthenticated".to_string(),
                "true".to_string(),
            );
        }
        let (source_principal, baggage_outcome) = self.resolve_source_principal(ctx);
        let trust_domain_mismatch = baggage_outcome == BaggageOutcome::TrustDomainMismatch;
        let untrusted_assertor = baggage_outcome == BaggageOutcome::UntrustedAssertor;
        if trust_domain_mismatch {
            record_ignored_baggage_reason(&mut ctx.metadata, "trust_domain_mismatch");
            ctx.metadata.insert(
                "mesh_authz.ignored_baggage.trust_domain_mismatch".to_string(),
                "true".to_string(),
            );
        }
        if untrusted_assertor {
            record_ignored_baggage_reason(&mut ctx.metadata, "untrusted_assertor");
            ctx.metadata.insert(
                "mesh_authz.ignored_baggage.untrusted_assertor".to_string(),
                "true".to_string(),
            );
        }
        let mut host = ctx
            .raw_header_get("host")
            .or_else(|| ctx.raw_header_get(":authority"))
            .map(str::to_string);
        let headers = if self.has_header_rules {
            ctx.materialize_headers();
            if host.is_none() {
                host = ctx.headers.get("host").cloned();
            }
            ctx.headers
                .iter()
                .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
                .collect()
        } else {
            if host.is_none() {
                host = ctx.headers.get("host").cloned();
            }
            BTreeMap::new()
        };
        let request_principal = ctx.metadata.get("jwks_auth.request_principal").cloned();
        let request = MeshAuthzRequest {
            source_principal,
            request_principal,
            method: Some(ctx.method.clone()),
            path: Some(ctx.path.clone()),
            host,
            port: ctx.frontend_listen_port.or_else(|| {
                ctx.matched_proxy
                    .as_ref()
                    .and_then(|proxy| proxy.listen_port)
            }),
            headers,
            attributes: BTreeMap::new(),
        };
        // GAP-2M.4: per-pod scoping for node-waypoint topology.
        //
        // When `per_pod_policy_scoping` is enabled, the construction-time
        // filter was skipped (`self.slice.mesh_policies` carries the full
        // unfiltered set) and we filter per-request using the source pod's
        // PolicyScopeCache. If the scope is absent, retain mesh-wide policies
        // only so scoped policies do not leak across pods. Other topologies
        // keep the pre-filtered slice.
        //
        // Filtering is expressed as an iterator predicate so the hot path
        // never clones the full `MeshSlice` (which carries workloads,
        // services, destination_rules, etc. the authz engine never reads).
        let mut scope_missing = false;
        let decision = if self.per_pod_policy_scoping {
            let scope = ctx.node_waypoint_policy_scope.as_deref();
            scope_missing = scope.is_none();
            let policies = self
                .slice
                .mesh_policies
                .iter()
                .filter(|policy| Self::policy_applies_to_pod(policy, scope));
            evaluate_mesh_authorization_policies(policies, &request)
        } else {
            evaluate_mesh_authorization(&self.slice, &request)
        };
        // Surface the per-pod-scope race window through transaction logs so
        // operators can see when mesh_authz is falling back to mesh-wide
        // policies because the resolver hasn't enrolled the pod's workload
        // metadata yet. Only emitted when per_pod_policy_scoping is on, so
        // sidecar/ambient/east-west/egress traffic is unaffected.
        if scope_missing {
            ctx.metadata
                .insert("mesh_authz.scope_missing".to_string(), "true".to_string());
        }
        let result = self.decision_to_result(decision, &mut ctx.metadata);
        if matches!(
            result,
            PluginResult::Reject { .. } | PluginResult::RejectBinary { .. }
        ) {
            if unauthenticated_hbone_baggage {
                ctx.metadata.insert(
                    "mesh_authz.deny_policy".to_string(),
                    "unauthenticated_baggage".to_string(),
                );
            } else if trust_domain_mismatch {
                ctx.metadata.insert(
                    "mesh_authz.deny_policy".to_string(),
                    "trust_domain_mismatch".to_string(),
                );
            } else if untrusted_assertor {
                ctx.metadata.insert(
                    "mesh_authz.deny_policy".to_string(),
                    "untrusted_assertor".to_string(),
                );
            }
        }
        result
    }

    fn is_authorize_plugin(&self) -> bool {
        true
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let mut metadata = ctx.metadata.clone().unwrap_or_default();
        let source_principal = metadata
            .get("peer_spiffe_id")
            .and_then(|value| SpiffeId::new(value).ok())
            .or_else(|| {
                ctx.authenticated_identity
                    .as_deref()
                    .and_then(|value| SpiffeId::new(value).ok())
            });
        let request = MeshAuthzRequest {
            source_principal,
            port: Some(ctx.listen_port),
            attributes: BTreeMap::new(),
            ..MeshAuthzRequest::default()
        };
        let result = self.decision_to_result(
            evaluate_mesh_authorization(&self.slice, &request),
            &mut metadata,
        );
        ctx.metadata = (!metadata.is_empty()).then_some(metadata);
        result
    }
}

impl MeshAuthz {
    /// Resolve the SPIFFE identity used for authz, applying the HBONE baggage
    /// trust-assertor and trust-domain checks.
    ///
    /// Returns `(principal, BaggageOutcome)`. The outcome describes the
    /// disposition of any incoming HBONE `baggage: source.principal` so that
    /// the caller can stamp diagnostic metadata:
    ///
    /// - `Honored` — baggage parsed, the peer is a trusted assertor, and the
    ///   baggage identity's trust domain matched the peer cert's (or an
    ///   alias). The returned principal is the baggage identity.
    /// - `UntrustedAssertor` — the peer is not on
    ///   [`MeshAuthz::trusted_hbone_assertors`]. Baggage is dropped; the
    ///   returned principal is the peer cert identity.
    /// - `TrustDomainMismatch` — the peer is trusted but the baggage
    ///   identity's trust domain neither matched the peer cert's nor appeared
    ///   in [`MeshAuthz::trust_domain_aliases`]. Baggage is dropped; the
    ///   returned principal is the peer cert identity (typically the
    ///   ztunnel's own SPIFFE id).
    /// - `NoBaggageOrNonHbone` — non-HBONE request, no baggage, or no
    ///   authenticated peer to begin with. No diagnostic stamped.
    fn resolve_source_principal(&self, ctx: &RequestContext) -> (Option<SpiffeId>, BaggageOutcome) {
        if !is_authenticated_hbone_request(ctx) {
            return (
                ctx.peer_spiffe_id.clone(),
                BaggageOutcome::NoBaggageOrNonHbone,
            );
        }
        let Some(peer) = ctx.peer_spiffe_id.as_ref() else {
            return (None, BaggageOutcome::NoBaggageOrNonHbone);
        };
        let baggage_principal = HboneIdentity::from_baggage_values(
            ctx.raw_header_values(BAGGAGE_HEADER)
                .chain(ctx.headers.get(BAGGAGE_HEADER).map(String::as_str)),
        )
        .source_principal;
        if !self.is_trusted_hbone_assertor(peer) {
            // Stamp `UntrustedAssertor` only when the request actually carried
            // a baggage source identity that we suppressed. Without that
            // signal there's nothing observable for operators to triage and
            // the metadata would just be noise on every non-assertor HBONE
            // flow.
            let outcome = if baggage_principal.is_some() {
                BaggageOutcome::UntrustedAssertor
            } else {
                BaggageOutcome::NoBaggageOrNonHbone
            };
            return (Some(peer.clone()), outcome);
        }
        match baggage_principal {
            Some(b) if self.trust_domain_allowed(peer.trust_domain(), b.trust_domain()) => {
                (Some(b), BaggageOutcome::Honored)
            }
            Some(_) => (Some(peer.clone()), BaggageOutcome::TrustDomainMismatch),
            None => (Some(peer.clone()), BaggageOutcome::NoBaggageOrNonHbone),
        }
    }

    fn trust_domain_allowed(&self, peer_td: &TrustDomain, baggage_td: &TrustDomain) -> bool {
        peer_td == baggage_td
            || self
                .trust_domain_aliases
                .iter()
                .any(|alias| alias == baggage_td)
    }

    fn is_trusted_hbone_assertor(&self, peer: &SpiffeId) -> bool {
        self.trusted_hbone_assertors
            .iter()
            .any(|entry| entry.matches(peer))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaggageOutcome {
    /// Baggage parsed and accepted; returned principal is the baggage identity.
    Honored,
    /// Peer is not a trusted assertor and baggage carried a source identity
    /// that we dropped; returned principal is the peer cert identity.
    UntrustedAssertor,
    /// Baggage's trust domain did not match the peer's or an alias; returned
    /// principal is the peer cert identity.
    TrustDomainMismatch,
    /// Nothing to surface — non-HBONE request, no baggage, or no authenticated
    /// peer.
    NoBaggageOrNonHbone,
}

pub(crate) fn parse_trust_domain_aliases(config: &Value) -> Result<Vec<TrustDomain>, String> {
    match config.get("trust_domain_aliases") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                let raw = item
                    .as_str()
                    .ok_or_else(|| "trust_domain_aliases entries must be strings".to_string())?;
                TrustDomain::new(raw)
                    .map_err(|e| format!("invalid trust_domain_aliases entry '{raw}': {e}"))
            })
            .collect(),
        Some(_) => Err("trust_domain_aliases must be an array of strings".to_string()),
    }
}

fn is_authenticated_hbone_request(ctx: &RequestContext) -> bool {
    ctx.peer_spiffe_id.is_some() && is_hbone_request(ctx)
}

fn is_hbone_request(ctx: &RequestContext) -> bool {
    ctx.metadata
        .get("request_protocol")
        .is_some_and(|value| value == "hbone")
}

fn record_ignored_baggage_reason(metadata: &mut HashMap<String, String>, reason: &'static str) {
    metadata
        .entry("mesh_authz.ignored_baggage".to_string())
        .and_modify(|existing| {
            if !existing.split(',').any(|item| item == reason) {
                existing.push(',');
                existing.push_str(reason);
            }
        })
        .or_insert_with(|| reason.to_string());
}

fn has_baggage_header_from_request(ctx: &RequestContext) -> bool {
    ctx.raw_header_get(BAGGAGE_HEADER).is_some() || ctx.headers.contains_key(BAGGAGE_HEADER)
}

fn parse_trusted_hbone_assertors(config: &Value) -> Result<Vec<TrustedAssertor>, String> {
    let items = match config.get("trusted_hbone_assertors") {
        None | Some(Value::Null) => {
            return Ok(default_trusted_hbone_assertors());
        }
        Some(Value::Array(items)) => items,
        Some(_) => {
            return Err("trusted_hbone_assertors must be an array of strings".to_string());
        }
    };

    // Empty array intentionally means "no peer can assert baggage"; default
    // assertors only apply when the key is absent or null. Operators can use
    // `[]` to lock down baggage-rewrite entirely while still leaving the
    // mesh_authz plugin active.
    items
        .iter()
        .map(|item| {
            let raw = item
                .as_str()
                .ok_or_else(|| "trusted_hbone_assertors entries must be strings".to_string())?;
            parse_trusted_hbone_assertor(raw)
        })
        .collect()
}

fn parse_trusted_hbone_assertor(raw: &str) -> Result<TrustedAssertor, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("trusted_hbone_assertors entries must not be empty".to_string());
    }
    if trimmed.starts_with("spiffe://") {
        SpiffeId::new(trimmed)
            .map(TrustedAssertor::Spiffe)
            .map_err(|e| format!("invalid trusted_hbone_assertors SPIFFE id '{trimmed}': {e}"))
    } else {
        // Reject anything that looks like an attempted URI but isn't a SPIFFE
        // id (e.g. typo'd scheme) instead of silently treating it as a
        // service-account name.
        if trimmed.contains("://") {
            return Err(format!(
                "trusted_hbone_assertors entry '{trimmed}' looks like a URI but is not a 'spiffe://' SPIFFE id"
            ));
        }
        Ok(TrustedAssertor::ServiceAccount(trimmed.to_string()))
    }
}

fn default_trusted_hbone_assertors() -> Vec<TrustedAssertor> {
    DEFAULT_TRUSTED_HBONE_ASSERTOR_SA_NAMES
        .iter()
        .map(|name| TrustedAssertor::ServiceAccount((*name).to_string()))
        .collect()
}
