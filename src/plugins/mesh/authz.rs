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
//! The plugin pre-filters `slice.mesh_policies` at construction time using
//! [`crate::modes::mesh::config::policy_scope_applies_to_workload`]. The hot path
//! ([`evaluate_mesh_authorization`]) then sees only the policies that apply
//! to **this** proxy's workload, so the per-request cost stays at the same
//! O(policies × rules) it was before — minus any policies the scope filter
//! discarded. Filtering is keyed on `(proxy_namespace, proxy_labels)`
//! supplied either by the embedded `mesh_slice` (mesh mode injection) or by
//! explicit `namespace` / `labels` config fields (direct-config / test).

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

use crate::identity::{SpiffeId, TrustDomain};
use crate::modes::mesh::config::{MeshPolicy, PolicyScope, policy_scope_applies_to_workload};
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, HboneIdentity};
use crate::modes::mesh::policy::{
    MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization,
    mesh_policies_have_header_rules, normalize_mesh_policy_header_names,
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
    /// When `true`, the construction-time slice-level scope filter is
    /// skipped and policies are filtered per-request using
    /// [`RequestContext::node_waypoint_policy_scope`] instead. Used in
    /// node-waypoint topology where one listener serves many pods and a
    /// single proxy-identity filter doesn't fit. Default `false`
    /// preserves the existing sidecar/ambient/east-west/egress-gateway
    /// behaviour (slice-level filter at construction).
    per_pod_policy_scoping: bool,
}

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

        // Allow explicit identity overrides on top of the slice-embedded
        // namespace/labels — useful when `mesh_policies` is supplied directly
        // (no slice context) or to override what the slice carried.
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
            per_pod_policy_scoping,
        })
    }

    /// Filter `slice.mesh_policies` against the request's per-pod scope.
    ///
    /// When the scope is missing, only mesh-wide policies are retained. That
    /// avoids applying namespace- or selector-scoped policies to the wrong
    /// source pod while still honoring policies that explicitly apply to all
    /// workloads.
    fn slice_for_pod_scope(
        &self,
        scope: Option<&crate::modes::mesh::runtime::PolicyScopeCache>,
    ) -> std::borrow::Cow<'_, MeshSlice> {
        let applies = |policy: &MeshPolicy| match scope {
            Some(scope) => scope.policy_applies(policy),
            None => matches!(policy.scope, PolicyScope::MeshWide),
        };
        if self.slice.mesh_policies.iter().all(&applies) {
            // Fast path: all policies apply to this pod, so share the
            // existing slice without rebuilding mesh_policies.
            std::borrow::Cow::Borrowed(&self.slice)
        } else {
            let mut narrowed = self.slice.clone();
            narrowed.mesh_policies = self
                .slice
                .mesh_policies
                .iter()
                .filter(|policy| applies(policy))
                .cloned()
                .collect();
            std::borrow::Cow::Owned(narrowed)
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
        let (source_principal, trust_domain_mismatch) = self.resolve_source_principal(ctx);
        if trust_domain_mismatch {
            record_ignored_baggage_reason(&mut ctx.metadata, "trust_domain_mismatch");
            ctx.metadata.insert(
                "mesh_authz.ignored_baggage.trust_domain_mismatch".to_string(),
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
        let effective_slice = if self.per_pod_policy_scoping {
            self.slice_for_pod_scope(ctx.node_waypoint_policy_scope.as_deref())
        } else {
            std::borrow::Cow::Borrowed(&self.slice)
        };
        let decision = evaluate_mesh_authorization(effective_slice.as_ref(), &request);
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
    /// trust-domain check.
    ///
    /// Returns `(principal, trust_domain_mismatch)`. When the second tuple
    /// element is `true`, baggage carried a `source.principal` whose trust
    /// domain neither matched the peer cert's trust domain nor appeared in
    /// the configured `trust_domain_aliases` — the baggage identity is
    /// dropped and the peer cert (the ztunnel's own SPIFFE id) is used as
    /// fallback. Caller stamps diagnostic metadata.
    fn resolve_source_principal(&self, ctx: &RequestContext) -> (Option<SpiffeId>, bool) {
        if !is_authenticated_hbone_request(ctx) {
            return (ctx.peer_spiffe_id.clone(), false);
        }
        let Some(peer) = ctx.peer_spiffe_id.as_ref() else {
            return (None, false);
        };
        let baggage_principal = HboneIdentity::from_baggage_values(
            ctx.raw_header_values(BAGGAGE_HEADER)
                .chain(ctx.headers.get(BAGGAGE_HEADER).map(String::as_str)),
        )
        .source_principal;
        match baggage_principal {
            Some(b) if self.trust_domain_allowed(peer.trust_domain(), b.trust_domain()) => {
                (Some(b), false)
            }
            Some(_) => (Some(peer.clone()), true),
            None => (Some(peer.clone()), false),
        }
    }

    fn trust_domain_allowed(&self, peer_td: &TrustDomain, baggage_td: &TrustDomain) -> bool {
        peer_td == baggage_td
            || self
                .trust_domain_aliases
                .iter()
                .any(|alias| alias == baggage_td)
    }
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
