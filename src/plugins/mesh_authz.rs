//! Mesh authorization plugin.
//!
//! Evaluates Layer 2 `MeshPolicy` rules against the SPIFFE identity extracted
//! by `spiffe_identity` or, for ambient HBONE streams, the identity carried in
//! the HBONE baggage metadata.
//!
//! ## PolicyScope enforcement
//!
//! Each [`crate::config::mesh::MeshPolicy`] carries a [`crate::config::mesh::PolicyScope`]
//! that determines which workloads it applies to. Applying every policy to
//! every workload is a security correctness gap — a namespace-scoped DENY in
//! namespace `A` would deny traffic for workloads in namespace `B`, and a
//! namespace-scoped ALLOW in `A` would raise the implicit-deny floor for
//! unrelated namespaces.
//!
//! The plugin pre-filters `slice.mesh_policies` at construction time using
//! [`crate::config::mesh::policy_scope_applies_to_workload`]. The hot path
//! ([`evaluate_mesh_authorization`]) then sees only the policies that apply
//! to **this** proxy's workload, so the per-request cost stays at the same
//! O(policies × rules) it was before — minus any policies the scope filter
//! discarded. Filtering is keyed on `(proxy_namespace, proxy_labels)`
//! supplied either by the embedded `mesh_slice` (mesh mode injection) or by
//! explicit `namespace` / `labels` config fields (direct-config / test).

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

use super::{Plugin, PluginResult, RequestContext, StreamConnectionContext};
use crate::config::mesh::{MeshPolicy, PolicyScope, policy_scope_applies_to_workload};
use crate::identity::SpiffeId;
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, HboneIdentity};
use crate::modes::mesh::policy::{
    MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization,
};
use crate::xds::slice::MeshSlice;

pub struct MeshAuthz {
    slice: MeshSlice,
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

        validate_scope_filter_identity(&slice)?;

        // Pre-filter the slice's mesh_policies down to those whose `scope`
        // applies to this proxy's workload identity. Done once at construction
        // (cold path); the request hot path then iterates a smaller list.
        let proxy_namespace = slice.namespace.clone();
        let proxy_labels = slice.labels.clone();
        slice.mesh_policies.retain(|policy| {
            policy_scope_applies_to_workload(policy, &proxy_namespace, &proxy_labels)
        });

        Ok(Self { slice })
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
        super::priority::MESH_AUTHZ
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        let source_principal = source_principal_from_request(ctx);
        ctx.materialize_headers();
        // The proxy handler backfills HTTP/2/3 `:authority` into materialized
        // `host` before plugin phases run, so the materialized map is the
        // single source of truth here.
        let host = ctx.headers.get("host").cloned();
        let headers: BTreeMap<String, String> = ctx
            .headers
            .iter()
            .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
            .collect();
        let request = MeshAuthzRequest {
            source_principal,
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
        let decision = evaluate_mesh_authorization(&self.slice, &request);
        self.decision_to_result(decision, &mut ctx.metadata)
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

fn source_principal_from_request(ctx: &RequestContext) -> Option<SpiffeId> {
    ctx.peer_spiffe_id.clone().or_else(|| {
        HboneIdentity::from_baggage_values(ctx.raw_header_values(BAGGAGE_HEADER)).source_principal
    })
}
