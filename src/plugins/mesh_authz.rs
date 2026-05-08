//! Mesh authorization plugin.
//!
//! Evaluates Layer 2 `MeshPolicy` rules against the SPIFFE identity extracted
//! by `spiffe_identity` or, for ambient HBONE streams, the identity carried in
//! the HBONE baggage metadata.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

use super::{Plugin, PluginResult, RequestContext, StreamConnectionContext};
use crate::config::mesh::MeshPolicy;
use crate::identity::{SpiffeId, TrustDomain};
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, HboneIdentity};
use crate::modes::mesh::policy::{
    MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization,
};
use crate::xds::slice::MeshSlice;

pub struct MeshAuthz {
    slice: MeshSlice,
    /// Additional SPIFFE trust domains accepted as equivalent to the peer
    /// cert's trust domain when authorising HBONE baggage `source.principal`.
    /// Default empty: strict same-trust-domain match.
    trust_domain_aliases: Vec<TrustDomain>,
}

impl MeshAuthz {
    pub fn new(config: &Value) -> Result<Self, String> {
        let slice = if let Some(value) = config.get("mesh_slice") {
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
        Ok(Self {
            slice,
            trust_domain_aliases,
        })
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
        ctx.materialize_headers();
        let unauthenticated_hbone_baggage = is_hbone_request(ctx)
            && has_baggage_header_from_request(ctx)
            && !is_authenticated_hbone_request(ctx);
        if unauthenticated_hbone_baggage {
            ctx.metadata.insert(
                "mesh_authz.ignored_baggage".to_string(),
                "unauthenticated_hbone".to_string(),
            );
        }
        let (source_principal, trust_domain_mismatch) = self.resolve_source_principal(ctx);
        if trust_domain_mismatch {
            ctx.metadata.insert(
                "mesh_authz.ignored_baggage".to_string(),
                "trust_domain_mismatch".to_string(),
            );
        }
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
        let baggage_principal = baggage_header_from_request(ctx)
            .map(HboneIdentity::from_baggage_header)
            .and_then(|identity| identity.source_principal);
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

fn baggage_header_from_request(ctx: &RequestContext) -> Option<&str> {
    ctx.headers.get(BAGGAGE_HEADER).map(String::as_str)
}

fn has_baggage_header_from_request(ctx: &RequestContext) -> bool {
    ctx.headers.contains_key(BAGGAGE_HEADER)
}
