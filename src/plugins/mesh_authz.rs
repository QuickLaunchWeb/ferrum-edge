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
        ctx.raw_header_get(BAGGAGE_HEADER)
            .map(HboneIdentity::from_baggage_header)
            .and_then(|identity| identity.source_principal)
    })
}
