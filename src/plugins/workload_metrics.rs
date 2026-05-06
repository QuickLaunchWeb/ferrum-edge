//! Mesh workload metadata plugin.
//!
//! Adds Istio/GAMMA-style identity labels into transaction metadata. The
//! existing logging and metrics sinks then pick them up without plugin-trait
//! changes.

use async_trait::async_trait;
use serde_json::Value;

use super::{Plugin, PluginResult, RequestContext, StreamConnectionContext};
use crate::identity::SpiffeId;
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, HboneIdentity};

pub struct WorkloadMetrics;

impl WorkloadMetrics {
    pub fn new(_config: &Value) -> Result<Self, String> {
        Ok(Self)
    }
}

#[async_trait]
impl Plugin for WorkloadMetrics {
    fn name(&self) -> &str {
        "workload_metrics"
    }

    fn priority(&self) -> u16 {
        super::priority::WORKLOAD_METRICS
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut std::collections::HashMap<String, String>,
    ) -> PluginResult {
        annotate_http_context(ctx);
        PluginResult::Continue
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let metadata = ctx.metadata.get_or_insert_with(Default::default);
        metadata.insert(
            "mesh.connection_security_policy".to_string(),
            if ctx.tls_client_cert_der.is_some() {
                "mutual_tls"
            } else {
                "none"
            }
            .to_string(),
        );
        if let Some(identity) = ctx
            .authenticated_identity
            .as_deref()
            .and_then(|value| SpiffeId::new(value).ok())
            .or_else(|| {
                metadata
                    .get("peer_spiffe_id")
                    .and_then(|value| SpiffeId::new(value).ok())
            })
        {
            insert_spiffe_labels(metadata, "mesh.source", &identity);
        }
        PluginResult::Continue
    }
}

fn annotate_http_context(ctx: &mut RequestContext) {
    ctx.metadata.insert(
        "mesh.connection_security_policy".to_string(),
        if ctx.peer_spiffe_id.is_some() {
            "mutual_tls"
        } else {
            "none"
        }
        .to_string(),
    );
    if let Some(identity) = http_source_identity(ctx).as_ref() {
        insert_spiffe_labels(&mut ctx.metadata, "mesh.source", identity);
    }
    if let Some(proxy) = ctx.matched_proxy.as_ref() {
        ctx.metadata.insert(
            "mesh.destination.namespace".to_string(),
            proxy.namespace.clone(),
        );
        ctx.metadata.insert(
            "mesh.destination.service".to_string(),
            proxy.name.clone().unwrap_or_else(|| proxy.id.clone()),
        );
    }
}

fn http_source_identity(ctx: &RequestContext) -> Option<SpiffeId> {
    ctx.peer_spiffe_id.clone().or_else(|| {
        ctx.raw_header_get(BAGGAGE_HEADER)
            .map(HboneIdentity::from_baggage_header)
            .and_then(|identity| identity.source_principal)
    })
}

fn insert_spiffe_labels(
    metadata: &mut std::collections::HashMap<String, String>,
    prefix: &str,
    identity: &SpiffeId,
) {
    metadata.insert(format!("{prefix}.principal"), identity.to_string());
    metadata.insert(
        format!("{prefix}.trust_domain"),
        identity.trust_domain().as_str().to_string(),
    );
    if let Some(namespace) = spiffe_path_value(identity, "ns") {
        metadata.insert(format!("{prefix}.namespace"), namespace.to_string());
    }
    if let Some(service_account) = spiffe_path_value(identity, "sa") {
        metadata.insert(
            format!("{prefix}.service_account"),
            service_account.to_string(),
        );
    }
}

fn spiffe_path_value<'a>(identity: &'a SpiffeId, key: &str) -> Option<&'a str> {
    let mut segments = identity.path_segments();
    while let Some(segment) = segments.next() {
        if segment == key {
            return segments.next();
        }
    }
    None
}
