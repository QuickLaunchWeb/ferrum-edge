//! Mesh workload metadata plugin.
//!
//! Adds Istio/GAMMA-style identity labels into transaction metadata. The
//! existing logging and metrics sinks then pick them up without plugin-trait
//! changes.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use crate::identity::{SpiffeId, TrustDomain};
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, HboneIdentity};
use crate::plugins::mesh::authz::parse_trust_domain_aliases;
use crate::plugins::{
    ALL_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, StreamConnectionContext,
    priority,
};

const MESH_SOURCE_PRINCIPAL: &str = "mesh.source.principal";
const MESH_SOURCE_TRUST_DOMAIN: &str = "mesh.source.trust_domain";
const MESH_SOURCE_NAMESPACE: &str = "mesh.source.namespace";
const MESH_SOURCE_SERVICE_ACCOUNT: &str = "mesh.source.service_account";

#[derive(Debug, Clone, Default)]
pub struct WorkloadMetrics {
    node_id: Option<String>,
    topology: Option<String>,
    namespace: Option<String>,
    workload_spiffe_id: Option<SpiffeId>,
    labels: HashMap<String, String>,
    trust_domain_aliases: Vec<TrustDomain>,
}

impl WorkloadMetrics {
    pub fn new(config: &Value) -> Result<Self, String> {
        let workload_spiffe_id = config
            .get("workload_spiffe_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(SpiffeId::new)
            .transpose()
            .map_err(|e| format!("workload_metrics: invalid workload_spiffe_id: {e}"))?;
        let labels = config
            .get("labels")
            .and_then(Value::as_object)
            .map(|labels| {
                labels
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let trust_domain_aliases =
            parse_trust_domain_aliases(config).map_err(|e| format!("workload_metrics: {e}"))?;

        Ok(Self {
            node_id: string_config(config, "node_id"),
            topology: string_config(config, "topology"),
            namespace: string_config(config, "namespace"),
            workload_spiffe_id,
            labels,
            trust_domain_aliases,
        })
    }

    fn annotate_http_context(&self, ctx: &mut RequestContext, headers: &HashMap<String, String>) {
        self.insert_common_metadata(&mut ctx.metadata);
        let hbone_identity = authenticated_hbone_identity(ctx, headers);
        // For authenticated ambient HBONE, the peer cert identifies the
        // ztunnel, while baggage identifies the originating workload. If the
        // baggage identity's trust domain neither matches the peer cert's
        // trust domain nor appears in `trust_domain_aliases`, drop it and
        // fall back to the ztunnel's cert identity. Mirror of the gate
        // applied by `mesh_authz`.
        let baggage_source_principal = hbone_identity
            .as_ref()
            .and_then(|identity| identity.source_principal.clone());
        let trust_domain_mismatch = match (
            ctx.peer_spiffe_id.as_ref(),
            baggage_source_principal.as_ref(),
        ) {
            (Some(peer), Some(baggage)) => {
                !self.trust_domain_allowed(peer.trust_domain(), baggage.trust_domain())
            }
            _ => false,
        };
        if trust_domain_mismatch {
            ctx.metadata.insert(
                "mesh.ignored_baggage".to_string(),
                "trust_domain_mismatch".to_string(),
            );
        }
        let source_identity = if trust_domain_mismatch {
            ctx.peer_spiffe_id
                .clone()
                .or_else(|| self.workload_spiffe_id.clone())
        } else {
            baggage_source_principal
                .or_else(|| ctx.peer_spiffe_id.clone())
                .or_else(|| self.workload_spiffe_id.clone())
        };
        ctx.metadata.insert(
            "mesh.connection_security_policy".to_string(),
            if ctx.peer_spiffe_id.is_some() || ctx.tls_client_cert_der.is_some() {
                "mutual_tls"
            } else {
                "none"
            }
            .to_string(),
        );
        ctx.metadata.insert(
            "mesh.request_protocol".to_string(),
            request_protocol(ctx, headers).to_string(),
        );
        if let Some(identity) = source_identity.as_ref() {
            insert_source_spiffe_labels(&mut ctx.metadata, identity);
        }
        self.insert_source_workload_labels(&mut ctx.metadata, source_identity.as_ref());
        if let Some(proxy) = ctx.matched_proxy.as_ref() {
            let destination = proxy.name.clone().unwrap_or_else(|| proxy.id.clone());
            ctx.metadata.insert(
                "mesh.destination.namespace".to_string(),
                proxy.namespace.clone(),
            );
            ctx.metadata
                .insert("mesh.destination.workload".to_string(), destination.clone());
            ctx.metadata
                .insert("mesh.destination.app".to_string(), destination.clone());
            ctx.metadata
                .insert("mesh.destination.service".to_string(), destination);
        }
    }

    fn trust_domain_allowed(&self, peer_td: &TrustDomain, baggage_td: &TrustDomain) -> bool {
        peer_td == baggage_td
            || self
                .trust_domain_aliases
                .iter()
                .any(|alias| alias == baggage_td)
    }

    fn insert_common_metadata(&self, metadata: &mut HashMap<String, String>) {
        if let Some(node_id) = self.node_id.as_ref() {
            metadata.insert("mesh.node_id".to_string(), node_id.clone());
        }
        if let Some(topology) = self.topology.as_ref() {
            metadata.insert("mesh.topology".to_string(), topology.clone());
        }
    }

    fn insert_source_workload_labels(
        &self,
        metadata: &mut HashMap<String, String>,
        source_identity: Option<&SpiffeId>,
    ) {
        if let Some(namespace) = metadata
            .get("mesh.source.namespace")
            .cloned()
            .or_else(|| self.namespace.clone())
        {
            metadata.insert("mesh.source.namespace".to_string(), namespace);
        }

        let service_account = metadata.get("mesh.source.service_account").cloned();
        let workload = first_label(
            &self.labels,
            &[
                "service.istio.io/canonical-name",
                "app.kubernetes.io/name",
                "app",
                "k8s-app",
                "workload",
            ],
        )
        .or(service_account.as_deref())
        .or_else(|| source_identity.and_then(|identity| spiffe_path_value(identity, "sa")))
        .unwrap_or("unknown");
        let app = first_label(&self.labels, &["app.kubernetes.io/name", "app", "k8s-app"])
            .unwrap_or(workload);
        let service = first_label(
            &self.labels,
            &["service.istio.io/canonical-name", "service", "app"],
        )
        .unwrap_or(workload);

        metadata.insert("mesh.source.workload".to_string(), workload.to_string());
        metadata.insert("mesh.source.app".to_string(), app.to_string());
        metadata.insert("mesh.source.service".to_string(), service.to_string());
    }
}

#[async_trait]
impl Plugin for WorkloadMetrics {
    fn name(&self) -> &str {
        "workload_metrics"
    }

    fn priority(&self) -> u16 {
        priority::WORKLOAD_METRICS
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        self.annotate_http_context(ctx, headers);
        PluginResult::Continue
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let metadata = ctx.metadata.get_or_insert_with(Default::default);
        self.insert_common_metadata(metadata);
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
            .or_else(|| self.workload_spiffe_id.clone())
        {
            insert_source_spiffe_labels(metadata, &identity);
            self.insert_source_workload_labels(metadata, Some(&identity));
        } else {
            self.insert_source_workload_labels(metadata, None);
        }
        PluginResult::Continue
    }
}

fn string_config(config: &Value, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn first_label<'a>(labels: &'a HashMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        labels
            .get(*key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    })
}

fn request_protocol(ctx: &RequestContext, headers: &HashMap<String, String>) -> &'static str {
    if ctx
        .metadata
        .get("request_protocol")
        .is_some_and(|value| value == "hbone")
    {
        return "hbone";
    }
    let content_type = header_value(headers, "content-type")
        .or_else(|| ctx.raw_header_get("content-type"))
        .unwrap_or("");
    if content_type
        .split(';')
        .next()
        .is_some_and(|value| is_grpc_content_type(value.trim()))
    {
        "grpc"
    } else {
        "http"
    }
}

fn authenticated_hbone_identity(
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
) -> Option<HboneIdentity> {
    if ctx.peer_spiffe_id.is_none()
        || ctx
            .metadata
            .get("request_protocol")
            .is_none_or(|value| value != "hbone")
    {
        return None;
    }

    headers
        .get(BAGGAGE_HEADER)
        .map(String::as_str)
        .map(HboneIdentity::from_baggage_header)
}

fn is_grpc_content_type(value: &str) -> bool {
    value
        .as_bytes()
        .get(..b"application/grpc".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"application/grpc"))
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str).or_else(|| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

fn insert_source_spiffe_labels(metadata: &mut HashMap<String, String>, identity: &SpiffeId) {
    metadata.insert(MESH_SOURCE_PRINCIPAL.to_string(), identity.to_string());
    metadata.insert(
        MESH_SOURCE_TRUST_DOMAIN.to_string(),
        identity.trust_domain().as_str().to_string(),
    );
    if let Some(namespace) = spiffe_path_value(identity, "ns") {
        metadata.insert(MESH_SOURCE_NAMESPACE.to_string(), namespace.to_string());
    }
    if let Some(service_account) = spiffe_path_value(identity, "sa") {
        metadata.insert(
            MESH_SOURCE_SERVICE_ACCOUNT.to_string(),
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
