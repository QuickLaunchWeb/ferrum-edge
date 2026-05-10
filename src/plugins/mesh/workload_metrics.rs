//! Mesh workload metadata plugin.
//!
//! Adds Istio/GAMMA-style identity labels into transaction metadata. The
//! existing logging and metrics sinks then pick them up without plugin-trait
//! changes.

use async_trait::async_trait;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use std::cell::Cell;
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

#[derive(Debug, Default)]
pub struct WorkloadMetrics {
    node_id: Option<String>,
    topology: Option<String>,
    namespace: Option<String>,
    workload_spiffe_id: Option<SpiffeId>,
    labels: HashMap<String, String>,
    trust_domain_aliases: Vec<TrustDomain>,
    /// Tracing sampling percentage 0.0–100.0 (from Telemetry CRD).
    sampling_percentage: f64,
    /// Custom tags injected into every transaction's metadata.
    custom_tags: HashMap<String, String>,
    /// Custom tags populated from request headers.
    custom_header_tags: HashMap<String, String>,
    metric_tag_overrides: Vec<MetricTagOverrideConfig>,
    disabled_metrics: Vec<String>,
}

#[derive(Debug)]
enum MetricTagOverrideConfig {
    Remove { name: String },
    Rename { name: String, new_name: String },
    Set { name: String, value: String },
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
        let sampling_percentage = config
            .get("sampling_percentage")
            .and_then(Value::as_f64)
            .unwrap_or(100.0);
        let custom_tags = config
            .get("custom_tags")
            .and_then(Value::as_object)
            .map(|tags| {
                tags.iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let custom_header_tags = config
            .get("custom_header_tags")
            .and_then(Value::as_object)
            .map(|tags| {
                tags.iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (metric_tag_overrides, disabled_metrics) = parse_metric_config(config.get("metrics"))?;

        Ok(Self {
            node_id: string_config(config, "node_id"),
            topology: string_config(config, "topology"),
            namespace: string_config(config, "namespace"),
            workload_spiffe_id,
            labels,
            trust_domain_aliases,
            sampling_percentage,
            custom_tags,
            custom_header_tags,
            metric_tag_overrides,
            disabled_metrics,
        })
    }

    fn annotate_http_context(&self, ctx: &mut RequestContext, headers: &HashMap<String, String>) {
        self.insert_common_metadata(&mut ctx.metadata);
        self.apply_telemetry_metadata(&mut ctx.metadata, headers);
        let hbone_identity = hbone_identity_from_headers(ctx, headers);
        // For authenticated ambient HBONE, the peer cert identifies the
        // ztunnel, while baggage identifies the originating workload. If the
        // baggage identity's trust domain neither matches the peer cert's
        // trust domain nor appears in `trust_domain_aliases`, drop it and
        // fall back to the ztunnel's cert identity. Mirror of the gate
        // applied by `mesh_authz`.
        let baggage_source_principal = hbone_identity
            .as_ref()
            .and_then(|identity| identity.source_principal.clone());
        let trusted_baggage_source_principal = ctx
            .peer_spiffe_id
            .is_some()
            .then(|| baggage_source_principal.clone())
            .flatten();
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
        } else if ctx.peer_spiffe_id.is_none()
            && hbone_identity
                .as_ref()
                .and_then(|identity| identity.source_principal.as_ref())
                .is_some()
        {
            ctx.metadata.insert(
                "mesh.ignored_baggage".to_string(),
                "unauthenticated_hbone".to_string(),
            );
        }
        let source_identity = if trust_domain_mismatch {
            ctx.peer_spiffe_id
                .clone()
                .or_else(|| self.workload_spiffe_id.clone())
        } else {
            trusted_baggage_source_principal
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

    fn apply_telemetry_metadata(
        &self,
        metadata: &mut HashMap<String, String>,
        headers: &HashMap<String, String>,
    ) {
        if self.sampling_percentage < 100.0 {
            let sampled = trace_sampled(self.sampling_percentage);
            metadata.insert(
                "trace_sampled".to_string(),
                if sampled { "true" } else { "false" }.to_string(),
            );
        }
        for (key, value) in &self.custom_tags {
            metadata.insert(key.clone(), value.clone());
        }
        for (key, header_name) in &self.custom_header_tags {
            if let Some(value) = header_value(headers, header_name) {
                metadata.insert(key.clone(), value.to_string());
            }
        }
        for override_config in &self.metric_tag_overrides {
            match override_config {
                MetricTagOverrideConfig::Remove { name } => {
                    metadata.remove(name);
                }
                MetricTagOverrideConfig::Rename { name, new_name } => {
                    if let Some(value) = metadata.remove(name) {
                        metadata.insert(new_name.clone(), value);
                    }
                }
                MetricTagOverrideConfig::Set { name, value } => {
                    metadata.insert(name.clone(), value.clone());
                }
            }
        }
        if !self.disabled_metrics.is_empty() {
            metadata.insert(
                "mesh.metrics.disabled".to_string(),
                self.disabled_metrics.join(","),
            );
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
        self.apply_telemetry_metadata(metadata, &HashMap::new());
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

fn parse_metric_config(
    value: Option<&Value>,
) -> Result<(Vec<MetricTagOverrideConfig>, Vec<String>), String> {
    let Some(metrics) = value else {
        return Ok((Vec::new(), Vec::new()));
    };
    let object = metrics
        .as_object()
        .ok_or_else(|| "workload_metrics: 'metrics' must be an object".to_string())?;
    let disabled_metrics = object
        .get("disabled_metrics")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|metric| !metric.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect();
    let mut tag_overrides = Vec::new();
    for entry in object
        .get("tag_overrides")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(operation) = entry.get("operation").and_then(Value::as_object) else {
            continue;
        };
        match operation.get("type").and_then(Value::as_str) {
            Some("remove") => tag_overrides.push(MetricTagOverrideConfig::Remove {
                name: name.to_string(),
            }),
            Some("rename") => {
                if let Some(new_name) = operation.get("new_name").and_then(Value::as_str) {
                    tag_overrides.push(MetricTagOverrideConfig::Rename {
                        name: name.to_string(),
                        new_name: new_name.to_string(),
                    });
                }
            }
            Some("set") => {
                if let Some(value) = operation.get("value").and_then(Value::as_str) {
                    tag_overrides.push(MetricTagOverrideConfig::Set {
                        name: name.to_string(),
                        value: value.to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    Ok((tag_overrides, disabled_metrics))
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

fn hbone_identity_from_headers(
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
) -> Option<HboneIdentity> {
    if ctx
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

thread_local! {
    static TRACE_SAMPLING_STATE: Cell<u64> = Cell::new(random_sampling_seed());
}

fn trace_sampled(sampling_percentage: f64) -> bool {
    if sampling_percentage <= 0.0 {
        return false;
    }
    if sampling_percentage >= 100.0 {
        return true;
    }

    let random = next_sampling_u64();
    (random as f64 / u64::MAX as f64) * 100.0 < sampling_percentage
}

fn next_sampling_u64() -> u64 {
    TRACE_SAMPLING_STATE.with(|state| {
        let next = state.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
        state.set(next);
        splitmix64(next)
    })
}

fn random_sampling_seed() -> u64 {
    let mut bytes = [0u8; 8];
    if SystemRandom::new().fill(&mut bytes).is_ok() {
        let seed = u64::from_ne_bytes(bytes);
        if seed != 0 {
            return seed;
        }
    }

    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0xA5A5_5A5A_D3C1_B2A0)
}

fn splitmix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn custom_header_tags_resolve_request_header_values() {
        let metrics = WorkloadMetrics::new(&json!({
            "custom_tags": {
                "literal": "constant"
            },
            "custom_header_tags": {
                "tenant": "x-tenant"
            }
        }))
        .expect("metrics config");
        let headers = HashMap::from([("X-Tenant".to_string(), "acme".to_string())]);
        let mut metadata = HashMap::new();

        metrics.apply_telemetry_metadata(&mut metadata, &headers);

        assert_eq!(
            metadata.get("literal").map(String::as_str),
            Some("constant")
        );
        assert_eq!(metadata.get("tenant").map(String::as_str), Some("acme"));
    }
}
