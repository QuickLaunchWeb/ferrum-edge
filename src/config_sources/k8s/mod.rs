//! Kubernetes config-source translation (Layer 4).
//!
//! This module accepts unstructured Kubernetes resources and translates the
//! supported Istio + Gateway API surface into Ferrum's canonical Layer 2 model.
//! Unsupported resources fail closed when silent translation would be unsafe.

mod gateway_api;
mod istio;

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::types::{
    BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig, LoadBalancerAlgorithm,
    PluginAssociation, PluginConfig, PluginScope, Proxy, ResponseBodyMode, RetryConfig, Upstream,
    UpstreamTarget, default_namespace,
};
use crate::identity::spiffe::TrustDomain;
use crate::modes::mesh::config::MeshConfig;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct K8sMetadata {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct K8sObject {
    #[serde(default, rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub metadata: K8sMetadata,
    #[serde(default)]
    pub spec: Value,
}

#[derive(Debug, Clone)]
pub struct K8sTranslationOptions {
    pub namespace: String,
    pub trust_domain: TrustDomain,
    pub prefer_istio_on_overlap: bool,
    pub istio_root_namespace: String,
    source_namespaces: Option<HashSet<String>>,
}

impl K8sTranslationOptions {
    pub fn new(namespace: String, trust_domain: TrustDomain) -> Self {
        let source_namespaces = HashSet::from([namespace.clone()]);
        Self {
            namespace,
            trust_domain,
            prefer_istio_on_overlap: true,
            istio_root_namespace: "istio-system".to_string(),
            source_namespaces: Some(source_namespaces),
        }
    }

    pub fn with_istio_root_namespace(mut self, namespace: String) -> Self {
        if !namespace.trim().is_empty() {
            self.istio_root_namespace = namespace;
        }
        self
    }

    pub fn with_source_namespaces(mut self, namespaces: Vec<String>) -> Self {
        self.source_namespaces = if namespaces.is_empty() {
            None
        } else {
            Some(namespaces.into_iter().collect())
        };
        self
    }

    fn includes_namespace(&self, namespace: &str) -> bool {
        self.source_namespaces
            .as_ref()
            .is_none_or(|namespaces| namespaces.contains(namespace))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedK8sResource {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum K8sTranslateError {
    Unsupported(UnsupportedK8sResource),
    InvalidResource {
        kind: String,
        namespace: String,
        name: String,
        message: String,
    },
}

impl std::fmt::Display for K8sTranslateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(resource) => write!(
                f,
                "unsupported Kubernetes resource {}/{} {}: {}",
                resource.namespace, resource.name, resource.kind, resource.reason
            ),
            Self::InvalidResource {
                kind,
                namespace,
                name,
                message,
            } => write!(
                f,
                "invalid Kubernetes resource {}/{} {}: {}",
                namespace, name, kind, message
            ),
        }
    }
}

impl std::error::Error for K8sTranslateError {}

#[derive(Debug, Clone, Default)]
pub struct K8sTranslation {
    pub config: GatewayConfig,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceKind {
    Istio,
    GatewayApi,
}

pub(crate) struct K8sAccumulator {
    pub options: K8sTranslationOptions,
    pub config: GatewayConfig,
    pub mesh: MeshConfig,
    pub warnings: Vec<String>,
    reference_grants: HashSet<ReferenceGrantPermission>,
    proxy_sources: HashMap<String, SourceKind>,
    known_namespaces: HashSet<String>,
}

impl K8sAccumulator {
    fn new(options: K8sTranslationOptions) -> Self {
        Self {
            options,
            config: GatewayConfig::default(),
            mesh: MeshConfig::default(),
            warnings: Vec::new(),
            reference_grants: HashSet::new(),
            proxy_sources: HashMap::new(),
            known_namespaces: HashSet::new(),
        }
    }

    fn observe_namespace(&mut self, namespace: &str) {
        self.known_namespaces.insert(namespace.to_string());
    }

    pub(crate) fn add_reference_grant(
        &mut self,
        from_namespace: String,
        from_group: String,
        from_kind: String,
        to_namespace: String,
        to_group: String,
        to_kind: String,
    ) {
        self.reference_grants.insert(ReferenceGrantPermission {
            from_namespace,
            from_group,
            from_kind,
            to_namespace,
            to_group,
            to_kind,
        });
    }

    pub(crate) fn reference_grant_allows(
        &self,
        from_namespace: &str,
        from_group: &str,
        from_kind: &str,
        to_namespace: &str,
        to_group: &str,
        to_kind: &str,
    ) -> bool {
        self.reference_grants.contains(&ReferenceGrantPermission {
            from_namespace: from_namespace.to_string(),
            from_group: from_group.to_string(),
            from_kind: from_kind.to_string(),
            to_namespace: to_namespace.to_string(),
            to_group: to_group.to_string(),
            to_kind: to_kind.to_string(),
        })
    }

    pub(crate) fn upsert_proxy(&mut self, proxy: Proxy, source: SourceKind) {
        if let Some(existing_source) = self.proxy_sources.get(&proxy.id).copied() {
            let istio_wins = self.options.prefer_istio_on_overlap
                && existing_source == SourceKind::GatewayApi
                && source == SourceKind::Istio;
            let gateway_loses = self.options.prefer_istio_on_overlap
                && existing_source == SourceKind::Istio
                && source == SourceKind::GatewayApi;

            if gateway_loses {
                self.warnings.push(format!(
                    "Gateway API proxy '{}' ignored because Istio resource has precedence",
                    proxy.id
                ));
                return;
            }

            if let Some(existing) = self.config.proxies.iter_mut().find(|p| p.id == proxy.id) {
                if istio_wins || !self.options.prefer_istio_on_overlap {
                    *existing = proxy;
                    self.proxy_sources.insert(existing.id.clone(), source);
                }
                return;
            }
        }

        self.proxy_sources.insert(proxy.id.clone(), source);
        self.config.proxies.push(proxy);
    }

    pub(crate) fn upsert_upstream(&mut self, upstream: Upstream) {
        if let Some(existing) = self
            .config
            .upstreams
            .iter_mut()
            .find(|candidate| candidate.id == upstream.id)
        {
            *existing = upstream;
        } else {
            self.config.upstreams.push(upstream);
        }
    }

    fn finish(mut self) -> K8sTranslation {
        self.mesh.normalize();
        self.mesh.request_authentications.sort_by(|left, right| {
            (&left.namespace, &left.name).cmp(&(&right.namespace, &right.name))
        });
        self.mesh.telemetry_resources.sort_by(|left, right| {
            (&left.namespace, &left.name).cmp(&(&right.namespace, &right.name))
        });
        if self.mesh != MeshConfig::default() {
            self.config.mesh = Some(Box::new(self.mesh));
        }
        let mut known_namespaces: Vec<String> = self.known_namespaces.into_iter().collect();
        known_namespaces.sort();
        self.config.known_namespaces.extend(known_namespaces);
        self.config.normalize_fields();
        K8sTranslation {
            config: self.config,
            warnings: self.warnings,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReferenceGrantPermission {
    from_namespace: String,
    from_group: String,
    from_kind: String,
    to_namespace: String,
    to_group: String,
    to_kind: String,
}

pub fn translate_k8s_objects(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
) -> Result<K8sTranslation, K8sTranslateError> {
    translate_k8s_objects_with_filter(objects, options, |_| true)
}

pub(crate) fn translate_k8s_objects_with_filter<F>(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    include: F,
) -> Result<K8sTranslation, K8sTranslateError>
where
    F: Fn(&K8sObject) -> bool,
{
    let mut acc = K8sAccumulator::new(options);

    for object in objects.iter().filter(|object| include(object)) {
        if !acc.options.includes_namespace(&object.metadata.namespace) {
            continue;
        }
        acc.observe_namespace(&object.metadata.namespace);
        if object.kind == "ReferenceGrant" {
            gateway_api::collect_reference_grant(&mut acc, object)?;
        }
    }

    for object in objects.iter().filter(|object| include(object)) {
        if !acc.options.includes_namespace(&object.metadata.namespace) {
            continue;
        }
        acc.observe_namespace(&object.metadata.namespace);

        if object.kind == "EnvoyFilter" {
            return Err(K8sTranslateError::Unsupported(UnsupportedK8sResource {
                kind: object.kind.clone(),
                namespace: object.metadata.namespace.clone(),
                name: object.metadata.name.clone(),
                reason: "EnvoyFilter is intentionally unsupported; file an issue with the required behavior instead of relying on opaque Envoy patches".to_string(),
            }));
        }

        if istio::translate(&mut acc, object)? || gateway_api::translate(&mut acc, object)? {
            continue;
        }

        acc.warnings.push(format!(
            "Ignoring unsupported Kubernetes resource kind '{}' in {}/{}",
            object.kind, object.metadata.namespace, object.metadata.name
        ));
    }

    Ok(acc.finish())
}

pub(crate) fn invalid_resource(
    object: &K8sObject,
    message: impl Into<String>,
) -> K8sTranslateError {
    K8sTranslateError::InvalidResource {
        kind: object.kind.clone(),
        namespace: object.metadata.namespace.clone(),
        name: object.metadata.name.clone(),
        message: message.into(),
    }
}

pub(crate) fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

pub(crate) fn string_array(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

pub(crate) fn string_map(value: &Value) -> HashMap<String, String> {
    value
        .as_object()
        .into_iter()
        .flat_map(|map| map.iter())
        .filter_map(|(key, value)| value.as_str().map(|v| (key.clone(), v.to_string())))
        .collect()
}

pub(crate) fn port_from_u64(
    object: &K8sObject,
    raw: u64,
    field: &str,
) -> Result<u16, K8sTranslateError> {
    if raw == 0 || raw > u16::MAX as u64 {
        return Err(invalid_resource(
            object,
            format!("{field} must be between 1 and 65535 (got {raw})"),
        ));
    }
    Ok(raw as u16)
}

pub(crate) fn optional_port_field(
    object: &K8sObject,
    value: Option<&Value>,
    field: &str,
) -> Result<Option<u16>, K8sTranslateError> {
    value
        .and_then(Value::as_u64)
        .map(|raw| port_from_u64(object, raw, field))
        .transpose()
}

pub(crate) fn selector_from_istio(value: Option<&Value>) -> HashMap<String, String> {
    value
        .and_then(|selector| selector.get("matchLabels"))
        .map(string_map)
        .unwrap_or_default()
}

pub(crate) struct RouteProxySpec {
    pub id: String,
    pub namespace: String,
    pub hosts: Vec<String>,
    pub listen_path: Option<String>,
    pub strip_listen_path: bool,
    pub backend_host: String,
    pub backend_port: u16,
    pub upstream_id: Option<String>,
    pub backend_scheme: BackendScheme,
    pub listen_port: Option<u16>,
    pub retry: Option<RetryConfig>,
    pub backend_read_timeout_ms: Option<u64>,
}

pub(crate) fn proxy_for_route(spec: RouteProxySpec) -> Proxy {
    let now = Utc::now();
    Proxy {
        id: spec.id,
        name: None,
        namespace: spec.namespace,
        hosts: spec.hosts,
        listen_path: spec.listen_path,
        backend_scheme: Some(spec.backend_scheme),
        dispatch_kind: DispatchKind::default(),
        backend_host: spec.backend_host,
        backend_port: spec.backend_port,
        backend_path: None,
        strip_listen_path: spec.strip_listen_path,
        preserve_host_header: false,
        backend_connect_timeout_ms: 30_000,
        backend_read_timeout_ms: spec.backend_read_timeout_ms.unwrap_or(30_000),
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: spec.upstream_id,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: spec.retry,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: spec.listen_port,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

/// Build a `fault_injection` plugin config scoped to a specific proxy.
pub(crate) fn fault_injection_plugin_for_proxy(
    proxy_id: &str,
    namespace: &str,
    fault: &Value,
) -> Option<PluginConfig> {
    let obj = fault.as_object()?;
    let mut config = serde_json::Map::new();

    if let Some(delay_obj) = obj.get("delay").and_then(Value::as_object)
        && let Some(delay_str) = delay_obj.get("fixedDelay").and_then(Value::as_str)
        && let Some(ms) = parse_istio_duration_ms(delay_str)
        && let Some(percentage) = istio_fault_percentage(delay_obj)
    {
        config.insert(
            "delay".to_string(),
            serde_json::json!({
                "duration_ms": ms,
                "percentage": percentage,
            }),
        );
    }

    if let Some(abort_obj) = obj.get("abort").and_then(Value::as_object)
        && let Some(percentage) = istio_fault_percentage(abort_obj)
    {
        let mut abort_value = serde_json::Map::new();
        abort_value.insert("percentage".to_string(), serde_json::json!(percentage));

        if let Some(status) = abort_obj.get("httpStatus").and_then(Value::as_u64)
            && (200..=599).contains(&status)
        {
            abort_value.insert("status_code".to_string(), serde_json::json!(status));
        }

        if let Some(grpc) = abort_obj
            .get("grpcStatus")
            .and_then(parse_istio_grpc_status)
        {
            abort_value.insert("grpc_status".to_string(), serde_json::json!(grpc));
        }

        // Plugin requires status_code; skip the abort sub-field if absent.
        if abort_value.contains_key("status_code") {
            config.insert("abort".to_string(), Value::Object(abort_value));
        }
    }

    if config.is_empty() {
        return None;
    }

    let now = Utc::now();
    Some(PluginConfig {
        id: format!("istio-vs-fi-{proxy_id}"),
        plugin_name: "fault_injection".to_string(),
        namespace: namespace.to_string(),
        config: Value::Object(config),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    })
}

/// Parse an Istio duration string to milliseconds. Supports the same suffix
/// set as Go's `time.ParseDuration` (`ns`, `us`, `ms`, `s`, `m`, `h`); Istio's
/// CRDs expose this format via `google.protobuf.Duration`'s string form
/// (e.g., `"5s"`, `"500ms"`, `"30m"`, `"1.5h"`). Sub-millisecond inputs that
/// round down to zero return `None` because the target plugins require
/// `duration_ms > 0`.
pub(crate) fn parse_istio_duration_ms(duration: &str) -> Option<u64> {
    let trimmed = duration.trim();
    // 2-char suffixes first so they aren't shadowed by the trailing `s` or `m`.
    if let Some(s) = trimmed.strip_suffix("ms") {
        return duration_component_ms(s, 1.0);
    }
    if let Some(s) = trimmed.strip_suffix("us") {
        return duration_component_ms(s, 0.001);
    }
    if let Some(s) = trimmed.strip_suffix("ns") {
        return duration_component_ms(s, 0.000_001);
    }
    if let Some(s) = trimmed.strip_suffix('s') {
        return duration_component_ms(s, 1000.0);
    }
    if let Some(s) = trimmed.strip_suffix('m') {
        return duration_component_ms(s, 60_000.0);
    }
    if let Some(s) = trimmed.strip_suffix('h') {
        return duration_component_ms(s, 3_600_000.0);
    }
    None
}

fn duration_component_ms(raw: &str, multiplier: f64) -> Option<u64> {
    let value: f64 = raw.trim().parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let ms = value * multiplier;
    if !ms.is_finite() || ms > u64::MAX as f64 {
        return None;
    }
    let result = ms as u64;
    if result > 0 { Some(result) } else { None }
}

/// Extract an Istio fault percentage in the range (0.0, 100.0]. Accepts both
/// the nested `percentage.value` (Istio's `Percent` message) and the legacy
/// `percent` integer field. Returns `None` for omitted, zero, or out-of-range
/// values so the caller can skip emitting a sub-field that the
/// `fault_injection` plugin would reject (`parse_percentage` rejects 0.0 and
/// anything outside 0–100 inclusive).
fn istio_fault_percentage(obj: &serde_json::Map<String, Value>) -> Option<f64> {
    let raw = obj
        .get("percentage")
        .and_then(|p| p.get("value"))
        .and_then(Value::as_f64)
        .or_else(|| obj.get("percent").and_then(Value::as_f64));
    let pct = raw.unwrap_or(100.0);
    if pct.is_finite() && pct > 0.0 && pct <= 100.0 {
        Some(pct)
    } else {
        None
    }
}

/// Translate Istio's `grpcStatus` field (per
/// <https://github.com/grpc/grpc/blob/master/doc/statuscodes.md>) into the
/// numeric `0..=16` form expected by the `fault_injection` plugin. Accepts the
/// canonical string name (`"UNAVAILABLE"`), the same name with hyphens, or a
/// numeric literal. Returns `None` for unknown / out-of-range input rather
/// than emitting a plugin config the plugin constructor would reject.
fn parse_istio_grpc_status(value: &Value) -> Option<u32> {
    if let Some(code) = value.as_u64() {
        return u32::try_from(code).ok().filter(|c| *c <= 16);
    }
    let raw = value.as_str()?.trim();
    if let Ok(code) = raw.parse::<u32>() {
        return if code <= 16 { Some(code) } else { None };
    }
    let normalized = raw.replace('-', "_").to_ascii_uppercase();
    match normalized.as_str() {
        "OK" => Some(0),
        "CANCELLED" | "CANCELED" => Some(1),
        "UNKNOWN" => Some(2),
        "INVALID_ARGUMENT" => Some(3),
        "DEADLINE_EXCEEDED" => Some(4),
        "NOT_FOUND" => Some(5),
        "ALREADY_EXISTS" => Some(6),
        "PERMISSION_DENIED" => Some(7),
        "RESOURCE_EXHAUSTED" => Some(8),
        "FAILED_PRECONDITION" => Some(9),
        "ABORTED" => Some(10),
        "OUT_OF_RANGE" => Some(11),
        "UNIMPLEMENTED" => Some(12),
        "INTERNAL" => Some(13),
        "UNAVAILABLE" => Some(14),
        "DATA_LOSS" => Some(15),
        "UNAUTHENTICATED" => Some(16),
        _ => None,
    }
}

pub(crate) struct RouteBackend {
    pub host: String,
    pub port: u16,
    pub weight: u32,
}

pub(crate) fn upstream_for_route(
    id: String,
    namespace: String,
    backends: Vec<RouteBackend>,
) -> Upstream {
    let now = Utc::now();
    let first_weight = backends.first().map(|backend| backend.weight).unwrap_or(1);
    let has_weighted_target = backends
        .iter()
        .any(|backend| backend.weight != first_weight);
    Upstream {
        id: id.clone(),
        name: Some(id),
        namespace,
        targets: backends
            .into_iter()
            .map(|backend| UpstreamTarget {
                host: backend.host,
                port: backend.port,
                weight: backend.weight,
                tags: HashMap::new(),
                path: None,
            })
            .collect(),
        algorithm: if has_weighted_target {
            LoadBalancerAlgorithm::WeightedRoundRobin
        } else {
            LoadBalancerAlgorithm::RoundRobin
        },
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn service_dns_name(name: &str, namespace: &str) -> String {
    format!("{name}.{namespace}.svc.cluster.local")
}

pub(crate) fn exact_path_listen_path(path: &str) -> String {
    format!("={path}")
}

pub(crate) fn resource_id(prefix: &str, namespace: &str, name: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        format!("{prefix}-{namespace}-{name}")
    } else {
        format!("{prefix}-{namespace}-{name}-{suffix}")
    }
    .replace(['/', '.'], "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(kind: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: "networking.istio.io/v1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: "sample".to_string(),
                namespace: "default".to_string(),
                labels: HashMap::new(),
            },
            spec,
        }
    }

    fn options(namespace: &str) -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            namespace.to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    #[test]
    fn rejects_envoy_filter_fail_closed() {
        let err = translate_k8s_objects(
            &[object("EnvoyFilter", serde_json::json!({}))],
            options("default"),
        )
        .expect_err("EnvoyFilter must fail closed");

        assert!(
            err.to_string()
                .contains("EnvoyFilter is intentionally unsupported")
        );
    }

    #[test]
    fn filters_resources_by_namespace() {
        let ignored = object(
            "PeerAuthentication",
            serde_json::json!({"mtls": {"mode": "STRICT"}}),
        );
        let result =
            translate_k8s_objects(&[ignored], options("prod")).expect("translation should succeed");

        assert!(result.config.mesh.is_none());
    }

    #[test]
    fn controller_can_disable_source_namespace_filter() {
        let object = object(
            "PeerAuthentication",
            serde_json::json!({"mtls": {"mode": "STRICT"}}),
        );
        let options = options("ferrum").with_source_namespaces(Vec::new());

        let result = translate_k8s_objects(&[object], options).expect("translation should succeed");

        assert!(result.config.mesh.is_some());
    }

    #[test]
    fn translation_records_included_source_namespaces() {
        let mut default_object = object(
            "PeerAuthentication",
            serde_json::json!({"mtls": {"mode": "STRICT"}}),
        );
        default_object.metadata.namespace = "default".to_string();
        let mut prod_object = default_object.clone();
        prod_object.metadata.namespace = "prod".to_string();
        let mut ignored_object = default_object.clone();
        ignored_object.metadata.namespace = "ignored".to_string();
        let options = options("ferrum")
            .with_source_namespaces(vec!["default".to_string(), "prod".to_string()]);

        let result = translate_k8s_objects(&[default_object, prod_object, ignored_object], options)
            .expect("translation should succeed");

        assert_eq!(
            result.config.known_namespaces,
            vec!["default".to_string(), "prod".to_string()]
        );
    }

    #[test]
    fn controller_source_namespace_filter_uses_watch_namespaces() {
        let object = object(
            "PeerAuthentication",
            serde_json::json!({"mtls": {"mode": "STRICT"}}),
        );
        let options = options("ferrum")
            .with_source_namespaces(vec!["default".to_string(), "prod".to_string()]);

        let result = translate_k8s_objects(&[object], options).expect("translation should succeed");

        assert!(result.config.mesh.is_some());
    }

    #[test]
    fn port_from_u64_enforces_kubernetes_port_boundaries() {
        let object = object("HTTPRoute", serde_json::json!({}));

        assert!(port_from_u64(&object, 0, "port").is_err());
        assert_eq!(port_from_u64(&object, 1, "port").unwrap(), 1);
        assert_eq!(port_from_u64(&object, 65_535, "port").unwrap(), 65_535);
        assert!(port_from_u64(&object, 65_536, "port").is_err());
        assert!(port_from_u64(&object, u64::MAX, "port").is_err());
    }
}
