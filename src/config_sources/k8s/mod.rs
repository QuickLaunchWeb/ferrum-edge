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

use crate::config::mesh::MeshConfig;
use crate::config::types::{
    BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig, PluginAssociation, Proxy,
    ResponseBodyMode, default_namespace,
};
use crate::identity::spiffe::TrustDomain;

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
}

impl K8sTranslationOptions {
    pub fn new(namespace: String, trust_domain: TrustDomain) -> Self {
        Self {
            namespace,
            trust_domain,
            prefer_istio_on_overlap: true,
        }
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
        }
    }

    pub(crate) fn add_reference_grant(
        &mut self,
        from_namespace: String,
        from_kind: String,
        to_namespace: String,
        to_kind: String,
    ) {
        self.reference_grants.insert(ReferenceGrantPermission {
            from_namespace,
            from_kind,
            to_namespace,
            to_kind,
        });
    }

    pub(crate) fn reference_grant_allows(
        &self,
        from_namespace: &str,
        from_kind: &str,
        to_namespace: &str,
        to_kind: &str,
    ) -> bool {
        self.reference_grants.contains(&ReferenceGrantPermission {
            from_namespace: from_namespace.to_string(),
            from_kind: from_kind.to_string(),
            to_namespace: to_namespace.to_string(),
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

    fn finish(mut self) -> K8sTranslation {
        self.mesh.normalize();
        if self.mesh != MeshConfig::default() {
            self.config.mesh = Some(Box::new(self.mesh));
        }
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
    from_kind: String,
    to_namespace: String,
    to_kind: String,
}

pub fn translate_k8s_objects(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
) -> Result<K8sTranslation, K8sTranslateError> {
    let mut acc = K8sAccumulator::new(options);

    for object in objects {
        if object.kind == "ReferenceGrant" {
            gateway_api::collect_reference_grant(&mut acc, object)?;
        }
    }

    for object in objects {
        if object.metadata.namespace != acc.options.namespace {
            continue;
        }

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
    pub backend_scheme: BackendScheme,
    pub listen_port: Option<u16>,
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
        backend_read_timeout_ms: 30_000,
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
        upstream_id: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
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
}
