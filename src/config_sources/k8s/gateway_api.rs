use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::config::mesh::{AppProtocol, MeshService, ServicePort};
use crate::config::types::{BackendScheme, MAX_TARGET_WEIGHT};

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, RouteBackend, RouteProxySpec, SourceKind,
    exact_path_listen_path, invalid_resource, optional_port_field, port_from_u64, proxy_for_route,
    resource_id, service_dns_name, string_array, string_field, upstream_for_route,
};

const ZERO_WEIGHT_BACKEND_HOST: &str = "ferrum-zero-weight.invalid";
const ZERO_WEIGHT_BACKEND_PORT: u16 = 65535;

pub(super) fn translate(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<bool, K8sTranslateError> {
    match object.kind.as_str() {
        "Gateway" => {
            for service in mesh_services_from_gateway(object)? {
                acc.mesh.services.push(service);
            }
            Ok(true)
        }
        "HTTPRoute" | "GRPCRoute" => {
            for proxy in http_route_proxies(object, acc)? {
                acc.upsert_proxy(proxy, SourceKind::GatewayApi);
            }
            Ok(true)
        }
        "TCPRoute" => {
            for proxy in l4_route_proxies(object, acc, BackendScheme::Tcp)? {
                acc.upsert_proxy(proxy, SourceKind::GatewayApi);
            }
            Ok(true)
        }
        "TLSRoute" => {
            for proxy in l4_route_proxies(object, acc, BackendScheme::Tcps)? {
                acc.upsert_proxy(proxy, SourceKind::GatewayApi);
            }
            Ok(true)
        }
        "ReferenceGrant" => Ok(true),
        _ => Ok(false),
    }
}

pub(super) fn collect_reference_grant(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<(), K8sTranslateError> {
    for from in object
        .spec
        .get("from")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let from_namespace = string_field(from, "namespace").ok_or_else(|| {
            invalid_resource(object, "ReferenceGrant spec.from[].namespace is required")
        })?;
        let from_group = string_field(from, "group").unwrap_or_default();
        let from_kind = string_field(from, "kind").ok_or_else(|| {
            invalid_resource(object, "ReferenceGrant spec.from[].kind is required")
        })?;

        for to in object
            .spec
            .get("to")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let to_kind = string_field(to, "kind").ok_or_else(|| {
                invalid_resource(object, "ReferenceGrant spec.to[].kind is required")
            })?;
            let to_group = string_field(to, "group").unwrap_or_default();
            acc.add_reference_grant(
                from_namespace.to_string(),
                from_group.to_string(),
                from_kind.to_string(),
                object.metadata.namespace.clone(),
                to_group.to_string(),
                to_kind.to_string(),
            );
        }
    }
    Ok(())
}

fn mesh_services_from_gateway(object: &K8sObject) -> Result<Vec<MeshService>, K8sTranslateError> {
    let mut services = Vec::new();
    object
        .spec
        .get("listeners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .try_for_each(|listener| {
            let Some(raw_port) = listener.get("port").and_then(Value::as_u64) else {
                return Ok(());
            };
            let port = port_from_u64(object, raw_port, "listeners[].port")?;
            let name = string_field(listener, "name").unwrap_or("listener");
            services.push(MeshService {
                name: format!("{}-{name}", object.metadata.name),
                namespace: object.metadata.namespace.clone(),
                ports: vec![ServicePort {
                    port,
                    protocol: app_protocol(string_field(listener, "protocol")),
                    name: Some(name.to_string()),
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            });
            Ok::<(), K8sTranslateError>(())
        })?;
    Ok(services)
}

fn http_route_proxies(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
) -> Result<Vec<crate::config::types::Proxy>, K8sTranslateError> {
    let hostnames = string_array(&object.spec, "hostnames");
    let route_kind = object.kind.to_ascii_lowercase();
    let mut proxies = Vec::new();

    for (rule_index, rule) in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let match_paths = match_paths(object, rule);
        if match_paths.is_empty() {
            continue;
        }

        let backends = route_backends(object, rule, acc)?;
        let (backend_host, backend_port, upstream_id) = if backends.is_empty() {
            if !has_only_zero_weight_backend_refs(rule) {
                continue;
            }
            (
                ZERO_WEIGHT_BACKEND_HOST.to_string(),
                ZERO_WEIGHT_BACKEND_PORT,
                None,
            )
        } else if backends.len() == 1 {
            let Some(backend) = backends.into_iter().next() else {
                continue;
            };
            (backend.host, backend.port, None)
        } else {
            let route_suffix = format!("{route_kind}-{rule_index}");
            let upstream_id = resource_id(
                "gwapi-route-upstream",
                &object.metadata.namespace,
                &object.metadata.name,
                &route_suffix,
            );
            acc.upsert_upstream(upstream_for_route(
                upstream_id.clone(),
                object.metadata.namespace.clone(),
                backends,
            ));
            (String::new(), 0, Some(upstream_id))
        };

        let match_count = match_paths.len();
        for (match_index, listen_path) in match_paths.into_iter().enumerate() {
            let suffix = if match_count == 1 {
                format!("{route_kind}-{rule_index}")
            } else {
                format!("{route_kind}-{rule_index}-{match_index}")
            };
            proxies.push(proxy_for_route(RouteProxySpec {
                id: resource_id(
                    "gwapi-route",
                    &object.metadata.namespace,
                    &object.metadata.name,
                    &suffix,
                ),
                namespace: object.metadata.namespace.clone(),
                hosts: hostnames.clone(),
                listen_path,
                strip_listen_path: false,
                backend_host: backend_host.clone(),
                backend_port,
                upstream_id: upstream_id.clone(),
                backend_scheme: BackendScheme::Http,
                listen_port: None,
            }));
        }
    }

    Ok(proxies)
}

fn has_only_zero_weight_backend_refs(rule: &Value) -> bool {
    let Some(backend_refs) = rule.get("backendRefs").and_then(Value::as_array) else {
        return false;
    };
    if backend_refs.is_empty() {
        return false;
    }

    backend_refs
        .iter()
        .all(|backend_ref| backend_ref.get("weight").and_then(Value::as_u64) == Some(0))
}

fn match_paths(object: &K8sObject, rule: &Value) -> Vec<Option<String>> {
    let Some(matches) = rule.get("matches").and_then(Value::as_array) else {
        return vec![Some("/".to_string())];
    };
    if matches.is_empty() {
        return vec![Some("/".to_string())];
    }

    let mut seen_paths = HashSet::new();
    if object.kind == "GRPCRoute" {
        return matches
            .iter()
            .map(|m| {
                m.get("path")
                    .and_then(http_path_match)
                    .or_else(|| Some("/".to_string()))
            })
            .filter(|listen_path| seen_paths.insert(listen_path.clone()))
            .collect();
    }

    matches
        .iter()
        .filter_map(|m| {
            if let Some(path) = m.get("path").and_then(http_path_match) {
                return Some(Some(path));
            }
            if m.as_object().is_some_and(|object| object.is_empty()) {
                return Some(Some("/".to_string()));
            }
            // Pathless predicate-only matches default to "/" in Gateway API, but
            // Ferrum route proxies do not encode those predicates yet.
            None
        })
        .filter(|listen_path| seen_paths.insert(listen_path.clone()))
        .collect()
}

fn route_backends(
    object: &K8sObject,
    rule: &Value,
    acc: &K8sAccumulator,
) -> Result<Vec<RouteBackend>, K8sTranslateError> {
    let mut backends = Vec::new();
    for backend_ref in rule
        .get("backendRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let weight = backend_weight(object, backend_ref)?;
        if weight == 0 {
            continue;
        }
        let backend_name = string_field(backend_ref, "name")
            .ok_or_else(|| invalid_resource(object, "backendRefs[].name is required"))?;
        let backend_namespace =
            checked_backend_namespace(object, backend_ref, acc, object.kind.as_str())?;
        let backend_port =
            optional_port_field(object, backend_ref.get("port"), "backendRefs[].port")?.unwrap_or(
                if object.kind == "GRPCRoute" {
                    50051
                } else {
                    80
                },
            );
        backends.push(RouteBackend {
            host: service_dns_name(backend_name, &backend_namespace),
            port: backend_port,
            weight,
        });
    }
    Ok(backends)
}

fn backend_weight(object: &K8sObject, backend_ref: &Value) -> Result<u32, K8sTranslateError> {
    let Some(weight_value) = backend_ref.get("weight") else {
        return Ok(1);
    };
    let Some(weight) = weight_value.as_u64() else {
        return Err(invalid_resource(
            object,
            format!(
                "backendRefs[].weight must be between 0 and {MAX_TARGET_WEIGHT} (got {weight_value})"
            ),
        ));
    };
    if weight > u64::from(MAX_TARGET_WEIGHT) {
        return Err(invalid_resource(
            object,
            format!(
                "backendRefs[].weight must be between 0 and {MAX_TARGET_WEIGHT} (got {weight})"
            ),
        ));
    }
    Ok(weight as u32)
}

fn l4_route_proxies(
    object: &K8sObject,
    acc: &K8sAccumulator,
    scheme: BackendScheme,
) -> Result<Vec<crate::config::types::Proxy>, K8sTranslateError> {
    let mut proxies = Vec::new();
    for (rule_index, rule) in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(backend_ref) = first_backend_ref(rule) else {
            continue;
        };
        let backend_name = string_field(backend_ref, "name")
            .ok_or_else(|| invalid_resource(object, "backendRefs[].name is required"))?;
        let backend_namespace =
            checked_backend_namespace(object, backend_ref, acc, object.kind.as_str())?;
        let raw_backend_port =
            backend_ref
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    invalid_resource(object, "TCPRoute/TLSRoute backendRefs[].port is required")
                })?;
        let backend_port = port_from_u64(
            object,
            raw_backend_port,
            "TCPRoute/TLSRoute backendRefs[].port",
        )?;

        proxies.push(proxy_for_route(RouteProxySpec {
            id: resource_id(
                "gwapi-l4",
                &object.metadata.namespace,
                &object.metadata.name,
                &rule_index.to_string(),
            ),
            namespace: object.metadata.namespace.clone(),
            hosts: string_array(&object.spec, "hostnames"),
            listen_path: None,
            strip_listen_path: false,
            backend_host: service_dns_name(backend_name, &backend_namespace),
            backend_port,
            upstream_id: None,
            backend_scheme: scheme,
            listen_port: Some(backend_port),
        }));
    }
    Ok(proxies)
}

fn checked_backend_namespace(
    object: &K8sObject,
    backend_ref: &Value,
    acc: &K8sAccumulator,
    from_kind: &str,
) -> Result<String, K8sTranslateError> {
    let backend_namespace =
        string_field(backend_ref, "namespace").unwrap_or(&object.metadata.namespace);
    let to_group = string_field(backend_ref, "group").unwrap_or_default();
    let to_kind = string_field(backend_ref, "kind").unwrap_or("Service");
    validate_supported_backend_ref(object, to_group, to_kind)?;

    if backend_namespace == object.metadata.namespace {
        return Ok(backend_namespace.to_string());
    }

    if acc.reference_grant_allows(
        &object.metadata.namespace,
        api_group(&object.api_version),
        from_kind,
        backend_namespace,
        to_group,
        to_kind,
    ) {
        Ok(backend_namespace.to_string())
    } else {
        Err(invalid_resource(
            object,
            format!(
                "{} backendRef to {} in namespace '{}' requires a matching ReferenceGrant",
                from_kind, to_kind, backend_namespace
            ),
        ))
    }
}

fn validate_supported_backend_ref(
    object: &K8sObject,
    to_group: &str,
    to_kind: &str,
) -> Result<(), K8sTranslateError> {
    if to_group.is_empty() && to_kind == "Service" {
        return Ok(());
    }

    Err(invalid_resource(
        object,
        format!(
            "unsupported backendRef target group '{}' kind '{}'; only core Service backendRefs are supported",
            to_group, to_kind
        ),
    ))
}

fn api_group(api_version: &str) -> &str {
    // Core Kubernetes API versions such as "v1" have no slash; Gateway API
    // represents that core group as the empty string in ReferenceGrant fields.
    api_version
        .split_once('/')
        .map(|(group, _version)| group)
        .unwrap_or_default()
}

fn first_backend_ref(rule: &Value) -> Option<&Value> {
    rule.get("backendRefs")
        .and_then(Value::as_array)
        .and_then(|backend_refs| backend_refs.first())
}

fn http_path_match(path: &Value) -> Option<String> {
    let value = string_field(path, "value")?;
    match string_field(path, "type").unwrap_or("PathPrefix") {
        "Exact" => Some(exact_path_listen_path(value)),
        "RegularExpression" => Some(format!("~{value}")),
        _ => Some(value.to_string()),
    }
}

fn app_protocol(value: Option<&str>) -> AppProtocol {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "http" => AppProtocol::Http,
        "https" | "tls" => AppProtocol::Tls,
        "grpc" => AppProtocol::Grpc,
        "tcp" => AppProtocol::Tcp,
        _ => AppProtocol::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sources::k8s::{K8sMetadata, K8sTranslationOptions, translate_k8s_objects};
    use crate::identity::spiffe::TrustDomain;

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    fn object(kind: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: "sample".to_string(),
                namespace: "default".to_string(),
                labels: HashMap::new(),
            },
            spec,
        }
    }

    fn object_in_namespace(kind: &str, namespace: &str, spec: Value) -> K8sObject {
        K8sObject {
            metadata: K8sMetadata {
                namespace: namespace.to_string(),
                ..object(kind, Value::Null).metadata
            },
            spec,
            ..object(kind, Value::Null)
        }
    }

    #[test]
    fn translates_http_route_to_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].hosts, vec!["api.example.com"]);
        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("/api")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn translates_http_route_exact_path_to_exact_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "Exact", "value": "/api.v1"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("=/api.v1")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
    }

    #[test]
    fn translates_http_route_regular_expression_path_to_regex_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "matches": [{"path": {"type": "RegularExpression", "value": "/v[0-9]+/items"}}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("~/v[0-9]+/items")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
    }

    #[test]
    fn http_route_preserves_weighted_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                        "backendRefs": [
                            {"name": "api-v1", "port": 8080, "weight": 90},
                            {"name": "api-v2", "port": 8081, "weight": 10}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.upstreams.len(), 1);
        assert_eq!(
            result.config.proxies[0].upstream_id.as_deref(),
            Some(result.config.upstreams[0].id.as_str())
        );
        assert_eq!(result.config.upstreams[0].targets.len(), 2);
        assert_eq!(result.config.upstreams[0].targets[0].weight, 90);
        assert_eq!(result.config.upstreams[0].targets[1].port, 8081);
    }

    #[test]
    fn http_route_creates_proxy_per_match() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {"path": {"type": "PathPrefix", "value": "/v1"}},
                            {"path": {"type": "PathPrefix", "value": "/v2"}}
                        ],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let paths: Vec<_> = result
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.listen_path.as_deref())
            .collect();
        assert_eq!(paths, vec![Some("/v1"), Some("/v2")]);
        assert!(
            result
                .config
                .proxies
                .iter()
                .all(|proxy| proxy.backend_port == 8080)
        );
    }

    #[test]
    fn http_route_skips_predicate_only_pathless_matches() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {"headers": [{"name": "x-tenant", "value": "a"}]},
                            {"method": "GET"}
                        ],
                        "backendRefs": [
                            {"name": "api-a", "port": 8080},
                            {"name": "api-b", "port": 8081}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
        assert!(result.config.upstreams.is_empty());
    }

    #[test]
    fn http_route_keeps_empty_match_as_default_catch_all() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [{}],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/"));
        assert_eq!(result.config.proxies[0].backend_port, 8080);
        assert!(result.config.upstreams.is_empty());
    }

    #[test]
    fn http_route_ignores_pathless_match_in_mixed_rule() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [{
                        "matches": [
                            {"path": {"type": "PathPrefix", "value": "/v1"}},
                            {"headers": [{"name": "x-tenant", "value": "a"}]}
                        ],
                        "backendRefs": [{"name": "api", "port": 8080}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/v1"));
    }

    #[test]
    fn grpc_route_keeps_pathless_matches_as_catch_all() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [
                            {"method": {"service": "helloworld.Greeter", "method": "SayHello"}},
                            {"method": {"service": "helloworld.Greeter", "method": "SayGoodbye"}}
                        ],
                        "backendRefs": [{"name": "grpc-api"}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].hosts, vec!["grpc.example.com"]);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/"));
        assert_eq!(result.config.proxies[0].backend_port, 50051);
    }

    #[test]
    fn grpc_route_preserves_weighted_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "hostnames": ["grpc.example.com"],
                    "rules": [{
                        "matches": [
                            {"method": {"service": "helloworld.Greeter", "method": "SayHello"}},
                            {"method": {"service": "helloworld.Greeter", "method": "SayGoodbye"}}
                        ],
                        "backendRefs": [
                            {"name": "grpc-v1", "port": 50051, "weight": 90},
                            {"name": "grpc-v2", "port": 50052, "weight": 10}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/"));
        assert_eq!(result.config.upstreams.len(), 1);
        assert_eq!(
            result.config.proxies[0].upstream_id.as_deref(),
            Some(result.config.upstreams[0].id.as_str())
        );
        assert_eq!(result.config.upstreams[0].targets.len(), 2);
        assert_eq!(result.config.upstreams[0].targets[0].weight, 90);
        assert_eq!(result.config.upstreams[0].targets[1].port, 50052);
    }

    #[test]
    fn gateway_api_weighted_upstream_ids_include_route_kind() {
        let result = translate_k8s_objects(
            &[
                object(
                    "HTTPRoute",
                    serde_json::json!({
                        "hostnames": ["api.example.com"],
                        "rules": [{
                            "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                            "backendRefs": [
                                {"name": "api-v1", "port": 8080, "weight": 90},
                                {"name": "api-v2", "port": 8081, "weight": 10}
                            ]
                        }]
                    }),
                ),
                object(
                    "GRPCRoute",
                    serde_json::json!({
                        "hostnames": ["grpc.example.com"],
                        "rules": [{
                            "matches": [
                                {"method": {"service": "helloworld.Greeter", "method": "SayHello"}}
                            ],
                            "backendRefs": [
                                {"name": "grpc-v1", "port": 50051, "weight": 90},
                                {"name": "grpc-v2", "port": 50052, "weight": 10}
                            ]
                        }]
                    }),
                ),
            ],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        assert_eq!(result.config.upstreams.len(), 2);
        assert_ne!(result.config.upstreams[0].id, result.config.upstreams[1].id);
        assert!(
            result
                .config
                .upstreams
                .iter()
                .any(|upstream| upstream.id.contains("httproute"))
        );
        assert!(
            result
                .config
                .upstreams
                .iter()
                .any(|upstream| upstream.id.contains("grpcroute"))
        );
        assert_eq!(
            result
                .config
                .proxies
                .iter()
                .filter_map(|proxy| proxy.upstream_id.as_deref())
                .collect::<HashSet<_>>()
                .len(),
            2
        );
    }

    #[test]
    fn http_route_keeps_all_zero_weight_rule_as_blackhole() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "hostnames": ["api.example.com"],
                    "rules": [
                        {
                            "matches": [{"path": {"type": "PathPrefix", "value": "/admin"}}],
                            "backendRefs": [{"name": "admin", "port": 8080, "weight": 0}]
                        },
                        {
                            "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                            "backendRefs": [{"name": "api", "port": 8080}]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        let admin_proxy = result
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.listen_path.as_deref() == Some("/admin"))
            .expect("admin route proxy exists");
        assert_eq!(admin_proxy.backend_host, ZERO_WEIGHT_BACKEND_HOST);
        assert_eq!(admin_proxy.backend_port, ZERO_WEIGHT_BACKEND_PORT);
        assert!(admin_proxy.upstream_id.is_none());
    }

    #[test]
    fn http_route_rejects_backend_weight_above_ferrum_limit() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "api", "port": 8080, "weight": 65536}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("oversized backend weight should fail translation");

        assert!(
            err.to_string()
                .contains("weight must be between 0 and 65535")
        );
    }

    #[test]
    fn http_route_rejects_malformed_backend_weights() {
        for weight in [serde_json::json!(-1), serde_json::json!(1.5)] {
            let err = translate_k8s_objects(
                &[object(
                    "HTTPRoute",
                    serde_json::json!({
                        "rules": [{
                            "backendRefs": [{"name": "api", "port": 8080, "weight": weight}]
                        }]
                    }),
                )],
                options(),
            )
            .expect_err("malformed backend weight should fail translation");

            assert!(
                err.to_string()
                    .contains("weight must be between 0 and 65535")
            );
        }
    }

    #[test]
    fn translates_tcp_route_to_stream_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "TCPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "db", "port": 5432}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].listen_port, Some(5432));
        assert_eq!(
            result.config.proxies[0].backend_scheme,
            Some(BackendScheme::Tcp)
        );
    }

    #[test]
    fn rejects_gateway_api_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "api", "port": 70000}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid port must fail closed");

        assert!(err.to_string().contains("backendRefs[].port"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_gateway_listener_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "Gateway",
                serde_json::json!({
                    "listeners": [{"name": "http", "port": 70000, "protocol": "HTTP"}]
                }),
            )],
            options(),
        )
        .expect_err("invalid listener port must fail closed");

        assert!(err.to_string().contains("listeners[].port"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_l4_route_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "TCPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "db", "port": 70000}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid L4 backend port must fail closed");

        assert!(
            err.to_string()
                .contains("TCPRoute/TLSRoute backendRefs[].port")
        );
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_cross_namespace_backend_ref_without_reference_grant() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{
                            "name": "api",
                            "namespace": "backend",
                            "port": 8080
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("cross-namespace backendRef must fail closed");

        assert!(
            err.to_string()
                .contains("requires a matching ReferenceGrant")
        );
    }

    #[test]
    fn skips_zero_weight_cross_namespace_backend_ref_without_reference_grant() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "api", "port": 8080},
                            {
                                "name": "staged-api",
                                "namespace": "backend",
                                "port": 8081,
                                "weight": 0
                            }
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("zero-weight cross-namespace backendRef should not require a ReferenceGrant");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "api.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 8080);
        assert!(result.config.upstreams.is_empty());
    }

    #[test]
    fn rejects_cross_namespace_backend_ref_when_reference_grant_from_group_mismatches() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let err = translate_k8s_objects(&[route, grant], options())
            .expect_err("ReferenceGrant group must match route API group");

        assert!(
            err.to_string()
                .contains("requires a matching ReferenceGrant")
        );
    }

    #[test]
    fn rejects_cross_namespace_backend_ref_when_reference_grant_to_group_mismatches() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "example.com",
                    "kind": "Service"
                }]
            }),
        );

        let err = translate_k8s_objects(&[route, grant], options())
            .expect_err("ReferenceGrant target group must match backendRef group");

        assert!(
            err.to_string()
                .contains("requires a matching ReferenceGrant")
        );
    }

    #[test]
    fn rejects_unsupported_backend_ref_kind() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{
                            "group": "example.com",
                            "kind": "Backend",
                            "name": "api",
                            "namespace": "default",
                            "port": 8080
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("non-Service backendRefs must fail closed");

        assert!(
            err.to_string()
                .contains("only core Service backendRefs are supported")
        );
    }

    #[test]
    fn accepts_cross_namespace_backend_ref_with_reference_grant() {
        let route = object(
            "HTTPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let result = translate_k8s_objects(&[route, grant], options())
            .expect("ReferenceGrant should authorize backendRef");

        assert_eq!(
            result.config.proxies[0].backend_host,
            "api.backend.svc.cluster.local"
        );
    }

    #[test]
    fn accepts_tcp_route_cross_namespace_backend_ref_with_reference_grant() {
        let route = object(
            "TCPRoute",
            serde_json::json!({
                "rules": [{
                    "backendRefs": [{
                        "name": "db",
                        "namespace": "backend",
                        "port": 5432
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "gateway.networking.k8s.io",
                    "kind": "TCPRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let result = translate_k8s_objects(&[route, grant], options())
            .expect("ReferenceGrant should authorize TCPRoute backendRef");

        assert_eq!(
            result.config.proxies[0].backend_host,
            "db.backend.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].listen_port, Some(5432));
        assert_eq!(
            result.config.proxies[0].backend_scheme,
            Some(BackendScheme::Tcp)
        );
    }

    #[test]
    fn rejects_tls_route_cross_namespace_backend_ref_when_reference_grant_from_group_mismatches() {
        let route = object(
            "TLSRoute",
            serde_json::json!({
                "hostnames": ["db.example.com"],
                "rules": [{
                    "backendRefs": [{
                        "name": "db",
                        "namespace": "backend",
                        "port": 15443
                    }]
                }]
            }),
        );
        let grant = object_in_namespace(
            "ReferenceGrant",
            "backend",
            serde_json::json!({
                "from": [{
                    "group": "",
                    "kind": "TLSRoute",
                    "namespace": "default"
                }],
                "to": [{
                    "group": "",
                    "kind": "Service"
                }]
            }),
        );

        let err = translate_k8s_objects(&[route, grant], options())
            .expect_err("ReferenceGrant group must match TLSRoute API group");

        assert!(
            err.to_string()
                .contains("requires a matching ReferenceGrant")
        );
    }
}
