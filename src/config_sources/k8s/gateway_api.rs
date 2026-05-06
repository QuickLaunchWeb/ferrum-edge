use std::collections::HashMap;

use serde_json::Value;

use crate::config::mesh::{AppProtocol, MeshService, ServicePort};
use crate::config::types::BackendScheme;

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, RouteBackend, RouteProxySpec, SourceKind,
    invalid_resource, proxy_for_route, resource_id, service_dns_name, string_array, string_field,
    upstream_for_route,
};

pub(super) fn translate(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<bool, K8sTranslateError> {
    match object.kind.as_str() {
        "Gateway" => {
            for service in mesh_services_from_gateway(object) {
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
            acc.add_reference_grant(
                from_namespace.to_string(),
                from_kind.to_string(),
                object.metadata.namespace.clone(),
                to_kind.to_string(),
            );
        }
    }
    Ok(())
}

fn mesh_services_from_gateway(object: &K8sObject) -> Vec<MeshService> {
    object
        .spec
        .get("listeners")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|listener| {
            let port = listener.get("port").and_then(Value::as_u64)? as u16;
            let name = string_field(listener, "name").unwrap_or("listener");
            Some(MeshService {
                name: format!("{}-{name}", object.metadata.name),
                namespace: object.metadata.namespace.clone(),
                ports: vec![ServicePort {
                    port,
                    protocol: app_protocol(string_field(listener, "protocol")),
                    name: Some(name.to_string()),
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            })
        })
        .collect()
}

fn http_route_proxies(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
) -> Result<Vec<crate::config::types::Proxy>, K8sTranslateError> {
    let hostnames = string_array(&object.spec, "hostnames");
    let mut proxies = Vec::new();

    for (rule_index, rule) in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let backends = route_backends(object, rule, acc)?;
        if backends.is_empty() {
            continue;
        };

        let (backend_host, backend_port, upstream_id) = if backends.len() == 1 {
            let backend = backends.into_iter().next().expect("one backend");
            (backend.host, backend.port, None)
        } else {
            let upstream_id = resource_id(
                "gwapi-route-upstream",
                &object.metadata.namespace,
                &object.metadata.name,
                &rule_index.to_string(),
            );
            acc.upsert_upstream(upstream_for_route(
                upstream_id.clone(),
                object.metadata.namespace.clone(),
                backends,
            ));
            (String::new(), 0, Some(upstream_id))
        };

        let match_paths = rule
            .get("matches")
            .and_then(Value::as_array)
            .map(|matches| {
                matches
                    .iter()
                    .map(|m| {
                        m.get("path")
                            .and_then(http_path_match)
                            .or_else(|| Some("/".to_string()))
                    })
                    .collect::<Vec<_>>()
            })
            .filter(|matches| !matches.is_empty())
            .unwrap_or_else(|| vec![Some("/".to_string())]);

        let match_count = match_paths.len();
        for (match_index, listen_path) in match_paths.into_iter().enumerate() {
            let suffix = if match_count == 1 {
                rule_index.to_string()
            } else {
                format!("{rule_index}-{match_index}")
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
        let backend_name = string_field(backend_ref, "name")
            .ok_or_else(|| invalid_resource(object, "backendRefs[].name is required"))?;
        let backend_namespace =
            checked_backend_namespace(object, backend_ref, acc, object.kind.as_str())?;
        let backend_port = backend_ref.get("port").and_then(Value::as_u64).unwrap_or(
            if object.kind == "GRPCRoute" {
                50051
            } else {
                80
            },
        ) as u16;
        let weight = backend_weight(object, backend_ref)?;
        if weight == 0 {
            continue;
        }
        backends.push(RouteBackend {
            host: service_dns_name(backend_name, &backend_namespace),
            port: backend_port,
            weight,
        });
    }
    Ok(backends)
}

fn backend_weight(object: &K8sObject, backend_ref: &Value) -> Result<u32, K8sTranslateError> {
    let Some(weight) = backend_ref.get("weight").and_then(Value::as_u64) else {
        return Ok(1);
    };
    u32::try_from(weight).map_err(|_| {
        invalid_resource(
            object,
            format!("backendRefs[].weight {weight} exceeds u32::MAX"),
        )
    })
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
        let backend_port = backend_ref
            .get("port")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                invalid_resource(object, "TCPRoute/TLSRoute backendRefs[].port is required")
            })? as u16;

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
    if backend_namespace == object.metadata.namespace {
        return Ok(backend_namespace.to_string());
    }

    let to_kind = string_field(backend_ref, "kind").unwrap_or("Service");
    if acc.reference_grant_allows(
        &object.metadata.namespace,
        from_kind,
        backend_namespace,
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

fn first_backend_ref(rule: &Value) -> Option<&Value> {
    rule.get("backendRefs")
        .and_then(Value::as_array)
        .and_then(|backend_refs| backend_refs.first())
}

fn http_path_match(path: &Value) -> Option<String> {
    let value = string_field(path, "value")?;
    match string_field(path, "type").unwrap_or("PathPrefix") {
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
        assert_eq!(result.config.proxies[0].backend_port, 8080);
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
}
