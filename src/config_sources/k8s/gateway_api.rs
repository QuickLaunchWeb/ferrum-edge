use std::collections::HashMap;

use serde_json::Value;

use crate::config::mesh::{AppProtocol, MeshService, ServicePort};
use crate::config::types::BackendScheme;

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, RouteProxySpec, SourceKind, invalid_resource,
    optional_port_field, port_from_u64, proxy_for_route, resource_id, service_dns_name,
    string_array, string_field,
};

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
    let mut proxies = Vec::new();

    for (rule_index, rule) in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(backend_ref) = first_backend_ref(object, rule, acc)? else {
            continue;
        };
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

        let listen_path = rule
            .get("matches")
            .and_then(Value::as_array)
            .and_then(|matches| matches.first())
            .and_then(|m| m.get("path"))
            .and_then(http_path_match)
            .or_else(|| Some("/".to_string()));

        let backend_host = service_dns_name(backend_name, &backend_namespace);
        proxies.push(proxy_for_route(RouteProxySpec {
            id: resource_id(
                "gwapi-route",
                &object.metadata.namespace,
                &object.metadata.name,
                &rule_index.to_string(),
            ),
            namespace: object.metadata.namespace.clone(),
            hosts: hostnames.clone(),
            listen_path,
            backend_host: backend_host.clone(),
            backend_port,
            backend_scheme: BackendScheme::Http,
            listen_port: None,
        }));
    }

    Ok(proxies)
}

fn l4_route_proxies(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
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
        let Some(backend_ref) = first_backend_ref(object, rule, acc)? else {
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
            backend_host: service_dns_name(backend_name, &backend_namespace),
            backend_port,
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

fn first_backend_ref<'a>(
    object: &K8sObject,
    rule: &'a Value,
    acc: &mut K8sAccumulator,
) -> Result<Option<&'a Value>, K8sTranslateError> {
    let Some(backend_refs) = rule.get("backendRefs").and_then(Value::as_array) else {
        return Ok(None);
    };

    let mut selected_backend = None;
    let mut skipped_zero = 0usize;
    for backend_ref in backend_refs {
        let weight = backend_ref_weight(object, backend_ref)?;
        if weight > 0 {
            selected_backend.get_or_insert(backend_ref);
        } else {
            skipped_zero += 1;
        }
    }

    if let Some(backend_ref) = selected_backend {
        if skipped_zero > 0 {
            acc.warnings.push(format!(
                "{} skipped {} zero-weight backendRef(s)",
                object.kind, skipped_zero
            ));
        }
        return Ok(Some(backend_ref));
    }

    if skipped_zero > 0 {
        acc.warnings.push(format!(
            "{} rule has only zero-weight backendRefs; no proxy was materialized",
            object.kind
        ));
    }
    Ok(None)
}

fn backend_ref_weight(object: &K8sObject, backend_ref: &Value) -> Result<u64, K8sTranslateError> {
    match backend_ref.get("weight") {
        Some(Value::Number(number)) if number.as_i64().is_some_and(|weight| weight < 0) => Err(
            invalid_resource(object, "backendRefs[].weight must be zero or positive"),
        ),
        Some(value) => Ok(value.as_u64().unwrap_or(1)),
        None => Ok(1),
    }
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
    fn http_route_skips_zero_weight_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "dark", "port": 8080, "weight": 0},
                            {"name": "stable", "port": 9090, "weight": 100}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 9090);
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("zero-weight backendRef"))
        );
    }

    #[test]
    fn http_route_with_only_zero_weight_backend_refs_is_not_materialized() {
        let result = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "dark", "port": 8080, "weight": 0}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight backendRefs"))
        );
    }

    #[test]
    fn grpc_route_skips_zero_weight_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "GRPCRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "dark", "port": 50051, "weight": 0},
                            {"name": "stable", "port": 50052, "weight": 100}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 50052);
    }

    #[test]
    fn tcp_route_skips_zero_weight_backend_refs() {
        let result = translate_k8s_objects(
            &[object(
                "TCPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "dark", "port": 5432, "weight": 0},
                            {"name": "stable", "port": 5433, "weight": 1}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(
            result.config.proxies[0].backend_host,
            "stable.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].listen_port, Some(5433));
        assert_eq!(
            result.config.proxies[0].backend_scheme,
            Some(BackendScheme::Tcp)
        );
    }

    #[test]
    fn tls_route_with_only_zero_weight_backend_refs_is_not_materialized() {
        let result = translate_k8s_objects(
            &[object(
                "TLSRoute",
                serde_json::json!({
                    "hostnames": ["db.example.com"],
                    "rules": [{
                        "backendRefs": [{"name": "dark", "port": 15443, "weight": 0}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight backendRefs"))
        );
    }

    #[test]
    fn gateway_route_rejects_negative_backend_ref_weight() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [{"name": "dark", "port": 8080, "weight": -1}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("negative backendRef weights are invalid");

        assert!(err.to_string().contains("weight must be zero or positive"));
    }

    #[test]
    fn gateway_route_rejects_negative_backend_ref_after_selected_backend() {
        let err = translate_k8s_objects(
            &[object(
                "HTTPRoute",
                serde_json::json!({
                    "rules": [{
                        "backendRefs": [
                            {"name": "stable", "port": 8080, "weight": 100},
                            {"name": "invalid", "port": 9090, "weight": -1}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("negative backendRef weights are invalid even after a target is selected");

        assert!(err.to_string().contains("weight must be zero or positive"));
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
