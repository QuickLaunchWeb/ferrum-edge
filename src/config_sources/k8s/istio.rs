use std::collections::HashMap;

use serde_json::Value;

use crate::config::mesh::{
    AppProtocol, ConditionMatch, MeshEndpoint, MeshPolicy, MeshRule, MtlsMode, PeerAuthentication,
    PolicyAction, PolicyScope, PrincipalMatch, RequestMatch, Resolution, ServiceEntry,
    ServiceEntryLocation, ServicePort, Workload, WorkloadPort, WorkloadSelector,
};
use crate::identity::spiffe::SpiffeId;

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, RouteProxySpec, SourceKind,
    exact_path_listen_path, invalid_resource, optional_port_field, port_from_u64, proxy_for_route,
    resource_id, selector_from_istio, string_array, string_field, string_map,
};
use crate::config::types::BackendScheme;

const ALLOW_NOTHING_SPIFFE_PATTERN: &str = "__ferrum_allow_nothing_never_matches__";

pub(super) fn translate(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<bool, K8sTranslateError> {
    match object.kind.as_str() {
        "AuthorizationPolicy" => {
            acc.mesh.mesh_policies.push(authorization_policy(object)?);
            Ok(true)
        }
        "PeerAuthentication" => {
            acc.mesh
                .peer_authentications
                .push(peer_authentication(object)?);
            Ok(true)
        }
        "ServiceEntry" => {
            acc.mesh.service_entries.push(service_entry(object)?);
            Ok(true)
        }
        "WorkloadEntry" => {
            acc.mesh.workloads.push(workload_entry(acc, object)?);
            Ok(true)
        }
        "VirtualService" => {
            for proxy in virtual_service_routes(object)? {
                acc.upsert_proxy(proxy, SourceKind::Istio);
            }
            Ok(true)
        }
        "DestinationRule" => {
            acc.warnings.push(format!(
                "DestinationRule {}/{} accepted; traffic-policy details will map onto Ferrum upstream policy in a follow-up Phase D slice",
                object.metadata.namespace, object.metadata.name
            ));
            Ok(true)
        }
        "RequestAuthentication" => {
            acc.warnings.push(format!(
                "RequestAuthentication {}/{} accepted; JWT request identity is kept at the config-source boundary until the canonical request-auth model lands",
                object.metadata.namespace, object.metadata.name
            ));
            Ok(true)
        }
        "Sidecar" => {
            acc.warnings.push(format!(
                "Sidecar {}/{} accepted; egress listener scoping is tracked for the Phase D reconciler and has no direct proxy output yet",
                object.metadata.namespace, object.metadata.name
            ));
            Ok(true)
        }
        "Telemetry" => {
            acc.warnings.push(format!(
                "Telemetry {}/{} accepted; observability materialization is additive and remains behind Phase E runtime metrics",
                object.metadata.namespace, object.metadata.name
            ));
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn authorization_policy(object: &K8sObject) -> Result<MeshPolicy, K8sTranslateError> {
    let action = match string_field(&object.spec, "action").unwrap_or("ALLOW") {
        "ALLOW" => PolicyAction::Allow,
        "DENY" => PolicyAction::Deny,
        "AUDIT" => PolicyAction::Audit,
        other => {
            return Err(invalid_resource(
                object,
                format!("AuthorizationPolicy action '{other}' is unsupported"),
            ));
        }
    };

    let scope = match object.spec.get("selector") {
        Some(selector) => PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: selector_from_istio(Some(selector)),
                namespace: Some(object.metadata.namespace.clone()),
            },
        },
        None => PolicyScope::Namespace {
            namespace: object.metadata.namespace.clone(),
        },
    };

    let mut rules: Vec<MeshRule> = object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|rule| mesh_rule(object, rule, action))
        .collect::<Result<Vec<_>, _>>()?;
    if rules.is_empty() && action == PolicyAction::Allow {
        rules.push(allow_nothing_rule());
    }

    Ok(MeshPolicy {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        scope,
        rules,
    })
}

fn allow_nothing_rule() -> MeshRule {
    MeshRule {
        from: vec![PrincipalMatch {
            spiffe_id_pattern: Some(ALLOW_NOTHING_SPIFFE_PATTERN.to_string()),
            namespace_pattern: None,
            trust_domain: None,
        }],
        to: Vec::new(),
        when: Vec::new(),
        action: PolicyAction::Allow,
    }
}

fn mesh_rule(
    object: &K8sObject,
    rule: &Value,
    action: PolicyAction,
) -> Result<MeshRule, K8sTranslateError> {
    let from = rule
        .get("from")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|from| principal_matches(from.get("source").unwrap_or(&Value::Null)))
        .collect();
    let to = rule
        .get("to")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|to| request_match(object, to.get("operation").unwrap_or(&Value::Null)))
        .collect::<Result<Vec<_>, _>>()?;
    let when = rule
        .get("when")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(condition_match)
        .collect();

    Ok(MeshRule {
        from,
        to,
        when,
        action,
    })
}

fn principal_matches(source: &Value) -> Vec<PrincipalMatch> {
    let mut matches = Vec::new();
    for principal in string_array(source, "principals") {
        matches.push(PrincipalMatch {
            spiffe_id_pattern: Some(principal),
            namespace_pattern: None,
            trust_domain: None,
        });
    }
    for namespace in string_array(source, "namespaces") {
        matches.push(PrincipalMatch {
            spiffe_id_pattern: None,
            namespace_pattern: Some(namespace),
            trust_domain: None,
        });
    }
    matches
}

fn request_match(object: &K8sObject, operation: &Value) -> Result<RequestMatch, K8sTranslateError> {
    let ports = string_array(operation, "ports")
        .into_iter()
        .map(|port| port_from_string(object, &port, "rules[].to[].operation.ports"))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RequestMatch {
        methods: string_array(operation, "methods"),
        paths: string_array(operation, "paths"),
        hosts: string_array(operation, "hosts"),
        headers: HashMap::new(),
        ports,
    })
}

fn condition_match(value: &Value) -> Option<ConditionMatch> {
    Some(ConditionMatch {
        key: string_field(value, "key")?.to_string(),
        values: string_array(value, "values"),
        not_values: string_array(value, "notValues"),
    })
}

fn peer_authentication(object: &K8sObject) -> Result<PeerAuthentication, K8sTranslateError> {
    let mtls = object.spec.get("mtls").unwrap_or(&Value::Null);
    let effective_mtls_mode = mtls_mode(string_field(mtls, "mode").unwrap_or("PERMISSIVE"));
    let mut port_overrides = HashMap::new();
    for (port, value) in object
        .spec
        .get("portLevelMtls")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|ports| ports.iter())
    {
        let port = port_from_string(object, port, "portLevelMtls")?;
        let mode = mtls_mode(string_field(value, "mode").unwrap_or("PERMISSIVE"));
        port_overrides.insert(port, mode);
    }

    Ok(PeerAuthentication {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        selector: object
            .spec
            .get("selector")
            .map(|selector| WorkloadSelector {
                labels: selector_from_istio(Some(selector)),
                namespace: Some(object.metadata.namespace.clone()),
            }),
        mtls_mode: effective_mtls_mode,
        port_overrides,
    })
}

fn port_from_string(object: &K8sObject, raw: &str, field: &str) -> Result<u16, K8sTranslateError> {
    let parsed = raw.parse::<u64>().map_err(|_| {
        invalid_resource(
            object,
            format!("{field} must be a numeric port between 1 and 65535 (got {raw})"),
        )
    })?;
    port_from_u64(object, parsed, field)
}

fn mtls_mode(value: &str) -> MtlsMode {
    match value {
        "STRICT" => MtlsMode::Strict,
        "DISABLE" => MtlsMode::Disable,
        _ => MtlsMode::Permissive,
    }
}

fn service_entry(object: &K8sObject) -> Result<ServiceEntry, K8sTranslateError> {
    let hosts = string_array(&object.spec, "hosts");
    if hosts.is_empty() {
        return Err(invalid_resource(object, "ServiceEntry requires spec.hosts"));
    }

    let mut endpoints = Vec::new();
    for endpoint in object
        .spec
        .get("endpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(address) = string_field(endpoint, "address") else {
            continue;
        };
        let mut ports = HashMap::new();
        for (name, port) in endpoint
            .get("ports")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|ports| ports.iter())
        {
            if let Some(raw_port) = port.as_u64() {
                ports.insert(
                    name.clone(),
                    port_from_u64(object, raw_port, "endpoints[].ports")?,
                );
            }
        }
        endpoints.push(MeshEndpoint {
            address: address.to_string(),
            ports,
            labels: endpoint.get("labels").map(string_map).unwrap_or_default(),
            network: string_field(endpoint, "network").map(ToOwned::to_owned),
        });
    }

    Ok(ServiceEntry {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        hosts,
        endpoints,
        resolution: match string_field(&object.spec, "resolution").unwrap_or("NONE") {
            "DNS" => Resolution::Dns,
            "STATIC" => Resolution::Static,
            _ => Resolution::None,
        },
        location: match string_field(&object.spec, "location").unwrap_or("MESH_EXTERNAL") {
            "MESH_INTERNAL" => ServiceEntryLocation::MeshInternal,
            _ => ServiceEntryLocation::MeshExternal,
        },
        ports: service_ports(object)?,
    })
}

fn workload_entry(acc: &K8sAccumulator, object: &K8sObject) -> Result<Workload, K8sTranslateError> {
    let service_account = string_field(&object.spec, "serviceAccount").unwrap_or("default");
    let path = format!("ns/{}/sa/{service_account}", object.metadata.namespace);
    let spiffe_id = SpiffeId::from_parts(&acc.options.trust_domain, &path)
        .map_err(|e| invalid_resource(object, format!("invalid workload SPIFFE ID: {e}")))?;

    Ok(Workload {
        spiffe_id: spiffe_id.clone(),
        selector: WorkloadSelector {
            labels: object
                .spec
                .get("labels")
                .map(string_map)
                .unwrap_or_default(),
            namespace: Some(object.metadata.namespace.clone()),
        },
        service_name: object
            .spec
            .get("service")
            .and_then(Value::as_str)
            .unwrap_or(&object.metadata.name)
            .to_string(),
        addresses: string_field(&object.spec, "address")
            .map(|address| vec![address.to_string()])
            .unwrap_or_default(),
        ports: workload_ports(object)?,
        trust_domain: acc.options.trust_domain.clone(),
        namespace: object.metadata.namespace.clone(),
        network: string_field(&object.spec, "network").map(ToOwned::to_owned),
        cluster: string_field(&object.spec, "cluster").map(ToOwned::to_owned),
    })
}

fn virtual_service_routes(
    object: &K8sObject,
) -> Result<Vec<crate::config::types::Proxy>, K8sTranslateError> {
    let hosts = string_array(&object.spec, "hosts");
    let mut proxies = Vec::new();

    for (index, http) in object
        .spec
        .get("http")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(route) = http
            .get("route")
            .and_then(Value::as_array)
            .and_then(|routes| routes.first())
        else {
            continue;
        };
        let Some(destination) = route.get("destination") else {
            continue;
        };
        let Some(host) = string_field(destination, "host") else {
            return Err(invalid_resource(
                object,
                "VirtualService route.destination.host is required",
            ));
        };
        let port = optional_port_field(
            object,
            destination.get("port").and_then(|p| p.get("number")),
            "route.destination.port.number",
        )?
        .unwrap_or(80);

        let listen_path = http
            .get("match")
            .and_then(Value::as_array)
            .and_then(|matches| matches.first())
            .and_then(|m| m.get("uri"))
            .and_then(path_match);

        proxies.push(proxy_for_route(RouteProxySpec {
            id: resource_id(
                "istio-vs",
                &object.metadata.namespace,
                &object.metadata.name,
                &index.to_string(),
            ),
            namespace: object.metadata.namespace.clone(),
            hosts: hosts.clone(),
            listen_path: listen_path.or_else(|| Some("/".to_string())),
            strip_listen_path: false,
            backend_host: host.to_string(),
            backend_port: port,
            backend_scheme: BackendScheme::Http,
            listen_port: None,
        }));
    }

    Ok(proxies)
}

fn path_match(uri: &Value) -> Option<String> {
    if let Some(prefix) = string_field(uri, "prefix") {
        return Some(prefix.to_string());
    }
    if let Some(exact) = string_field(uri, "exact") {
        return Some(exact_path_listen_path(exact));
    }
    string_field(uri, "regex").map(|pattern| format!("~{pattern}"))
}

fn service_ports(object: &K8sObject) -> Result<Vec<ServicePort>, K8sTranslateError> {
    let mut ports = Vec::new();
    object
        .spec
        .get("ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .try_for_each(|port| {
            let Some(raw_port) = port.get("number").and_then(Value::as_u64) else {
                return Ok(());
            };
            ports.push(ServicePort {
                port: port_from_u64(object, raw_port, "ports[].number")?,
                protocol: app_protocol(string_field(port, "protocol")),
                name: string_field(port, "name").map(ToOwned::to_owned),
            });
            Ok::<(), K8sTranslateError>(())
        })?;
    Ok(ports)
}

fn workload_ports(object: &K8sObject) -> Result<Vec<WorkloadPort>, K8sTranslateError> {
    let mut workload_ports = Vec::new();
    object
        .spec
        .get("ports")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|ports| ports.iter())
        .try_for_each(|(name, port)| {
            let Some(raw_port) = port.as_u64() else {
                return Ok(());
            };
            workload_ports.push(WorkloadPort {
                port: port_from_u64(object, raw_port, "ports")?,
                protocol: AppProtocol::Unknown,
                name: Some(name.clone()),
            });
            Ok::<(), K8sTranslateError>(())
        })?;
    Ok(workload_ports)
}

fn app_protocol(value: Option<&str>) -> AppProtocol {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "http" => AppProtocol::Http,
        "http2" => AppProtocol::Http2,
        "grpc" => AppProtocol::Grpc,
        "tcp" => AppProtocol::Tcp,
        "tls" => AppProtocol::Tls,
        "mongo" => AppProtocol::Mongo,
        "redis" => AppProtocol::Redis,
        "mysql" => AppProtocol::Mysql,
        "postgres" => AppProtocol::Postgres,
        _ => AppProtocol::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sources::k8s::{K8sMetadata, K8sTranslationOptions, translate_k8s_objects};
    use crate::identity::spiffe::TrustDomain;
    use crate::modes::mesh::policy::{
        MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization,
    };
    use crate::xds::slice::MeshSlice;

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    fn object(kind: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: "security.istio.io/v1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: "sample".to_string(),
                namespace: "default".to_string(),
                labels: HashMap::new(),
            },
            spec,
        }
    }

    fn translated_authorization_policy(spec: Value) -> MeshPolicy {
        let result = translate_k8s_objects(&[object("AuthorizationPolicy", spec)], options())
            .expect("translation succeeds");
        let mesh = result.config.mesh.expect("mesh config");
        mesh.mesh_policies
            .into_iter()
            .next()
            .expect("one translated mesh policy")
    }

    #[test]
    fn translates_authorization_policy() {
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "DENY",
                    "selector": {"matchLabels": {"app": "api"}},
                    "rules": [{
                        "from": [{"source": {"principals": ["spiffe://cluster.local/ns/default/sa/web"]}}],
                        "to": [{"operation": {"methods": ["POST"], "paths": ["/admin/*"], "ports": ["8080"]}}],
                        "when": [{"key": "request.auth.claims[iss]", "values": ["issuer-a"]}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.mesh_policies.len(), 1);
        assert_eq!(mesh.mesh_policies[0].rules[0].action, PolicyAction::Deny);
        assert_eq!(mesh.mesh_policies[0].rules[0].to[0].ports, vec![8080]);
    }

    #[test]
    fn translates_allow_authorization_policy_without_rules_to_allow_nothing() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "selector": {"matchLabels": {"app": "api"}}
        }));

        assert!(matches!(
            &policy.scope,
            PolicyScope::WorkloadSelector { .. }
        ));
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].action, PolicyAction::Allow);
        assert_eq!(
            policy.rules[0].from[0].spiffe_id_pattern.as_deref(),
            Some(ALLOW_NOTHING_SPIFFE_PATTERN)
        );

        let decision = evaluate_mesh_authorization(
            &MeshSlice {
                mesh_policies: vec![policy],
                ..MeshSlice::default()
            },
            &MeshAuthzRequest::default(),
        );
        assert_eq!(
            decision,
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn translates_namespace_allow_authorization_policy_without_rules_to_allow_nothing() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW"
        }));

        assert!(matches!(
            &policy.scope,
            PolicyScope::Namespace { namespace } if namespace == "default"
        ));
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].action, PolicyAction::Allow);
        assert_eq!(
            policy.rules[0].from[0].spiffe_id_pattern.as_deref(),
            Some(ALLOW_NOTHING_SPIFFE_PATTERN)
        );
    }

    #[test]
    fn translates_missing_action_authorization_policy_without_rules_to_allow_nothing() {
        let policy = translated_authorization_policy(serde_json::json!({}));

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].action, PolicyAction::Allow);
        assert_eq!(
            policy.rules[0].from[0].spiffe_id_pattern.as_deref(),
            Some(ALLOW_NOTHING_SPIFFE_PATTERN)
        );
    }

    #[test]
    fn translates_deny_authorization_policy_without_rules_to_noop() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "DENY"
        }));

        assert_eq!(policy.rules, Vec::new());
    }

    #[test]
    fn translates_audit_authorization_policy_without_rules_to_noop() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "AUDIT"
        }));

        assert_eq!(policy.rules, Vec::new());
    }

    #[test]
    fn translates_service_entry() {
        let result = translate_k8s_objects(
            &[object(
                "ServiceEntry",
                serde_json::json!({
                    "hosts": ["api.EXAMPLE.com"],
                    "resolution": "DNS",
                    "ports": [{"number": 443, "name": "https", "protocol": "TLS"}]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.service_entries[0].hosts, vec!["api.example.com"]);
        assert_eq!(mesh.service_entries[0].ports[0].protocol, AppProtocol::Tls);
    }

    #[test]
    fn rejects_istio_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "ServiceEntry",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "ports": [{"number": 70000, "name": "http", "protocol": "HTTP"}]
                }),
            )],
            options(),
        )
        .expect_err("invalid port must fail closed");

        assert!(err.to_string().contains("ports[].number"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_authorization_policy_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["70000"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid AuthorizationPolicy port must fail closed");

        assert!(err.to_string().contains("rules[].to[].operation.ports"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_peer_authentication_port_level_mtls_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "PeerAuthentication",
                serde_json::json!({
                    "mtls": {"mode": "PERMISSIVE"},
                    "portLevelMtls": {
                        "70000": {"mode": "STRICT"}
                    }
                }),
            )],
            options(),
        )
        .expect_err("invalid PeerAuthentication port must fail closed");

        assert!(err.to_string().contains("portLevelMtls"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_virtual_service_destination_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 70000}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid VirtualService destination port must fail closed");

        assert!(err.to_string().contains("route.destination.port.number"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn translates_workload_entry_vm_metadata() {
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "VM-API.Example",
                    "serviceAccount": "api",
                    "service": "api",
                    "network": "network-a",
                    "cluster": "cluster-a",
                    "labels": {"app": "api"},
                    "ports": {"http": 8080}
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let workload = &mesh.workloads[0];
        assert_eq!(workload.addresses, vec!["vm-api.example"]);
        assert_eq!(workload.network.as_deref(), Some("network-a"));
        assert_eq!(workload.cluster.as_deref(), Some("cluster-a"));
        assert_eq!(
            workload.spiffe_id.as_str(),
            "spiffe://cluster.local/ns/default/sa/api"
        );
    }

    #[test]
    fn translates_virtual_service_to_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/v1"));
        assert!(!result.config.proxies[0].strip_listen_path);
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn translates_virtual_service_exact_uri_to_exact_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"exact": "/v1.items"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(
            result.config.proxies[0].listen_path.as_deref(),
            Some("=/v1.items")
        );
        assert!(!result.config.proxies[0].strip_listen_path);
    }

    #[test]
    fn translates_virtual_service_regex_uri_to_regex_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"regex": "/v[0-9]+/items"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
}
