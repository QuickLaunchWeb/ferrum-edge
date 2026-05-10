use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::identity::spiffe::SpiffeId;
use crate::modes::mesh::config::{
    AccessLogFilter, AppProtocol, ConditionMatch, JwtHeader, MeshAccessLoggingConfig, MeshEndpoint,
    MeshJwtRule, MeshMetricsConfig, MeshPolicy, MeshRequestAuthentication, MeshRule,
    MeshTelemetryConfig, MeshTelemetryResource, MeshTracingConfig, MetricTagOverride, MtlsMode,
    PeerAuthentication, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch, Resolution,
    ServiceEntry, ServiceEntryLocation, ServicePort, TagOverrideOperation, Workload, WorkloadPort,
    WorkloadSelector,
};

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, K8sTranslationOptions, RouteBackend,
    RouteProxySpec, SourceKind, exact_path_listen_path, invalid_resource, optional_port_field,
    port_from_u64, proxy_for_route, resource_id, selector_from_istio, string_array, string_field,
    string_map, upstream_for_route,
};
use crate::config::types::{BackendScheme, MAX_TARGET_WEIGHT};

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
            let (proxies, upstreams) = virtual_service_routes(object, acc)?;
            for upstream in upstreams {
                acc.upsert_upstream(upstream);
            }
            for proxy in proxies {
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
            acc.mesh
                .request_authentications
                .push(request_authentication(acc, object)?);
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
            acc.mesh.telemetry_resources.push(telemetry(acc, object)?);
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
        tracing::warn!(
            namespace = %object.metadata.namespace,
            policy = %object.metadata.name,
            "Istio ALLOW AuthorizationPolicy has no rules; emitting synthetic never-match allow rule to preserve allow-nothing semantics",
        );
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
        from: Vec::new(),
        to: Vec::new(),
        when: Vec::new(),
        never_matches: true,
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
    let mut to = Vec::new();
    let mut has_unconstrained_to = false;
    for request in rule
        .get("to")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|to| request_match(object, to.get("operation").unwrap_or(&Value::Null)))
    {
        let request = request?;
        if request_match_is_unconstrained(&request) {
            has_unconstrained_to = true;
        } else {
            to.push(request);
        }
    }
    if has_unconstrained_to {
        to.clear();
    }
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
        never_matches: false,
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
    validate_supported_operation_fields(object, operation)?;
    let (ports, port_patterns) = operation_ports(object, operation)?;

    Ok(RequestMatch {
        methods: string_array(operation, "methods"),
        paths: string_array(operation, "paths"),
        hosts: string_array(operation, "hosts"),
        headers: HashMap::new(),
        ports,
        port_patterns,
    })
}

fn validate_supported_operation_fields(
    object: &K8sObject,
    operation: &Value,
) -> Result<(), K8sTranslateError> {
    for key in operation
        .as_object()
        .into_iter()
        .flat_map(|fields| fields.keys())
    {
        match key.as_str() {
            "methods" | "paths" | "hosts" | "ports" => {}
            _ => {
                return Err(invalid_resource(
                    object,
                    format!("rules[].to[].operation.{key} is unsupported"),
                ));
            }
        }
    }
    Ok(())
}

fn operation_ports(
    object: &K8sObject,
    operation: &Value,
) -> Result<(Vec<u16>, Vec<String>), K8sTranslateError> {
    let mut ports = Vec::new();
    let mut port_patterns = Vec::new();
    for port in string_array(operation, "ports") {
        if is_istio_port_pattern(&port) {
            port_patterns.push(port);
            continue;
        }
        ports.push(port_from_string(
            object,
            &port,
            "rules[].to[].operation.ports",
        )?);
    }
    Ok((ports, port_patterns))
}

fn is_istio_port_pattern(port: &str) -> bool {
    if port == "*" {
        return true;
    }
    if let Some(prefix) = port.strip_suffix('*') {
        return !prefix.is_empty() && prefix.bytes().all(|byte| byte.is_ascii_digit());
    }
    if let Some(suffix) = port.strip_prefix('*') {
        return !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit());
    }
    false
}

fn request_match_is_unconstrained(request: &RequestMatch) -> bool {
    request.methods.is_empty()
        && request.paths.is_empty()
        && request.hosts.is_empty()
        && request.headers.is_empty()
        && request.ports.is_empty()
        && request.port_patterns.is_empty()
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

fn request_authentication(
    acc: &K8sAccumulator,
    object: &K8sObject,
) -> Result<MeshRequestAuthentication, K8sTranslateError> {
    let scope = istio_policy_scope(&acc.options, object, object.spec.get("selector"));

    let jwt_rules: Vec<MeshJwtRule> = object
        .spec
        .get("jwtRules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|rule| translate_jwt_rule(object, rule))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(MeshRequestAuthentication {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        scope,
        jwt_rules,
    })
}

fn translate_jwt_rule(object: &K8sObject, rule: &Value) -> Result<MeshJwtRule, K8sTranslateError> {
    let issuer = string_field(rule, "issuer")
        .ok_or_else(|| {
            invalid_resource(
                object,
                "RequestAuthentication jwtRules[].issuer is required",
            )
        })?
        .to_string();

    let audiences = optional_string_array(
        object,
        rule,
        "audiences",
        "RequestAuthentication jwtRules[].audiences",
    )?;
    let jwks_uri = string_field(rule, "jwksUri").map(ToOwned::to_owned);
    let jwks = string_field(rule, "jwks").map(ToOwned::to_owned);

    let from_headers: Vec<JwtHeader> = rule
        .get("fromHeaders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|header| {
            let name = string_field(header, "name")?.to_string();
            let prefix = string_field(header, "prefix").map(ToOwned::to_owned);
            Some(JwtHeader { name, prefix })
        })
        .collect();

    let from_params = optional_string_array(
        object,
        rule,
        "fromParams",
        "RequestAuthentication jwtRules[].fromParams",
    )?;
    let forward_original_token = rule
        .get("forwardOriginalToken")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(MeshJwtRule {
        issuer,
        audiences,
        jwks_uri,
        jwks,
        from_headers,
        from_params,
        forward_original_token,
    })
}

fn istio_policy_scope(
    options: &K8sTranslationOptions,
    object: &K8sObject,
    selector: Option<&Value>,
) -> PolicyScope {
    let is_root_namespace = object.metadata.namespace == options.istio_root_namespace;
    match selector {
        Some(selector) => PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: selector_from_istio(Some(selector)),
                namespace: (!is_root_namespace).then(|| object.metadata.namespace.clone()),
            },
        },
        None if is_root_namespace => PolicyScope::MeshWide,
        None => PolicyScope::Namespace {
            namespace: object.metadata.namespace.clone(),
        },
    }
}

fn optional_string_array(
    object: &K8sObject,
    value: &Value,
    key: &str,
    display_path: &str,
) -> Result<Vec<String>, K8sTranslateError> {
    let Some(raw) = value.get(key) else {
        return Ok(Vec::new());
    };
    let Some(items) = raw.as_array() else {
        return Err(invalid_resource(
            object,
            format!("{display_path} must be an array of strings"),
        ));
    };
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                invalid_resource(object, format!("{display_path}[{index}] must be a string"))
            })
        })
        .collect()
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
    acc: &mut K8sAccumulator,
) -> Result<
    (
        Vec<crate::config::types::Proxy>,
        Vec<crate::config::types::Upstream>,
    ),
    K8sTranslateError,
> {
    let hosts = string_array(&object.spec, "hosts");
    let mut proxies = Vec::new();
    let mut upstreams = Vec::new();

    for (index, http) in object
        .spec
        .get("http")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let match_paths = match_paths(http);
        if match_paths.is_empty() {
            continue;
        }

        let backends = route_backends(object, http, acc, index)?;
        if backends.is_empty() {
            continue;
        };

        let (backend_host, backend_port, upstream_id) = if backends.len() == 1 {
            let Some(backend) = backends.into_iter().next() else {
                continue;
            };
            (backend.host, backend.port, None)
        } else {
            let upstream_id = resource_id(
                "istio-vs-upstream",
                &object.metadata.namespace,
                &object.metadata.name,
                &index.to_string(),
            );
            upstreams.push(upstream_for_route(
                upstream_id.clone(),
                object.metadata.namespace.clone(),
                backends,
            ));
            (String::new(), 0, Some(upstream_id))
        };

        let match_count = match_paths.len();
        for (match_index, listen_path) in match_paths.into_iter().enumerate() {
            let suffix = if match_count == 1 {
                index.to_string()
            } else {
                format!("{index}-{match_index}")
            };
            proxies.push(proxy_for_route(RouteProxySpec {
                id: resource_id(
                    "istio-vs",
                    &object.metadata.namespace,
                    &object.metadata.name,
                    &suffix,
                ),
                namespace: object.metadata.namespace.clone(),
                hosts: hosts.clone(),
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

    Ok((proxies, upstreams))
}

fn match_paths(http: &Value) -> Vec<Option<String>> {
    let Some(matches) = http.get("match").and_then(Value::as_array) else {
        return vec![Some("/".to_string())];
    };
    if matches.is_empty() {
        return vec![Some("/".to_string())];
    }

    let mut seen_paths = HashSet::new();
    matches
        .iter()
        // Istio forbids empty HTTPMatchRequest blocks; URI-less entries depend on
        // unsupported predicates such as headers/method/queryParams, so do not
        // broaden them into Ferrum catch-all routes.
        .filter_map(|m| m.get("uri").and_then(path_match).map(Some))
        .filter(|listen_path| seen_paths.insert(listen_path.clone()))
        .collect()
}

fn route_backends(
    object: &K8sObject,
    http: &Value,
    acc: &mut K8sAccumulator,
    route_index: usize,
) -> Result<Vec<RouteBackend>, K8sTranslateError> {
    let mut backends = Vec::new();
    let routes: Vec<_> = http
        .get("route")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let preserve_single_destination = routes.len() == 1;
    let mut skipped_zero = 0usize;
    let mut active_route_without_backend = false;
    for route in routes {
        let weight = route_weight(object, route)?;
        if weight == 0 && !preserve_single_destination {
            skipped_zero += 1;
            continue;
        }
        let Some(destination) = route.get("destination") else {
            active_route_without_backend = true;
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
        backends.push(RouteBackend {
            host: host.to_string(),
            port,
            weight,
        });
    }
    if skipped_zero > 0 {
        if backends.is_empty() && !active_route_without_backend {
            acc.warnings.push(format!(
                "VirtualService '{}' HTTP route {} has only zero-weight split destinations; no proxy was materialized",
                object.metadata.name, route_index
            ));
        } else {
            acc.warnings.push(format!(
                "VirtualService '{}' HTTP route {} skipped {} zero-weight split destination(s)",
                object.metadata.name, route_index, skipped_zero
            ));
        }
    }
    Ok(backends)
}

fn route_weight(object: &K8sObject, route: &Value) -> Result<u32, K8sTranslateError> {
    let Some(weight_value) = route.get("weight") else {
        return Ok(0);
    };
    let Some(weight) = weight_value.as_u64() else {
        return Err(invalid_resource(
            object,
            format!(
                "VirtualService route.weight must be between 0 and {MAX_TARGET_WEIGHT} (got {weight_value})"
            ),
        ));
    };
    if weight > u64::from(MAX_TARGET_WEIGHT) {
        return Err(invalid_resource(
            object,
            format!(
                "VirtualService route.weight must be between 0 and {MAX_TARGET_WEIGHT} (got {weight})"
            ),
        ));
    }
    Ok(weight as u32)
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

fn telemetry(
    acc: &K8sAccumulator,
    object: &K8sObject,
) -> Result<MeshTelemetryResource, K8sTranslateError> {
    let scope = istio_policy_scope(&acc.options, object, object.spec.get("selector"));

    let tracing = object
        .spec
        .get("tracing")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .map(|t| {
            let sampling = t.get("randomSamplingPercentage").and_then(Value::as_f64);
            let mut custom_header_tags = HashMap::new();
            let custom_tags = t
                .get("customTags")
                .and_then(Value::as_object)
                .map(|tags| {
                    tags.iter()
                        .filter_map(|(key, val)| {
                            // Istio customTags: { tagName: { literal: { value: "v" } } }
                            if let Some(header_name) = val
                                .get("header")
                                .and_then(|h| h.get("name"))
                                .and_then(Value::as_str)
                            {
                                custom_header_tags.insert(key.clone(), header_name.to_string());
                                return None;
                            }

                            let value = val
                                .get("literal")
                                .and_then(|l| l.get("value"))
                                .and_then(Value::as_str)
                                .or_else(|| {
                                    val.get("environment")
                                        .and_then(|e| e.get("name"))
                                        .and_then(Value::as_str)
                                });
                            value.map(|v| (key.clone(), v.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            MeshTracingConfig {
                sampling_percentage: sampling,
                custom_tags,
                custom_header_tags,
            }
        });

    let metrics = object
        .spec
        .get("metrics")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .map(|m| {
            let mut tag_overrides = Vec::new();
            let mut disabled_metrics = Vec::new();
            if let Some(overrides) = m.get("overrides").and_then(Value::as_array) {
                for ovr in overrides {
                    if ovr.get("disabled").and_then(Value::as_bool).unwrap_or(false) {
                        let metric_name = ovr
                            .get("match")
                            .and_then(|m| m.get("metric"))
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                invalid_resource(
                                    object,
                                    "Telemetry metrics.overrides[].match.metric is required when disabled=true",
                                )
                            })?;
                        disabled_metrics.push(metric_name.to_string());
                    }
                    if let Some(tags) = ovr.get("tagOverrides").and_then(Value::as_object) {
                        for (tag_name, tag_spec) in tags {
                            let op = tag_spec
                                .get("operation")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            let operation = match op {
                                "REMOVE" => TagOverrideOperation::Remove,
                                "UPSERT" => {
                                    let value = tag_spec
                                        .get("value")
                                        .and_then(Value::as_str)
                                        .unwrap_or("")
                                        .to_string();
                                    TagOverrideOperation::Set { value }
                                }
                                _ => continue,
                            };
                            tag_overrides.push(MetricTagOverride {
                                name: tag_name.clone(),
                                operation,
                            });
                        }
                    }
                }
            }
            Ok::<_, K8sTranslateError>(MeshMetricsConfig {
                tag_overrides,
                disabled_metrics,
            })
        })
        .transpose()?;

    let access_logging = object
        .spec
        .get("accessLogging")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .map(|al| {
            let disabled = al.get("disabled").and_then(Value::as_bool).unwrap_or(false);
            let filter = al
                .get("filter")
                .and_then(|f| f.get("expression"))
                .and_then(Value::as_str)
                .map(parse_access_log_filter_expression)
                .transpose()
                .map_err(|message| invalid_resource(object, message))?
                .flatten();
            Ok::<_, K8sTranslateError>(MeshAccessLoggingConfig {
                enabled: !disabled,
                filter,
            })
        })
        .transpose()?;

    Ok(MeshTelemetryResource {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        scope,
        config: MeshTelemetryConfig {
            tracing,
            metrics,
            access_logging,
        },
    })
}

/// Parse simple filter expressions like `response.code >= 400` into an
/// [`AccessLogFilter`]. Returns `Ok(None)` for expressions without supported
/// access-log predicates and `Err` for malformed supported predicates.
fn parse_access_log_filter_expression(expr: &str) -> Result<Option<AccessLogFilter>, String> {
    if expr.contains("||") {
        return Err(
            "Telemetry access log filter expressions with '||' are not supported".to_string(),
        );
    }

    let mut filter = AccessLogFilter {
        status_code_min: None,
        status_code_max: None,
        min_latency_ms: None,
        errors_only: false,
    };
    let mut matched = false;

    // Split on && to handle compound expressions
    for part in expr.split("&&") {
        let part = part.trim();
        if part.starts_with("response.code") || part.starts_with("response.status") {
            let Some(val) = extract_numeric_comparison(part) else {
                return Err(
                    "Telemetry access log response.code filter must use a numeric comparison"
                        .to_string(),
                );
            };
            match val {
                Comparison::Gte(n) => filter.status_code_min = Some(status_code_value(n)?),
                Comparison::Gt(n) => {
                    filter.status_code_min = Some(status_code_value(comparison_increment(n)?)?)
                }
                Comparison::Lte(n) => filter.status_code_max = Some(status_code_value(n)?),
                Comparison::Lt(n) => {
                    filter.status_code_max = Some(status_code_value(comparison_decrement(n)?)?)
                }
                Comparison::Eq(n) => {
                    let code = status_code_value(n)?;
                    filter.status_code_min = Some(code);
                    filter.status_code_max = Some(code);
                }
            }
            matched = true;
        } else if part.starts_with("response.duration") {
            let Some(val) = extract_numeric_comparison(part) else {
                return Err(
                    "Telemetry access log response.duration filter must use a numeric comparison"
                        .to_string(),
                );
            };
            match val {
                Comparison::Gte(n) => {
                    filter.min_latency_ms = Some(duration_value(n)?);
                }
                Comparison::Gt(n) => {
                    filter.min_latency_ms = Some(duration_value(comparison_increment(n)?)?);
                }
                Comparison::Lte(_) | Comparison::Lt(_) | Comparison::Eq(_) => {
                    return Err(
                        "Telemetry access log response.duration filters only support '>' and '>='"
                            .to_string(),
                    );
                }
            }
            matched = true;
        }
    }

    if matched { Ok(Some(filter)) } else { Ok(None) }
}

fn status_code_value(value: i64) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| {
        format!("Telemetry access log response code filter value {value} is outside 0..=65535")
    })
}

fn duration_value(value: i64) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| {
        format!("Telemetry access log duration filter value {value} must be non-negative")
    })
}

fn comparison_increment(value: i64) -> Result<i64, String> {
    value
        .checked_add(1)
        .ok_or_else(|| format!("Telemetry access log comparison value {value} overflows"))
}

fn comparison_decrement(value: i64) -> Result<i64, String> {
    value
        .checked_sub(1)
        .ok_or_else(|| format!("Telemetry access log comparison value {value} underflows"))
}

enum Comparison {
    Gte(i64),
    Gt(i64),
    Lte(i64),
    Lt(i64),
    Eq(i64),
}

fn extract_numeric_comparison(expr: &str) -> Option<Comparison> {
    let ops = [">=", "<=", ">", "<", "=="];
    for op in ops {
        if let Some(idx) = expr.find(op) {
            let val_str = expr[idx + op.len()..].trim();
            let val: i64 = val_str.parse().ok()?;
            return match op {
                ">=" => Some(Comparison::Gte(val)),
                ">" => Some(Comparison::Gt(val)),
                "<=" => Some(Comparison::Lte(val)),
                "<" => Some(Comparison::Lt(val)),
                "==" => Some(Comparison::Eq(val)),
                _ => None,
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sources::k8s::{K8sMetadata, K8sTranslationOptions, translate_k8s_objects};
    use crate::identity::spiffe::TrustDomain;
    use crate::modes::mesh::policy::{
        MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization,
    };
    use crate::modes::mesh::slice::MeshSlice;

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    fn options_for_namespace(namespace: &str) -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            namespace.to_string(),
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
        assert!(policy.rules[0].never_matches);
        assert!(policy.rules[0].from.is_empty());

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
        assert!(policy.rules[0].never_matches);
    }

    #[test]
    fn translates_missing_action_authorization_policy_without_rules_to_allow_nothing() {
        let policy = translated_authorization_policy(serde_json::json!({}));

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].action, PolicyAction::Allow);
        assert!(policy.rules[0].never_matches);
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
    fn preserves_authorization_policy_wildcard_ports() {
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["*"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("wildcard AuthorizationPolicy port must translate");

        let mesh = result.config.mesh.expect("mesh config");
        let request = &mesh.mesh_policies[0].rules[0].to[0];
        assert!(request.ports.is_empty());
        assert_eq!(request.port_patterns, vec!["*"]);
    }

    #[test]
    fn preserves_authorization_policy_prefix_port_patterns() {
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["8*"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("prefix AuthorizationPolicy port pattern must translate");

        let mesh = result.config.mesh.expect("mesh config");
        let request = &mesh.mesh_policies[0].rules[0].to[0];
        assert!(request.ports.is_empty());
        assert_eq!(request.port_patterns, vec!["8*"]);
    }

    #[test]
    fn preserves_authorization_policy_suffix_port_patterns() {
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["*43"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("suffix AuthorizationPolicy port pattern must translate");

        let mesh = result.config.mesh.expect("mesh config");
        let request = &mesh.mesh_policies[0].rules[0].to[0];
        assert!(request.ports.is_empty());
        assert_eq!(request.port_patterns, vec!["*43"]);
    }

    #[test]
    fn rejects_authorization_policy_mid_string_port_patterns() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["8*9"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("mid-string AuthorizationPolicy port pattern is unsupported");

        assert!(err.to_string().contains("rules[].to[].operation.ports"));
        assert!(err.to_string().contains("8*9"));
    }

    #[test]
    fn rejects_authorization_policy_non_numeric_non_pattern_ports() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"ports": ["http"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("named AuthorizationPolicy port is not representable");

        assert!(err.to_string().contains("rules[].to[].operation.ports"));
        assert!(err.to_string().contains("http"));
    }

    #[test]
    fn validates_later_authorization_policy_to_entries_after_unconstrained_match() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [
                            {"operation": {}},
                            {"operation": {"ports": ["70000"]}}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("later invalid AuthorizationPolicy port must still fail closed");

        assert!(err.to_string().contains("rules[].to[].operation.ports"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn rejects_unsupported_authorization_policy_operation_fields() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "DENY",
                    "rules": [{
                        "to": [{"operation": {"notPorts": ["8080"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("unsupported negative operation fields must fail closed");

        assert!(err.to_string().contains("rules[].to[].operation.notPorts"));
        assert!(err.to_string().contains("unsupported"));
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

    #[test]
    fn virtual_service_without_match_defaults_to_catch_all() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].listen_path.as_deref(), Some("/"));
    }

    #[test]
    fn virtual_service_without_route_does_not_emit_zero_weight_warning() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/old"}}],
                        "redirect": {"uri": "/new"}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
        assert!(
            !result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight"))
        );
    }

    #[test]
    fn virtual_service_preserves_weighted_destinations() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api-v1.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 80},
                            {"destination": {"host": "api-v2.default.svc.cluster.local", "port": {"number": 8081}}, "weight": 20}
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
        assert_eq!(result.config.upstreams[0].targets[0].weight, 80);
        assert_eq!(
            result.config.upstreams[0].targets[1].host,
            "api-v2.default.svc.cluster.local"
        );
    }

    #[test]
    fn virtual_service_skips_zero_weight_destination_in_multi_destination_split() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "dark.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 0},
                            {"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 9090}}, "weight": 100}
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
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("zero-weight split destination"))
        );
    }

    #[test]
    fn virtual_service_skips_all_omitted_weights_in_multi_destination_split() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api-v1.default.svc.cluster.local", "port": {"number": 8080}}},
                            {"destination": {"host": "api-v2.default.svc.cluster.local", "port": {"number": 8081}}}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight"))
        );
    }

    #[test]
    fn virtual_service_skips_omitted_weight_in_multi_destination_split() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api-v1.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 100},
                            {"destination": {"host": "api-v2.default.svc.cluster.local", "port": {"number": 8081}}}
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
            "api-v1.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 8080);
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("zero-weight split destination"))
        );
    }

    #[test]
    fn virtual_service_skips_all_zero_weight_destinations_in_multi_destination_split() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api-v1.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 0},
                            {"destination": {"host": "api-v2.default.svc.cluster.local", "port": {"number": 8081}}, "weight": 0}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies.is_empty());
        assert!(result.config.upstreams.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("only zero-weight"))
        );
    }

    #[test]
    fn virtual_service_keeps_single_zero_weight_destination() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [
                            {"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 0}
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
            "api.default.svc.cluster.local"
        );
        assert_eq!(result.config.proxies[0].backend_port, 8080);
        assert!(result.config.upstreams.is_empty());
    }

    #[test]
    fn virtual_service_creates_proxy_per_uri_match() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/v1"}},
                            {"uri": {"prefix": "/v2"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
    fn virtual_service_skips_explicit_pathless_matches() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"headers": {"x-tenant": {"exact": "a"}}},
                            {"method": {"exact": "GET"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
    fn virtual_service_ignores_pathless_match_in_mixed_rule() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/v1"}},
                            {"headers": {"x-tenant": {"exact": "a"}}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
    fn virtual_service_rejects_route_weight_above_ferrum_limit() {
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "route": [
                            {"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 65536}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("oversized route weight should fail translation");

        assert!(
            err.to_string()
                .contains("weight must be between 0 and 65535")
        );
    }

    #[test]
    fn virtual_service_rejects_malformed_route_weights() {
        for weight in [serde_json::json!(-1), serde_json::json!(1.5)] {
            let err = translate_k8s_objects(
                &[object(
                    "VirtualService",
                    serde_json::json!({
                        "hosts": ["api.example.com"],
                        "http": [{
                            "route": [
                                {"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}, "weight": weight}
                            ]
                        }]
                    }),
                )],
                options(),
            )
            .expect_err("malformed route weight should fail translation");

            assert!(
                err.to_string()
                    .contains("weight must be between 0 and 65535")
            );
        }
    }

    // ── RequestAuthentication ────────────────────────────────────────────

    #[test]
    fn translates_request_authentication_with_selector() {
        let result = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "selector": {"matchLabels": {"app": "httpbin"}},
                    "jwtRules": [{
                        "issuer": "https://accounts.google.com",
                        "jwksUri": "https://www.googleapis.com/oauth2/v3/certs",
                        "audiences": ["my-app"],
                        "fromHeaders": [
                            {"name": "Authorization", "prefix": "Bearer "},
                            {"name": "X-Custom-Token"}
                        ],
                        "fromParams": ["access_token"],
                        "forwardOriginalToken": true
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.request_authentications.len(), 1);
        let ra = &mesh.request_authentications[0];
        assert_eq!(ra.name, "sample");
        assert_eq!(ra.namespace, "default");
        assert!(
            matches!(&ra.scope, PolicyScope::WorkloadSelector { selector } if selector.namespace.as_deref() == Some("default") && selector.labels.get("app") == Some(&"httpbin".to_string()))
        );
        assert_eq!(ra.jwt_rules.len(), 1);
        let rule = &ra.jwt_rules[0];
        assert_eq!(rule.issuer, "https://accounts.google.com");
        assert_eq!(
            rule.jwks_uri.as_deref(),
            Some("https://www.googleapis.com/oauth2/v3/certs")
        );
        assert_eq!(rule.audiences, vec!["my-app"]);
        assert_eq!(rule.from_headers.len(), 2);
        assert_eq!(rule.from_headers[0].name, "Authorization");
        assert_eq!(rule.from_headers[0].prefix.as_deref(), Some("Bearer "));
        assert_eq!(rule.from_headers[1].name, "X-Custom-Token");
        assert!(rule.from_headers[1].prefix.is_none());
        assert_eq!(rule.from_params, vec!["access_token"]);
        assert!(rule.forward_original_token);
    }

    #[test]
    fn root_namespace_request_authentication_selector_is_mesh_wide_by_labels() {
        let mut ra = object(
            "RequestAuthentication",
            serde_json::json!({
                "selector": {"matchLabels": {"app": "httpbin"}},
                "jwtRules": [{
                    "issuer": "https://accounts.google.com",
                    "jwksUri": "https://www.googleapis.com/oauth2/v3/certs"
                }]
            }),
        );
        ra.metadata.namespace = "istio-config".to_string();

        let result = translate_k8s_objects(
            &[ra],
            options_for_namespace("istio-config")
                .with_istio_root_namespace("istio-config".to_string()),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let scope = &mesh.request_authentications[0].scope;
        assert!(
            matches!(scope, PolicyScope::WorkloadSelector { selector } if selector.namespace.is_none() && selector.labels.get("app") == Some(&"httpbin".to_string()))
        );
    }

    #[test]
    fn translates_request_authentication_without_selector_to_namespace_scope() {
        let result = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "issuer": "https://auth.example.com",
                        "jwksUri": "https://auth.example.com/.well-known/jwks.json"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let ra = &mesh.request_authentications[0];
        assert!(matches!(
            &ra.scope,
            PolicyScope::Namespace { namespace } if namespace == "default"
        ));
    }

    #[test]
    fn root_namespace_telemetry_selector_is_mesh_wide_by_labels() {
        let mut telemetry = object(
            "Telemetry",
            serde_json::json!({
                "selector": {"matchLabels": {"app": "gateway"}},
                "tracing": [{"randomSamplingPercentage": 10.0}]
            }),
        );
        telemetry.metadata.namespace = "istio-config".to_string();

        let result = translate_k8s_objects(
            &[telemetry],
            options_for_namespace("istio-config")
                .with_istio_root_namespace("istio-config".to_string()),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let scope = &mesh.telemetry_resources[0].scope;
        assert!(
            matches!(scope, PolicyScope::WorkloadSelector { selector } if selector.namespace.is_none() && selector.labels.get("app") == Some(&"gateway".to_string()))
        );
    }

    #[test]
    fn telemetry_header_tags_are_runtime_header_references() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "customTags": {
                            "tenant": {"header": {"name": "x-tenant"}},
                            "region": {"literal": {"value": "us-east"}}
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");

        assert_eq!(tracing.sampling_percentage, None);
        assert_eq!(
            tracing.custom_header_tags.get("tenant").map(String::as_str),
            Some("x-tenant")
        );
        assert_eq!(
            tracing.custom_tags.get("region").map(String::as_str),
            Some("us-east")
        );
        assert!(!tracing.custom_tags.contains_key("tenant"));
    }

    #[test]
    fn telemetry_access_log_filter_with_or_is_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "accessLogging": [{
                        "filter": {
                            "expression": "response.code >= 500 || response.duration >= 1000"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("OR filters should fail closed");

        assert!(err.to_string().contains("with '||' are not supported"));
    }

    #[test]
    fn telemetry_access_log_duration_gt_preserves_strict_semantics() {
        let filter = parse_access_log_filter_expression("response.duration > 100")
            .expect("filter parses")
            .expect("filter is present");

        assert_eq!(filter.min_latency_ms, Some(101));
    }

    #[test]
    fn telemetry_access_log_duration_unsupported_comparator_is_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "accessLogging": [{
                        "filter": {
                            "expression": "response.duration <= 100"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("unsupported duration comparator should fail closed");

        assert!(
            err.to_string()
                .contains("response.duration filters only support")
        );
    }

    #[test]
    fn telemetry_access_log_malformed_status_filter_is_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "accessLogging": [{
                        "filter": {
                            "expression": "response.code != 500"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect_err("malformed status filter should fail closed");

        assert!(
            err.to_string()
                .contains("response.code filter must use a numeric comparison")
        );
    }

    #[test]
    fn translates_request_authentication_with_empty_jwt_rules() {
        let result = translate_k8s_objects(
            &[object("RequestAuthentication", serde_json::json!({}))],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.request_authentications.len(), 1);
        assert!(mesh.request_authentications[0].jwt_rules.is_empty());
    }

    #[test]
    fn translates_request_authentication_with_inline_jwks() {
        let result = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "issuer": "https://auth.example.com",
                        "jwks": "{\"keys\":[{\"kty\":\"RSA\"}]}"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let rule = &mesh.request_authentications[0].jwt_rules[0];
        assert!(rule.jwks_uri.is_none());
        assert_eq!(rule.jwks.as_deref(), Some("{\"keys\":[{\"kty\":\"RSA\"}]}"));
    }

    #[test]
    fn translates_request_authentication_multiple_jwt_rules() {
        let result = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [
                        {
                            "issuer": "https://first.example.com",
                            "jwksUri": "https://first.example.com/jwks"
                        },
                        {
                            "issuer": "https://second.example.com",
                            "jwksUri": "https://second.example.com/jwks",
                            "audiences": ["aud-a", "aud-b"]
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.request_authentications[0].jwt_rules.len(), 2);
        assert_eq!(
            mesh.request_authentications[0].jwt_rules[0].issuer,
            "https://first.example.com"
        );
        assert_eq!(
            mesh.request_authentications[0].jwt_rules[1].audiences,
            vec!["aud-a", "aud-b"]
        );
    }

    #[test]
    fn rejects_request_authentication_jwt_rule_without_issuer() {
        let err = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "jwksUri": "https://example.com/jwks"
                    }]
                }),
            )],
            options(),
        )
        .expect_err("missing issuer must fail");

        assert!(err.to_string().contains("issuer is required"));
    }

    #[test]
    fn translates_request_authentication_no_warning_emitted() {
        let result = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "issuer": "https://auth.example.com",
                        "jwksUri": "https://auth.example.com/jwks"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        // Should NOT emit a warning now that it's fully translated
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("RequestAuthentication"))
        );
    }
}
