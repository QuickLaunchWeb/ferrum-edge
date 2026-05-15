use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::Value;

use crate::identity::spiffe::SpiffeId;
use crate::modes::mesh::config::{
    AccessLogFilter, AppProtocol, ConditionMatch, JwtHeader, MeshAccessLoggingConfig,
    MeshConsistentHash, MeshDestinationRule, MeshEndpoint, MeshJwtRule, MeshLoadBalancer,
    MeshMetricsConfig, MeshOutlierDetection, MeshPolicy, MeshProxyConfig,
    MeshRequestAuthentication, MeshRule, MeshSidecar, MeshSidecarEgress, MeshSimpleLb, MeshSubset,
    MeshTelemetryConfig, MeshTelemetryResource, MeshTracingConfig, MeshTrafficPolicy,
    MeshTrafficPolicyTls, MetricTagOverride, MtlsMode, PeerAuthentication, PolicyAction,
    PolicyScope, PrincipalMatch, RequestMatch, Resolution, ServiceEntry, ServiceEntryLocation,
    ServicePort, TagOverrideOperation, TracingProvider, Workload, WorkloadPort, WorkloadSelector,
};

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, K8sTranslationOptions,
    MeshRouteDispatchDestination, RouteBackend, RouteProxySpec, SourceKind,
    attach_route_plugins_to_proxy, exact_path_listen_path, fault_injection_plugin_for_proxy,
    invalid_resource, mesh_route_dispatch_can_emit_rule,
    mesh_route_dispatch_has_unsupported_predicate, mesh_route_dispatch_plugin_from_rules,
    mesh_route_dispatch_rules_for_proxy, optional_port_field, parse_istio_duration_ms,
    port_from_u64, proxy_for_route, request_termination_plugin_for_proxy, resource_id,
    selector_from_istio, string_array, string_field, string_map, upstream_for_route,
    workload_entry_service_key_from_host,
};
use crate::config::types::{
    BackendScheme, MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES,
    MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH, MAX_TARGET_WEIGHT, PluginConfig, Proxy,
    RetryConfig, validate_backend_tls_san_allow_list_entry, validate_backend_tls_sni,
};

const URI_LESS_MATCH_LISTEN_PATH: &str = "~.*";

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
            let peer_auth = peer_authentication(&acc.options, object)?;
            acc.mesh.peer_authentications.push(peer_auth);
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
            let (proxies, upstreams, plugins) = virtual_service_routes(object, acc)?;
            for upstream in upstreams {
                acc.upsert_upstream(upstream);
            }
            for proxy in proxies {
                acc.upsert_proxy(proxy, SourceKind::Istio);
            }
            for plugin in plugins {
                acc.config.plugin_configs.push(plugin);
            }
            Ok(true)
        }
        "DestinationRule" => {
            let dr = destination_rule(acc, object)?;
            acc.mesh.destination_rules.push(dr);
            Ok(true)
        }
        "RequestAuthentication" => {
            acc.mesh
                .request_authentications
                .push(request_authentication(acc, object)?);
            Ok(true)
        }
        "Sidecar" => {
            let sidecar = sidecar(acc, object)?;
            acc.mesh.sidecars.push(sidecar);
            Ok(true)
        }
        "Telemetry" => {
            acc.mesh.telemetry_resources.push(telemetry(acc, object)?);
            Ok(true)
        }
        "ProxyConfig" => {
            acc.mesh
                .proxy_configs
                .push(proxy_config(&acc.options, object)?);
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

    let mut rules = Vec::new();
    for rule in object
        .spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        rules.extend(mesh_rules(object, rule, action)?);
    }
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
        never_matches: true,
        action: PolicyAction::Allow,
        ..MeshRule::default()
    }
}

fn mesh_rules(
    object: &K8sObject,
    rule: &Value,
    action: PolicyAction,
) -> Result<Vec<MeshRule>, K8sTranslateError> {
    let sources: Vec<&Value> = rule
        .get("from")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|source_entry| source_entry.get("source").unwrap_or(&Value::Null))
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

    if sources.is_empty() {
        return Ok(vec![MeshRule {
            from: Vec::new(),
            to,
            when,
            request_principals: Vec::new(),
            never_matches: false,
            action,
        }]);
    }

    Ok(sources
        .into_iter()
        .map(|source| MeshRule {
            from: principal_matches(source),
            to: to.clone(),
            when: when.clone(),
            request_principals: string_array(source, "requestPrincipals"),
            never_matches: false,
            action,
        })
        .collect())
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
    let (ports, port_patterns) = operation_ports(object, operation, "ports")?;
    let (not_ports, not_port_patterns) = operation_ports(object, operation, "notPorts")?;
    if !not_port_patterns.is_empty() {
        return Err(invalid_resource(
            object,
            "rules[].to[].operation.notPorts wildcard patterns are unsupported \
             (use literal numeric ports)"
                .to_string(),
        ));
    }

    Ok(RequestMatch {
        methods: string_array(operation, "methods"),
        paths: string_array(operation, "paths"),
        hosts: string_array(operation, "hosts"),
        headers: HashMap::new(),
        ports,
        port_patterns,
        not_methods: string_array(operation, "notMethods"),
        not_paths: string_array(operation, "notPaths"),
        not_hosts: string_array(operation, "notHosts"),
        not_ports,
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
            "methods" | "paths" | "hosts" | "ports" | "notMethods" | "notPaths" | "notHosts"
            | "notPorts" => {}
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
    field: &str,
) -> Result<(Vec<u16>, Vec<String>), K8sTranslateError> {
    let mut ports = Vec::new();
    let mut port_patterns = Vec::new();
    for port in string_array(operation, field) {
        if is_istio_port_pattern(&port) {
            port_patterns.push(port);
            continue;
        }
        ports.push(port_from_string(
            object,
            &port,
            &format!("rules[].to[].operation.{field}"),
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
        && request.not_methods.is_empty()
        && request.not_paths.is_empty()
        && request.not_hosts.is_empty()
        && request.not_ports.is_empty()
}

fn condition_match(value: &Value) -> Option<ConditionMatch> {
    Some(ConditionMatch {
        key: string_field(value, "key")?.to_string(),
        values: string_array(value, "values"),
        not_values: string_array(value, "notValues"),
    })
}

fn peer_authentication(
    options: &K8sTranslationOptions,
    object: &K8sObject,
) -> Result<PeerAuthentication, K8sTranslateError> {
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

    let selector = object.spec.get("selector");
    let scope = istio_policy_scope(options, object, selector);
    let selector = match &scope {
        PolicyScope::WorkloadSelector { selector } => Some(selector.clone()),
        PolicyScope::MeshWide | PolicyScope::Namespace { .. } => None,
    };

    Ok(PeerAuthentication {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        scope: Some(scope),
        selector,
        mtls_mode: effective_mtls_mode,
        port_overrides,
    })
}

/// Translate an Istio `Sidecar` resource into a [`MeshSidecar`].
///
/// Parses:
///   - `spec.workloadSelector.matchLabels` → [`MeshSidecar::workload_selector`]
///     with the Sidecar's own namespace (a `Sidecar` only ever targets
///     workloads in its own namespace, per Istio semantics).
///   - `spec.egress[].hosts` → [`MeshSidecarEgress::hosts`] (verbatim — the
///     slice builder parses each entry via `MeshSidecarEgress::parse_host_pattern`).
///   - `spec.egress[].port.number` → [`MeshSidecarEgress::port`] (optional).
///
/// Ingress listener configuration (`spec.ingress[]`) and `outboundTrafficPolicy`
/// are deliberately not translated yet — egress scoping is the immediate
/// compatibility gap; the other surfaces stay in the documented "deferred"
/// table until separate PRs land them.
fn sidecar(acc: &mut K8sAccumulator, object: &K8sObject) -> Result<MeshSidecar, K8sTranslateError> {
    if object.metadata.namespace == acc.options.istio_root_namespace {
        acc.warnings.push(format!(
            "Sidecar {}/{} is in the Istio root namespace '{}', but Ferrum Sidecar egress scoping is namespace-local today; it will not act as a mesh-wide default",
            object.metadata.namespace, object.metadata.name, acc.options.istio_root_namespace
        ));
    }

    let workload_selector = match object.spec.get("workloadSelector") {
        Some(selector_value) => {
            let labels = selector_from_istio(Some(selector_value));
            if labels.is_empty() {
                None
            } else {
                Some(WorkloadSelector {
                    labels,
                    namespace: Some(object.metadata.namespace.clone()),
                })
            }
        }
        None => None,
    };

    let mut egress = Vec::new();
    let mut egress_inherits_defaults = false;
    let mut port_scopes = BTreeSet::new();
    match object.spec.get("egress") {
        None => {
            // Istio: omitted egress inherits the namespace default outbound
            // scope. Keep it distinct from an explicit empty `egress: []`,
            // which means block all.
            egress_inherits_defaults = true;
        }
        Some(raw_egress) => {
            let entries = raw_egress
                .as_array()
                .ok_or_else(|| invalid_resource(object, "Sidecar egress must be an array"))?;
            for entry in entries {
                let hosts_value = entry.get("hosts").ok_or_else(|| {
                    invalid_resource(
                        object,
                        "Sidecar egress[].hosts must be a non-empty array of strings",
                    )
                })?;
                let hosts_array = hosts_value.as_array().ok_or_else(|| {
                    invalid_resource(
                        object,
                        "Sidecar egress[].hosts must be a non-empty array of strings",
                    )
                })?;
                if hosts_array.is_empty() {
                    return Err(invalid_resource(
                        object,
                        "Sidecar egress[].hosts must be a non-empty array of strings",
                    ));
                }
                let hosts: Vec<String> = hosts_array
                    .iter()
                    .map(|host| {
                        host.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                            invalid_resource(
                                object,
                                "Sidecar egress[].hosts must be a non-empty array of strings",
                            )
                        })
                    })
                    .collect::<Result<_, _>>()?;
                let port = match entry.get("port") {
                    Some(port_obj) => optional_port_field(
                        object,
                        port_obj.get("number"),
                        "Sidecar egress[].port.number",
                    )?,
                    None => None,
                };
                if let Some(port) = port {
                    port_scopes.insert(port);
                }
                egress.push(MeshSidecarEgress { hosts, port });
            }
        }
    }

    if !port_scopes.is_empty() {
        acc.warnings.push(format!(
            "Sidecar {}/{} uses egress port scoping {:?}, but Ferrum currently narrows Sidecar egress by host only; the port field is parsed and preserved but not enforced",
            object.metadata.namespace, object.metadata.name, port_scopes
        ));
    }

    Ok(MeshSidecar {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        workload_selector,
        egress_inherits_defaults,
        egress,
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

    let from_headers = jwt_from_headers(object, rule)?;

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

fn jwt_from_headers(object: &K8sObject, rule: &Value) -> Result<Vec<JwtHeader>, K8sTranslateError> {
    let Some(raw) = rule.get("fromHeaders") else {
        return Ok(Vec::new());
    };
    let Some(headers) = raw.as_array() else {
        return Err(invalid_resource(
            object,
            "RequestAuthentication jwtRules[].fromHeaders must be an array of objects",
        ));
    };

    headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            let name = string_field(header, "name").ok_or_else(|| {
                invalid_resource(
                    object,
                    format!(
                        "RequestAuthentication jwtRules[].fromHeaders[{index}].name is required"
                    ),
                )
            })?;
            let prefix = match header.get("prefix") {
                Some(prefix) => Some(prefix.as_str().ok_or_else(|| {
                    invalid_resource(
                        object,
                        format!(
                            "RequestAuthentication jwtRules[].fromHeaders[{index}].prefix must be a string"
                        ),
                    )
                })?),
                None => None,
            };
            Ok(JwtHeader {
                name: name.to_string(),
                prefix: prefix.map(ToOwned::to_owned),
            })
        })
        .collect()
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

fn destination_rule(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
) -> Result<MeshDestinationRule, K8sTranslateError> {
    let host_raw = string_field(&object.spec, "host")
        .ok_or_else(|| invalid_resource(object, "DestinationRule requires spec.host"))?;
    let host = host_raw.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(invalid_resource(
            object,
            "DestinationRule spec.host must be a non-empty hostname",
        ));
    }

    let traffic_policy = object
        .spec
        .get("trafficPolicy")
        .map(|tp| translate_traffic_policy(acc, object, tp))
        .transpose()?;

    let port_level_settings = object
        .spec
        .get("trafficPolicy")
        .and_then(|tp| tp.get("portLevelSettings"))
        .map(|pls| translate_port_level_settings(acc, object, pls))
        .transpose()?
        .unwrap_or_default();

    let subsets = object
        .spec
        .get("subsets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|subset| translate_subset(acc, object, subset))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(MeshDestinationRule {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        host,
        traffic_policy,
        port_level_settings,
        subsets,
    })
}

/// Parse Istio `trafficPolicy.portLevelSettings` into a per-port
/// [`MeshTrafficPolicy`] map keyed by port number. Each entry is a regular
/// traffic-policy block scoped to one port; the cold-path apply pass layers
/// the resolved policy onto the matching upstream's `port_overrides`.
///
/// Today only `connectionPool.tcp.connectTimeout` is actually enforced
/// per-port — see `Upstream::effective_connect_timeout_ms` and the dispatch
/// call to `resolve_effective_proxy_for_target`. Per-port `loadBalancer`
/// and `outlierDetection` fields ARE parsed (so the slice round-trips), but
/// the gateway keeps a single `LoadBalancer` and `PassiveHealthCheck` per
/// upstream — switching algorithm/hash-ring or thresholds per destination
/// port would require per-port balancer instances and is out of scope here.
/// We emit translator warnings so operators see the gap at apply time.
fn translate_port_level_settings(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    value: &Value,
) -> Result<HashMap<u16, MeshTrafficPolicy>, K8sTranslateError> {
    let entries = value.as_array().ok_or_else(|| {
        invalid_resource(object, "trafficPolicy.portLevelSettings must be an array")
    })?;

    let mut out = HashMap::with_capacity(entries.len());
    for entry in entries {
        let port_value = entry
            .get("port")
            .and_then(|p| p.get("number"))
            .ok_or_else(|| {
                invalid_resource(
                    object,
                    "trafficPolicy.portLevelSettings[].port.number is required",
                )
            })?;
        let port_u64 = port_value.as_u64().ok_or_else(|| {
            invalid_resource(
                object,
                "trafficPolicy.portLevelSettings[].port.number must be an integer",
            )
        })?;
        if port_u64 == 0 || port_u64 > u16::MAX as u64 {
            return Err(invalid_resource(
                object,
                format!(
                    "trafficPolicy.portLevelSettings[].port.number must be 1-65535 (got {port_u64})"
                ),
            ));
        }
        let port = port_u64 as u16;

        // Warn for parsed-but-not-enforced per-port fields so operators see
        // the gap at apply time instead of silently expecting per-port LB
        // / outlier behaviour. `connectTimeout` IS enforced and stays
        // silent.
        if entry.get("loadBalancer").is_some() {
            acc.warnings.push(format!(
                "DestinationRule {}/{}: trafficPolicy.portLevelSettings[].loadBalancer is parsed but not enforced per-port today (gateway keeps a single load balancer per upstream); only connectTimeout is applied at request time",
                object.metadata.namespace, object.metadata.name
            ));
        }
        if entry.get("outlierDetection").is_some() {
            acc.warnings.push(format!(
                "DestinationRule {}/{}: trafficPolicy.portLevelSettings[].outlierDetection is parsed but not enforced per-port today (gateway keeps a single passive health check per upstream); only connectTimeout is applied at request time",
                object.metadata.namespace, object.metadata.name
            ));
        }

        let policy = translate_traffic_policy(acc, object, entry)?;

        if out.insert(port, policy).is_some() {
            return Err(invalid_resource(
                object,
                format!("trafficPolicy.portLevelSettings has duplicate port {port}"),
            ));
        }
    }
    Ok(out)
}

fn translate_traffic_policy(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    value: &Value,
) -> Result<MeshTrafficPolicy, K8sTranslateError> {
    let connect_timeout_ms = value
        .get("connectionPool")
        .and_then(|cp| cp.get("tcp"))
        .and_then(|tcp| string_field(tcp, "connectTimeout"))
        .and_then(parse_istio_duration_ms);

    let outlier_detection = value
        .get("outlierDetection")
        .map(|od| translate_outlier_detection(object, od))
        .transpose()?;

    let load_balancer = value
        .get("loadBalancer")
        .map(|lb| translate_load_balancer(acc, object, lb))
        .transpose()?;

    let tls = value
        .get("tls")
        .map(|tls| translate_client_tls_settings(object, tls))
        .transpose()?;

    Ok(MeshTrafficPolicy {
        connect_timeout_ms,
        outlier_detection,
        load_balancer,
        tls,
    })
}

/// Translate Istio `DestinationRule.trafficPolicy.tls` (a.k.a.
/// `ClientTLSSettings`) into a `MeshTrafficPolicyTls`.
///
/// `mode` maps:
/// - `DISABLE` -> `MtlsMode::Disable`
/// - `SIMPLE` -> `MtlsMode::Simple`
/// - `MUTUAL` -> `MtlsMode::Mutual`
/// - `ISTIO_MUTUAL` -> `MtlsMode::IstioMutual`
///
/// Validation:
/// - `ISTIO_MUTUAL` rejects explicit `clientCertificate`/`privateKey`/
///   `caCertificates` — Istio reuses the workload's SPIFFE identity material.
/// - `MUTUAL` requires both `clientCertificate` AND `privateKey` (matches
///   Istio's `pilot-validation`).
fn translate_client_tls_settings(
    object: &K8sObject,
    value: &Value,
) -> Result<MeshTrafficPolicyTls, K8sTranslateError> {
    let mode_raw = string_field(value, "mode").unwrap_or("SIMPLE");
    let mode = match mode_raw {
        "DISABLE" => MtlsMode::Disable,
        "SIMPLE" => MtlsMode::Simple,
        "MUTUAL" => MtlsMode::Mutual,
        "ISTIO_MUTUAL" => MtlsMode::IstioMutual,
        other => {
            return Err(invalid_resource(
                object,
                format!(
                    "trafficPolicy.tls.mode '{other}' is unsupported (expected one of \
                     DISABLE, SIMPLE, MUTUAL, ISTIO_MUTUAL)"
                ),
            ));
        }
    };

    let sni = string_field(value, "sni").map(ToOwned::to_owned);
    let ca_certificates = string_field(value, "caCertificates").map(ToOwned::to_owned);
    let client_certificate = string_field(value, "clientCertificate").map(ToOwned::to_owned);
    let private_key = string_field(value, "privateKey").map(ToOwned::to_owned);
    let subject_alt_names = string_array(value, "subjectAltNames");
    if subject_alt_names.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES {
        return Err(invalid_resource(
            object,
            format!(
                "trafficPolicy.tls.subjectAltNames must not have more than {} entries (got {})",
                MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES,
                subject_alt_names.len()
            ),
        ));
    }
    for (idx, san) in subject_alt_names.iter().enumerate() {
        if san.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH {
            return Err(invalid_resource(
                object,
                format!(
                    "trafficPolicy.tls.subjectAltNames[{idx}] must not exceed {} characters (got {})",
                    MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH,
                    san.len()
                ),
            ));
        }
        if let Err(e) = validate_backend_tls_san_allow_list_entry(san) {
            return Err(invalid_resource(
                object,
                format!("trafficPolicy.tls.subjectAltNames[{idx}]: {e}"),
            ));
        }
    }
    if let Some(ref sni_value) = sni
        && let Err(e) = validate_backend_tls_sni(sni_value)
    {
        return Err(invalid_resource(
            object,
            format!("trafficPolicy.tls.sni: {e}"),
        ));
    }
    let insecure_skip_verify = value
        .get("insecureSkipVerify")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    match mode {
        MtlsMode::IstioMutual => {
            if client_certificate.is_some() || private_key.is_some() || ca_certificates.is_some() {
                return Err(invalid_resource(
                    object,
                    "trafficPolicy.tls.mode=ISTIO_MUTUAL must not set \
                     clientCertificate/privateKey/caCertificates — Istio reuses the \
                     workload's SPIFFE identity material",
                ));
            }
        }
        MtlsMode::Mutual => {
            if client_certificate.is_none() || private_key.is_none() {
                return Err(invalid_resource(
                    object,
                    "trafficPolicy.tls.mode=MUTUAL requires both clientCertificate and \
                     privateKey",
                ));
            }
        }
        MtlsMode::Disable | MtlsMode::Simple => {}
        // PeerAuthentication-side modes can't be set via DR.tls.mode in Istio;
        // translation above only emits the four client-side modes.
        MtlsMode::Strict | MtlsMode::Permissive => {
            return Err(invalid_resource(
                object,
                format!("trafficPolicy.tls.mode '{mode_raw}' is not a client-side TLS mode"),
            ));
        }
    }

    Ok(MeshTrafficPolicyTls {
        mode,
        sni,
        ca_certificates,
        client_certificate,
        private_key,
        subject_alt_names,
        insecure_skip_verify,
    })
}

fn translate_outlier_detection(
    object: &K8sObject,
    value: &Value,
) -> Result<MeshOutlierDetection, K8sTranslateError> {
    let consecutive_errors = value
        .get("consecutive5xxErrors")
        .or_else(|| value.get("consecutiveErrors"))
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok());

    let interval_seconds = string_field(value, "interval")
        .and_then(parse_istio_duration_secs)
        .filter(|seconds| *seconds > 0);

    let base_ejection_seconds =
        string_field(value, "baseEjectionTime").and_then(parse_istio_duration_secs);

    let max_ejection_percent = value
        .get("maxEjectionPercent")
        .and_then(Value::as_u64)
        .map(|v| {
            if v <= 100 {
                Ok(v as u8)
            } else {
                Err(invalid_resource(
                    object,
                    format!("outlierDetection.maxEjectionPercent must be 0-100 (got {v})"),
                ))
            }
        })
        .transpose()?;

    Ok(MeshOutlierDetection {
        consecutive_errors,
        interval_seconds,
        base_ejection_seconds,
        max_ejection_percent,
    })
}

fn translate_load_balancer(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    value: &Value,
) -> Result<MeshLoadBalancer, K8sTranslateError> {
    if let Some(simple) = string_field(value, "simple") {
        let algorithm = match simple {
            "ROUND_ROBIN" => MeshSimpleLb::RoundRobin,
            "LEAST_REQUEST" | "LEAST_CONN" => MeshSimpleLb::LeastRequest,
            "RANDOM" => MeshSimpleLb::Random,
            "PASSTHROUGH" => {
                acc.warnings.push(format!(
                    "DestinationRule {}/{} loadBalancer.simple=PASSTHROUGH is approximated as ROUND_ROBIN; Ferrum always routes via configured upstream targets and cannot preserve the original destination IP",
                    object.metadata.namespace, object.metadata.name
                ));
                MeshSimpleLb::Passthrough
            }
            other => {
                return Err(invalid_resource(
                    object,
                    format!("loadBalancer.simple '{other}' is unsupported"),
                ));
            }
        };
        return Ok(MeshLoadBalancer::Simple(algorithm));
    }

    if let Some(ch) = value.get("consistentHash") {
        let http_header_name = string_field(ch, "httpHeaderName").map(ToOwned::to_owned);
        let http_cookie_name = ch
            .get("httpCookie")
            .and_then(|cookie| string_field(cookie, "name"))
            .map(ToOwned::to_owned);
        let use_source_ip = ch
            .get("useSourceIp")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let set_count = u8::from(http_header_name.is_some())
            + u8::from(http_cookie_name.is_some())
            + u8::from(use_source_ip);
        if set_count > 1 {
            return Err(invalid_resource(
                object,
                "loadBalancer.consistentHash must set exactly one of httpHeaderName, httpCookie, or useSourceIp",
            ));
        }
        if set_count == 0 {
            return Err(invalid_resource(
                object,
                "loadBalancer.consistentHash requires one of httpHeaderName, httpCookie, or useSourceIp",
            ));
        }
        return Ok(MeshLoadBalancer::ConsistentHash(MeshConsistentHash {
            http_header_name,
            http_cookie_name,
            use_source_ip,
        }));
    }

    // Default to RoundRobin when loadBalancer is present but empty
    Ok(MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin))
}

fn translate_subset(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    value: &Value,
) -> Result<MeshSubset, K8sTranslateError> {
    let name = string_field(value, "name")
        .ok_or_else(|| invalid_resource(object, "DestinationRule subset requires a name"))?
        .to_string();
    let labels = string_map(value.get("labels").unwrap_or(&Value::Null));
    let traffic_policy = value
        .get("trafficPolicy")
        .map(|tp| translate_traffic_policy(acc, object, tp))
        .transpose()?;

    if let Some(ref policy) = traffic_policy {
        if policy.connect_timeout_ms.is_some() {
            acc.warnings.push(format!(
                "DestinationRule {}/{} subset '{}' connectionPool.tcp.connectTimeout is currently ignored; only the top-level trafficPolicy connectTimeout applies",
                object.metadata.namespace, object.metadata.name, name
            ));
        }
        if policy.outlier_detection.is_some() {
            acc.warnings.push(format!(
                "DestinationRule {}/{} subset '{}' outlierDetection is currently ignored; only the top-level trafficPolicy outlierDetection applies",
                object.metadata.namespace, object.metadata.name, name
            ));
        }
        if policy.tls.is_some() {
            acc.warnings.push(format!(
                "DestinationRule {}/{} subset '{}' trafficPolicy.tls is parsed but not yet applied per-subset; only the top-level trafficPolicy.tls projects onto the resolved Upstream's backend_tls_* fields",
                object.metadata.namespace, object.metadata.name, name
            ));
        }
    }

    Ok(MeshSubset {
        name,
        labels,
        traffic_policy,
    })
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
        export_to: string_array(&object.spec, "exportTo"),
        workload_selector: object
            .spec
            .get("workloadSelector")
            .and_then(|selector| selector.get("labels"))
            .map(string_map)
            .map(|labels| WorkloadSelector {
                namespace: Some(object.metadata.namespace.clone()),
                labels,
            }),
    })
}

fn workload_entry(acc: &K8sAccumulator, object: &K8sObject) -> Result<Workload, K8sTranslateError> {
    // Treat empty-string `serviceAccount` as missing (Istio semantics: missing
    // or empty → fall back to `"default"` for SVID issuance). Without this
    // collapse, an empty string would propagate into the SPIFFE path
    // `ns/{ns}/sa/`, which the SPIFFE parser rejects as a trailing-slash error
    // and surfaces a confusing translation failure to operators.
    let service_account_raw =
        string_field(&object.spec, "serviceAccount").filter(|s| !s.is_empty());
    let path = format!(
        "ns/{}/sa/{}",
        object.metadata.namespace,
        service_account_raw.unwrap_or("default")
    );
    let spiffe_id = SpiffeId::from_parts(&acc.options.trust_domain, &path)
        .map_err(|e| invalid_resource(object, format!("invalid workload SPIFFE ID: {e}")))?;

    let weight = object
        .spec
        .get("weight")
        .map(|w| {
            let raw = w.as_u64().ok_or_else(|| {
                invalid_resource(
                    object,
                    "WorkloadEntry.weight must be a non-negative integer",
                )
            })?;
            if raw > u64::from(MAX_TARGET_WEIGHT) {
                return Err(invalid_resource(
                    object,
                    format!("WorkloadEntry.weight must be 0..={MAX_TARGET_WEIGHT} (got {raw})"),
                ));
            }
            Ok(raw as u32)
        })
        .transpose()?;

    // Empty-string `locality` is operator intent for "unset"; collapse to
    // None so downstream consumers don't need to special-case empty strings.
    let locality = string_field(&object.spec, "locality")
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let service_raw = object
        .spec
        .get("service")
        .and_then(Value::as_str)
        .unwrap_or(&object.metadata.name);
    let service_key = workload_entry_service_key_from_host(
        service_raw,
        &object.metadata.namespace,
        &acc.options.cluster_domain,
        &acc.known_namespaces,
    );
    match service_key.as_ref() {
        Some(key) if key.namespace != object.metadata.namespace => {
            return Err(invalid_resource(
                object,
                format!(
                    "WorkloadEntry.service '{service_raw}' references Service namespace '{}' but WorkloadEntry namespace is '{}'; cross-namespace WorkloadEntry service hosts are not supported",
                    key.namespace, object.metadata.namespace
                ),
            ));
        }
        _ => {}
    }
    let service_name = service_key
        .map(|key| key.name)
        .unwrap_or_else(|| service_raw.to_string());

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
        service_name,
        addresses: string_field(&object.spec, "address")
            .map(|address| vec![address.to_string()])
            .unwrap_or_default(),
        ports: workload_ports(object)?,
        trust_domain: acc.options.trust_domain.clone(),
        namespace: object.metadata.namespace.clone(),
        network: string_field(&object.spec, "network").map(ToOwned::to_owned),
        cluster: string_field(&object.spec, "cluster").map(ToOwned::to_owned),
        weight,
        locality,
        service_account: service_account_raw.map(ToOwned::to_owned),
    })
}

type VsRouteResult = (
    Vec<crate::config::types::Proxy>,
    Vec<crate::config::types::Upstream>,
    Vec<PluginConfig>,
);

struct PendingRouteDispatch {
    proxy: Proxy,
    route_plugins: Vec<PluginConfig>,
    rules: Vec<Value>,
    is_uri_less_catch_all: bool,
    force_terminate: bool,
}

fn stash_pending_route_dispatch(
    pending: &mut Vec<(Option<String>, PendingRouteDispatch)>,
    listen_path: Option<String>,
    proxy: Proxy,
    route_plugins: Vec<PluginConfig>,
    rules: Vec<Value>,
    is_uri_less_catch_all: bool,
    force_terminate: bool,
) {
    if let Some((_, bucket)) = pending.iter_mut().find(|(key, _)| *key == listen_path) {
        bucket.proxy = proxy;
        bucket.route_plugins = route_plugins;
        bucket.rules.extend(rules);
        bucket.is_uri_less_catch_all = is_uri_less_catch_all;
        bucket.force_terminate |= force_terminate;
    } else {
        pending.push((
            listen_path,
            PendingRouteDispatch {
                proxy,
                route_plugins,
                rules,
                is_uri_less_catch_all,
                force_terminate,
            },
        ));
    }
}

fn take_pending_route_dispatch(
    pending: &mut Vec<(Option<String>, PendingRouteDispatch)>,
    listen_path: &Option<String>,
) -> Option<PendingRouteDispatch> {
    let index = pending.iter().position(|(key, _)| key == listen_path)?;
    Some(pending.remove(index).1)
}

fn route_has_local_policy(
    route_plugins: &[PluginConfig],
    retry: &Option<RetryConfig>,
    timeout_ms: Option<u64>,
) -> bool {
    !route_plugins.is_empty() || retry.is_some() || timeout_ms.is_some()
}

#[allow(clippy::too_many_arguments)]
fn materialize_route_candidate(
    proxies: &mut Vec<Proxy>,
    plugins: &mut Vec<PluginConfig>,
    deferred_uri_less_proxies: &mut Vec<Proxy>,
    deferred_uri_less_plugins: &mut Vec<PluginConfig>,
    namespace: &str,
    mut proxy: Proxy,
    mut route_plugins: Vec<PluginConfig>,
    dispatch_rules: Vec<Value>,
    reject_unmatched: bool,
    is_uri_less_catch_all: bool,
    force_terminate: bool,
) {
    let terminate_unconditionally = force_terminate && dispatch_rules.is_empty();
    if terminate_unconditionally {
        route_plugins.push(request_termination_plugin_for_proxy(
            &proxy.id,
            namespace,
            "unsupported Istio VirtualService match predicate",
        ));
    }

    let reject_unmatched = reject_unmatched || force_terminate;
    if let Some(plugin) = mesh_route_dispatch_plugin_from_rules(
        &proxy.id,
        namespace,
        dispatch_rules,
        reject_unmatched,
    ) {
        route_plugins.push(plugin);
    }

    attach_route_plugins_to_proxy(&mut proxy, &route_plugins);
    if is_uri_less_catch_all {
        deferred_uri_less_plugins.extend(route_plugins);
        deferred_uri_less_proxies.push(proxy);
    } else {
        plugins.extend(route_plugins);
        proxies.push(proxy);
    }
}

fn virtual_service_routes(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
) -> Result<VsRouteResult, K8sTranslateError> {
    let hosts = string_array(&object.spec, "hosts");
    let mut proxies = Vec::new();
    let mut upstreams = Vec::new();
    let mut plugins = Vec::new();
    let mut deferred_uri_less_proxies = Vec::new();
    let mut deferred_uri_less_plugins = Vec::new();
    let mut pending_uri_less_route: Option<PendingRouteDispatch> = None;
    let mut pending_scoped_routes: Vec<(Option<String>, PendingRouteDispatch)> = Vec::new();
    let http_routes: Vec<&Value> = object
        .spec
        .get("http")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();

    for (index, http) in http_routes.iter().copied().enumerate() {
        let route_candidates =
            route_candidate_paths(http, acc.options.vs_header_routing_experimental);
        if route_candidates.is_empty() {
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

        let retry = route_retry_config(http);
        let timeout_ms = route_timeout_ms(http);

        let match_count = route_candidates.len();
        for (match_index, (listen_path, force_terminate_current)) in
            route_candidates.into_iter().enumerate()
        {
            let is_uri_less_catch_all = listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH);
            let mut route_plugins = Vec::new();
            let suffix = if match_count == 1 {
                index.to_string()
            } else {
                format!("{index}-{match_index}")
            };
            let proxy_id = resource_id(
                "istio-vs",
                &object.metadata.namespace,
                &object.metadata.name,
                &suffix,
            );

            // Extract fault injection config and create a proxy-scoped plugin
            if let Some(fault_value) = http.get("fault")
                && let Some(plugin) = fault_injection_plugin_for_proxy(
                    &proxy_id,
                    &object.metadata.namespace,
                    fault_value,
                )
            {
                route_plugins.push(plugin);
            }

            let (current_route_rules, has_uri_only_match) =
                if acc.options.vs_header_routing_experimental {
                    mesh_route_dispatch_rules_for_proxy(
                        http,
                        listen_path.as_deref(),
                        MeshRouteDispatchDestination {
                            backend_host: backend_host.as_str(),
                            backend_port,
                            upstream_id: upstream_id.as_deref(),
                        },
                        false,
                    )
                } else {
                    (Vec::new(), false)
                };

            let proxy = proxy_for_route(RouteProxySpec {
                id: proxy_id,
                namespace: object.metadata.namespace.clone(),
                hosts: hosts.clone(),
                listen_path: listen_path.clone(),
                strip_listen_path: false,
                backend_host: backend_host.clone(),
                backend_port,
                upstream_id: upstream_id.clone(),
                backend_scheme: BackendScheme::Http,
                listen_port: None,
                retry: retry.clone(),
                backend_read_timeout_ms: timeout_ms,
            });

            // `mesh_route_dispatch` candidates whose every in-scope match entry
            // is guarded by method/header/queryParam predicates cannot stand as
            // independent proxies when a later route has the same listen_path:
            // a predicate miss must fall through to the later route, but Ferrum's
            // hot router selects exactly one proxy. Stash those guarded rules and
            // prepend them to the later materialized proxy. URI-less guarded
            // rules are stashed globally and decorate every later concrete route;
            // a synthetic `~.*` catch-all is emitted at the end for paths no later
            // route handles.
            let current_route_has_rules = !current_route_rules.is_empty();
            let guarded_route = force_terminate_current
                || (acc.options.vs_header_routing_experimental
                    && current_route_has_rules
                    && !has_uri_only_match);
            let has_later_same_path = guarded_route
                && !is_uri_less_catch_all
                && http_routes.iter().skip(index + 1).any(|later| {
                    route_candidate_paths(later, acc.options.vs_header_routing_experimental)
                        .iter()
                        .any(|(later_path, _)| later_path == &listen_path)
                });
            let has_later_any_path = is_uri_less_catch_all
                && http_routes.iter().skip(index + 1).any(|later| {
                    !route_candidate_paths(later, acc.options.vs_header_routing_experimental)
                        .is_empty()
                });
            let consumes_pending_uri_less = pending_uri_less_route.is_some();
            let consumes_pending_scoped = pending_scoped_routes
                .iter()
                .any(|(key, _)| key == &listen_path);
            let collapse_required = has_later_same_path
                || consumes_pending_scoped
                || (is_uri_less_catch_all
                    && (has_later_any_path || pending_uri_less_route.is_some()));
            if route_has_local_policy(&route_plugins, &retry, timeout_ms)
                && (consumes_pending_uri_less
                    || consumes_pending_scoped
                    || (guarded_route && collapse_required))
            {
                return Err(invalid_resource(
                    object,
                    format!(
                        "VirtualService HTTP route {index} uses route-local fault/retries/timeout policy on a route that must be merged with another route; Ferrum cannot apply that policy per mesh_route_dispatch rule"
                    ),
                ));
            }

            if guarded_route && (is_uri_less_catch_all || has_later_same_path) {
                if is_uri_less_catch_all {
                    if let Some(bucket) = pending_uri_less_route.as_mut() {
                        bucket.proxy = proxy;
                        bucket.route_plugins = route_plugins;
                        bucket.rules.extend(current_route_rules);
                        bucket.is_uri_less_catch_all = true;
                        bucket.force_terminate |= force_terminate_current;
                    } else {
                        pending_uri_less_route = Some(PendingRouteDispatch {
                            proxy,
                            route_plugins,
                            rules: current_route_rules,
                            is_uri_less_catch_all: true,
                            force_terminate: force_terminate_current,
                        });
                    }
                } else {
                    stash_pending_route_dispatch(
                        &mut pending_scoped_routes,
                        listen_path.clone(),
                        proxy,
                        route_plugins,
                        current_route_rules,
                        false,
                        force_terminate_current,
                    );
                }
                continue;
            }

            let mut dispatch_rules = Vec::new();
            let mut force_terminate = force_terminate_current;
            if let Some(bucket) = pending_uri_less_route.as_ref() {
                dispatch_rules.extend(bucket.rules.iter().cloned());
                force_terminate |= bucket.force_terminate;
            }
            if let Some(bucket) =
                take_pending_route_dispatch(&mut pending_scoped_routes, &listen_path)
            {
                dispatch_rules.extend(bucket.rules);
                force_terminate |= bucket.force_terminate;
            }

            dispatch_rules.extend(current_route_rules);
            let reject_unmatched = guarded_route && !force_terminate;

            materialize_route_candidate(
                &mut proxies,
                &mut plugins,
                &mut deferred_uri_less_proxies,
                &mut deferred_uri_less_plugins,
                &object.metadata.namespace,
                proxy,
                route_plugins,
                dispatch_rules,
                reject_unmatched,
                is_uri_less_catch_all,
                force_terminate,
            );
        }
    }

    for (_, bucket) in pending_scoped_routes {
        materialize_route_candidate(
            &mut proxies,
            &mut plugins,
            &mut deferred_uri_less_proxies,
            &mut deferred_uri_less_plugins,
            &object.metadata.namespace,
            bucket.proxy,
            bucket.route_plugins,
            bucket.rules,
            true,
            bucket.is_uri_less_catch_all,
            bucket.force_terminate,
        );
    }
    if let Some(bucket) = pending_uri_less_route {
        materialize_route_candidate(
            &mut proxies,
            &mut plugins,
            &mut deferred_uri_less_proxies,
            &mut deferred_uri_less_plugins,
            &object.metadata.namespace,
            bucket.proxy,
            bucket.route_plugins,
            bucket.rules,
            true,
            true,
            bucket.force_terminate,
        );
    }

    plugins.extend(deferred_uri_less_plugins);
    proxies.extend(deferred_uri_less_proxies);

    Ok((proxies, upstreams, plugins))
}

fn route_candidate_paths(
    http: &Value,
    vs_header_routing_experimental: bool,
) -> Vec<(Option<String>, bool)> {
    let supported_paths = match_paths(http, vs_header_routing_experimental);
    let mut seen_paths: HashSet<Option<String>> = HashSet::with_capacity(supported_paths.len());
    let mut candidates = Vec::with_capacity(supported_paths.len());
    for path in supported_paths {
        seen_paths.insert(path.clone());
        candidates.push((path, false));
    }

    for path in unsupported_match_paths(http, vs_header_routing_experimental) {
        if seen_paths.insert(path.clone()) {
            candidates.push((path, true));
        } else if let Some((_, force_terminate)) = candidates
            .iter_mut()
            .find(|(candidate_path, _)| candidate_path == &path)
        {
            *force_terminate = true;
        }
    }

    candidates
}

fn match_paths(http: &Value, vs_header_routing_experimental: bool) -> Vec<Option<String>> {
    let Some(matches) = http.get("match").and_then(Value::as_array) else {
        return vec![Some("/".to_string())];
    };
    if matches.is_empty() {
        return vec![Some("/".to_string())];
    }

    let mut seen_paths: HashSet<Option<String>> = HashSet::new();
    let mut paths: Vec<Option<String>> = matches
        .iter()
        // Istio forbids empty HTTPMatchRequest blocks; URI-less entries depend on
        // unsupported predicates such as headers/method/queryParams, so do not
        // broaden them into Ferrum catch-all routes.
        .filter(|m| {
            !vs_header_routing_experimental || !mesh_route_dispatch_has_unsupported_predicate(m)
        })
        .filter_map(|m| m.get("uri").and_then(path_match).map(Some))
        .filter(|listen_path| seen_paths.insert(listen_path.clone()))
        .collect();

    // Codex P2 (#3237631709): with `vs_header_routing_experimental=true`,
    // materialize a regex catch-all listen_path when at least one match
    // entry has NO URI predicate but DOES carry a fully-supported non-URI
    // predicate (`method.exact`, `headers.X.exact`, `queryParams.X.exact`).
    // Without this, an `http.match[]` consisting only of header/method/
    // queryParam predicates produces no listen_path → no proxy → the
    // operator's predicates are silently dropped and traffic that should
    // have been routed by header is unroutable. The mesh_route_dispatch
    // plugin scopes match entries to the listen_path it's installed on,
    // so any URI-bearing siblings stay on their own proxy and do not
    // bleed onto the catch-all. The synthetic path is regex (`~.*`) rather
    // than prefix `/` so Ferrum's prefix-before-regex router does not let
    // a URI-less sibling shadow real prefix URI routes. The translator
    // defers these catch-all proxies until after all URI-derived proxies so
    // they also do not shadow later regex URI routes.
    if vs_header_routing_experimental
        && !seen_paths.contains(&Some(URI_LESS_MATCH_LISTEN_PATH.to_string()))
        && matches
            .iter()
            .any(|m| m.get("uri").is_none() && mesh_route_dispatch_can_emit_rule(m))
    {
        paths.push(Some(URI_LESS_MATCH_LISTEN_PATH.to_string()));
    }

    paths
}

fn unsupported_match_paths(
    http: &Value,
    vs_header_routing_experimental: bool,
) -> Vec<Option<String>> {
    if !vs_header_routing_experimental {
        return Vec::new();
    }

    let Some(matches) = http.get("match").and_then(Value::as_array) else {
        return Vec::new();
    };
    if matches.is_empty() {
        return Vec::new();
    }

    let mut seen_paths: HashSet<Option<String>> = HashSet::new();
    let mut paths = Vec::new();
    for entry in matches
        .iter()
        .filter(|entry| mesh_route_dispatch_has_unsupported_predicate(entry))
    {
        let ignore_uri_case_is_unsupported = entry
            .get("ignoreUriCase")
            .is_some_and(|value| value.as_bool() != Some(false));
        let listen_path = if ignore_uri_case_is_unsupported {
            Some(URI_LESS_MATCH_LISTEN_PATH.to_string())
        } else {
            entry
                .get("uri")
                .and_then(path_match)
                .map(Some)
                .unwrap_or_else(|| Some(URI_LESS_MATCH_LISTEN_PATH.to_string()))
        };
        if seen_paths.insert(listen_path.clone()) {
            paths.push(listen_path);
        }
    }

    paths
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
        let port = resolve_destination_port(object, destination, host, acc)?.unwrap_or(80);
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

/// Resolve `destination.port` to a numeric port. Accepts either
/// `port.number` (integer) or `port.name` (string), with the latter looked
/// up against the `Service.spec.ports[].name` index built in the
/// translator pre-pass. Hosts that point at a service outside the loaded
/// namespace set (cluster-external hosts, foreign namespaces) and lack a
/// numeric port fall back to the caller's default — matching today's
/// behavior of "no port specified".
fn resolve_destination_port(
    object: &K8sObject,
    destination: &Value,
    host: &str,
    acc: &K8sAccumulator,
) -> Result<Option<u16>, K8sTranslateError> {
    let Some(port_value) = destination.get("port") else {
        return Ok(None);
    };
    if let Some(numeric) = port_value.get("number") {
        return optional_port_field(object, Some(numeric), "route.destination.port.number");
    }
    let Some(name) = string_field(port_value, "name") else {
        return Ok(None);
    };
    let cluster_domain = &acc.options.cluster_domain;
    let Some((svc, ns)) = service_host_components(host, &object.metadata.namespace, cluster_domain)
    else {
        return Err(invalid_resource(
            object,
            format!(
                "VirtualService route.destination.host '{}' is not a recognized in-cluster service form; \
                 port.name resolution only supports <svc>, <svc>.<ns>, <svc>.<ns>.svc, or \
                 <svc>.<ns>.svc.{} (optional trailing dot)",
                host, cluster_domain
            ),
        ));
    };
    match acc.lookup_service_port(ns, svc, name) {
        Some(port) => Ok(Some(port)),
        None => Err(invalid_resource(
            object,
            format!(
                "VirtualService route.destination.port.name '{}' did not match any port on Service {}/{}",
                name, ns, svc
            ),
        )),
    }
}

/// Parse an Istio destination host into `(service_name, namespace)` as borrowed
/// slices of either `host` or `default_namespace` — no allocation.
///
/// Accepted shapes (all may carry an optional trailing `.` root anchor):
///   - `<svc>` — short form; inherits the caller's default namespace
///   - `<svc>.<ns>` — two-label form
///   - `<svc>.<ns>.svc` — three-label form (final label MUST be `svc`)
///   - `<svc>.<ns>.svc.<cluster_domain>` — FQDN form (cluster_domain is
///     configurable via `FERRUM_K8S_CLUSTER_DOMAIN`, default `cluster.local`)
///
/// Any other shape — including external hosts (`api.example.com`), foreign
/// FQDNs (`foo.bar.tld.invalid`), partial suffixes (`<svc>.<ns>.cluster.local`,
/// `<svc>.<ns>.svc.cluster`), or hosts whose FQDN suffix doesn't match the
/// configured cluster domain — returns `None`. Empty labels (leading/trailing
/// dots that aren't the root anchor, consecutive dots) are also rejected.
/// Callers MUST treat `None` as "this host is not a Kubernetes service
/// reference" and surface a clear error instead of attempting a service lookup.
fn service_host_components<'a>(
    host: &'a str,
    default_namespace: &'a str,
    cluster_domain: &str,
) -> Option<(&'a str, &'a str)> {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    // Reject empty strings, leading/trailing dots, and consecutive dots in one
    // pass over the borrowed slice — avoids the Vec<&str> allocation the old
    // `split('.').collect()` + `any(empty)` shape required.
    if trimmed.is_empty()
        || trimmed.starts_with('.')
        || trimmed.ends_with('.')
        || trimmed.contains("..")
    {
        return None;
    }
    // Limit to four splits: <svc>.<ns>.svc.<domain-rest>. The fourth split
    // captures the entire cluster-domain suffix verbatim so we can compare it
    // against `cluster_domain` with `eq_ignore_ascii_case` and no `join(".")`.
    let mut labels = trimmed.splitn(4, '.');
    let svc = labels.next()?;
    let Some(ns) = labels.next() else {
        return Some((svc, default_namespace));
    };
    let Some(third) = labels.next() else {
        return Some((svc, ns));
    };
    if third != "svc" {
        return None;
    }
    let Some(domain) = labels.next() else {
        return Some((svc, ns));
    };
    if domain.eq_ignore_ascii_case(cluster_domain) {
        Some((svc, ns))
    } else {
        None
    }
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

/// Extract Istio VirtualService `http[].retries` into a Ferrum [`RetryConfig`].
///
/// Maps:
///   - `retries.attempts` -> `max_retries`
///   - `retries.retryOn` -> `retryable_status_codes` (from `5xx`, `gateway-error`,
///     or bare numeric codes) and `retry_on_connect_failure` (from `connect-failure`,
///     `reset`, `refused-stream`)
///
/// Returns `None` when no `retries` block is present or when `attempts` is zero.
fn route_retry_config(http: &Value) -> Option<RetryConfig> {
    let retries = http.get("retries")?;
    let attempts = retries.get("attempts").and_then(Value::as_u64).unwrap_or(0);
    if attempts == 0 {
        return None;
    }

    let mut retry = RetryConfig {
        max_retries: attempts.min(u64::from(u32::MAX)) as u32,
        ..RetryConfig::default()
    };

    if let Some(retry_on) = string_field(retries, "retryOn") {
        let mut status_codes = Vec::new();
        let mut connect_failure = false;

        for token in retry_on.split(',').map(str::trim) {
            match token {
                "5xx" => {
                    status_codes.extend(500..=599);
                }
                "retriable-status-codes" => {
                    status_codes.extend(retriable_status_codes(retries));
                }
                "connect-failure" | "reset" | "refused-stream" => {
                    connect_failure = true;
                }
                "gateway-error" => {
                    status_codes.extend_from_slice(&[502, 503, 504]);
                }
                other => {
                    if let Ok(code @ 100..=599) = other.parse::<u16>() {
                        status_codes.push(code);
                    }
                }
            }
        }

        status_codes.sort_unstable();
        status_codes.dedup();
        if !status_codes.is_empty() {
            retry.retryable_status_codes = status_codes;
        }
        retry.retry_on_connect_failure = connect_failure;
    }

    Some(retry)
}

fn retriable_status_codes(retries: &Value) -> impl Iterator<Item = u16> + '_ {
    retries
        .get("retriableStatusCodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .filter(|code| (100..=599).contains(code))
        .map(|code| code as u16)
}

fn route_timeout_ms(http: &Value) -> Option<u64> {
    let raw = string_field(http, "timeout")?;
    parse_istio_duration_ms(raw)
}

fn parse_istio_duration_secs(raw: &str) -> Option<u64> {
    parse_istio_duration_ms(raw).map(|ms| if ms == 0 { 0 } else { ms.div_ceil(1000) })
}

pub(super) fn path_match(uri: &Value) -> Option<String> {
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
            let provider = telemetry_tracing_provider(object, t)?;
            Ok::<_, K8sTranslateError>(MeshTracingConfig {
                sampling_percentage: sampling,
                custom_tags,
                custom_header_tags,
                provider,
            })
        })
        .transpose()?;

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

/// Extract the first `tracing[].providers[]` entry as a [`TracingProvider`].
///
/// Mirrors Istio's Telemetry CRD: `providers[]` is a list of named provider
/// references. Today we surface only the first entry; multi-provider fan-out
/// is deferred.
///
/// Istio's standard provider model defines providers once at the mesh-config
/// level (`meshConfig.extensionProviders`) and references them by name from
/// Telemetry resources. This translator supports **inline** provider config
/// only (provider type inferred from `name`, required fields on the entry
/// itself). Name-only references (`{name: "my-zipkin"}` with no inline
/// fields) and unrecognised provider names are gracefully skipped with a
/// warning — `meshConfig.extensionProviders` lookup is deferred.
fn telemetry_tracing_provider(
    object: &K8sObject,
    tracing_entry: &Value,
) -> Result<Option<TracingProvider>, K8sTranslateError> {
    let Some(providers) = tracing_entry.get("providers").and_then(Value::as_array) else {
        return Ok(None);
    };
    let Some(first) = providers.first() else {
        return Ok(None);
    };
    if providers.len() > 1 {
        tracing::warn!(
            resource = %object.metadata.name,
            namespace = %object.metadata.namespace,
            count = providers.len(),
            "Telemetry tracing.providers[] has multiple entries; only the first is surfaced (multi-provider fan-out is deferred)"
        );
    }
    let name = first
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_resource(object, "Telemetry tracing.providers[].name is required"))?
        .trim();
    if name.is_empty() {
        return Err(invalid_resource(
            object,
            "Telemetry tracing.providers[].name must not be empty",
        ));
    }
    let is_reference_only = first
        .as_object()
        .map(|obj| obj.keys().all(|k| k == "name"))
        .unwrap_or(false);
    if is_reference_only {
        tracing::warn!(
            resource = %object.metadata.name,
            namespace = %object.metadata.namespace,
            provider_name = name,
            "Telemetry tracing.providers[] entry is a name-only reference \
             (no inline config fields); meshConfig.extensionProviders lookup \
             is not yet supported — provider skipped"
        );
        return Ok(None);
    }
    let provider = match name {
        "zipkin" => {
            let url = telemetry_provider_string_field(object, first, "zipkin", "url")?;
            TracingProvider::Zipkin { url }
        }
        "datadog" => {
            let agent_url = telemetry_provider_string_field_aliased(
                object,
                first,
                "datadog",
                "agentUrl",
                &["agent_url"],
            )?;
            let service = first
                .get("service")
                .and_then(Value::as_str)
                .map(str::to_string);
            TracingProvider::Datadog { agent_url, service }
        }
        "lightstep" => {
            let collector_url = telemetry_provider_string_field_aliased(
                object,
                first,
                "lightstep",
                "collectorUrl",
                &["collector_url"],
            )?;
            let access_token = telemetry_provider_string_field_aliased(
                object,
                first,
                "lightstep",
                "accessToken",
                &["access_token"],
            )?;
            TracingProvider::Lightstep {
                collector_url,
                access_token,
            }
        }
        "opentelemetry" => {
            let endpoint =
                telemetry_provider_string_field(object, first, "opentelemetry", "endpoint")?;
            TracingProvider::OpenTelemetry { endpoint }
        }
        other => {
            tracing::warn!(
                resource = %object.metadata.name,
                namespace = %object.metadata.namespace,
                provider_name = other,
                "Telemetry tracing.providers[] name '{other}' is not a recognised \
                 inline provider type (supported: zipkin/datadog/lightstep/opentelemetry); \
                 if this references a meshConfig.extensionProviders entry, that lookup \
                 is not yet supported — provider skipped"
            );
            return Ok(None);
        }
    };
    Ok(Some(provider))
}

fn telemetry_provider_string_field(
    object: &K8sObject,
    entry: &Value,
    provider_name: &str,
    field: &str,
) -> Result<String, K8sTranslateError> {
    telemetry_provider_string_field_aliased(object, entry, provider_name, field, &[])
}

/// Read a required string field, trying the canonical (camelCase) name first
/// then any provided aliases. Non-empty after trim is required. The returned
/// value is trimmed so stray whitespace in CRDs (e.g. `"url": " http://zipkin:9411 "`)
/// does not propagate into pool keys, DNS resolvers, or URL parsers downstream.
fn telemetry_provider_string_field_aliased(
    object: &K8sObject,
    entry: &Value,
    provider_name: &str,
    field: &str,
    aliases: &[&str],
) -> Result<String, K8sTranslateError> {
    std::iter::once(field)
        .chain(aliases.iter().copied())
        .find_map(|name| {
            entry
                .get(name)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .ok_or_else(|| {
            invalid_resource(
                object,
                format!(
                    "Telemetry tracing.providers[] '{provider_name}' is missing required field '{field}'"
                ),
            )
        })
}

/// Translate an Istio `ProxyConfig` (`networking.istio.io/v1beta1`) CRD into a
/// [`MeshProxyConfig`].
///
/// ProxyConfig fields are config-time only — they shape the data plane's
/// startup posture (concurrency, image) and tracing sampling but do not
/// affect the request path. Fields:
///
/// - `metadata.name` -> `name`
/// - `metadata.namespace` -> `namespace`
/// - `spec.selector` + root-namespace rule -> [`PolicyScope`] (via
///   [`istio_policy_scope`]). A ProxyConfig in the Istio root namespace
///   with no selector applies mesh-wide; with a selector it applies to
///   matching workloads across the mesh. In any other namespace, no
///   selector means namespace-default and a selector narrows further.
/// - `spec.concurrency` -> `concurrency` (rejected as invalid if outside
///   `u32` range)
/// - `spec.image.imageType` -> `image` (informational)
/// - `spec.environmentVariables` -> `environment`
/// - `spec.tracing.sampling` -> `tracing_sampling` (percentage 0-100,
///   merged into `workload_metrics.sampling_percentage` at slice-apply time)
fn proxy_config(
    options: &K8sTranslationOptions,
    object: &K8sObject,
) -> Result<MeshProxyConfig, K8sTranslateError> {
    let scope = istio_policy_scope(options, object, object.spec.get("selector"));

    let concurrency = match object.spec.get("concurrency") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let raw = value.as_u64().ok_or_else(|| {
                invalid_resource(
                    object,
                    format!(
                        "ProxyConfig spec.concurrency must be a non-negative integer (got {value})"
                    ),
                )
            })?;
            Some(u32::try_from(raw).map_err(|_| {
                invalid_resource(
                    object,
                    format!(
                        "ProxyConfig spec.concurrency must fit in u32 (0..={}), got {raw}",
                        u32::MAX
                    ),
                )
            })?)
        }
    };

    let image = object
        .spec
        .get("image")
        .and_then(|img| img.get("imageType"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    let environment = object
        .spec
        .get("environmentVariables")
        .map(string_map)
        .unwrap_or_default();

    let tracing_sampling = object
        .spec
        .get("tracing")
        .and_then(|tracing| tracing.get("sampling"))
        .and_then(Value::as_f64);

    Ok(MeshProxyConfig {
        name: object.metadata.name.clone(),
        namespace: object.metadata.namespace.clone(),
        scope,
        concurrency,
        image,
        environment,
        tracing_sampling,
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
            apply_status_code_comparison(&mut filter, val)?;
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
                    merge_min_latency_ms(&mut filter.min_latency_ms, n)?;
                }
                Comparison::Gt(n) => {
                    merge_min_latency_ms(&mut filter.min_latency_ms, comparison_increment(n)?)?;
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

fn apply_status_code_comparison(
    filter: &mut AccessLogFilter,
    comparison: Comparison,
) -> Result<(), String> {
    match comparison {
        Comparison::Gte(n) => merge_status_code_min(&mut filter.status_code_min, n)?,
        Comparison::Gt(n) => {
            merge_status_code_min(&mut filter.status_code_min, comparison_increment(n)?)?
        }
        Comparison::Lte(n) => merge_status_code_max(&mut filter.status_code_max, n)?,
        Comparison::Lt(n) => {
            merge_status_code_max(&mut filter.status_code_max, comparison_decrement(n)?)?
        }
        Comparison::Eq(n) => {
            merge_status_code_min(&mut filter.status_code_min, n)?;
            merge_status_code_max(&mut filter.status_code_max, n)?;
        }
    }
    Ok(())
}

fn merge_status_code_min(current: &mut Option<u16>, value: i64) -> Result<(), String> {
    let value = status_code_value(value)?;
    *current = Some(current.map_or(value, |existing| existing.max(value)));
    Ok(())
}

fn merge_status_code_max(current: &mut Option<u16>, value: i64) -> Result<(), String> {
    let value = status_code_value(value)?;
    *current = Some(current.map_or(value, |existing| existing.min(value)));
    Ok(())
}

fn merge_min_latency_ms(current: &mut Option<u64>, value: i64) -> Result<(), String> {
    let value = duration_value(value)?;
    *current = Some(current.map_or(value, |existing| existing.max(value)));
    Ok(())
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
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
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

    fn proxy_has_plugin(proxy: &Proxy, plugin: &PluginConfig) -> bool {
        proxy
            .plugins
            .iter()
            .any(|assoc| assoc.plugin_config_id == plugin.id)
    }

    fn object(kind: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: "security.istio.io/v1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: "sample".to_string(),
                namespace: "default".to_string(),
                labels: HashMap::new(),
                deletion_timestamp: None,
            },
            spec,
            status: Value::Object(serde_json::Map::new()),
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
                        "to": [{"operation": {"someUnsupportedField": ["foo"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("unsupported operation fields must fail closed");

        assert!(
            err.to_string()
                .contains("rules[].to[].operation.someUnsupportedField")
        );
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn translates_authorization_policy_negative_match_fields() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "selector": {"matchLabels": {"app": "api"}},
            "rules": [{
                "to": [{"operation": {
                    "methods": ["GET"],
                    "notMethods": ["POST", "DELETE"],
                    "notPaths": ["/admin/*"],
                    "notHosts": ["evil.example.com"],
                    "notPorts": ["8080"]
                }}]
            }]
        }));

        assert_eq!(policy.rules.len(), 1);
        let operation = &policy.rules[0].to[0];
        assert_eq!(operation.methods, vec!["GET".to_string()]);
        assert_eq!(
            operation.not_methods,
            vec!["POST".to_string(), "DELETE".to_string()]
        );
        assert_eq!(operation.not_paths, vec!["/admin/*".to_string()]);
        // Host is normalised to ASCII-lowercase at config-load time.
        assert_eq!(operation.not_hosts, vec!["evil.example.com".to_string()]);
        assert_eq!(operation.not_ports, vec![8080]);
    }

    #[test]
    fn negative_match_operation_alone_is_constrained() {
        // An operation that has ONLY negative-match fields is still a
        // constraint — the translator must not collapse it to "any".
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "selector": {"matchLabels": {"app": "api"}},
            "rules": [{
                "to": [{"operation": {"notMethods": ["POST"]}}]
            }]
        }));

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].to.len(), 1);
        assert_eq!(policy.rules[0].to[0].not_methods, vec!["POST".to_string()]);
        assert!(policy.rules[0].to[0].methods.is_empty());
    }

    #[test]
    fn rejects_authorization_policy_not_ports_wildcard_pattern() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"notPorts": ["8*"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("wildcard notPorts patterns must fail closed");

        assert!(err.to_string().contains("notPorts"));
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn rejects_authorization_policy_not_ports_outside_kubernetes_range() {
        let err = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "rules": [{
                        "to": [{"operation": {"notPorts": ["70000"]}}]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("invalid notPorts must fail closed");

        assert!(err.to_string().contains("rules[].to[].operation.notPorts"));
        assert!(err.to_string().contains("70000"));
    }

    #[test]
    fn authorization_policy_negative_match_round_trip_decision() {
        // ALLOW with methods=[GET] AND notPaths=[/admin/*]:
        // - GET /api allowed (positive method match, negative path mismatch)
        // - GET /admin/users denied (positive method match BUT negative path matches → rule fails → implicit deny)
        // - POST /api denied (positive method does not match → implicit deny)
        let result = translate_k8s_objects(
            &[object(
                "AuthorizationPolicy",
                serde_json::json!({
                    "action": "ALLOW",
                    "selector": {"matchLabels": {"app": "api"}},
                    "rules": [{
                        "to": [{"operation": {
                            "methods": ["GET"],
                            "notPaths": ["/admin/*"]
                        }}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let slice = MeshSlice {
            mesh_policies: mesh.mesh_policies,
            ..MeshSlice::default()
        };

        let get_api = MeshAuthzRequest {
            method: Some("GET".to_string()),
            path: Some("/api/items".to_string()),
            ..MeshAuthzRequest::default()
        };
        let get_admin = MeshAuthzRequest {
            method: Some("GET".to_string()),
            path: Some("/admin/users".to_string()),
            ..MeshAuthzRequest::default()
        };
        let post_api = MeshAuthzRequest {
            method: Some("POST".to_string()),
            path: Some("/api/items".to_string()),
            ..MeshAuthzRequest::default()
        };

        assert_eq!(
            evaluate_mesh_authorization(&slice, &get_api),
            MeshAuthzDecision::Allow
        );
        assert!(matches!(
            evaluate_mesh_authorization(&slice, &get_admin),
            MeshAuthzDecision::Deny { .. }
        ));
        assert!(matches!(
            evaluate_mesh_authorization(&slice, &post_api),
            MeshAuthzDecision::Deny { .. }
        ));
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
    fn root_namespace_peer_authentication_without_selector_is_mesh_wide() {
        let mut peer_auth = object(
            "PeerAuthentication",
            serde_json::json!({
                "mtls": {"mode": "STRICT"}
            }),
        );
        peer_auth.metadata.namespace = "istio-config".to_string();

        let result = translate_k8s_objects(
            &[peer_auth],
            options_for_namespace("istio-config")
                .with_istio_root_namespace("istio-config".to_string()),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert!(matches!(
            mesh.peer_authentications[0].scope,
            Some(PolicyScope::MeshWide)
        ));
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
        assert_eq!(workload.service_account.as_deref(), Some("api"));
    }

    #[test]
    fn workload_entry_cross_namespace_service_host_fails_closed() {
        let err = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "service": "reviews.prod.svc.cluster.local"
                }),
            )],
            options(),
        )
        .expect_err("cross-namespace WorkloadEntry service host must fail closed");

        let err = err.to_string();
        assert!(
            err.contains("WorkloadEntry.service"),
            "error should mention WorkloadEntry.service: {err}"
        );
        assert!(
            err.contains("reviews.prod.svc.cluster.local"),
            "error should include the offending host: {err}"
        );
        assert!(
            err.contains("cross-namespace"),
            "error should identify the unsupported cross-namespace reference: {err}"
        );
    }

    #[test]
    fn workload_entry_two_label_cross_namespace_service_host_fails_closed() {
        let mut prod_service = object(
            "Service",
            serde_json::json!({
                "ports": [{"port": 80}]
            }),
        );
        prod_service.metadata.name = "reviews".to_string();
        prod_service.metadata.namespace = "prod".to_string();
        let err = translate_k8s_objects(
            &[
                prod_service,
                object(
                    "WorkloadEntry",
                    serde_json::json!({
                        "address": "10.0.1.5",
                        "service": "reviews.prod"
                    }),
                ),
            ],
            options().with_source_namespaces(Vec::new()),
        )
        .expect_err("two-label cross-namespace WorkloadEntry service host must fail closed");

        let err = err.to_string();
        assert!(
            err.contains("WorkloadEntry.service"),
            "error should mention WorkloadEntry.service: {err}"
        );
        assert!(
            err.contains("reviews.prod"),
            "error should include the offending host: {err}"
        );
        assert!(
            err.contains("cross-namespace"),
            "error should identify the unsupported cross-namespace reference: {err}"
        );
    }

    #[test]
    fn workload_entry_two_label_dns_service_name_is_preserved() {
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "service": "example.com"
                }),
            )],
            options(),
        )
        .expect("two-label DNS WorkloadEntry service should remain valid");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads[0].service_name, "example.com");
    }

    #[test]
    fn workload_entry_weight_and_locality_translate() {
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "serviceAccount": "api",
                    "weight": 42,
                    "locality": "us-west-2/us-west-2a/sub-a"
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let workload = &mesh.workloads[0];
        assert_eq!(workload.weight, Some(42));
        assert_eq!(
            workload.locality.as_deref(),
            Some("us-west-2/us-west-2a/sub-a")
        );
    }

    #[test]
    fn workload_entry_weight_above_max_target_weight_fails_closed() {
        let err = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "weight": 70_000
                }),
            )],
            options(),
        )
        .expect_err("weight exceeds MAX_TARGET_WEIGHT must fail");
        assert!(
            err.to_string().contains("WorkloadEntry.weight"),
            "error should mention WorkloadEntry.weight: {err}"
        );
    }

    #[test]
    fn workload_entry_omitted_optionals_are_none() {
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5"
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let mesh = result.config.mesh.expect("mesh config");
        let workload = &mesh.workloads[0];
        assert!(workload.weight.is_none());
        assert!(workload.locality.is_none());
        assert!(workload.service_account.is_none());
        // SPIFFE still falls back to "default" SA for SVID issuance.
        assert!(workload.spiffe_id.as_str().ends_with("/sa/default"));
    }

    #[test]
    fn workload_entry_weight_zero_is_accepted() {
        // Istio uses `weight: 0` to mean "drain / no traffic". The translator
        // must not reject it; the runtime LB layer is responsible for
        // interpreting the value once locality-aware routing is wired.
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "weight": 0
                }),
            )],
            options(),
        )
        .expect("weight=0 must translate");
        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.workloads[0].weight, Some(0));
    }

    #[test]
    fn workload_entry_empty_service_account_falls_back_to_default() {
        // Istio treats missing OR empty `serviceAccount` as `"default"` for
        // SVID issuance. The translator must not surface the SPIFFE parser's
        // trailing-slash error to operators when YAML serialization yields
        // `serviceAccount: ""`.
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "serviceAccount": ""
                }),
            )],
            options(),
        )
        .expect("empty serviceAccount must translate");
        let mesh = result.config.mesh.expect("mesh config");
        let workload = &mesh.workloads[0];
        assert!(workload.service_account.is_none());
        assert!(workload.spiffe_id.as_str().ends_with("/sa/default"));
    }

    #[test]
    fn workload_entry_empty_locality_collapses_to_none() {
        // Empty-string locality is operator intent for "unset"; downstream
        // consumers should not have to special-case it.
        let result = translate_k8s_objects(
            &[object(
                "WorkloadEntry",
                serde_json::json!({
                    "address": "10.0.1.5",
                    "locality": ""
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let mesh = result.config.mesh.expect("mesh config");
        assert!(mesh.workloads[0].locality.is_none());
    }

    #[test]
    fn workload_entry_locality_is_free_form() {
        // The translator stores `locality` verbatim — it does not validate the
        // `region/zone/subzone` slash convention. Locality-aware routing (when
        // wired) is responsible for any parsing.
        for raw in [
            "us-west-2/us-west-2a/sub-a",
            "us-west-2/us-west-2a",
            "us-west-2",
            "single-token-no-slashes",
            "//empty/region",
        ] {
            let result = translate_k8s_objects(
                &[object(
                    "WorkloadEntry",
                    serde_json::json!({
                        "address": "10.0.1.5",
                        "locality": raw
                    }),
                )],
                options(),
            )
            .unwrap_or_else(|e| panic!("locality {raw:?} must translate: {e}"));
            let mesh = result.config.mesh.expect("mesh config");
            assert_eq!(
                mesh.workloads[0].locality.as_deref(),
                Some(raw),
                "locality must be stored verbatim",
            );
        }
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
    fn request_authentication_rejects_malformed_from_headers() {
        let err = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "issuer": "https://accounts.google.com",
                        "jwksUri": "https://www.googleapis.com/oauth2/v3/certs",
                        "fromHeaders": [
                            {"prefix": "Bearer "}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("malformed fromHeaders should fail translation");

        assert!(
            err.to_string()
                .contains("RequestAuthentication jwtRules[].fromHeaders[0].name is required")
        );
    }

    #[test]
    fn request_authentication_rejects_malformed_from_header_prefix() {
        let err = translate_k8s_objects(
            &[object(
                "RequestAuthentication",
                serde_json::json!({
                    "jwtRules": [{
                        "issuer": "https://accounts.google.com",
                        "jwksUri": "https://www.googleapis.com/oauth2/v3/certs",
                        "fromHeaders": [
                            {"name": "Authorization", "prefix": 42}
                        ]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("malformed fromHeaders prefix should fail translation");

        assert!(
            err.to_string().contains(
                "RequestAuthentication jwtRules[].fromHeaders[0].prefix must be a string"
            )
        );
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
    fn telemetry_access_log_repeated_status_predicates_intersect() {
        let filter =
            parse_access_log_filter_expression("response.code >= 500 && response.code >= 400")
                .expect("filter parses")
                .expect("filter is present");

        assert_eq!(filter.status_code_min, Some(500));
        assert_eq!(filter.status_code_max, None);

        let filter =
            parse_access_log_filter_expression("response.code <= 599 && response.code <= 499")
                .expect("filter parses")
                .expect("filter is present");

        assert_eq!(filter.status_code_min, None);
        assert_eq!(filter.status_code_max, Some(499));
    }

    #[test]
    fn telemetry_access_log_repeated_duration_predicates_intersect() {
        let filter = parse_access_log_filter_expression(
            "response.duration >= 1000 && response.duration >= 500",
        )
        .expect("filter parses")
        .expect("filter is present");

        assert_eq!(filter.min_latency_ms, Some(1000));
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
    fn telemetry_tracing_zipkin_provider_translates() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "zipkin",
                            "url": "http://zipkin.istio-system:9411/api/v2/spans"
                        }]
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
        match tracing.provider.as_ref().expect("provider translated") {
            TracingProvider::Zipkin { url } => {
                assert_eq!(url, "http://zipkin.istio-system:9411/api/v2/spans");
            }
            other => panic!("expected Zipkin, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_datadog_provider_translates() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "datadog",
                            "agentUrl": "http://datadog-agent:8126",
                            "service": "reviews"
                        }]
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
        match tracing.provider.as_ref().expect("provider translated") {
            TracingProvider::Datadog { agent_url, service } => {
                assert_eq!(agent_url, "http://datadog-agent:8126");
                assert_eq!(service.as_deref(), Some("reviews"));
            }
            other => panic!("expected Datadog, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_datadog_snake_case_alias_still_accepted() {
        // Backward compat: operators who wrote against the first draft used
        // `agent_url`. The translator accepts both spellings so manifests
        // captured before the camelCase canonicalisation keep working.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "datadog",
                            "agent_url": "http://datadog-agent:8126"
                        }]
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
        match tracing.provider.as_ref().expect("provider translated") {
            TracingProvider::Datadog { agent_url, service } => {
                assert_eq!(agent_url, "http://datadog-agent:8126");
                assert!(service.is_none(), "service omitted in manifest");
            }
            other => panic!("expected Datadog, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_datadog_missing_agent_url_fails_closed() {
        let err = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "datadog",
                            "service": "reviews"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect_err("missing required field should fail closed");

        let msg = err.to_string();
        assert!(
            msg.contains("datadog"),
            "error must mention provider: {msg}"
        );
        assert!(
            msg.contains("agentUrl"),
            "error must mention missing field: {msg}"
        );
    }

    #[test]
    fn telemetry_tracing_lightstep_provider_translates() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "lightstep",
                            "collectorUrl": "https://ingest.lightstep.com:443",
                            "accessToken": "secret-token"
                        }]
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
        match tracing.provider.as_ref().expect("provider translated") {
            TracingProvider::Lightstep {
                collector_url,
                access_token,
            } => {
                assert_eq!(collector_url, "https://ingest.lightstep.com:443");
                assert_eq!(access_token, "secret-token");
            }
            other => panic!("expected Lightstep, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_opentelemetry_provider_translates() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "opentelemetry",
                            "endpoint": "http://otel-collector.istio-system:4317"
                        }]
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
        match tracing.provider.as_ref().expect("provider translated") {
            TracingProvider::OpenTelemetry { endpoint } => {
                assert_eq!(endpoint, "http://otel-collector.istio-system:4317");
            }
            other => panic!("expected OpenTelemetry, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_without_providers_block_has_no_provider() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "randomSamplingPercentage": 25.0
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
        assert_eq!(tracing.sampling_percentage, Some(25.0));
        assert!(
            tracing.provider.is_none(),
            "providers omitted, provider should be None"
        );
    }

    #[test]
    fn telemetry_tracing_unknown_provider_name_gracefully_skipped() {
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "stackdriver",
                            "endpoint": "https://example.com"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("unknown provider name should not fail translation");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert!(
            tracing.provider.is_none(),
            "unrecognised provider name should be skipped, not surfaced"
        );
    }

    #[test]
    fn telemetry_tracing_name_only_reference_gracefully_skipped() {
        // Standard Istio pattern: providers[].name references a
        // meshConfig.extensionProviders entry with no inline fields.
        // Since extensionProviders lookup is deferred, the translator
        // should gracefully skip these rather than failing.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "zipkin"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("name-only reference should not fail translation");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert!(
            tracing.provider.is_none(),
            "name-only reference should be skipped (extensionProviders lookup deferred)"
        );
    }

    #[test]
    fn telemetry_tracing_custom_extension_provider_name_gracefully_skipped() {
        // Custom extensionProvider names like "my-zipkin" are valid Istio
        // references but not one of the four inline provider types.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "my-zipkin"
                        }]
                    }]
                }),
            )],
            options(),
        )
        .expect("custom provider name should not fail translation");

        let mesh = result.config.mesh.expect("mesh config");
        let tracing = mesh.telemetry_resources[0]
            .config
            .tracing
            .as_ref()
            .expect("tracing config");
        assert!(
            tracing.provider.is_none(),
            "custom extensionProvider reference should be skipped"
        );
    }

    #[test]
    fn telemetry_tracing_multiple_providers_takes_first() {
        // Istio's Telemetry CRD allows `providers[]` to list multiple entries.
        // Multi-provider fan-out is deferred; today we surface only the first
        // entry. This test pins that behavior so the limitation cannot drift
        // silently as later providers (Stackdriver/SkyWalking) are added — a
        // future change that needs to surface every entry should also update
        // this test.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [
                            {
                                "name": "zipkin",
                                "url": "http://zipkin.istio-system:9411/api/v2/spans"
                            },
                            {
                                "name": "datadog",
                                "agentUrl": "http://datadog-agent:8126"
                            }
                        ]
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
        match tracing.provider.as_ref().expect("provider translated") {
            TracingProvider::Zipkin { url } => {
                assert_eq!(url, "http://zipkin.istio-system:9411/api/v2/spans");
            }
            other => panic!("expected first-entry Zipkin, got {other:?}"),
        }
    }

    #[test]
    fn telemetry_tracing_provider_without_sampling_still_surfaces() {
        // Provider configuration is independent from sampling. A Telemetry
        // block with only `providers[]` (no `randomSamplingPercentage`)
        // should still surface the provider — sampling is allowed to come
        // from a less-specific Telemetry resource via merge_tracing_config.
        let result = translate_k8s_objects(
            &[object(
                "Telemetry",
                serde_json::json!({
                    "tracing": [{
                        "providers": [{
                            "name": "zipkin",
                            "url": "http://zipkin.istio-system:9411/api/v2/spans"
                        }]
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
        assert!(
            tracing.sampling_percentage.is_none(),
            "sampling omitted in manifest"
        );
        assert!(
            tracing.provider.is_some(),
            "provider should surface independently of sampling"
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

    // ── DestinationRule ────────────────────────────────────────────────

    #[test]
    fn translates_destination_rule_connection_pool() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {
                                "connectTimeout": "5s"
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.destination_rules.len(), 1);
        let dr = &mesh.destination_rules[0];
        assert_eq!(dr.host, "reviews.default.svc.cluster.local");
        let tp = dr.traffic_policy.as_ref().expect("traffic policy");
        assert_eq!(tp.connect_timeout_ms, Some(5000));
    }

    #[test]
    fn translates_destination_rule_outlier_detection() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "outlierDetection": {
                            "consecutive5xxErrors": 5,
                            "interval": "10s",
                            "baseEjectionTime": "30s",
                            "maxEjectionPercent": 50
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let od = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .outlier_detection
            .as_ref()
            .expect("outlier detection");
        assert_eq!(od.consecutive_errors, Some(5));
        assert_eq!(od.interval_seconds, Some(10));
        assert_eq!(od.base_ejection_seconds, Some(30));
        assert_eq!(od.max_ejection_percent, Some(50));
    }

    #[test]
    fn translates_destination_rule_lb_round_robin() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "simple": "ROUND_ROBIN"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        assert!(matches!(
            lb,
            MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin)
        ));
    }

    #[test]
    fn translates_destination_rule_lb_least_request() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "simple": "LEAST_REQUEST"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        assert!(matches!(
            lb,
            MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)
        ));
    }

    #[test]
    fn translates_destination_rule_lb_random() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "simple": "RANDOM"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        assert!(matches!(lb, MeshLoadBalancer::Simple(MeshSimpleLb::Random)));
    }

    #[test]
    fn translates_destination_rule_consistent_hash_header() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "consistentHash": {
                                "httpHeaderName": "x-user-id"
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        match lb {
            MeshLoadBalancer::ConsistentHash(ch) => {
                assert_eq!(ch.http_header_name.as_deref(), Some("x-user-id"));
                assert!(!ch.use_source_ip);
            }
            _ => panic!("expected consistent hash"),
        }
    }

    #[test]
    fn translates_destination_rule_consistent_hash_source_ip() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "consistentHash": {
                                "useSourceIp": true
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        match lb {
            MeshLoadBalancer::ConsistentHash(ch) => {
                assert!(ch.use_source_ip);
            }
            _ => panic!("expected consistent hash"),
        }
    }

    #[test]
    fn translates_destination_rule_subsets() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "subsets": [
                        {
                            "name": "v1",
                            "labels": {"version": "v1"}
                        },
                        {
                            "name": "v2",
                            "labels": {"version": "v2"},
                            "trafficPolicy": {
                                "loadBalancer": {"simple": "RANDOM"}
                            }
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.destination_rules[0].subsets.len(), 2);
        assert_eq!(mesh.destination_rules[0].subsets[0].name, "v1");
        assert_eq!(
            mesh.destination_rules[0].subsets[0].labels.get("version"),
            Some(&"v1".to_string())
        );
        assert!(
            mesh.destination_rules[0].subsets[0]
                .traffic_policy
                .is_none()
        );
        assert_eq!(mesh.destination_rules[0].subsets[1].name, "v2");
        assert!(
            mesh.destination_rules[0].subsets[1]
                .traffic_policy
                .is_some()
        );
    }

    #[test]
    fn destination_rule_rejects_missing_host() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "trafficPolicy": {
                        "loadBalancer": {"simple": "RANDOM"}
                    }
                }),
            )],
            options(),
        )
        .expect_err("missing host must fail");

        assert!(err.to_string().contains("requires spec.host"));
    }

    #[test]
    fn destination_rule_rejects_unsupported_lb() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {"simple": "MAGLEV"}
                    }
                }),
            )],
            options(),
        )
        .expect_err("unsupported LB must fail");

        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn destination_rule_rejects_outlier_ejection_percent_above_100() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "outlierDetection": {
                            "maxEjectionPercent": 101
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("invalid max ejection percent must fail");

        assert!(
            err.to_string()
                .contains("outlierDetection.maxEjectionPercent must be 0-100")
        );
    }

    #[test]
    fn destination_rule_rejects_subset_without_name() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "subsets": [{"labels": {"version": "v1"}}]
                }),
            )],
            options(),
        )
        .expect_err("subset without name must fail");

        assert!(err.to_string().contains("subset requires a name"));
    }

    #[test]
    fn destination_rule_no_warning_emitted() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local"
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("DestinationRule"))
        );
    }

    #[test]
    fn destination_rule_host_is_lowercased() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "Reviews.Default.SVC.Cluster.Local"
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(
            mesh.destination_rules[0].host,
            "reviews.default.svc.cluster.local"
        );
    }

    #[test]
    fn destination_rule_connect_timeout_ms_format() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "api.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "tcp": {
                                "connectTimeout": "100ms"
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tp = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy");
        assert_eq!(tp.connect_timeout_ms, Some(100));
    }

    #[test]
    fn destination_rule_rejects_empty_host() {
        let err = translate_k8s_objects(
            &[object("DestinationRule", serde_json::json!({"host": ""}))],
            options(),
        )
        .expect_err("empty host must fail");
        assert!(err.to_string().contains("non-empty hostname"));
    }

    #[test]
    fn destination_rule_rejects_dot_only_host() {
        let err = translate_k8s_objects(
            &[object("DestinationRule", serde_json::json!({"host": "."}))],
            options(),
        )
        .expect_err("dot-only host must fail");
        assert!(err.to_string().contains("non-empty hostname"));
    }

    #[test]
    fn destination_rule_lb_least_conn_alias_translates() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {"simple": "LEAST_CONN"}
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let mesh = result.config.mesh.expect("mesh config");
        let lb = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .load_balancer
            .as_ref()
            .expect("load balancer");
        assert!(matches!(
            lb,
            MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)
        ));
    }

    #[test]
    fn destination_rule_consistent_hash_rejects_multiple_options() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "consistentHash": {
                                "httpHeaderName": "x-user-id",
                                "useSourceIp": true
                            }
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("multi-option consistentHash must fail");
        assert!(err.to_string().contains("must set exactly one"));
    }

    #[test]
    fn destination_rule_consistent_hash_rejects_no_options() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "consistentHash": {}
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("empty consistentHash must fail");
        assert!(err.to_string().contains("requires one of"));
    }

    #[test]
    fn destination_rule_passthrough_emits_warning() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {"simple": "PASSTHROUGH"}
                    }
                }),
            )],
            options(),
        )
        .expect("PASSTHROUGH translates with warning");
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("PASSTHROUGH") && w.contains("ROUND_ROBIN")),
            "expected PASSTHROUGH approximation warning, got {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_subset_unsupported_fields_warn() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "subsets": [{
                        "name": "v1",
                        "labels": {"version": "v1"},
                        "trafficPolicy": {
                            "connectionPool": {"tcp": {"connectTimeout": "5s"}},
                            "outlierDetection": {"consecutive5xxErrors": 3}
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("subset with unsupported fields still translates");
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("subset 'v1'") && w.contains("connectTimeout")),
            "expected subset connectTimeout warning, got {:?}",
            result.warnings
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("subset 'v1'") && w.contains("outlierDetection")),
            "expected subset outlierDetection warning, got {:?}",
            result.warnings
        );
    }

    // -- VirtualService fault injection / retry / timeout ----------------

    #[test]
    fn virtual_service_extracts_fault_injection_abort() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percentage": {"value": 50.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.plugin_configs.len(), 1);
        let plugin = &result.config.plugin_configs[0];
        assert_eq!(plugin.plugin_name, "fault_injection");
        assert_eq!(
            plugin.proxy_id.as_deref(),
            Some(result.config.proxies[0].id.as_str())
        );
        let abort = plugin.config.get("abort").expect("abort config");
        assert_eq!(abort["status_code"], 503);
        assert_eq!(abort["percentage"], 50.0);
    }

    #[test]
    fn virtual_service_extracts_fault_injection_delay() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "delay": {
                                "fixedDelay": "5s",
                                "percentage": {"value": 25.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.plugin_configs.len(), 1);
        let plugin = &result.config.plugin_configs[0];
        assert_eq!(plugin.plugin_name, "fault_injection");
        let delay = plugin.config.get("delay").expect("delay config");
        assert_eq!(delay["duration_ms"], 5000);
        assert_eq!(delay["percentage"], 25.0);
    }

    #[test]
    fn virtual_service_extracts_fault_injection_abort_and_delay() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 500,
                                "percentage": {"value": 10.0}
                            },
                            "delay": {
                                "fixedDelay": "2s",
                                "percentage": {"value": 30.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        assert!(plugin.config.get("abort").is_some());
        assert!(plugin.config.get("delay").is_some());
        assert_eq!(plugin.config["abort"]["status_code"], 500);
        assert_eq!(plugin.config["delay"]["duration_ms"], 2000);
    }

    #[test]
    fn virtual_service_maps_retries_to_proxy_retry_config() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 3,
                            "retryOn": "5xx,connect-failure"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        let proxy = &result.config.proxies[0];
        let retry = proxy.retry.as_ref().expect("retry config should be set");
        assert_eq!(retry.max_retries, 3);
        assert!(retry.retry_on_connect_failure);
        assert!(retry.retryable_status_codes.contains(&500));
        assert!(retry.retryable_status_codes.contains(&502));
        assert!(retry.retryable_status_codes.contains(&503));
        assert!(retry.retryable_status_codes.contains(&504));
    }

    #[test]
    fn virtual_service_maps_gateway_error_retry_on() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 2,
                            "retryOn": "gateway-error"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0]
            .retry
            .as_ref()
            .expect("retry config");
        assert_eq!(retry.max_retries, 2);
        assert!(retry.retryable_status_codes.contains(&502));
        assert!(retry.retryable_status_codes.contains(&503));
        assert!(retry.retryable_status_codes.contains(&504));
        assert!(!retry.retryable_status_codes.contains(&500));
        assert!(!retry.retry_on_connect_failure);
    }

    #[test]
    fn virtual_service_retriable_status_codes_uses_explicit_codes() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 2,
                            "retryOn": "retriable-status-codes",
                            "retriableStatusCodes": [409, 425, 503, 700]
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0]
            .retry
            .as_ref()
            .expect("retry config");
        assert_eq!(retry.retryable_status_codes, vec![409, 425, 503]);
    }

    #[test]
    fn virtual_service_retry_5xx_covers_full_server_error_range() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 1,
                            "retryOn": "5xx"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0]
            .retry
            .as_ref()
            .expect("retry config");
        assert_eq!(retry.retryable_status_codes.len(), 100);
        assert!(retry.retryable_status_codes.contains(&500));
        assert!(retry.retryable_status_codes.contains(&599));
    }

    #[test]
    fn virtual_service_zero_retry_attempts_produces_no_retry_config() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {"attempts": 0}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.proxies[0].retry.is_none());
    }

    #[test]
    fn virtual_service_retries_without_retry_on_defaults_to_connect_retry() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 3
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0].retry.as_ref().expect("retry");
        assert_eq!(retry.max_retries, 3);
        assert!(retry.retry_on_connect_failure);
        assert!(retry.retryable_status_codes.is_empty());
    }

    #[test]
    fn virtual_service_retries_refused_stream_sets_connect_retry() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 2,
                            "retryOn": "refused-stream"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0].retry.as_ref().expect("retry");
        assert!(retry.retry_on_connect_failure);
        assert!(retry.retryable_status_codes.is_empty());
    }

    #[test]
    fn virtual_service_retries_numeric_code_out_of_range_filtered() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {
                            "attempts": 1,
                            "retryOn": "503,9999,42,418"
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let retry = result.config.proxies[0].retry.as_ref().expect("retry");
        assert!(retry.retryable_status_codes.contains(&503));
        assert!(retry.retryable_status_codes.contains(&418));
        assert!(!retry.retryable_status_codes.contains(&9999));
        assert!(!retry.retryable_status_codes.contains(&42));
    }

    #[test]
    fn virtual_service_maps_timeout_to_backend_read_timeout() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "5s"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].backend_read_timeout_ms, 5000);
    }

    #[test]
    fn virtual_service_maps_millisecond_timeout() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "500ms"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].backend_read_timeout_ms, 500);
    }

    #[test]
    fn virtual_service_maps_fractional_second_timeout() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "1.5s"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].backend_read_timeout_ms, 1500);
    }

    #[test]
    fn virtual_service_timeout_extended_units() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "2m"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies[0].backend_read_timeout_ms, 120_000);
    }

    #[test]
    fn virtual_service_timeout_and_retry_combined() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "timeout": "10s",
                        "retries": {"attempts": 2, "retryOn": "connect-failure,reset"}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let proxy = &result.config.proxies[0];
        assert_eq!(proxy.backend_read_timeout_ms, 10_000);
        let retry = proxy.retry.as_ref().expect("retry config");
        assert_eq!(retry.max_retries, 2);
        assert!(retry.retry_on_connect_failure);
    }

    #[test]
    fn virtual_service_retry_shared_across_multiple_uri_matches() {
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
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "retries": {"attempts": 3, "retryOn": "5xx"},
                        "timeout": "3s"
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 2);
        for proxy in &result.config.proxies {
            assert_eq!(proxy.backend_read_timeout_ms, 3000);
            let retry = proxy.retry.as_ref().expect("retry config");
            assert_eq!(retry.max_retries, 3);
        }
    }

    #[test]
    fn virtual_service_no_fault_or_retry_or_timeout() {
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

        assert!(result.config.plugin_configs.is_empty());
        assert!(result.config.proxies[0].retry.is_none());
        assert_eq!(result.config.proxies[0].backend_read_timeout_ms, 30_000);
    }

    #[test]
    fn virtual_service_weighted_destinations_with_retry() {
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
                        ],
                        "retries": {"attempts": 2, "retryOn": "5xx"}
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.upstreams.len(), 1);
        let retry = result.config.proxies[0]
            .retry
            .as_ref()
            .expect("retry config");
        assert_eq!(retry.max_retries, 2);
    }

    #[test]
    fn virtual_service_fault_delay_ms_format() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "delay": {
                                "fixedDelay": "250ms",
                                "percent": 100.0
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let delay = plugin.config.get("delay").expect("delay config");
        assert_eq!(delay["duration_ms"], 250);
        assert_eq!(delay["percentage"], 100.0);
    }

    #[test]
    fn virtual_service_fault_abort_defaults_percentage_100() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let abort = plugin.config.get("abort").expect("abort config");
        assert_eq!(abort["percentage"], 100.0);
    }

    #[test]
    fn virtual_service_fault_abort_zero_percentage_skips_subfield() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percentage": {"value": 0.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(result.config.plugin_configs.is_empty());
    }

    #[test]
    fn virtual_service_fault_zero_abort_keeps_valid_delay() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percentage": {"value": 0.0}
                            },
                            "delay": {
                                "fixedDelay": "100ms",
                                "percentage": {"value": 25.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.plugin_configs.len(), 1);
        let plugin = &result.config.plugin_configs[0];
        assert!(plugin.config.get("abort").is_none());
        let delay = plugin.config.get("delay").expect("delay config");
        assert_eq!(delay["duration_ms"], 100);
        assert_eq!(delay["percentage"], 25.0);
    }

    #[test]
    fn virtual_service_fault_ignores_invalid_generated_plugin_config() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/zero-delay"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "delay": {
                                "fixedDelay": "0s",
                                "percentage": {"value": 100.0}
                            }
                        }
                    }, {
                        "match": [{"uri": {"prefix": "/too-long-delay"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "delay": {
                                "fixedDelay": "2h",
                                "percentage": {"value": 100.0}
                            }
                        }
                    }, {
                        "match": [{"uri": {"prefix": "/zero-percent"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percentage": {"value": 0.0}
                            }
                        }
                    }, {
                        "match": [{"uri": {"prefix": "/bad-percent"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percent": 101.0
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert_eq!(result.config.proxies.len(), 4);
        assert!(result.config.plugin_configs.is_empty());
    }

    #[test]
    fn virtual_service_fault_abort_grpc_status_string() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["grpc.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {"host": "svc.default.svc.cluster.local", "port": {"number": 50051}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 200,
                                "grpcStatus": "UNAVAILABLE",
                                "percentage": {"value": 30.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let abort = plugin.config.get("abort").expect("abort config");
        assert_eq!(abort["grpc_status"], 14);
        assert_eq!(abort["status_code"], 200);
    }

    #[test]
    fn virtual_service_fault_abort_grpc_status_numeric() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["grpc.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {"host": "svc.default.svc.cluster.local", "port": {"number": 50051}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 200,
                                "grpcStatus": 13,
                                "percentage": {"value": 10.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let abort = plugin.config.get("abort").expect("abort config");
        assert_eq!(abort["grpc_status"], 13);
    }

    #[test]
    fn virtual_service_fault_abort_invalid_grpc_status_dropped() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["grpc.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {"host": "svc.default.svc.cluster.local", "port": {"number": 50051}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "grpcStatus": "NOT_A_REAL_CODE",
                                "percentage": {"value": 10.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        let abort = plugin.config.get("abort").expect("abort config");
        assert!(abort.get("grpc_status").is_none());
        assert_eq!(abort["status_code"], 503);
    }

    #[test]
    fn virtual_service_fault_plugin_scoped_to_proxy() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}],
                        "fault": {
                            "abort": {
                                "httpStatus": 503,
                                "percentage": {"value": 10.0}
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let plugin = &result.config.plugin_configs[0];
        assert!(matches!(
            plugin.scope,
            crate::config::types::PluginScope::Proxy
        ));
        assert_eq!(
            plugin.proxy_id.as_deref(),
            Some(result.config.proxies[0].id.as_str())
        );
        assert!(
            proxy_has_plugin(&result.config.proxies[0], plugin),
            "generated fault_injection config must be associated with the proxy or PluginCache will not instantiate it"
        );
    }

    // -- mesh_route_dispatch ----------------------------------------------

    #[test]
    fn virtual_service_method_match_dropped_without_experimental_flag() {
        // env var OFF (default): predicates silently dropped, no plugin emitted.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "method": {"exact": "GET"}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        assert!(
            result
                .config
                .plugin_configs
                .iter()
                .all(|p| p.plugin_name != "mesh_route_dispatch"),
            "no mesh_route_dispatch plugin should be emitted when env var is off"
        );
    }

    #[test]
    fn virtual_service_method_match_emits_plugin_with_experimental_flag() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "method": {"exact": "GET"}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("mesh_route_dispatch plugin should be emitted");
        assert!(matches!(
            plugin.scope,
            crate::config::types::PluginScope::Proxy
        ));
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| plugin.proxy_id.as_deref() == Some(p.id.as_str()))
            .expect("plugin proxy exists");
        assert!(
            proxy_has_plugin(proxy, plugin),
            "generated mesh_route_dispatch config must be associated with its proxy"
        );
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        let methods = rules[0]["match"]["methods"]
            .as_array()
            .expect("methods array");
        assert_eq!(methods[0].as_str(), Some("GET"));
        // VirtualService match semantics: requests that miss the predicates
        // must NOT fall through to the proxy's default backend.
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "VS-emitted mesh_route_dispatch must enforce match semantics via reject_unmatched"
        );
    }

    #[test]
    fn virtual_service_method_match_preserves_exact_case() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "method": {"exact": "get"}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("mesh_route_dispatch plugin should be emitted");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        let methods = rules[0]["match"]["methods"]
            .as_array()
            .expect("methods array");
        assert_eq!(methods[0].as_str(), Some("get"));
    }

    #[test]
    fn virtual_service_uri_only_match_does_not_emit_plugin() {
        // URI-only matches still get the env-var path translated, but no
        // mesh_route_dispatch plugin is emitted because there are no
        // non-URI predicates.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/api"}}],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        assert!(
            result
                .config
                .plugin_configs
                .iter()
                .all(|p| p.plugin_name != "mesh_route_dispatch"),
            "URI-only match should not emit mesh_route_dispatch"
        );
    }

    #[test]
    fn virtual_service_regex_uri_with_ignored_predicates_fails_closed() {
        // Unsupported non-URI match shapes (regex method/header/queryParam)
        // cannot be enforced by mesh_route_dispatch. A match entry with URI
        // plus only unsupported predicate types must not materialize a naked
        // URI proxy, because that would forward every regex-URI request
        // without the method/header/query gates.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"regex": "/v[0-9]+/api"},
                            "method": {"regex": "GET|POST"},
                            "headers": {"x-canary": {"regex": "v[0-9]+"}},
                            "queryParams": {"variant": {"regex": "beta|stable"}}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        assert!(
            result
                .config
                .plugin_configs
                .iter()
                .all(|p| p.plugin_name != "mesh_route_dispatch"),
            "URI plus ignored predicates should not emit mesh_route_dispatch"
        );
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("~/v[0-9]+/api"))
            .expect("URI plus unsupported predicates materializes a terminating proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("unsupported predicates attach a termination plugin");
        assert!(proxy_has_plugin(proxy, plugin));
    }

    #[test]
    fn virtual_service_header_match_emits_plugin_with_headers() {
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "headers": {"x-canary": {"exact": "v2"}}
                        }],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("mesh_route_dispatch plugin should be emitted");
        let headers = &plugin.config["rules"][0]["match"]["headers"];
        assert_eq!(headers["x-canary"].as_str(), Some("v2"));
    }

    #[test]
    fn virtual_service_mixed_uri_only_and_header_match_disables_reject_unmatched() {
        // Codex P1 (#3237393205): a VirtualService whose `match[]` mixes a
        // URI-only branch with a URI+header branch on the same URI must let
        // plain `/api` requests fall through to the proxy's default backend.
        // Istio `match[]` entries are ORed -- the URI-only entry is an
        // unconditional catch-all for this listen_path. With
        // `reject_unmatched: true` the silently dropped URI-only branch
        // turned legitimate traffic into 404s.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}},
                            {
                                "uri": {"prefix": "/api"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("mesh_route_dispatch plugin should still be emitted to surface predicates");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(
            rules.len(),
            1,
            "URI-only sibling does not become a rule; the header branch does"
        );
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(false),
            "URI-only catch-all sibling must disable reject_unmatched so plain `/api` traffic still reaches the default backend"
        );
    }

    #[test]
    fn virtual_service_match_rules_scoped_to_listen_path() {
        // Codex P1 (#3232888791): match entries from a sibling URI branch
        // must not bleed into a path-specific proxy. A `match[]` with
        // `[{uri:/api}, {uri:/v2, headers:...}]` produces two proxies
        // (`/api`, `/v2`); the header rule belongs only to the `/v2`
        // proxy. Without scoping, the `/v2` header rule fires on `/api`
        // requests too, violating VirtualService semantics.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}},
                            {
                                "uri": {"prefix": "/v2"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let api_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/api"))
            .expect("/api proxy");
        let v2_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/v2"))
            .expect("/v2 proxy");

        // The /api branch is URI-only -- no rule applies to this proxy and
        // every request matches the unconditional URI branch, so we emit
        // no plugin at all (would-be plugin has zero rules).
        let api_plugin = result.config.plugin_configs.iter().find(|p| {
            p.plugin_name == "mesh_route_dispatch"
                && p.proxy_id.as_deref() == Some(api_proxy.id.as_str())
        });
        assert!(
            api_plugin.is_none(),
            "/api proxy has only a URI-only branch -- no mesh_route_dispatch plugin should be emitted"
        );

        // The /v2 branch has a header predicate. Its proxy must get a
        // plugin with the header rule AND `reject_unmatched: true` (no
        // URI-only sibling in scope for this listen_path).
        let v2_plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(v2_proxy.id.as_str())
            })
            .expect("/v2 proxy mesh_route_dispatch plugin");
        let v2_rules = v2_plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules");
        assert_eq!(v2_rules.len(), 1, "/v2 proxy sees only its own header rule");
        assert_eq!(
            v2_rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            v2_plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "/v2 has no URI-only sibling -- reject_unmatched stays on so traffic without x-canary 404s"
        );
    }

    #[test]
    fn virtual_service_unsupported_method_regex_does_not_disable_reject_unmatched() {
        // Codex P1 (#3237631705): a `match[]` mixing one supported
        // `method.exact` rule with one unsupported `method.regex` rule
        // must NOT collapse the regex entry onto the URI-only catch-all
        // branch. Doing so would flip `reject_unmatched` to false and
        // forward requests the operator gated (e.g., DELETE traffic
        // sneaking past a route that only allows GET via `.exact` and
        // hoped to allow POST/PUT via `.regex`).
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "method": {"exact": "GET"}},
                            {"uri": {"prefix": "/api"}, "method": {"regex": "PO.*"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("mesh_route_dispatch plugin should be emitted for the GET branch");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(
            rules.len(),
            1,
            "supported method.exact rule emitted; unsupported method.regex sibling skipped"
        );
        assert_eq!(rules[0]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "unsupported predicate sibling must NOT relax reject_unmatched -- DELETE traffic should 404 instead of leaking through"
        );
    }

    #[test]
    fn virtual_service_unsupported_authority_predicate_does_not_disable_reject_unmatched() {
        // Codex P1 (#3237631705): `authority` is a non-URI predicate we
        // don't currently extract. An entry consisting of `uri` plus
        // `authority` is NOT a URI-only catch-all -- it's URI plus an
        // unsupported predicate. Treating it as URI-only would forward
        // requests that don't carry the gated authority.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "headers": {"x-canary": {"exact": "v2"}}},
                            {"uri": {"prefix": "/api"}, "authority": {"exact": "internal.example.com"}}
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("mesh_route_dispatch plugin should be emitted");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(
            rules.len(),
            1,
            "only the supported header rule survives; authority-bearing sibling is skipped"
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "unsupported authority predicate must NOT collapse onto URI-only catch-all"
        );
    }

    #[test]
    fn virtual_service_header_only_match_materializes_catch_all() {
        // Codex P2 (#3237631709): a VirtualService whose `match[]`
        // contains only non-URI predicates (no `uri` block at all) is a
        // legitimate Istio configuration -- it routes "any URI with these
        // predicates" on the listed hosts. Previously the translator
        // dropped such routes entirely because match_paths was URI-driven.
        // With the experimental flag on, materialize a regex catch-all
        // proxy + mesh_route_dispatch plugin so the operator's predicates
        // are actually enforced without shadowing real prefix/regex routes.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"headers": {"x-canary": {"exact": "v2"}}}
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("regex catch-all proxy materialized for header-only match");
        assert_eq!(proxy.hosts, vec!["api.example.com".to_string()]);

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("plugin attached to the catch-all proxy");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "header-only match with no URI-only sibling keeps reject_unmatched on"
        );
    }

    #[test]
    fn virtual_service_header_only_match_decorates_later_default_route() {
        // Regression for the URI-less catch-all routing order: Ferrum routes
        // prefix paths before regex paths, so a generated `~.*` header-only
        // proxy loses to a later default `/` proxy. Attach the earlier
        // URI-less rule to the later default proxy as an override instead:
        // matching traffic diverts to canary, non-matching traffic stays on
        // the default backend.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [
                                {"headers": {"x-canary": {"exact": "v2"}}}
                            ],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("/")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later default proxy");

        let matched = crate::router_cache::RouterCache::new(&result.config, 0)
            .find_proxy(Some("api.example.com"), "/anything")
            .expect("default prefix proxy should match");
        assert_eq!(
            matched.proxy.id, stable_proxy.id,
            "the later default prefix is the proxy the hot router selects"
        );

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("prior URI-less rule decorates later default proxy");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            rules[0]["destination"]["backend_host"].as_str(),
            Some("canary.default.svc.cluster.local")
        );
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(9090));
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(false),
            "misses must fall through to the selected default proxy backend"
        );
    }

    #[test]
    fn virtual_service_unsupported_uri_less_predicate_decorates_later_default_with_termination() {
        // Unsupported URI-less predicates cannot be represented by
        // mesh_route_dispatch. If they were skipped, the later default route
        // would serve requests that Istio gated. Collapse a terminating plugin
        // onto the selected default proxy instead.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [
                                {"headers": {"x-tier": {"regex": "gold|platinum"}}}
                            ],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("/")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later default proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("unsupported URI-less predicate terminates the selected proxy");
        assert!(proxy_has_plugin(stable_proxy, plugin));
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "mesh_route_dispatch"),
            "unsupported predicate must not emit a partial dispatch rule"
        );
    }

    #[test]
    fn virtual_service_ignore_uri_case_match_fails_closed() {
        // `ignoreUriCase` changes path matching itself, which Ferrum's
        // router cannot emulate with a normal prefix route. Treat it as an
        // unsupported predicate and fail closed rather than accidentally
        // making only one casing reachable.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/Api"},
                                "ignoreUriCase": true
                            }],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/api"}}],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let stable_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| {
                p.listen_path.as_deref() == Some("/api")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later case-sensitive URI proxy");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("ignoreUriCase branch attaches termination to later proxy");
        assert!(proxy_has_plugin(stable_proxy, plugin));
    }

    #[test]
    fn virtual_service_ignore_uri_case_false_uses_regular_uri_match() {
        // Explicit `ignoreUriCase: false` is equivalent to Istio's default
        // case-sensitive path matching and must not be treated as unsupported.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/Api"},
                            "ignoreUriCase": false
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/Api"))
            .expect("regular case-sensitive URI proxy");
        assert_eq!(proxy.backend_host, "canary.default.svc.cluster.local");
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "request_termination"),
            "ignoreUriCase=false must not emit fail-closed termination"
        );
    }

    #[test]
    fn virtual_service_ignore_uri_case_false_with_other_unsupported_predicate_stays_uri_scoped() {
        // If some other predicate is unsupported, an explicit
        // `ignoreUriCase: false` should not broaden the fail-closed proxy to
        // the synthetic URI-less catch-all.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [{
                            "uri": {"prefix": "/Api"},
                            "ignoreUriCase": false,
                            "method": {"regex": "GET|POST"}
                        }],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/Api"))
            .expect("fail-closed proxy stays scoped to the URI match");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("unsupported method regex terminates the URI-scoped proxy");
        assert!(proxy_has_plugin(proxy, plugin));
        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH)),
            "ignoreUriCase=false must not force URI-less fail-closed broadening"
        );
    }

    #[test]
    fn virtual_service_same_path_guarded_route_decorates_later_default() {
        // Ordered Istio http[] routes with the same URI must behave like
        // route-list fall-through: a canary header branch can divert matches,
        // while misses continue to the later stable route. Two Ferrum proxies
        // with the same host+listen_path cannot express that, so the earlier
        // guarded branch is collapsed into a dispatch rule on the later proxy.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/api"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/api"}}],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let api_proxies: Vec<&Proxy> = result
            .config
            .proxies
            .iter()
            .filter(|p| p.listen_path.as_deref() == Some("/api"))
            .collect();
        assert_eq!(
            api_proxies.len(),
            1,
            "same-path ordered routes must collapse to one proxy"
        );
        let stable_proxy = api_proxies[0];
        assert_eq!(
            stable_proxy.backend_host,
            "stable.default.svc.cluster.local"
        );

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("canary branch decorates the stable proxy");
        assert!(proxy_has_plugin(stable_proxy, plugin));
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            rules[0]["destination"]["backend_host"].as_str(),
            Some("canary.default.svc.cluster.local")
        );
        assert_eq!(rules[0]["destination"]["backend_port"].as_u64(), Some(9090));
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(false),
            "predicate misses must fall through to the later stable backend"
        );
    }

    #[test]
    fn virtual_service_same_path_mixed_supported_and_unsupported_match_fails_closed_on_miss() {
        // If one match entry on a route is representable and a sibling on the
        // same listen_path is not, preserve the supported dispatch rule but
        // keep reject_unmatched enabled after collapse. Otherwise traffic that
        // might have matched the unsupported predicate would leak to the later
        // default route.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [
                                {"uri": {"prefix": "/api"}, "method": {"exact": "GET"}},
                                {"uri": {"prefix": "/api"}, "method": {"regex": "PO.*"}}
                            ],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/api"}}],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let api_proxies: Vec<&Proxy> = result
            .config
            .proxies
            .iter()
            .filter(|p| p.listen_path.as_deref() == Some("/api"))
            .collect();
        assert_eq!(api_proxies.len(), 1);
        let stable_proxy = api_proxies[0];
        assert_eq!(
            stable_proxy.backend_host,
            "stable.default.svc.cluster.local"
        );

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("supported rule decorates the stable proxy");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["match"]["methods"][0].as_str(), Some("GET"));
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "unsupported sibling must make predicate misses fail closed"
        );
        assert!(
            !result.config.plugin_configs.iter().any(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            }),
            "a supported dispatch rule can fail closed with reject_unmatched instead of terminating every request"
        );
    }

    #[test]
    fn virtual_service_same_path_guarded_route_with_local_policy_is_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{
                                "uri": {"prefix": "/api"},
                                "headers": {"x-canary": {"exact": "v2"}}
                            }],
                            "timeout": "250ms",
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"uri": {"prefix": "/api"}}],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect_err("route-local timeout cannot be collapsed into a destination-only rule");
        assert!(err.to_string().contains("route-local"), "got: {err}");
        assert!(
            err.to_string().contains("mesh_route_dispatch"),
            "got: {err}"
        );
    }

    #[test]
    fn virtual_service_multiple_uri_less_routes_collapse_in_order() {
        // Multiple URI-less guarded routes all materialize as `~.*`; emitting
        // one proxy per route would make the first reject misses before the
        // second can match. Collapse them into one ordered rule list.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [{"headers": {"x-canary": {"exact": "v2"}}}],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [{"headers": {"x-region": {"exact": "east"}}}],
                            "route": [{"destination": {"host": "east.default.svc.cluster.local", "port": {"number": 8081}}}]
                        }
                    ]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let catch_all_proxies: Vec<&Proxy> = result
            .config
            .proxies
            .iter()
            .filter(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .collect();
        assert_eq!(
            catch_all_proxies.len(),
            1,
            "URI-less guarded route list must collapse to one catch-all proxy"
        );
        let proxy = catch_all_proxies[0];
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("collapsed catch-all has dispatch plugin");
        assert!(proxy_has_plugin(proxy, plugin));
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            rules[0]["destination"]["backend_host"].as_str(),
            Some("canary.default.svc.cluster.local")
        );
        assert_eq!(
            rules[1]["match"]["headers"]["x-region"].as_str(),
            Some("east")
        );
        assert_eq!(
            rules[1]["destination"]["backend_host"].as_str(),
            Some("east.default.svc.cluster.local")
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "with no later default route, misses must still fail closed"
        );
    }

    #[test]
    fn virtual_service_header_only_match_does_not_shadow_later_regex_route() {
        // Codex P1 (#3238865239): regex routes are first-match in config
        // order. An earlier URI-less rule materialized as `~.*` must be
        // deferred after later regex URI routes; otherwise it wins routing
        // and 404s predicate misses before the later regex route can run.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [
                        {
                            "match": [
                                {"headers": {"x-canary": {"exact": "v2"}}}
                            ],
                            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                        },
                        {
                            "match": [
                                {"uri": {"regex": "/v[0-9]+/api"}}
                            ],
                            "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                        }
                    ]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let stable_index = result
            .config
            .proxies
            .iter()
            .position(|p| {
                p.listen_path.as_deref() == Some("~/v[0-9]+/api")
                    && p.backend_host == "stable.default.svc.cluster.local"
            })
            .expect("later regex URI proxy");
        let catch_all_index = result
            .config
            .proxies
            .iter()
            .position(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("deferred URI-less catch-all proxy");
        assert!(
            stable_index < catch_all_index,
            "later regex URI proxy must be indexed before the synthetic catch-all"
        );

        let stable_proxy = &result.config.proxies[stable_index];
        let matched = crate::router_cache::RouterCache::new(&result.config, 0)
            .find_proxy(Some("api.example.com"), "/v1/api")
            .expect("regex URI proxy should match");
        assert_eq!(
            matched.proxy.id, stable_proxy.id,
            "the hot router should select the later regex route, not the `~.*` catch-all"
        );

        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(stable_proxy.id.as_str())
            })
            .expect("prior URI-less rule decorates later regex proxy");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2")
        );
        assert_eq!(
            rules[0]["destination"]["backend_host"].as_str(),
            Some("canary.default.svc.cluster.local")
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(false),
            "predicate misses must fall through to the selected regex route backend"
        );
    }

    #[test]
    fn virtual_service_header_only_match_skipped_without_experimental_flag() {
        // The experimental flag still gates this materialization. With it
        // off, behaviour matches today's wire output: no proxy is emitted
        // for a header-only match block.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"headers": {"x-canary": {"exact": "v2"}}}
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH)),
            "no catch-all materialized when experimental flag is off"
        );
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "mesh_route_dispatch"),
            "no plugin emitted when experimental flag is off"
        );
    }

    #[test]
    fn virtual_service_header_only_match_with_unsupported_predicates_fails_closed() {
        // A header-only entry whose only header predicate is `regex`
        // cannot be enforced by mesh_route_dispatch. Materializing a
        // catch-all to the route's backend would silently widen past the
        // operator's intent. Emit a terminating catch-all instead, so a
        // later broader route cannot accidentally serve the guarded traffic.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"headers": {"x-tier": {"regex": "gold|platinum"}}}
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "mesh_route_dispatch"),
            "unsupported predicates must not emit a partial dispatch plugin"
        );
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("terminating catch-all proxy materialized");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("termination plugin attached");
        assert!(proxy_has_plugin(proxy, plugin));
    }

    #[test]
    fn virtual_service_header_only_match_with_partial_unsupported_predicates_fails_closed() {
        // A URI-less entry with one exact predicate and one unsupported
        // predicate is unsafe to materialize: mesh_route_dispatch would skip
        // the partial rule, leaving an unguarded catch-all proxy behind. The
        // translator emits a terminating catch-all instead.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {
                                "headers": {
                                    "x-canary": {"exact": "v2"},
                                    "x-tier": {"regex": "gold|platinum"}
                                }
                            }
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        let proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("terminating catch-all proxy materialized");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "request_termination"
                    && p.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .expect("termination plugin attached");
        assert!(proxy_has_plugin(proxy, plugin));
        assert!(
            !result
                .config
                .plugin_configs
                .iter()
                .any(|p| p.plugin_name == "mesh_route_dispatch"),
            "partial URI-less predicates must not emit a dispatch plugin"
        );
    }

    #[test]
    fn virtual_service_mixed_uri_and_header_only_match_emits_both_proxies() {
        // A `match[]` mixing one URI entry and one URI-less header entry
        // must produce BOTH proxies: the URI-derived `/api` AND a regex
        // catch-all for the URI-less header rule. Without the catch-all,
        // `/other` requests carrying the header would 404 even though
        // Istio semantics route them via the URI-less branch.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}},
                            {"headers": {"x-canary": {"exact": "v2"}}}
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        let api_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some("/api"))
            .expect("URI-derived /api proxy");
        let catch_all = result
            .config
            .proxies
            .iter()
            .find(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH))
            .expect("URI-less catch-all proxy");
        assert_ne!(api_proxy.id, catch_all.id);

        // The catch-all proxy MUST have a plugin (the URI-less header
        // rule). The `/api` proxy ALSO has a plugin because the URI-less
        // header entry applies to every listen_path of this http rule,
        // and the URI-only `/api` entry triggers has_uri_only_match.
        let api_plugin = result.config.plugin_configs.iter().find(|p| {
            p.plugin_name == "mesh_route_dispatch"
                && p.proxy_id.as_deref() == Some(api_proxy.id.as_str())
        });
        let catch_all_plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| {
                p.plugin_name == "mesh_route_dispatch"
                    && p.proxy_id.as_deref() == Some(catch_all.id.as_str())
            })
            .expect("catch-all proxy has the URI-less header rule attached");

        // /api proxy: URI-only branch keeps reject_unmatched off so
        // unrelated traffic to /api still routes.
        if let Some(plugin) = api_plugin {
            assert_eq!(
                plugin
                    .config
                    .get("reject_unmatched")
                    .and_then(Value::as_bool),
                Some(false),
                "URI-only sibling on /api proxy disables reject_unmatched"
            );
        }
        assert_eq!(
            catch_all_plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
            "catch-all proxy has no URI-only sibling in scope, so reject_unmatched stays on"
        );
    }

    #[test]
    fn virtual_service_mixed_regex_uri_and_header_only_uses_regex_catch_all() {
        // Ferrum routes prefixes before regexes. If the URI-less header
        // branch were materialized as prefix `/`, it would shadow the real
        // regex URI branch and reject requests that should match it.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"regex": "/v[0-9]+/api"}},
                            {"headers": {"x-canary": {"exact": "v2"}}}
                        ],
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");

        assert!(
            result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some("~/v[0-9]+/api")),
            "regex URI branch must still materialize"
        );
        assert!(
            result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some(URI_LESS_MATCH_LISTEN_PATH)),
            "URI-less branch should use regex catch-all"
        );
        assert!(
            !result
                .config
                .proxies
                .iter()
                .any(|p| p.listen_path.as_deref() == Some("/")),
            "URI-less branch must not become prefix `/`, which shadows regex routes"
        );
    }

    #[test]
    fn virtual_service_partial_predicate_extraction_skips_rule() {
        // Codex P1 (#3237631705) follow-on: an entry with one supported
        // and one unsupported predicate is also unsafe to emit as a
        // partial rule. `method=GET + headers.X.regex` cannot be honored
        // (the regex header predicate is dropped), so emitting a rule
        // with only `methods=[GET]` would silently widen the route to
        // match GET regardless of the gated header value. Skip the entry
        // entirely; `reject_unmatched: true` 404s the request, which is
        // the fail-closed VirtualService semantic.
        let result = translate_k8s_objects(
            &[object(
                "VirtualService",
                serde_json::json!({
                    "hosts": ["api.example.com"],
                    "http": [{
                        "match": [
                            {"uri": {"prefix": "/api"}, "headers": {"x-canary": {"exact": "v2"}}},
                            {
                                "uri": {"prefix": "/api"},
                                "method": {"exact": "GET"},
                                "headers": {"x-tier": {"regex": "gold|platinum"}}
                            }
                        ],
                        "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }]
                }),
            )],
            options().with_vs_header_routing_experimental(true),
        )
        .expect("translation succeeds");
        let plugin = result
            .config
            .plugin_configs
            .iter()
            .find(|p| p.plugin_name == "mesh_route_dispatch")
            .expect("mesh_route_dispatch plugin should be emitted");
        let rules = plugin
            .config
            .get("rules")
            .and_then(Value::as_array)
            .expect("rules array");
        assert_eq!(
            rules.len(),
            1,
            "only the fully-supported header rule emits; the partial-extraction entry is skipped"
        );
        assert_eq!(
            rules[0]["match"]["headers"]["x-canary"].as_str(),
            Some("v2"),
            "the emitted rule is the fully-supported one"
        );
        assert!(
            rules[0]["match"].get("methods").is_none(),
            "method=GET from the partial entry must NOT leak onto the surviving rule"
        );
        assert_eq!(
            plugin
                .config
                .get("reject_unmatched")
                .and_then(Value::as_bool),
            Some(true),
        );
    }

    #[test]
    fn parse_istio_duration_ms_formats() {
        assert_eq!(parse_istio_duration_ms("5s"), Some(5000));
        assert_eq!(parse_istio_duration_ms("1.5s"), Some(1500));
        assert_eq!(parse_istio_duration_ms("500ms"), Some(500));
        assert_eq!(parse_istio_duration_ms("0s"), Some(0));
        assert_eq!(parse_istio_duration_ms("0ms"), Some(0));
        assert_eq!(parse_istio_duration_ms("-1s"), None);
        assert_eq!(parse_istio_duration_ms("-500ms"), None);
        assert_eq!(parse_istio_duration_ms("NaN s"), None);
        assert_eq!(parse_istio_duration_ms("10"), None);
        assert_eq!(parse_istio_duration_ms("30m"), Some(1_800_000));
        assert_eq!(parse_istio_duration_ms("2h"), Some(7_200_000));
        assert_eq!(parse_istio_duration_ms("1.5h"), Some(5_400_000));
        assert_eq!(parse_istio_duration_ms("5000us"), Some(5));
        assert_eq!(parse_istio_duration_ms("100us"), Some(1));
        assert_eq!(parse_istio_duration_ms("999ns"), Some(1));
    }

    #[test]
    fn translates_authorization_policy_request_principals() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{
                    "source": {
                        "requestPrincipals": [
                            "https://accounts.google.com/*",
                            "https://auth.example.com/admin"
                        ]
                    }
                }]
            }]
        }));

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(
            policy.rules[0].request_principals,
            vec![
                "https://accounts.google.com/*".to_string(),
                "https://auth.example.com/admin".to_string(),
            ]
        );
    }

    #[test]
    fn translates_authorization_policy_request_principals_empty() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{"source": {"principals": ["spiffe://cluster.local/ns/default/sa/web"]}}]
            }]
        }));

        assert!(
            policy.rules[0].request_principals.is_empty(),
            "no requestPrincipals should produce empty list"
        );
    }

    #[test]
    fn authorization_policy_from_entries_remain_or_alternatives() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [
                    {"source": {"principals": ["spiffe://cluster.local/ns/default/sa/web"]}},
                    {"source": {"requestPrincipals": ["https://auth.example.com/admin"]}}
                ]
            }]
        }));

        assert_eq!(
            policy.rules.len(),
            2,
            "each from[] source should become its own OR alternative"
        );
        assert_eq!(policy.rules[0].from.len(), 1);
        assert!(policy.rules[0].request_principals.is_empty());
        assert!(policy.rules[1].from.is_empty());
        assert_eq!(
            policy.rules[1].request_principals,
            vec!["https://auth.example.com/admin".to_string()]
        );

        let slice = MeshSlice {
            mesh_policies: vec![policy],
            ..MeshSlice::default()
        };

        let spiffe_only = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &spiffe_only),
            MeshAuthzDecision::Allow
        );

        let jwt_only = MeshAuthzRequest {
            request_principal: Some("https://auth.example.com/admin".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &jwt_only),
            MeshAuthzDecision::Allow
        );

        assert_eq!(
            evaluate_mesh_authorization(&slice, &MeshAuthzRequest::default()),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );
    }

    #[test]
    fn authorization_policy_from_entry_keeps_principal_and_jwt_together() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{
                    "source": {
                        "principals": ["spiffe://cluster.local/ns/default/sa/web"],
                        "requestPrincipals": ["https://auth.example.com/admin"]
                    }
                }]
            }]
        }));

        let slice = MeshSlice {
            mesh_policies: vec![policy],
            ..MeshSlice::default()
        };

        let spiffe_only = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe id"),
            ),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &spiffe_only),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );

        let both = MeshAuthzRequest {
            source_principal: Some(
                SpiffeId::new("spiffe://cluster.local/ns/default/sa/web").expect("spiffe id"),
            ),
            request_principal: Some("https://auth.example.com/admin".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &both),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn request_principals_block_anonymous_requests_in_authz_evaluation() {
        let policy = translated_authorization_policy(serde_json::json!({
            "action": "ALLOW",
            "rules": [{
                "from": [{
                    "source": {"requestPrincipals": ["*"]}
                }]
            }]
        }));

        let slice = MeshSlice {
            mesh_policies: vec![policy],
            ..MeshSlice::default()
        };

        let anon = MeshAuthzRequest::default();
        assert_eq!(
            evaluate_mesh_authorization(&slice, &anon),
            MeshAuthzDecision::Deny {
                policy: "implicit-deny".to_string()
            }
        );

        let authed = MeshAuthzRequest {
            request_principal: Some("https://auth.example.com/user".to_string()),
            ..MeshAuthzRequest::default()
        };
        assert_eq!(
            evaluate_mesh_authorization(&slice, &authed),
            MeshAuthzDecision::Allow
        );
    }

    #[test]
    fn parse_istio_duration_rejects_negative_non_finite_and_overflow() {
        assert_eq!(parse_istio_duration_ms("-1s"), None);
        assert_eq!(parse_istio_duration_ms("NaNs"), None);
        assert_eq!(parse_istio_duration_ms("infms"), None);
        assert_eq!(
            parse_istio_duration_ms("999999999999999999999999999999m"),
            None
        );
    }

    #[test]
    fn parse_istio_duration_secs_rounds_positive_subseconds_up() {
        assert_eq!(parse_istio_duration_secs("0.5s"), Some(1));
        assert_eq!(parse_istio_duration_secs("1.1s"), Some(2));
        assert_eq!(parse_istio_duration_secs("0s"), Some(0));
    }

    #[test]
    fn destination_rule_outlier_interval_ignores_zero_and_rounds_subsecond() {
        let zero_interval = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "outlierDetection": {
                            "interval": "0s"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let mesh = zero_interval.config.mesh.expect("mesh config");
        assert_eq!(
            mesh.destination_rules[0]
                .traffic_policy
                .as_ref()
                .and_then(|policy| policy.outlier_detection.as_ref())
                .and_then(|outlier| outlier.interval_seconds),
            None
        );

        let subsecond_interval = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "outlierDetection": {
                            "interval": "0.5s"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");
        let mesh = subsecond_interval.config.mesh.expect("mesh config");
        assert_eq!(
            mesh.destination_rules[0]
                .traffic_policy
                .as_ref()
                .and_then(|policy| policy.outlier_detection.as_ref())
                .and_then(|outlier| outlier.interval_seconds),
            Some(1)
        );
    }

    // ── ProxyConfig translation ─────────────────────────────────────────

    #[test]
    fn translates_proxy_config_with_all_fields_populated() {
        let result = translate_k8s_objects(
            &[object(
                "ProxyConfig",
                serde_json::json!({
                    "selector": {"matchLabels": {"app": "api"}},
                    "concurrency": 4,
                    "image": {"imageType": "distroless"},
                    "environmentVariables": {
                        "GOMAXPROCS": "4",
                        "PILOT_ENABLE_FOO": "true"
                    },
                    "tracing": {"sampling": 42.5}
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        let pc = &mesh.proxy_configs[0];
        assert_eq!(pc.name, "sample");
        assert_eq!(pc.namespace, "default");
        match &pc.scope {
            PolicyScope::WorkloadSelector { selector } => {
                assert_eq!(selector.labels.get("app").map(String::as_str), Some("api"));
                assert_eq!(selector.namespace.as_deref(), Some("default"));
            }
            other => panic!("expected WorkloadSelector scope, got {other:?}"),
        }
        assert_eq!(pc.concurrency, Some(4));
        assert_eq!(pc.image.as_deref(), Some("distroless"));
        assert_eq!(
            pc.environment.get("GOMAXPROCS").map(String::as_str),
            Some("4")
        );
        assert_eq!(
            pc.environment.get("PILOT_ENABLE_FOO").map(String::as_str),
            Some("true")
        );
        assert_eq!(pc.tracing_sampling, Some(42.5));
    }

    #[test]
    fn translates_proxy_config_without_selector_is_namespace_default() {
        let result = translate_k8s_objects(
            &[object(
                "ProxyConfig",
                serde_json::json!({
                    "concurrency": 2
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        let pc = &mesh.proxy_configs[0];
        match &pc.scope {
            PolicyScope::Namespace { namespace } => {
                assert_eq!(namespace, "default");
            }
            other => panic!("expected Namespace scope, got {other:?}"),
        }
        assert_eq!(pc.namespace, "default");
        assert_eq!(pc.concurrency, Some(2));
    }

    #[test]
    fn translates_proxy_config_omits_unset_fields() {
        let result =
            translate_k8s_objects(&[object("ProxyConfig", serde_json::json!({}))], options())
                .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        let pc = &mesh.proxy_configs[0];
        match &pc.scope {
            PolicyScope::Namespace { namespace } => assert_eq!(namespace, "default"),
            other => panic!("expected Namespace scope, got {other:?}"),
        }
        assert!(pc.concurrency.is_none());
        assert!(pc.image.is_none());
        assert!(pc.environment.is_empty());
        assert!(pc.tracing_sampling.is_none());
    }

    #[test]
    fn translates_root_namespace_proxy_config_without_selector_is_mesh_wide() {
        // A ProxyConfig in the Istio root namespace with no selector is the
        // canonical Istio pattern for a mesh-wide default. The previous
        // namespace-only filter dropped this entirely; PolicyScope::MeshWide
        // is the fix.
        let result = translate_k8s_objects(
            &[K8sObject {
                api_version: "networking.istio.io/v1beta1".to_string(),
                kind: "ProxyConfig".to_string(),
                metadata: K8sMetadata {
                    name: "mesh-default".to_string(),
                    namespace: "istio-config".to_string(),
                    labels: HashMap::new(),
                    deletion_timestamp: None,
                },
                spec: serde_json::json!({"tracing": {"sampling": 5.0}}),
                status: Value::Object(serde_json::Map::new()),
            }],
            options_for_namespace("default")
                .with_istio_root_namespace("istio-config".to_string())
                .with_source_namespaces(vec!["default".to_string(), "istio-config".to_string()]),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        let pc = &mesh.proxy_configs[0];
        assert!(
            matches!(pc.scope, PolicyScope::MeshWide),
            "expected MeshWide, got {:?}",
            pc.scope
        );
        assert_eq!(pc.tracing_sampling, Some(5.0));
    }

    #[test]
    fn translates_root_namespace_proxy_config_with_selector_is_mesh_wide_selector() {
        // A ProxyConfig in the Istio root namespace with a selector applies
        // to matching workloads across all namespaces. Encoded as
        // PolicyScope::WorkloadSelector with namespace=None — same pattern
        // as Telemetry / RequestAuthentication.
        let result = translate_k8s_objects(
            &[K8sObject {
                api_version: "networking.istio.io/v1beta1".to_string(),
                kind: "ProxyConfig".to_string(),
                metadata: K8sMetadata {
                    name: "mesh-api".to_string(),
                    namespace: "istio-config".to_string(),
                    labels: HashMap::new(),
                    deletion_timestamp: None,
                },
                spec: serde_json::json!({
                    "selector": {"matchLabels": {"app": "api"}},
                    "tracing": {"sampling": 50.0}
                }),
                status: Value::Object(serde_json::Map::new()),
            }],
            options_for_namespace("default")
                .with_istio_root_namespace("istio-config".to_string())
                .with_source_namespaces(vec!["default".to_string(), "istio-config".to_string()]),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        let pc = &mesh.proxy_configs[0];
        match &pc.scope {
            PolicyScope::WorkloadSelector { selector } => {
                assert_eq!(selector.labels.get("app").map(String::as_str), Some("api"));
                assert!(
                    selector.namespace.is_none(),
                    "root-namespace selector must drop namespace pin"
                );
            }
            other => panic!("expected WorkloadSelector with no namespace, got {other:?}"),
        }
        assert_eq!(pc.tracing_sampling, Some(50.0));
    }

    #[test]
    fn proxy_config_concurrency_overflow_is_rejected() {
        // Out-of-range concurrency must surface as an InvalidResource error
        // instead of silently clamping to u32::MAX.
        let err = translate_k8s_objects(
            &[object(
                "ProxyConfig",
                serde_json::json!({"concurrency": 9_999_999_999_u64}),
            )],
            options(),
        )
        .expect_err("overflow must be rejected");

        match err {
            K8sTranslateError::InvalidResource { kind, message, .. } => {
                assert_eq!(kind, "ProxyConfig");
                assert!(
                    message.contains("concurrency"),
                    "error message must mention concurrency: {message}"
                );
            }
            other => panic!("expected InvalidResource, got {other:?}"),
        }
    }

    #[test]
    fn proxy_config_concurrency_invalid_json_forms_are_rejected() {
        // A present-but-invalid concurrency value must surface as
        // InvalidResource — not silently dropped via the `as_u64` filter.
        let bad_values = [
            ("string", serde_json::json!("4")),
            ("float", serde_json::json!(4.5)),
            ("negative", serde_json::json!(-1)),
            ("bool", serde_json::json!(true)),
            ("array", serde_json::json!([4])),
            ("object", serde_json::json!({"n": 4})),
        ];

        for (label, bad) in bad_values {
            let err = translate_k8s_objects(
                &[object(
                    "ProxyConfig",
                    serde_json::json!({"concurrency": bad}),
                )],
                options(),
            )
            .expect_err(&format!("expected InvalidResource for {label}"));
            match err {
                K8sTranslateError::InvalidResource { kind, message, .. } => {
                    assert_eq!(kind, "ProxyConfig", "case {label}");
                    assert!(
                        message.contains("concurrency"),
                        "case {label}: error must mention concurrency: {message}"
                    );
                }
                other => panic!("case {label}: expected InvalidResource, got {other:?}"),
            }
        }
    }

    #[test]
    fn proxy_config_concurrency_null_is_treated_as_unset() {
        // Explicit JSON null is semantically equivalent to omitting the
        // field — both mean "use the data plane default."
        let result = translate_k8s_objects(
            &[object(
                "ProxyConfig",
                serde_json::json!({"concurrency": serde_json::Value::Null}),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.proxy_configs.len(), 1);
        assert!(mesh.proxy_configs[0].concurrency.is_none());
    }

    #[test]
    fn proxy_config_workload_selector_wins_over_namespace_default() {
        // Two ProxyConfigs in same namespace: one namespace-default (no
        // selector), one with a workload selector. Slice resolution must
        // prefer the workload-scoped one for a matching workload.
        use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
        use std::collections::BTreeMap;

        let result = translate_k8s_objects(
            &[
                object(
                    "ProxyConfig",
                    serde_json::json!({"tracing": {"sampling": 10.0}}),
                ),
                K8sObject {
                    api_version: "networking.istio.io/v1beta1".to_string(),
                    kind: "ProxyConfig".to_string(),
                    metadata: K8sMetadata {
                        name: "api-overrides".to_string(),
                        namespace: "default".to_string(),
                        labels: HashMap::new(),
                        deletion_timestamp: None,
                    },
                    spec: serde_json::json!({
                        "selector": {"matchLabels": {"app": "api"}},
                        "tracing": {"sampling": 99.0}
                    }),
                    status: Value::Object(serde_json::Map::new()),
                },
            ],
            options(),
        )
        .expect("translation succeeds");
        let gateway_config = result.config;
        assert_eq!(gateway_config.mesh.as_ref().unwrap().proxy_configs.len(), 2);

        let request = MeshSliceRequest {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            workload_spiffe_id: None,
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            cluster_domain: "cluster.local".to_string(),
            enforce_sidecar_egress: false,
        };
        let slice = MeshSlice::from_gateway_config(&gateway_config, request);
        // Both should match — namespace-default applies to any workload, and
        // the workload-scoped one applies to `app=api`.
        assert_eq!(slice.proxy_configs.len(), 2);

        let resolved = slice
            .resolved_proxy_config()
            .expect("expected resolved proxy_config");
        assert_eq!(resolved.tracing_sampling, Some(99.0));
        assert_eq!(resolved.name, "api-overrides");
    }
    // ── DestinationRule trafficPolicy.tls ───────────────────────────────

    #[test]
    fn translates_destination_rule_tls_simple_with_ca() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "caCertificates": "/etc/certs/ca.pem",
                            "sni": "reviews.example.com"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert_eq!(tls.mode, MtlsMode::Simple);
        assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));
        assert_eq!(tls.sni.as_deref(), Some("reviews.example.com"));
        assert!(tls.client_certificate.is_none());
        assert!(tls.private_key.is_none());
        assert!(!tls.insecure_skip_verify);
    }

    #[test]
    fn translates_destination_rule_tls_mutual_with_cert_and_key() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "MUTUAL",
                            "caCertificates": "/etc/certs/ca.pem",
                            "clientCertificate": "/etc/certs/client.pem",
                            "privateKey": "/etc/certs/client.key",
                            "subjectAltNames": ["spiffe://example/sa/reviews"],
                            "insecureSkipVerify": false
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert_eq!(tls.mode, MtlsMode::Mutual);
        assert_eq!(
            tls.client_certificate.as_deref(),
            Some("/etc/certs/client.pem")
        );
        assert_eq!(tls.private_key.as_deref(), Some("/etc/certs/client.key"));
        assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));
        assert_eq!(
            tls.subject_alt_names,
            vec!["spiffe://example/sa/reviews".to_string()]
        );
        assert!(!tls.insecure_skip_verify);
    }

    #[test]
    fn translates_destination_rule_tls_rejects_too_many_subject_alt_names() {
        let too_many_sans: Vec<String> = (0..=MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES)
            .map(|i| format!("san-{i}.example.com"))
            .collect();
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "subjectAltNames": too_many_sans
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("too many subjectAltNames must fail");

        assert!(
            err.to_string()
                .contains("subjectAltNames must not have more than"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_rejects_overlong_subject_alt_name() {
        let overlong_san = format!(
            "{}.example.com",
            "a".repeat(MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH)
        );
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "subjectAltNames": [overlong_san]
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("overlong subjectAltNames entry must fail");

        assert!(
            err.to_string()
                .contains("subjectAltNames[0] must not exceed"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_rejects_invalid_sni() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "sni": "*.mesh.internal"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("wildcard SNI must fail");

        assert!(
            err.to_string().contains("trafficPolicy.tls.sni"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_rejects_invalid_san_content() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "subjectAltNames": ["spiffe://cluster.local"]
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("SPIFFE URI without path must fail");

        assert!(err.to_string().contains("subjectAltNames[0]"), "got: {err}");
    }

    #[test]
    fn translates_destination_rule_tls_mutual_rejects_missing_cert_or_key() {
        // MUTUAL requires BOTH clientCertificate AND privateKey.
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "MUTUAL",
                            "clientCertificate": "/etc/certs/client.pem"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("MUTUAL without privateKey must fail");
        assert!(
            err.to_string()
                .contains("MUTUAL requires both clientCertificate and privateKey"),
            "got: {err}"
        );

        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "MUTUAL",
                            "privateKey": "/etc/certs/client.key"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("MUTUAL without clientCertificate must fail");
        assert!(
            err.to_string()
                .contains("MUTUAL requires both clientCertificate and privateKey"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_istio_mutual() {
        // ISTIO_MUTUAL must not carry explicit cert/key/CA — Istio reuses
        // the workload's SPIFFE identity material.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "ISTIO_MUTUAL",
                            "sni": "reviews.example.com"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert_eq!(tls.mode, MtlsMode::IstioMutual);
        assert!(tls.client_certificate.is_none());
        assert!(tls.private_key.is_none());
        assert!(tls.ca_certificates.is_none());
        assert_eq!(tls.sni.as_deref(), Some("reviews.example.com"));
    }

    #[test]
    fn translates_destination_rule_tls_istio_mutual_rejects_explicit_cert() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "ISTIO_MUTUAL",
                            "clientCertificate": "/etc/certs/client.pem",
                            "privateKey": "/etc/certs/client.key"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("ISTIO_MUTUAL with explicit cert/key must fail");
        assert!(
            err.to_string()
                .contains("ISTIO_MUTUAL must not set clientCertificate/privateKey/caCertificates"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_istio_mutual_rejects_explicit_ca() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "ISTIO_MUTUAL",
                            "caCertificates": "/etc/certs/ca.pem"
                        }
                    }
                }),
            )],
            options(),
        )
        .expect_err("ISTIO_MUTUAL with explicit CA must fail");
        assert!(
            err.to_string()
                .contains("ISTIO_MUTUAL must not set clientCertificate/privateKey/caCertificates"),
            "got: {err}"
        );
    }

    #[test]
    fn translates_destination_rule_tls_disable() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {"mode": "DISABLE"}
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert_eq!(tls.mode, MtlsMode::Disable);
    }

    #[test]
    fn translates_destination_rule_tls_insecure_skip_verify() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "insecureSkipVerify": true
                        }
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert!(tls.insecure_skip_verify);
    }

    #[test]
    fn destination_rule_without_tls_translates_to_none() {
        // Preserves today's behavior: no tls block in DR -> MeshTrafficPolicy.tls is None.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {"simple": "ROUND_ROBIN"}
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tp = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy");
        assert!(tp.tls.is_none());
    }

    #[test]
    fn destination_rule_rejects_unsupported_tls_mode() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {"mode": "BANANA"}
                    }
                }),
            )],
            options(),
        )
        .expect_err("unsupported TLS mode must fail");
        assert!(
            err.to_string()
                .contains("trafficPolicy.tls.mode 'BANANA' is unsupported"),
            "got: {err}"
        );
    }

    #[test]
    fn destination_rule_subset_tls_is_parsed_and_warns() {
        // Per-subset trafficPolicy.tls is parsed onto the MeshSubset but not
        // yet projected onto a per-subset Upstream-TLS view — surface a warning.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "subsets": [{
                        "name": "v1",
                        "labels": {"version": "v1"},
                        "trafficPolicy": {
                            "tls": {
                                "mode": "SIMPLE",
                                "caCertificates": "/etc/certs/v1-ca.pem"
                            }
                        }
                    }]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let subset = &mesh.destination_rules[0].subsets[0];
        let tls = subset
            .traffic_policy
            .as_ref()
            .expect("subset traffic policy")
            .tls
            .as_ref()
            .expect("subset tls");
        assert_eq!(tls.mode, MtlsMode::Simple);
        assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/v1-ca.pem"));

        // And a translator-level warning surfaced so operators know it isn't
        // applied per-subset on the cold path yet.
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("trafficPolicy.tls is parsed but not yet applied per-subset")),
            "expected per-subset tls warning, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn destination_rule_tls_defaults_to_simple_mode() {
        // Istio defaults `tls.mode` to SIMPLE when the field is omitted from
        // the block. Preserve that semantics.
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "tls": {"caCertificates": "/etc/certs/ca.pem"}
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let tls = mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .expect("traffic policy")
            .tls
            .as_ref()
            .expect("tls block");
        assert_eq!(tls.mode, MtlsMode::Simple);
    }

    // ── Service.spec.ports[].name resolution ──────────────────────────────

    fn service_with_named_ports(name: &str, namespace: &str, ports: &[(&str, u16)]) -> K8sObject {
        let ports_json: Vec<Value> = ports
            .iter()
            .map(|(name, port)| serde_json::json!({"name": name, "port": *port}))
            .collect();
        K8sObject {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                namespace: namespace.to_string(),
                labels: HashMap::new(),
                deletion_timestamp: None,
            },
            spec: serde_json::json!({ "ports": ports_json }),
            status: Value::Object(serde_json::Map::new()),
        }
    }

    fn virtual_service_with_destination(name: &str, destination: Value) -> K8sObject {
        K8sObject {
            api_version: "networking.istio.io/v1".to_string(),
            kind: "VirtualService".to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                namespace: "default".to_string(),
                labels: HashMap::new(),
                deletion_timestamp: None,
            },
            spec: serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/api"}}],
                    "route": [{"destination": destination}]
                }]
            }),
            status: Value::Object(serde_json::Map::new()),
        }
    }

    #[test]
    fn vs_destination_port_name_resolves_against_collected_service() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080), ("grpc", 9090)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );

        let result = translate_k8s_objects(&[svc, vs], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn vs_destination_port_number_still_wins_over_name() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"number": 7777, "name": "http"}
            }),
        );

        let result = translate_k8s_objects(&[svc, vs], options()).expect("translation succeeds");
        // Explicit `number` takes precedence even when both are set.
        assert_eq!(result.config.proxies[0].backend_port, 7777);
    }

    #[test]
    fn vs_destination_port_name_short_host_uses_vs_namespace() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews",
                "port": {"name": "http"}
            }),
        );

        let result = translate_k8s_objects(&[svc, vs], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn vs_destination_port_name_unknown_fails_closed() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "missing-port"}
            }),
        );

        let err = translate_k8s_objects(&[svc, vs], options())
            .expect_err("unknown port name must fail closed");
        assert!(
            err.to_string().contains("missing-port"),
            "error must name the missing port: {err}"
        );
    }

    #[test]
    fn vs_destination_no_port_defaults_to_80() {
        // No port block at all — preserve today's "default to 80" behavior
        // regardless of whether a matching Service exists.
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local"
            }),
        );

        let result = translate_k8s_objects(&[vs], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies[0].backend_port, 80);
    }

    #[test]
    fn service_object_is_not_translated_as_warning() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let result = translate_k8s_objects(&[svc], options()).expect("translation succeeds");
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("Ignoring unsupported Kubernetes resource kind 'Service'")),
            "Service kind must be consumed by the port-name pre-pass, not warned: {:?}",
            result.warnings
        );
    }

    #[test]
    fn vs_destination_port_name_isolates_services_by_namespace() {
        // Two services named `reviews` in different namespaces with the same
        // port name but different port numbers; lookup must resolve against
        // the namespace embedded in the destination host, not the first match.
        let svc_default = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let svc_prod = service_with_named_ports("reviews", "prod", &[("http", 9090)]);
        let vs_default = virtual_service_with_destination(
            "reviews-default",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );
        let mut vs_prod = virtual_service_with_destination(
            "reviews-prod",
            serde_json::json!({
                "host": "reviews.prod.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );
        // Cross-namespace destination is allowed: VS in `default` pointing at
        // a Service in `prod` — must resolve to the prod port number.
        vs_prod.metadata.namespace = "default".to_string();
        let result = translate_k8s_objects(
            &[svc_default, svc_prod, vs_default, vs_prod],
            options().with_source_namespaces(vec!["default".to_string(), "prod".to_string()]),
        )
        .expect("translation succeeds");
        let default_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.id.contains("reviews-default"))
            .expect("default-namespace proxy materialized");
        let prod_proxy = result
            .config
            .proxies
            .iter()
            .find(|p| p.id.contains("reviews-prod"))
            .expect("prod-namespace proxy materialized");
        assert_eq!(default_proxy.backend_port, 8080);
        assert_eq!(prod_proxy.backend_port, 9090);
    }

    #[test]
    fn vs_destination_short_host_isolates_services_by_vs_namespace() {
        // Short host (`reviews`) must inherit the VS's own namespace, NOT the
        // first matching service in any namespace. Two services with the same
        // name in different namespaces; the short-host VS in `prod` must pick
        // the `prod` service.
        let svc_default = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let svc_prod = service_with_named_ports("reviews", "prod", &[("http", 9090)]);
        let mut vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews",
                "port": {"name": "http"}
            }),
        );
        vs.metadata.namespace = "prod".to_string();
        let result = translate_k8s_objects(
            &[svc_default, svc_prod, vs],
            options().with_source_namespaces(vec!["default".to_string(), "prod".to_string()]),
        )
        .expect("translation succeeds");
        assert_eq!(result.config.proxies.len(), 1);
        assert_eq!(result.config.proxies[0].backend_port, 9090);
    }

    #[test]
    fn service_with_unnamed_ports_does_not_panic_and_lookup_misses() {
        // K8s allows Service ports without a `name` field. Those entries are
        // silently skipped by the indexer (no panic, no error). A VS that
        // references such a Service by port name must still fail closed
        // because the name was never indexed.
        let svc = K8sObject {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            metadata: K8sMetadata {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                labels: HashMap::new(),
                deletion_timestamp: None,
            },
            spec: serde_json::json!({
                "ports": [
                    {"port": 8080},                           // no name
                    {"name": "grpc", "port": 9090}            // named entry survives
                ]
            }),
            status: Value::Object(serde_json::Map::new()),
        };
        let vs_missing = virtual_service_with_destination(
            "vs-missing",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );
        let err = translate_k8s_objects(&[svc.clone(), vs_missing], options())
            .expect_err("unnamed Service ports must not satisfy a name lookup");
        assert!(
            err.to_string().contains("http"),
            "error must name the missing port: {err}"
        );

        // The named entry is still indexed and resolvable.
        let vs_grpc = virtual_service_with_destination(
            "vs-grpc",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "grpc"}
            }),
        );
        let result =
            translate_k8s_objects(&[svc, vs_grpc], options()).expect("named entry still resolves");
        assert_eq!(result.config.proxies[0].backend_port, 9090);
    }

    #[test]
    fn service_with_no_ports_field_does_not_panic() {
        // Service objects with no `spec.ports` array at all must not panic
        // the pre-pass — we just index an empty entry.
        let svc = K8sObject {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            metadata: K8sMetadata {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                labels: HashMap::new(),
                deletion_timestamp: None,
            },
            spec: serde_json::json!({}),
            status: Value::Object(serde_json::Map::new()),
        };
        let result =
            translate_k8s_objects(&[svc], options()).expect("Service with no ports must not panic");
        assert!(result.config.proxies.is_empty());
    }

    #[test]
    fn vs_destination_port_name_resolves_with_trailing_dot_fqdn() {
        // Trailing dot is a valid DNS-FQDN form (root anchor); the host parser
        // must treat `reviews.default.svc.cluster.local.` the same as the
        // non-anchored FQDN. Otherwise hand-written Istio configs that copy
        // from `dig` output fail closed for no good reason.
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local.",
                "port": {"name": "http"}
            }),
        );
        let result = translate_k8s_objects(&[svc, vs], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn vs_destination_port_name_resolves_with_svc_only_suffix() {
        // `<svc>.<ns>.svc` (no cluster domain) is another canonical short
        // form Istio docs reference — the parser must take only the first
        // two labels and discard the `.svc` suffix.
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc",
                "port": {"name": "http"}
            }),
        );
        let result = translate_k8s_objects(&[svc, vs], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn service_objects_are_processed_regardless_of_input_order() {
        // The pre-pass design must tolerate arbitrary input order — a
        // VirtualService that appears BEFORE its Service in the input slice
        // must still resolve the port name. Two-pass translation guarantees
        // this, but a regression to single-pass would silently fail closed.
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let result = translate_k8s_objects(&[vs, svc], options()).expect("translation succeeds");
        assert_eq!(result.config.proxies[0].backend_port, 8080);
    }

    #[test]
    fn vs_destination_port_name_rejects_external_host() {
        // External hosts that happen to share a first/second label with a
        // real in-cluster Service must NOT trigger a service lookup. Before
        // this guard, `api.example.com` would silently parse as service=api,
        // namespace=example and either resolve against an unrelated Service
        // or emit a misleading "Service example/api not found" error.
        let svc = service_with_named_ports("api", "example", &[("http", 8080)]);
        let vs = virtual_service_with_destination(
            "external-vs",
            serde_json::json!({
                "host": "api.example.com",
                "port": {"name": "http"}
            }),
        );
        let err = translate_k8s_objects(&[svc, vs], options())
            .expect_err("external host must not be resolved against a Service");
        let msg = err.to_string();
        assert!(
            msg.contains("not a recognized in-cluster service form"),
            "error must explain the host shape rejection: {msg}"
        );
        assert!(
            msg.contains("api.example.com"),
            "error must echo the offending host: {msg}"
        );
    }

    #[test]
    fn vs_destination_port_name_rejects_partial_cluster_suffix() {
        // `<svc>.<ns>.cluster.local` (missing the `.svc.` infix) and
        // `<svc>.<ns>.svc.cluster` (missing the `.local` tail) are NOT valid
        // Kubernetes service DNS forms — accepting them silently encourages
        // operator typos to resolve against real services.
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        for host in [
            "reviews.default.cluster.local",
            "reviews.default.svc.cluster",
            "reviews.default.svc.cluster.local.extra",
        ] {
            let vs = virtual_service_with_destination(
                "reviews-vs",
                serde_json::json!({
                    "host": host,
                    "port": {"name": "http"}
                }),
            );
            let err = translate_k8s_objects(&[svc.clone(), vs], options())
                .err()
                .unwrap_or_else(|| panic!("host '{host}' must be rejected"));
            assert!(
                err.to_string()
                    .contains("not a recognized in-cluster service form"),
                "host '{host}' must hit shape rejection: {err}"
            );
        }
    }

    #[test]
    fn vs_destination_port_name_rejects_empty_labels() {
        // Leading dots, consecutive dots, and lone-dot hosts produce empty
        // labels — the parser must reject these rather than picking the empty
        // string up as a service name.
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        for host in [".reviews", "reviews..default", "."] {
            let vs = virtual_service_with_destination(
                "reviews-vs",
                serde_json::json!({
                    "host": host,
                    "port": {"name": "http"}
                }),
            );
            let err = translate_k8s_objects(&[svc.clone(), vs], options())
                .expect_err("empty-label host must be rejected");
            assert!(
                err.to_string()
                    .contains("not a recognized in-cluster service form"),
                "host '{host}' must hit shape rejection: {err}"
            );
        }
    }

    #[test]
    fn vs_destination_port_name_accepts_trailing_dot_on_short_forms() {
        // Trailing dot must apply uniformly across all accepted shapes, not
        // only the 5-label FQDN. Otherwise an operator typing `reviews.` or
        // `reviews.default.` gets an inconsistent rejection vs. the FQDN.
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        for host in [
            "reviews.",
            "reviews.default.",
            "reviews.default.svc.",
            "reviews.default.svc.cluster.local.",
        ] {
            let vs = virtual_service_with_destination(
                "reviews-vs",
                serde_json::json!({
                    "host": host,
                    "port": {"name": "http"}
                }),
            );
            let result = translate_k8s_objects(&[svc.clone(), vs], options())
                .unwrap_or_else(|e| panic!("trailing-dot host '{host}' must resolve: {e}"));
            assert_eq!(result.config.proxies[0].backend_port, 8080);
        }
    }

    #[test]
    fn vs_destination_port_name_resolves_custom_cluster_domain() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let opts = options().with_cluster_domain("corp.example".to_string());
        for host in [
            "reviews.default.svc.corp.example",
            "reviews.default.svc.corp.example.",
        ] {
            let vs = virtual_service_with_destination(
                "reviews-vs",
                serde_json::json!({
                    "host": host,
                    "port": {"name": "http"}
                }),
            );
            let result = translate_k8s_objects(&[svc.clone(), vs], opts.clone())
                .unwrap_or_else(|e| panic!("custom domain host '{host}' must resolve: {e}"));
            assert_eq!(result.config.proxies[0].backend_port, 8080);
        }
    }

    #[test]
    fn vs_destination_port_name_rejects_wrong_cluster_domain() {
        let svc = service_with_named_ports("reviews", "default", &[("http", 8080)]);
        let opts = options().with_cluster_domain("corp.example".to_string());
        let vs = virtual_service_with_destination(
            "reviews-vs",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "port": {"name": "http"}
            }),
        );
        let err = translate_k8s_objects(&[svc, vs], opts)
            .expect_err("cluster.local must be rejected when domain is corp.example");
        let msg = err.to_string();
        assert!(
            msg.contains("not a recognized in-cluster service form"),
            "error must explain shape rejection: {msg}"
        );
        assert!(
            msg.contains("corp.example"),
            "error must show the configured cluster domain: {msg}"
        );
    }

    // ── DestinationRule portLevelSettings ────────────────────────────────

    #[test]
    fn destination_rule_translates_single_port_level_setting() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 8080},
                                "connectionPool": {"tcp": {"connectTimeout": "750ms"}},
                                "loadBalancer": {"simple": "LEAST_REQUEST"}
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let dr = &mesh.destination_rules[0];
        assert_eq!(dr.port_level_settings.len(), 1);
        let policy = dr.port_level_settings.get(&8080).expect("port 8080 entry");
        assert_eq!(policy.connect_timeout_ms, Some(750));
        assert!(matches!(
            policy.load_balancer,
            Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest))
        ));
    }

    #[test]
    fn destination_rule_translates_two_distinct_port_level_settings() {
        let result = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 8080},
                                "connectionPool": {"tcp": {"connectTimeout": "750ms"}},
                                "loadBalancer": {"simple": "LEAST_REQUEST"}
                            },
                            {
                                "port": {"number": 9090},
                                "connectionPool": {"tcp": {"connectTimeout": "2s"}},
                                "loadBalancer": {"simple": "RANDOM"}
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        let dr = &mesh.destination_rules[0];
        assert_eq!(dr.port_level_settings.len(), 2);

        let p8080 = dr.port_level_settings.get(&8080).expect("port 8080 entry");
        assert_eq!(p8080.connect_timeout_ms, Some(750));
        assert!(matches!(
            p8080.load_balancer,
            Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest))
        ));

        let p9090 = dr.port_level_settings.get(&9090).expect("port 9090 entry");
        assert_eq!(p9090.connect_timeout_ms, Some(2000));
        assert!(matches!(
            p9090.load_balancer,
            Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random))
        ));
    }

    #[test]
    fn destination_rule_rejects_port_level_settings_port_out_of_range() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 70000},
                                "connectionPool": {"tcp": {"connectTimeout": "1s"}}
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect_err("port out of range must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("portLevelSettings") && msg.contains("1-65535"),
            "expected port out-of-range error, got {msg}"
        );

        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "port": {"number": 0},
                                "connectionPool": {"tcp": {"connectTimeout": "1s"}}
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect_err("port zero must fail");
        assert!(
            err.to_string().contains("1-65535"),
            "expected port zero error, got {err}"
        );
    }

    #[test]
    fn destination_rule_rejects_port_level_settings_without_port_number() {
        let err = translate_k8s_objects(
            &[object(
                "DestinationRule",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "portLevelSettings": [
                            {
                                "connectionPool": {"tcp": {"connectTimeout": "1s"}}
                            }
                        ]
                    }
                }),
            )],
            options(),
        )
        .expect_err("port.number missing must fail");
        assert!(
            err.to_string().contains("port.number is required"),
            "expected port.number required error, got {err}"
        );
    }

    // ── Sidecar translator ──────────────────────────────────────────────

    #[test]
    fn sidecar_with_workload_selector_and_egress_translates_correctly() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "workloadSelector": {
                        "matchLabels": {"app": "frontend"}
                    },
                    "egress": [
                        {
                            "hosts": [
                                "./reviews.default.svc.cluster.local",
                                "*/external.example.com"
                            ],
                            "port": {"number": 8080}
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        // Sidecar must NOT produce the old Phase-D warning. Port scoping is
        // parsed but not enforced yet, so that unsupported field gets a focused
        // warning instead.
        assert!(
            !result.warnings.iter().any(|w| w.contains("Phase D")),
            "Sidecar translation must not emit the deferred warning; warnings = {:?}",
            result.warnings
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| { w.contains("egress port scoping") && w.contains("host only") }),
            "Sidecar egress port should emit a host-only warning; warnings = {:?}",
            result.warnings
        );

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.sidecars.len(), 1);
        let sc = &mesh.sidecars[0];
        assert_eq!(sc.name, "sample");
        assert_eq!(sc.namespace, "default");
        let selector = sc
            .workload_selector
            .as_ref()
            .expect("workload selector parsed");
        assert_eq!(
            selector.labels.get("app").map(String::as_str),
            Some("frontend")
        );
        assert_eq!(selector.namespace.as_deref(), Some("default"));
        assert!(!sc.egress_inherits_defaults);
        assert_eq!(sc.egress.len(), 1);
        assert_eq!(
            sc.egress[0].hosts,
            vec![
                "./reviews.default.svc.cluster.local".to_string(),
                "*/external.example.com".to_string(),
            ]
        );
        assert_eq!(sc.egress[0].port, Some(8080));
    }

    #[test]
    fn sidecar_without_workload_selector_is_namespace_default() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"hosts": ["./reviews.default.svc.cluster.local"]}
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.sidecars.len(), 1);
        assert!(mesh.sidecars[0].workload_selector.is_none());
        assert!(!mesh.sidecars[0].egress_inherits_defaults);
        assert_eq!(mesh.sidecars[0].egress[0].port, None);
    }

    #[test]
    fn sidecar_with_omitted_egress_inherits_outbound_defaults() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "workloadSelector": {"matchLabels": {"app": "frontend"}},
                    "ingress": [
                        {"port": {"number": 8080, "protocol": "HTTP", "name": "http"}}
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.sidecars.len(), 1);
        assert!(mesh.sidecars[0].egress_inherits_defaults);
        assert!(mesh.sidecars[0].egress.is_empty());
    }

    #[test]
    fn sidecar_translator_emits_no_warning_for_valid_resource() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"hosts": ["*/*"]}
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        assert!(
            result.warnings.is_empty(),
            "valid Sidecar must produce no warnings; got {:?}",
            result.warnings
        );
    }

    #[test]
    fn sidecar_in_root_namespace_emits_scope_warning() {
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"hosts": ["*/*"]}
                    ]
                }),
            )],
            options().with_istio_root_namespace("default".to_string()),
        )
        .expect("translation succeeds");

        assert!(
            result
                .warnings
                .iter()
                .any(|w| { w.contains("root namespace") && w.contains("namespace-local") }),
            "root namespace Sidecar should emit scope warning; got {:?}",
            result.warnings
        );
    }

    #[test]
    fn sidecar_with_empty_workload_selector_matchlabels_is_namespace_default() {
        // workloadSelector present but matchLabels empty → treat as no
        // selector. Mirrors Istio: a Sidecar with an empty selector applies
        // to every workload in the namespace (i.e. namespace-default).
        let result = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "workloadSelector": {"matchLabels": {}},
                    "egress": [
                        {"hosts": ["*/*"]}
                    ]
                }),
            )],
            options(),
        )
        .expect("translation succeeds");

        let mesh = result.config.mesh.expect("mesh config");
        assert_eq!(mesh.sidecars.len(), 1);
        assert!(
            mesh.sidecars[0].workload_selector.is_none(),
            "empty matchLabels should round-trip to no selector"
        );
    }

    #[test]
    fn sidecar_with_invalid_port_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {
                            "hosts": ["./svc.default.svc.cluster.local"],
                            "port": {"number": 0}
                        }
                    ]
                }),
            )],
            options(),
        )
        .expect_err("port 0 should be rejected");
        assert!(
            err.to_string().contains("Sidecar egress[].port.number"),
            "error must reference the field; got {err}"
        );
    }

    #[test]
    fn sidecar_egress_missing_hosts_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"port": {"number": 8080}}
                    ]
                }),
            )],
            options(),
        )
        .expect_err("missing hosts should be rejected");
        assert!(
            err.to_string().contains("Sidecar egress[].hosts"),
            "error must reference hosts; got {err}"
        );
    }

    #[test]
    fn sidecar_egress_empty_hosts_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"hosts": []}
                    ]
                }),
            )],
            options(),
        )
        .expect_err("empty hosts should be rejected");
        assert!(
            err.to_string().contains("Sidecar egress[].hosts"),
            "error must reference hosts; got {err}"
        );
    }

    #[test]
    fn sidecar_egress_non_string_hosts_rejected() {
        let err = translate_k8s_objects(
            &[object(
                "Sidecar",
                serde_json::json!({
                    "egress": [
                        {"hosts": ["./svc.default.svc.cluster.local", 42]}
                    ]
                }),
            )],
            options(),
        )
        .expect_err("non-string hosts should be rejected");
        assert!(
            err.to_string().contains("Sidecar egress[].hosts"),
            "error must reference hosts; got {err}"
        );
    }
}
