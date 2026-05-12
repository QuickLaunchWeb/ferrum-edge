use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::identity::spiffe::SpiffeId;
use crate::modes::mesh::config::{
    AccessLogFilter, AppProtocol, ConditionMatch, JwtHeader, MeshAccessLoggingConfig,
    MeshConsistentHash, MeshDestinationRule, MeshEndpoint, MeshJwtRule, MeshLoadBalancer,
    MeshMetricsConfig, MeshOutlierDetection, MeshPolicy, MeshProxyConfig,
    MeshRequestAuthentication, MeshRule, MeshSimpleLb, MeshSubset, MeshTelemetryConfig,
    MeshTelemetryResource, MeshTracingConfig, MeshTrafficPolicy, MeshTrafficPolicyTls,
    MetricTagOverride, MtlsMode, PeerAuthentication, PolicyAction, PolicyScope, PrincipalMatch,
    RequestMatch, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
    TagOverrideOperation, Workload, WorkloadPort, WorkloadSelector,
};

use super::{
    K8sAccumulator, K8sObject, K8sTranslateError, K8sTranslationOptions, RouteBackend,
    RouteProxySpec, SourceKind, exact_path_listen_path, fault_injection_plugin_for_proxy,
    invalid_resource, optional_port_field, parse_istio_duration_ms, port_from_u64, proxy_for_route,
    resource_id, selector_from_istio, string_array, string_field, string_map, upstream_for_route,
};
use crate::config::types::{BackendScheme, MAX_TARGET_WEIGHT, PluginConfig, RetryConfig};

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
        subsets,
    })
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

type VsRouteResult = (
    Vec<crate::config::types::Proxy>,
    Vec<crate::config::types::Upstream>,
    Vec<PluginConfig>,
);

fn virtual_service_routes(
    object: &K8sObject,
    acc: &mut K8sAccumulator,
) -> Result<VsRouteResult, K8sTranslateError> {
    let hosts = string_array(&object.spec, "hosts");
    let mut proxies = Vec::new();
    let mut upstreams = Vec::new();
    let mut plugins = Vec::new();

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

        let retry = route_retry_config(http);
        let timeout_ms = route_timeout_ms(http);

        let match_count = match_paths.len();
        for (match_index, listen_path) in match_paths.into_iter().enumerate() {
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
                plugins.push(plugin);
            }

            proxies.push(proxy_for_route(RouteProxySpec {
                id: proxy_id,
                namespace: object.metadata.namespace.clone(),
                hosts: hosts.clone(),
                listen_path,
                strip_listen_path: false,
                backend_host: backend_host.clone(),
                backend_port,
                upstream_id: upstream_id.clone(),
                backend_scheme: BackendScheme::Http,
                listen_port: None,
                retry: retry.clone(),
                backend_read_timeout_ms: timeout_ms,
            }));
        }
    }

    Ok((proxies, upstreams, plugins))
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
    match acc.lookup_service_port(&ns, &svc, name) {
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

/// Parse an Istio destination host into `(service_name, namespace)`.
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
fn service_host_components(
    host: &str,
    default_namespace: &str,
    cluster_domain: &str,
) -> Option<(String, String)> {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    if trimmed.is_empty() {
        return None;
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    match labels.as_slice() {
        [svc] => Some(((*svc).to_string(), default_namespace.to_string())),
        [svc, ns] => Some(((*svc).to_string(), (*ns).to_string())),
        [svc, ns, "svc"] => Some(((*svc).to_string(), (*ns).to_string())),
        [svc, ns, "svc", domain_labels @ ..] if !domain_labels.is_empty() => {
            let suffix = domain_labels.join(".");
            if suffix.eq_ignore_ascii_case(cluster_domain) {
                Some(((*svc).to_string(), (*ns).to_string()))
            } else {
                None
            }
        }
        _ => None,
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
                },
                spec: serde_json::json!({"tracing": {"sampling": 5.0}}),
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
                },
                spec: serde_json::json!({
                    "selector": {"matchLabels": {"app": "api"}},
                    "tracing": {"sampling": 50.0}
                }),
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
                    },
                    spec: serde_json::json!({
                        "selector": {"matchLabels": {"app": "api"}},
                        "tracing": {"sampling": 99.0}
                    }),
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
            },
            spec: serde_json::json!({ "ports": ports_json }),
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
            },
            spec: serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/api"}}],
                    "route": [{"destination": destination}]
                }]
            }),
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
            },
            spec: serde_json::json!({
                "ports": [
                    {"port": 8080},                           // no name
                    {"name": "grpc", "port": 9090}            // named entry survives
                ]
            }),
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
            },
            spec: serde_json::json!({}),
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
}
