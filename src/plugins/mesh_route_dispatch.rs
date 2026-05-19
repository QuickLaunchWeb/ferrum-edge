//! `mesh_route_dispatch` — rewrites the routing decision per request based on
//! method/header/query-param predicates.
//!
//! This plugin closes the Istio `VirtualService.http[].match` header/method
//! gap without extending the `Proxy` schema with new routing dimensions. One
//! `Proxy` is emitted per `(hosts, listen_path)` group; the per-match
//! conditions (method, headers, query params) become `mesh_route_dispatch`
//! rules attached as a proxy-scoped plugin. At request time the plugin walks
//! its rule list and — when a rule matches — sets one or more of
//! `RequestContext.route_override_{upstream_id, backend_host, backend_port, resolved_tls}`
//! and optionally publishes per-rule
//! `route_override_{request,response}_transform` lists for the request /
//! response transformer plugins to apply after their own static rules.
//! The dispatch path picks those up after the `before_proxy` phase via
//! `RequestContext::apply_route_overrides`, which bakes the overrides into a
//! fresh `Arc<Proxy>` so every downstream pool key, capability-registry
//! lookup, circuit-breaker target key, and URL construction sees the
//! effective destination.
//! When multiple plugin instances run on one proxy, each matching instance
//! replaces the complete override destination set by earlier instances; a
//! non-matching instance leaves any prior override intact. Per-rule
//! `backend_tls` is intentionally direct-backend-only. `upstream_id`
//! destinations inherit TLS material from the referenced `Upstream` (including
//! mesh `DestinationRule` TLS projection), so per-canary TLS for upstream
//! overrides should be modeled as distinct upstream resources.
//!
//! The plugin intentionally runs after authentication, authorization, and
//! rate limiting. Those admission decisions use the public listener proxy
//! identity; only downstream `before_proxy` plugins and backend dispatch see
//! the effective override destination. WebSocket support applies to the
//! HTTP upgrade handshake destination only — once upgraded, a WebSocket
//! connection stays pinned to that backend and is not re-routed per frame.
//! HBONE CONNECT traffic now flows through the standard `before_proxy` chain
//! before the HBONE relay branch in `proxy/mod.rs`, so this plugin can
//! match on the outer CONNECT request (method, headers, query params) and
//! set `route_override_*` fields that `handle_hbone_request` consumes via
//! `apply_route_overrides_with_upstreams`. Once the upgrade succeeds, the
//! HBONE tunnel is a transparent TCP relay — inner H2 frames are not
//! re-classified per stream, mirroring the post-upgrade WebSocket pinning.
//!
//! ## Wire compatibility
//!
//! Old data planes that lack this plugin will receive a `create_plugin`
//! warning and skip the instance, preserving the existing "drop the
//! header/method match" behavior. The CP can emit the plugin instances
//! unconditionally — they're a no-op on old binaries.
//! `retry_disabled` / `timeout_disabled` are intentionally build-out-era
//! additive config: older DPs that do know this plugin but do not know those
//! fields will ignore them, so operators must upgrade DPs before relying on
//! collapsed routes that clear inherited retry or timeout policy.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::types::{
    BackendTlsConfig, MAX_BACKEND_HOST_LENGTH, MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES, RetryConfig,
    normalize_backend_tls_san_allow_list_entry, validate_backend_tls_san_allow_list_entry,
    validate_backend_tls_sni,
};
use crate::plugins::utils::route_header_transform::{
    RawRouteHeaderTransformRule, RouteHeaderTransformRule, parse_route_header_transforms,
};
use crate::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, priority,
};

/// Top-level config for the plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRouteDispatchConfig {
    /// Ordered list of rules. First match wins; rules with no match criteria
    /// are rejected at config-load time to avoid silently-overriding catch-alls.
    #[serde(default)]
    pub rules: Vec<RouteRule>,
    /// When `true`, requests that match no rule are rejected with 404 instead
    /// of falling through to the proxy's default backend. The Istio
    /// VirtualService translator sets this so a route with `match.method=GET`
    /// does not serve POST traffic via the proxy's default backend (which
    /// would silently violate VS match semantics). Defaults to `false` for
    /// operators who configure the plugin directly as a soft override.
    #[serde(default)]
    pub reject_unmatched: bool,
}

impl MeshRouteDispatchConfig {
    pub fn from_value(config: &Value) -> Result<Self, String> {
        serde_json::from_value(config.clone())
            .map_err(|e| format!("mesh_route_dispatch config: {e}"))
    }

    pub fn from_value_normalized(config: &Value) -> Result<Self, String> {
        let mut parsed = Self::from_value(config)?;
        parsed.normalize_and_validate()?;
        Ok(parsed)
    }

    pub fn references_upstream_id(&self, upstream_id: &str) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.destination.upstream_id.as_deref() == Some(upstream_id))
    }

    fn normalize_and_validate(&mut self) -> Result<(), String> {
        if self.rules.is_empty() {
            return Err("mesh_route_dispatch.rules cannot be empty".to_string());
        }
        for (idx, rule) in self.rules.iter_mut().enumerate() {
            normalize_header_match_keys(idx, &mut rule.match_.headers)?;
            // Empty match is normally rejected because it would silently
            // shadow later rules. The exception is a "transform catch-all":
            // a rule emitted by the K8s VirtualService translator for a
            // URI-only `match.uri` whose http[] carries header transforms.
            // Such a rule has no routing effect (its destination is the
            // proxy's default) but carries the per-rule transform Arcs.
            // `rule_matches` treats empty match as "match all" only when
            // transforms are present, so this stays a no-op for any other
            // operator config.
            let has_transforms =
                !rule.request_transform.is_empty() || !rule.response_transform.is_empty();
            if rule.match_.is_empty() && !has_transforms {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].match requires at least one of \
                     methods / headers / query_params (an empty match would silently \
                     never fire, contradicting first-match-wins semantics)"
                ));
            }
            if rule.destination.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination requires upstream_id or \
                     a direct backend override (backend_host and backend_port); backend_tls \
                     may only accompany a direct backend"
                ));
            }
            if rule.retry.is_some() && rule.retry_disabled {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}] cannot set both retry and retry_disabled"
                ));
            }
            if rule.timeout_ms.is_some() && rule.timeout_disabled {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}] cannot set both timeout_ms and timeout_disabled"
                ));
            }
            if let Some(retry) = &rule.retry
                && let Err(errors) = retry.validate_fields()
            {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].retry: {}",
                    errors.join("; ")
                ));
            }
            if let Some(port) = rule.destination.backend_port
                && port == 0
            {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.backend_port must be non-zero"
                ));
            }
            if let Some(host) = rule.destination.backend_host.as_mut() {
                let trimmed = host.trim();
                if trimmed.is_empty() {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{idx}].destination.backend_host must not be empty"
                    ));
                }
                if trimmed.len() > MAX_BACKEND_HOST_LENGTH {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{idx}].destination.backend_host must not exceed {MAX_BACKEND_HOST_LENGTH} characters"
                    ));
                }
                if trimmed.contains("://") {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{idx}].destination.backend_host must not contain a scheme"
                    ));
                }
                if trimmed.chars().any(char::is_whitespace) {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{idx}].destination.backend_host must not contain whitespace"
                    ));
                }
                *host = trimmed.to_ascii_lowercase();
            }
            let has_backend_host = rule.destination.backend_host.is_some();
            let has_backend_port = rule.destination.backend_port.is_some();
            if rule.destination.upstream_id.is_some()
                && (has_backend_host || has_backend_port || rule.destination.backend_tls.is_some())
            {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.upstream_id cannot be \
                     combined with backend_host / backend_port / backend_tls"
                ));
            }
            if has_backend_host != has_backend_port {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.backend_host and \
                     backend_port must be set together for direct-backend overrides"
                ));
            }
            if rule.destination.backend_tls.is_some() && !(has_backend_host && has_backend_port) {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.backend_tls requires \
                     backend_host and backend_port so TLS overrides only apply to a direct backend"
                ));
            }
            if let Some(tls) = rule.destination.backend_tls.as_mut() {
                normalize_and_validate_backend_tls(idx, tls)?;
            }
            rule.request_transform_compiled =
                compile_transform_field(idx, "request_transform", &rule.request_transform)?;
            rule.response_transform_compiled =
                compile_transform_field(idx, "response_transform", &rule.response_transform)?;
            rule.methods_compiled = compile_method_matchers(idx, &rule.match_.methods)?;
            rule.headers_compiled = compile_header_matchers(idx, &rule.match_.headers)?;
        }
        Ok(())
    }
}

fn compile_transform_field(
    rule_idx: usize,
    field: &str,
    raw: &[RawRouteHeaderTransformRule],
) -> Result<Option<Arc<Vec<RouteHeaderTransformRule>>>, String> {
    if raw.is_empty() {
        return Ok(None);
    }
    let context = format!("mesh_route_dispatch.rules[{rule_idx}].{field}");
    let parsed = parse_route_header_transforms(raw, &context)?;
    Ok(Some(Arc::new(parsed)))
}

fn normalize_and_validate_backend_tls(
    rule_idx: usize,
    tls: &mut BackendTlsConfig,
) -> Result<(), String> {
    let has_client_cert = tls
        .client_cert_path
        .as_deref()
        .is_some_and(|path| !path.is_empty());
    let has_client_key = tls
        .client_key_path
        .as_deref()
        .is_some_and(|path| !path.is_empty());
    if has_client_cert != has_client_key {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].destination.backend_tls.client_cert_path \
             and client_key_path must be set together"
        ));
    }

    if let Some(sni) = tls.sni.as_mut() {
        validate_backend_tls_sni(sni).map_err(|e| {
            format!("mesh_route_dispatch.rules[{rule_idx}].destination.backend_tls.sni: {e}")
        })?;
        *sni = sni.to_ascii_lowercase();
    }

    if tls.san_allow_list.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES {
        return Err(format!(
            "mesh_route_dispatch.rules[{rule_idx}].destination.backend_tls.san_allow_list \
             must not have more than {MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES} entries (got {})",
            tls.san_allow_list.len()
        ));
    }
    for (san_idx, san) in tls.san_allow_list.iter_mut().enumerate() {
        validate_backend_tls_san_allow_list_entry(san).map_err(|e| {
            format!(
                "mesh_route_dispatch.rules[{rule_idx}].destination.backend_tls.san_allow_list[{san_idx}]: {e}"
            )
        })?;
        normalize_backend_tls_san_allow_list_entry(san);
    }
    tls.recompute_san_digest();

    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteRule {
    /// Match criteria — all configured fields must match for the rule to fire.
    #[serde(default, rename = "match")]
    pub match_: MatchCriteria,
    /// What to override on a matching request. At least one override field
    /// MUST be set; otherwise the rule would be a no-op.
    pub destination: RouteDestination,
    /// Override the proxy's backend response/read timeout for this rule.
    /// Istio `VirtualService.http[].timeout` is projected here when route
    /// candidates are collapsed into a shared Ferrum proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Explicitly clear the selected proxy's backend response/read timeout
    /// for this rule. Translator-generated collapsed rules use this when the
    /// source VirtualService route omits `timeout`, because Istio's default is
    /// timeout-disabled and the selected fallback proxy may carry a timeout.
    #[serde(default, skip_serializing_if = "is_false")]
    pub timeout_disabled: bool,
    /// Override the proxy's retry policy for this rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryConfig>,
    /// Explicitly clear the selected proxy's retry policy for this rule.
    /// Translator-generated collapsed rules use this to prevent a later
    /// fallback route's retry policy from leaking onto an earlier route.
    #[serde(default, skip_serializing_if = "is_false")]
    pub retry_disabled: bool,
    /// Optional request-header transforms applied by `request_transformer`
    /// after its own static rules when this rule matches. Projects Istio
    /// `VirtualService.http[].headers.request.{set,add,remove}` onto each
    /// emitted dispatch rule. Operators may also configure these directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_transform: Vec<RawRouteHeaderTransformRule>,
    /// Optional response-header transforms applied by `response_transformer`
    /// after its own static rules when this rule matches. Counterpart to
    /// `request_transform`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_transform: Vec<RawRouteHeaderTransformRule>,
    /// Pre-compiled `request_transform` rules, built during normalize so the
    /// hot path clones an `Arc` pointer (not the rule list) on every match.
    /// `None` when `request_transform` is empty.
    #[serde(skip)]
    request_transform_compiled: Option<Arc<Vec<RouteHeaderTransformRule>>>,
    /// Pre-compiled `response_transform` rules; counterpart to
    /// `request_transform_compiled`.
    #[serde(skip)]
    response_transform_compiled: Option<Arc<Vec<RouteHeaderTransformRule>>>,
    /// Pre-compiled per-method matchers built during normalize. `Regex`
    /// values are compiled here, not per request — the hot path only does
    /// `matchers.iter().any(|m| m.matches(ctx.method.as_str()))`. Empty when
    /// `match.methods` is empty (no method restriction).
    #[serde(skip)]
    methods_compiled: Vec<MethodMatcher>,
    /// Pre-compiled per-header matchers built during normalize. `Regex`
    /// values are compiled here, not per request — the hot path only does
    /// `HashMap::get(name).is_some_and(|v| matcher.matches(v))`.
    /// Empty when `match.headers` is empty.
    #[serde(skip)]
    headers_compiled: HashMap<String, HeaderMatcher>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchCriteria {
    /// HTTP methods (any-of). Empty = no method restriction. Each entry is
    /// one of:
    ///
    /// - a plain string — interpreted as an `Exact` match (back-compat with
    ///   the original `Vec<String>` shape);
    /// - an object with exactly one of `exact` / `prefix` / `regex` — the
    ///   Istio `StringMatch` shape, projected from VirtualService translation.
    ///
    /// HTTP methods are conventionally uppercase ASCII (RFC 9110 §9.1). The
    /// translator preserves operator casing on the wire, but the plugin
    /// uppercases `prefix` / `regex` patterns at compile time so the hot
    /// path can do a single case-sensitive compare against the request
    /// method without per-request casing work. `Exact` keeps the operator's
    /// literal casing to preserve the existing `method_match_is_case_sensitive`
    /// contract.
    ///
    /// Regexes compile at config-load time (cold path); the hot path reads
    /// the pre-compiled `Regex` from the rule's `methods_compiled` slot.
    #[serde(default)]
    pub methods: Vec<MethodMatchOp>,
    /// Header matches (all-of). Header names are case-insensitive. The value
    /// shape is one of:
    ///
    /// - a plain string — interpreted as an `Exact` match (back-compat with
    ///   the original `HashMap<String, String>` shape);
    /// - an object with exactly one of `exact` / `prefix` / `regex` — the
    ///   Istio `StringMatch` shape, projected from VirtualService translation.
    ///
    /// Regexes compile at config-load time (cold path); the hot path reads
    /// the pre-compiled `Regex` from the rule's `headers_compiled` slot.
    #[serde(default)]
    pub headers: HashMap<String, HeaderMatchOp>,
    /// Query parameter equality matches (all-of). Names and values match
    /// exactly after percent-decoding (the gateway materializes
    /// `ctx.query_params` from the raw query string).
    #[serde(default)]
    pub query_params: HashMap<String, String>,
}

impl MatchCriteria {
    fn is_empty(&self) -> bool {
        self.methods.is_empty() && self.headers.is_empty() && self.query_params.is_empty()
    }
}

/// Per-method match operator. Mirrors the Istio `StringMatch` shape (one of
/// `exact` / `prefix` / `regex`), with an extra wire-compat arm for the
/// legacy plain-string form (`["GET", "POST"]` → two `Exact` entries).
///
/// Serde-untagged so JSON round-trips byte-identical for both shapes:
/// a plain-string method entry deserializes (and re-serializes) as the legacy
/// form; the tagged form deserializes (and re-serializes) as the
/// `StringMatch` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MethodMatchOp {
    /// Back-compat form: bare string, interpreted as `Exact`.
    Legacy(String),
    /// Tagged form: `{ "exact" | "prefix" | "regex": "..." }`.
    Tagged(MethodStringMatch),
}

/// Tagged `StringMatch` for HTTP method matchers — exactly one of `exact`,
/// `prefix`, or `regex` may be present. `deny_unknown_fields` rejects e.g.
/// typos like `{"prefiks": "..."}` at config-load time rather than silently
/// ignoring them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MethodStringMatch {
    Exact(String),
    Prefix(String),
    Regex(String),
}

/// Compiled hot-path representation of a `MethodMatchOp`. Regexes are stored
/// as `Regex` (compiled once at config load); exact/prefix keep an owned
/// `String` value. `Clone` is cheap because the `regex` crate's `Regex` is
/// `Arc`-backed internally and clones are refcount bumps, not pattern
/// recompiles.
///
/// `Prefix` and `Regex` are uppercased at compile time (methods are
/// conventionally uppercase ASCII per RFC 9110 §9.1) so the hot path is a
/// single case-sensitive compare against the request method. `Exact` retains
/// the operator's casing exactly so `method_match_is_case_sensitive` stays
/// truthful — operators who write `"get"` continue to match only literal
/// `"get"` requests, never `"GET"`.
#[derive(Debug, Clone)]
pub(crate) enum MethodMatcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

impl MethodMatcher {
    fn matches(&self, method: &str) -> bool {
        match self {
            MethodMatcher::Exact(expected) => method == expected.as_str(),
            MethodMatcher::Prefix(prefix) => method.starts_with(prefix.as_str()),
            MethodMatcher::Regex(re) => re.is_match(method),
        }
    }
}

/// Per-header match operator. Mirrors the Istio `StringMatch` shape (one of
/// `exact` / `prefix` / `regex`), with an extra wire-compat arm for the
/// legacy plain-string form (`{"x-canary": "v2"}` → `Exact("v2")`).
///
/// Serde-untagged so JSON round-trips byte-identical for both shapes:
/// a plain-string header value deserializes (and re-serializes) as the legacy
/// form; the tagged form deserializes (and re-serializes) as the
/// `StringMatch` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HeaderMatchOp {
    /// Back-compat form: bare string, interpreted as `Exact`.
    Legacy(String),
    /// Tagged form: `{ "exact" | "prefix" | "regex": "..." }`.
    Tagged(HeaderStringMatch),
}

/// Tagged `StringMatch` for headers — exactly one of `exact`, `prefix`, or
/// `regex` may be present. `deny_unknown_fields` rejects e.g. typos like
/// `{"prefiks": "..."}` at config-load time rather than silently ignoring them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HeaderStringMatch {
    Exact(String),
    Prefix(String),
    Regex(String),
}

/// Compiled hot-path representation of a `HeaderMatchOp`. Regexes are stored
/// as `Regex` (compiled once at config load); exact/prefix keep the borrowed
/// reference into the original config string. `Clone` is cheap because the
/// `regex` crate's `Regex` is `Arc`-backed internally and clones are
/// refcount bumps, not pattern recompiles.
#[derive(Debug, Clone)]
pub(crate) enum HeaderMatcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

impl HeaderMatcher {
    fn matches(&self, value: &str) -> bool {
        match self {
            HeaderMatcher::Exact(expected) => value == expected.as_str(),
            HeaderMatcher::Prefix(prefix) => value.starts_with(prefix.as_str()),
            HeaderMatcher::Regex(re) => re.is_match(value),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteDestination {
    /// Override the proxy's `upstream_id`. Wins over `proxy.upstream_id`
    /// at upstream-target selection time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_id: Option<String>,
    /// Override the proxy's `backend_host`. Wins over `proxy.backend_host`.
    /// Pool keys partition by the effective host, so two rules with
    /// different `backend_host` values get distinct backend connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_host: Option<String>,
    /// Override the proxy's `backend_port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_port: Option<u16>,
    /// Override the proxy's resolved backend TLS materials when the rule
    /// routes to a direct backend that uses different mTLS settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls: Option<BackendTlsConfig>,
}

impl RouteDestination {
    fn is_empty(&self) -> bool {
        self.upstream_id.is_none()
            && self.backend_host.is_none()
            && self.backend_port.is_none()
            && self.backend_tls.is_none()
    }
}

#[derive(Debug)]
pub struct MeshRouteDispatch {
    config: MeshRouteDispatchConfig,
}

impl MeshRouteDispatch {
    pub fn new(config: &serde_json::Value) -> Result<Self, String> {
        let parsed = MeshRouteDispatchConfig::from_value_normalized(config)?;
        Ok(Self { config: parsed })
    }

    /// Public for tests.
    #[cfg(test)]
    pub fn rules(&self) -> &[RouteRule] {
        &self.config.rules
    }
}

fn normalize_header_match_keys(
    rule_idx: usize,
    headers: &mut HashMap<String, HeaderMatchOp>,
) -> Result<(), String> {
    if headers.is_empty() {
        return Ok(());
    }

    let mut normalized = HashMap::with_capacity(headers.len());
    for (name, expected) in std::mem::take(headers) {
        let key = name.to_ascii_lowercase();
        if normalized.insert(key.clone(), expected).is_some() {
            return Err(format!(
                "mesh_route_dispatch.rules[{rule_idx}].match.headers contains duplicate \
                 header `{key}` after ASCII case normalization"
            ));
        }
    }
    *headers = normalized;
    Ok(())
}

/// Compile each per-method matcher once, at config load. Regex compilation is
/// the cold-path work; the request hot path only calls `Regex::is_match`.
/// Invalid regex (or an empty pattern after the operator-provided string) is a
/// hard error from `Plugin::new()`, per CLAUDE.md's "no Ok-with-runtime-panic"
/// plugin-config-validation rule.
///
/// HTTP methods are conventionally uppercase ASCII (RFC 9110 §9.1). `Prefix`
/// and `Regex` patterns are uppercased here at compile time so the hot path
/// can do a single case-sensitive compare against the request method.
/// `Exact` deliberately preserves the operator's casing so the existing
/// `method_match_is_case_sensitive` test continues to pass (operators who
/// write `"get"` continue to match only literal `"get"` requests).
fn compile_method_matchers(
    rule_idx: usize,
    methods: &[MethodMatchOp],
) -> Result<Vec<MethodMatcher>, String> {
    let mut compiled = Vec::with_capacity(methods.len());
    for (op_idx, op) in methods.iter().enumerate() {
        let matcher = match op {
            MethodMatchOp::Legacy(value) => MethodMatcher::Exact(value.clone()),
            MethodMatchOp::Tagged(MethodStringMatch::Exact(value)) => {
                MethodMatcher::Exact(value.clone())
            }
            MethodMatchOp::Tagged(MethodStringMatch::Prefix(prefix)) => {
                if prefix.is_empty() {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.methods[{op_idx}].prefix \
                         must not be empty (every method would match — likely a misconfiguration)"
                    ));
                }
                MethodMatcher::Prefix(prefix.to_ascii_uppercase())
            }
            MethodMatchOp::Tagged(MethodStringMatch::Regex(pattern)) => {
                if pattern.is_empty() {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.methods[{op_idx}].regex \
                         must not be empty"
                    ));
                }
                let uppercased = pattern.to_ascii_uppercase();
                let re = Regex::new(&uppercased).map_err(|e| {
                    format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.methods[{op_idx}].regex \
                         is invalid: {e}"
                    )
                })?;
                MethodMatcher::Regex(re)
            }
        };
        compiled.push(matcher);
    }
    Ok(compiled)
}

/// Compile each per-header matcher once, at config load. Regex compilation is
/// the cold-path work; the request hot path only calls `Regex::is_match`.
/// Invalid regex (or an empty pattern after the operator-provided string) is a
/// hard error from `Plugin::new()`, per CLAUDE.md's "no Ok-with-runtime-panic"
/// plugin-config-validation rule.
fn compile_header_matchers(
    rule_idx: usize,
    headers: &HashMap<String, HeaderMatchOp>,
) -> Result<HashMap<String, HeaderMatcher>, String> {
    let mut compiled = HashMap::with_capacity(headers.len());
    for (name, op) in headers {
        let matcher = match op {
            HeaderMatchOp::Legacy(value) => HeaderMatcher::Exact(value.clone()),
            HeaderMatchOp::Tagged(HeaderStringMatch::Exact(value)) => {
                HeaderMatcher::Exact(value.clone())
            }
            HeaderMatchOp::Tagged(HeaderStringMatch::Prefix(prefix)) => {
                if prefix.is_empty() {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.headers[`{name}`].prefix \
                         must not be empty (every value would match — likely a misconfiguration)"
                    ));
                }
                HeaderMatcher::Prefix(prefix.clone())
            }
            HeaderMatchOp::Tagged(HeaderStringMatch::Regex(pattern)) => {
                if pattern.is_empty() {
                    return Err(format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.headers[`{name}`].regex \
                         must not be empty"
                    ));
                }
                let re = Regex::new(pattern).map_err(|e| {
                    format!(
                        "mesh_route_dispatch.rules[{rule_idx}].match.headers[`{name}`].regex \
                         is invalid: {e}"
                    )
                })?;
                HeaderMatcher::Regex(re)
            }
        };
        compiled.insert(name.clone(), matcher);
    }
    Ok(compiled)
}

#[async_trait]
impl Plugin for MeshRouteDispatch {
    fn name(&self) -> &str {
        "mesh_route_dispatch"
    }

    fn priority(&self) -> u16 {
        priority::MESH_ROUTE_DISPATCH
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        // Istio `VirtualService.http[]` covers HTTP, gRPC, and WebSocket
        // upgrade requests. The dispatch shadow runs on all three before
        // backend selection, so the override channel applies uniformly.
        // Defaulting to HTTP-only would silently drop predicates for
        // gRPC and WS — the plugin would never run on those protocols.
        HTTP_FAMILY_PROTOCOLS
    }

    fn requires_decoded_query_params(&self) -> bool {
        self.config
            .rules
            .iter()
            .any(|rule| !rule.match_.query_params.is_empty())
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        for rule in &self.config.rules {
            if rule_matches(rule, ctx, headers) {
                // Route overrides are a whole-destination decision, not a
                // field-wise merge. If an earlier plugin instance matched,
                // this matching instance intentionally replaces all four
                // fields; if this instance does not match, any earlier
                // override remains in place for soft/fallback composition.
                ctx.route_override_upstream_id = rule.destination.upstream_id.clone();
                ctx.route_override_backend_host = rule.destination.backend_host.clone();
                ctx.route_override_backend_port = rule.destination.backend_port;
                ctx.route_override_resolved_tls = rule.destination.backend_tls.clone();
                // `timeout_disabled: true` (with `timeout_ms = None`) maps to
                // `Some(0)`: the proxy hot path interprets `backend_read_timeout_ms == 0`
                // as "no timeout" (see `proxy/mod.rs` and `proxy/tcp_proxy.rs` —
                // every dispatch site guards on `backend_read_timeout_ms > 0`). The
                // explicit `Some(0)` is necessary to override an inherited proxy-level
                // timeout; leaving the field `None` would fall back to that inherited
                // value, which is the opposite of the operator's intent.
                ctx.route_override_backend_read_timeout_ms =
                    if rule.timeout_ms.is_some() || rule.timeout_disabled {
                        Some(rule.timeout_ms.unwrap_or(0))
                    } else {
                        None
                    };
                ctx.route_override_retry = if rule.retry.is_some() || rule.retry_disabled {
                    Some(rule.retry.clone())
                } else {
                    None
                };
                // Per-rule header transforms: publish the pre-compiled Arc
                // so request_transformer / response_transformer can apply
                // them after their own static rules. Cloning an Arc is one
                // atomic refcount bump — cheaper than rebuilding the rule
                // list on every match.
                ctx.route_override_request_transform =
                    rule.request_transform_compiled.as_ref().map(Arc::clone);
                ctx.route_override_response_transform =
                    rule.response_transform_compiled.as_ref().map(Arc::clone);
                return PluginResult::Continue;
            }
        }
        if self.config.reject_unmatched {
            // Istio VirtualService.http[].match semantics: a route gated by
            // `method`/`headers`/`queryParams` must NOT serve requests that
            // miss those predicates. Without this, the proxy's default
            // backend would receive traffic the operator explicitly excluded
            // (e.g., a GET-only canary route serving POST). 404 matches
            // Envoy's behavior when no Istio route matches a request.
            return PluginResult::Reject {
                status_code: 404,
                body: "no route matched mesh_route_dispatch predicates".to_string(),
                headers: HashMap::new(),
            };
        }
        PluginResult::Continue
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn rule_matches(rule: &RouteRule, ctx: &RequestContext, headers: &HashMap<String, String>) -> bool {
    let m = &rule.match_;
    if m.is_empty() {
        // Empty match means "match all". `normalize_and_validate` accepts
        // this only when the rule carries route-level transforms — that
        // narrow shape comes from the K8s VirtualService translator's
        // catch-all rule for URI-only matches. `compile_transform_field`
        // returns `None` for empty input, so an `Arc` is only present when
        // there is at least one rule to apply.
        return rule.request_transform_compiled.is_some()
            || rule.response_transform_compiled.is_some();
    }
    // Method match: any-of across the compiled matchers. Matchers are
    // pre-compiled (regex included) at config load — the hot path is one
    // pass over the matcher slice with a case-sensitive compare per entry.
    if !rule.methods_compiled.is_empty()
        && !rule
            .methods_compiled
            .iter()
            .any(|matcher| matcher.matches(ctx.method.as_str()))
    {
        return false;
    }
    // `before_proxy` receives the in-flight header map; `ctx.headers`
    // may have been moved out by the dispatcher. Config header names are
    // normalized at construction time and matchers are pre-compiled
    // (regex included) — the hot path is one HashMap lookup plus the
    // matcher op per configured header.
    for (name, matcher) in &rule.headers_compiled {
        match headers.get(name.as_str()) {
            Some(actual) if matcher.matches(actual) => {}
            _ => return false,
        }
    }
    for (name, expected) in &m.query_params {
        match ctx.query_params.get(name.as_str()) {
            Some(actual) if actual == expected => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_with(method: &str, path: &str) -> RequestContext {
        RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            path.to_string(),
        )
    }

    #[test]
    fn rejects_empty_rules() {
        let err = MeshRouteDispatch::new(&json!({"rules": []})).unwrap_err();
        assert!(err.contains("cannot be empty"), "got: {err}");
    }

    #[test]
    fn rejects_rule_with_empty_match_criteria() {
        // A rule with `match: {}` would never fire (defense-in-depth in
        // `rule_matches`) but accepting it would let operator misconfig
        // silently disable header/method routing without an error.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {}, "destination": {"upstream_id": "x"}}]
        }))
        .unwrap_err();
        assert!(err.contains("match requires at least one"), "got: {err}");
    }

    #[test]
    fn rejects_rule_with_missing_match_field() {
        // Omitting `match` entirely is also caught (defaults to empty
        // MatchCriteria via `#[serde(default)]`).
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"destination": {"upstream_id": "x"}}]
        }))
        .unwrap_err();
        assert!(err.contains("match requires at least one"), "got: {err}");
    }

    #[test]
    fn normalizes_header_match_keys_at_load() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Canary": "v2"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();

        assert!(
            plugin.rules()[0].match_.headers.contains_key("x-canary"),
            "configured header keys should be normalized once, not per request"
        );
    }

    #[test]
    fn rejects_duplicate_header_matches_after_normalization() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Canary": "v2", "x-canary": "v3"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap_err();

        assert!(err.contains("duplicate header"), "got: {err}");
    }

    #[test]
    fn rejects_timeout_ms_with_timeout_disabled() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "timeout_ms": 250,
                "timeout_disabled": true
            }]
        }))
        .unwrap_err();

        assert!(
            err.contains("cannot set both timeout_ms and timeout_disabled"),
            "got: {err}"
        );
    }

    #[test]
    fn declares_http_family_protocols() {
        // Istio VirtualService.http[] covers HTTP/gRPC/WebSocket. The
        // plugin must apply to all three or it silently drops predicates
        // for non-plain-HTTP requests.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();
        let protocols = plugin.supported_protocols();
        assert!(protocols.contains(&ProxyProtocol::Http));
        assert!(protocols.contains(&ProxyProtocol::Grpc));
        assert!(protocols.contains(&ProxyProtocol::WebSocket));
    }

    #[test]
    fn rejects_destination_with_no_override_fields() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {"methods": ["GET"]}, "destination": {}}]
        }))
        .unwrap_err();
        assert!(err.contains("upstream_id"), "got: {err}");
        assert!(err.contains("direct backend"), "got: {err}");
        assert!(err.contains("backend_tls"), "got: {err}");
    }

    #[test]
    fn rejects_destination_with_zero_port() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {"methods": ["GET"]}, "destination": {"backend_port": 0}}]
        }))
        .unwrap_err();
        assert!(err.contains("non-zero"), "got: {err}");
    }

    #[test]
    fn rejects_destination_with_empty_backend_host() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_host": "", "backend_port": 443}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("backend_host must not be empty"), "got: {err}");
    }

    #[test]
    fn normalizes_direct_backend_host_at_load() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_host": "  Canary.SVC.Cluster.Local  ", "backend_port": 443}
            }]
        }))
        .unwrap();

        assert_eq!(
            plugin.rules()[0].destination.backend_host.as_deref(),
            Some("canary.svc.cluster.local")
        );
    }

    #[test]
    fn rejects_backend_host_without_backend_port() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_host": "canary.svc"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("must be set together"), "got: {err}");
    }

    #[test]
    fn rejects_backend_port_without_backend_host() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_port": 9090}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("must be set together"), "got: {err}");
    }

    #[test]
    fn rejects_upstream_id_combined_with_direct_backend() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "upstream_id": "canary",
                    "backend_host": "canary.svc",
                    "backend_port": 9090
                }
            }]
        }))
        .unwrap_err();
        assert!(err.contains("cannot be combined"), "got: {err}");
    }

    #[test]
    fn rejects_backend_tls_client_cert_without_key() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "canary.svc",
                    "backend_port": 443,
                    "backend_tls": {"client_cert_path": "/certs/client.pem"}
                }
            }]
        }))
        .unwrap_err();

        assert!(err.contains("must be set together"), "got: {err}");
    }

    #[test]
    fn normalizes_backend_tls_identity_fields_and_recomputes_san_digest() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "canary.svc",
                    "backend_port": 443,
                    "backend_tls": {
                        "sni": "Reviews.Mesh.Internal",
                        "san_allow_list": [
                            "Ratings.Mesh.Internal",
                            "spiffe://cluster.local/ns/default/sa/reviews",
                            "10.0.0.8"
                        ]
                    }
                }
            }]
        }))
        .unwrap();

        let tls = plugin.rules()[0]
            .destination
            .backend_tls
            .as_ref()
            .expect("backend_tls override");
        assert_eq!(tls.sni.as_deref(), Some("reviews.mesh.internal"));
        assert_eq!(
            tls.san_allow_list,
            vec![
                "ratings.mesh.internal".to_string(),
                "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
                "10.0.0.8".to_string(),
            ]
        );
        assert_eq!(
            tls.san_allow_list_key_digest,
            BackendTlsConfig::compute_san_digest(&tls.san_allow_list),
            "route-local backend_tls must be ready for pool-key emission"
        );
    }

    #[test]
    fn rejects_backend_tls_invalid_sni_and_san_allow_list() {
        let sni_err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "canary.svc",
                    "backend_port": 443,
                    "backend_tls": {"sni": "10.0.0.8"}
                }
            }]
        }))
        .unwrap_err();
        assert!(sni_err.contains("backend_tls.sni"), "got: {sni_err}");

        let san_err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "canary.svc",
                    "backend_port": 443,
                    "backend_tls": {"san_allow_list": ["https://not-spiffe.example"]}
                }
            }]
        }))
        .unwrap_err();
        assert!(
            san_err.contains("backend_tls.san_allow_list[0]"),
            "got: {san_err}"
        );
    }

    #[test]
    fn rejects_backend_tls_without_direct_backend() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_tls": {"verify_server_cert": false}
                }
            }]
        }))
        .unwrap_err();
        assert!(err.contains("requires"), "got: {err}");
        assert!(err.contains("backend_host"), "got: {err}");
        assert!(err.contains("backend_port"), "got: {err}");
    }

    #[test]
    fn rejects_upstream_id_combined_with_backend_tls() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "upstream_id": "canary",
                    "backend_tls": {"verify_server_cert": false}
                }
            }]
        }))
        .unwrap_err();
        assert!(err.contains("cannot be combined"), "got: {err}");
    }

    #[tokio::test]
    async fn method_match_routes_to_override_upstream() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
    }

    #[tokio::test]
    async fn method_match_can_clear_backend_read_timeout() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"},
                "timeout_disabled": true
            }]
        }))
        .unwrap();

        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
        assert_eq!(ctx.route_override_backend_read_timeout_ms, Some(0));
    }

    #[tokio::test]
    async fn method_mismatch_falls_through() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn method_match_is_case_sensitive() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["get"]},
                "destination": {"upstream_id": "lowercase"}
            }]
        }))
        .unwrap();

        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());

        let mut ctx = ctx_with("get", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("lowercase"));
    }

    #[tokio::test]
    async fn header_match_routes_to_canary() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Canary": "v2"}},
                "destination": {"backend_host": "canary.svc", "backend_port": 9090}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            ctx.route_override_backend_host.as_deref(),
            Some("canary.svc")
        );
        assert_eq!(ctx.route_override_backend_port, Some(9090));
    }

    #[tokio::test]
    async fn header_absence_falls_through() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-canary": "v2"}},
                "destination": {"backend_host": "canary.svc", "backend_port": 9090}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_backend_host.is_none());
    }

    #[tokio::test]
    async fn header_value_mismatch_falls_through() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-canary": "v2"}},
                "destination": {"backend_host": "canary.svc", "backend_port": 9090}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-canary".to_string(), "v1".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_backend_host.is_none());
    }

    #[tokio::test]
    async fn method_and_header_must_both_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["POST"], "headers": {"x-canary": "v2"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        // Method matches, header missing
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
        // Header matches, method wrong
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
        // Both match
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
    }

    #[tokio::test]
    async fn first_matching_rule_wins() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [
                {"match": {"methods": ["GET"]}, "destination": {"upstream_id": "first"}},
                {"match": {"methods": ["GET"]}, "destination": {"upstream_id": "second"}}
            ]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("first"));
    }

    #[tokio::test]
    async fn later_plugin_match_replaces_prior_route_overrides() {
        let upstream_plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "first"}
            }]
        }))
        .unwrap();
        let direct_backend_plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_host": "direct.svc", "backend_port": 8081}
            }]
        }))
        .unwrap();

        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = upstream_plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("first"));

        let _ = direct_backend_plugin
            .before_proxy(&mut ctx, &mut headers)
            .await;
        assert!(ctx.route_override_upstream_id.is_none());
        assert_eq!(
            ctx.route_override_backend_host.as_deref(),
            Some("direct.svc")
        );
        assert_eq!(ctx.route_override_backend_port, Some(8081));
    }

    #[tokio::test]
    async fn query_param_match_routes() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"query_params": {"variant": "beta"}},
                "destination": {"upstream_id": "beta-upstream"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        ctx.query_params
            .insert("variant".to_string(), "beta".to_string());
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            ctx.route_override_upstream_id.as_deref(),
            Some("beta-upstream")
        );
    }

    #[test]
    fn requires_decoded_query_params_for_query_rules_only() {
        let method_only = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        assert!(
            !method_only.requires_decoded_query_params(),
            "method/header-only routing must not change HTTP/3 query-param materialization"
        );

        let query_rule = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"query_params": {"variant": "beta"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        assert!(query_rule.requires_decoded_query_params());
    }

    #[tokio::test]
    async fn reject_unmatched_returns_404_when_no_rule_matches() {
        // VirtualService semantics: a `match: method=GET` rule must NOT
        // forward POST traffic to the proxy's default backend. With
        // `reject_unmatched: true`, the plugin short-circuits with 404.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }],
            "reject_unmatched": true,
        }))
        .unwrap();
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        match result {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 404);
                assert!(body.contains("no route matched"), "got: {body}");
            }
            other => panic!("expected Reject 404, got {other:?}"),
        }
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn reject_unmatched_continues_when_rule_matches() {
        // `reject_unmatched: true` must NOT reject matching requests —
        // it only fires when every rule misses.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }],
            "reject_unmatched": true,
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("canary"));
    }

    #[tokio::test]
    async fn reject_unmatched_default_false_preserves_fall_through() {
        // Operators configuring the plugin directly (without VirtualService
        // translation) keep today's soft-override behavior unless they
        // explicitly opt in. This protects non-mesh consumers from a
        // breaking semantic change.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn rule_with_request_transform_publishes_arc_on_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "request_transform": [
                    {"operation": "update", "target": "header", "key": "X-Api-Version", "value": "v1"},
                    {"operation": "add",    "target": "header", "key": "X-Trace", "value": "y"},
                    {"operation": "remove", "target": "header", "key": "X-Debug"},
                ]
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        let arc = ctx
            .route_override_request_transform
            .expect("request_transform must be published on match");
        assert_eq!(arc.len(), 3);
        assert!(ctx.route_override_response_transform.is_none());
    }

    #[tokio::test]
    async fn rule_with_response_transform_publishes_arc_on_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "response_transform": [
                    {"operation": "update", "target": "header", "key": "X-Backend", "value": "v1"},
                ]
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_request_transform.is_none());
        let arc = ctx
            .route_override_response_transform
            .expect("response_transform must be published on match");
        assert_eq!(arc.len(), 1);
    }

    #[tokio::test]
    async fn non_matching_rule_does_not_publish_transforms() {
        // A rule with transforms that does not match must not leak its Arcs
        // onto the context (would be applied to the wrong route).
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "request_transform": [
                    {"operation": "update", "target": "header", "key": "X-Api-Version", "value": "v1"},
                ]
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("POST", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_request_transform.is_none());
    }

    #[test]
    fn rejects_invalid_request_transform_rule_at_load() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "request_transform": [
                    {"operation": "update", "target": "header", "key": "X-Inject",
                     "value": "good\r\nX-Injected: 1"}
                ]
            }]
        }))
        .unwrap_err();
        assert!(err.contains("request_transform"), "got: {err}");
        assert!(err.contains("CR or LF"), "got: {err}");
    }

    #[tokio::test]
    async fn empty_match_with_transforms_matches_all() {
        // Translator-generated catch-all for URI-only VirtualService routes:
        // empty match + transforms must publish the transform Arc on every
        // request (the proxy's listen_path filter already gates traffic).
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {},
                "destination": {"backend_host": "v1.svc", "backend_port": 8080},
                "request_transform": [
                    {"operation": "update", "target": "header", "key": "X-Api-Version", "value": "v1"}
                ]
            }]
        }))
        .unwrap();

        for method in ["GET", "POST", "DELETE"] {
            let mut ctx = ctx_with(method, "/v1/anything");
            let mut headers = HashMap::new();
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert!(
                ctx.route_override_request_transform.is_some(),
                "empty-match catch-all must fire for {method}"
            );
        }
    }

    #[test]
    fn rejects_empty_match_without_transforms() {
        // The empty-match exception is narrow: only allowed when transforms
        // are present. A rule with empty match AND no transforms is still
        // rejected (it would be a silent no-op otherwise).
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{"match": {}, "destination": {"upstream_id": "x"}}]
        }))
        .unwrap_err();
        assert!(err.contains("match requires at least one"), "got: {err}");
    }

    #[test]
    fn rejects_request_transform_with_unknown_operation_at_load() {
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "x"},
                "request_transform": [
                    {"operation": "rename", "target": "header", "key": "X", "value": "Y"}
                ]
            }]
        }))
        .unwrap_err();
        assert!(err.contains("request_transform"), "got: {err}");
        assert!(err.contains("add/update/remove"), "got: {err}");
    }

    // ── MethodMatchOp (exact / prefix / regex) ────────────────────────────
    //
    // T1-B.2: VirtualService translation can emit prefix/regex method
    // matchers; the plugin compiles regex at config-load time and the hot
    // path stays one pass over the compiled matcher slice per request.
    // Methods are conventionally uppercase ASCII (RFC 9110 §9.1) — prefix
    // and regex inputs are uppercased at compile time so the matcher does a
    // single case-sensitive compare against the request method without
    // per-request casing work.

    #[test]
    fn accepts_legacy_bare_string_method_entry_as_exact() {
        // Back-compat: a bare string is the existing wire shape — must keep
        // round-tripping byte-identical and evaluate as `Exact`.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let compiled = &plugin.rules()[0].methods_compiled;
        assert_eq!(compiled.len(), 1);
        match &compiled[0] {
            MethodMatcher::Exact(v) => assert_eq!(v, "GET"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_tagged_exact_method_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"exact": "GET"}]},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].methods_compiled[0] {
            MethodMatcher::Exact(v) => assert_eq!(v, "GET"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_prefix_method_match_at_load_and_uppercases_pattern() {
        // The translator preserves operator casing on the wire, but the
        // hot-path compare is case-sensitive: uppercase the prefix at
        // compile time so `"po"` matches `"POST"` / `"PUT"` like the
        // operator intended without per-request casing.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"prefix": "po"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].methods_compiled[0] {
            MethodMatcher::Prefix(p) => assert_eq!(p, "PO"),
            other => panic!("expected Prefix, got {other:?}"),
        }
    }

    #[test]
    fn accepts_regex_method_match_at_load_and_uppercases_pattern() {
        // Same uppercase-at-load contract as Prefix: operator casing is not
        // load-bearing because the request method is uppercase ASCII.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": "^(post|put|patch)$"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        match &plugin.rules()[0].methods_compiled[0] {
            MethodMatcher::Regex(re) => {
                assert!(re.is_match("POST"));
                assert!(re.is_match("PUT"));
                assert!(re.is_match("PATCH"));
                assert!(!re.is_match("GET"));
                assert!(
                    !re.is_match("post"),
                    "regex was uppercased at compile time — \
                     hot path stays case-sensitive against uppercase methods"
                );
            }
            other => panic!("expected Regex, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_regex_method_match_at_load() {
        // CLAUDE.md "Plugin Config Validation": invalid regex MUST be a hard
        // error from `Plugin::new()`, never `Ok` with a runtime panic.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": "["}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("invalid"), "got: {err}");
        assert!(err.contains("methods[0]"), "got: {err}");
        assert!(err.contains("regex"), "got: {err}");
    }

    #[test]
    fn rejects_empty_regex_method_match_at_load() {
        // An empty regex (`""`) matches every method, which is almost always
        // a misconfiguration. Fail loud instead of silently widening traffic.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": ""}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("regex"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_empty_prefix_method_match_at_load() {
        // An empty prefix matches every method, see regex rationale above.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"prefix": ""}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("prefix"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_method_match_operator_at_load() {
        // `deny_unknown_fields` on `MethodStringMatch` catches typos like
        // `{"prefiks": "..."}` at load time so we never compile and ship a
        // rule that silently never fires.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"prefiks": "PO"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("mesh_route_dispatch") || err.contains("unknown"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn regex_method_match_routes_when_method_matches() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": "^(POST|PUT|PATCH)$"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        for method in ["POST", "PUT", "PATCH"] {
            let mut ctx = ctx_with(method, "/api");
            let mut headers = HashMap::new();
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                ctx.route_override_upstream_id.as_deref(),
                Some("writes"),
                "regex must match {method}"
            );
        }
    }

    #[tokio::test]
    async fn regex_method_match_falls_through_when_method_does_not_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"regex": "^(POST|PUT|PATCH)$"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn prefix_method_match_routes_when_method_starts_with_prefix() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"prefix": "PO"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        for method in ["POST", "POLL"] {
            let mut ctx = ctx_with(method, "/api");
            let mut headers = HashMap::new();
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                ctx.route_override_upstream_id.as_deref(),
                Some("writes"),
                "prefix must match {method}"
            );
        }
    }

    #[tokio::test]
    async fn prefix_method_match_falls_through_when_method_does_not_start_with_prefix() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": [{"prefix": "PO"}]},
                "destination": {"upstream_id": "writes"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn mixed_exact_prefix_regex_methods_are_anyed() {
        // Any-of semantics across mixed matcher kinds — a single method match
        // is enough for the rule to fire. Mirrors Istio's `method` predicate
        // (Istio expresses any-of via sibling `match[]` entries; mesh_route
        // _dispatch collapses sibling entries onto one rule when they share
        // the URI scope, so we accept any-of in one rule too).
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "methods": [
                        "GET",
                        {"prefix": "PO"},
                        {"regex": "^DELE.*$"}
                    ]
                },
                "destination": {"upstream_id": "any-match"}
            }]
        }))
        .unwrap();

        for method in ["GET", "POST", "POLL", "DELETE"] {
            let mut ctx = ctx_with(method, "/api");
            let mut headers = HashMap::new();
            let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
            assert_eq!(
                ctx.route_override_upstream_id.as_deref(),
                Some("any-match"),
                "{method} should match one of the matchers"
            );
        }

        // None match → no override.
        let mut ctx = ctx_with("OPTIONS", "/api");
        let mut headers = HashMap::new();
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[test]
    fn legacy_and_tagged_method_form_round_trip_through_serde() {
        // The schema must keep the two wire shapes byte-stable so existing
        // configs deserialize unchanged.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "methods": [
                        "GET",
                        {"regex": "^(POST|PUT)$"}
                    ]
                },
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();

        // The compiled hot-path representation reflects each form correctly.
        let compiled = &plugin.rules()[0].methods_compiled;
        assert_eq!(compiled.len(), 2);
        match &compiled[0] {
            MethodMatcher::Exact(v) => assert_eq!(v, "GET"),
            other => panic!("expected Exact for legacy form, got {other:?}"),
        }
        match &compiled[1] {
            MethodMatcher::Regex(_) => {}
            other => panic!("expected Regex for tagged form, got {other:?}"),
        }

        // The serialized JSON for the raw `MatchCriteria.methods` list keeps
        // the bare string vs object distinction the operator wrote.
        let raw = serde_json::to_value(&plugin.rules()[0].match_.methods).unwrap();
        let arr = raw.as_array().expect("methods array");
        assert_eq!(arr.len(), 2);
        assert!(arr[0].is_string());
        assert_eq!(arr[0].as_str(), Some("GET"));
        assert!(arr[1].is_object());
        assert_eq!(arr[1]["regex"].as_str(), Some("^(POST|PUT)$"));
    }

    // ── HeaderMatchOp (exact / prefix / regex) ────────────────────────────
    //
    // T1-B.1: VirtualService translation can emit prefix/regex header
    // matchers; the plugin compiles regex at config-load time and the hot
    // path stays one HashMap lookup plus the matcher op per header.

    #[test]
    fn accepts_legacy_bare_string_header_value_as_exact() {
        // Back-compat: a bare string is the existing wire shape — must keep
        // round-tripping byte-identical and evaluate as `Exact`.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Canary": "v2"}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        let compiled = &plugin.rules()[0].headers_compiled;
        match compiled.get("x-canary") {
            Some(HeaderMatcher::Exact(v)) => assert_eq!(v, "v2"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_tagged_exact_header_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Canary": {"exact": "v2"}}},
                "destination": {"upstream_id": "canary"}
            }]
        }))
        .unwrap();
        match plugin.rules()[0].headers_compiled.get("x-canary") {
            Some(HeaderMatcher::Exact(v)) => assert_eq!(v, "v2"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn accepts_prefix_header_match_at_load_and_compiles_no_regex() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tenant": {"prefix": "admin-"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        match plugin.rules()[0].headers_compiled.get("x-tenant") {
            Some(HeaderMatcher::Prefix(p)) => assert_eq!(p, "admin-"),
            other => panic!("expected Prefix, got {other:?}"),
        }
    }

    #[test]
    fn accepts_regex_header_match_at_load_and_compiles_once() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tier": {"regex": "^(gold|platinum)$"}}},
                "destination": {"upstream_id": "premium"}
            }]
        }))
        .unwrap();
        match plugin.rules()[0].headers_compiled.get("x-tier") {
            Some(HeaderMatcher::Regex(re)) => {
                assert!(re.is_match("gold"));
                assert!(re.is_match("platinum"));
                assert!(!re.is_match("silver"));
            }
            other => panic!("expected Regex, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_regex_header_match_at_load() {
        // CLAUDE.md "Plugin Config Validation": invalid regex MUST be a hard
        // error from `Plugin::new()`, never `Ok` with a runtime panic.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tier": {"regex": "["}}},
                "destination": {"upstream_id": "premium"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("invalid"), "got: {err}");
        assert!(err.contains("x-tier"), "got: {err}");
        assert!(err.contains("regex"), "got: {err}");
    }

    #[test]
    fn rejects_empty_regex_header_match_at_load() {
        // An empty regex (`""`) matches every value, which is almost always
        // a misconfiguration. Fail loud instead of silently widening traffic.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tier": {"regex": ""}}},
                "destination": {"upstream_id": "premium"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("regex"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_empty_prefix_header_match_at_load() {
        // An empty prefix matches every value, see regex rationale above.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tier": {"prefix": ""}}},
                "destination": {"upstream_id": "premium"}
            }]
        }))
        .unwrap_err();
        assert!(err.contains("prefix"), "got: {err}");
        assert!(err.contains("not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_header_match_operator_at_load() {
        // `deny_unknown_fields` on `HeaderStringMatch` catches typos like
        // `{"prefiks": "..."}` at load time so we never compile and ship a
        // rule that silently never fires.
        let err = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"X-Tier": {"prefiks": "admin-"}}},
                "destination": {"upstream_id": "premium"}
            }]
        }))
        .unwrap_err();
        assert!(
            err.contains("mesh_route_dispatch") || err.contains("unknown"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn regex_header_match_routes_when_value_matches() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-tier": {"regex": "^admin-.*$"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-tier".to_string(), "admin-east".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn regex_header_match_falls_through_when_value_does_not_match() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-tier": {"regex": "^admin-.*$"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-tier".to_string(), "user-east".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn prefix_header_match_routes_when_value_starts_with_prefix() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-tenant": {"prefix": "admin-"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-tenant".to_string(), "admin-acme".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn prefix_header_match_falls_through_when_value_does_not_start_with_prefix() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-tenant": {"prefix": "admin-"}}},
                "destination": {"upstream_id": "admin"}
            }]
        }))
        .unwrap();
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([("x-tenant".to_string(), "user-acme".to_string())]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[tokio::test]
    async fn mixed_exact_prefix_regex_headers_are_anded() {
        // All-of semantics across mixed matcher kinds: each header must
        // independently match. A miss on any one means the rule does not
        // fire — matches Istio's `headers` map semantics.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "headers": {
                        "x-canary": {"exact": "v2"},
                        "x-tenant": {"prefix": "admin-"},
                        "x-tier": {"regex": "^(gold|platinum)$"}
                    }
                },
                "destination": {"upstream_id": "all-match"}
            }]
        }))
        .unwrap();

        // All match → route override applies.
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([
            ("x-canary".to_string(), "v2".to_string()),
            ("x-tenant".to_string(), "admin-acme".to_string()),
            ("x-tier".to_string(), "gold".to_string()),
        ]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("all-match"));

        // Regex miss → fall-through.
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([
            ("x-canary".to_string(), "v2".to_string()),
            ("x-tenant".to_string(), "admin-acme".to_string()),
            ("x-tier".to_string(), "silver".to_string()),
        ]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());

        // Prefix miss → fall-through.
        let mut ctx = ctx_with("GET", "/api");
        let mut headers = HashMap::from([
            ("x-canary".to_string(), "v2".to_string()),
            ("x-tenant".to_string(), "user-acme".to_string()),
            ("x-tier".to_string(), "gold".to_string()),
        ]);
        let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(ctx.route_override_upstream_id.is_none());
    }

    #[test]
    fn legacy_and_tagged_header_form_round_trip_through_serde() {
        // The schema must keep the two wire shapes byte-stable so existing
        // configs deserialize unchanged.
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {
                    "headers": {
                        "x-canary": "v2",
                        "x-tier": {"regex": "^(gold|platinum)$"}
                    }
                },
                "destination": {"upstream_id": "x"}
            }]
        }))
        .unwrap();

        // The compiled hot-path representation reflects each form correctly.
        let compiled = &plugin.rules()[0].headers_compiled;
        match compiled.get("x-canary") {
            Some(HeaderMatcher::Exact(v)) => assert_eq!(v, "v2"),
            other => panic!("expected Exact for legacy form, got {other:?}"),
        }
        match compiled.get("x-tier") {
            Some(HeaderMatcher::Regex(_)) => {}
            other => panic!("expected Regex for tagged form, got {other:?}"),
        }

        // The serialized JSON for the raw `MatchCriteria.headers` map keeps
        // the bare string vs object distinction the operator wrote.
        let raw = serde_json::to_value(&plugin.rules()[0].match_.headers).unwrap();
        assert!(raw["x-canary"].is_string());
        assert!(raw["x-tier"].is_object());
        assert_eq!(raw["x-tier"]["regex"].as_str(), Some("^(gold|platinum)$"));
    }
}
