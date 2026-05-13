//! `mesh_route_dispatch` — rewrites the routing decision per request based on
//! method/header/query-param predicates.
//!
//! This plugin closes the Istio `VirtualService.http[].match` header/method
//! gap without extending the `Proxy` schema with new routing dimensions. One
//! `Proxy` is emitted per `(hosts, listen_path)` group; the per-match
//! conditions (method, headers, query params) become `mesh_route_dispatch`
//! rules attached as a proxy-scoped plugin. At request time the plugin walks
//! its rule list and — when a rule matches — sets one or more of
//! `RequestContext.route_override_{upstream_id, backend_host, backend_port, resolved_tls}`.
//! The dispatch path picks those up after the `before_proxy` phase via
//! `RequestContext::apply_route_overrides`, which bakes the overrides into a
//! fresh `Arc<Proxy>` so every downstream pool key, capability-registry
//! lookup, circuit-breaker target key, and URL construction sees the
//! effective destination.
//!
//! The plugin intentionally runs after authentication, authorization, and
//! rate limiting. Those admission decisions use the public listener proxy
//! identity; only downstream `before_proxy` plugins and backend dispatch see
//! the effective override destination. WebSocket support applies to the
//! HTTP upgrade handshake destination only — once upgraded, a WebSocket
//! connection stays pinned to that backend and is not re-routed per frame.
//! HBONE CONNECT traffic branches before `before_proxy`, so this plugin does
//! not currently set route overrides for HBONE streams.
//!
//! ## Wire compatibility
//!
//! Old data planes that lack this plugin will receive a `create_plugin`
//! warning and skip the instance, preserving the existing "drop the
//! header/method match" behavior. The CP can emit the plugin instances
//! unconditionally — they're a no-op on old binaries.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::types::BackendTlsConfig;
use crate::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, priority,
};

/// Top-level config for the plugin.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteRule {
    /// Match criteria — all configured fields must match for the rule to fire.
    #[serde(default, rename = "match")]
    pub match_: MatchCriteria,
    /// What to override on a matching request. At least one override field
    /// MUST be set; otherwise the rule would be a no-op.
    pub destination: RouteDestination,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchCriteria {
    /// HTTP methods (any-of). Empty = no method restriction.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Header equality matches (all-of). Header names are case-insensitive;
    /// values match exactly.
    #[serde(default)]
    pub headers: HashMap<String, String>,
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
        let mut parsed: MeshRouteDispatchConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("mesh_route_dispatch config: {e}"))?;
        if parsed.rules.is_empty() {
            return Err("mesh_route_dispatch.rules cannot be empty".to_string());
        }
        for (idx, rule) in parsed.rules.iter_mut().enumerate() {
            normalize_header_match_keys(idx, &mut rule.match_.headers)?;
            if rule.match_.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].match requires at least one of \
                     methods / headers / query_params (an empty match would silently \
                     never fire, contradicting first-match-wins semantics)"
                ));
            }
            if rule.destination.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination requires at least one of \
                     upstream_id / backend_host / backend_port / backend_tls"
                ));
            }
            if let Some(port) = rule.destination.backend_port
                && port == 0
            {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.backend_port must be non-zero"
                ));
            }
            let has_backend_host = rule.destination.backend_host.is_some();
            let has_backend_port = rule.destination.backend_port.is_some();
            if has_backend_host != has_backend_port {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.backend_host and \
                     backend_port must be set together for direct-backend overrides"
                ));
            }
        }
        Ok(Self { config: parsed })
    }

    /// Public for tests / introspection.
    #[allow(dead_code)]
    pub fn rules(&self) -> &[RouteRule] {
        &self.config.rules
    }
}

fn normalize_header_match_keys(
    rule_idx: usize,
    headers: &mut HashMap<String, String>,
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
            if rule_matches(&rule.match_, ctx, headers) {
                ctx.route_override_upstream_id = rule.destination.upstream_id.clone();
                ctx.route_override_backend_host = rule.destination.backend_host.clone();
                ctx.route_override_backend_port = rule.destination.backend_port;
                ctx.route_override_resolved_tls = rule.destination.backend_tls.clone();
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

fn rule_matches(
    m: &MatchCriteria,
    ctx: &RequestContext,
    headers: &HashMap<String, String>,
) -> bool {
    if m.is_empty() {
        // Unreachable in normal config — `new()` rejects empty match at
        // load time. Defense in depth in case a construction path skips
        // the constructor (e.g., a future hot-reload that mutates rules).
        return false;
    }
    if !m.methods.is_empty()
        && !m
            .methods
            .iter()
            .any(|method| ctx.method.as_str() == method.as_str())
    {
        return false;
    }
    for (name, expected) in &m.headers {
        // `before_proxy` receives the in-flight header map; `ctx.headers`
        // may have been moved out by the dispatcher. Config header names are
        // normalized at construction time, so this stays allocation-free.
        match headers.get(name.as_str()) {
            Some(actual) if actual == expected => {}
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
        assert!(err.contains("at least one of"), "got: {err}");
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
}
