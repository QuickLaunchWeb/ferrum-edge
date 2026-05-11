//! `mesh_route_dispatch` — rewrites the routing decision per request based on
//! method/header/query-param predicates.
//!
//! This plugin closes the Istio `VirtualService.http[].match` header/method
//! gap without extending the `Proxy` schema with new routing dimensions. One
//! `Proxy` is emitted per `(hosts, listen_path)` group; the per-match
//! conditions (method, headers, query params) become `mesh_route_dispatch`
//! rules attached as a proxy-scoped plugin. At request time the plugin walks
//! its rule list and — when a rule matches — sets one or more of
//! `RequestContext.route_override_{upstream_id, backend_host, backend_port}`.
//! The dispatch path picks those up after the `before_proxy` phase via
//! `RequestContext::apply_route_overrides`, which bakes the overrides into a
//! fresh `Arc<Proxy>` so every downstream pool key, capability-registry
//! lookup, circuit-breaker target key, and URL construction sees the
//! effective destination.
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

use crate::plugins::{Plugin, PluginResult, RequestContext, priority};

/// Top-level config for the plugin.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MeshRouteDispatchConfig {
    /// Ordered list of rules. First match wins; rules with no match criteria
    /// are rejected at config-load time to avoid silently-overriding catch-alls.
    #[serde(default)]
    pub rules: Vec<RouteRule>,
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
}

impl RouteDestination {
    fn is_empty(&self) -> bool {
        self.upstream_id.is_none() && self.backend_host.is_none() && self.backend_port.is_none()
    }
}

#[derive(Debug)]
pub struct MeshRouteDispatch {
    config: MeshRouteDispatchConfig,
}

impl MeshRouteDispatch {
    pub fn new(config: &serde_json::Value) -> Result<Self, String> {
        let parsed: MeshRouteDispatchConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("mesh_route_dispatch config: {e}"))?;
        if parsed.rules.is_empty() {
            return Err("mesh_route_dispatch.rules cannot be empty".to_string());
        }
        for (idx, rule) in parsed.rules.iter().enumerate() {
            if rule.destination.is_empty() {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination requires at least one of \
                     upstream_id / backend_host / backend_port"
                ));
            }
            if let Some(port) = rule.destination.backend_port
                && port == 0
            {
                return Err(format!(
                    "mesh_route_dispatch.rules[{idx}].destination.backend_port must be 1-65535"
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

#[async_trait]
impl Plugin for MeshRouteDispatch {
    fn name(&self) -> &str {
        "mesh_route_dispatch"
    }

    fn priority(&self) -> u16 {
        priority::MESH_ROUTE_DISPATCH
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        for rule in &self.config.rules {
            if rule_matches(&rule.match_, ctx, headers) {
                if let Some(id) = &rule.destination.upstream_id {
                    ctx.route_override_upstream_id = Some(id.clone());
                }
                if let Some(host) = &rule.destination.backend_host {
                    ctx.route_override_backend_host = Some(host.clone());
                }
                if let Some(port) = rule.destination.backend_port {
                    ctx.route_override_backend_port = Some(port);
                }
                return PluginResult::Continue;
            }
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
        // A rule with no match criteria would always fire and effectively
        // pin every request to its destination. `new()` rejects this at
        // config load — defense in depth here.
        return false;
    }
    if !m.methods.is_empty()
        && !m
            .methods
            .iter()
            .any(|method| ctx.method.eq_ignore_ascii_case(method))
    {
        return false;
    }
    for (name, expected) in &m.headers {
        // `before_proxy` receives the in-flight header map; `ctx.headers`
        // may have been moved out by the dispatcher. Read from the
        // parameter; canonicalize the key by lowercasing once.
        let key = name.to_ascii_lowercase();
        match headers.get(key.as_str()) {
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
        assert!(err.contains("1-65535"), "got: {err}");
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
    async fn header_match_routes_to_canary() {
        let plugin = MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"headers": {"x-canary": "v2"}},
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
                "destination": {"backend_host": "canary.svc"}
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
                "destination": {"backend_host": "canary.svc"}
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
}
