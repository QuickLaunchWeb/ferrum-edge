//! Tests for `RequestContext::apply_route_overrides` and the `effective_*`
//! helpers — the plumbing that lets `mesh_route_dispatch` rewrite the
//! routing decision per request without mutating the matched `Proxy` in
//! shared `ArcSwap` state.

use std::sync::Arc;

use ferrum_edge::config::types::Proxy;
use ferrum_edge::plugins::RequestContext;

fn test_proxy() -> Arc<Proxy> {
    let p: Proxy = serde_json::from_value(serde_json::json!({
        "backend_host": "stable.svc",
        "backend_port": 8080,
    }))
    .expect("minimal proxy should deserialize");
    Arc::new(p)
}

fn ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    )
}

#[test]
fn no_overrides_returns_same_arc() {
    let proxy = test_proxy();
    let ctx = ctx();
    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert!(
        Arc::ptr_eq(&proxy, &result),
        "no overrides should return the same Arc — no per-request allocation"
    );
}

#[test]
fn upstream_override_swaps_arc_and_sets_upstream_id() {
    let proxy = test_proxy();
    assert!(proxy.upstream_id.is_none());
    let mut ctx = ctx();
    ctx.route_override_upstream_id = Some("canary".to_string());
    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert!(
        !Arc::ptr_eq(&proxy, &result),
        "override should allocate a fresh Arc"
    );
    assert_eq!(result.upstream_id.as_deref(), Some("canary"));
    // Original Arc is untouched — shared ArcSwap state is unaffected.
    assert!(proxy.upstream_id.is_none());
}

#[test]
fn backend_host_and_port_override_apply_to_clone() {
    let proxy = test_proxy();
    let mut ctx = ctx();
    ctx.route_override_backend_host = Some("canary.svc".to_string());
    ctx.route_override_backend_port = Some(9090);
    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(result.backend_host, "canary.svc");
    assert_eq!(result.backend_port, 9090);
    // Original Arc retains template values.
    assert_eq!(proxy.backend_host, "stable.svc");
    assert_eq!(proxy.backend_port, 8080);
}

#[test]
fn partial_override_only_swaps_specified_fields() {
    let proxy = test_proxy();
    let mut ctx = ctx();
    ctx.route_override_backend_host = Some("canary.svc".to_string());
    // No port override.
    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(result.backend_host, "canary.svc");
    assert_eq!(
        result.backend_port, 8080,
        "port should fall back to proxy.backend_port"
    );
}

#[test]
fn has_route_overrides_reflects_field_set() {
    let mut ctx = ctx();
    assert!(!ctx.has_route_overrides());
    ctx.route_override_upstream_id = Some("x".to_string());
    assert!(ctx.has_route_overrides());
    ctx.route_override_upstream_id = None;
    ctx.route_override_backend_port = Some(443);
    assert!(ctx.has_route_overrides());
}

#[test]
fn effective_helpers_match_apply_route_overrides() {
    // The `effective_*` helpers must agree with `apply_route_overrides`
    // — both are paths to the same effective destination.
    let proxy = test_proxy();
    let mut ctx = ctx();
    ctx.route_override_upstream_id = Some("canary".to_string());
    ctx.route_override_backend_host = Some("canary.svc".to_string());
    ctx.route_override_backend_port = Some(9090);

    let overridden = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(
        ctx.effective_upstream_id(&proxy),
        overridden.upstream_id.as_deref()
    );
    assert_eq!(ctx.effective_backend_host(&proxy), overridden.backend_host);
    assert_eq!(ctx.effective_backend_port(&proxy), overridden.backend_port);
}
