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

// ---- Pool-key partitioning -------------------------------------------------
//
// CLAUDE.md mandates that every connection-pool key include every field
// affecting connection identity ("Missing field = pool poisoning"). After
// `apply_route_overrides`, two requests through the SAME matched proxy with
// DIFFERENT override hosts/ports/upstream-ids must land in DIFFERENT pool
// entries. These tests exercise the capability registry and the HTTP/3
// pool key helpers — the same `proxy.backend_host`/`backend_port`/
// `upstream_id` fields that `connection_pool.rs`, `http2_pool.rs`, and
// `grpc_proxy.rs` derive their pool keys from.

#[test]
fn pool_key_partitions_on_backend_host_override() {
    // Two override sets for the SAME matched proxy must produce DIFFERENT
    // capability keys, because the capability registry is keyed by deduped
    // backend identity (`scheme|host|port|...`). If the override didn't
    // partition, both requests would share a registry record and traffic
    // for canary.svc would be classified by the probe of stable.svc.
    use ferrum_edge::proxy::backend_capabilities::capability_key;

    let proxy = test_proxy();
    let mut canary_ctx = ctx();
    canary_ctx.route_override_backend_host = Some("canary.svc".to_string());
    let canary_proxy = canary_ctx.apply_route_overrides(Arc::clone(&proxy));

    let mut stable_ctx = ctx();
    stable_ctx.route_override_backend_host = Some("stable.svc".to_string());
    let stable_proxy = stable_ctx.apply_route_overrides(Arc::clone(&proxy));

    let canary_key = capability_key(&canary_proxy);
    let stable_key = capability_key(&stable_proxy);
    assert_ne!(
        canary_key, stable_key,
        "different backend_host overrides must produce different pool keys — \
         pool-poisoning invariant violated"
    );
}

#[test]
fn pool_key_partitions_on_backend_port_override() {
    use ferrum_edge::proxy::backend_capabilities::capability_key;

    let proxy = test_proxy();
    let mut ctx_a = ctx();
    ctx_a.route_override_backend_port = Some(9090);
    let proxy_a = ctx_a.apply_route_overrides(Arc::clone(&proxy));

    let mut ctx_b = ctx();
    ctx_b.route_override_backend_port = Some(9091);
    let proxy_b = ctx_b.apply_route_overrides(Arc::clone(&proxy));

    let key_a = capability_key(&proxy_a);
    let key_b = capability_key(&proxy_b);
    assert_ne!(
        key_a, key_b,
        "different backend_port overrides must produce different pool keys"
    );
}

#[test]
fn pool_key_matches_baseline_when_no_overrides() {
    // The no-override path must produce the same capability key as the
    // unmodified proxy — guarantees zero behavior change for deployments
    // where the override channel is unused.
    use ferrum_edge::proxy::backend_capabilities::capability_key;

    let proxy = test_proxy();
    let ctx = ctx();
    let unchanged = ctx.apply_route_overrides(Arc::clone(&proxy));

    let baseline_key = capability_key(&proxy);
    let after_apply_key = capability_key(&unchanged);
    assert_eq!(
        baseline_key, after_apply_key,
        "no-override path must produce the baseline pool key"
    );
}

#[test]
fn http3_pool_key_partitions_on_backend_host_override() {
    // The H3 pool key helper takes `&Proxy` so the shadowed override flows
    // through naturally. Different override hosts → different H3 pool slots,
    // matching `Http3ConnectionPool::pool_key`'s contract.
    use ferrum_edge::http3::client::Http3ConnectionPool;

    let proxy = test_proxy();
    let mut canary_ctx = ctx();
    canary_ctx.route_override_backend_host = Some("canary.svc".to_string());
    let canary_proxy = canary_ctx.apply_route_overrides(Arc::clone(&proxy));

    let mut stable_ctx = ctx();
    stable_ctx.route_override_backend_host = Some("stable.svc".to_string());
    let stable_proxy = stable_ctx.apply_route_overrides(Arc::clone(&proxy));

    let canary_key = Http3ConnectionPool::pool_key(&canary_proxy, 0);
    let stable_key = Http3ConnectionPool::pool_key(&stable_proxy, 0);
    assert_ne!(
        canary_key, stable_key,
        "H3 pool key must partition on backend_host override"
    );
}

#[test]
fn http2_pool_key_partitions_on_backend_host_override() {
    use ferrum_edge::proxy::http2_pool::Http2ConnectionPool;

    let proxy = test_proxy();
    let mut canary_ctx = ctx();
    canary_ctx.route_override_backend_host = Some("canary.svc".to_string());
    let canary_proxy = canary_ctx.apply_route_overrides(Arc::clone(&proxy));

    let mut stable_ctx = ctx();
    stable_ctx.route_override_backend_host = Some("stable.svc".to_string());
    let stable_proxy = stable_ctx.apply_route_overrides(Arc::clone(&proxy));

    let canary_key = Http2ConnectionPool::pool_key_for_warmup(&canary_proxy);
    let stable_key = Http2ConnectionPool::pool_key_for_warmup(&stable_proxy);
    assert_ne!(
        canary_key, stable_key,
        "H2 pool key must partition on backend_host override"
    );
}
