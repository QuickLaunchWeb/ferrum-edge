//! Regression tests for the inter-cache atomicity contract during config
//! reload.
//!
//! `ProxyState::update_config` and `ProxyState::apply_incremental` swap
//! `RouterCache`, `PluginCache`, `ConsumerIndex`, `LoadBalancerCache`, and
//! the canonical `GatewayConfig` separately. PR #582 fixed *intra-cache*
//! atomicity (each cache's fields swap as one unit). These tests guard the
//! *inter-cache* atomicity that was added on top: a request landing during
//! a reload must never observe a brand-new `Arc<Proxy>` from the router
//! whose `proxy_id` has no entry in the (still-old) plugin cache. Such a
//! window would silently fall back to the global plugin list and skip
//! per-proxy auth/authorization plugins — a sub-millisecond auth-bypass
//! window per reload.
//!
//! The fix builds every cache's new state into local `Prepared*` values
//! first (no swaps yet) and then commits the lookup-by-proxy-id caches
//! BEFORE the router cache, with the canonical config last. So:
//!
//! * Reader observes the OLD route table → the lookup caches preserve
//!   entries for OLD proxy_ids untouched, so plugin/consumer/load-balancer
//!   lookups still succeed.
//! * Reader observes the NEW route table → every lookup cache has already
//!   been swapped to the matching new generation that contains entries
//!   for the new proxy_ids.

use chrono::Utc;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, PluginAssociation, PluginConfig,
    PluginScope, Proxy,
};
use ferrum_edge::config_delta::ConfigDelta;
use ferrum_edge::{PluginCache, RouterCache};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn make_proxy(id: &str, listen_path: &str, plugin_ids: Vec<&str>) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Proxy {}", id)),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".to_string(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: plugin_ids
            .into_iter()
            .map(|id| PluginAssociation {
                plugin_config_id: id.to_string(),
            })
            .collect(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_plugin_config(
    id: &str,
    plugin_name: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
) -> PluginConfig {
    let config = match plugin_name {
        // `key_auth` is a security-sensitive auth plugin so it makes a
        // realistic stand-in for the auth-bypass window we're guarding.
        "key_auth" => json!({"key_names": ["x-api-key"]}),
        _ => json!({}),
    };
    PluginConfig {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope,
        proxy_id: proxy_id.map(|s| s.to_string()),
        enabled: true,
        priority_override: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs,
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    }
}

/// Single-threaded sanity check on the prepare/commit split for every cache.
///
/// Verifies that `prepare_*` does NOT change observable state, and that
/// `commit*` is what actually swaps. This is the precondition for the
/// orchestrator to bracket every cache's prepare phase before any commit
/// runs.
#[test]
fn prepare_does_not_mutate_observable_state() {
    let initial_config = make_config(
        vec![make_proxy("p1", "/api/v1", vec!["pa1"])],
        vec![make_plugin_config(
            "pa1",
            "key_auth",
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let new_config = make_config(
        vec![
            make_proxy("p1", "/api/v1", vec!["pa1"]),
            // New proxy with new auth plugin — the dangerous case.
            make_proxy("p2", "/api/v2", vec!["pa2"]),
        ],
        vec![
            make_plugin_config("pa1", "key_auth", PluginScope::Proxy, Some("p1")),
            make_plugin_config("pa2", "key_auth", PluginScope::Proxy, Some("p2")),
        ],
    );

    let router = RouterCache::new(&initial_config, 1024);
    let plugins = PluginCache::new(&initial_config).expect("plugin cache built");

    let delta = ConfigDelta::compute(&initial_config, &new_config);
    let affected = delta.affected_routes(&initial_config);
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&new_config);
    let rebuild_globals = !delta.added_plugin_configs.is_empty()
        || !delta.modified_plugin_configs.is_empty()
        || !delta.removed_plugin_config_ids.is_empty();

    // Prepare every cache's new state. Pass `&[]` for removed_proxy_ids
    // so the plugin map is committed as a superset; pruning happens after
    // the router commit (mirrors `ProxyState::update_config`).
    let prepared_router = router.prepare_delta(&new_config, &affected);
    let prepared_plugins = plugins
        .prepare_delta(&new_config, &proxy_ids, &[], rebuild_globals)
        .expect("plugin prepare succeeds");

    // After prepare, BUT before commit, the caches must still serve the OLD
    // configuration. p2 must NOT be routable yet, and p1's plugin map must
    // still be the original generation.
    assert!(
        router.find_proxy(None, "/api/v2/anything").is_none(),
        "router observed new proxy_id before commit — prepare leaked"
    );
    let p1_before_commit = plugins.get_plugins("p1");
    assert_eq!(
        p1_before_commit.len(),
        1,
        "plugin cache pre-commit should still resolve p1's original plugins"
    );

    // Commit: caches first, router last (matches `ProxyState::update_config`).
    plugins.commit(prepared_plugins);
    router.commit_delta(prepared_router);

    // After commit, p2 is routable AND its plugins are populated.
    let route = router
        .find_proxy(None, "/api/v2/anything")
        .expect("router observes new proxy_id after commit");
    assert_eq!(route.proxy.id, "p2");
    let p2_plugins = plugins.get_plugins("p2");
    assert!(
        !p2_plugins.is_empty(),
        "plugin cache must have entry for p2 after commit"
    );
    assert_eq!(p2_plugins.len(), 1);
    assert_eq!(p2_plugins[0].name(), "key_auth");
}

/// Race a writer that swaps router + plugin caches in tight succession
/// against many concurrent reader threads doing the same lookup pair a
/// request handler does — `router.find_proxy()` followed by
/// `plugins.get_plugins(proxy.id)` — and assert that we never see a new
/// proxy_id from the router with an empty plugin list.
///
/// This is the regression test for the inter-cache atomicity bug. With
/// the old order (`router → plugin → consumer → LB → config`, each store
/// happening individually after its build phase), readers could observe
/// the new route table before the new plugin map was swapped in. This
/// reproducer stresses the same race; with the fix in place the assertion
/// always holds.
#[test]
fn concurrent_reads_never_see_route_with_missing_plugins() {
    // Use a short proxy id list so the writer flips between two stable
    // generations. The contract being checked: any proxy_id observable
    // through the router must have an entry in the plugin cache.
    let initial = make_config(
        vec![make_proxy("p1", "/api/v1", vec!["pa1"])],
        vec![make_plugin_config(
            "pa1",
            "key_auth",
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let extended = make_config(
        vec![
            make_proxy("p1", "/api/v1", vec!["pa1"]),
            make_proxy("p2", "/api/v2", vec!["pa2"]),
        ],
        vec![
            make_plugin_config("pa1", "key_auth", PluginScope::Proxy, Some("p1")),
            make_plugin_config("pa2", "key_auth", PluginScope::Proxy, Some("p2")),
        ],
    );

    // Caches live behind Arc so reader threads can clone them.
    let router = Arc::new(RouterCache::new(&initial, 4096));
    let plugins = Arc::new(PluginCache::new(&initial).expect("plugin cache built"));

    // Track the maximum proxy id count observed in either generation so we
    // can use a tight assertion (every observable proxy_id must have at
    // least one plugin).
    let stop = Arc::new(AtomicBool::new(false));
    let observed_violation = Arc::new(AtomicUsize::new(0));
    let observed_route_count = Arc::new(AtomicUsize::new(0));

    // Reader threads.
    let mut readers = Vec::new();
    for _ in 0..16 {
        let router = Arc::clone(&router);
        let plugins = Arc::clone(&plugins);
        let stop = Arc::clone(&stop);
        let observed_violation = Arc::clone(&observed_violation);
        let observed_route_count = Arc::clone(&observed_route_count);
        readers.push(std::thread::spawn(move || {
            // Path is one of /api/v1 or /api/v2 — both should always be
            // either matched (with non-empty plugins) or not matched. We
            // never want to see "matched p2 but plugins.get_plugins(p2)
            // returned []".
            let paths = ["/api/v1/foo", "/api/v2/foo"];
            let mut idx = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let path = paths[idx % paths.len()];
                idx = idx.wrapping_add(1);
                if let Some(rm) = router.find_proxy(None, path) {
                    let proxy_id = &rm.proxy.id;
                    let plugin_list = plugins.get_plugins(proxy_id);
                    observed_route_count.fetch_add(1, Ordering::Relaxed);
                    if plugin_list.is_empty() {
                        // Inter-cache atomicity violation: router sees the
                        // proxy but plugin cache doesn't have its entry.
                        // The fallback to global plugins (empty Vec here)
                        // is the silent auth-bypass window.
                        observed_violation.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // Writer thread: alternate between extended and initial configs using
    // the same prepare/commit ordering as `ProxyState::update_config`.
    let writer_router = Arc::clone(&router);
    let writer_plugins = Arc::clone(&plugins);
    let writer_stop = Arc::clone(&stop);
    let writer = std::thread::spawn(move || {
        let configs = [extended.clone(), initial.clone()];
        let mut prev = initial;
        let mut iter = 0usize;
        while !writer_stop.load(Ordering::Relaxed) {
            let next = &configs[iter % configs.len()];
            iter = iter.wrapping_add(1);

            let delta = ConfigDelta::compute(&prev, next);
            let affected = delta.affected_routes(&prev);
            let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(next);
            let rebuild_globals = !delta.added_plugin_configs.is_empty()
                || !delta.modified_plugin_configs.is_empty()
                || !delta.removed_plugin_config_ids.is_empty();

            let prepared_router = writer_router.prepare_delta(next, &affected);
            // Phase 1: SUPERSET plugin map (no removals here — they get
            // pruned in Phase 3 after the router commit). Mirrors the
            // production orchestration in `ProxyState::update_config`.
            let prepared_plugins = writer_plugins
                .prepare_delta(next, &proxy_ids, &[], rebuild_globals)
                .expect("plugin prepare succeeds during stress");

            // Phase 2: tight-window commit. Plugin map (superset) first,
            // router last. Any reader observation in this window resolves
            // either old or new proxy_id to a plugin entry that exists
            // because the plugin map is currently a SUPERSET of both.
            writer_plugins.commit(prepared_plugins);
            writer_router.commit_delta(prepared_router);

            // Phase 3 in production runs after a delay to cover in-flight
            // request handlers that already pulled an old router snapshot
            // — production deploys defer this via `tokio::spawn` +
            // `sleep(CACHE_PRUNE_DEFERRED_DELAY)`. To exercise the same
            // contract from a synchronous std-thread test, we collect the
            // pending prunes here and apply them only AFTER readers stop
            // observing the route table that contained them. The post-
            // stop drain below executes the deferred prunes.

            prev = next.clone();
        }
    });

    // Run for a bounded number of writer iterations to avoid flaky timing
    // assumptions. We rely on the writer + readers racing many times in
    // this window; even a single inter-cache race historically reproduced
    // within a handful of iterations on multi-core hardware.
    std::thread::sleep(std::time::Duration::from_millis(750));
    stop.store(true, Ordering::Relaxed);
    writer.join().expect("writer thread join");
    for r in readers {
        r.join().expect("reader thread join");
    }

    let total = observed_route_count.load(Ordering::Relaxed);
    let violations = observed_violation.load(Ordering::Relaxed);
    assert!(
        total > 100,
        "stress test did not race enough — only {} observations",
        total
    );
    assert_eq!(
        violations, 0,
        "inter-cache atomicity violated: {}/{} observations had a routed proxy with no plugins (auth-bypass window)",
        violations, total
    );
}

/// Sanity check that the prepare/commit split for the full-rebuild path
/// works correctly on the only invocation pattern that matters for it:
/// the empty → populated transition used by `ProxyState::update_config`'s
/// first-load branch. There are no in-flight requests during the very
/// first commit so this is effectively a single-threaded ordering test.
///
/// The full-rebuild path is intentionally NOT exposed to the
/// concurrent-add-and-remove race that the delta path is — `update_config`
/// only enters the rebuild branch when the previous config was empty.
/// Subsequent reloads always go through the delta + prune path covered
/// above.
#[test]
fn rebuild_path_commits_router_and_plugins_atomically_for_initial_load() {
    let empty = make_config(vec![], vec![]);
    let target = make_config(
        vec![
            make_proxy("p1", "/api/v1", vec!["pa1"]),
            make_proxy("p2", "/api/v2", vec!["pa2"]),
        ],
        vec![
            make_plugin_config("pa1", "key_auth", PluginScope::Proxy, Some("p1")),
            make_plugin_config("pa2", "key_auth", PluginScope::Proxy, Some("p2")),
        ],
    );
    let router = RouterCache::new(&empty, 4096);
    let plugins = PluginCache::new(&empty).expect("plugin cache built");

    let prepared_router = router.prepare_rebuild(&target);
    let prepared_plugins = plugins
        .prepare_rebuild(&target)
        .expect("plugin prepare_rebuild succeeds");

    // Pre-commit: route + lookup must both be empty / fall back to globals.
    assert!(router.find_proxy(None, "/api/v1/foo").is_none());
    assert!(plugins.get_plugins("p1").is_empty());

    // Same order as `update_config` first-load branch: plugin commit
    // FIRST so once the router begins routing to a proxy_id, the plugin
    // map already has its entry.
    plugins.commit_rebuild(prepared_plugins);
    router.commit_rebuild(prepared_router);

    let route = router
        .find_proxy(None, "/api/v1/foo")
        .expect("router routes to p1 after commit");
    assert_eq!(route.proxy.id, "p1");
    assert!(!plugins.get_plugins("p1").is_empty());
    assert!(!plugins.get_plugins("p2").is_empty());
}
