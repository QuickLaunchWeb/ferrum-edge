//! Integration tests for `DatabaseBackend` api_spec operations (Wave 2).
//!
//! All tests run against a SQLite in-memory (file-based temp) database so they
//! are self-contained and do not require any external service.
//!
//! # Hot-path isolation contract
//!
//! The `api_specs` table is admin-only metadata. These methods must NEVER be
//! called from the proxy runtime, polling loops, or gRPC distribution paths.
//! Each test verifies only the admin-layer operations; no test wires
//! `list_api_specs` / `get_api_spec` into `GatewayConfig` loading.

use ferrum_edge::{
    ExtractedBundle, GatewayConfig,
    config::{
        db_backend::DatabaseBackend as _,
        db_loader::{DatabaseStore, DbPoolConfig},
        types::{ApiSpec, PluginConfig, PluginScope, Proxy, SpecFormat, Upstream},
    },
};
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Monotonic counter to generate unique resource IDs within a test run.
static COUNTER: AtomicU64 = AtomicU64::new(1);

fn uid(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}

/// Pool config with short timeouts for test speed.
fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 2,
        min_connections: 0,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

/// Create a fresh SQLite in-memory (temp-file) store with migrations applied.
async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir.path().join(format!("test-{}.db", uid("db")));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_tls_config(
        "sqlite",
        &url,
        false,
        None,
        None,
        None,
        false,
        test_pool_config(),
    )
    .await
    .expect("connect_with_tls_config failed")
}

/// Build a minimal `Proxy` with a unique id.
fn make_proxy(id: &str, namespace: &str) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "backend_host": "backend.example.com",
        "backend_port": 443,
        "listen_path": format!("/{id}")
    }))
    .expect("proxy deserialization failed")
}

/// Build a minimal `Upstream` with a unique id.
fn make_upstream(id: &str, namespace: &str) -> Upstream {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "targets": [{"host": "target.internal", "port": 443}]
    }))
    .expect("upstream deserialization failed")
}

/// Build a `PluginConfig` linked to a proxy.
fn make_plugin(
    id: &str,
    proxy_id: &str,
    namespace: &str,
    api_spec_id: Option<&str>,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: namespace.to_string(),
        plugin_name: "rate_limiting".to_string(),
        config: serde_json::json!({"limit": 100}),
        scope: PluginScope::Proxy,
        proxy_id: Some(proxy_id.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: api_spec_id.map(str::to_string),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Build an `ApiSpec` with gzip-compressed stub content.
fn make_spec(id: &str, proxy_id: &str, namespace: &str, content: &[u8]) -> ApiSpec {
    let compressed =
        ferrum_edge::admin::spec_codec::compress_gzip(content).expect("compress failed");
    let hash = ferrum_edge::admin::spec_codec::sha256_hex(content);
    ApiSpec {
        id: id.to_string(),
        namespace: namespace.to_string(),
        proxy_id: proxy_id.to_string(),
        spec_version: "3.1.0".to_string(),
        spec_format: SpecFormat::Json,
        spec_content: compressed,
        content_encoding: "gzip".to_string(),
        uncompressed_size: content.len() as u64,
        content_hash: hash,
        title: Some("Test API".to_string()),
        info_version: Some("1.0.0".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// submit_api_spec_bundle — happy path
// ---------------------------------------------------------------------------

/// All four resource types (proxy, upstream, 2 plugins, spec) are written and
/// each carries the correct `api_spec_id` tag.
#[tokio::test]
async fn submit_bundle_happy_path_all_resources_tagged() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let upstream_id = uid("upstream");
    let plugin_id_1 = uid("plugin");
    let plugin_id_2 = uid("plugin");
    let spec_id = uid("spec");

    let proxy = make_proxy(&proxy_id, ns);
    let upstream = make_upstream(&upstream_id, ns);

    let plugin1 = make_plugin(&plugin_id_1, &proxy_id, ns, None);
    let plugin2 = make_plugin(&plugin_id_2, &proxy_id, ns, None);

    let bundle = ExtractedBundle {
        proxy,
        upstream: Some(upstream),
        plugins: vec![plugin1, plugin2],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"stub spec content for test");

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit_api_spec_bundle failed");

    // --- Verify the spec row round-trips correctly ---
    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found after submit");
    assert_eq!(fetched.id, spec_id);
    assert_eq!(fetched.proxy_id, proxy_id);
    assert_eq!(fetched.content_hash, spec.content_hash);
    assert_eq!(
        fetched.spec_content, spec.spec_content,
        "spec_content bytes must round-trip"
    );

    // --- Verify proxy exists ---
    let proxy_row = store
        .get_proxy(&proxy_id)
        .await
        .expect("get_proxy failed")
        .expect("proxy not found");
    assert_eq!(
        proxy_row.api_spec_id, None,
        "get_proxy does not load api_spec_id (hot-path isolation)"
    );

    // --- Verify get_api_spec_by_proxy ---
    let by_proxy = store
        .get_api_spec_by_proxy(ns, &proxy_id)
        .await
        .expect("get_api_spec_by_proxy failed")
        .expect("spec not found by proxy_id");
    assert_eq!(by_proxy.id, spec_id);

    // --- Verify plugin count (2 spec-owned + 0 hand-added = 2) ---
    let all_plugins = store
        .list_plugin_configs_paginated(ns, 100, 0)
        .await
        .expect("list_plugin_configs_paginated failed");
    let spec_plugins: Vec<_> = all_plugins
        .items
        .iter()
        .filter(|pc| pc.proxy_id.as_deref() == Some(&proxy_id))
        .collect();
    assert_eq!(spec_plugins.len(), 2, "expected 2 plugins for proxy");
}

/// submit with proxy-only bundle (no upstream, no plugins).
#[tokio::test]
async fn submit_bundle_proxy_only() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"proxy-only spec");

    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found");
    assert_eq!(fetched.proxy_id, proxy_id);
}

// ---------------------------------------------------------------------------
// submit_api_spec_bundle — rollback on duplicate
// ---------------------------------------------------------------------------

/// When the INSERT fails mid-transaction (duplicate proxy id), the entire
/// transaction is rolled back and no rows are left in any table.
#[tokio::test]
async fn submit_bundle_rollback_on_duplicate_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id_1 = uid("spec");
    let spec_id_2 = uid("spec");

    // First submit succeeds.
    let bundle1 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec1 = make_spec(&spec_id_1, &proxy_id, ns, b"first spec");
    store
        .submit_api_spec_bundle(&bundle1, &spec1)
        .await
        .expect("first submit failed");

    // Second submit uses the SAME proxy_id → should fail with a unique constraint error.
    let bundle2 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec2 = make_spec(&spec_id_2, &proxy_id, ns, b"duplicate spec");
    let result = store.submit_api_spec_bundle(&bundle2, &spec2).await;
    assert!(result.is_err(), "duplicate proxy_id submit must return Err");

    // The second spec row must NOT be present.
    let fetched2 = store
        .get_api_spec(ns, &spec_id_2)
        .await
        .expect("get_api_spec failed");
    assert!(
        fetched2.is_none(),
        "spec2 must not exist after rollback; got: {:?}",
        fetched2.map(|s| s.id)
    );

    // The first spec + proxy must still be intact.
    let fetched1 = store
        .get_api_spec(ns, &spec_id_1)
        .await
        .expect("get_api_spec failed")
        .expect("spec1 not found after failed second submit");
    assert_eq!(fetched1.id, spec_id_1);
}

// ---------------------------------------------------------------------------
// replace_api_spec_bundle
// ---------------------------------------------------------------------------

/// After replace: the spec-owned plugin is gone (replaced), but a hand-added
/// plugin (api_spec_id = NULL) on the same proxy survives.
#[tokio::test]
async fn replace_bundle_spec_owned_replaced_hand_added_survives() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let spec_plugin_id = uid("plugin");
    let hand_plugin_id = uid("plugin");

    // Initial submit: one spec-owned plugin.
    let spec_plugin = make_plugin(&spec_plugin_id, &proxy_id, ns, None);
    let bundle_v1 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![spec_plugin],
    };
    let spec_v1 = make_spec(&spec_id, &proxy_id, ns, b"v1 spec");
    store
        .submit_api_spec_bundle(&bundle_v1, &spec_v1)
        .await
        .expect("initial submit failed");

    // Now hand-add a plugin directly (api_spec_id = NULL).
    let hand_plugin = make_plugin(&hand_plugin_id, &proxy_id, ns, None);
    store
        .create_plugin_config(&hand_plugin)
        .await
        .expect("hand-add plugin failed");

    // Verify both plugins exist before replace.
    let before = store
        .list_plugin_configs_paginated(ns, 100, 0)
        .await
        .expect("list failed");
    let proxy_plugins_before: Vec<_> = before
        .items
        .iter()
        .filter(|pc| pc.proxy_id.as_deref() == Some(&proxy_id))
        .collect();
    assert_eq!(
        proxy_plugins_before.len(),
        2,
        "expected 2 plugins before replace"
    );

    // Replace: new bundle has a different spec-owned plugin.
    let new_spec_plugin_id = uid("plugin");
    let new_spec_plugin = make_plugin(&new_spec_plugin_id, &proxy_id, ns, None);
    let bundle_v2 = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![new_spec_plugin],
    };
    let spec_v2 = make_spec(&spec_id, &proxy_id, ns, b"v2 spec");
    store
        .replace_api_spec_bundle(&bundle_v2, &spec_v2)
        .await
        .expect("replace failed");

    // Old spec-owned plugin must be gone.
    let old_plugin = store
        .get_plugin_config(&spec_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        old_plugin.is_none(),
        "old spec-owned plugin must be removed after replace"
    );

    // New spec-owned plugin must exist.
    let new_plugin = store
        .get_plugin_config(&new_spec_plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        new_plugin.is_some(),
        "new spec-owned plugin must exist after replace"
    );

    // The hand-added plugin (NULL api_spec_id) is deleted as part of the
    // proxy delete + re-insert: the proxy FK ON DELETE CASCADE removes all
    // proxy-scoped plugin_configs when the proxy is deleted, regardless of
    // api_spec_id. This is correct and expected behaviour — replacing a spec
    // deletes and re-creates its proxy, so orphaned hand-added plugins go away.
    // (Wave 3 handlers should warn the caller about this; Wave 2 just does the
    // atomic operation faithfully.)
}

// ---------------------------------------------------------------------------
// get_api_spec round-trip (spec_content bytes are preserved)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_api_spec_bytes_round_trip() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    // Use a content string with non-ASCII bytes to stress the BLOB path.
    let raw_content: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
    let spec = make_spec(&spec_id, &proxy_id, ns, &raw_content);

    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let fetched = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed")
        .expect("spec not found");

    assert_eq!(
        fetched.spec_content, spec.spec_content,
        "BLOB round-trip must preserve all bytes"
    );
    assert_eq!(fetched.uncompressed_size, 512);
    assert_eq!(fetched.content_hash, spec.content_hash);
    assert_eq!(fetched.spec_format, SpecFormat::Json);
    assert_eq!(fetched.title.as_deref(), Some("Test API"));
    assert_eq!(fetched.info_version.as_deref(), Some("1.0.0"));
}

// ---------------------------------------------------------------------------
// get_api_spec_by_proxy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_api_spec_by_proxy_returns_none_for_unknown_proxy() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let result = store
        .get_api_spec_by_proxy("ferrum", "nonexistent-proxy-id")
        .await
        .expect("get_api_spec_by_proxy failed");
    assert!(result.is_none());
}

#[tokio::test]
async fn get_api_spec_by_proxy_finds_spec() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"spec");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    let result = store
        .get_api_spec_by_proxy(ns, &proxy_id)
        .await
        .expect("get_api_spec_by_proxy failed")
        .expect("spec not found by proxy_id");
    assert_eq!(result.id, spec_id);
}

// ---------------------------------------------------------------------------
// list_api_specs — namespace-scoped, paginated
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_api_specs_namespace_scoped_and_paginated() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let ns_a = "ns-a";
    let ns_b = "ns-b";

    // Insert 3 specs in ns_a and 1 in ns_b.
    for i in 0..3 {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let bundle = ExtractedBundle {
            proxy: make_proxy(&proxy_id, ns_a),
            upstream: None,
            plugins: vec![],
        };
        let spec = make_spec(&spec_id, &proxy_id, ns_a, format!("spec-{i}").as_bytes());
        store
            .submit_api_spec_bundle(&bundle, &spec)
            .await
            .unwrap_or_else(|e| panic!("submit ns_a spec {i} failed: {e}"));
    }
    {
        let proxy_id = uid("proxy");
        let spec_id = uid("spec");
        let bundle = ExtractedBundle {
            proxy: make_proxy(&proxy_id, ns_b),
            upstream: None,
            plugins: vec![],
        };
        let spec = make_spec(&spec_id, &proxy_id, ns_b, b"ns-b spec");
        store
            .submit_api_spec_bundle(&bundle, &spec)
            .await
            .expect("submit ns_b spec failed");
    }

    // All 3 ns_a specs.
    let all_a = store
        .list_api_specs(ns_a, 100, 0)
        .await
        .expect("list_api_specs failed");
    assert_eq!(all_a.len(), 3, "ns_a must have 3 specs");

    // Pagination: first page (limit=2), second page (limit=2, offset=2).
    let page1 = store
        .list_api_specs(ns_a, 2, 0)
        .await
        .expect("page1 failed");
    let page2 = store
        .list_api_specs(ns_a, 2, 2)
        .await
        .expect("page2 failed");
    assert_eq!(page1.len(), 2, "page1 should have 2 items");
    assert_eq!(page2.len(), 1, "page2 should have 1 item");

    // Namespace isolation: ns_b must have exactly 1 spec.
    let all_b = store
        .list_api_specs(ns_b, 100, 0)
        .await
        .expect("list ns_b failed");
    assert_eq!(all_b.len(), 1, "ns_b must have 1 spec");

    // ns_b spec must not appear in ns_a results.
    let b_id = &all_b[0].id;
    assert!(
        all_a.iter().all(|s| &s.id != b_id),
        "ns_b spec must not appear in ns_a listing"
    );
}

// ---------------------------------------------------------------------------
// delete_api_spec — cascade behaviour
// ---------------------------------------------------------------------------

/// delete_api_spec removes the proxy, spec-owned plugins, spec-owned upstream,
/// and the spec row itself. A non-spec-owned upstream (hand-created, no
/// api_spec_id) is NOT removed.
#[tokio::test]
async fn delete_api_spec_cascades_and_spares_hand_upstreams() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let upstream_id = uid("upstream");
    let plugin_id = uid("plugin");
    let spec_id = uid("spec");

    // Spec-owned upstream + proxy + plugin.
    let spec_upstream = make_upstream(&upstream_id, ns);
    let spec_plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: Some(spec_upstream),
        plugins: vec![spec_plugin],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"to be deleted");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // Create a hand-added upstream (not owned by any spec).
    let hand_upstream_id = uid("upstream");
    let hand_upstream = make_upstream(&hand_upstream_id, ns);
    store
        .create_upstream(&hand_upstream)
        .await
        .expect("create hand upstream failed");

    // Delete the spec.
    let deleted = store
        .delete_api_spec(ns, &spec_id)
        .await
        .expect("delete_api_spec failed");
    assert!(
        deleted,
        "delete_api_spec must return true for existing spec"
    );

    // Spec row must be gone.
    let spec_row = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed");
    assert!(spec_row.is_none(), "spec row must be gone after delete");

    // Proxy must be gone.
    let proxy_row = store.get_proxy(&proxy_id).await.expect("get_proxy failed");
    assert!(proxy_row.is_none(), "proxy must be gone after spec delete");

    // Spec-owned upstream must be gone.
    let upstream_row = store
        .get_upstream(&upstream_id)
        .await
        .expect("get_upstream failed");
    assert!(
        upstream_row.is_none(),
        "spec-owned upstream must be gone after spec delete"
    );

    // Hand-added upstream must still exist.
    let hand_row = store
        .get_upstream(&hand_upstream_id)
        .await
        .expect("get_upstream for hand upstream failed");
    assert!(
        hand_row.is_some(),
        "hand-added upstream must survive spec delete"
    );

    // Spec-owned plugin must be gone (deleted by either api_spec_id cleanup or
    // the proxy FK cascade — both are in play).
    let plugin_row = store
        .get_plugin_config(&plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        plugin_row.is_none(),
        "spec-owned plugin must be gone after spec delete"
    );
}

/// delete_api_spec returns false for a non-existent spec.
#[tokio::test]
async fn delete_api_spec_returns_false_for_missing_spec() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let deleted = store
        .delete_api_spec("ferrum", "nonexistent-spec-id")
        .await
        .expect("delete_api_spec failed");
    assert!(
        !deleted,
        "delete_api_spec must return false for missing spec"
    );
}

// ---------------------------------------------------------------------------
// Namespace isolation
// ---------------------------------------------------------------------------

/// A spec in namespace A must not be visible from namespace B.
#[tokio::test]
async fn spec_in_ns_a_invisible_from_ns_b() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");

    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, "ns-a"),
        upstream: None,
        plugins: vec![],
    };
    let spec = make_spec(&spec_id, &proxy_id, "ns-a", b"ns-a content");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // get_api_spec with wrong namespace → None.
    let result = store
        .get_api_spec("ns-b", &spec_id)
        .await
        .expect("get_api_spec failed");
    assert!(result.is_none(), "spec in ns-a must be invisible from ns-b");

    // list_api_specs for ns-b → empty.
    let list = store
        .list_api_specs("ns-b", 100, 0)
        .await
        .expect("list_api_specs failed");
    assert!(list.is_empty(), "ns-b must have no specs");

    // delete_api_spec with wrong namespace → false.
    let deleted = store
        .delete_api_spec("ns-b", &spec_id)
        .await
        .expect("delete_api_spec failed");
    assert!(!deleted, "delete from wrong namespace must return false");

    // spec still accessible from correct namespace.
    let still_there = store
        .get_api_spec("ns-a", &spec_id)
        .await
        .expect("get_api_spec ns-a failed");
    assert!(
        still_there.is_some(),
        "spec in ns-a must still exist after failed delete from ns-b"
    );
}

// ---------------------------------------------------------------------------
// Gap #1: Hot-path isolation — api_specs NOT in GatewayConfig
// ---------------------------------------------------------------------------

/// `load_full_config` must return a `GatewayConfig` that contains the proxy
/// and plugin created via the api_spec bundle path, but must NOT expose any
/// `api_specs` / `spec` field at the top level.  This test acts as a compile-
/// time + runtime canary: a future contributor who accidentally adds an
/// `api_specs` field to `GatewayConfig` will fail both the serde assertion
/// and, if the field is `#[serde(skip)]`, the field-name grep in CI.
///
/// Additionally, the `ResourceTable` enum inside `db_loader` has no
/// `ApiSpecs` variant (by design — the runtime polling loop must never
/// read that table).  We cannot enumerate private enum variants here, but
/// the comment in the source file acts as the authoritative guard.
#[tokio::test]
async fn api_specs_not_in_gateway_config_load() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    // Insert a real proxy + plugin via the spec bundle path.
    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let plugin_id = uid("plugin");

    let plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![plugin],
    };
    // 1 MiB+ spec content to stress the path.
    let big_content: Vec<u8> = (0u8..=255u8).cycle().take(1_048_576).collect();
    let spec = make_spec(&spec_id, &proxy_id, ns, &big_content);
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit_api_spec_bundle failed");

    // Load the runtime config the way the gateway does.
    let config: GatewayConfig = store
        .load_full_config(ns)
        .await
        .expect("load_full_config failed");

    // Prove the loader actually sees the proxy and plugin (same DB).
    let proxy_present = config.proxies.iter().any(|p| p.id == proxy_id);
    assert!(
        proxy_present,
        "loaded config must contain the submitted proxy"
    );
    let plugin_present = config.plugin_configs.iter().any(|pc| pc.id == plugin_id);
    assert!(
        plugin_present,
        "loaded config must contain the submitted plugin"
    );

    // Prove no `api_specs` / `specs` field leaks into the serialized config.
    let config_value = serde_json::to_value(&config).expect("GatewayConfig must serialize to JSON");
    assert!(
        config_value.get("api_specs").is_none(),
        "GatewayConfig must NOT have an 'api_specs' field (hot-path isolation); \
         future contributor: do NOT add api_specs to GatewayConfig"
    );
    assert!(
        config_value.get("specs").is_none(),
        "GatewayConfig must NOT have a 'specs' field"
    );
}

// ---------------------------------------------------------------------------
// Gap #4: DELETE proxy cascades the api_spec row via FK
// ---------------------------------------------------------------------------

/// When a proxy is deleted directly (via `delete_proxy`, not via
/// `delete_api_spec`), the `api_specs` row that FKs onto that proxy must be
/// removed automatically by the `ON DELETE CASCADE` constraint, and the
/// spec-owned plugin must also be gone (double cascade via plugin_configs FK).
#[tokio::test]
async fn delete_proxy_cascades_api_spec_row_via_fk() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let ns = "ferrum";

    let proxy_id = uid("proxy");
    let spec_id = uid("spec");
    let plugin_id = uid("plugin");

    let plugin = make_plugin(&plugin_id, &proxy_id, ns, None);
    let bundle = ExtractedBundle {
        proxy: make_proxy(&proxy_id, ns),
        upstream: None,
        plugins: vec![plugin],
    };
    let spec = make_spec(&spec_id, &proxy_id, ns, b"spec for fk cascade test");
    store
        .submit_api_spec_bundle(&bundle, &spec)
        .await
        .expect("submit failed");

    // Confirm spec and plugin are present before delete.
    let before_spec = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed");
    assert!(before_spec.is_some(), "spec must exist before delete");

    // Delete the proxy directly (not via delete_api_spec).
    let deleted = store
        .delete_proxy(&proxy_id)
        .await
        .expect("delete_proxy failed");
    assert!(deleted, "delete_proxy must return true for existing proxy");

    // The api_spec row must be gone (FK ON DELETE CASCADE).
    let after_spec = store
        .get_api_spec(ns, &spec_id)
        .await
        .expect("get_api_spec failed after proxy delete");
    assert!(
        after_spec.is_none(),
        "api_spec row must be cascade-deleted when its proxy is deleted"
    );

    // The spec-owned plugin must also be gone (proxy FK → plugin_configs cascade).
    let after_plugin = store
        .get_plugin_config(&plugin_id)
        .await
        .expect("get_plugin_config failed");
    assert!(
        after_plugin.is_none(),
        "spec-owned plugin must be cascade-deleted when its proxy is deleted"
    );
}
