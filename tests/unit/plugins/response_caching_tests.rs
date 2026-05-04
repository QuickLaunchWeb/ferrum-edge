//! Tests for response_caching plugin

use super::plugin_utils::create_test_proxy;
use chrono::Utc;
use ferrum_edge::config::types::Consumer;
use ferrum_edge::plugins::response_caching::ResponseCaching;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_ctx(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    ctx.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    ctx
}

fn make_ctx_with_query(method: &str, path: &str, query: &[(&str, &str)]) -> RequestContext {
    let mut ctx = make_ctx(method, path);
    for (k, v) in query {
        ctx.query_params.insert(k.to_string(), v.to_string());
    }
    ctx
}

fn default_plugin() -> ResponseCaching {
    ResponseCaching::new(&json!({})).unwrap()
}

fn plugin_with_config(config: serde_json::Value) -> ResponseCaching {
    ResponseCaching::new(&config).unwrap()
}

fn expect_reject(result: PluginResult) -> (u16, Vec<u8>, HashMap<String, String>) {
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, body.into_bytes(), headers),
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => (status_code, body.to_vec(), headers),
        PluginResult::Continue => panic!("Expected cache hit"),
    }
}

fn is_reject(result: &PluginResult) -> bool {
    matches!(
        result,
        PluginResult::Reject { .. } | PluginResult::RejectBinary { .. }
    )
}

// Helper to simulate a full cache flow: before_proxy (miss) -> after_proxy -> on_final_response_body
async fn cache_response(
    plugin: &ResponseCaching,
    method: &str,
    path: &str,
    status: u16,
    response_headers: &HashMap<String, String>,
    body: &[u8],
) {
    let mut ctx = make_ctx(method, path);
    let mut headers = HashMap::new();

    // before_proxy (should be MISS)
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // after_proxy
    let mut resp_headers = response_headers.clone();
    plugin
        .after_proxy(&mut ctx, status, &mut resp_headers)
        .await;

    // on_final_response_body
    plugin
        .on_final_response_body(&mut ctx, status, &resp_headers, body)
        .await;
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = default_plugin();
    assert_eq!(plugin.name(), "response_caching");
    assert_eq!(plugin.priority(), 3500);
    assert!(plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_supported_protocols() {
    let plugin = default_plugin();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols.len(), 1);
    assert_eq!(protocols[0], ferrum_edge::plugins::ProxyProtocol::Http);
}

// === Cache miss on first request ===

#[tokio::test]
async fn test_cache_miss_first_request() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("cache_status").unwrap(), "MISS");
    assert!(ctx.metadata.contains_key("cache_base_key"));
}

// === Cache hit on second request ===

#[tokio::test]
async fn test_cache_hit_second_request() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"{\"key\":\"value\"}",
    )
    .await;

    // Second request should be a HIT
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    let (status_code, body, headers) = expect_reject(result);
    assert_eq!(status_code, 200);
    assert_eq!(body, b"{\"key\":\"value\"}");
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
    assert_eq!(headers.get("x-cache-status").unwrap(), "HIT");
}

// === TTL expiry ===

#[tokio::test]
async fn test_ttl_expiry() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 0  // Immediate expiry
    }));

    cache_response(&plugin, "GET", "/api/data", 200, &HashMap::new(), b"cached").await;

    // Wait a tiny bit to ensure expiry
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let status = ctx.metadata.get("cache_status").unwrap().as_str();
    assert!(
        status == "MISS" || status == "PREDICTED-BYPASS",
        "expected MISS or PREDICTED-BYPASS, got {status}"
    );
}

// === Cache-Control: no-store ===

#[tokio::test]
async fn test_cache_control_no_store_response() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "no-store".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/secret",
        200,
        &resp_headers,
        b"secret data",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/secret");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Cache-Control: private ===

#[tokio::test]
async fn test_cache_control_private_response() {
    let plugin = default_plugin();
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "private".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/private",
        200,
        &resp_headers,
        b"private data",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/private");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Cache-Control: max-age ===

#[tokio::test]
async fn test_cache_control_max_age() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 1  // Short default
    }));

    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "max-age=3600".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"long-lived",
    )
    .await;

    // Should still be cached (max-age=3600 overrides ttl_seconds=1)
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === Cache-Control: s-maxage takes precedence ===

#[tokio::test]
async fn test_cache_control_s_maxage_precedence() {
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 0  // Would expire immediately
    }));

    let mut resp_headers = HashMap::new();
    resp_headers.insert(
        "cache-control".to_string(),
        "max-age=0, s-maxage=3600".to_string(),
    );

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"s-maxage wins",
    )
    .await;

    // s-maxage=3600 should override max-age=0
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === Client Cache-Control: no-cache bypasses cache ===

#[tokio::test]
async fn test_client_no_cache_bypasses() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &HashMap::new(),
        b"cached data",
    )
    .await;

    // Request with Cache-Control: no-cache should bypass
    let mut ctx = make_ctx("GET", "/api/data");
    ctx.headers
        .insert("cache-control".to_string(), "no-cache".to_string());
    let mut headers = HashMap::new();
    headers.insert("cache-control".to_string(), "no-cache".to_string());
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("cache_status").unwrap(), "BYPASS");
}

// === Non-cacheable methods ===

#[tokio::test]
async fn test_post_not_cached() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("POST", "/api/data");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("cache_status").unwrap(), "BYPASS");
}

#[tokio::test]
async fn test_delete_not_cached() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("DELETE", "/api/data");
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("cache_status").unwrap(), "BYPASS");
}

// === Non-cacheable status codes ===

#[tokio::test]
async fn test_500_not_cached() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/error",
        500,
        &HashMap::new(),
        b"server error",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/error");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Cache invalidation on unsafe methods ===

#[tokio::test]
async fn test_post_invalidates_cached_get() {
    let plugin = default_plugin();

    // Cache a GET response
    cache_response(
        &plugin,
        "GET",
        "/api/items",
        200,
        &HashMap::new(),
        b"[\"item1\"]",
    )
    .await;

    // Verify it's cached
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));

    // POST to the same path should invalidate
    let mut ctx = make_ctx("POST", "/api/items");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // GET should now be a MISS
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Max entry size ===

#[tokio::test]
async fn test_max_entry_size_exceeded() {
    let plugin = plugin_with_config(json!({
        "max_entry_size_bytes": 10  // Very small
    }));

    cache_response(
        &plugin,
        "GET",
        "/api/large",
        200,
        &HashMap::new(),
        b"this response is way too large for the cache",
    )
    .await;

    // Should not be cached
    let mut ctx = make_ctx("GET", "/api/large");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Max entries eviction ===

#[tokio::test]
async fn test_max_entries_eviction() {
    let plugin = plugin_with_config(json!({
        "max_entries": 2,
        "ttl_seconds": 3600
    }));

    // Cache 3 entries (max is 2, so oldest should be evicted)
    for i in 0..3 {
        let path = format!("/api/item/{}", i);
        cache_response(
            &plugin,
            "GET",
            &path,
            200,
            &HashMap::new(),
            format!("data-{}", i).as_bytes(),
        )
        .await;
    }

    // The third entry should be cached
    let mut ctx = make_ctx("GET", "/api/item/2");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === Vary header ===

#[tokio::test]
async fn test_vary_by_headers() {
    let plugin = plugin_with_config(json!({
        "vary_by_headers": ["accept"]
    }));

    // Cache JSON response
    let mut ctx = make_ctx("GET", "/api/data");
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());
    ctx.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut headers = HashMap::new();
    headers.insert("accept".to_string(), "application/json".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    plugin
        .on_final_response_body(&mut ctx, 200, &resp_headers, b"{\"json\":true}")
        .await;

    // Cache XML response (different Accept header = different cache key)
    let mut ctx2 = make_ctx("GET", "/api/data");
    ctx2.headers
        .insert("accept".to_string(), "application/xml".to_string());
    ctx2.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut headers2 = HashMap::new();
    headers2.insert("accept".to_string(), "application/xml".to_string());
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    let mut resp_headers2 = HashMap::new();
    resp_headers2.insert("content-type".to_string(), "application/xml".to_string());
    plugin.after_proxy(&mut ctx2, 200, &mut resp_headers2).await;
    plugin
        .on_final_response_body(&mut ctx2, 200, &resp_headers2, b"<xml/>")
        .await;

    // JSON accept should get JSON response
    let mut ctx_json = make_ctx("GET", "/api/data");
    ctx_json
        .headers
        .insert("accept".to_string(), "application/json".to_string());
    let mut h = HashMap::new();
    h.insert("accept".to_string(), "application/json".to_string());
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_json, &mut h).await);
    assert_eq!(body, b"{\"json\":true}");

    // XML accept should get XML response
    let mut ctx_xml = make_ctx("GET", "/api/data");
    ctx_xml
        .headers
        .insert("accept".to_string(), "application/xml".to_string());
    let mut h2 = HashMap::new();
    h2.insert("accept".to_string(), "application/xml".to_string());
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_xml, &mut h2).await);
    assert_eq!(body, b"<xml/>");
}

#[tokio::test]
async fn test_backend_vary_accept_encoding_caches_binary_variant() {
    let plugin = default_plugin();
    let compressed = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0xff];

    let mut ctx = make_ctx("GET", "/assets/app.js");
    ctx.headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut headers = HashMap::new();
    headers.insert("accept-encoding".to_string(), "gzip".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-encoding".to_string(), "gzip".to_string());
    response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, &compressed)
        .await;

    let mut gzip_ctx = make_ctx("GET", "/assets/app.js");
    gzip_ctx
        .headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut gzip_headers = HashMap::new();
    gzip_headers.insert("accept-encoding".to_string(), "gzip".to_string());
    let (status_code, body, headers) =
        expect_reject(plugin.before_proxy(&mut gzip_ctx, &mut gzip_headers).await);
    assert_eq!(status_code, 200);
    assert_eq!(body, compressed);
    assert_eq!(headers.get("content-encoding"), Some(&"gzip".to_string()));
    assert_eq!(headers.get("x-cache-status"), Some(&"HIT".to_string()));

    let mut plain_ctx = make_ctx("GET", "/assets/app.js");
    let mut plain_headers = HashMap::new();
    let miss = plugin
        .before_proxy(&mut plain_ctx, &mut plain_headers)
        .await;
    assert!(matches!(miss, PluginResult::Continue));
}

#[tokio::test]
async fn test_vary_wildcard_not_cached() {
    let plugin = default_plugin();
    let mut response_headers = HashMap::new();
    response_headers.insert("vary".to_string(), "*".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &response_headers,
        b"volatile",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_if_none_match_returns_304_from_cache() {
    let plugin = default_plugin();
    let mut response_headers = HashMap::new();
    response_headers.insert("etag".to_string(), r#"W/"abc123""#.to_string());
    response_headers.insert("cache-control".to_string(), "max-age=60".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &response_headers,
        b"cached-body",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/data");
    ctx.headers
        .insert("if-none-match".to_string(), r#""abc123""#.to_string());
    let mut headers = HashMap::new();
    headers.insert("if-none-match".to_string(), r#""abc123""#.to_string());
    let (status_code, body, headers) =
        expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status_code, 304);
    assert!(body.is_empty());
    assert_eq!(headers.get("etag"), Some(&r#"W/"abc123""#.to_string()));
    assert_eq!(
        headers.get("x-cache-status"),
        Some(&"REVALIDATED".to_string())
    );
}

#[tokio::test]
async fn test_authorization_response_not_shared_cached_without_public() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/private");
    ctx.headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("cache-control".to_string(), "max-age=60".to_string());
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"user-a")
        .await;

    let mut second_ctx = make_ctx("GET", "/api/private");
    second_ctx
        .headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    let mut second_headers = HashMap::new();
    let result = plugin
        .before_proxy(&mut second_ctx, &mut second_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_authorization_response_with_public_can_be_cached() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/public-auth");
    ctx.headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    let mut headers = HashMap::new();
    headers.insert("authorization".to_string(), "Bearer token-a".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut response_headers = HashMap::new();
    response_headers.insert(
        "cache-control".to_string(),
        "public, max-age=60".to_string(),
    );
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, b"shared")
        .await;

    // Second request from the SAME bearer token must hit. The plugin auto-merges
    // `authorization` into the Vary list when caching authorized responses, so
    // the second lookup must present the same Authorization value to land on the
    // same cache entry.
    let mut second_ctx = make_ctx("GET", "/api/public-auth");
    second_ctx
        .headers
        .insert("authorization".to_string(), "Bearer token-a".to_string());
    let mut second_headers = HashMap::new();
    second_headers.insert("authorization".to_string(), "Bearer token-a".to_string());
    let (_, body, response_headers) = expect_reject(
        plugin
            .before_proxy(&mut second_ctx, &mut second_headers)
            .await,
    );
    assert_eq!(body, b"shared");
    // The cached response surfaces the auto-merged `Vary: authorization` so
    // downstream caches/clients honor the same dimension.
    let vary = response_headers
        .get("vary")
        .expect("Vary header should be present on cached authorized response");
    assert!(
        vary.split(',')
            .map(str::trim)
            .any(|h| h.eq_ignore_ascii_case("authorization")),
        "expected `Vary` to include `authorization`, got `{}`",
        vary
    );
}

// === X-Cache-Status header ===

#[tokio::test]
async fn test_x_cache_status_miss_header() {
    let plugin = default_plugin();
    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert_eq!(resp_headers.get("x-cache-status").unwrap(), "MISS");
}

#[tokio::test]
async fn test_x_cache_status_disabled() {
    let plugin = plugin_with_config(json!({
        "add_cache_status_header": false
    }));

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!resp_headers.contains_key("x-cache-status"));
}

// === Consumer-keyed caching ===

#[tokio::test]
async fn test_consumer_keyed_caching() {
    let plugin = plugin_with_config(json!({
        "cache_key_include_consumer": true
    }));

    // Cache response for user A
    let mut ctx_a = make_ctx("GET", "/api/data");
    ctx_a.identified_consumer = Some(Arc::new(make_consumer("a", "alice")));
    let mut h = HashMap::new();
    plugin.before_proxy(&mut ctx_a, &mut h).await;
    let mut rh = HashMap::new();
    plugin.after_proxy(&mut ctx_a, 200, &mut rh).await;
    plugin
        .on_final_response_body(&mut ctx_a, 200, &rh, b"alice-data")
        .await;

    // User B should get a MISS (different consumer = different cache key)
    let mut ctx_b = make_ctx("GET", "/api/data");
    ctx_b.identified_consumer = Some(Arc::new(make_consumer("b", "bob")));
    let mut h2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx_b, &mut h2).await;
    assert!(matches!(result, PluginResult::Continue));

    // User A should get a HIT
    let mut ctx_a2 = make_ctx("GET", "/api/data");
    ctx_a2.identified_consumer = Some(Arc::new(make_consumer("a", "alice")));
    let mut h3 = HashMap::new();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_a2, &mut h3).await);
    assert_eq!(body, b"alice-data");
}

#[tokio::test]
async fn test_consumer_keyed_caching_uses_authenticated_identity_fallback() {
    let plugin = plugin_with_config(json!({
        "cache_key_include_consumer": true
    }));

    let mut ctx_external = make_ctx("GET", "/api/data");
    ctx_external.authenticated_identity = Some("oidc-alice".to_string());
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx_external, &mut headers).await;
    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx_external, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx_external, 200, &response_headers, b"alice-data")
        .await;

    let mut ctx_other = make_ctx("GET", "/api/data");
    ctx_other.authenticated_identity = Some("oidc-bob".to_string());
    let mut miss_headers = HashMap::new();
    let miss = plugin.before_proxy(&mut ctx_other, &mut miss_headers).await;
    assert!(matches!(miss, PluginResult::Continue));

    let mut ctx_external_again = make_ctx("GET", "/api/data");
    ctx_external_again.authenticated_identity = Some("oidc-alice".to_string());
    let mut hit_headers = HashMap::new();
    let (_, body, _) = expect_reject(
        plugin
            .before_proxy(&mut ctx_external_again, &mut hit_headers)
            .await,
    );
    assert_eq!(body, b"alice-data");
}

// === Query string caching ===

#[tokio::test]
async fn test_different_query_params_different_cache() {
    let plugin = default_plugin();

    // Cache response for ?page=1
    let mut ctx1 = make_ctx_with_query("GET", "/api/items", &[("page", "1")]);
    ctx1.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h = HashMap::new();
    plugin.before_proxy(&mut ctx1, &mut h).await;
    let mut rh = HashMap::new();
    plugin.after_proxy(&mut ctx1, 200, &mut rh).await;
    plugin
        .on_final_response_body(&mut ctx1, 200, &rh, b"page-1-data")
        .await;

    // ?page=2 should be a MISS
    let mut ctx2 = make_ctx_with_query("GET", "/api/items", &[("page", "2")]);
    ctx2.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx2, &mut h2).await;
    assert!(matches!(result, PluginResult::Continue));

    // ?page=1 should be a HIT
    let mut ctx3 = make_ctx_with_query("GET", "/api/items", &[("page", "1")]);
    ctx3.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h3 = HashMap::new();
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx3, &mut h3).await);
    assert_eq!(body, b"page-1-data");
}

// === Query-insensitive caching ===

#[tokio::test]
async fn test_query_excluded_from_cache_key() {
    let plugin = plugin_with_config(json!({
        "cache_key_include_query": false
    }));

    // Cache with ?page=1
    let mut ctx1 = make_ctx_with_query("GET", "/api/items", &[("page", "1")]);
    ctx1.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h = HashMap::new();
    plugin.before_proxy(&mut ctx1, &mut h).await;
    let mut rh = HashMap::new();
    plugin.after_proxy(&mut ctx1, 200, &mut rh).await;
    plugin
        .on_final_response_body(&mut ctx1, 200, &rh, b"same-data")
        .await;

    // ?page=2 should be a HIT (query excluded from key)
    let mut ctx2 = make_ctx_with_query("GET", "/api/items", &[("page", "2")]);
    ctx2.matched_proxy = Some(std::sync::Arc::new(create_test_proxy()));
    let mut h2 = HashMap::new();
    let result = plugin.before_proxy(&mut ctx2, &mut h2).await;
    assert!(is_reject(&result));
}

// === HEAD method cacheable ===

#[tokio::test]
async fn test_head_method_cacheable() {
    let plugin = default_plugin();

    cache_response(&plugin, "HEAD", "/api/data", 200, &HashMap::new(), b"").await;

    let mut ctx = make_ctx("HEAD", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === respect_cache_control disabled ===

#[tokio::test]
async fn test_respect_cache_control_disabled() {
    let plugin = plugin_with_config(json!({
        "respect_cache_control": false,
        "ttl_seconds": 3600
    }));

    // Even with no-store, response should be cached when respect_cache_control=false
    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "no-store".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/data",
        200,
        &resp_headers,
        b"should be cached",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/data");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === Cache-Control: no-cache response not cached ===

#[tokio::test]
async fn test_cache_control_no_cache_response() {
    let plugin = default_plugin();

    let mut resp_headers = HashMap::new();
    resp_headers.insert("cache-control".to_string(), "no-cache".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/volatile",
        200,
        &resp_headers,
        b"volatile data",
    )
    .await;

    // Should not be cached (no-cache means always revalidate)
    let mut ctx = make_ctx("GET", "/api/volatile");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === 301 and 404 cacheable by default ===

#[tokio::test]
async fn test_301_cacheable() {
    let plugin = default_plugin();

    cache_response(&plugin, "GET", "/old-path", 301, &HashMap::new(), b"").await;

    let mut ctx = make_ctx("GET", "/old-path");
    let mut headers = HashMap::new();
    let (status_code, _, _) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status_code, 301);
}

#[tokio::test]
async fn test_404_cacheable() {
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/not-found",
        404,
        &HashMap::new(),
        b"not found",
    )
    .await;

    let mut ctx = make_ctx("GET", "/not-found");
    let mut headers = HashMap::new();
    let (status_code, _, _) = expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(status_code, 404);
}

// === Invalidation disabled ===

#[tokio::test]
async fn test_invalidation_disabled() {
    let plugin = plugin_with_config(json!({
        "invalidate_on_unsafe_methods": false
    }));

    cache_response(&plugin, "GET", "/api/items", 200, &HashMap::new(), b"items").await;

    // POST should NOT invalidate when disabled
    let mut ctx = make_ctx("POST", "/api/items");
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // GET should still be a HIT
    let mut ctx = make_ctx("GET", "/api/items");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// === Max total size ===

#[tokio::test]
async fn test_max_total_size_exceeded() {
    let plugin = plugin_with_config(json!({
        "max_total_size_bytes": 300,
        "max_entry_size_bytes": 1048576
    }));

    // Cache a response that takes up most of the total size
    // Each entry is ~200 bytes body + ~64 bytes overhead = ~264 bytes
    cache_response(&plugin, "GET", "/api/a", 200, &HashMap::new(), &[b'x'; 200]).await;

    // This should fail to cache (would exceed 300-byte total size)
    cache_response(&plugin, "GET", "/api/b", 200, &HashMap::new(), &[b'y'; 200]).await;

    // First should be cached
    let mut ctx = make_ctx("GET", "/api/a");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));

    // Second should NOT be cached (total size exceeded)
    let mut ctx = make_ctx("GET", "/api/b");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_total_size_limit_uses_saturating_add() {
    // Verify that the total size check doesn't overflow when current_total is
    // near usize::MAX. The fix uses saturating_add to prevent wrapping around
    // to a small number that would bypass the size limit check.
    //
    // We can't directly set the internal total_size counter, but we verify
    // that the cache respects max_total_size_bytes by checking that entries
    // that would exceed the limit are rejected. This validates the comparison
    // logic path that now uses saturating_add.
    let plugin = plugin_with_config(json!({
        "ttl_seconds": 60,
        "max_total_size_bytes": 1, // Extremely small limit
    }));

    // Cache a response that will exceed the 1-byte limit
    cache_response(
        &plugin,
        "GET",
        "/api/overflow",
        200,
        &HashMap::new(),
        b"this body is much larger than 1 byte",
    )
    .await;

    // Should NOT be cached (entry_size > max_total_size_bytes)
    let mut ctx = make_ctx("GET", "/api/overflow");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Entry exceeding max_total_size_bytes should not be cached"
    );
    assert_eq!(ctx.metadata.get("cache_status").unwrap(), "MISS");
}

// === Set-Cookie safety ===

#[tokio::test]
async fn test_set_cookie_response_not_cached() {
    let plugin = default_plugin();

    // Cache a response that contains Set-Cookie
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    response_headers.insert(
        "set-cookie".to_string(),
        "session=abc123; Path=/; HttpOnly".to_string(),
    );

    cache_response(
        &plugin,
        "GET",
        "/api/login",
        200,
        &response_headers,
        b"user-specific-data",
    )
    .await;

    // Second request should be a MISS — Set-Cookie responses must not be cached
    let mut ctx = make_ctx("GET", "/api/login");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Response with Set-Cookie header must not be cached"
    );
    let status = ctx.metadata.get("cache_status").unwrap().as_str();
    assert!(
        status == "MISS" || status == "PREDICTED-BYPASS",
        "expected MISS or PREDICTED-BYPASS, got {status}"
    );
}

#[tokio::test]
async fn test_response_without_set_cookie_still_cached() {
    let plugin = default_plugin();

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    cache_response(
        &plugin,
        "GET",
        "/api/public",
        200,
        &response_headers,
        b"public-data",
    )
    .await;

    // Second request should be a HIT — no Set-Cookie, normal caching
    let mut ctx = make_ctx("GET", "/api/public");
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        is_reject(&result),
        "Response without Set-Cookie should be cached normally"
    );
}

// === Auto-Vary on Authorization (RFC 7234 §3.2 cross-user leak fix) ===

#[tokio::test]
async fn test_authorization_auto_vary_isolates_users() {
    // Two users hit the same `public, max-age=...` resource with different
    // bearer tokens. Without the auto-Vary fix, User B would receive User A's
    // cached payload. With the fix, the cache is keyed by the Authorization
    // value so each user gets their own entry.
    let plugin = default_plugin();

    // User A: cache `user-a-data` under `Authorization: Bearer A`.
    let mut ctx_a = make_ctx("GET", "/api/me/data");
    ctx_a
        .headers
        .insert("authorization".to_string(), "Bearer A".to_string());
    let mut headers_a = HashMap::new();
    headers_a.insert("authorization".to_string(), "Bearer A".to_string());
    plugin.before_proxy(&mut ctx_a, &mut headers_a).await;

    let mut response_headers_a = HashMap::new();
    response_headers_a.insert(
        "cache-control".to_string(),
        "public, max-age=300".to_string(),
    );
    plugin
        .after_proxy(&mut ctx_a, 200, &mut response_headers_a)
        .await;
    plugin
        .on_final_response_body(&mut ctx_a, 200, &response_headers_a, b"user-a-data")
        .await;

    // User B presents a DIFFERENT bearer token on the same path. Without the
    // fix this would return User A's cached body (cross-user leak); with the
    // fix it must be a cache MISS because the auto-Vary on `authorization`
    // makes the cache key user-specific.
    let mut ctx_b = make_ctx("GET", "/api/me/data");
    ctx_b
        .headers
        .insert("authorization".to_string(), "Bearer B".to_string());
    let mut headers_b = HashMap::new();
    headers_b.insert("authorization".to_string(), "Bearer B".to_string());
    let result_b = plugin.before_proxy(&mut ctx_b, &mut headers_b).await;
    assert!(
        matches!(result_b, PluginResult::Continue),
        "User B with different bearer token must NOT receive User A's cached response"
    );

    // User A re-issuing the same request with the same token must still HIT.
    let mut ctx_a2 = make_ctx("GET", "/api/me/data");
    ctx_a2
        .headers
        .insert("authorization".to_string(), "Bearer A".to_string());
    let mut headers_a2 = HashMap::new();
    headers_a2.insert("authorization".to_string(), "Bearer A".to_string());
    let (_, body, response_headers) =
        expect_reject(plugin.before_proxy(&mut ctx_a2, &mut headers_a2).await);
    assert_eq!(
        body, b"user-a-data",
        "User A with the same bearer token must still receive their cached response"
    );
    // Cached response surfaces auto-merged `Vary: authorization`.
    let vary = response_headers
        .get("vary")
        .expect("Vary header should be present on cached authorized response");
    assert!(
        vary.split(',')
            .map(str::trim)
            .any(|h| h.eq_ignore_ascii_case("authorization")),
        "expected `Vary` to include `authorization`, got `{}`",
        vary
    );
}

#[tokio::test]
async fn test_no_authorization_no_auto_vary() {
    // When the request has no Authorization header, the plugin must NOT
    // auto-add `authorization` to the cached response's Vary list — the
    // existing behavior (cache hit on identical anonymous request) is
    // preserved.
    let plugin = default_plugin();

    cache_response(
        &plugin,
        "GET",
        "/api/anon",
        200,
        &HashMap::new(),
        b"anon-data",
    )
    .await;

    let mut ctx = make_ctx("GET", "/api/anon");
    let mut headers = HashMap::new();
    let (_, body, response_headers) =
        expect_reject(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(body, b"anon-data");
    // No Vary header should have been auto-added (vary_headers list was empty
    // and the request had no Authorization, so the auto-merge branch did not
    // fire).
    let vary_lower = response_headers.get("vary").map(|v| v.to_ascii_lowercase());
    if let Some(vary) = vary_lower {
        assert!(
            !vary.contains("authorization"),
            "Vary must NOT include `authorization` when request had no Authorization header, got `{}`",
            vary
        );
    }
}

// === Host included in base cache key (multi-host proxy isolation) ===

#[tokio::test]
async fn test_different_host_headers_different_cache_keys() {
    // A multi-host proxy (`hosts: ["a.example.com", "b.example.com"]`) shares
    // the same `proxy_id`. Without including Host in the cache key, the two
    // hosts collide and a response cached under host A is served to clients
    // addressing host B.
    let plugin = default_plugin();

    // Cache a response from host A.
    let mut ctx_a = make_ctx("GET", "/api/data");
    ctx_a
        .headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut headers_a = HashMap::new();
    headers_a.insert("host".to_string(), "a.example.com".to_string());
    plugin.before_proxy(&mut ctx_a, &mut headers_a).await;
    let mut response_headers_a = HashMap::new();
    plugin
        .after_proxy(&mut ctx_a, 200, &mut response_headers_a)
        .await;
    plugin
        .on_final_response_body(&mut ctx_a, 200, &response_headers_a, b"a-data")
        .await;

    // A request to host B on the same path must MISS — different host =
    // different cache key, no cross-host pollution.
    let mut ctx_b = make_ctx("GET", "/api/data");
    ctx_b
        .headers
        .insert("host".to_string(), "b.example.com".to_string());
    let mut headers_b = HashMap::new();
    headers_b.insert("host".to_string(), "b.example.com".to_string());
    let result_b = plugin.before_proxy(&mut ctx_b, &mut headers_b).await;
    assert!(
        matches!(result_b, PluginResult::Continue),
        "Different Host header must NOT hit cache stored under another host"
    );

    // Re-issuing the original host request must still HIT.
    let mut ctx_a2 = make_ctx("GET", "/api/data");
    ctx_a2
        .headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut headers_a2 = HashMap::new();
    headers_a2.insert("host".to_string(), "a.example.com".to_string());
    let (_, body, _) = expect_reject(plugin.before_proxy(&mut ctx_a2, &mut headers_a2).await);
    assert_eq!(body, b"a-data");
}

#[tokio::test]
async fn test_host_header_case_insensitive_in_cache_key() {
    // Per RFC 9110 §4.2.3 the host component is case-insensitive. The base
    // key normalizes ASCII case so `A.Example.COM` and `a.example.com`
    // collapse to the same cache entry.
    let plugin = default_plugin();

    let mut ctx_upper = make_ctx("GET", "/api/data");
    ctx_upper
        .headers
        .insert("host".to_string(), "A.Example.COM".to_string());
    let mut headers_upper = HashMap::new();
    headers_upper.insert("host".to_string(), "A.Example.COM".to_string());
    plugin
        .before_proxy(&mut ctx_upper, &mut headers_upper)
        .await;
    let mut resp = HashMap::new();
    plugin.after_proxy(&mut ctx_upper, 200, &mut resp).await;
    plugin
        .on_final_response_body(&mut ctx_upper, 200, &resp, b"host-data")
        .await;

    let mut ctx_lower = make_ctx("GET", "/api/data");
    ctx_lower
        .headers
        .insert("host".to_string(), "a.example.com".to_string());
    let mut headers_lower = HashMap::new();
    headers_lower.insert("host".to_string(), "a.example.com".to_string());
    let (_, body, _) = expect_reject(
        plugin
            .before_proxy(&mut ctx_lower, &mut headers_lower)
            .await,
    );
    assert_eq!(body, b"host-data");
}

// === SSE bypass ===

#[tokio::test]
async fn test_sse_request_skips_response_buffering() {
    // When the client requests SSE via `Accept: text/event-stream`, the
    // response body MUST NOT be buffered — buffering an unbounded event
    // stream collects frames forever and 502s once the
    // FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES ceiling is hit.
    let plugin = default_plugin();
    assert!(plugin.requires_response_body_buffering());

    let mut ctx = make_ctx("GET", "/events");
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_non_sse_request_still_buffers() {
    // Plain JSON requests must still take the buffered/cacheable path.
    let plugin = default_plugin();

    let mut ctx = make_ctx("GET", "/api/data");
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_sse_in_accept_list_skips_buffering() {
    // EventSource clients send `Accept: text/event-stream` but other clients
    // may include it as one of several alternatives. Any presence of SSE in
    // the Accept list signals streaming intent.
    let plugin = default_plugin();

    let mut ctx = make_ctx("GET", "/events");
    ctx.headers.insert(
        "accept".to_string(),
        "text/html, text/event-stream;q=0.9, */*".to_string(),
    );

    assert!(!plugin.should_buffer_response_body(&ctx));
}
