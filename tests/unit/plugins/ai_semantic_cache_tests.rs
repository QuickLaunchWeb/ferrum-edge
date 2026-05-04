use ferrum_edge::config::types::Consumer;
use ferrum_edge::plugins::ai_semantic_cache::AiSemanticCache;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

/// Build a synthetic Consumer for cross-consumer scoping tests. Only
/// `username` matters because that's what `effective_identity()` returns
/// when `identified_consumer` is set.
fn make_consumer(username: &str) -> Arc<Consumer> {
    Arc::new(Consumer {
        id: format!("consumer-{}", username),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    })
}

/// Drive a request through `before_proxy` and report whether the call
/// returned a cache HIT (`RejectBinary`) or a MISS (`Continue`).
async fn run_before_proxy_get_status(
    plugin: &AiSemanticCache,
    body_str: &str,
    consumer: Option<Arc<Consumer>>,
) -> bool {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), body_str.to_string());
    if let Some(c) = consumer {
        ctx.identified_consumer = Some(c);
    }
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::RejectBinary { .. }
    )
}

/// MISS+store helper: send a request through `before_proxy` (cache MISS) and
/// then write a synthetic response into the cache via `on_final_response_body`.
async fn store_response(
    plugin: &AiSemanticCache,
    body_str: &str,
    consumer: Option<Arc<Consumer>>,
    response_body: &[u8],
) {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), body_str.to_string());
    if let Some(c) = consumer {
        ctx.identified_consumer = Some(c);
    }
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, response_body)
        .await;
}

fn make_plugin(config: serde_json::Value) -> AiSemanticCache {
    AiSemanticCache::new(&config, PluginHttpClient::default()).unwrap()
}

#[test]
fn test_new_default_config() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_semantic_cache");
}

#[test]
fn test_new_custom_config() {
    let config = json!({
        "ttl_seconds": 600,
        "max_entries": 5000,
        "max_entry_size_bytes": 524288,
        "max_total_size_bytes": 52428800,
        "include_model_in_key": true,
        "include_params_in_key": true,
        "scope_by_consumer": true
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_semantic_cache");
}

#[test]
fn test_new_zero_ttl_fails() {
    let config = json!({"ttl_seconds": 0});
    let result = AiSemanticCache::new(&config, PluginHttpClient::default());
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("ttl_seconds"));
}

#[test]
fn test_new_with_redis_config() {
    let config = json!({
        "sync_mode": "redis",
        "redis_url": "redis://localhost:6379/0"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_semantic_cache");
}

#[test]
fn test_requires_response_body_buffering() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_requires_request_body() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert!(plugin.requires_request_body_before_before_proxy());
}

#[tokio::test]
async fn test_cache_miss_then_hit() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body_json = json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "What is the capital of France?"}
        ]
    });
    let body_str = serde_json::to_string(&body_json).unwrap();

    // First request — cache MISS
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx1.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx1.metadata.get("ai_cache_status").unwrap(), "MISS");
    assert!(ctx1.metadata.contains_key("_ai_cache_key"));

    // Simulate caching the response
    let response_body = br#"{"choices":[{"message":{"content":"Paris"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, response_body)
        .await;

    // Second request with same prompt — cache HIT
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx2.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
            ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(headers.get("x-ai-cache-status").unwrap(), "HIT");
            assert_eq!(&body[..], response_body);
        }
        _ => panic!("Expected cache HIT (RejectBinary), got {:?}", result),
    }
}

#[tokio::test]
async fn test_different_prompts_no_cache_hit() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    // First request
    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of France?"}]
    });
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx1.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body1).unwrap(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    let response_headers = HashMap::new();
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"cached")
        .await;

    // Different prompt — should MISS
    let body2 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of Germany?"}]
    });
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx2.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx2.metadata.get("ai_cache_status").unwrap(), "MISS");
}

#[tokio::test]
async fn test_whitespace_normalization_cache_hit() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    // First request with normal spacing
    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the capital of France?"}]
    });
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx1.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body1).unwrap(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    let response_headers = HashMap::new();
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"Paris")
        .await;

    // Same prompt with extra whitespace and case differences — should HIT
    let body2 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "  What  is  the  Capital  of  France?  "}]
    });
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx2.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary { status_code, .. } => {
            assert_eq!(status_code, 200);
        }
        _ => panic!("Expected cache HIT after whitespace normalization"),
    }
}

#[tokio::test]
async fn test_different_model_no_cache_hit() {
    let config = json!({"ttl_seconds": 300, "include_model_in_key": true});
    let plugin = make_plugin(config);

    // Cache with gpt-4o
    let body1 = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx1.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body1).unwrap(),
    );
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;
    let response_headers = HashMap::new();
    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"hi")
        .await;

    // Same prompt but different model — should MISS
    let body2 = json!({
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx2.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body2).unwrap(),
    );
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_get_request_skipped() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/chat".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("ai_cache_status"));
}

#[tokio::test]
async fn test_non_json_skipped() {
    let config = json!({});
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/plain".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_error_response_not_cached() {
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body).unwrap(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    // 500 response should not be cached
    let response_headers = HashMap::new();
    let _ = plugin
        .on_final_response_body(&mut ctx, 500, &response_headers, b"error")
        .await;

    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[test]
fn test_tracked_keys_count() {
    let config = json!({});
    let plugin = make_plugin(config);
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_sensitive_response_headers_not_replayed_on_cache_hit() {
    // SECURITY: Cached responses must not replay per-response identity
    // (cookies, auth tokens) or per-request rate-limit/trace headers to a
    // different consumer. Without this, a cache hit would leak the original
    // user's session cookie to the next user that asks the same question.
    let config = json!({"ttl_seconds": 300});
    let plugin = make_plugin(config);

    let body_json = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}]
    });
    let body_str = serde_json::to_string(&body_json).unwrap();

    // First request — cache MISS, store response with a Set-Cookie / Auth header.
    let mut ctx1 = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx1.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers1 = HashMap::new();
    headers1.insert("content-type".to_string(), "application/json".to_string());
    let _ = plugin.before_proxy(&mut ctx1, &mut headers1).await;

    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    response_headers.insert(
        "Set-Cookie".to_string(),
        "session=user-A-secret".to_string(),
    );
    response_headers.insert(
        "authorization".to_string(),
        "Bearer user-A-token".to_string(),
    );
    response_headers.insert(
        "X-Request-Id".to_string(),
        "request-id-from-user-A".to_string(),
    );
    response_headers.insert("x-ai-ratelimit-remaining".to_string(), "999".to_string());

    let _ = plugin
        .on_final_response_body(&mut ctx1, 200, &response_headers, b"Hello back")
        .await;

    // Second request from a different consumer (different IP) hits the cache.
    let mut ctx2 = RequestContext::new(
        "203.0.113.99".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx2.metadata
        .insert("request_body".to_string(), body_str.clone());
    let mut headers2 = HashMap::new();
    headers2.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    match result {
        PluginResult::RejectBinary { headers, .. } => {
            assert!(
                !headers.contains_key("Set-Cookie"),
                "cache MUST NOT replay Set-Cookie to a different consumer"
            );
            assert!(
                !headers.contains_key("authorization"),
                "cache MUST NOT replay Authorization to a different consumer"
            );
            assert!(
                !headers.contains_key("X-Request-Id"),
                "cache MUST NOT replay X-Request-Id to a different consumer"
            );
            assert!(
                !headers.contains_key("x-ai-ratelimit-remaining"),
                "cache MUST NOT replay rate-limit counters from the original request"
            );
            // The cache-status indicator and content-type must still be present.
            assert_eq!(headers.get("x-ai-cache-status").unwrap(), "HIT");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
        }
        _ => panic!("Expected cache HIT (RejectBinary), got {:?}", result),
    }
}

// -------------------------------------------------------------------------
// Cross-prompt / param-collapse / consumer-leak hardening tests.
//
// These guard against four distinct correctness/security gaps:
//   1. Anthropic top-level `system` prompt collapsing into the messages key.
//   2. Sampling-parameter differences (temperature) collapsing under the old
//      `include_params_in_key=false` default.
//   3. Cross-consumer cache replay under the old `scope_by_consumer=false`
//      default.
//   4. `stream:true` vs `stream:false` collapsing into the same entry, which
//      would let a non-streaming MISS-then-store replay JSON to a streaming
//      caller (and vice versa).
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_different_system_prompt_no_cache_hit() {
    // SECURITY: Anthropic Messages API uses a top-level `system` field, not
    // an in-`messages` system role. Without including it in the key, two
    // requests with identical messages but different system prompts would
    // collapse to the same cache entry — a cross-prompt poisoning vector.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "claude-3-5-sonnet-20241022",
        "system": "You are a helpful assistant.",
        "messages": [{"role": "user", "content": "Say hi."}]
    });
    let body2 = json!({
        "model": "claude-3-5-sonnet-20241022",
        "system": "You are a pirate. Speak in pirate dialect.",
        "messages": [{"role": "user", "content": "Say hi."}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        b"Hello!",
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "different `system` prompts must NOT collapse to the same cache key"
    );
}

#[tokio::test]
async fn test_different_system_array_form_no_cache_hit() {
    // Anthropic also accepts `system` as an array of content blocks; the
    // array form must produce different keys for different system text.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "claude-3-5-sonnet-20241022",
        "system": [{"type": "text", "text": "Be terse."}],
        "messages": [{"role": "user", "content": "ping"}]
    });
    let body2 = json!({
        "model": "claude-3-5-sonnet-20241022",
        "system": [{"type": "text", "text": "Be verbose."}],
        "messages": [{"role": "user", "content": "ping"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        b"pong",
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "different array-form `system` prompts must NOT collapse to the same cache key"
    );
}

#[tokio::test]
async fn test_different_temperature_no_cache_hit_with_default_config() {
    // SECURITY: With the new `include_params_in_key=true` default, two
    // requests differing only in `temperature` must produce different cache
    // keys. The old default (`false`) silently served a temperature=0
    // response to a temperature=1.5 request.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "gpt-4o",
        "temperature": 0.0,
        "messages": [{"role": "user", "content": "draft a poem"}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "temperature": 1.5,
        "messages": [{"role": "user", "content": "draft a poem"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        b"poem-from-temp-0",
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "different `temperature` must NOT collapse with `include_params_in_key=true` default"
    );
}

#[tokio::test]
async fn test_same_request_different_consumer_no_cache_hit_with_default_config() {
    // SECURITY: With the new `scope_by_consumer=true` default, two requests
    // from different authenticated consumers must NOT share a cache entry.
    // The old default (`false`) leaked one consumer's response to the next.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "what's my last invoice"}]
    });
    let body_str = serde_json::to_string(&body).unwrap();

    let alice = make_consumer("alice");
    let bob = make_consumer("bob");

    store_response(&plugin, &body_str, Some(alice.clone()), b"alice-only-data").await;

    let hit = run_before_proxy_get_status(&plugin, &body_str, Some(bob.clone())).await;
    assert!(
        !hit,
        "consumer `bob` MUST NOT receive a cache hit on `alice`'s entry under default config"
    );

    // Sanity check: alice's repeat hits her own entry.
    let alice_hit = run_before_proxy_get_status(&plugin, &body_str, Some(alice.clone())).await;
    assert!(
        alice_hit,
        "consumer `alice` SHOULD see her own cache entry on repeat"
    );
}

#[tokio::test]
async fn test_same_request_same_consumer_same_params_cache_hit_positive() {
    // POSITIVE control: when *every* key field matches (messages, model,
    // params, system, stream, consumer), the second call must HIT. Confirms
    // the harder-to-collide key composition is not over-broken.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));
    let consumer = make_consumer("carol");

    let body = json!({
        "model": "gpt-4o",
        "temperature": 0.7,
        "max_tokens": 256,
        "stream": false,
        "system": "You are concise.",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let body_str = serde_json::to_string(&body).unwrap();

    store_response(&plugin, &body_str, Some(consumer.clone()), b"hello-back").await;

    let hit = run_before_proxy_get_status(&plugin, &body_str, Some(consumer)).await;
    assert!(
        hit,
        "fully-identical request from the same consumer MUST hit the cache (positive control)"
    );
}

#[tokio::test]
async fn test_stream_true_vs_false_no_cache_hit() {
    // SECURITY: `stream:true` produces SSE; `stream:false` produces a single
    // JSON response. They must not share a cache entry. Note that we cache
    // the `stream:false` response (since SSE is filtered out at store time)
    // — without `stream` in the key, a `stream:true` follow-up would receive
    // the buffered JSON in a `RejectBinary` reply and the client SDK would
    // fail to parse SSE.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body_nostream = json!({
        "model": "gpt-4o",
        "stream": false,
        "messages": [{"role": "user", "content": "hello"}]
    });
    let body_stream = json!({
        "model": "gpt-4o",
        "stream": true,
        "messages": [{"role": "user", "content": "hello"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body_nostream).unwrap(),
        None,
        b"{\"choices\":[{\"message\":{\"content\":\"hi\"}}]}",
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body_stream).unwrap(), None)
            .await;
    assert!(
        !hit,
        "`stream:true` request MUST NOT receive the `stream:false` cached entry"
    );
}

#[tokio::test]
async fn test_different_tools_no_cache_hit() {
    // SECURITY: Two requests with identical messages but different tool
    // schemas should produce different responses (model may invoke a tool in
    // one and not the other). Must not collapse to the same key.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "gpt-4o",
        "tools": [{"type": "function", "function": {"name": "get_weather"}}],
        "messages": [{"role": "user", "content": "weather in NYC?"}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "tools": [{"type": "function", "function": {"name": "get_news"}}],
        "messages": [{"role": "user", "content": "weather in NYC?"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        b"weather-tool-call",
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "different `tools` definitions must NOT collapse to the same cache key"
    );
}

#[tokio::test]
async fn test_different_response_format_no_cache_hit() {
    // OpenAI: `response_format: {"type":"json_object"}` vs `text` produces
    // structurally different responses; must not collide.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "gpt-4o",
        "response_format": {"type": "json_object"},
        "messages": [{"role": "user", "content": "give me a fruit"}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "response_format": {"type": "text"},
        "messages": [{"role": "user", "content": "give me a fruit"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        b"{\"fruit\":\"apple\"}",
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(
        !hit,
        "different `response_format` must NOT collapse to the same cache key"
    );
}

#[tokio::test]
async fn test_different_seed_no_cache_hit() {
    // OpenAI's `seed` controls reproducibility; different seeds can produce
    // different completions and should not collide.
    let plugin = make_plugin(json!({"ttl_seconds": 300}));

    let body1 = json!({
        "model": "gpt-4o",
        "seed": 42,
        "messages": [{"role": "user", "content": "tell a joke"}]
    });
    let body2 = json!({
        "model": "gpt-4o",
        "seed": 99,
        "messages": [{"role": "user", "content": "tell a joke"}]
    });

    store_response(
        &plugin,
        &serde_json::to_string(&body1).unwrap(),
        None,
        b"joke-seed-42",
    )
    .await;

    let hit =
        run_before_proxy_get_status(&plugin, &serde_json::to_string(&body2).unwrap(), None).await;
    assert!(!hit, "different `seed` must NOT collapse cache keys");
}
