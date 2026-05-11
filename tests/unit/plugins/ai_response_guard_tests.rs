use ferrum_edge::plugins::ai_response_guard::AiResponseGuard;
use ferrum_edge::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_plugin(config: serde_json::Value) -> AiResponseGuard {
    AiResponseGuard::new(&config).unwrap()
}

fn ctx_with_content_type(method: &str, content_type: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/chat".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), content_type.to_string());
    ctx
}

fn ctx_without_content_type(method: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/chat".to_string(),
    )
}

#[test]
fn test_new_with_pii_patterns() {
    let config = json!({
        "pii_patterns": ["ssn", "credit_card", "email"],
        "action": "reject"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_new_with_blocked_phrases() {
    let config = json!({
        "blocked_phrases": ["kill yourself", "illegal activity"],
        "action": "reject"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_new_with_blocked_patterns() {
    let config = json!({
        "blocked_patterns": [
            {"name": "profanity", "regex": "\\b(?:damn|hell)\\b"}
        ],
        "action": "warn"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_new_with_required_fields() {
    let config = json!({
        "required_fields": ["choices", "model"],
        "action": "reject"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_new_with_max_completion_length() {
    let config = json!({
        "max_completion_length": 1000,
        "action": "reject"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_new_no_patterns_fails() {
    let config = json!({});
    let result = AiResponseGuard::new(&config);
    assert!(result.is_err());
    assert!(
        result
            .err()
            .unwrap()
            .contains("no patterns, phrases, or validation rules")
    );
}

#[test]
fn test_new_invalid_custom_regex_fails() {
    let config = json!({
        "blocked_patterns": [
            {"name": "bad", "regex": "[invalid"}
        ]
    });
    let result = AiResponseGuard::new(&config);
    assert!(result.is_err());
}

#[test]
fn test_new_invalid_custom_pii_regex_fails() {
    let config = json!({
        "custom_pii_patterns": [
            {"name": "bad", "regex": "(unclosed"}
        ]
    });
    let result = AiResponseGuard::new(&config);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_pii_detection_reject() {
    let config = json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "Your SSN is 123-45-6789"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("content guard"));
            assert!(body.contains("pii:ssn"));
        }
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

#[tokio::test]
async fn test_pii_detection_warn() {
    let config = json!({
        "pii_patterns": ["email"],
        "action": "warn"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "Contact us at user@example.com"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("ai_response_guard_detected"));
}

#[tokio::test]
async fn test_pii_detection_redact() {
    let config = json!({
        "pii_patterns": ["email"],
        "action": "redact"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "Contact us at user@example.com"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    // on_response_body marks for redaction
    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("ai_response_guard_redacted"));

    // transform_response_body actually redacts
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await;
    assert!(transformed.is_some());
    let transformed_str = String::from_utf8(transformed.unwrap()).unwrap();
    assert!(!transformed_str.contains("user@example.com"));
    assert!(transformed_str.contains("[REDACTED:pii:email]"));
}

#[tokio::test]
async fn test_blocked_phrase_detection() {
    let config = json!({
        "blocked_phrases": ["harmful content"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "This contains harmful content that should be blocked"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn test_clean_response_passes() {
    let config = json!({
        "pii_patterns": ["ssn", "credit_card"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "The weather is nice today"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_non_json_skipped() {
    let config = json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, b"Your SSN is 123-45-6789")
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_error_status_skipped() {
    let config = json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "SSN: 123-45-6789"}}]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    // 4xx/5xx responses are not scanned
    let result = plugin
        .on_response_body(&mut ctx, 400, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_required_fields_missing() {
    let config = json!({
        "required_fields": ["choices", "model"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{"message": {"content": "hi"}}]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("model"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_max_completion_length() {
    let config = json!({
        "max_completion_length": 10,
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "choices": [{
            "message": {
                "content": "This is a very long completion that exceeds the limit"
            }
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn test_anthropic_response_format() {
    let config = json!({
        "pii_patterns": ["email"],
        "action": "reject"
    });
    let plugin = make_plugin(config);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/chat".to_string(),
    );
    let body = serde_json::to_vec(&json!({
        "content": [{
            "type": "text",
            "text": "Please email admin@secret.com for help"
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[test]
fn test_require_json_config() {
    let config = json!({
        "require_json": true
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_redact_action_with_no_patterns_still_works_with_other_rules() {
    let config = json!({
        "max_completion_length": 100,
        "action": "redact"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.name(), "ai_response_guard");
}

#[test]
fn test_requires_response_body_buffering() {
    let config = json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    });
    let plugin = make_plugin(config);
    assert_eq!(plugin.priority(), 4075);
    assert_eq!(
        plugin.supported_protocols(),
        &[ProxyProtocol::Http, ProxyProtocol::Grpc]
    );
    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "application/json")));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type(
        "POST",
        "multipart/form-data; boundary=abc"
    )));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "text/plain")));
    assert!(plugin.should_buffer_response_body(&ctx_without_content_type("POST")));
    assert!(!plugin.should_buffer_response_body(&ctx_with_content_type("GET", "application/json")));

    let mut sse_accept = ctx_with_content_type("POST", "application/json");
    sse_accept
        .headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    assert!(
        !plugin.should_buffer_response_body(&sse_accept),
        "SSE clients must keep the response streaming instead of forcing a full-body buffer"
    );

    let mut stream_true = ctx_with_content_type("POST", "application/json");
    stream_true
        .metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());
    assert!(
        !plugin.should_buffer_response_body(&stream_true),
        "prompt-shield stream:true metadata must prevent unbounded response buffering"
    );
}

#[test]
fn test_unknown_builtin_pii_pattern_is_fatal() {
    // Unknown built-in names previously logged a warning and silently
    // dropped detection coverage. They are now fatal so misconfiguration
    // cannot quietly disable PII protection.
    let err = AiResponseGuard::new(&json!({
        "pii_patterns": ["this_is_not_a_real_pii_type"],
        "action": "reject"
    }))
    .err()
    .unwrap();
    assert!(err.contains("unknown built-in PII pattern"), "got: {err}");
}

#[test]
fn test_invalid_config_shapes_rejected() {
    for (config, needle) in [
        (json!(null), "config must be an object"),
        (json!({"pii_patterns": ["ssn"], "action": "drop"}), "action"),
        (
            json!({"pii_patterns": ["ssn"], "scan_fields": "everything"}),
            "scan_fields",
        ),
        (
            json!({"pii_patterns": ["ssn"], "max_scan_bytes": 0}),
            "max_scan_bytes",
        ),
        (
            json!({"pii_patterns": ["ssn"], "require_json": "yes"}),
            "require_json",
        ),
        (
            json!({"required_fields": ["choices", 42]}),
            "required_fields[1]",
        ),
        (json!({"blocked_phrases": [""]}), "blocked_phrases[0]"),
        (
            json!({"custom_pii_patterns": [{"name": "secret"}]}),
            "custom_pii_patterns[0].regex",
        ),
        (json!({"blocked_patterns": [42]}), "blocked_patterns[0]"),
    ] {
        let err = AiResponseGuard::new(&config).err().unwrap();
        assert!(err.contains(needle), "needle={needle}, got: {err}");
    }
}

// ─── ScanMode::All — structural keys are protected from redaction ─────

fn ipv4_redact_plugin() -> AiResponseGuard {
    // ip_address pattern is broad and will match strings that look like
    // dotted quads — including timestamps in the form "2024.01.15.10".
    AiResponseGuard::new(&json!({
        "pii_patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "redact"
    }))
    .unwrap()
}

#[tokio::test]
async fn test_all_mode_does_not_redact_structural_keys() {
    // The previous implementation walked every string in the response and
    // would happily rewrite values under structural keys like `id`,
    // `model`, `created`, etc. Verify those are now protected even when
    // the value matches a PII pattern.
    let plugin = ipv4_redact_plugin();

    // Body has no recognized AI shape (no "choices", "content",
    // "candidates"), so the recursive walker is exercised.
    let body = serde_json::to_vec(&json!({
        "id": "127.0.0.1",        // looks like an IP — must be preserved
        "model": "10.20.30.40",   // also IP-shaped — must be preserved
        "details": "user IP was 192.168.1.99 last seen"
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = super::plugin_utils::create_test_context();
    ctx.method = "POST".to_string();

    // First trigger detection; then call transform_response_body to apply.
    let _ = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("expected redacted body when match present");

    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
    assert_eq!(v["id"], "127.0.0.1", "structural id must be preserved");
    assert_eq!(
        v["model"], "10.20.30.40",
        "structural model must be preserved"
    );
    assert!(
        v["details"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "non-structural strings should still be redacted: {}",
        v["details"]
    );
}

#[tokio::test]
async fn test_all_mode_uses_structured_redaction_when_choices_present() {
    // When the body looks like a recognized AI response (has `choices`),
    // even ScanMode::All should prefer the structured redactor that only
    // touches choices[].message.content rather than the recursive walker.
    let plugin = ipv4_redact_plugin();

    let body = serde_json::to_vec(&json!({
        "id": "10.0.0.1",
        "model": "127.0.0.1",
        "choices": [{
            "message": {"role": "assistant", "content": "Server lives at 8.8.8.8"}
        }]
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = super::plugin_utils::create_test_context();
    ctx.method = "POST".to_string();
    let _ = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("expected transformation when match present");

    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();
    assert_eq!(v["id"], "10.0.0.1");
    assert_eq!(v["model"], "127.0.0.1");
    assert!(
        v["choices"][0]["message"]["content"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "completion content should be redacted: {}",
        v["choices"][0]["message"]["content"]
    );
}

#[tokio::test]
async fn test_all_mode_redacts_sibling_fields_when_choices_present() {
    // Regression test: when `scan_mode == All` and `choices` contains
    // PII, the plugin must still redact PII in sibling fields outside
    // the recognized completion shape. Previously the either-or split
    // meant the structured redactor ran and the recursive walker was
    // skipped, leaving sibling PII untouched even though detection
    // reported it.
    let plugin = ipv4_redact_plugin();

    let body = serde_json::to_vec(&json!({
        "id": "10.0.0.1",                 // structural — must be preserved
        "model": "127.0.0.1",             // structural — must be preserved
        "choices": [{
            "message": {"role": "assistant", "content": "Server lives at 8.8.8.8"}
        }],
        "metadata": {"trace": "upstream 192.168.1.1 responded"},
        "extra": "see also 172.16.0.5"
    }))
    .unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let mut ctx = super::plugin_utils::create_test_context();
    ctx.method = "POST".to_string();
    let _ = plugin
        .on_response_body(&mut ctx, 200, &headers, &body)
        .await;
    let transformed = plugin
        .transform_response_body(&body, Some("application/json"), &headers)
        .await
        .expect("expected transformation when match present");

    let v: serde_json::Value = serde_json::from_slice(&transformed).unwrap();

    // Structural keys preserved
    assert_eq!(v["id"], "10.0.0.1", "structural id must be preserved");
    assert_eq!(
        v["model"], "127.0.0.1",
        "structural model must be preserved"
    );

    // Known completion content redacted (structured redactor path)
    assert!(
        v["choices"][0]["message"]["content"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "completion content should be redacted: {}",
        v["choices"][0]["message"]["content"]
    );

    // Sibling fields redacted (recursive walker path)
    assert!(
        v["metadata"]["trace"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "metadata.trace sibling should be redacted: {}",
        v["metadata"]["trace"]
    );
    assert!(
        v["extra"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:pii:ip_address]"),
        "extra sibling should be redacted: {}",
        v["extra"]
    );
}

// ─── SSE / streaming response support ────────────────────────────────

fn sse_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "text/event-stream".to_string());
    h
}

fn openai_sse_body(chunks: &[&str]) -> Vec<u8> {
    let mut body = String::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let frame = json!({
            "id": format!("chatcmpl-{}", i),
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"content": chunk}, "finish_reason": serde_json::Value::Null}]
        });
        body.push_str(&format!(
            "data: {}\n\n",
            serde_json::to_string(&frame).unwrap()
        ));
    }
    body.push_str("data: [DONE]\n\n");
    body.into_bytes()
}

#[tokio::test]
async fn test_sse_pii_detection_reject() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["Your SSN is ", "123-45-6789", " ok?"]);

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), &body)
        .await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("pii:ssn"));
        }
        _ => panic!("Expected Reject for SSE with SSN, got {:?}", result),
    }
}

#[tokio::test]
async fn test_sse_pii_detection_warn() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "warn"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["Contact ", "admin@secret.com", " now"]);

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        ctx.metadata.contains_key("ai_response_guard_detected"),
        "warn mode should set detected metadata"
    );
}

#[tokio::test]
async fn test_sse_pii_redaction() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["Email: user@example.com please"]);

    // on_response_body marks for redaction
    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("ai_response_guard_redacted"));

    // transform_response_body actually redacts
    let transformed = plugin
        .transform_response_body(&body, Some("text/event-stream"), &sse_headers())
        .await;
    let transformed = transformed.expect("expected redacted SSE body");
    let transformed_str = String::from_utf8(transformed).unwrap();
    assert!(
        !transformed_str.contains("user@example.com"),
        "email should be removed"
    );
    assert!(
        transformed_str.contains("[REDACTED:pii:email]"),
        "should contain redaction placeholder"
    );
    assert!(
        transformed_str.contains("data: "),
        "SSE framing must be preserved"
    );
    assert!(
        transformed_str.contains("[DONE]"),
        "[DONE] sentinel must be preserved"
    );
}

#[tokio::test]
async fn test_sse_clean_response_passes() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn", "credit_card"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["The weather ", "is nice today"]);

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_sse_max_completion_length_across_deltas() {
    let plugin = make_plugin(json!({
        "max_completion_length": 10,
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    // Each chunk is short, but concatenated they exceed 10 chars
    let body = openai_sse_body(&["Hello ", "wonderful ", "world!"]);

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), &body)
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "accumulated text exceeds max_completion_length"
    );
}

#[tokio::test]
async fn test_sse_anthropic_streaming_format() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    let mut body = String::new();
    // Anthropic content_block_delta frames
    for text in &["Your SSN is ", "123-45-6789"] {
        let frame = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": text}
        });
        body.push_str(&format!(
            "data: {}\n\n",
            serde_json::to_string(&frame).unwrap()
        ));
    }
    body.push_str("data: {\"type\":\"message_stop\"}\n\n");

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), body.as_bytes())
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "Anthropic SSE with SSN should be rejected"
    );
}

#[tokio::test]
async fn test_sse_anthropic_redaction() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    let frame = json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": "email me at bob@corp.io"}
    });
    let body_str = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame).unwrap()
    );
    let body = body_str.as_bytes();

    let _ = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), body)
        .await;
    let transformed = plugin
        .transform_response_body(body, Some("text/event-stream"), &sse_headers())
        .await
        .expect("expected redacted body");
    let out = String::from_utf8(transformed).unwrap();
    assert!(!out.contains("bob@corp.io"));
    assert!(out.contains("[REDACTED:pii:email]"));
}

#[tokio::test]
async fn test_sse_gemini_streaming_format() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["credit_card"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    let mut body = String::new();
    for text in &["Card number: ", "4111-1111-1111-1111"] {
        let frame = json!({
            "candidates": [{"content": {"parts": [{"text": text}]}}]
        });
        body.push_str(&format!(
            "data: {}\n\n",
            serde_json::to_string(&frame).unwrap()
        ));
    }

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), body.as_bytes())
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "Gemini SSE with credit card should be rejected"
    );
}

#[tokio::test]
async fn test_sse_scan_all_mode() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    // IP address appears in a non-content field within the SSE body
    let frame = json!({"metadata": {"source_ip": "192.168.1.1"}, "choices": [{"delta": {"content": "hi"}}]});
    let body = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame).unwrap()
    );

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), body.as_bytes())
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "scan_all mode should detect PII anywhere in SSE body"
    );
}

#[tokio::test]
async fn test_sse_scan_all_redaction() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ip_address"],
        "scan_fields": "all",
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    let frame =
        json!({"extra": "see 10.0.0.1", "choices": [{"delta": {"content": "IP: 8.8.8.8"}}]});
    let body = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame).unwrap()
    );

    let _ = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), body.as_bytes())
        .await;
    let transformed = plugin
        .transform_response_body(body.as_bytes(), Some("text/event-stream"), &sse_headers())
        .await
        .expect("expected redacted body");
    let out = String::from_utf8(transformed).unwrap();
    assert!(!out.contains("10.0.0.1"));
    assert!(!out.contains("8.8.8.8"));
    assert!(out.contains("[REDACTED:pii:ip_address]"));
}

#[tokio::test]
async fn test_sse_blocked_phrase_detection() {
    let plugin = make_plugin(json!({
        "blocked_phrases": ["harmful content"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["This has ", "harmful content", " in it"]);

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Reject { .. }));
}

#[tokio::test]
async fn test_sse_error_status_skipped() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = openai_sse_body(&["SSN: 123-45-6789"]);

    let result = plugin
        .on_response_body(&mut ctx, 500, &sse_headers(), &body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_sse_empty_frames_pass() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let body = b"data: [DONE]\n\n";

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_sse_redaction_preserves_non_content_frames() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));

    // Frame 1 has no content, frame 2 has PII
    let frame1 = json!({"choices": [{"index": 0, "delta": {"role": "assistant"}}]});
    let frame2 = json!({"choices": [{"index": 0, "delta": {"content": "hi user@test.io"}}]});
    let body = format!(
        "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame1).unwrap(),
        serde_json::to_string(&frame2).unwrap()
    );

    let transformed = plugin
        .transform_response_body(body.as_bytes(), Some("text/event-stream"), &HashMap::new())
        .await
        .expect("expected redacted body");
    let out = String::from_utf8(transformed).unwrap();

    // First frame (role-only) should still be present
    assert!(out.contains("\"role\":\"assistant\""));
    // Second frame should be redacted
    assert!(!out.contains("user@test.io"));
    assert!(out.contains("[REDACTED:pii:email]"));
}

#[tokio::test]
async fn test_sse_no_redaction_returns_none() {
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "redact"
    }));
    let body = openai_sse_body(&["The weather is nice"]);

    let transformed = plugin
        .transform_response_body(&body, Some("text/event-stream"), &HashMap::new())
        .await;
    assert!(
        transformed.is_none(),
        "no modification expected when no PII present"
    );
}

#[tokio::test]
async fn test_sse_scan_all_no_match_returns_none() {
    // Fast-skip: scan-all mode with no pattern anywhere in the body must
    // return None without paying per-frame parse/serialize cost.
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn", "credit_card"],
        "scan_fields": "all",
        "action": "redact"
    }));
    let body = openai_sse_body(&["nothing sensitive here"]);

    let transformed = plugin
        .transform_response_body(&body, Some("text/event-stream"), &HashMap::new())
        .await;
    assert!(transformed.is_none());
}

#[tokio::test]
async fn test_sse_redaction_preserves_crlf_line_endings() {
    // Real-world SSE servers often emit CRLF terminators. The redactor must
    // preserve them on rewritten `data:` lines instead of mixing CR/LF.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let frame = json!({"choices": [{"index": 0, "delta": {"content": "ping admin@example.com"}}]});
    let body = format!(
        "data: {}\r\n\r\ndata: [DONE]\r\n\r\n",
        serde_json::to_string(&frame).unwrap()
    );

    let transformed = plugin
        .transform_response_body(body.as_bytes(), Some("text/event-stream"), &HashMap::new())
        .await
        .expect("expected redacted body");
    let out = String::from_utf8(transformed).unwrap();

    // Every `data:` line we emitted must end with CRLF, not bare LF.
    for line in out.split('\n') {
        if line.starts_with("data:") {
            assert!(
                line.ends_with('\r'),
                "data line lost CR terminator: {:?}",
                line
            );
        }
    }
    // Content was actually redacted.
    assert!(!out.contains("admin@example.com"));
    assert!(out.contains("[REDACTED:pii:email]"));
    // [DONE] sentinel passed through unchanged (still CRLF).
    assert!(out.contains("data: [DONE]\r"));
}

#[tokio::test]
async fn test_sse_preserves_non_data_event_lines() {
    // SSE comments (`:`), `event:`, `id:`, and `retry:` lines must round-trip
    // unchanged. Only `data:` frames carry JSON we touch.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact"
    }));
    let frame = json!({"choices": [{"index": 0, "delta": {"content": "hi user@test.io"}}]});
    let body = format!(
        ": keep-alive comment\nevent: message\nid: 42\nretry: 5000\ndata: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&frame).unwrap()
    );

    let transformed = plugin
        .transform_response_body(body.as_bytes(), Some("text/event-stream"), &HashMap::new())
        .await
        .expect("expected redacted body");
    let out = String::from_utf8(transformed).unwrap();

    assert!(out.contains(": keep-alive comment"));
    assert!(out.contains("event: message"));
    assert!(out.contains("id: 42"));
    assert!(out.contains("retry: 5000"));
    assert!(out.contains("[REDACTED:pii:email]"));
    assert!(!out.contains("user@test.io"));
}

#[tokio::test]
async fn test_sse_oversize_body_skipped_in_transform() {
    // The `max_scan_bytes` guard must block redaction of oversize SSE bodies
    // even when content-type is text/event-stream.
    let plugin = make_plugin(json!({
        "pii_patterns": ["email"],
        "action": "redact",
        "max_scan_bytes": 64
    }));
    let frame = json!({"choices": [{"index": 0, "delta": {"content": "user@example.com"}}]});
    let mut body = String::new();
    // Inflate well past 64 bytes.
    for _ in 0..16 {
        body.push_str(&format!(
            "data: {}\n\n",
            serde_json::to_string(&frame).unwrap()
        ));
    }
    assert!(body.len() > 64);

    let transformed = plugin
        .transform_response_body(body.as_bytes(), Some("text/event-stream"), &HashMap::new())
        .await;
    assert!(
        transformed.is_none(),
        "oversize body must skip redaction (returned Some)"
    );
}

#[tokio::test]
async fn test_sse_oversize_body_skipped_in_detection() {
    // Mirror the transform guard: `on_response_body` must also bail out on
    // oversize SSE bodies rather than buffering and scanning them.
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "reject",
        "max_scan_bytes": 64
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    let filler = "filler ".repeat(20);
    let body = openai_sse_body(&["SSN: 123-45-6789 ", filler.as_str()]);
    assert!(body.len() > 64);

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), &body)
        .await;
    // Skipped, not rejected — the size guard wins over detection.
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_sse_cross_frame_pii_redact_returns_none() {
    // PII split across frames: detection still flags it (on accumulated
    // content), but per-frame redaction can't reach it. The redactor must
    // return None (no body change) and log a warning. We can't assert the
    // log here without a tracing subscriber harness, but we can pin the
    // observable behavior: no transform, detection metadata still set.
    let plugin = make_plugin(json!({
        "pii_patterns": ["ssn"],
        "action": "redact"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");
    // The SSN "123-45-6789" is split across two delta chunks.
    let body = openai_sse_body(&["my ssn is 123-", "45-6789 ok"]);

    let detect = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), &body)
        .await;
    assert!(matches!(detect, PluginResult::Continue));
    assert!(
        ctx.metadata.contains_key("ai_response_guard_redacted"),
        "accumulated-text detection should still fire"
    );

    let transformed = plugin
        .transform_response_body(&body, Some("text/event-stream"), &sse_headers())
        .await;
    assert!(
        transformed.is_none(),
        "cross-frame PII cannot be redacted per-frame; expected zero-copy None"
    );
}

#[tokio::test]
async fn test_sse_accumulated_text_order_is_deterministic() {
    // Multiple choice indices arriving out of order must accumulate in a
    // stable, index-sorted order so detection results don't flap between
    // runs. We assert that a `max_completion_length` check on a high-index
    // choice fires the same way regardless of frame arrival order.
    let plugin = make_plugin(json!({
        "max_completion_length": 5,
        "action": "reject"
    }));
    let mut ctx = ctx_with_content_type("POST", "text/event-stream");

    // Emit choice index=2 first, then index=0, then index=1. Each choice's
    // content alone is short, but index=2's exceeds the limit.
    let frames = [
        json!({"choices": [{"index": 2, "delta": {"content": "longer content"}}]}),
        json!({"choices": [{"index": 0, "delta": {"content": "hi"}}]}),
        json!({"choices": [{"index": 1, "delta": {"content": "ok"}}]}),
    ];
    let mut body = String::new();
    for frame in &frames {
        body.push_str(&format!(
            "data: {}\n\n",
            serde_json::to_string(frame).unwrap()
        ));
    }

    let result = plugin
        .on_response_body(&mut ctx, 200, &sse_headers(), body.as_bytes())
        .await;
    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "max_completion_length must be enforced regardless of frame order"
    );
}
