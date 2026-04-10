use ferrum_edge::plugins::ai_response_guard::AiResponseGuard;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_plugin(config: serde_json::Value) -> AiResponseGuard {
    AiResponseGuard::new(&config).unwrap()
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
    assert!(plugin.requires_response_body_buffering());
}
