//! Tests for jwt_auth plugin (proxy-side JWT authentication, not admin JWT)

use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, RequestContext, jwt_auth::JwtAuth};
use serde_json::json;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ferrum_edge::config::types::Consumer;
use serde_json::Value;
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, assert_reject, create_test_consumer};

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn create_jwt_token(claims: &serde_json::Value, secret: &str) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

#[tokio::test]
async fn test_jwt_auth_plugin_creation() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "jwt_auth");
}

#[tokio::test]
async fn test_jwt_auth_creation_with_config() {
    let plugin = JwtAuth::new(&json!({
        "token_lookup": "header:X-Token",
        "consumer_claim_field": "user_id"
    }))
    .unwrap();
    assert_eq!(plugin.name(), "jwt_auth");
}

#[tokio::test]
async fn test_jwt_auth_successful_with_bearer_header() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "test-jwt-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_jwt_auth_successful_with_consumer_id() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Use consumer ID instead of username
    let token = create_jwt_token(&json!({"sub": "test-consumer"}), "test-jwt-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_jwt_auth_wrong_secret() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "wrong-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_missing_token() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    let mut ctx = make_ctx();
    // No authorization header

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_jwt_auth_wrong_claim_value() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Token signed with correct secret but sub doesn't match any consumer
    let token = create_jwt_token(&json!({"sub": "unknown-user"}), "test-jwt-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_custom_claim_field() {
    let plugin = JwtAuth::new(&json!({"consumer_claim_field": "user_id"})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"user_id": "testuser"}), "test-jwt-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_jwt_auth_query_param_lookup() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "query:jwt"})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "test-jwt-secret");

    let mut ctx = make_ctx();
    ctx.query_params.insert("jwt".to_string(), token);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_jwt_auth_custom_header_lookup() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "header:X-Token"})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "test-jwt-secret");

    let mut ctx = make_ctx();
    ctx.headers.insert("x-token".to_string(), token);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_jwt_auth_bearer_lowercase() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "test-jwt-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwt_auth_bearer_uppercase() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "test-jwt-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("BEARER {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwt_auth_custom_header_strips_bearer_case_insensitively() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "header:X-Token"})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "test-jwt-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-token".to_string(), format!("BeArEr {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwt_auth_empty_consumers() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "test-jwt-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_malformed_token() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), "Bearer not.a.jwt".to_string());

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ---- Multi-credential rotation tests ----

fn make_consumer_with_jwt_secrets(secrets: &[&str]) -> Consumer {
    let mut credentials = HashMap::new();
    let arr: Vec<Value> = secrets.iter().map(|s| json!({"secret": s})).collect();
    credentials.insert("jwt".to_string(), Value::Array(arr));

    Consumer {
        id: "test-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "testuser".to_string(),
        custom_id: Some("custom-123".to_string()),
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test]
async fn test_jwt_auth_multi_secret_old_secret_still_works() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = make_consumer_with_jwt_secrets(&["old-secret", "new-secret"]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "old-secret");
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_jwt_auth_multi_secret_new_secret_works() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = make_consumer_with_jwt_secrets(&["old-secret", "new-secret"]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "new-secret");
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_jwt_auth_multi_secret_wrong_secret_rejected() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = make_consumer_with_jwt_secrets(&["secret-a", "secret-b"]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "wrong-secret");
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ---- Algorithm confusion / alg:none security regression tests ----
//
// The jsonwebtoken crate v10 does not include Algorithm::None in its enum,
// so alg:"none" tokens fail header deserialization. These tests serve as
// regression guards: if the crate or our code ever changes, they catch it.

/// Build a raw JWT string with an arbitrary header (bypassing the
/// jsonwebtoken encoder so we can forge headers the library refuses to create).
fn forge_jwt(header_json: &str, claims: &serde_json::Value, signature: &str) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    format!("{}.{}.{}", header_b64, claims_b64, signature)
}

#[tokio::test]
async fn test_jwt_auth_rejects_alg_none_unsigned() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    // Forge a token with alg:"none" and an empty signature
    let token = forge_jwt(
        r#"{"alg":"none","typ":"JWT"}"#,
        &json!({"sub": "testuser", "exp": 9999999999u64}),
        "",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_jwt_auth_rejects_alg_none_case_variations() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    for alg in &["none", "None", "NONE", "nOnE"] {
        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
        let token = forge_jwt(
            &header,
            &json!({"sub": "testuser", "exp": 9999999999u64}),
            "",
        );

        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".to_string(), format!("Bearer {}", token));

        let result = plugin.authenticate(&mut ctx, &consumer_index).await;
        assert_reject(result, Some(401));
        assert!(
            ctx.identified_consumer.is_none(),
            "alg:{} must not authenticate",
            alg
        );
    }
}

#[tokio::test]
async fn test_jwt_auth_rejects_alg_none_with_valid_consumer_secret_as_signature() {
    // An attacker might set alg:none but still attach a real HMAC signature,
    // hoping the server ignores the algorithm field and verifies anyway.
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    // Create a legitimately signed token to steal its signature
    let legit_token = create_jwt_token(
        &json!({"sub": "testuser", "exp": 9999999999u64}),
        "test-jwt-secret",
    );
    let legit_sig = legit_token.rsplit('.').next().unwrap_or("");

    // Forge a token with alg:none but the legit signature
    let token = forge_jwt(
        r#"{"alg":"none","typ":"JWT"}"#,
        &json!({"sub": "testuser", "exp": 9999999999u64}),
        legit_sig,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_rejects_algorithm_mismatch_rs256_header_with_hmac_secret() {
    // Algorithm confusion: attacker sets alg:RS256 in header but the consumer
    // only has an HMAC secret. The library must reject the family mismatch.
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    let token = forge_jwt(
        r#"{"alg":"RS256","typ":"JWT"}"#,
        &json!({"sub": "testuser", "exp": 9999999999u64}),
        "fakesignature",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_jwt_auth_rejects_expired_token() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    // exp in the past (before the 60s leeway)
    let token = create_jwt_token(
        &json!({"sub": "testuser", "exp": 1000000000u64}),
        "test-jwt-secret",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_rejects_completely_empty_signature() {
    // A properly-structured 3-part JWT with a valid HS256 header but empty signature
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    let token = forge_jwt(
        r#"{"alg":"HS256","typ":"JWT"}"#,
        &json!({"sub": "testuser", "exp": 9999999999u64}),
        "",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}
