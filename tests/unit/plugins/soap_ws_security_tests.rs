use ferrum_edge::plugins::soap_ws_security::SoapWsSecurity;
use ferrum_edge::plugins::{HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use serde_json::json;
use std::collections::HashMap;

// ── Helper functions ────────────────────────────────────────────────────────

fn make_ctx_with_soap_body(body: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "text/xml".to_string());
    ctx.metadata
        .insert("request_body".to_string(), body.to_string());
    ctx
}

fn soap_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "text/xml".to_string());
    h
}

fn non_soap_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

fn make_ctx_non_soap() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    )
}

fn timestamp_only_config() -> serde_json::Value {
    json!({
        "timestamp": {
            "require": true,
            "max_age_seconds": 300,
            "clock_skew_seconds": 300
        },
        "reject_missing_security_header": true
    })
}

fn username_token_config() -> serde_json::Value {
    json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": [
                {"username": "alice", "password": "secret123"},
                {"username": "bob", "password": "bobpass"}
            ]
        },
        "reject_missing_security_header": true
    })
}

fn username_token_digest_config() -> serde_json::Value {
    json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordDigest",
            "credentials": [
                {"username": "alice", "password": "secret123"}
            ]
        },
        "reject_missing_security_header": true
    })
}

fn wrap_soap(security_content: &str) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      {}
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetPrice xmlns="http://example.com/prices"><Item>Widget</Item></GetPrice>
  </soap:Body>
</soap:Envelope>"#,
        security_content
    )
}

fn fresh_timestamp() -> String {
    let now = chrono::Utc::now();
    let created = now.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let expires = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%S%.3fZ");
    format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
        <wsu:Created>{}</wsu:Created>
        <wsu:Expires>{}</wsu:Expires>
      </wsu:Timestamp>"#,
        created, expires
    )
}

fn is_reject(result: &PluginResult) -> bool {
    matches!(result, PluginResult::Reject { .. })
}

fn reject_status(result: &PluginResult) -> u16 {
    match result {
        PluginResult::Reject { status_code, .. } => *status_code,
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

fn reject_body(result: &PluginResult) -> &str {
    match result {
        PluginResult::Reject { body, .. } => body.as_str(),
        _ => panic!("Expected Reject, got {:?}", result),
    }
}

// ── Constructor validation tests ────────────────────────────────────────────

#[test]
fn test_non_object_config_is_error() {
    let result = SoapWsSecurity::new(&json!(null));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[test]
fn test_no_features_enabled_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "username_token": { "enabled": false },
        "x509_signature": { "enabled": false },
        "saml": { "enabled": false }
    });
    let result = SoapWsSecurity::new(&config);
    assert!(result.is_err());
    assert!(
        result
            .err()
            .unwrap()
            .contains("no security features enabled")
    );
}

#[test]
fn test_username_token_no_credentials_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "PasswordText",
            "credentials": []
        }
    });
    let result = SoapWsSecurity::new(&config);
    assert!(result.is_err());
    assert!(
        result
            .err()
            .unwrap()
            .contains("no credentials are configured")
    );
}

#[test]
fn test_invalid_password_type_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "username_token": {
            "enabled": true,
            "password_type": "InvalidType",
            "credentials": [{"username": "a", "password": "b"}]
        }
    });
    let result = SoapWsSecurity::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("invalid password_type"));
}

#[test]
fn test_x509_no_trusted_certs_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "x509_signature": {
            "enabled": true,
            "trusted_certs": []
        }
    });
    let result = SoapWsSecurity::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("no trusted_certs"));
}

#[test]
fn test_saml_no_issuers_is_error() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": []
        }
    });
    let result = SoapWsSecurity::new(&config);
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("no trusted_issuers"));
}

#[test]
fn test_valid_timestamp_only_config() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    assert_eq!(plugin.name(), "soap_ws_security");
}

#[test]
fn test_plugin_contract() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();

    assert_eq!(plugin.priority(), priority::SOAP_WS_SECURITY);
    assert_eq!(plugin.priority(), 1500);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    // SOAP WS-Security validates in before_proxy after SOAP bodies are buffered;
    // enrolling it in the generic auth phase rejects before it can inspect the
    // UsernameToken.
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.requires_request_body_before_authenticate());
    assert!(!plugin.needs_request_body_bytes());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[test]
fn test_valid_username_token_config() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    assert_eq!(plugin.name(), "soap_ws_security");
}

// ── Non-SOAP request passthrough tests ──────────────────────────────────────

#[tokio::test]
async fn test_non_soap_content_type_passes_through() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = make_ctx_non_soap();
    let mut headers = non_soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_no_content_type_passes_through() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_application_soap_xml_is_processed() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap(&fresh_timestamp());
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.metadata.insert("request_body".to_string(), body);
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/soap+xml; charset=utf-8".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// ── Missing security header tests ───────────────────────────────────────────

#[tokio::test]
async fn test_missing_security_header_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Header></soap:Header>
      <soap:Body><Test/></soap:Body>
    </soap:Envelope>"#;
    let mut ctx = make_ctx_with_soap_body(body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 401);
    assert!(reject_body(&result).contains("Security header is missing"));
}

#[tokio::test]
async fn test_missing_security_header_allowed_when_not_required() {
    let config = json!({
        "timestamp": { "require": true, "max_age_seconds": 300 },
        "reject_missing_security_header": false
    });
    let plugin = SoapWsSecurity::new(&config).unwrap();
    let body = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Header></soap:Header>
      <soap:Body><Test/></soap:Body>
    </soap:Envelope>"#;
    let mut ctx = make_ctx_with_soap_body(body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// ── Timestamp validation tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_valid_timestamp_passes() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap(&fresh_timestamp());
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_missing_timestamp_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = wrap_soap("<!-- no timestamp -->");
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("missing Timestamp"));
}

#[tokio::test]
async fn test_expired_timestamp_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let old_time = "2020-01-01T00:00:00.000Z";
    let ts = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
            <wsu:Created>{}</wsu:Created>
            <wsu:Expires>{}</wsu:Expires>
        </wsu:Timestamp>"#,
        old_time, old_time
    );
    let body = wrap_soap(&ts);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("too old"));
}

#[tokio::test]
async fn test_future_timestamp_rejects() {
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": {
            "require": true,
            "max_age_seconds": 300,
            "clock_skew_seconds": 5  // very small skew
        }
    }))
    .unwrap();

    let future = (chrono::Utc::now() + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let ts = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
            <wsu:Created>{}</wsu:Created>
        </wsu:Timestamp>"#,
        future
    );
    let body = wrap_soap(&ts);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("in the future"));
}

#[tokio::test]
async fn test_timestamp_expires_past_rejects() {
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": {
            "require": true,
            "max_age_seconds": 86400,
            "clock_skew_seconds": 5
        }
    }))
    .unwrap();

    let now = chrono::Utc::now();
    let created = (now - chrono::Duration::minutes(1)).format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let expires = (now - chrono::Duration::minutes(30)).format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let ts = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
            <wsu:Created>{}</wsu:Created>
            <wsu:Expires>{}</wsu:Expires>
        </wsu:Timestamp>"#,
        created, expires
    );
    let body = wrap_soap(&ts);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("expired"));
}

#[tokio::test]
async fn test_timestamp_require_expires_missing_rejects() {
    let config = json!({
        "timestamp": {
            "require": true,
            "max_age_seconds": 300,
            "require_expires": true
        }
    });
    let plugin = SoapWsSecurity::new(&config).unwrap();

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let ts = format!(
        r#"<wsu:Timestamp wsu:Id="TS-1">
            <wsu:Created>{}</wsu:Created>
        </wsu:Timestamp>"#,
        now
    );
    let body = wrap_soap(&ts);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("missing required Expires"));
}

// ── UsernameToken tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_username_token_password_text_valid() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">secret123</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(ctx.metadata.get("soap_ws_username").unwrap(), "alice");
}

#[tokio::test]
async fn test_username_token_wrong_password_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">wrongpass</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 401);
    assert!(reject_body(&result).contains("invalid password"));
}

#[tokio::test]
async fn test_username_token_unknown_user_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>eve</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">anything</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("unknown username"));
}

#[tokio::test]
async fn test_username_token_missing_password_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("missing Password"));
}

#[tokio::test]
async fn test_username_token_missing_username_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Password>secret123</wsse:Password>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("missing Username"));
}

// ── PasswordDigest tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_password_digest_valid() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();

    // Compute a valid PasswordDigest: Base64(SHA-1(nonce + created + password))
    let nonce_bytes = b"test-nonce-12345";
    let nonce_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);
    let created = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let mut data = Vec::new();
    data.extend_from_slice(nonce_bytes);
    data.extend_from_slice(created.as_bytes());
    data.extend_from_slice(b"secret123");

    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
    let digest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest.as_ref());

    let ut = format!(
        r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{}</wsse:Nonce>
        <wsu:Created>{}</wsu:Created>
    </wsse:UsernameToken>"#,
        digest_b64, nonce_b64, created
    );
    let body = wrap_soap(&ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "Expected Continue, got {:?}",
        result
    );
    assert_eq!(ctx.metadata.get("soap_ws_username").unwrap(), "alice");
}

#[tokio::test]
async fn test_password_digest_wrong_password_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();

    let nonce_bytes = b"wrong-nonce-test";
    let nonce_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);
    let created = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    // Use wrong password for digest
    let mut data = Vec::new();
    data.extend_from_slice(nonce_bytes);
    data.extend_from_slice(created.as_bytes());
    data.extend_from_slice(b"wrongpassword");

    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
    let digest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest.as_ref());

    let ut = format!(
        r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
        <wsse:Nonce>{}</wsse:Nonce>
        <wsu:Created>{}</wsu:Created>
    </wsse:UsernameToken>"#,
        digest_b64, nonce_b64, created
    );
    let body = wrap_soap(&ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("PasswordDigest verification failed"));
}

#[tokio::test]
async fn test_password_digest_missing_nonce_rejects() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();
    let ut = r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">dGVzdA==</wsse:Password>
        <wsu:Created>2026-01-01T00:00:00Z</wsu:Created>
    </wsse:UsernameToken>"#;
    let body = wrap_soap(ut);
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("requires Nonce"));
}

// ── Nonce replay protection tests ───────────────────────────────────────────

#[tokio::test]
async fn test_nonce_replay_detected() {
    let plugin = SoapWsSecurity::new(&username_token_digest_config()).unwrap();

    let nonce_bytes = b"replay-nonce-001";
    let nonce_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);
    let created = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let mut data = Vec::new();
    data.extend_from_slice(nonce_bytes);
    data.extend_from_slice(created.as_bytes());
    data.extend_from_slice(b"secret123");

    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
    let digest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest.as_ref());

    let ut = format!(
        r#"<wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{}</wsse:Password>
        <wsse:Nonce>{}</wsse:Nonce>
        <wsu:Created>{}</wsu:Created>
    </wsse:UsernameToken>"#,
        digest_b64, nonce_b64, created
    );
    let body = wrap_soap(&ut);

    // First request succeeds
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    // Second request with same nonce is replay
    let mut ctx2 = make_ctx_with_soap_body(&body);
    let mut headers2 = soap_headers();
    let result2 = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(is_reject(&result2));
    assert!(reject_body(&result2).contains("nonce replay"));
}

// ── SAML config tests ───────────────────────────────────────────────────────
//
// `saml.enabled: true` is rejected at construction time because the
// plugin does not currently cryptographically verify SAML assertion
// signatures. Issuer / NotBefore / NotOnOrAfter / Audience are plain
// XML text that any caller can craft, so accepting them without
// signature verification is trivially spoofable. The runtime
// `validate_saml_assertion` code path is retained for the future when
// XMLDSIG signature verification lands, but it cannot be reached from
// configuration today.

#[test]
fn test_saml_enabled_rejected_until_signature_verification_lands() {
    let config = json!({
        "timestamp": { "require": false },
        "saml": {
            "enabled": true,
            "trusted_issuers": ["https://idp.example.com"]
        }
    });
    let err = SoapWsSecurity::new(&config)
        .err()
        .expect("saml.enabled must be rejected until signature verification is implemented");
    assert!(
        err.contains("saml.enabled is not currently supported"),
        "got: {err}"
    );
}

#[test]
fn test_saml_disabled_construction_still_succeeds() {
    // Disabled SAML config alongside another feature still constructs cleanly.
    let config = json!({
        "timestamp": { "require": true },
        "saml": { "enabled": false }
    });
    assert!(SoapWsSecurity::new(&config).is_ok());
}

// ── Body buffering flag tests ───────────────────────────────────────────────

#[test]
fn test_requires_body_buffering() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    assert!(plugin.requires_request_body_before_before_proxy());
}

#[test]
fn test_should_buffer_soap_content_type() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ws".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "text/xml".to_string());
    assert!(plugin.should_buffer_request_body(&ctx));

    ctx.headers.insert(
        "content-type".to_string(),
        "application/soap+xml; charset=utf-8".to_string(),
    );
    assert!(plugin.should_buffer_request_body(&ctx));
}

#[test]
fn test_should_not_buffer_non_soap() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    assert!(!plugin.should_buffer_request_body(&ctx));
}

// ── Non-envelope request tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_non_envelope_soap_body_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = make_ctx_with_soap_body("<notasoap>hello</notasoap>");
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert!(reject_body(&result).contains("not a SOAP envelope"));
}

#[tokio::test]
async fn test_doctype_entity_payload_rejected() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let body = format!(
        r#"<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
{}"#,
        wrap_soap(&fresh_timestamp())
    );
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
    assert_eq!(reject_status(&result), 400);
    assert!(reject_body(&result).contains("forbidden XML declaration"));
}

// ── Plugin metadata tests ───────────────────────────────────────────────────

#[test]
fn test_plugin_name() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    assert_eq!(plugin.name(), "soap_ws_security");
}

#[test]
fn test_plugin_priority() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::SOAP_WS_SECURITY
    );
}

// ── Namespace prefix agnostic tests ─────────────────────────────────────────

#[tokio::test]
async fn test_handles_different_namespace_prefixes() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();

    let now = chrono::Utc::now();
    let created = now.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let expires = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%S%.3fZ");

    // Use non-standard prefixes (s: instead of soap:, sec: instead of wsse:)
    let body = format!(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Header>
    <sec:Security xmlns:sec="{}" xmlns:u="{}">
      <u:Timestamp u:Id="TS-1">
        <u:Created>{}</u:Created>
        <u:Expires>{}</u:Expires>
      </u:Timestamp>
    </sec:Security>
  </s:Header>
  <s:Body><Test/></s:Body>
</s:Envelope>"#,
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        created,
        expires
    );
    let mut ctx = make_ctx_with_soap_body(&body);
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_empty_body_rejects() {
    let plugin = SoapWsSecurity::new(&timestamp_only_config()).unwrap();
    let mut ctx = make_ctx_with_soap_body("");
    let mut headers = soap_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(is_reject(&result));
}

// ── Nonce cache cap enforcement tests ───────────────────────────────────────

#[test]
fn test_nonce_cache_enforces_max_size_by_evicting_oldest() {
    let max_size: usize = 20;
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true },
        "nonce": { "max_cache_size": max_size, "ttl_seconds": 300 },
        "reject_missing_security_header": false
    }))
    .unwrap();

    // Insert nonces well past the cap
    for i in 0..(max_size + 50) {
        let nonce = format!("nonce-{}", i);
        let _ = plugin.check_nonce_replay(&nonce);
    }

    // The oldest nonces should have been evicted to enforce the cap.
    // Verify by checking that the first nonce is no longer tracked as a replay.
    assert!(
        plugin.check_nonce_replay("nonce-0").is_ok(),
        "nonce-0 should have been evicted by cap enforcement"
    );

    // But recent nonces should still be detected as replays
    let last_nonce = format!("nonce-{}", max_size + 49);
    assert!(
        plugin.check_nonce_replay(&last_nonce).is_err(),
        "most recent nonce should still be in cache"
    );
}

#[test]
fn test_nonce_replay_detected_via_direct_api() {
    let plugin = SoapWsSecurity::new(&json!({
        "timestamp": { "require": true },
        "nonce": { "max_cache_size": 100, "ttl_seconds": 300 },
        "reject_missing_security_header": false
    }))
    .unwrap();

    assert!(plugin.check_nonce_replay("unique-nonce").is_ok());
    assert!(plugin.check_nonce_replay("unique-nonce").is_err());
}

// ── X.509 signature verification — end-to-end roundtrip ─────────────────────
//
// PR #844 fixed `cert.public_key().raw` → `cert.public_key().subject_public_key.data`
// so the bytes passed to `ring::signature::UnparsedPublicKey::new(&RSA_PKCS1_*, ...)`
// are the bare RFC 8017 `RSAPublicKey` (modulus + exponent) instead of the full
// RFC 5280 `SubjectPublicKeyInfo`. Without these tests, the only existing X.509
// coverage was `test_x509_no_trusted_certs_is_error`, which only exercises the
// empty-list error path — every signed-envelope flow was silently broken since
// the feature was added because *no* test ever loaded an RSA cert and ran the
// plugin against a real signature.
//
// These tests lock in the fix by minting a self-signed RSA cert with rcgen,
// signing a deterministic `<SignedInfo>` block with ring's `RSA_PKCS1_SHA256`,
// and feeding the resulting SOAP envelope through the public `before_proxy`
// path. If a future refactor re-introduces the SPKI/RSAPublicKey mismatch the
// happy-path test will start rejecting valid signatures; the
// tampered-signature test makes sure we are not accidentally "verifying" by
// returning Ok for anything.

mod x509_roundtrip {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256,
        PKCS_RSA_SHA256,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

    /// rcgen-minted self-signed RSA cert + the same PKCS#8 key material that
    /// signed it, so we can both (a) hand the cert PEM to `SoapWsSecurity` for
    /// trust-store loading and (b) hand the same private key to ring for
    /// signing the `<SignedInfo>` block.
    struct TestRsaCert {
        cert_pem: String,
        cert_der_b64: String,
        signing_key: RsaKeyPair,
    }

    fn mint_rsa_cert() -> TestRsaCert {
        let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256)
            .expect("rcgen RSA keypair (requires aws_lc_rs feature on rcgen)");
        let mut params = CertificateParams::new(vec!["soap-ws-security-test".to_string()])
            .expect("rcgen CertificateParams");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "soap-ws-security-test");
        params.distinguished_name = dn;
        let cert = params
            .self_signed(&key_pair)
            .expect("rcgen self-sign RSA cert");
        let cert_pem = cert.pem();
        let cert_der_b64 = B64.encode(cert.der().as_ref());

        // rcgen `KeyPair::serialize_der` exposes the key as a PKCS#8 DER, which
        // is the input format ring's `RsaKeyPair::from_pkcs8` expects.
        let pkcs8_der = key_pair.serialize_der();
        let signing_key =
            RsaKeyPair::from_pkcs8(&pkcs8_der).expect("ring RsaKeyPair from rcgen PKCS#8 DER");

        TestRsaCert {
            cert_pem,
            cert_der_b64,
            signing_key,
        }
    }

    /// rcgen-minted self-signed ECDSA P-256 cert PEM, used to drive the
    /// non-RSA SPKI rejection path at constructor time.
    fn mint_ecdsa_cert_pem() -> String {
        let key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("rcgen ECDSA P-256 keypair");
        let mut params = CertificateParams::new(vec!["soap-ws-security-ecdsa-test".to_string()])
            .expect("rcgen CertificateParams");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "soap-ws-security-ecdsa-test");
        params.distinguished_name = dn;
        let cert = params
            .self_signed(&key_pair)
            .expect("rcgen self-sign ECDSA cert");
        cert.pem()
    }

    fn write_pem_to_tempfile(pem: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::with_suffix(".pem").expect("tempfile");
        file.write_all(pem.as_bytes()).expect("write pem");
        file.flush().expect("flush pem");
        file
    }

    /// Construct a SOAP envelope whose `<wsse:Security>` block contains a
    /// `<Timestamp wsu:Id="TS-1">` and a `<Signature>` covering that Timestamp.
    /// The `<SignedInfo>` byte sequence in the returned envelope is exactly
    /// what `validate_x509_signature` extracts via `find_element_block`, so
    /// the signature computed here will match what the verifier checks.
    fn build_signed_soap_envelope(cert: &TestRsaCert) -> String {
        let now = chrono::Utc::now();
        let created = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let expires = (now + chrono::Duration::minutes(5))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let timestamp_xml = format!(
            r#"<wsu:Timestamp wsu:Id="TS-1"><wsu:Created>{}</wsu:Created><wsu:Expires>{}</wsu:Expires></wsu:Timestamp>"#,
            created, expires
        );

        // verify_reference_digests hashes the raw bytes of the referenced
        // element as extracted from the envelope (no XML C14N in this impl),
        // so we hash the exact `timestamp_xml` string we'll embed below.
        let ts_digest = ring::digest::digest(&ring::digest::SHA256, timestamp_xml.as_bytes());
        let ts_digest_b64 = B64.encode(ts_digest.as_ref());

        // Build SignedInfo as the EXACT bytes that will appear in the envelope.
        // This is what `find_element_block(security_block, "SignedInfo")`
        // returns and what we pass into `ring::RsaKeyPair::sign`.
        // Raw-string delimiter must be `##` because the URL fragments
        // `xml-exc-c14n#`, `xmldsig-more#`, and `xmlenc#` contain `#`
        // and a single-`#` raw literal would terminate at the first
        // `"#` (e.g. inside `xml-exc-c14n#"/>`), which is what tripped
        // the parser before the fix.
        let signed_info = format!(
            r##"<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#TS-1"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>{}</DigestValue></Reference></SignedInfo>"##,
            ts_digest_b64
        );

        // Sign the SignedInfo bytes with RSA-PKCS1-v1_5 over SHA-256.
        let rng = SystemRandom::new();
        let mut signature = vec![0u8; cert.signing_key.public().modulus_len()];
        cert.signing_key
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                signed_info.as_bytes(),
                &mut signature,
            )
            .expect("ring RSA sign");
        let signature_b64 = B64.encode(&signature);

        format!(
            r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      {timestamp}
      <wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">{cert_b64}</wsse:BinarySecurityToken>
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        {signed_info}
        <SignatureValue>{sig_b64}</SignatureValue>
      </Signature>
    </wsse:Security>
  </soap:Header>
  <soap:Body><GetPrice xmlns="http://example.com/prices"><Item>Widget</Item></GetPrice></soap:Body>
</soap:Envelope>"#,
            timestamp = timestamp_xml,
            cert_b64 = cert.cert_der_b64,
            signed_info = signed_info,
            sig_b64 = signature_b64,
        )
    }

    fn x509_plugin_config(cert_path: &std::path::Path) -> serde_json::Value {
        json!({
            "timestamp": { "require": true, "max_age_seconds": 300 },
            "x509_signature": {
                "enabled": true,
                "trusted_certs": [cert_path.to_str().unwrap()],
                "allowed_algorithms": ["rsa-sha256"],
                "require_signed_timestamp": true,
            },
            "reject_missing_security_header": true
        })
    }

    #[tokio::test]
    async fn valid_rsa_signature_is_accepted() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path()))
            .expect("plugin should construct with valid RSA cert");

        let body = build_signed_soap_envelope(&cert);
        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(
            matches!(result, PluginResult::Continue),
            "expected Continue with valid RSA signature, got {:?}",
            result,
        );
    }

    #[tokio::test]
    async fn tampered_signature_is_rejected() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();

        // Flip the first character of the base64-encoded SignatureValue so
        // ring's verify fails. Replacing with another valid base64 digit keeps
        // the payload decodable — we want the *cryptographic* check to reject,
        // not the base64 decoder.
        let original = build_signed_soap_envelope(&cert);
        let open = original
            .find("<SignatureValue>")
            .expect("envelope must have <SignatureValue>")
            + "<SignatureValue>".len();
        let first_char = original.as_bytes()[open];
        let replacement = if first_char == b'A' { 'B' } else { 'A' };
        let mut body = String::with_capacity(original.len());
        body.push_str(&original[..open]);
        body.push(replacement);
        body.push_str(&original[open + 1..]);

        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        match result {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 401);
                assert!(
                    body.contains("signature verification failed"),
                    "expected signature failure message, got: {body}"
                );
            }
            other => panic!("expected Reject on tampered signature, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn tampered_digest_value_breaks_reference_check() {
        let cert = mint_rsa_cert();
        let cert_file = write_pem_to_tempfile(&cert.cert_pem);
        let plugin = SoapWsSecurity::new(&x509_plugin_config(cert_file.path())).unwrap();

        // Flip the first character of the Reference DigestValue in SignedInfo.
        // The recomputed digest of the (untouched) Timestamp will no longer
        // match the (tampered) base64 in SignedInfo, so `verify_reference_digests`
        // must reject. We can't tamper with the Timestamp text itself here
        // because `validate_timestamp` runs first in the pipeline and would
        // fail on the parse before signature checks even run.
        let original = build_signed_soap_envelope(&cert);
        let dv_open = original
            .find("<DigestValue>")
            .expect("envelope must have <DigestValue>")
            + "<DigestValue>".len();
        let first_char = original.as_bytes()[dv_open];
        let replacement = if first_char == b'A' { 'B' } else { 'A' };
        let mut body = String::with_capacity(original.len());
        body.push_str(&original[..dv_open]);
        body.push(replacement);
        body.push_str(&original[dv_open + 1..]);

        let mut ctx = make_ctx_with_soap_body(&body);
        let mut headers = soap_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        match result {
            PluginResult::Reject { body, .. } => assert!(
                body.contains("digest mismatch"),
                "expected digest mismatch, got: {body}"
            ),
            other => panic!("expected Reject on tampered DigestValue, got {:?}", other),
        }
    }

    #[test]
    fn non_rsa_cert_is_rejected_at_load_time() {
        // Defense-in-depth: an ECDSA cert should fail with a precise error
        // mentioning RSA, not silently load and only fail later at request
        // time with a generic "signature verification failed" message.
        let ecdsa_pem = mint_ecdsa_cert_pem();
        let cert_file = write_pem_to_tempfile(&ecdsa_pem);

        let result = SoapWsSecurity::new(&x509_plugin_config(cert_file.path()));
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("ECDSA cert must be rejected at constructor time"),
        };
        assert!(
            err.contains("not an RSA public key"),
            "error should name the RSA constraint, got: {err}"
        );
        // The error must include the canonical RSA OID so operators can
        // cross-reference with their cert tooling.
        assert!(
            err.contains("1.2.840.113549.1.1.1"),
            "error should include canonical RSA OID, got: {err}"
        );
    }

    #[test]
    fn unreadable_cert_path_is_rejected_at_load_time() {
        // A non-existent path must fail at constructor time with the
        // existing "failed to read" surface, not panic.
        let result = SoapWsSecurity::new(&x509_plugin_config(std::path::Path::new(
            "/this/path/does/not/exist/cert.pem",
        )));
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("missing cert file must fail load"),
        };
        assert!(err.contains("failed to read trusted cert"), "got: {err}");
    }
}
