use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, jwks_auth::JwksAuth};
use serde_json::json;

use super::jwks_auth_support::{
    build_rsa_jwks_from_pem, create_rs256_token, default_client, make_ctx,
};
use super::plugin_utils::{assert_continue, assert_reject};

fn inline_jwks() -> String {
    build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string()
}

#[tokio::test]
async fn multi_audience_accepts_any_configured_audience() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks(),
                "audiences": ["api-a", "api-b"]
            }]
        }),
        default_client(),
    )
    .unwrap();

    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "aud-user",
            "aud": "api-b"
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("aud-user"));
}

#[tokio::test]
async fn multi_audience_rejects_unconfigured_audience() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks(),
                "audiences": ["api-a", "api-b"]
            }]
        }),
        default_client(),
    )
    .unwrap();

    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "aud-user",
            "aud": "api-c"
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn legacy_audience_alias_still_validates() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks(),
                "audience": "legacy-api"
            }]
        }),
        default_client(),
    )
    .unwrap();

    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "legacy-user",
            "aud": "legacy-api"
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("legacy-user"));
}
