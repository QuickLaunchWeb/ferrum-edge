use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, jwks_auth::JwksAuth};
use serde_json::json;

use super::jwks_auth_support::{
    build_rsa_jwks_from_pem, create_rs256_token, default_client, make_ctx,
};
use super::plugin_utils::assert_continue;

#[tokio::test]
async fn inline_jwks_verifies_token_without_network() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let inline_jwks = build_rsa_jwks_from_pem(public_key_pem).to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks
            }]
        }),
        default_client(),
    )
    .unwrap();

    assert!(plugin.active_jwks_uris().is_empty());
    plugin.warmup_jwks().await;

    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "inline-user"
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
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("inline-user"));
}

#[test]
fn inline_jwks_rejects_malformed_json() {
    let result = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": "not-json"
            }]
        }),
        default_client(),
    );

    assert!(result.is_err());
    assert!(
        result
            .as_ref()
            .err()
            .unwrap()
            .contains("inline JWKS parse failed")
    );
}
