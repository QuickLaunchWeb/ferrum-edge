use ferrum_edge::config::mesh::{
    MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch,
};
use ferrum_edge::identity::SpiffeId;
use ferrum_edge::plugins::mesh_authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::sync::Arc;

use super::plugin_utils::create_test_proxy;

fn mesh_wide_policy(action: PolicyAction) -> MeshPolicy {
    MeshPolicy {
        name: "default".to_string(),
        namespace: "ferrum".to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
                namespace_pattern: None,
                trust_domain: None,
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".to_string()],
                paths: vec!["/api/*".to_string()],
                ..Default::default()
            }],
            when: Vec::new(),
            action,
        }],
    }
}

fn context_with_peer(path: &str, peer: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), path.to_string());
    ctx.peer_spiffe_id = Some(SpiffeId::new(peer).unwrap());
    ctx
}

#[tokio::test]
async fn mesh_authz_allows_matching_allow_policy() {
    let plugin =
        MeshAuthz::new(&json!({"policies": [mesh_wide_policy(PolicyAction::Allow)]})).unwrap();
    let mut ctx = context_with_peer("/api/orders", "spiffe://cluster.local/ns/default/sa/client");

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata.get("source_principal").map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/client")
    );
}

#[tokio::test]
async fn mesh_authz_rejects_when_allow_policy_does_not_match() {
    let plugin =
        MeshAuthz::new(&json!({"policies": [mesh_wide_policy(PolicyAction::Allow)]})).unwrap();
    let mut ctx = context_with_peer("/api/orders", "spiffe://cluster.local/ns/default/sa/other");

    let result = plugin.authorize(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_deny_takes_precedence() {
    let mut allow = mesh_wide_policy(PolicyAction::Allow);
    allow.rules[0].from.clear();
    let deny = mesh_wide_policy(PolicyAction::Deny);
    let plugin = MeshAuthz::new(&json!({"policies": [allow, deny]})).unwrap();
    let mut ctx = context_with_peer("/api/orders", "spiffe://cluster.local/ns/default/sa/client");

    let result = plugin.authorize(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_namespace_scope_requires_known_destination_namespace() {
    let mut deny = mesh_wide_policy(PolicyAction::Deny);
    deny.scope = PolicyScope::Namespace {
        namespace: "payments".to_string(),
    };
    let plugin = MeshAuthz::new(&json!({"policies": [deny]})).unwrap();

    let mut unknown_destination =
        context_with_peer("/api/orders", "spiffe://cluster.local/ns/default/sa/client");
    assert!(matches!(
        plugin.authorize(&mut unknown_destination).await,
        PluginResult::Continue
    ));

    let mut payments_destination =
        context_with_peer("/api/orders", "spiffe://cluster.local/ns/default/sa/client");
    let mut proxy = create_test_proxy();
    proxy.namespace = "payments".to_string();
    payments_destination.matched_proxy = Some(Arc::new(proxy));

    match plugin.authorize(&mut payments_destination).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected namespace-scoped rejection, got {other:?}"),
    }
}
