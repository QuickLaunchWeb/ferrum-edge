use ferrum_edge::config::mesh::{
    MeshPolicy, MeshRule, MtlsMode, PeerAuthentication, PolicyAction, PolicyScope, PrincipalMatch,
    RequestMatch, WorkloadSelector,
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

fn context_without_peer_in_namespace(path: &str, namespace: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), path.to_string());
    let mut proxy = create_test_proxy();
    proxy.namespace = namespace.to_string();
    ctx.matched_proxy = Some(Arc::new(proxy));
    ctx
}

fn namespace_peer_auth(namespace: &str, mtls_mode: MtlsMode) -> PeerAuthentication {
    PeerAuthentication {
        name: "default".to_string(),
        namespace: namespace.to_string(),
        selector: None,
        mtls_mode,
        port_overrides: Default::default(),
    }
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

#[tokio::test]
async fn mesh_authz_strict_peer_authentication_requires_identity() {
    let plugin = MeshAuthz::new(&json!({
        "peer_authentications": [namespace_peer_auth("payments", MtlsMode::Strict)]
    }))
    .unwrap();
    let mut ctx = context_without_peer_in_namespace("/api/orders", "payments");

    match plugin.authorize(&mut ctx).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 401);
            assert!(body.contains("peer_authentication_strict_mtls_required"));
        }
        other => panic!("expected strict mTLS rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_permissive_peer_authentication_allows_missing_identity() {
    let plugin = MeshAuthz::new(&json!({
        "peer_authentications": [namespace_peer_auth("payments", MtlsMode::Permissive)]
    }))
    .unwrap();
    let mut ctx = context_without_peer_in_namespace("/api/orders", "payments");

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn mesh_authz_peer_authentication_port_override_takes_precedence() {
    let mut peer_auth = namespace_peer_auth("payments", MtlsMode::Strict);
    peer_auth.port_overrides.insert(8080, MtlsMode::Disable);
    let plugin = MeshAuthz::new(&json!({ "peer_authentications": [peer_auth] })).unwrap();
    let mut ctx = context_without_peer_in_namespace("/api/orders", "payments");
    ctx.metadata
        .insert("destination_port".to_string(), "8080".to_string());

    assert!(matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn mesh_authz_peer_authentication_selector_overrides_namespace_default() {
    let namespace_default = namespace_peer_auth("payments", MtlsMode::Permissive);
    let selector = PeerAuthentication {
        name: "selected-strict".to_string(),
        namespace: "payments".to_string(),
        selector: Some(WorkloadSelector {
            labels: [("app".to_string(), "checkout".to_string())]
                .into_iter()
                .collect(),
            namespace: None,
        }),
        mtls_mode: MtlsMode::Strict,
        port_overrides: Default::default(),
    };
    let plugin = MeshAuthz::new(&json!({
        "peer_authentications": [namespace_default, selector]
    }))
    .unwrap();
    let mut ctx = context_without_peer_in_namespace("/api/orders", "payments");
    ctx.metadata
        .insert("destination.label.app".to_string(), "checkout".to_string());

    match plugin.authorize(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 401),
        other => panic!("expected selector strict mTLS rejection, got {other:?}"),
    }
}
