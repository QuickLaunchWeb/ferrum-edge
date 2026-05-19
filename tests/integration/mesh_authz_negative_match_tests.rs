//! Integration coverage for `AuthorizationPolicy` negative-match fields
//! (`notMethods`, `notPaths`, `notHosts`, `notPorts`).
//!
//! Exercises the canonical Istio scenario end-to-end through the
//! `mesh_authz` plugin: an ALLOW policy that combines a positive `methods`
//! match with a negative `notPaths` match — the resulting rule must
//! authorise GET /api but deny BOTH GET /admin (negative match fires) AND
//! POST /admin (positive method match fails).
//!
//! This is the same scenario covered by inline policy.rs and istio.rs
//! tests; this integration test additionally drives it through the plugin
//! surface (`MeshAuthz::authorize`) so the wiring between the JSON
//! plugin-config schema, the policy evaluator, and the plugin's reject
//! semantics is validated together.
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch, WorkloadSelector,
};
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;

fn policy_allow_get_except_admin() -> MeshPolicy {
    MeshPolicy {
        name: "allow-get-except-admin".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".to_string()],
                not_paths: vec!["/admin/*".to_string()],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

fn request_context(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    ctx.peer_spiffe_id = Some(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/client").expect("valid spiffe id"),
    );
    ctx
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_authorizes_get_to_non_admin_path() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("GET", "/api/items");

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "GET /api should be allowed (positive method match + negative path mismatch), got {result:?}"
    );
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_denies_get_to_admin_path() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("GET", "/admin/users");

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "GET /admin should be rejected (negative path match → rule fails → \
             implicit deny), got {other:?}"
        ),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_denies_post_to_admin_path() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("POST", "/admin/users");

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "POST /admin should be rejected (positive method does not match GET \
             → rule fails → implicit deny), got {other:?}"
        ),
    }
}

#[tokio::test]
async fn allow_with_methods_and_not_paths_denies_post_to_non_admin_path() {
    // Sanity: POST /api also fails because the positive method=GET predicate
    // does not match POST. This is independent of the negative-match logic
    // but locks in conjunctive-AND semantics across positive + negative.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_allow_get_except_admin()]
    }))
    .expect("plugin config");
    let mut ctx = request_context("POST", "/api/items");

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "POST /api should fall through to implicit-deny, got {result:?}"
    );
}

#[tokio::test]
async fn deny_host_pattern_is_normalized_for_direct_mesh_policies_config() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [{
            "name": "deny-admin-host",
            "namespace": "default",
            "scope": { "kind": "mesh_wide" },
            "rules": [{
                "action": "deny",
                "from": [],
                "to": [{ "hosts": ["Admin.Example.COM."] }],
                "when": [],
                "request_principals": [],
                "never_matches": false
            }]
        }]
    }))
    .expect("plugin config");

    let mut ctx = request_context("GET", "/");
    ctx.host = Some("admin.example.com".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Reject { .. }),
        "mixed-case / trailing-dot deny host pattern should be normalized and reject, got {result:?}"
    );
}
