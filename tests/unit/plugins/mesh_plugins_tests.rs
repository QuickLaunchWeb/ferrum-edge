use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::config::mesh::{
    MeshConfig, MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch,
    WorkloadSelector,
};
use ferrum_edge::config::types::Proxy;
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::plugins::access_log::AccessLog;
use ferrum_edge::plugins::mesh_authz::MeshAuthz;
use ferrum_edge::plugins::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, PluginResult, RequestContext, TransactionSummary, available_plugins,
    create_plugin, is_security_plugin, priority,
};
use serde_json::json;

fn allow_client_policy(action: PolicyAction) -> MeshPolicy {
    MeshPolicy {
        name: "client-policy".to_string(),
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
            to: Vec::new(),
            when: Vec::new(),
            never_matches: false,
            action,
        }],
    }
}

fn allow_host_policy(host: &str) -> MeshPolicy {
    MeshPolicy {
        name: "host-policy".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: Vec::new(),
            to: vec![RequestMatch {
                hosts: vec![host.to_string()],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

fn request_context(source: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.peer_spiffe_id = source.map(|id| SpiffeId::new(id).expect("valid spiffe id"));
    ctx
}

#[test]
fn mesh_config_normalize_lowercases_policy_hosts() {
    let mut mesh = MeshConfig {
        mesh_policies: vec![allow_host_policy("Api.Example.Com")],
        ..MeshConfig::default()
    };

    mesh.normalize();

    assert_eq!(
        mesh.mesh_policies[0].rules[0].to[0].hosts,
        vec!["api.example.com"]
    );
}

#[test]
fn mesh_plugins_are_registered() {
    let available = available_plugins();
    assert!(available.contains(&"mesh_authz"));
    assert!(available.contains(&"workload_metrics"));
    assert!(available.contains(&"access_log"));
    assert!(is_security_plugin("mesh_authz"));
    assert!(create_plugin("mesh_authz", &json!({})).unwrap().is_some());
    assert!(
        create_plugin("workload_metrics", &json!({}))
            .unwrap()
            .is_some()
    );
    assert!(create_plugin("access_log", &json!({})).unwrap().is_some());
}

#[test]
fn mesh_authz_rejects_namespace_scoped_direct_policy_without_namespace() {
    let err = match MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "ns-deny",
            PolicyScope::Namespace { namespace: "default".to_string() },
            PolicyAction::Deny,
        )]
    })) {
        Ok(_) => panic!("namespace-scoped direct policy without proxy namespace must fail closed"),
        Err(err) => err,
    };

    assert!(err.contains("namespace scope"));
    assert!(err.contains("proxy namespace"));
}

#[test]
fn mesh_authz_rejects_label_selector_direct_policy_without_labels() {
    let selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        namespace: None,
    };
    let err = match MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "app-deny",
            PolicyScope::WorkloadSelector { selector },
            PolicyAction::Deny,
        )],
        "namespace": "default",
    })) {
        Ok(_) => panic!("label-scoped direct policy without proxy labels must fail closed"),
        Err(err) => err,
    };

    assert!(err.contains("workload selector labels"));
    assert!(err.contains("proxy labels"));
}

#[tokio::test]
async fn mesh_authz_allows_matching_spiffe_identity() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_denies_non_matching_identity_when_allow_policy_exists() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/other"));

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("Mesh authorization denied"));
        }
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn mesh_authz_reads_hbone_baggage_source_identity() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_reads_materialized_hbone_baggage_source_identity() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);
    ctx.materialize_headers();

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_ignores_hbone_baggage_without_authenticated_peer() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage")
            .map(String::as_str),
        Some("unauthenticated_hbone")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("unauthenticated_baggage")
    );
}

#[tokio::test]
async fn mesh_authz_reads_split_hbone_baggage_headers() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.append(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    headers.append(
        "baggage",
        "destination.principal=spiffe://cluster.local/ns/default/sa/server"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);
    ctx.materialize_headers();

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_denies_percent_encoded_hbone_baggage_mismatch() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.append(
        "baggage",
        "destination.principal=spiffe://cluster.local/ns/default/sa/server"
            .parse()
            .expect("header value"),
    );
    headers.append(
        "baggage",
        "source.principal=spiffe%3A%2F%2Fcluster.local%2Fns%2Fdefault%2Fsa%2Fother"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);
    ctx.materialize_headers();

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("Mesh authorization denied"));
        }
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn mesh_authz_uses_materialized_host_backfilled_from_authority() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_host_policy("api.example.com")]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = http::HeaderMap::new();
    headers.insert("host", "api.example.com".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_strips_host_port_before_matching_policy() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_host_policy("api.example.com")]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = http::HeaderMap::new();
    headers.insert("host", "api.example.com:443".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_rejects_non_matching_host_policy() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_host_policy("api.example.com")]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = http::HeaderMap::new();
    headers.insert("host", "other.example.com".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn mesh_authz_matches_http_frontend_port_policy() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [{
            "name": "port-policy",
            "namespace": "default",
            "scope": {"kind": "mesh_wide"},
            "rules": [{
                "to": [{"ports": [8443]}],
                "action": "allow"
            }]
        }]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.frontend_listen_port = Some(8443);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn workload_metrics_adds_identity_metadata_without_header_changes() {
    let plugin = WorkloadMetrics::new(&json!({
        "node_id": "node-a",
        "topology": "sidecar",
        "namespace": "default",
        "labels": {
            "app": "client",
            "service.istio.io/canonical-name": "client-svc"
        }
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "svc-proxy",
        "name": "payments",
        "namespace": "default",
        "hosts": ["payments.default.svc.cluster.local"],
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .expect("proxy fixture");
    ctx.matched_proxy = Some(Arc::new(proxy));
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(headers.is_empty());
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.source.namespace")
            .map(String::as_str),
        Some("default")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.destination.service")
            .map(String::as_str),
        Some("payments")
    );
    assert_eq!(
        ctx.metadata.get("mesh.topology").map(String::as_str),
        Some("sidecar")
    );
    assert_eq!(
        ctx.metadata.get("mesh.source.workload").map(String::as_str),
        Some("client-svc")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.request_protocol")
            .map(String::as_str),
        Some("http")
    );
}

#[tokio::test]
async fn workload_metrics_reads_hbone_baggage_source_identity() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = HashMap::from([(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/default/sa/client".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("client")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
}

#[tokio::test]
async fn workload_metrics_marks_mtls_when_http_peer_cert_has_no_spiffe_id() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(None);
    ctx.tls_client_cert_der = Some(Arc::new(vec![0x30, 0x82, 0x01, 0x00]));
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
    assert!(!ctx.metadata.contains_key("mesh.source.principal"));
}

#[tokio::test]
async fn workload_metrics_reads_split_hbone_baggage_headers() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut raw_headers = http::HeaderMap::new();
    raw_headers.append(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    raw_headers.append(
        "baggage",
        "destination.principal=spiffe://cluster.local/ns/default/sa/server"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(raw_headers);
    ctx.materialize_headers();
    let mut headers = std::mem::take(&mut ctx.headers);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("client")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
}

#[tokio::test]
async fn workload_metrics_reads_forwarded_materialized_hbone_baggage() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut raw_headers = http::HeaderMap::new();
    raw_headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(raw_headers);
    ctx.materialize_headers();
    let mut headers = std::mem::take(&mut ctx.headers);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("client")
    );
}

#[tokio::test]
async fn workload_metrics_ignores_stale_materialized_hbone_baggage() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    ctx.headers.insert(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/default/sa/client".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("ztunnel")
    );
}

#[tokio::test]
async fn workload_metrics_does_not_trust_hbone_baggage_without_authenticated_peer() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = HashMap::from([(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/default/sa/client".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("none")
    );
    assert!(!ctx.metadata.contains_key("mesh.source.principal"));
    assert!(!ctx.metadata.contains_key("mesh.source.service_account"));
}

#[tokio::test]
async fn workload_metrics_uses_workload_hint_when_peer_identity_absent() {
    let plugin = WorkloadMetrics::new(&json!({
        "topology": "ambient",
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/api",
        "labels": {
            "app.kubernetes.io/name": "api"
        }
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = HashMap::from([(
        "content-type".to_string(),
        "application/grpc+proto".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/api")
    );
    assert_eq!(
        ctx.metadata.get("mesh.source.workload").map(String::as_str),
        Some("api")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.request_protocol")
            .map(String::as_str),
        Some("grpc")
    );
}

#[tokio::test]
async fn access_log_is_all_protocol_logging_plugin() {
    let plugin = AccessLog::new(&json!({})).expect("plugin config");

    assert_eq!(plugin.name(), "access_log");
    assert_eq!(plugin.priority(), priority::ACCESS_LOG);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
    plugin.log(&TransactionSummary::default()).await;
}

// ── PolicyScope enforcement tests ────────────────────────────────────────────
//
// These tests pin the security-correctness contract that `mesh_authz`
// honors `PolicyScope`. Before this fix, every policy in `slice.mesh_policies`
// applied to every workload regardless of scope, which let a namespace-scoped
// DENY in namespace `A` reject traffic in namespace `B`, and a namespace- /
// workload-scoped ALLOW raise the implicit-deny floor for unrelated proxies.

fn policy_with_scope(name: &str, scope: PolicyScope, action: PolicyAction) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "default".to_string(),
        scope,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: Vec::new(),
            never_matches: false,
            action,
        }],
    }
}

#[tokio::test]
async fn mesh_authz_mesh_wide_allow_applies_to_any_workload() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "mesh-wide-allow",
            PolicyScope::MeshWide,
            PolicyAction::Allow,
        )],
        "namespace": "billing",
        "labels": {"app": "api"},
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_namespace_scoped_allow_does_not_affect_other_namespaces() {
    // Cross-namespace ALLOW must NOT raise `saw_allow` for an unrelated proxy.
    // Pre-fix: this returned Reject{implicit-deny}.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "ns-a-allow",
            PolicyScope::Namespace { namespace: "team-a".to_string() },
            PolicyAction::Allow,
        )],
        "namespace": "team-b",
        "labels": {},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-b/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "namespace-scoped ALLOW in team-a must not implicit-deny team-b traffic, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_namespace_scoped_allow_applies_in_matching_namespace() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "ns-a-allow",
            PolicyScope::Namespace { namespace: "team-a".to_string() },
            PolicyAction::Allow,
        )],
        "namespace": "team-a",
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-a/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    // Allow rule has no `from` — empty principals match anything → matched_allow.
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_namespace_scoped_deny_only_denies_in_matching_namespace() {
    // DENY in team-a must not deny team-b.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "ns-a-deny",
            PolicyScope::Namespace { namespace: "team-a".to_string() },
            PolicyAction::Deny,
        )],
        "namespace": "team-b",
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-b/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "namespace-scoped DENY in team-a must not deny team-b traffic, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_namespace_scoped_deny_denies_in_matching_namespace() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "ns-a-deny",
            PolicyScope::Namespace { namespace: "team-a".to_string() },
            PolicyAction::Deny,
        )],
        "namespace": "team-a",
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-a/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("ns-a-deny")
    );
}

#[tokio::test]
async fn mesh_authz_workload_selector_subset_match_applies() {
    let selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        namespace: None,
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "wl-allow",
            PolicyScope::WorkloadSelector { selector },
            PolicyAction::Allow,
        )],
        "labels": {"app": "api", "tier": "frontend"},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/api"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_workload_selector_missing_label_does_not_affect_unrelated_workloads() {
    // Selector requires `app=api`; this workload has `app=worker` → policy must
    // NOT apply, so the unrelated proxy continues as if the policy were absent.
    let selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        namespace: None,
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "wl-allow",
            PolicyScope::WorkloadSelector { selector },
            PolicyAction::Allow,
        )],
        "labels": {"app": "worker"},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/worker"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "WorkloadSelector ALLOW for app=api must not implicit-deny app=worker, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_workload_selector_empty_labels_matches_any_workload() {
    // Empty labels + no namespace → applies to any workload (legacy behavior
    // preserved). Existing tests rely on this; this test pins the contract.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "wl-any-allow",
            PolicyScope::WorkloadSelector { selector: WorkloadSelector::default() },
            PolicyAction::Allow,
        )],
        "namespace": "anything",
        "labels": {"role": "backend"},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/anything/sa/anyone"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_workload_selector_namespace_and_labels_combined() {
    // Selector requires both namespace=team-a AND app=api. Proxy is namespace
    // team-a but app=worker → policy must NOT apply.
    let selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        namespace: Some("team-a".to_string()),
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "wl-team-a-api-allow",
            PolicyScope::WorkloadSelector { selector },
            PolicyAction::Allow,
        )],
        "namespace": "team-a",
        "labels": {"app": "worker"},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-a/sa/worker"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_workload_selector_namespace_mismatch_does_not_apply() {
    // Selector requires namespace=team-a (with empty labels = any workload in
    // team-a). Proxy is in team-b → policy must NOT apply.
    let selector = WorkloadSelector {
        labels: HashMap::new(),
        namespace: Some("team-a".to_string()),
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "wl-team-a-allow",
            PolicyScope::WorkloadSelector { selector },
            PolicyAction::Allow,
        )],
        "namespace": "team-b",
        "labels": {},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-b/sa/anyone"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_cross_namespace_deny_and_in_namespace_allow_compose_correctly() {
    // The original bug surfaces here: a Namespace{team-a} DENY plus a
    // MeshWide ALLOW. Pre-fix: the team-a DENY would return Reject regardless
    // of which namespace the proxy lived in. Post-fix: in team-b only the
    // MeshWide ALLOW applies → Continue.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [
            policy_with_scope(
                "team-a-deny",
                PolicyScope::Namespace { namespace: "team-a".to_string() },
                PolicyAction::Deny,
            ),
            policy_with_scope(
                "mesh-wide-allow",
                PolicyScope::MeshWide,
                PolicyAction::Allow,
            ),
        ],
        "namespace": "team-b",
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-b/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_slice_embedded_identity_drives_scope_filter() {
    // mesh-mode injection passes a full `mesh_slice` whose `namespace` and
    // `labels` describe the proxy's own workload. The plugin must use those
    // when filtering policies — explicit namespace/labels override is not
    // required when the slice already carries the identity.
    use ferrum_edge::xds::slice::MeshSlice;

    let slice = MeshSlice {
        namespace: "team-b".to_string(),
        labels: [("app".to_string(), "worker".to_string())]
            .into_iter()
            .collect(),
        mesh_policies: vec![policy_with_scope(
            "team-a-deny",
            PolicyScope::Namespace {
                namespace: "team-a".to_string(),
            },
            PolicyAction::Deny,
        )],
        ..MeshSlice::default()
    };
    let plugin = MeshAuthz::new(&json!({"mesh_slice": slice})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-b/sa/worker"));

    let result = plugin.authorize(&mut ctx).await;

    // Pre-fix: team-a-deny would deny team-b traffic. Post-fix: filtered out.
    assert!(matches!(result, PluginResult::Continue));
}
