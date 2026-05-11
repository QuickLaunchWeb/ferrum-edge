use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::{BackendScheme, Proxy};
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch,
    WorkloadSelector,
};
use ferrum_edge::plugins::access_log::AccessLog;
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, PluginResult, RequestContext, StreamConnectionContext,
    TransactionSummary, available_plugins, create_plugin, is_security_plugin, priority,
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
            request_principals: Vec::new(),
            never_matches: false,
            action,
        }],
    }
}

fn allow_ztunnel_policy() -> MeshPolicy {
    MeshPolicy {
        name: "ztunnel-policy".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/ztunnel".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            never_matches: false,
            action: PolicyAction::Allow,
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
            request_principals: Vec::new(),
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
            .get("mesh_authz.ignored_baggage.unauthenticated")
            .map(String::as_str),
        Some("true")
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
async fn mesh_authz_normalizes_header_policy_keys_at_construction() {
    let mut policy = allow_client_policy(PolicyAction::Allow);
    policy.rules[0].to = vec![RequestMatch {
        headers: HashMap::from([("X-Tenant".to_string(), "prod".to_string())]),
        ..RequestMatch::default()
    }];
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let mut headers = http::HeaderMap::new();
    headers.insert("x-tenant", "prod".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_preserves_conflicting_header_policy_keys() {
    let mut policy = allow_client_policy(PolicyAction::Allow);
    policy.rules[0].to = vec![RequestMatch {
        headers: HashMap::from([
            ("X-Tenant".to_string(), "prod".to_string()),
            ("x-tenant".to_string(), "dev".to_string()),
        ]),
        ..RequestMatch::default()
    }];
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let mut headers = http::HeaderMap::new();
    headers.insert("x-tenant", "prod".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected reject, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_skips_header_materialization_without_header_rules() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let mut headers = http::HeaderMap::new();
    headers.insert("x-unused", "still-raw".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.headers.is_empty());
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
async fn mesh_authz_preserves_host_policy_authority_port() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_host_policy("api.example.com:8443")]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "host",
        "api.example.com:8443".parse().expect("header value"),
    );
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
    assert_eq!(
        ctx.metadata.get("mesh.ignored_baggage").map(String::as_str),
        Some("unauthenticated_hbone")
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
        ctx.metadata
            .get("mesh.source.trust_domain")
            .map(String::as_str),
        Some("cluster.local")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.source.namespace")
            .map(String::as_str),
        Some("default")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("api")
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
async fn mesh_authz_drops_baggage_with_mismatched_trust_domain() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_ztunnel_policy()]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://attacker.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage")
            .map(String::as_str),
        Some("trust_domain_mismatch")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage.trust_domain_mismatch")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn mesh_authz_accepts_baggage_in_aliased_trust_domain() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)],
        "trust_domain_aliases": ["cluster.local"]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://partner.local/ns/default/sa/ztunnel"));
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
    assert!(!ctx.metadata.contains_key("mesh_authz.ignored_baggage"));
}

#[tokio::test]
async fn mesh_authz_rejected_baggage_mismatch_records_deny_policy() {
    let plugin = MeshAuthz::new(&json!({
        // Policy only allows the baggage workload identity. After we drop
        // the cross-trust-domain baggage, the peer (ztunnel) identity
        // doesn't match, so this rejects.
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://attacker.local/ns/default/sa/client"
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
        Some("trust_domain_mismatch")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("trust_domain_mismatch")
    );
}

#[tokio::test]
async fn mesh_authz_rejects_invalid_trust_domain_alias() {
    let result = MeshAuthz::new(&json!({
        "trust_domain_aliases": ["NotLowercase.Test"]
    }));
    let err = match result {
        Ok(_) => panic!("invalid alias should fail construction"),
        Err(e) => e,
    };
    assert!(
        err.contains("NotLowercase.Test"),
        "error should mention bad alias, got: {err}"
    );
}

#[tokio::test]
async fn workload_metrics_drops_baggage_with_mismatched_trust_domain() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = HashMap::from([(
        "baggage".to_string(),
        "source.principal=spiffe://attacker.local/ns/default/sa/client".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/ztunnel")
    );
    assert_eq!(
        ctx.metadata.get("mesh.ignored_baggage").map(String::as_str),
        Some("trust_domain_mismatch")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
}

#[tokio::test]
async fn workload_metrics_sampling_zero_records_unsampled() {
    let plugin = WorkloadMetrics::new(&json!({
        "sampling_percentage": 0.0
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("trace_sampled").map(String::as_str),
        Some("false")
    );
}

#[tokio::test]
async fn workload_metrics_on_stream_connect_adds_source_identity_metadata() {
    let plugin = WorkloadMetrics::new(&json!({
        "node_id": "node-a",
        "topology": "sidecar",
        "labels": {
            "service.istio.io/canonical-name": "client-svc"
        }
    }))
    .expect("plugin config");
    let mut ctx = StreamConnectionContext {
        client_ip: "127.0.0.1".to_string(),
        proxy_id: "tcp-proxy".to_string(),
        proxy_name: Some("payments-tcp".to_string()),
        listen_port: 15432,
        backend_scheme: BackendScheme::Tcp,
        consumer_index: Arc::new(ConsumerIndex::new(&[])),
        identified_consumer: None,
        authenticated_identity: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
        auth_method: None,
        metadata: None,
        tls_client_cert_der: Some(Arc::new(vec![1, 2, 3])),
        tls_client_cert_chain_der: None,
        sni_hostname: None,
    };

    let result = plugin.on_stream_connect(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    let metadata = ctx.metadata.expect("stream metadata");
    assert_eq!(
        metadata.get("mesh.source.principal").map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/client")
    );
    assert_eq!(
        metadata.get("mesh.source.namespace").map(String::as_str),
        Some("default")
    );
    assert_eq!(
        metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("client")
    );
    assert_eq!(
        metadata.get("mesh.source.workload").map(String::as_str),
        Some("client-svc")
    );
    assert_eq!(
        metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
    assert_eq!(
        metadata.get("mesh.topology").map(String::as_str),
        Some("sidecar")
    );
}

#[tokio::test]
async fn workload_metrics_accepts_baggage_in_aliased_trust_domain() {
    let plugin = WorkloadMetrics::new(&json!({
        "trust_domain_aliases": ["cluster.local"]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://partner.local/ns/default/sa/ztunnel"));
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
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/client")
    );
    assert!(!ctx.metadata.contains_key("mesh.ignored_baggage"));
}

#[tokio::test]
async fn workload_metrics_rejects_invalid_trust_domain_alias() {
    let result = WorkloadMetrics::new(&json!({
        "trust_domain_aliases": ["Bad.Trust"]
    }));
    let err = match result {
        Ok(_) => panic!("invalid alias should fail construction"),
        Err(e) => e,
    };
    assert!(
        err.contains("Bad.Trust"),
        "error should mention bad alias, got: {err}"
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
            request_principals: Vec::new(),
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
    // Empty labels + no namespace applies to any workload. This test pins the
    // selector contract.
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
    use ferrum_edge::modes::mesh::slice::MeshSlice;

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

// ── requestPrincipals JWT enforcement (Phase C) ─────────────────────────────
//
// These tests pin the Istio-compatible `requestPrincipals` semantics:
//
// 1. `jwks_auth` sets `ctx.metadata["jwks_auth.request_principal"]` = `{iss}/{sub}`.
// 2. `mesh_authz` passes that metadata value as `MeshAuthzRequest.request_principal`.
// 3. `MeshRule.request_principals` (from `from[].source.requestPrincipals`)
//    filters rules by glob-matching the request principal.
// 4. Empty `request_principals` means "any" (no filter).
// 5. Non-empty `request_principals` + no JWT (`None`) fails the match.

fn request_principal_policy(name: &str, action: PolicyAction, patterns: Vec<String>) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            request_principals: patterns,
            action,
            ..MeshRule::default()
        }],
    }
}

#[tokio::test]
async fn mesh_authz_request_principals_allow_matching_jwt() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "require-jwt",
            PolicyAction::Allow,
            vec!["https://auth.example.com/user-123".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata.insert(
        "jwks_auth.request_principal".to_string(),
        "https://auth.example.com/user-123".to_string(),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "matching request principal should be allowed, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_request_principals_deny_non_matching_jwt() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "require-jwt",
            PolicyAction::Allow,
            vec!["https://auth.example.com/admin-*".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata.insert(
        "jwks_auth.request_principal".to_string(),
        "https://auth.example.com/user-123".to_string(),
    );

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("non-matching request principal should be denied, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn mesh_authz_request_principals_deny_missing_jwt() {
    // A rule requiring requestPrincipals must reject anonymous (no-JWT) requests.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "require-any-jwt",
            PolicyAction::Allow,
            vec!["*".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    // No jwks_auth.request_principal metadata — anonymous request

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("missing JWT should trigger implicit deny, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_request_principals_wildcard_matches_any_jwt() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "require-any-jwt",
            PolicyAction::Allow,
            vec!["*".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata.insert(
        "jwks_auth.request_principal".to_string(),
        "https://any-issuer.example.com/any-subject".to_string(),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "wildcard should match any JWT principal, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_empty_request_principals_allows_anonymous() {
    // An empty request_principals list means "no filter" — anonymous is fine.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "no-jwt-constraint",
            PolicyAction::Allow,
            vec![],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "empty request_principals should allow anonymous, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_request_principals_deny_rule_blocks_jwt() {
    // A DENY rule with requestPrincipals should block matching JWTs.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "deny-admin",
            PolicyAction::Deny,
            vec!["https://auth.example.com/admin-*".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata.insert(
        "jwks_auth.request_principal".to_string(),
        "https://auth.example.com/admin-root".to_string(),
    );

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("deny rule should block matching JWT, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("deny-admin")
    );
}

#[tokio::test]
async fn mesh_authz_request_principals_deny_rule_skips_non_matching_jwt() {
    // A DENY rule with requestPrincipals should NOT block non-matching JWTs.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "deny-admin",
            PolicyAction::Deny,
            vec!["https://auth.example.com/admin-*".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata.insert(
        "jwks_auth.request_principal".to_string(),
        "https://auth.example.com/user-123".to_string(),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "deny rule should not block non-matching JWT, got {result:?}"
    );
}
