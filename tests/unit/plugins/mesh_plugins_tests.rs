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
    let mut ctx = request_context(None);
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
async fn mesh_authz_reads_split_hbone_baggage_headers() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = http::HeaderMap::new();
    headers.append(
        "baggage",
        "destination.principal=spiffe://cluster.local/ns/default/sa/server"
            .parse()
            .expect("header value"),
    );
    headers.append(
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
async fn mesh_authz_denies_percent_encoded_hbone_baggage_mismatch() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
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
    let mut ctx = request_context(None);
    let mut raw_headers = http::HeaderMap::new();
    raw_headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(raw_headers);
    let mut headers = HashMap::new();

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
async fn workload_metrics_reads_split_hbone_baggage_headers() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(None);
    let mut raw_headers = http::HeaderMap::new();
    raw_headers.append(
        "baggage",
        "destination.principal=spiffe://cluster.local/ns/default/sa/server"
            .parse()
            .expect("header value"),
    );
    raw_headers.append(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(raw_headers);
    let mut headers = HashMap::new();

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
