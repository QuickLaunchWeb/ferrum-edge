use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::config::types::{GatewayConfig, LoadBalancerAlgorithm, PluginConfig, Proxy};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::Value;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: if kind == "VirtualService" {
            "networking.istio.io/v1beta1".to_string()
        } else {
            "gateway.networking.k8s.io/v1".to_string()
        },
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: "sample".to_string(),
            namespace: "default".to_string(),
            generation: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn dispatch_plugin_for_proxy<'a>(config: &'a GatewayConfig, proxy: &Proxy) -> &'a PluginConfig {
    config
        .plugin_configs
        .iter()
        .find(|plugin| {
            plugin.plugin_name == "mesh_route_dispatch"
                && plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
        })
        .expect("mesh_route_dispatch plugin for proxy")
}

#[tokio::test]
async fn mesh_l7_routing_http_route_header_only_match_is_enforced() {
    let result = translate_k8s_objects(
        &[object(
            "HTTPRoute",
            serde_json::json!({
                "hostnames": ["api.example.com"],
                "rules": [{
                    "matches": [{"headers": [{"name": "x-canary", "value": "true"}]}],
                    "backendRefs": [{"name": "canary", "port": 8080}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("/"))
        .expect("catch-all proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(true)
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut headers = HashMap::from([("x-canary".to_string(), "true".to_string())]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/anything".to_string(),
    );
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("canary.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(8080));

    let mut missing_headers = HashMap::new();
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/anything".to_string(),
    );
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut missing_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

#[tokio::test]
async fn mesh_l7_routing_istio_query_match_sets_route_override() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{
                        "queryParams": {"variant": {"exact": "beta"}}
                    }],
                    "route": [{"destination": {"host": "beta.default.svc.cluster.local", "port": {"number": 9090}}}]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("~.*"))
        .expect("URI-less catch-all proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["query_params"]["variant"].as_str(),
        Some("beta")
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut headers = HashMap::new();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/search?variant=beta".to_string(),
    );
    ctx.query_params
        .insert("variant".to_string(), "beta".to_string());
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("beta.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(9090));
}

#[test]
fn mesh_l7_routing_virtual_service_weighted_split_uses_generated_upstream_weights() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"headers": {"x-canary": {"exact": "true"}}}],
                    "route": [
                        {"destination": {"host": "v1.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 900},
                        {"destination": {"host": "v2.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 90},
                        {"destination": {"host": "v3.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 10}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let upstream = result
        .config
        .upstreams
        .iter()
        .find(|upstream| upstream.targets.len() == 3)
        .expect("weighted upstream");
    assert_eq!(
        upstream.algorithm,
        LoadBalancerAlgorithm::WeightedRoundRobin
    );
    let plugin = result
        .config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        .expect("dispatch plugin");
    assert_eq!(
        plugin.config["rules"][0]["destination"]["upstream_id"].as_str(),
        Some(upstream.id.as_str())
    );

    let lb = LoadBalancerCache::new(&result.config);
    let mut counts: HashMap<String, usize> = HashMap::new();
    for i in 0..1000 {
        let target = lb
            .select_target(&upstream.id, &i.to_string(), None)
            .expect("target")
            .target;
        *counts.entry(target.host.clone()).or_default() += 1;
    }

    let v1 = counts
        .get("v1.default.svc.cluster.local")
        .copied()
        .unwrap_or_default();
    let v2 = counts
        .get("v2.default.svc.cluster.local")
        .copied()
        .unwrap_or_default();
    let v3 = counts
        .get("v3.default.svc.cluster.local")
        .copied()
        .unwrap_or_default();
    assert_eq!(v1, 900);
    assert_eq!(v2, 90);
    assert_eq!(v3, 10);
}

#[tokio::test]
async fn mesh_l7_routing_collapsed_istio_route_overrides_timeout_and_retry() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{
                            "uri": {"prefix": "/api"},
                            "headers": {"x-canary": {"exact": "true"}}
                        }],
                        "timeout": "2s",
                        "retries": {
                            "attempts": 2,
                            "retryOn": "5xx,connect-failure",
                            "backoff": {"fixedDelay": "25ms"}
                        },
                        "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                    },
                    {
                        "match": [{"uri": {"prefix": "/api"}}],
                        "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let stable_proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| {
            proxy.listen_path.as_deref() == Some("/api")
                && proxy.backend_host == "stable.default.svc.cluster.local"
        })
        .expect("stable proxy selected by hot router");
    assert_eq!(stable_proxy.backend_read_timeout_ms, 30_000);
    assert!(stable_proxy.retry.is_none());

    let plugin_config = dispatch_plugin_for_proxy(&result.config, stable_proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["timeout_ms"].as_u64(),
        Some(2000)
    );
    assert_eq!(
        plugin_config.config["rules"][0]["retry"]["max_retries"].as_u64(),
        Some(2)
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut headers = HashMap::from([("x-canary".to_string(), "true".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let effective =
        ctx.apply_route_overrides_with_upstreams(Arc::new(stable_proxy.clone()), &HashMap::new());
    assert_eq!(effective.backend_host, "canary.default.svc.cluster.local");
    assert_eq!(effective.backend_port, 9090);
    assert_eq!(effective.backend_read_timeout_ms, 2000);
    assert_eq!(
        effective.retry.as_ref().map(|retry| retry.max_retries),
        Some(2)
    );

    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Continue
    ));
    let effective_miss = miss_ctx
        .apply_route_overrides_with_upstreams(Arc::new(stable_proxy.clone()), &HashMap::new());
    assert_eq!(
        effective_miss.backend_host,
        "stable.default.svc.cluster.local"
    );
    assert_eq!(effective_miss.backend_read_timeout_ms, 30_000);
    assert!(effective_miss.retry.is_none());
}
