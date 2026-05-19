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

// ── VirtualService route-level header transforms ──────────────────────────
//
// Istio `VirtualService.http[].headers.{request,response}.{set,add,remove}`
// projects onto each emitted `mesh_route_dispatch` rule as
// `request_transform` / `response_transform` arrays, and the translator
// auto-emits a `request_transformer` / `response_transformer` instance so
// the per-rule transforms have a consumer at runtime.

#[tokio::test]
async fn mesh_l7_routing_virtual_service_header_set_emits_request_transform() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/v1"}}],
                    "headers": {
                        "request": {
                            "set": {"X-Api-Version": "v1"},
                            "add": {"X-Trace": "added"},
                            "remove": ["X-Debug"]
                        }
                    },
                    "route": [{"destination": {"host": "v1.default.svc.cluster.local", "port": {"number": 8080}}}]
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
        .find(|proxy| proxy.listen_path.as_deref() == Some("/v1"))
        .expect("/v1 proxy");

    // Dispatch plugin must carry the per-rule request_transform array.
    let dispatch = dispatch_plugin_for_proxy(&result.config, proxy);
    let transforms = dispatch.config["rules"][0]["request_transform"]
        .as_array()
        .expect("request_transform array");
    assert_eq!(transforms.len(), 3, "set + add + remove → 3 rules");
    assert!(
        transforms
            .iter()
            .any(|r| r["operation"] == "update" && r["key"] == "X-Api-Version")
    );
    assert!(
        transforms
            .iter()
            .any(|r| r["operation"] == "add" && r["key"] == "X-Trace")
    );
    assert!(
        transforms
            .iter()
            .any(|r| r["operation"] == "remove" && r["key"] == "X-Debug")
    );

    // Translator must auto-emit a request_transformer instance on this
    // proxy so the per-rule overrides have a consumer at runtime.
    let auto_xform = result
        .config
        .plugin_configs
        .iter()
        .find(|p| {
            p.plugin_name == "request_transformer"
                && p.proxy_id.as_deref() == Some(proxy.id.as_str())
        })
        .expect("auto-emitted request_transformer plugin for proxy");
    assert_eq!(
        auto_xform.config["apply_route_overrides"].as_bool(),
        Some(true)
    );
    assert!(
        auto_xform.config["rules"].as_array().unwrap().is_empty(),
        "auto-emitted instance carries only route-level rules, no static ones"
    );

    // End-to-end: when the dispatch rule matches, the per-rule Arc lands on
    // the context, and applying it via the auto-emitted transformer rewrites
    // headers. We exercise both halves via the plugin classes directly.
    use ferrum_edge::plugins::request_transformer::RequestTransformer;
    let mrd = MeshRouteDispatch::new(&dispatch.config).expect("mrd plugin");
    let req_xform = RequestTransformer::new(&auto_xform.config).expect("auto request_transformer");
    assert!(req_xform.modifies_request_headers());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/v1/items".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("x-debug".to_string(), "yes".to_string());
    let _ = mrd.before_proxy(&mut ctx, &mut headers).await;
    let _ = req_xform.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(headers.get("x-api-version").map(String::as_str), Some("v1"));
    assert_eq!(headers.get("x-trace").map(String::as_str), Some("added"));
    assert!(!headers.contains_key("x-debug"));
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_header_remove_emits_response_transform() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{"uri": {"prefix": "/v1"}}],
                    "headers": {
                        "response": {
                            "set": {"X-Backend": "v1"},
                            "remove": ["Server"]
                        }
                    },
                    "route": [{"destination": {"host": "v1.default.svc.cluster.local", "port": {"number": 8080}}}]
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
        .find(|proxy| proxy.listen_path.as_deref() == Some("/v1"))
        .expect("/v1 proxy");
    let dispatch = dispatch_plugin_for_proxy(&result.config, proxy);

    let transforms = dispatch.config["rules"][0]["response_transform"]
        .as_array()
        .expect("response_transform array");
    assert_eq!(transforms.len(), 2);
    // Request side must NOT be populated when the VS only configured
    // response-side transforms.
    assert!(
        dispatch.config["rules"][0]
            .get("request_transform")
            .is_none()
    );

    let auto_xform = result
        .config
        .plugin_configs
        .iter()
        .find(|p| {
            p.plugin_name == "response_transformer"
                && p.proxy_id.as_deref() == Some(proxy.id.as_str())
        })
        .expect("auto-emitted response_transformer plugin for proxy");
    assert_eq!(
        auto_xform.config["apply_route_overrides"].as_bool(),
        Some(true)
    );

    // No auto-emitted request_transformer when there are only response
    // transforms — the translator must avoid emitting plugins that would be
    // no-ops.
    let request_xform_emitted = result.config.plugin_configs.iter().any(|p| {
        p.plugin_name == "request_transformer" && p.proxy_id.as_deref() == Some(proxy.id.as_str())
    });
    assert!(
        !request_xform_emitted,
        "translator must not emit a request_transformer when only response-side transforms exist"
    );
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_headers_route_scope_does_not_leak_across_paths() {
    // Two http[] entries; only the /v1 entry has a header transform. The
    // header transform must NOT show up on the /v2 proxy.
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [
                    {
                        "match": [{"uri": {"prefix": "/v1"}}],
                        "headers": {"request": {"set": {"X-Api-Version": "v1"}}},
                        "route": [{"destination": {"host": "v1.default.svc.cluster.local", "port": {"number": 8080}}}]
                    },
                    {
                        "match": [{"uri": {"prefix": "/v2"}}],
                        "route": [{"destination": {"host": "v2.default.svc.cluster.local", "port": {"number": 8080}}}]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let v1_proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/v1"))
        .expect("/v1 proxy");
    let v2_proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("/v2"))
        .expect("/v2 proxy");

    // /v1's dispatch plugin carries request_transform; /v2's does not.
    let v1_dispatch = dispatch_plugin_for_proxy(&result.config, v1_proxy);
    assert!(
        v1_dispatch.config["rules"][0]["request_transform"]
            .as_array()
            .is_some_and(|arr| !arr.is_empty())
    );
    let v2_dispatch_plugin = result.config.plugin_configs.iter().find(|p| {
        p.plugin_name == "mesh_route_dispatch"
            && p.proxy_id.as_deref() == Some(v2_proxy.id.as_str())
    });
    if let Some(v2_dispatch) = v2_dispatch_plugin {
        // The /v2 proxy may have a dispatch plugin only if its match has a
        // non-URI predicate; in this VS it does not, so the dispatch plugin
        // may be absent. If present, no rule must carry request_transform.
        for rule in v2_dispatch.config["rules"]
            .as_array()
            .unwrap_or(&Vec::new())
        {
            assert!(rule.get("request_transform").is_none());
        }
    }

    // Only /v1's proxy gets the auto-emitted request_transformer.
    let v1_has_xform = result.config.plugin_configs.iter().any(|p| {
        p.plugin_name == "request_transformer"
            && p.proxy_id.as_deref() == Some(v1_proxy.id.as_str())
    });
    let v2_has_xform = result.config.plugin_configs.iter().any(|p| {
        p.plugin_name == "request_transformer"
            && p.proxy_id.as_deref() == Some(v2_proxy.id.as_str())
    });
    assert!(v1_has_xform);
    assert!(!v2_has_xform);
}

// ── VirtualService regex / prefix header matchers (T1-B.1) ─────────────────
//
// VirtualService `match[].headers.X.regex` and `match[].headers.X.prefix`
// are now first-class mesh_route_dispatch predicates. Each test below
// exercises the full translator → plugin construction → request hot path:
// the translator emits the tagged StringMatch shape, the plugin compiles
// the regex once at config-load time, and the request path routes vs
// falls through (or 404s, depending on `reject_unmatched`) based on the
// pre-compiled matcher.

#[tokio::test]
async fn mesh_l7_routing_virtual_service_header_regex_match_routes_and_misses_fall_closed() {
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [{
                        "uri": {"prefix": "/api"},
                        "headers": {"x-user": {"regex": "^admin-.*"}}
                    }],
                    "route": [{"destination": {"host": "admin.default.svc.cluster.local", "port": {"number": 9090}}}]
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
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("/api proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    // Translator emits the tagged regex shape, NOT a request_termination.
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["headers"]["x-user"]["regex"].as_str(),
        Some("^admin-.*")
    );
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(true),
        "guarded-route VS still enforces match semantics via reject_unmatched"
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Match: header value satisfies the regex → route override applies.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut headers = HashMap::from([("x-user".to_string(), "admin-acme".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("admin.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(9090));

    // Miss: header present but regex misses → 404, not silent fall-through to
    // the default backend (Envoy parity for VirtualService match semantics).
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::from([("x-user".to_string(), "user-acme".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

#[tokio::test]
async fn mesh_l7_routing_virtual_service_header_prefix_match_routes_and_falls_through_on_miss() {
    // Soft-fallback flavor of the regex test: a URI-only sibling branch
    // disables `reject_unmatched`, so prefix misses fall through to the
    // default backend rather than 404. This is the existing
    // `mesh_l7_routing_mixed_uri_only_and_header_match` shape, extended
    // with a prefix predicate instead of exact.
    let result = translate_k8s_objects(
        &[object(
            "VirtualService",
            serde_json::json!({
                "hosts": ["api.example.com"],
                "http": [{
                    "match": [
                        {"uri": {"prefix": "/api"}},
                        {
                            "uri": {"prefix": "/api"},
                            "headers": {"x-tenant": {"prefix": "admin-"}}
                        }
                    ],
                    "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
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
        .find(|p| p.listen_path.as_deref() == Some("/api"))
        .expect("/api proxy");
    let plugin_config = dispatch_plugin_for_proxy(&result.config, proxy);
    assert_eq!(
        plugin_config.config["rules"][0]["match"]["headers"]["x-tenant"]["prefix"].as_str(),
        Some("admin-")
    );
    assert_eq!(
        plugin_config.config["reject_unmatched"].as_bool(),
        Some(false),
        "URI-only sibling disables reject_unmatched"
    );

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Match.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut headers = HashMap::from([("x-tenant".to_string(), "admin-acme".to_string())]);
    assert!(matches!(
        dispatch.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    // Prefix match emits the same proxy's default backend on this VS, so the
    // override and the proxy's defaults agree — that's the intentional
    // shape of this fixture. The assertion is that the plugin Continued.

    // Miss: fall through to the default proxy backend (Continue, no override).
    let mut miss_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/items".to_string(),
    );
    let mut miss_headers = HashMap::from([("x-tenant".to_string(), "user-acme".to_string())]);
    assert!(matches!(
        dispatch
            .before_proxy(&mut miss_ctx, &mut miss_headers)
            .await,
        PluginResult::Continue
    ));
    assert!(miss_ctx.route_override_backend_host.is_none());
}
