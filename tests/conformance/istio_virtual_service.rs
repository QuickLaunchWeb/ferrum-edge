//! Istio VirtualService matcher conformance.
//!
//! Each test exercises one matcher predicate type (uri / headers / method /
//! authority / sourceNamespace / ignoreUriCase / fault) by translating a minimal
//! `VirtualService` through `translate_k8s_objects` and then driving the
//! resulting `mesh_route_dispatch` (or `request_termination` / `fault_injection`)
//! plugin to assert it routes / rejects / falls through as Istio operators expect.
//!
//! Coverage decisions:
//!   - Only the canonical "happy path" per predicate gets a test — the K8s
//!     translator unit-test crate already covers the long-tail edge cases.
//!     The conformance suite proves operator-visible Istio parity exists, not
//!     that every off-by-one is correct.
//!   - Each test registers exactly one feature into the matrix. A single test
//!     covering two features would force operators to read the test body to
//!     learn which assertion proved which feature.

use std::collections::HashMap;

use ferrum_edge::config::types::PluginConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::{Value, json};

use crate::conformance::registry::Status;

const CATEGORY: &str = "istio_virtual_service";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn virtual_service(spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1beta1".to_string(),
        kind: "VirtualService".to_string(),
        metadata: K8sMetadata {
            name: "vs-under-test".to_string(),
            namespace: "default".to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

/// Translate the VS and return the `mesh_route_dispatch` plugin config on the
/// canonical "/" proxy (the dispatch plugin sits on a single proxy when the
/// VS has only URI-style routes).
///
/// Returns `None` if the translation produced no dispatch plugin (e.g. when
/// the translator emitted a `request_termination` instead because all
/// predicates are unsupported).
fn dispatch_plugin_for_host_only(translation_input: &[K8sObject]) -> Option<PluginConfig> {
    let result = translate_k8s_objects(translation_input, options()).expect("translation succeeds");
    result
        .config
        .plugin_configs
        .into_iter()
        .find(|p| p.plugin_name == "mesh_route_dispatch")
}

fn ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    )
}

/// VS predicate: `uri.exact`. The translator collapses this onto a single
/// proxy with an exact-listen-path (`=/path`) match and no dispatch plugin —
/// classical Ferrum routing handles it. The conformance assertion is that
/// the proxy lands with the expected listen_path tier.
#[test]
fn vs_uri_exact_match() {
    register_feature!(
        category = CATEGORY,
        feature = "uri.exact",
        status = Status::Supported,
        notes = "Compiled to a Ferrum proxy with listen_path=`=/path` (exact tier).",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [{"uri": {"exact": "/health"}}],
                "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|p| p.listen_path.as_deref() == Some("=/health"))
        .expect("VirtualService uri.exact must compile to an exact-tier proxy");
    assert_eq!(proxy.backend_host, "echo.default.svc.cluster.local");
    assert_eq!(proxy.backend_port, 8080);
}

/// VS predicate: `uri.prefix`. Translates to the Ferrum prefix-tier route
/// (no leading sigil).
#[test]
fn vs_uri_prefix_match() {
    register_feature!(
        category = CATEGORY,
        feature = "uri.prefix",
        status = Status::Supported,
        notes = "Compiled to a Ferrum proxy with listen_path=`/prefix` (prefix tier).",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [{"uri": {"prefix": "/api/v1"}}],
                "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");

    assert!(
        result
            .config
            .proxies
            .iter()
            .any(|p| p.listen_path.as_deref() == Some("/api/v1")),
        "VirtualService uri.prefix must compile to a prefix-tier Ferrum proxy"
    );
}

/// VS predicate: `uri.regex`. Translates to the Ferrum regex-tier route
/// (leading `~`, auto-anchored full-path).
#[test]
fn vs_uri_regex_match() {
    register_feature!(
        category = CATEGORY,
        feature = "uri.regex",
        status = Status::Supported,
        notes = "Compiled to a Ferrum proxy with listen_path=`~pattern` (regex tier).",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [{"uri": {"regex": "/users/[0-9]+"}}],
                "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");

    assert!(
        result
            .config
            .proxies
            .iter()
            .any(|p| { matches!(p.listen_path.as_deref(), Some(path) if path.starts_with('~')) }),
        "VirtualService uri.regex must compile to a regex-tier Ferrum proxy"
    );
}

/// VS predicate: `headers.X.exact` — T1-B.1 (PR #891). Captured as a
/// `mesh_route_dispatch` rule that routes on header equality.
#[tokio::test]
async fn vs_headers_exact_match() {
    register_feature!(
        category = CATEGORY,
        feature = "headers.X.exact",
        status = Status::Supported,
        notes = "T1-B.1 (PR #891): mesh_route_dispatch rule with case-insensitive header equality.",
    );
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"headers": {"x-canary": {"exact": "v2"}}}],
            "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 8080}}}]
        }]
    }))])
    .expect("mesh_route_dispatch plugin must be emitted for header predicate");

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut headers = HashMap::from([("x-canary".to_string(), "v2".to_string())]);
    let mut req = ctx("GET", "/anything");
    assert!(matches!(
        dispatch.before_proxy(&mut req, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        req.route_override_backend_host.as_deref(),
        Some("canary.default.svc.cluster.local")
    );
}

/// VS predicate: `headers.X.{prefix,regex}` — T1-B.1 (PR #891). First-class
/// `mesh_route_dispatch` predicate that captures the tagged StringMatch shape
/// (`{prefix: "..."}` / `{regex: "..."}`). NOT a fail-closed termination.
#[test]
fn vs_headers_prefix_match() {
    register_feature!(
        category = CATEGORY,
        feature = "headers.X.{prefix,regex}",
        status = Status::Supported,
        notes = "T1-B.1 (PR #891): tagged StringMatch shape compiles into a mesh_route_dispatch rule; regex/prefix arms first-class.",
    );
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"headers": {"x-tenant": {"prefix": "admin-"}}}],
            "route": [{"destination": {"host": "admin.default.svc.cluster.local", "port": {"number": 8080}}}]
        }]
    }))])
    .expect("mesh_route_dispatch plugin must be emitted for prefix header predicate");

    // The translator emits the tagged StringMatch shape; the plugin
    // construction succeeds (regex compiled at config-load time).
    let _ = MeshRouteDispatch::new(&plugin_config.config).expect("plugin loads");
}

/// VS predicate: `method.exact` — T1-B.2 (PR #894). Captured as a
/// `mesh_route_dispatch` rule that restricts method.
#[tokio::test]
async fn vs_method_exact_match() {
    register_feature!(
        category = CATEGORY,
        feature = "method.exact",
        status = Status::Supported,
        notes = "T1-B.2 (PR #894): mesh_route_dispatch rule with method allow-list.",
    );
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"method": {"exact": "GET"}}],
            "route": [{"destination": {"host": "echo.default.svc.cluster.local", "port": {"number": 8080}}}]
        }]
    }))])
    .expect("mesh_route_dispatch plugin must be emitted for method predicate");

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    let mut headers = HashMap::new();
    let mut get_req = ctx("GET", "/x");
    assert!(matches!(
        dispatch.before_proxy(&mut get_req, &mut headers).await,
        PluginResult::Continue
    ));
    // POST must NOT match — `reject_unmatched: true` lands a 404, matching
    // Envoy's behavior when no Istio VS route matches a request.
    let mut post_req = ctx("POST", "/x");
    let mut post_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut post_req, &mut post_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

/// VS predicate: `authority` — deferred. The translator treats authority as
/// an unsupported sibling predicate today: rules carrying it are skipped
/// while other rules in the same `match[]` still emit. Critically, the
/// translator does NOT collapse onto a URI-only catch-all (which would forward
/// requests the operator gated). See the istio.rs::tests
/// `virtual_service_unsupported_authority_predicate_does_not_disable_reject_unmatched`
/// for the conformance regression test.
#[test]
fn vs_authority_match_deferred() {
    register_feature!(
        category = CATEGORY,
        feature = "authority.{exact,prefix,regex}",
        status = Status::Deferred,
        notes = "Unsupported predicate today: rules with `authority` are skipped, sibling rules still emit, reject_unmatched stays true so gated traffic 404s instead of leaking through.",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [
                    {"uri": {"prefix": "/api"}, "headers": {"x-canary": {"exact": "v2"}}},
                    {"uri": {"prefix": "/api"}, "authority": {"exact": "internal.example.com"}}
                ],
                "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");

    let plugin = result
        .config
        .plugin_configs
        .iter()
        .find(|p| p.plugin_name == "mesh_route_dispatch")
        .expect("dispatch plugin emitted for the supported sibling");
    let rules = plugin
        .config
        .get("rules")
        .and_then(Value::as_array)
        .expect("rules array");
    assert_eq!(
        rules.len(),
        1,
        "only the supported header rule survives; authority-bearing sibling is skipped"
    );
    assert_eq!(
        plugin
            .config
            .get("reject_unmatched")
            .and_then(Value::as_bool),
        Some(true),
        "unsupported authority predicate must NOT relax reject_unmatched -- gated traffic 404s rather than leaking through"
    );
}

/// VS predicate: `sourceNamespace` — T1-B.4 (PR #903). Restricts a route
/// to callers in a specific Kubernetes namespace, resolved from the peer's
/// SPIFFE ID. Fails closed when no peer identity is present.
#[tokio::test]
async fn vs_source_namespace_match() {
    register_feature!(
        category = CATEGORY,
        feature = "sourceNamespace",
        status = Status::Supported,
        notes = "T1-B.4 (PR #903): exact-only predicate on peer SPIFFE namespace; fails closed when no identity.",
    );
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"uri": {"prefix": "/internal"}, "sourceNamespace": "platform"}],
            "route": [{"destination": {"host": "platform.default.svc.cluster.local", "port": {"number": 8080}}}]
        }]
    }))])
    .expect("mesh_route_dispatch plugin must be emitted for sourceNamespace predicate");

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");

    // Matching peer SPIFFE ID encodes ns/platform.
    let mut matching = ctx("GET", "/internal/x");
    matching.peer_spiffe_id = Some(
        SpiffeId::new("spiffe://cluster.local/ns/platform/sa/billing").expect("valid spiffe id"),
    );
    let mut headers = HashMap::new();
    assert!(matches!(
        dispatch.before_proxy(&mut matching, &mut headers).await,
        PluginResult::Continue
    ));

    // Non-matching peer namespace: must fall through to reject_unmatched.
    let mut other_ns = ctx("GET", "/internal/x");
    other_ns.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/other/sa/billing").expect("valid spiffe id"));
    let mut other_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut other_ns, &mut other_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));

    // No peer identity at all: fails closed.
    let mut anonymous = ctx("GET", "/internal/x");
    let mut anon_headers = HashMap::new();
    assert!(matches!(
        dispatch
            .before_proxy(&mut anonymous, &mut anon_headers)
            .await,
        PluginResult::Reject {
            status_code: 404,
            ..
        }
    ));
}

/// VS predicate: `ignoreUriCase: true` — deferred. Ferrum's router cannot
/// emulate case-insensitive path matching with a normal prefix route, so the
/// translator emits a `request_termination` plugin attached to a sibling
/// proxy. This fails closed instead of silently making only one casing
/// reachable.
#[test]
fn vs_ignore_uri_case_falls_closed() {
    register_feature!(
        category = CATEGORY,
        feature = "ignoreUriCase: true",
        status = Status::Deferred,
        notes = "Router can't emulate case-insensitive matching; emits request_termination so case-insensitive intent never silently downgrades to case-sensitive.",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [
                {
                    "match": [{"uri": {"prefix": "/Api"}, "ignoreUriCase": true}],
                    "route": [{"destination": {"host": "canary.default.svc.cluster.local", "port": {"number": 9090}}}]
                },
                {
                    "match": [{"uri": {"prefix": "/api"}}],
                    "route": [{"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 8080}}}]
                }
            ]
        }))],
        options(),
    )
    .expect("translation succeeds");

    assert!(
        result
            .config
            .plugin_configs
            .iter()
            .any(|p| p.plugin_name == "request_termination"),
        "ignoreUriCase=true must compile to request_termination (fail-closed)"
    );
}

/// VS feature: `http[].fault` (route-local fault injection) — T1-E (PR #896).
/// Each fault block translates to a `fault_injection` plugin scoped to the
/// proxy. The conformance check is that the plugin is emitted with the
/// translated fault config.
#[test]
fn vs_route_local_fault_injection() {
    register_feature!(
        category = CATEGORY,
        feature = "http[].fault",
        status = Status::Supported,
        notes = "T1-E (PR #896): route-local fault block compiles to a fault_injection plugin on the matching proxy.",
    );
    let result = translate_k8s_objects(
        &[virtual_service(json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [{"uri": {"prefix": "/chaos"}}],
                "fault": {
                    "abort": {"percentage": {"value": 50.0}, "httpStatus": 503}
                },
                "route": [{"destination": {"host": "chaos.default.svc.cluster.local", "port": {"number": 8080}}}]
            }]
        }))],
        options(),
    )
    .expect("translation succeeds");

    assert!(
        result
            .config
            .plugin_configs
            .iter()
            .any(|p| p.plugin_name == "fault_injection"),
        "VirtualService http[].fault must compile to a fault_injection plugin"
    );
}

/// VS feature: `queryParams.X.exact`. Captured as a `mesh_route_dispatch`
/// rule with query-param equality; the rule opts the proxy into decoded
/// `ctx.query_params` materialization.
#[tokio::test]
async fn vs_query_params_exact_match() {
    register_feature!(
        category = CATEGORY,
        feature = "queryParams.X.exact",
        status = Status::Supported,
        notes =
            "mesh_route_dispatch rule with query-param equality; auto-decodes ctx.query_params.",
    );
    let plugin_config = dispatch_plugin_for_host_only(&[virtual_service(json!({
        "hosts": ["api.example.com"],
        "http": [{
            "match": [{"queryParams": {"variant": {"exact": "beta"}}}],
            "route": [{"destination": {"host": "beta.default.svc.cluster.local", "port": {"number": 8080}}}]
        }]
    }))])
    .expect("mesh_route_dispatch plugin must be emitted for queryParams predicate");

    let dispatch = MeshRouteDispatch::new(&plugin_config.config).expect("plugin config");
    assert!(
        dispatch.requires_decoded_query_params(),
        "queryParams predicate must opt the proxy into decoded query_params"
    );

    let mut req = ctx("GET", "/search");
    req.query_params
        .insert("variant".to_string(), "beta".to_string());
    let mut headers = HashMap::new();
    assert!(matches!(
        dispatch.before_proxy(&mut req, &mut headers).await,
        PluginResult::Continue
    ));
}
