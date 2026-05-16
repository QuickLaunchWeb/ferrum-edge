use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{MeshTracingConfig, TracingProvider};
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
}

fn k8s_object(
    api_version: &str,
    kind: &str,
    name: &str,
    namespace: &str,
    spec: Value,
) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            namespace: namespace.to_string(),
            labels: Default::default(),
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn telemetry(spec: Value) -> K8sObject {
    k8s_object(
        "telemetry.istio.io/v1",
        "Telemetry",
        "sample",
        "default",
        spec,
    )
}

fn istio_mesh_config(mesh: &str) -> K8sObject {
    k8s_object(
        "v1",
        "ConfigMap",
        "istio",
        "istio-system",
        json!({
            "data": {
                "mesh": mesh,
            }
        }),
    )
}

fn translated_tracing(objects: &[K8sObject]) -> (MeshTracingConfig, Vec<String>) {
    let result = translate_k8s_objects(objects, options()).expect("translation succeeds");
    let mesh = result.config.mesh.expect("mesh config");
    let tracing = mesh.telemetry_resources[0]
        .config
        .tracing
        .clone()
        .expect("tracing config");
    (tracing, result.warnings)
}

#[test]
fn k8s_telemetry_name_only_provider_resolves_from_mesh_config() {
    let (tracing, warnings) = translated_tracing(&[
        istio_mesh_config(
            r#"
extensionProviders:
- name: zipkin-prod
  zipkin:
    service: zipkin.istio-system.svc.cluster.local
    port: 9411
"#,
        ),
        telemetry(json!({
            "tracing": [{
                "providers": [{
                    "name": "zipkin-prod"
                }]
            }]
        })),
    ]);

    match tracing.providers.first().expect("provider translated") {
        TracingProvider::Zipkin { url } => {
            assert_eq!(
                url,
                "http://zipkin.istio-system.svc.cluster.local:9411/api/v2/spans"
            );
        }
        other => panic!("expected Zipkin provider, got {other:?}"),
    }
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
}

#[test]
fn k8s_telemetry_default_provider_resolves_from_mesh_config() {
    let (tracing, warnings) = translated_tracing(&[
        istio_mesh_config(
            r#"
defaultProviders:
  tracing:
  - otel-default
extensionProviders:
- name: otel-default
  opentelemetry:
    service: otel-collector.istio-system.svc.cluster.local
    port: 4318
"#,
        ),
        telemetry(json!({
            "tracing": [{
                "randomSamplingPercentage": 37.5
            }]
        })),
    ]);

    assert_eq!(tracing.sampling_percentage, Some(37.5));
    match tracing
        .providers
        .first()
        .expect("default provider translated")
    {
        TracingProvider::OpenTelemetry { endpoint } => {
            assert_eq!(
                endpoint,
                "http://otel-collector.istio-system.svc.cluster.local:4318"
            );
        }
        other => panic!("expected OpenTelemetry provider, got {other:?}"),
    }
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
}

#[test]
fn k8s_telemetry_missing_mesh_config_provider_warns_and_skips() {
    let (tracing, warnings) = translated_tracing(&[telemetry(json!({
        "tracing": [{
            "providers": [{
                "name": "missing-provider"
            }]
        }]
    }))]);

    assert!(
        tracing.providers.is_empty(),
        "missing provider reference must not surface a tracing provider"
    );
    assert!(
        warnings.iter().any(|warning| warning.contains(
            "Telemetry default/sample references unknown meshConfig extensionProvider 'missing-provider'"
        )),
        "missing provider should emit an operator-visible warning: {warnings:?}"
    );
}

#[test]
fn k8s_telemetry_inline_provider_still_translates_without_mesh_config() {
    let (tracing, warnings) = translated_tracing(&[telemetry(json!({
        "tracing": [{
            "providers": [{
                "name": "datadog",
                "agentUrl": "http://datadog-agent:8126",
                "service": "reviews"
            }]
        }]
    }))]);

    match tracing
        .providers
        .first()
        .expect("inline provider translated")
    {
        TracingProvider::Datadog { agent_url, service } => {
            assert_eq!(agent_url, "http://datadog-agent:8126");
            assert_eq!(service.as_deref(), Some("reviews"));
        }
        other => panic!("expected Datadog provider, got {other:?}"),
    }
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
}

#[test]
fn k8s_telemetry_non_tracing_extension_provider_lookup_distinguishes_from_unknown() {
    // Operator declared an `envoyExtAuthzHttp` extensionProvider and then
    // mistakenly referenced it from Telemetry tracing. The warning must
    // distinguish "declared but not tracing" from "name not declared at all"
    // so the operator can locate the misconfiguration.
    let (tracing, warnings) = translated_tracing(&[
        istio_mesh_config(
            r#"
extensionProviders:
- name: ext-authz
  envoyExtAuthzHttp:
    service: authz.default.svc.cluster.local
    port: 9000
"#,
        ),
        telemetry(json!({
            "tracing": [{
                "providers": [{
                    "name": "ext-authz"
                }]
            }]
        })),
    ]);

    assert!(
        tracing.providers.is_empty(),
        "non-tracing extensionProvider must not surface a tracing provider"
    );
    assert!(
        warnings.iter().any(|warning| warning.contains(
            "Telemetry default/sample references meshConfig extensionProvider 'ext-authz' which is declared but not a tracing provider type"
        )),
        "warning should distinguish declared-but-not-tracing from unknown: {warnings:?}"
    );
}

#[test]
fn k8s_telemetry_malformed_mesh_config_does_not_block_sibling_telemetry() {
    // A stray invalid-YAML edit in the istio ConfigMap must not silently
    // empty the registry and drop all Telemetry; the reconciler's
    // skip-retries fallback drops the bad ConfigMap and continues. An
    // inline-provider Telemetry resource still translates so the mesh
    // keeps emitting spans.
    use ferrum_edge::config_sources::k8s::{K8sTranslateError, translate_k8s_objects};

    let objects = vec![
        istio_mesh_config("not: valid: yaml"),
        telemetry(json!({
            "tracing": [{
                "providers": [{
                    "name": "datadog",
                    "agentUrl": "http://datadog-agent:8126",
                    "service": "reviews"
                }]
            }]
        })),
    ];

    // First pass surfaces the malformed ConfigMap as an InvalidResource
    // error so the reconciler can drop it on retry.
    let err = translate_k8s_objects(&objects, options())
        .expect_err("invalid mesh ConfigMap must surface as an error");
    match err {
        K8sTranslateError::InvalidResource { kind, name, .. } => {
            assert_eq!(kind, "ConfigMap");
            assert_eq!(name, "istio");
        }
        other => panic!("expected InvalidResource error, got {other:?}"),
    }

    // After the reconciler drops the bad ConfigMap, the Telemetry resource
    // still resolves through inline-provider translation — no provider
    // requires meshConfig because the spec carries its own config.
    let healthy = vec![objects[1].clone()];
    let translation = translate_k8s_objects(&healthy, options())
        .expect("sibling Telemetry must still translate after malformed ConfigMap is skipped");
    let mesh = translation.config.mesh.expect("mesh config emitted");
    let tracing = mesh.telemetry_resources[0]
        .config
        .tracing
        .clone()
        .expect("tracing config emitted");
    match tracing.providers.first().expect("inline provider emitted") {
        TracingProvider::Datadog { agent_url, .. } => {
            assert_eq!(agent_url, "http://datadog-agent:8126");
        }
        other => panic!("expected Datadog inline provider, got {other:?}"),
    }
}
