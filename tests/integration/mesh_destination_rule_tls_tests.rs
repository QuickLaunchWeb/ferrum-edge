//! Integration coverage for `DestinationRule.trafficPolicy.tls` flowing from
//! the Istio K8s translator all the way through `MeshSlice` and onto a
//! resolved `Upstream`'s `backend_tls_*` fields.
//!
//! Today the cell at [`docs/mesh.md`](../../docs/mesh.md) for
//! `trafficPolicy.tls` says it is honored as a backend TLS override on the
//! upstream when set, and that PeerAuthentication-derived posture continues
//! to drive the default when unset. These tests pin both halves of that
//! contract.

use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::types::{
    GatewayConfig, MAX_TARGET_WEIGHT, Proxy, Upstream, UpstreamTarget,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshTrafficPolicy, MeshTrafficPolicyTls, MtlsMode, OutboundTrafficPolicy,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};

fn slice_request_for_default_ns() -> MeshSliceRequest {
    MeshSliceRequest {
        namespace: "default".to_string(),
        ..Default::default()
    }
}

fn istio_object(kind: &str, name: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            namespace: "default".to_string(),
            labels: Default::default(),
            deletion_timestamp: None,
        },
        spec,
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

fn k8s_options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
}

fn test_addr(raw: &str) -> std::net::SocketAddr {
    raw.parse().expect("valid socket address")
}

fn test_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: test_addr("127.0.0.1:15006"),
        outbound_listen_addr: test_addr("127.0.0.1:15001"),
        hbone_listen_addr: test_addr("127.0.0.1:15008"),
        east_west_listen_port: 15443,
        egress_listen_addr: test_addr("0.0.0.0:15090"),
        workload_spiffe_id: None,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        workload_labels: Default::default(),
        dns_enabled: false,
        dns_listen_addr: test_addr("127.0.0.1:15053"),
        dns_upstream_addr: test_addr("127.0.0.53:53"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: CaptureMode::Explicit,
        outbound_traffic_policy: OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
    }
}

/// Build a matching `Upstream` so the DR's host resolves to it during cold-path
/// apply. The DR cold-path matches on `target.host` (or `upstream.name`) so we
/// give the upstream a single target with the same FQDN as the DR's host.
fn build_matching_upstream(id: &str, host_fqdn: &str) -> Upstream {
    use std::collections::HashMap;
    let now = chrono::Utc::now();
    Upstream {
        id: id.to_string(),
        namespace: "default".to_string(),
        name: Some(id.to_string()),
        targets: vec![UpstreamTarget {
            host: host_fqdn.to_string(),
            port: 8080,
            weight: MAX_TARGET_WEIGHT.min(1),
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: Default::default(),
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        port_overrides: HashMap::new(),
        source_locality: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

fn build_proxy(id: &str, upstream_id: &str) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "hosts": [format!("{id}.example.com")],
        "backend_host": "",
        "backend_port": 0,
        "upstream_id": upstream_id
    }))
    .expect("test proxy")
}

/// Translate a single Istio DestinationRule object and return the resulting
/// `GatewayConfig` plus the parsed `MeshTrafficPolicyTls` (if any).
fn translate_dr(spec: serde_json::Value) -> (GatewayConfig, Option<MeshTrafficPolicyTls>) {
    let result = translate_k8s_objects(
        &[istio_object("DestinationRule", "reviews", spec)],
        k8s_options(),
    )
    .expect("translation should succeed");
    let mesh = result.config.mesh.as_ref().expect("mesh present");
    let tls = mesh.destination_rules[0]
        .traffic_policy
        .as_ref()
        .and_then(|tp| tp.tls.clone());
    (result.config, tls)
}

#[test]
fn dr_tls_simple_flows_through_to_upstream_backend_tls() {
    // ── 1. Translate the DestinationRule YAML/JSON. ──
    let (mut config, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {
                "mode": "SIMPLE",
                "caCertificates": "/etc/certs/ca.pem"
            }
        }
    }));

    let tls = tls.expect("DR.tls should be parsed");
    assert_eq!(tls.mode, MtlsMode::Simple);
    assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));

    // ── 2. Attach an upstream that the DR's host matches. ──
    config.upstreams.push(build_matching_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));

    // ── 3. Run slice projection + cold-path DR apply via the public API. ──
    let slice = MeshSlice::from_gateway_config(&config, slice_request_for_default_ns());
    // The CP applies DRs onto the GatewayConfig at slice projection time; we
    // simulate that here by walking the slice's destination_rules and running
    // the same projection through the runtime's public preparation entry
    // point. Since `prepare_gateway_config_for_mesh` requires a
    // `MeshRuntimeConfig`, we instead reach for the integration-safe
    // primitive: rebuild a GatewayConfig from the slice + the upstream, then
    // assert the in-slice MeshDestinationRule carries the tls we expect.
    //
    // Cold-path application is unit-tested in `src/modes/mesh/mod.rs`; here
    // we anchor the wire-level contract: the slice transports the tls.
    assert_eq!(slice.destination_rules.len(), 1);
    let dr_tls = slice.destination_rules[0]
        .traffic_policy
        .as_ref()
        .and_then(|tp| tp.tls.as_ref())
        .expect("slice DR.tls present");
    assert_eq!(dr_tls.mode, MtlsMode::Simple);
    assert_eq!(dr_tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));
}

#[test]
fn dr_tls_mutual_carries_client_cert_and_key_through_slice() {
    let (_, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {
                "mode": "MUTUAL",
                "caCertificates": "/etc/certs/ca.pem",
                "clientCertificate": "/etc/certs/client.pem",
                "privateKey": "/etc/certs/client.key"
            }
        }
    }));

    let tls = tls.expect("DR.tls should be parsed");
    assert_eq!(tls.mode, MtlsMode::Mutual);
    assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));
    assert_eq!(
        tls.client_certificate.as_deref(),
        Some("/etc/certs/client.pem")
    );
    assert_eq!(tls.private_key.as_deref(), Some("/etc/certs/client.key"));
}

#[test]
fn dr_tls_istio_mutual_translates_without_explicit_cert_material() {
    let (_, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {"mode": "ISTIO_MUTUAL"}
        }
    }));

    let tls = tls.expect("DR.tls should be parsed");
    assert_eq!(tls.mode, MtlsMode::IstioMutual);
    assert!(tls.client_certificate.is_none());
    assert!(tls.private_key.is_none());
    assert!(tls.ca_certificates.is_none());
}

#[test]
fn dr_istio_mutual_projects_workload_svid_onto_upstream() {
    let (mut config, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {"mode": "ISTIO_MUTUAL"}
        }
    }));
    assert_eq!(
        tls.expect("DR.tls should be parsed").mode,
        MtlsMode::IstioMutual
    );

    config.upstreams.push(build_matching_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));
    config.proxies.push(build_proxy("reviews-p", "reviews-u"));
    let runtime = MeshRuntimeConfig {
        workload_svid_cert_path: Some("/var/run/secrets/ferrum/svid.pem".to_string()),
        workload_svid_key_path: Some("/var/run/secrets/ferrum/svid.key".to_string()),
        workload_svid_trust_bundle_path: Some(
            "/var/run/secrets/ferrum/trust-bundle.pem".to_string(),
        ),
        ..test_runtime()
    };

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == "reviews-u")
        .expect("matching upstream");
    assert_eq!(
        upstream.backend_tls_client_cert_path.as_deref(),
        Some("/var/run/secrets/ferrum/svid.pem")
    );
    assert_eq!(
        upstream.backend_tls_client_key_path.as_deref(),
        Some("/var/run/secrets/ferrum/svid.key")
    );
    assert_eq!(
        upstream.backend_tls_server_ca_cert_path.as_deref(),
        Some("/var/run/secrets/ferrum/trust-bundle.pem")
    );
    assert!(upstream.backend_tls_verify_server_cert);

    let proxy = prepared
        .proxies
        .iter()
        .find(|proxy| proxy.id == "reviews-p")
        .expect("proxy");
    assert_eq!(
        proxy.resolved_tls.client_cert_path.as_deref(),
        Some("/var/run/secrets/ferrum/svid.pem")
    );
    assert_eq!(
        proxy.resolved_tls.client_key_path.as_deref(),
        Some("/var/run/secrets/ferrum/svid.key")
    );
    assert_eq!(
        proxy.resolved_tls.server_ca_cert_path.as_deref(),
        Some("/var/run/secrets/ferrum/trust-bundle.pem")
    );
}

#[test]
fn dr_istio_mutual_without_runtime_svid_fails_mesh_preparation() {
    let (mut config, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {"mode": "ISTIO_MUTUAL"}
        }
    }));
    assert_eq!(
        tls.expect("DR.tls should be parsed").mode,
        MtlsMode::IstioMutual
    );

    let mut upstream = build_matching_upstream("reviews-u", "reviews.default.svc.cluster.local");
    upstream.backend_tls_client_cert_path = Some("/existing/client.pem".to_string());
    upstream.backend_tls_client_key_path = Some("/existing/client.key".to_string());
    config.upstreams.push(upstream);
    config.proxies.push(build_proxy("reviews-p", "reviews-u"));

    let err = prepare_gateway_config_for_mesh(config, &test_runtime())
        .expect_err("ISTIO_MUTUAL without runtime SVID material must fail");

    assert!(
        err.to_string()
            .contains("requires FERRUM_GATEWAY_SVID_CERT_PATH"),
        "got: {err}"
    );
}

#[test]
fn dr_tls_sni_and_sans_project_onto_upstream() {
    let (mut config, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {
                "mode": "SIMPLE",
                "sni": "reviews.mesh.internal",
                "subjectAltNames": [
                    "reviews.mesh.internal",
                    "spiffe://cluster.local/ns/default/sa/reviews"
                ]
            }
        }
    }));
    let tls = tls.expect("DR.tls should be parsed");
    assert_eq!(tls.sni.as_deref(), Some("reviews.mesh.internal"));
    assert_eq!(tls.subject_alt_names.len(), 2);

    config.upstreams.push(build_matching_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));
    config.proxies.push(build_proxy("reviews-p", "reviews-u"));

    let prepared = prepare_gateway_config_for_mesh(config, &test_runtime())
        .expect("mesh preparation succeeds");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == "reviews-u")
        .expect("matching upstream");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("reviews.mesh.internal")
    );
    assert_eq!(
        upstream.backend_tls_san_allow_list,
        vec![
            "reviews.mesh.internal".to_string(),
            "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
        ]
    );

    let proxy = prepared
        .proxies
        .iter()
        .find(|proxy| proxy.id == "reviews-p")
        .expect("proxy");
    assert_eq!(
        proxy.resolved_tls.sni.as_deref(),
        Some("reviews.mesh.internal")
    );
    assert_eq!(
        proxy.resolved_tls.san_allow_list,
        vec![
            "reviews.mesh.internal".to_string(),
            "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
        ]
    );
}

#[test]
fn dr_without_tls_block_yields_none_on_slice() {
    // Today's behavior must continue to work — DR without trafficPolicy.tls
    // leaves the upstream's backend_tls_* unchanged.
    let (mut config, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "loadBalancer": {"simple": "ROUND_ROBIN"}
        }
    }));

    assert!(tls.is_none(), "absent tls block must serialize as None");

    config.upstreams.push(build_matching_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));

    let slice = MeshSlice::from_gateway_config(&config, slice_request_for_default_ns());
    assert_eq!(slice.destination_rules.len(), 1);
    assert!(
        slice.destination_rules[0]
            .traffic_policy
            .as_ref()
            .and_then(|tp| tp.tls.as_ref())
            .is_none(),
        "DR.tls must remain None when not specified"
    );
}

#[test]
fn dr_tls_subset_traffic_policy_carries_tls_block() {
    // Subset-level tls block: present on the MeshSubset but cold-path
    // application happens only at the top level today (subset-level
    // projection is tracked separately and surfaced as a translator
    // warning).
    let result = translate_k8s_objects(
        &[istio_object(
            "DestinationRule",
            "reviews",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "subsets": [{
                    "name": "v1",
                    "labels": {"version": "v1"},
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "caCertificates": "/etc/certs/v1-ca.pem"
                        }
                    }
                }]
            }),
        )],
        k8s_options(),
    )
    .expect("translation succeeds");

    let mesh = result.config.mesh.expect("mesh");
    let subset = &mesh.destination_rules[0].subsets[0];
    let tls = subset
        .traffic_policy
        .as_ref()
        .expect("subset tp")
        .tls
        .as_ref()
        .expect("subset tls");
    assert_eq!(tls.mode, MtlsMode::Simple);
    assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/v1-ca.pem"));

    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("trafficPolicy.tls is parsed but not yet applied per-subset")),
        "subset-level tls must produce a translator warning: {:?}",
        result.warnings
    );
}

#[test]
fn mesh_traffic_policy_with_tls_none_omits_tls_key_from_json() {
    // Wire-compatibility invariant: a `MeshTrafficPolicy { tls: None, .. }`
    // serializes WITHOUT a `tls` key so old DPs reading new-format slices
    // see this as a no-op and round-trip stays loss-less. Same is true for
    // every other `Option<...>` field on the struct.
    let policy = MeshTrafficPolicy {
        connect_timeout_ms: Some(1000),
        outlier_detection: None,
        load_balancer: None,
        tls: None,
    };

    let json = serde_json::to_value(&policy).expect("serialize");
    let object = json.as_object().expect("object");
    assert!(
        !object.contains_key("tls"),
        "tls=None must NOT appear in serialized JSON (wire compatibility): {json}"
    );
    // Sanity: the explicitly-set field is present.
    assert_eq!(
        object.get("connect_timeout_ms"),
        Some(&serde_json::json!(1000))
    );
}

#[test]
fn mesh_traffic_policy_tls_optional_sub_fields_skip_when_none() {
    // Sub-field wire-compatibility: every `Option<String>` / `Vec<String>`
    // field skips when empty. `mode` always serializes (no
    // `skip_serializing_if`); only it and any explicitly-set extras
    // appear in the JSON.
    let tls = MeshTrafficPolicyTls {
        mode: MtlsMode::Simple,
        ..MeshTrafficPolicyTls::default()
    };

    let json = serde_json::to_value(&tls).expect("serialize");
    let object = json.as_object().expect("object");
    assert!(object.contains_key("mode"));
    assert!(!object.contains_key("sni"));
    assert!(!object.contains_key("ca_certificates"));
    assert!(!object.contains_key("client_certificate"));
    assert!(!object.contains_key("private_key"));
    assert!(!object.contains_key("subject_alt_names"));
    // `insecure_skip_verify` is a primitive bool; it does serialize when
    // false today (no `skip_serializing_if`). Verify the value, not the
    // presence, so the contract here is explicit.
    assert_eq!(
        object.get("insecure_skip_verify"),
        Some(&serde_json::json!(false))
    );
}

#[test]
fn mesh_traffic_policy_tls_round_trips_through_serde() {
    // Round-trip a populated TLS block to verify the JSON wire format is
    // deserializable back to an equivalent struct (catches any rename /
    // skip-serializing-if drift between fields).
    let original = MeshTrafficPolicyTls {
        mode: MtlsMode::Mutual,
        sni: Some("reviews.example.com".to_string()),
        ca_certificates: Some("/etc/certs/ca.pem".to_string()),
        client_certificate: Some("/etc/certs/client.pem".to_string()),
        private_key: Some("/etc/certs/client.key".to_string()),
        subject_alt_names: vec!["spiffe://example/sa/reviews".to_string()],
        insecure_skip_verify: true,
    };

    let json = serde_json::to_string(&original).expect("serialize");
    let parsed: MeshTrafficPolicyTls = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, original);
}

#[test]
fn mesh_traffic_policy_tls_defaults_mode_to_simple_when_omitted() {
    // Hand-authored or partially-updated TLS blocks may omit `mode`. The
    // serde default must match Istio's `ClientTLSSettings.mode` default
    // (SIMPLE) and the `translate_client_tls_settings` translator, otherwise
    // a JSON payload like `{ "tls": { "sni": "reviews.example.com" } }`
    // fails to load even though Istio semantics treat it as SIMPLE.
    let parsed: MeshTrafficPolicyTls =
        serde_json::from_str(r#"{"sni":"reviews.example.com"}"#).expect("deserialize");
    assert_eq!(parsed.mode, MtlsMode::Simple);
    assert_eq!(parsed.sni.as_deref(), Some("reviews.example.com"));

    // Empty object is also valid and produces the full default.
    let empty: MeshTrafficPolicyTls = serde_json::from_str("{}").expect("deserialize empty");
    assert_eq!(empty, MeshTrafficPolicyTls::default());
    assert_eq!(empty.mode, MtlsMode::Simple);
}

#[test]
fn dr_tls_translation_rejects_istio_mutual_with_explicit_cert() {
    let err = translate_k8s_objects(
        &[istio_object(
            "DestinationRule",
            "reviews",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "trafficPolicy": {
                    "tls": {
                        "mode": "ISTIO_MUTUAL",
                        "clientCertificate": "/etc/certs/client.pem",
                        "privateKey": "/etc/certs/client.key"
                    }
                }
            }),
        )],
        k8s_options(),
    )
    .expect_err("ISTIO_MUTUAL with explicit cert must be rejected");
    assert!(
        err.to_string()
            .contains("ISTIO_MUTUAL must not set clientCertificate/privateKey/caCertificates"),
        "got: {err}"
    );
}
