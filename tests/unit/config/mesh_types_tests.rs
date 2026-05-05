//! Layer-2 mesh type tests: serde round-trips, byte-identical
//! backwards-compat, decode helpers.

use ferrum_edge::config::mesh::{
    AppProtocol, MeshConfig, MeshEndpoint, MeshPolicy, MeshRule, MeshService, MtlsMode,
    PeerAuthentication, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch, Resolution,
    ServiceEntry, ServiceEntryLocation, ServicePort, TrustBundle, TrustBundleSet, Workload,
    WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use std::collections::HashMap;

// ── Backwards-compat (byte-identical) ────────────────────────────────────

/// A non-mesh `GatewayConfig` must round-trip through JSON without ANY of
/// the new mesh fields appearing in the output. This is the critical
/// guarantee that lets file/DB users adopt the binary upgrade transparently.
#[test]
fn non_mesh_config_round_trips_without_mesh_fields() {
    let cfg = GatewayConfig::default();
    let json = serde_json::to_value(&cfg).unwrap();
    let obj = json.as_object().expect("object");
    assert!(
        !obj.contains_key("mesh"),
        "non-mesh config serialised an empty `mesh` field",
    );
}

#[test]
fn mesh_config_round_trips_through_serde() {
    let td = TrustDomain::new("prod.example.com").unwrap();
    let id = SpiffeId::from_parts(&td, "ns/svc/sa/api").unwrap();
    let cfg = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: vec![Workload {
                spiffe_id: id.clone(),
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".into(), "api".into())]),
                    namespace: Some("svc".into()),
                },
                service_name: "api".into(),
                ports: vec![WorkloadPort {
                    port: 8443,
                    protocol: AppProtocol::Http2,
                    name: Some("https".into()),
                }],
                trust_domain: td.clone(),
                namespace: "svc".into(),
            }],
            services: vec![MeshService {
                name: "api".into(),
                namespace: "svc".into(),
                ports: vec![ServicePort {
                    port: 8443,
                    protocol: AppProtocol::Http2,
                    name: None,
                }],
                workloads: vec![WorkloadRef { spiffe_id: id }],
                protocol_overrides: HashMap::new(),
            }],
            ..Default::default()
        })),
        ..GatewayConfig::default()
    };
    let json = serde_json::to_string(&cfg).expect("serialises");
    let back: GatewayConfig = serde_json::from_str(&json).expect("deserialises");
    let mesh = back.mesh.as_ref().expect("mesh present");
    assert_eq!(mesh.workloads.len(), 1);
    assert_eq!(mesh.services.len(), 1);
    assert_eq!(mesh.workloads[0].service_name, "api");
}

#[test]
fn unknown_mesh_fields_are_tolerated() {
    // Forwards-compat: a newer ferrum schema may add fields under a mesh
    // resource. Older binaries must ignore them. Serde's default-on-unknown
    // is fine for our struct shape; this test confirms that.
    let json = r#"{
        "version": "1",
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": [],
        "loaded_at": "2026-04-28T00:00:00Z",
        "known_namespaces": [],
        "mesh": {
            "workloads": [
                {
                    "spiffe_id": "spiffe://td/ns/foo/sa/bar",
                    "selector": {"labels": {}, "namespace": null},
                    "service_name": "svc",
                    "ports": [],
                    "trust_domain": "td",
                    "namespace": "default",
                    "future_field_that_does_not_exist": "ignored"
                }
            ]
        }
    }"#;
    let cfg: GatewayConfig = serde_json::from_str(json).expect("future fields are tolerated");
    let mesh = cfg.mesh.as_ref().expect("mesh present");
    assert_eq!(mesh.workloads.len(), 1);
}

// ── Per-type smoke tests ─────────────────────────────────────────────────

#[test]
fn mesh_policy_serializes_with_oneof_scope() {
    let policy = MeshPolicy {
        name: "deny-cross-ns".into(),
        namespace: "default".into(),
        scope: PolicyScope::Namespace {
            namespace: "default".into(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://prod/ns/ext/sa/*".into()),
                namespace_pattern: None,
                trust_domain: None,
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".into()],
                paths: vec!["/api/*".into()],
                ports: Vec::new(),
                ..Default::default()
            }],
            when: Vec::new(),
            action: PolicyAction::Deny,
        }],
    };
    let s = serde_json::to_string(&policy).unwrap();
    let back: MeshPolicy = serde_json::from_str(&s).unwrap();
    assert_eq!(back, policy);
}

#[test]
fn peer_authentication_default_mtls_mode_is_permissive() {
    let pa = PeerAuthentication {
        name: "allow-mixed".into(),
        namespace: "default".into(),
        selector: None,
        mtls_mode: MtlsMode::default(),
        port_overrides: HashMap::new(),
    };
    assert_eq!(pa.mtls_mode, MtlsMode::Permissive);
}

#[test]
fn service_entry_static_resolution_with_endpoints() {
    let entry = ServiceEntry {
        name: "external-api".into(),
        namespace: "default".into(),
        hosts: vec!["api.partner.example".into()],
        endpoints: vec![MeshEndpoint {
            address: "10.0.0.1".into(),
            ports: HashMap::from([("https".into(), 443u16)]),
            labels: HashMap::new(),
            network: None,
        }],
        resolution: Resolution::Static,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port: 443,
            protocol: AppProtocol::Http2,
            name: Some("https".into()),
        }],
    };
    let s = serde_json::to_string(&entry).unwrap();
    let back: ServiceEntry = serde_json::from_str(&s).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn trust_bundle_decodes_base64_authorities() {
    use base64::Engine;
    let raw_der = b"fake DER blob";
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw_der);
    let bundle = TrustBundle {
        trust_domain: TrustDomain::new("td").unwrap(),
        x509_authorities: vec![b64],
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    };
    let decoded = bundle.decode_x509_authorities().unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0], raw_der);
}

#[test]
fn trust_bundle_set_to_runtime_fills_local_and_federated() {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let bundle = TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("local.test").unwrap(),
            x509_authorities: vec![engine.encode(b"local-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: vec![TrustBundle {
            trust_domain: TrustDomain::new("partner.test").unwrap(),
            x509_authorities: vec![engine.encode(b"partner-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: Some(300),
        }],
    };
    let runtime = bundle.to_runtime().unwrap();
    assert_eq!(runtime.local.x509_authorities.len(), 1);
    assert_eq!(runtime.federated.len(), 1);
    let partner_td = TrustDomain::new("partner.test").unwrap();
    assert!(runtime.federated.contains_key(&partner_td));
}

#[test]
fn app_protocol_default_is_unknown() {
    assert_eq!(AppProtocol::default(), AppProtocol::Unknown);
}
