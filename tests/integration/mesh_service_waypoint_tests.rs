//! Integration coverage for the GAMMA Service-Waypoint topology
//! (`MeshTopology::ServiceWaypoint`). Verifies:
//!
//! - The Kubernetes translator builds `MeshConfig.waypoint_bindings` from
//!   `Gateway` resources with `gatewayClassName: istio-waypoint` plus
//!   `Service` objects annotated with `istio.io/use-waypoint`.
//! - The slice builder narrows `services` / `service_entries` /
//!   `destination_rules` / `workloads` to the bound set when the request
//!   carries `waypoint_name`.
//! - `enabled: false` style opt-out (`waypoint_for: none`) yields an empty
//!   admitted set.
//! - The slice builder preserves admit behavior for unrelated topologies
//!   (no `waypoint_name`) — no regression for existing Sidecar/Ambient.

use std::collections::HashMap;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::SpiffeId;
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshService, MeshWaypointBinding, MeshWaypointServiceRef, ServicePort,
    Workload, WorkloadRef,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

fn translation_options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
    .with_pod_discovery_enabled(true)
}

fn meta(name: &str, annotations: HashMap<String, String>) -> K8sMetadata {
    K8sMetadata {
        name: name.to_string(),
        namespace: "default".to_string(),
        labels: HashMap::new(),
        annotations,
        deletion_timestamp: None,
    }
}

fn k8s_object(api_version: &str, kind: &str, meta: K8sMetadata, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: meta,
        spec,
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

fn waypoint_gateway(name: &str, annotations: HashMap<String, String>) -> K8sObject {
    k8s_object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        meta(name, annotations),
        serde_json::json!({
            "gatewayClassName": "istio-waypoint",
            "listeners": [
                {"name": "mesh", "port": 15008, "protocol": "HBONE"}
            ]
        }),
    )
}

fn service_with_use_waypoint(name: &str, waypoint: &str) -> K8sObject {
    let mut annotations = HashMap::new();
    annotations.insert("istio.io/use-waypoint".to_string(), waypoint.to_string());
    k8s_object(
        "v1",
        "Service",
        meta(name, annotations),
        serde_json::json!({
            "ports": [
                {"name": "http", "port": 8080, "protocol": "TCP", "targetPort": 8080}
            ]
        }),
    )
}

fn translate_objects(objects: Vec<K8sObject>) -> GatewayConfig {
    translate_k8s_objects(&objects, translation_options())
        .expect("translation succeeds")
        .config
}

#[test]
fn k8s_translator_records_waypoint_binding_from_gateway_and_service_annotations() {
    let cfg = translate_objects(vec![
        waypoint_gateway("api-waypoint", HashMap::new()),
        service_with_use_waypoint("reviews", "api-waypoint"),
        service_with_use_waypoint("ratings", "api-waypoint"),
    ]);

    let mesh = cfg.mesh.as_ref().expect("mesh config emitted");
    let binding = mesh
        .waypoint_bindings
        .iter()
        .find(|b| b.name == "api-waypoint")
        .expect("api-waypoint binding present");
    assert_eq!(binding.namespace, "default");
    assert_eq!(binding.waypoint_for, "service");
    let mut bound: Vec<&str> = binding.services.iter().map(|s| s.name.as_str()).collect();
    bound.sort_unstable();
    assert_eq!(bound, vec!["ratings", "reviews"]);
}

#[test]
fn k8s_translator_honors_waypoint_for_annotation_on_gateway() {
    let mut annotations = HashMap::new();
    annotations.insert(
        "istio.io/waypoint-for".to_string(),
        "workload".to_string(),
    );
    let cfg = translate_objects(vec![
        waypoint_gateway("api-waypoint", annotations),
        service_with_use_waypoint("reviews", "api-waypoint"),
    ]);

    let mesh = cfg.mesh.as_ref().expect("mesh config emitted");
    let binding = mesh
        .waypoint_bindings
        .iter()
        .find(|b| b.name == "api-waypoint")
        .expect("binding present");
    assert_eq!(binding.waypoint_for, "workload");
}

#[test]
fn k8s_translator_skips_non_waypoint_gateways() {
    let cfg = translate_objects(vec![k8s_object(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        meta("regular-gateway", HashMap::new()),
        serde_json::json!({
            "gatewayClassName": "istio",
            "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
        }),
    )]);
    let mesh = cfg.mesh.expect("mesh emitted");
    assert!(mesh.waypoint_bindings.is_empty());
}

#[test]
fn k8s_translator_ignores_use_waypoint_none_annotation() {
    let cfg = translate_objects(vec![
        waypoint_gateway("api-waypoint", HashMap::new()),
        service_with_use_waypoint("opt-out", "None"),
    ]);
    let mesh = cfg.mesh.expect("mesh");
    let binding = mesh
        .waypoint_bindings
        .iter()
        .find(|b| b.name == "api-waypoint")
        .expect("gateway-only binding");
    assert!(
        binding.services.is_empty(),
        "Service with use-waypoint=None must not bind"
    );
}

// ── Slice filter ─────────────────────────────────────────────────────────

fn service(name: &str, port: u16, workloads: Vec<&str>) -> MeshService {
    MeshService {
        name: name.to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port,
            protocol: Default::default(),
            name: Some("http".to_string()),
        }],
        workloads: workloads
            .into_iter()
            .map(|sid| WorkloadRef {
                spiffe_id: SpiffeId::new(sid).expect("valid spiffe"),
            })
            .collect(),
        protocol_overrides: HashMap::new(),
    }
}

fn workload(spiffe: &str) -> Workload {
    Workload {
        namespace: "default".to_string(),
        spiffe_id: SpiffeId::new(spiffe).expect("valid spiffe"),
        ..Default::default()
    }
}

fn config_with_mesh(mesh: MeshConfig) -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    }
}

#[test]
fn slice_filter_narrows_services_to_waypoint_binding() {
    let reviews_sa = "spiffe://cluster.local/ns/default/sa/reviews";
    let billing_sa = "spiffe://cluster.local/ns/default/sa/billing";
    let mesh = MeshConfig {
        services: vec![
            service("reviews", 8080, vec![reviews_sa]),
            service("ratings", 8081, vec![reviews_sa]),
            service("billing", 9090, vec![billing_sa]),
        ],
        workloads: vec![workload(reviews_sa), workload(billing_sa)],
        waypoint_bindings: vec![MeshWaypointBinding {
            name: "api-waypoint".to_string(),
            namespace: "default".to_string(),
            waypoint_for: "service".to_string(),
            services: vec![
                MeshWaypointServiceRef {
                    namespace: "default".to_string(),
                    name: "reviews".to_string(),
                },
                MeshWaypointServiceRef {
                    namespace: "default".to_string(),
                    name: "ratings".to_string(),
                },
            ],
        }],
        ..MeshConfig::default()
    };
    let cfg = config_with_mesh(mesh);

    let request = MeshSliceRequest {
        namespace: "default".to_string(),
        ..Default::default()
    }
    .with_waypoint_name(Some("api-waypoint".to_string()));
    let slice = MeshSlice::from_gateway_config(&cfg, request);

    let mut names: Vec<&str> = slice.services.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["ratings", "reviews"],
        "service-waypoint slice must drop billing (unbound)"
    );
    assert_eq!(
        slice.workloads.len(),
        1,
        "only the reviews workload SPIFFE identity is referenced by an admitted service"
    );
    assert_eq!(slice.waypoint_name.as_deref(), Some("api-waypoint"));
}

#[test]
fn slice_filter_without_waypoint_name_preserves_full_visibility() {
    let mesh = MeshConfig {
        services: vec![
            service("reviews", 8080, vec!["spiffe://cluster.local/ns/default/sa/r"]),
            service("billing", 9090, vec!["spiffe://cluster.local/ns/default/sa/b"]),
        ],
        waypoint_bindings: vec![MeshWaypointBinding {
            name: "api-waypoint".to_string(),
            namespace: "default".to_string(),
            waypoint_for: "service".to_string(),
            services: vec![MeshWaypointServiceRef {
                namespace: "default".to_string(),
                name: "reviews".to_string(),
            }],
        }],
        ..MeshConfig::default()
    };
    let cfg = config_with_mesh(mesh);

    let request = MeshSliceRequest {
        namespace: "default".to_string(),
        ..Default::default()
    };
    let slice = MeshSlice::from_gateway_config(&cfg, request);
    assert_eq!(
        slice.services.len(),
        2,
        "Sidecar/Ambient topology (no waypoint_name) must see every visible service"
    );
    assert!(slice.waypoint_name.is_none());
}

#[test]
fn slice_filter_unknown_waypoint_name_falls_open() {
    // Fail-open: operator flipped FERRUM_MESH_TOPOLOGY before the matching
    // Gateway lands. The slice must keep serving rather than going empty so
    // the rollout isn't a flag-day outage.
    let mesh = MeshConfig {
        services: vec![service(
            "reviews",
            8080,
            vec!["spiffe://cluster.local/ns/default/sa/r"],
        )],
        ..MeshConfig::default()
    };
    let cfg = config_with_mesh(mesh);

    let request = MeshSliceRequest {
        namespace: "default".to_string(),
        ..Default::default()
    }
    .with_waypoint_name(Some("missing-binding".to_string()));
    let slice = MeshSlice::from_gateway_config(&cfg, request);
    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.waypoint_name.as_deref(), Some("missing-binding"));
}

#[test]
fn slice_filter_honors_waypoint_for_none_as_opt_out() {
    let mesh = MeshConfig {
        services: vec![service(
            "reviews",
            8080,
            vec!["spiffe://cluster.local/ns/default/sa/r"],
        )],
        waypoint_bindings: vec![MeshWaypointBinding {
            name: "api-waypoint".to_string(),
            namespace: "default".to_string(),
            waypoint_for: "none".to_string(),
            services: vec![MeshWaypointServiceRef {
                namespace: "default".to_string(),
                name: "reviews".to_string(),
            }],
        }],
        ..MeshConfig::default()
    };
    let cfg = config_with_mesh(mesh);

    let request = MeshSliceRequest {
        namespace: "default".to_string(),
        ..Default::default()
    }
    .with_waypoint_name(Some("api-waypoint".to_string()));
    let slice = MeshSlice::from_gateway_config(&cfg, request);
    assert!(
        slice.services.is_empty() && slice.workloads.is_empty(),
        "waypoint_for=none must produce an empty admitted set"
    );
}
