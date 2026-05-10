use std::collections::{BTreeMap, HashMap};

use chrono::Utc;
use prost::Message;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshPolicy, MeshRule, MeshService, MtlsMode, PeerAuthentication,
    PolicyAction, PolicyScope, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
    TrustBundle, TrustBundleSet, Workload, WorkloadPort, WorkloadSelector,
};
use ferrum_edge::xds::conformance::{XdsConformanceCase, required_phase_b_cases};
use ferrum_edge::xds::proto;
use ferrum_edge::xds::{
    AckOutcome, CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, MeshSlice, MeshSliceRequest,
    RDS_TYPE_URL, SDS_TYPE_URL, XdsNonceTracker, XdsSnapshotCache,
    translate_mesh_slice_to_snapshot,
};

fn workload(name: &str, app: &str) -> Workload {
    let trust_domain = TrustDomain::new("cluster.local").expect("valid trust domain");
    let spiffe_id = SpiffeId::new(format!("spiffe://cluster.local/ns/default/sa/{name}"))
        .expect("valid spiffe id");
    Workload {
        spiffe_id,
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), app.to_string())]),
            namespace: Some("default".to_string()),
        },
        service_name: name.to_string(),
        addresses: Vec::new(),
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain,
        namespace: "default".to_string(),
        network: None,
        cluster: None,
    }
}

fn mesh_config() -> MeshConfig {
    MeshConfig {
        workloads: vec![workload("api", "api"), workload("worker", "worker")],
        services: vec![MeshService {
            name: "api".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }],
        mesh_policies: vec![
            MeshPolicy {
                name: "api-only".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "api".to_string())]),
                        namespace: Some("default".to_string()),
                    },
                },
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: Vec::new(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            },
            MeshPolicy {
                name: "other-namespace".to_string(),
                namespace: "other".to_string(),
                scope: PolicyScope::MeshWide,
                rules: Vec::new(),
            },
        ],
        peer_authentications: vec![PeerAuthentication {
            name: "default-mtls".to_string(),
            namespace: "default".to_string(),
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        service_entries: Vec::new(),
        trust_bundles: None,
        multi_cluster: None,
    }
}

fn gateway_config() -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(mesh_config())),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    }
}

#[test]
fn mesh_slice_is_per_namespace_and_policy_scoped() {
    let request = MeshSliceRequest {
        node_id: "sidecar-api".to_string(),
        namespace: "default".to_string(),
        workload_spiffe_id: Some("spiffe://cluster.local/ns/default/sa/api".to_string()),
        labels: BTreeMap::new(),
    };
    let slice = MeshSlice::from_gateway_config(&gateway_config(), request);

    assert_eq!(slice.namespace, "default");
    assert_eq!(slice.workloads.len(), 2);
    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.mesh_policies.len(), 1);
    assert_eq!(slice.mesh_policies[0].name, "api-only");
    assert_eq!(slice.peer_authentications.len(), 1);
    assert_eq!(slice.labels.get("app").map(String::as_str), Some("api"));
}

#[test]
fn translators_emit_all_phase_b_type_urls() {
    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let slice = MeshSlice::from_gateway_config(&gateway_config(), request);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);

    assert_eq!(snapshot.resources(LDS_TYPE_URL).len(), 1);
    assert_eq!(snapshot.resources(RDS_TYPE_URL).len(), 1);
    assert_eq!(snapshot.resources(CDS_TYPE_URL).len(), 1);
    assert_eq!(snapshot.resources(EDS_TYPE_URL).len(), 1);
    assert!(snapshot.resources(SDS_TYPE_URL).is_empty());

    let listener_resource = snapshot.resources(LDS_TYPE_URL)[0].clone();
    let listener = proto::Listener::decode(listener_resource.value.as_slice())
        .expect("minimal listener should decode");
    assert_eq!(listener.name, "listener/default/api/8080");
}

#[test]
fn translators_deduplicate_colliding_cluster_resources() {
    let mut mesh = mesh_config();
    mesh.service_entries.push(ServiceEntry {
        name: "api".to_string(),
        namespace: "default".to_string(),
        hosts: vec!["api.example.test".to_string()],
        endpoints: Vec::new(),
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
    });
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let slice = MeshSlice::from_gateway_config(&config, request);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);

    let cds = snapshot.resources(CDS_TYPE_URL);
    assert_eq!(cds.len(), 1);
    assert_eq!(cds[0].name, "cluster/default/api/8080");

    let eds = snapshot.resources(EDS_TYPE_URL);
    assert_eq!(eds.len(), 1);
    assert_eq!(eds[0].name, "cluster/default/api/8080");
}

#[test]
fn translators_deduplicate_colliding_listener_and_route_resources() {
    let mut mesh = mesh_config();
    mesh.services.push(mesh.services[0].clone());
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let slice = MeshSlice::from_gateway_config(&config, request);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);

    let lds = snapshot.resources(LDS_TYPE_URL);
    assert_eq!(lds.len(), 1);
    assert_eq!(lds[0].name, "listener/default/api/8080");

    let rds = snapshot.resources(RDS_TYPE_URL);
    assert_eq!(rds.len(), 1);
    assert_eq!(rds[0].name, "route/default/api");
}

#[test]
fn translator_deduplicates_colliding_sds_resources() {
    let mut mesh = mesh_config();
    let cluster_local = TrustDomain::new("cluster.local").expect("valid trust domain");
    let partner = TrustDomain::new("partner.local").expect("valid trust domain");
    mesh.trust_bundles = Some(TrustBundleSet {
        local: TrustBundle {
            trust_domain: cluster_local.clone(),
            x509_authorities: vec!["local-ca".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: vec![
            TrustBundle {
                trust_domain: partner.clone(),
                x509_authorities: vec!["partner-ca".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            TrustBundle {
                trust_domain: partner,
                x509_authorities: vec!["partner-ca-duplicate".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            TrustBundle {
                trust_domain: cluster_local,
                x509_authorities: vec!["local-ca-duplicate".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
        ],
    });
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let slice = MeshSlice::from_gateway_config(&config, request);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);

    let secrets = snapshot.resources(SDS_TYPE_URL);
    let secret_names: std::collections::HashSet<_> = secrets
        .iter()
        .map(|resource| resource.name.as_str())
        .collect();

    assert_eq!(secrets.len(), 2);
    assert!(secret_names.contains("secret/spiffe-bundle/cluster.local"));
    assert!(secret_names.contains("secret/spiffe-bundle/partner.local"));
}

#[test]
fn mesh_slice_content_eq_ignores_only_version() {
    let config = gateway_config();
    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let mut left = MeshSlice::from_gateway_config(&config, request.clone());
    let mut right = MeshSlice::from_gateway_config(&config, request);

    right.version = "different-version".to_string();
    assert!(left.content_eq(&right));

    left.namespace = "other".to_string();
    assert!(!left.content_eq(&right));

    left.namespace = right.namespace.clone();
    right.multi_cluster = Some(ferrum_edge::modes::mesh::config::MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        ..Default::default()
    });
    assert!(!left.content_eq(&right));
}

#[test]
fn snapshot_cache_is_keyed_by_node_id() {
    let cache = XdsSnapshotCache::new();
    let mut slice_a = MeshSlice::from_gateway_config(
        &gateway_config(),
        MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string()),
    );
    let mut slice_b = slice_a.clone();
    slice_b.node_id = "node-b".to_string();
    slice_a.version = "v1".to_string();
    slice_b.version = "v2".to_string();

    cache.insert(translate_mesh_slice_to_snapshot(&slice_a));
    cache.insert(translate_mesh_slice_to_snapshot(&slice_b));

    assert_eq!(cache.len(), 2);
    assert!(cache.get("node-a").unwrap().version.starts_with("v1:"));
    assert!(cache.get("node-b").unwrap().version.starts_with("v2:"));
}

#[test]
fn snapshot_reports_resource_removal_by_type_url() {
    let slice = MeshSlice::from_gateway_config(
        &gateway_config(),
        MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string()),
    );
    let before = translate_mesh_slice_to_snapshot(&slice);
    let mut after_slice = slice.clone();
    after_slice.services.clear();
    let after = translate_mesh_slice_to_snapshot(&after_slice);

    assert_eq!(
        before.removed_resource_names(&after, CDS_TYPE_URL),
        vec!["cluster/default/api/8080".to_string()]
    );
}

#[test]
fn nonce_tracker_keeps_ack_state_per_node_and_type_url() {
    let tracker = XdsNonceTracker::new();
    let lds_nonce = tracker.issue_nonce("node-a", LDS_TYPE_URL, "v1");
    let rds_nonce = tracker.issue_nonce("node-a", RDS_TYPE_URL, "v1");

    assert_eq!(
        tracker.record_response(
            "node-a",
            LDS_TYPE_URL,
            &lds_nonce,
            "v1",
            Some("bad listener")
        ),
        AckOutcome::Nacked {
            message: "bad listener".to_string()
        }
    );
    assert_eq!(
        tracker.record_response("node-a", RDS_TYPE_URL, &rds_nonce, "v1", None),
        AckOutcome::Acked
    );
    assert_eq!(
        tracker.last_error("node-a", LDS_TYPE_URL),
        Some("bad listener".to_string())
    );
    assert_eq!(tracker.last_error("node-a", RDS_TYPE_URL), None);
}

#[test]
fn nonce_tracker_rejects_version_drift() {
    let tracker = XdsNonceTracker::new();
    let nonce = tracker.issue_nonce("node-a", LDS_TYPE_URL, "v2");

    assert_eq!(
        tracker.record_response("node-a", LDS_TYPE_URL, &nonce, "v1", None),
        AckOutcome::VersionDrift {
            expected: "v2".to_string(),
            actual: "v1".to_string()
        }
    );
}

#[test]
fn phase_b_conformance_stubs_cover_known_xds_edges() {
    let cases = required_phase_b_cases();
    assert!(cases.contains(&XdsConformanceCase::ResourceRemovalDuringUpdate));
    assert!(cases.contains(&XdsConformanceCase::PartialNackPerTypeUrl));
    assert!(cases.contains(&XdsConformanceCase::VersionDriftRejected));
    assert!(cases.contains(&XdsConformanceCase::DeltaSubscribeUnsubscribe));
}
