//! East-West gateway + Egress gateway materialization coverage.
//!
//! Locks in the cold-path proxy/upstream materialization that
//! `prepare_gateway_config_for_mesh` performs only on the relevant
//! topology:
//!
//! - `EastWestGateway`: SNI-passthrough TCP proxies from
//!   `MultiClusterConfig.east_west_gateways` AND per-service
//!   passthrough proxies for local mesh services.
//! - `EgressGateway`: HTTP-family proxies from `ServiceEntry` resources
//!   with `location: MESH_EXTERNAL`.
//!
//! The materialisation is topology-gated — running on any other
//! topology must be a no-op so a flag flip doesn't accidentally double-
//! bind. The tests also verify the materialisation correctly skips
//! resources that should not be projected (wrong location, empty
//! hosts, no exported scope, no reachable workloads).

use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    AppProtocol, EastWestGateway, MultiClusterConfig, Resolution, ServiceEntry,
    ServiceEntryLocation, ServicePort,
};
use ferrum_edge::modes::mesh::prepare_gateway_config_for_mesh;
use ferrum_edge::modes::mesh::{MeshTopology, runtime::MeshRuntimeState};

use super::mesh_test_support::{
    DEFAULT_NAMESPACE, default_mesh_runtime, gateway_config_with_mesh, mesh_config_with,
    runtime_for_topology, service_for, workload_for,
};

// ── East-West gateway materialization ─────────────────────────────────────

fn east_west_gateway(name: &str, sni_hosts: Vec<&str>) -> EastWestGateway {
    EastWestGateway {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        host: "10.0.0.42".to_string(),
        port: 15443,
        sni_hosts: sni_hosts.into_iter().map(String::from).collect(),
        trust_domain: Some(TrustDomain::new("cluster.local").expect("td")),
        network: Some("network-1".to_string()),
    }
}

fn east_west_runtime() -> ferrum_edge::modes::mesh::MeshRuntimeConfig {
    let mut runtime = runtime_for_topology(MeshTopology::EastWestGateway);
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    runtime.east_west_listen_port = 15443;
    runtime
}

#[test]
fn east_west_gateway_materializes_sni_passthrough_proxy_from_remote_gateway_config() {
    // Explicit EastWestGateway entry in MultiClusterConfig produces a
    // passthrough TCP proxy on the east-west listen port. This is the
    // "remote gateway backend" flow — operators declare a remote
    // cluster's external east-west gateway and we materialise a
    // passthrough proxy that fronts it.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-1".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![east_west_gateway(
            "remote-cluster-gw",
            vec!["remote-svc.default.svc.cluster.local"],
        )],
    });
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &east_west_runtime()).expect("east-west prepared");
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id.starts_with("__mesh-east-west-"))
        .expect("east-west gateway proxy materialised");
    assert_eq!(
        proxy.listen_port,
        Some(15443),
        "proxy must bind east-west listen port"
    );
    assert!(
        proxy.passthrough,
        "east-west proxy is SNI passthrough (no TLS termination)"
    );
    assert_eq!(
        proxy.hosts,
        vec!["remote-svc.default.svc.cluster.local".to_string()],
        "SNI hosts copied onto the proxy.hosts list"
    );
    assert_eq!(proxy.backend_host, "10.0.0.42");
    assert_eq!(proxy.backend_port, 15443);
}

#[test]
fn east_west_gateway_materializes_local_service_proxies_for_sni_routing() {
    // Workloads + services in the mesh slice produce per-service
    // passthrough proxies so inbound cross-cluster traffic SNI-routes
    // to the right local workload. The SNI host is the service FQDN.
    let workload = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.0.0.5", "10.0.0.6"],
    );
    let service = service_for("reviews", DEFAULT_NAMESPACE, &[&workload]);
    let mesh = mesh_config_with(vec![workload], vec![service], Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &east_west_runtime()).expect("east-west prepared");

    // One proxy per service, materialised with the FQDN SNI host.
    let service_proxy = prepared
        .proxies
        .iter()
        .find(|p| {
            p.hosts
                .iter()
                .any(|h| h.contains("reviews.default.svc.cluster.local"))
        })
        .expect("east-west service proxy materialised");
    assert!(service_proxy.passthrough);
    assert_eq!(service_proxy.listen_port, Some(15443));

    // One upstream per service with the workload addresses as targets.
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id.contains("reviews"))
        .expect("east-west upstream materialised");
    assert!(
        upstream.targets.len() >= 2,
        "upstream must carry both workload addresses, got {:?}",
        upstream.targets.iter().map(|t| &t.host).collect::<Vec<_>>()
    );
}

#[test]
fn east_west_materialisation_is_a_no_op_on_other_topologies() {
    // Sidecar topology should NOT materialise the east-west gateway
    // even if the MultiClusterConfig is present — verifies the
    // topology-gated short-circuit.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-1".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![east_west_gateway("ghost-gw", vec!["a.example.com"])],
    });
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("sidecar prepared");
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.id.starts_with("__mesh-east-west-")),
        "east-west proxies must not be materialised under non-EW topology, got {:?}",
        prepared.proxies.iter().map(|p| &p.id).collect::<Vec<_>>()
    );
}

#[test]
fn east_west_gateway_skips_remote_gateway_from_other_namespace() {
    // An EastWestGateway whose namespace doesn't match the runtime
    // namespace must be ignored — operators rely on this for
    // namespace isolation across federated clusters.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    let mut foreign_gw = east_west_gateway("foreign", vec!["foreign.example.com"]);
    foreign_gw.namespace = "other-ns".to_string();
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-1".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![foreign_gw],
    });
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &east_west_runtime()).expect("prepared");
    assert!(
        prepared.proxies.iter().all(|p| !p.id.contains("foreign")),
        "foreign-namespace east-west gateway must be filtered out"
    );
}

// ── Egress gateway materialization ────────────────────────────────────────

fn egress_runtime() -> ferrum_edge::modes::mesh::MeshRuntimeConfig {
    let mut runtime = runtime_for_topology(MeshTopology::EgressGateway);
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    runtime
}

fn external_service_entry(name: &str, host: &str, port: u16) -> ServiceEntry {
    ServiceEntry {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        hosts: vec![host.to_string()],
        endpoints: Vec::new(),
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        export_to: vec![".".to_string()],
        workload_selector: None,
    }
}

#[test]
fn egress_gateway_materializes_proxy_for_external_service_entry() {
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries.push(external_service_entry(
        "payments",
        "payments.example.com",
        443,
    ));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("egress prepared");
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.hosts.iter().any(|h| h.contains("payments.example.com")))
        .expect("egress proxy materialised for payments.example.com");
    assert!(
        !proxy.passthrough,
        "egress proxy terminates HTTP, not passthrough"
    );
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id.contains("payments"))
        .expect("egress upstream materialised");
    assert!(
        !upstream.targets.is_empty(),
        "egress upstream must carry at least one target"
    );
}

#[test]
fn egress_gateway_skips_mesh_internal_service_entries() {
    // MESH_INTERNAL ServiceEntries are used for VM workload
    // registration, NOT egress targets. Materialisation must skip
    // them.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    let mut internal_entry = external_service_entry("vm-app", "vm.internal.example.com", 80);
    internal_entry.location = ServiceEntryLocation::MeshInternal;
    mesh.service_entries.push(internal_entry);
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("egress prepared");
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.hosts.iter().any(|h| h.contains("vm.internal"))),
        "MESH_INTERNAL ServiceEntry must not produce an egress proxy"
    );
}

#[test]
fn egress_gateway_skips_service_entries_without_export_scope_for_namespace() {
    // A ServiceEntry whose namespace doesn't match and whose export
    // doesn't include `*` or our namespace must not produce a proxy.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    let mut entry = external_service_entry("blocked", "blocked.example.com", 443);
    entry.namespace = "private-ns".to_string();
    entry.export_to = vec!["private-ns".to_string()];
    mesh.service_entries.push(entry);
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared =
        prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("egress prepared");
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.hosts.iter().any(|h| h.contains("blocked.example.com"))),
        "non-exported ServiceEntry must not produce an egress proxy"
    );
}

#[test]
fn egress_materialisation_is_a_no_op_on_other_topologies() {
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries
        .push(external_service_entry("ghost", "ghost.example.com", 443));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("sidecar prepared");
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.hosts.iter().any(|h| h.contains("ghost.example.com"))),
        "egress proxies must not be materialised under non-egress topology"
    );
}

#[test]
fn egress_gateway_materialises_distinct_proxies_per_external_entry() {
    // Multiple ServiceEntries → multiple proxies. Verify each gets a
    // distinct proxy/upstream.
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.service_entries
        .push(external_service_entry("a", "a.example.com", 443));
    mesh.service_entries
        .push(external_service_entry("b", "b.example.com", 443));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &egress_runtime()).expect("prepared");
    let a_proxy = prepared
        .proxies
        .iter()
        .find(|p| p.hosts.iter().any(|h| h.contains("a.example.com")))
        .expect("a proxy");
    let b_proxy = prepared
        .proxies
        .iter()
        .find(|p| p.hosts.iter().any(|h| h.contains("b.example.com")))
        .expect("b proxy");
    assert_ne!(a_proxy.id, b_proxy.id, "distinct proxy IDs per entry");
}

// ── MeshRuntimeState smoke ────────────────────────────────────────────────

#[test]
fn mesh_runtime_state_install_and_snapshot_round_trip() {
    let state = MeshRuntimeState::new();
    assert!(
        !state.has_first_slice(),
        "fresh state has no installed slice"
    );
    let slice = ferrum_edge::modes::mesh::slice::MeshSlice {
        version: "v-test".to_string(),
        node_id: "node-1".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        ..Default::default()
    };
    state.install_slice(slice);
    assert!(state.has_first_slice());
    let snapshot = state.snapshot();
    let slice_ref = snapshot.as_ref().as_ref().expect("snapshot has slice");
    assert_eq!(slice_ref.version, "v-test");
    assert_eq!(slice_ref.namespace, DEFAULT_NAMESPACE);
}
