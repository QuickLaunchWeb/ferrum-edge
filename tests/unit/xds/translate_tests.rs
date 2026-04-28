//! Tests that the translation pipeline produces well-formed Envoy
//! resources from a `MeshSlice`.

use ferrum_edge::config::mesh::{
    AppProtocol, MeshPolicy, MeshService, MeshSlice, MtlsMode, PeerAuthentication, PolicyAction,
    PolicyScope, PrincipalMatch, RequestMatch, Resolution, ServiceEntry, ServiceEntryLocation,
    ServicePort, TrustBundle, TrustBundleSet, Workload, WorkloadPort, WorkloadRef,
    WorkloadSelector,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::xds::snapshot::NodeIdentity;
use ferrum_edge::xds::translate::{cds, eds, lds, rds, sds};
use std::collections::HashMap;
use std::str::FromStr;

fn td() -> TrustDomain {
    TrustDomain::new("prod").unwrap()
}

fn workload(spiffe: &str, ns: &str) -> Workload {
    Workload {
        spiffe_id: SpiffeId::from_str(spiffe).unwrap(),
        selector: WorkloadSelector::default(),
        service_name: "test".into(),
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: None,
        }],
        trust_domain: td(),
        namespace: ns.into(),
    }
}

fn identity(node: &str, spiffe: Option<&str>) -> NodeIdentity {
    NodeIdentity {
        node_id: node.into(),
        namespace: "ferrum".into(),
        spiffe_id: spiffe.and_then(|s| SpiffeId::from_str(s).ok()),
    }
}

#[test]
fn cds_emits_eds_cluster_per_service_port() {
    let svc = MeshService {
        name: "billing".into(),
        namespace: "prod".into(),
        ports: vec![
            ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: Some("http".into()),
            },
            ServicePort {
                port: 9090,
                protocol: AppProtocol::Grpc,
                name: Some("grpc".into()),
            },
        ],
        workloads: vec![],
        protocol_overrides: HashMap::new(),
    };
    let slice = MeshSlice {
        workload: workload("spiffe://prod/ns/prod/sa/api", "prod"),
        services: vec![svc],
        policies: vec![],
        peer_authentications: vec![],
        service_entries: vec![],
        trust_bundles: None,
    };
    let id = identity("n1", Some("spiffe://prod/ns/prod/sa/api"));
    let clusters = cds::translate(Some(&slice), &id);
    assert!(clusters.contains_key("outbound|80||billing.prod.svc.cluster.local"));
    assert!(clusters.contains_key("outbound|9090||billing.prod.svc.cluster.local"));
}

#[test]
fn cds_emits_strict_dns_for_dns_service_entries() {
    let se = ServiceEntry {
        name: "external".into(),
        namespace: "prod".into(),
        hosts: vec!["api.example.com".into()],
        endpoints: vec![],
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port: 443,
            protocol: AppProtocol::Tls,
            name: None,
        }],
    };
    let slice = MeshSlice {
        workload: workload("spiffe://prod/ns/prod/sa/api", "prod"),
        services: vec![],
        policies: vec![],
        peer_authentications: vec![],
        service_entries: vec![se],
        trust_bundles: None,
    };
    let id = identity("n1", Some("spiffe://prod/ns/prod/sa/api"));
    let clusters = cds::translate(Some(&slice), &id);
    let cluster = clusters
        .values()
        .next()
        .expect("at least one cluster emitted");
    // STRICT_DNS = 1
    use envoy_types::pb::envoy::config::cluster::v3::cluster::ClusterDiscoveryType;
    if let Some(ClusterDiscoveryType::Type(t)) = &cluster.cluster_discovery_type {
        assert_eq!(*t, 1);
    } else {
        panic!("expected ClusterDiscoveryType::Type for STRICT_DNS");
    }
}

#[test]
fn rds_emits_route_per_service_port_and_inbound_table() {
    let svc = MeshService {
        name: "billing".into(),
        namespace: "prod".into(),
        ports: vec![ServicePort {
            port: 80,
            protocol: AppProtocol::Http,
            name: None,
        }],
        workloads: vec![],
        protocol_overrides: HashMap::new(),
    };
    let slice = MeshSlice {
        workload: workload("spiffe://prod/ns/prod/sa/api", "prod"),
        services: vec![svc],
        policies: vec![],
        peer_authentications: vec![],
        service_entries: vec![],
        trust_bundles: None,
    };
    let id = identity("n1", Some("spiffe://prod/ns/prod/sa/api"));
    let routes = rds::translate(Some(&slice), &id);
    assert!(routes.contains_key("inbound|http"));
    assert!(routes.contains_key("80"));
    let r80 = &routes["80"];
    assert_eq!(r80.virtual_hosts[0].routes.len(), 1);
}

#[test]
fn lds_emits_inbound_and_outbound_listeners() {
    let svc = MeshService {
        name: "billing".into(),
        namespace: "prod".into(),
        ports: vec![ServicePort {
            port: 80,
            protocol: AppProtocol::Http,
            name: None,
        }],
        workloads: vec![],
        protocol_overrides: HashMap::new(),
    };
    let slice = MeshSlice {
        workload: workload("spiffe://prod/ns/prod/sa/api", "prod"),
        services: vec![svc],
        policies: vec![],
        peer_authentications: vec![],
        service_entries: vec![],
        trust_bundles: None,
    };
    let id = identity("n1", Some("spiffe://prod/ns/prod/sa/api"));
    let listeners = lds::translate(Some(&slice), &id);
    assert!(listeners.contains_key("virtualInbound"));
    assert!(listeners.contains_key("virtualOutbound"));
}

#[test]
fn lds_strict_mtls_requires_client_certificate() {
    use prost::Message;
    let pa = PeerAuthentication {
        name: "strict".into(),
        namespace: "prod".into(),
        selector: None,
        mtls_mode: MtlsMode::Strict,
        port_overrides: HashMap::new(),
    };
    let slice = MeshSlice {
        workload: workload("spiffe://prod/ns/prod/sa/api", "prod"),
        services: vec![],
        policies: vec![],
        peer_authentications: vec![pa],
        service_entries: vec![],
        trust_bundles: None,
    };
    let id = identity("n1", Some("spiffe://prod/ns/prod/sa/api"));
    let listeners = lds::translate(Some(&slice), &id);
    let inbound = &listeners["virtualInbound"];
    let chain = &inbound.filter_chains[0];
    let ts = chain
        .transport_socket
        .as_ref()
        .expect("strict mode must wire TLS");
    use envoy_types::pb::envoy::config::core::v3::transport_socket::ConfigType;
    use envoy_types::pb::envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext;
    let ConfigType::TypedConfig(any) = ts.config_type.as_ref().unwrap();
    let downstream = DownstreamTlsContext::decode(any.value.as_slice()).unwrap();
    assert_eq!(
        downstream.require_client_certificate.map(|v| v.value),
        Some(true),
        "Strict mTLS must require client certs"
    );
}

#[test]
fn lds_disable_mtls_omits_transport_socket() {
    let pa = PeerAuthentication {
        name: "off".into(),
        namespace: "prod".into(),
        selector: None,
        mtls_mode: MtlsMode::Disable,
        port_overrides: HashMap::new(),
    };
    let slice = MeshSlice {
        workload: workload("spiffe://prod/ns/prod/sa/api", "prod"),
        services: vec![],
        policies: vec![],
        peer_authentications: vec![pa],
        service_entries: vec![],
        trust_bundles: None,
    };
    let id = identity("n1", Some("spiffe://prod/ns/prod/sa/api"));
    let listeners = lds::translate(Some(&slice), &id);
    let chain = &listeners["virtualInbound"].filter_chains[0];
    assert!(chain.transport_socket.is_none());
}

#[test]
fn eds_emits_cluster_load_assignment_per_service() {
    let svc = MeshService {
        name: "billing".into(),
        namespace: "prod".into(),
        ports: vec![ServicePort {
            port: 80,
            protocol: AppProtocol::Http,
            name: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: SpiffeId::from_str("spiffe://prod/ns/prod/sa/billing").unwrap(),
        }],
        protocol_overrides: HashMap::new(),
    };
    let slice = MeshSlice {
        workload: workload("spiffe://prod/ns/prod/sa/api", "prod"),
        services: vec![svc],
        policies: vec![],
        peer_authentications: vec![],
        service_entries: vec![],
        trust_bundles: None,
    };
    let id = identity("n1", Some("spiffe://prod/ns/prod/sa/api"));
    let endpoints = eds::translate(Some(&slice), &id);
    let key = "outbound|80||billing.prod.svc.cluster.local";
    let cla = endpoints
        .get(key)
        .expect("EDS must emit a ClusterLoadAssignment for the cluster");
    assert_eq!(cla.cluster_name, key);
    assert_eq!(cla.endpoints.len(), 1);
    assert_eq!(cla.endpoints[0].lb_endpoints.len(), 1);
}

#[test]
fn sds_emits_default_cert_and_validation_secrets() {
    let id = identity("n1", Some("spiffe://prod/ns/prod/sa/api"));
    let config = GatewayConfig {
        trust_bundles: Some(TrustBundleSet {
            local: TrustBundle {
                trust_domain: td(),
                x509_authorities: vec!["AAAA".into()],
                jwt_authorities: vec![],
                refresh_hint_seconds: None,
            },
            federated: vec![],
        }),
        ..Default::default()
    };
    let secrets = sds::translate(None, &id, &config);
    assert!(secrets.contains_key("default"));
    assert!(secrets.contains_key("ROOTCA"));
    let rootca = &secrets["ROOTCA"];
    use envoy_types::pb::envoy::extensions::transport_sockets::tls::v3::secret::Type;
    if let Some(Type::ValidationContext(ctx)) = rootca.r#type.as_ref() {
        let trusted = ctx.trusted_ca.as_ref().unwrap();
        use envoy_types::pb::envoy::config::core::v3::data_source::Specifier;
        if let Some(Specifier::InlineString(pem)) = &trusted.specifier {
            assert!(pem.contains("AAAA"));
            assert!(pem.contains("BEGIN CERTIFICATE"));
        } else {
            panic!("trusted_ca should be inline string");
        }
    } else {
        panic!("ROOTCA secret should be a ValidationContext");
    }
}

#[test]
fn unknown_workload_means_empty_translation() {
    // No slice => no resources.
    let id = identity("n1", Some("spiffe://prod/ns/prod/sa/api"));
    let listeners = lds::translate(None, &id);
    let routes = rds::translate(None, &id);
    let clusters = cds::translate(None, &id);
    let endpoints = eds::translate(None, &id);
    assert!(listeners.is_empty());
    assert!(routes.is_empty());
    assert!(clusters.is_empty());
    assert!(endpoints.is_empty());
}

#[test]
fn allow_policy_keeps_workload_in_from() {
    // Sanity check that Allow policies also reach the slice (caught by
    // the slice tests separately, but we want to make sure translation
    // tolerates them).
    let policy = MeshPolicy {
        name: "allow".into(),
        namespace: "prod".into(),
        scope: PolicyScope::Namespace {
            namespace: "prod".into(),
        },
        rules: vec![ferrum_edge::config::mesh::MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://prod/ns/prod/sa/*".into()),
                namespace_pattern: None,
                trust_domain: None,
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".into()],
                paths: vec!["/api/*".into()],
                hosts: vec![],
                headers: HashMap::new(),
                ports: vec![],
            }],
            when: vec![],
            action: PolicyAction::Allow,
        }],
    };
    let slice = MeshSlice {
        workload: workload("spiffe://prod/ns/prod/sa/api", "prod"),
        services: vec![],
        policies: vec![policy],
        peer_authentications: vec![],
        service_entries: vec![],
        trust_bundles: None,
    };
    let id = identity("n1", Some("spiffe://prod/ns/prod/sa/api"));
    let routes = rds::translate(Some(&slice), &id);
    // Inbound table is always emitted; outbound is empty when there
    // are no services. Smoke-check only.
    assert!(routes.contains_key("inbound|http"));
}
