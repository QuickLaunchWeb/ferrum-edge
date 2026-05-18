use std::collections::HashMap;

use chrono::Utc;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, MAX_TARGET_WEIGHT, Proxy, Upstream, UpstreamTarget,
};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshDestinationRule, MeshLoadBalancer, MeshOutlierDetection, MeshSimpleLb,
    MeshTrafficPolicy,
};
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};

fn runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        outbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        hbone_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        east_west_listen_port: 15443,
        egress_listen_addr: "0.0.0.0:15090".parse().expect("addr"),
        workload_spiffe_id: None,
        waypoint_name: None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        workload_labels: HashMap::new(),
        dns_enabled: false,
        dns_listen_addr: "127.0.0.1:15053".parse().expect("addr"),
        dns_upstream_addr: "127.0.0.53:53".parse().expect("addr"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: ferrum_edge::capture::CaptureMode::Explicit,
        outbound_traffic_policy: ferrum_edge::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
    }
}

fn upstream() -> Upstream {
    let now = Utc::now();
    Upstream {
        id: "reviews-u".to_string(),
        namespace: "default".to_string(),
        name: Some("reviews".to_string()),
        targets: vec![UpstreamTarget {
            host: "reviews.default.svc.cluster.local".to_string(),
            port: 8080,
            weight: MAX_TARGET_WEIGHT.min(1),
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

fn proxy() -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "reviews-p",
        "namespace": "default",
        "hosts": ["reviews.example.com"],
        "backend_host": "reviews.default.svc.cluster.local",
        "backend_port": 0,
        "backend_scheme": "http",
        "upstream_id": "reviews-u"
    }))
    .expect("proxy fixture")
}

#[test]
fn destination_rule_port_level_load_balancer_projects_to_upstream_override() {
    let mut port_level_settings = HashMap::new();
    port_level_settings.insert(
        8080,
        MeshTrafficPolicy {
            load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
            ..MeshTrafficPolicy::default()
        },
    );
    let mut config = GatewayConfig {
        upstreams: vec![upstream()],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings,
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");
    let port_override = prepared.upstreams[0]
        .port_overrides
        .get(&8080)
        .expect("port override projected");
    assert_eq!(port_override.algorithm, Some(LoadBalancerAlgorithm::Random));
}

#[test]
fn destination_rule_port_level_outlier_detection_projects_to_dispatch_override() {
    let mut port_level_settings = HashMap::new();
    port_level_settings.insert(
        8080,
        MeshTrafficPolicy {
            load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
            outlier_detection: Some(MeshOutlierDetection {
                consecutive_errors: Some(5),
                interval_seconds: Some(11),
                base_ejection_seconds: Some(17),
                max_ejection_percent: Some(50),
            }),
            ..MeshTrafficPolicy::default()
        },
    );
    let mut config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![upstream()],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings,
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");
    let upstream_override = prepared.upstreams[0]
        .port_overrides
        .get(&8080)
        .expect("upstream port override projected");
    assert_eq!(
        upstream_override.algorithm,
        Some(LoadBalancerAlgorithm::Random)
    );
    let upstream_passive = upstream_override
        .passive_health_check
        .as_ref()
        .expect("upstream passive health projected");
    assert_eq!(upstream_passive.unhealthy_threshold, 5);
    assert_eq!(upstream_passive.unhealthy_window_seconds, 11);
    assert_eq!(upstream_passive.healthy_after_seconds, 17);
    assert_eq!(upstream_passive.max_ejection_percent, Some(50));

    let dispatch_override = prepared.proxies[0]
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&8080))
        .expect("proxy dispatch port override projected");
    assert_eq!(
        dispatch_override.algorithm,
        Some(LoadBalancerAlgorithm::Random)
    );
    let dispatch_passive = dispatch_override
        .passive_health_check
        .as_ref()
        .expect("dispatch passive health projected");
    assert_eq!(dispatch_passive.unhealthy_threshold, 5);
    assert_eq!(dispatch_passive.unhealthy_window_seconds, 11);
    assert_eq!(dispatch_passive.healthy_after_seconds, 17);
    assert_eq!(dispatch_passive.max_ejection_percent, Some(50));
}
