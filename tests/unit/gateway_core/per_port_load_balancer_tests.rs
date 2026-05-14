use std::collections::HashMap;

use chrono::Utc;
use ferrum_edge::config::types::{
    GatewayConfig, HealthCheckConfig, LoadBalancerAlgorithm, PassiveHealthCheck, Proxy, Upstream,
    UpstreamPortOverride, UpstreamTarget,
};
use ferrum_edge::health_check::HealthChecker;
use ferrum_edge::load_balancer::LoadBalancerCache;

fn target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        weight: 1,
        tags: HashMap::new(),
        path: None,
    }
}

fn upstream_with_overrides(
    algorithm: LoadBalancerAlgorithm,
    targets: Vec<UpstreamTarget>,
    port_overrides: HashMap<u16, UpstreamPortOverride>,
) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: "u1".to_string(),
        namespace: "ferrum".to_string(),
        name: Some("u1".to_string()),
        targets,
        algorithm,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

fn proxy_for_upstream() -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "p1",
        "backend_host": "svc.local",
        "backend_port": 8080,
        "upstream_id": "u1",
    }))
    .expect("test proxy should deserialize")
}

#[test]
fn upstream_round_robin_port_override_random_uses_port_specific_algorithm() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::Random),
            ..Default::default()
        },
    );
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080), target("c", 8080)],
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let port_sequence: Vec<String> = (0..3)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "same-key", 8080, None)
                .expect("port override should select")
                .target
                .host
                .clone()
        })
        .collect();
    assert_eq!(port_sequence, vec!["a", "b", "b"]);

    let parent_sequence: Vec<String> = (0..3)
        .map(|_| {
            LoadBalancerCache::select_target_from(&snapshot, "u1", "same-key", None)
                .expect("parent LB should select")
                .target
                .host
                .clone()
        })
        .collect();
    assert_eq!(parent_sequence, vec!["a", "b", "c"]);
}

#[test]
fn per_port_passive_health_threshold_differs_from_upstream_level() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                ..PassiveHealthCheck::default()
            }),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080)],
        port_overrides,
    );
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            unhealthy_threshold: 3,
            ..PassiveHealthCheck::default()
        }),
    });
    let mut config = GatewayConfig {
        proxies: vec![proxy_for_upstream()],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_port_overrides();
    let port_passive = config.proxies[0]
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&8080))
        .and_then(|override_config| override_config.passive_health_check.as_ref())
        .expect("port passive health projected");
    assert_eq!(port_passive.unhealthy_threshold, 1);
    assert_eq!(
        config.upstreams[0]
            .health_checks
            .as_ref()
            .and_then(|hc| hc.passive.as_ref())
            .map(|passive| passive.unhealthy_threshold),
        Some(3)
    );

    let checker = HealthChecker::default();
    let selected = target("a", 8080);
    checker.report_response("p1", &selected, 500, false, Some(port_passive));
    let proxy_state = checker
        .passive_health
        .get("p1")
        .expect("passive health state created");
    assert!(
        proxy_state.unhealthy.contains_key("a:8080"),
        "port-level threshold 1 should eject after one matching failure"
    );
}
