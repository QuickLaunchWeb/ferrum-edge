use std::collections::HashMap;

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{
    GatewayConfig, HealthCheckConfig, LoadBalancerAlgorithm, PassiveHealthCheck, Proxy,
    SubsetDefinition, Upstream, UpstreamPortOverride, UpstreamTarget,
};
use ferrum_edge::health_check::HealthChecker;
use ferrum_edge::load_balancer::{HealthContext, LoadBalancerCache};

fn target(host: &str, port: u16) -> UpstreamTarget {
    weighted_target(host, port, 1)
}

fn weighted_target(host: &str, port: u16, weight: u32) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        weight,
        tags: HashMap::new(),
        path: None,
    }
}

fn tagged_target(host: &str, port: u16, tags: &[(&str, &str)]) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        weight: 1,
        tags: tags
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect(),
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

#[test]
fn port_wrr_zero_weight_fallback_uses_port_counter() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::WeightedRoundRobin),
            ..Default::default()
        },
    );
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![
            weighted_target("a", 8080, 0),
            weighted_target("b", 8080, 0),
            weighted_target("c", 8080, 0),
        ],
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    for _ in 0..2 {
        LoadBalancerCache::select_target_from(&snapshot, "u1", "parent", None)
            .expect("parent selection");
    }

    let port_sequence: Vec<String> = (0..2)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "port", 8080, None)
                .expect("port selection")
                .target
                .host
                .clone()
        })
        .collect();

    assert_eq!(port_sequence, vec!["a", "b"]);
}

#[test]
fn port_least_latency_warmup_fallback_uses_port_counter() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::LeastLatency),
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

    for _ in 0..2 {
        LoadBalancerCache::select_target_from(&snapshot, "u1", "parent", None)
            .expect("parent selection");
    }

    let port_sequence: Vec<String> = (0..2)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "port", 8080, None)
                .expect("port selection")
                .target
                .host
                .clone()
        })
        .collect();

    assert_eq!(port_sequence, vec!["a", "b"]);
}

#[test]
fn port_wrr_vec_zero_weight_fallback_uses_port_counter() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::WeightedRoundRobin),
            ..Default::default()
        },
    );
    let targets: Vec<UpstreamTarget> = (0..129)
        .map(|idx| weighted_target(&format!("h{idx}"), 8080, 0))
        .collect();
    let upstream =
        upstream_with_overrides(LoadBalancerAlgorithm::RoundRobin, targets, port_overrides);
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    LoadBalancerCache::select_target_from(&snapshot, "u1", "parent", None)
        .expect("parent selection");
    let selected =
        LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "port", 8080, None)
            .expect("port selection");

    assert_eq!(selected.target.host, "h0");
}

#[test]
fn port_subset_fully_unhealthy_intersection_returns_none() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![
            tagged_target("a", 8080, &[("version", "v1")]),
            tagged_target("b", 8080, &[("version", "v1")]),
            tagged_target("c", 9090, &[("version", "v1")]),
        ],
        port_overrides,
    );
    upstream.subsets = Some(vec![SubsetDefinition {
        name: "v1".to_string(),
        labels: HashMap::from([("version".to_string(), "v1".to_string())]),
        traffic_policy: None,
    }]);
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert("u1::a:8080".to_string(), 0);
    active_unhealthy.insert("u1::b:8080".to_string(), 0);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection = LoadBalancerCache::select_target_for_port_subset_from(
        &snapshot,
        "u1",
        "key",
        8080,
        "v1",
        Some(&health),
    );

    assert!(
        selection.is_none(),
        "retry must not escape to healthy subset targets outside the selected port"
    );
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
