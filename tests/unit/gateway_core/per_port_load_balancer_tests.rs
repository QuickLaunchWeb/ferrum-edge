use std::collections::HashMap;

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{
    GatewayConfig, HealthCheckConfig, LoadBalancerAlgorithm, PassiveHealthCheck, Proxy,
    SubsetDefinition, Upstream, UpstreamPortOverride, UpstreamTarget,
};
use ferrum_edge::health_check::HealthChecker;
use ferrum_edge::load_balancer::{
    HashOnStrategy, HealthContext, LoadBalancerCache, target_host_port_key,
};

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
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn initial_dispatch_port_override_requires_all_targets_on_overridden_port() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(8080, UpstreamPortOverride::default());

    let mixed = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 9090)],
        port_overrides.clone(),
    );
    let mixed_config = GatewayConfig {
        upstreams: vec![mixed],
        ..GatewayConfig::default()
    };
    let mixed_cache = LoadBalancerCache::new(&mixed_config);
    let mixed_snapshot = mixed_cache.load();

    assert_eq!(
        LoadBalancerCache::initial_dispatch_port_override_from(&mixed_snapshot, "u1"),
        0,
        "mixed-port upstreams must wait until a concrete target is selected"
    );

    let uniform = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080)],
        port_overrides,
    );
    let uniform_config = GatewayConfig {
        upstreams: vec![uniform],
        ..GatewayConfig::default()
    };
    let uniform_cache = LoadBalancerCache::new(&uniform_config);
    let uniform_snapshot = uniform_cache.load();

    assert_eq!(
        LoadBalancerCache::initial_dispatch_port_override_from(&uniform_snapshot, "u1"),
        8080,
        "single-port upstreams can use the port override before selection"
    );
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

#[test]
fn port_subset_vec_fallback_filters_intersection_for_large_upstreams() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let targets: Vec<UpstreamTarget> = (0..129)
        .map(|idx| {
            let port = if idx % 3 == 0 { 8080 } else { 9090 };
            let version = if idx % 5 == 0 { "v1" } else { "v2" };
            tagged_target(&format!("h{idx}"), port, &[("version", version)])
        })
        .collect();
    let mut upstream =
        upstream_with_overrides(LoadBalancerAlgorithm::RoundRobin, targets, port_overrides);
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

    let selection = LoadBalancerCache::select_target_for_port_subset_from(
        &snapshot, "u1", "key", 8080, "v1", None,
    )
    .expect("large-target port subset selection");
    assert_eq!(selection.target.port, 8080);
    assert_eq!(
        selection.target.tags.get("version").map(String::as_str),
        Some("v1")
    );

    let retry = LoadBalancerCache::select_next_target_for_port_subset_from(
        &snapshot,
        "u1",
        "retry",
        8080,
        "v1",
        selection.target.as_ref(),
        None,
    )
    .expect("large-target port subset retry selection");
    assert_eq!(retry.port, 8080);
    assert_eq!(retry.tags.get("version").map(String::as_str), Some("v1"));
    assert_ne!(
        retry.host, selection.target.host,
        "retry should exclude the original target while staying in the port/subset intersection"
    );
}

#[test]
fn port_retry_selection_does_not_escape_selected_port() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
            ..Default::default()
        },
    );
    let targets = vec![target("a", 8080), target("b", 8080), target("c", 9090)];
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        targets.clone(),
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert("u1::a:8080".to_string(), 0);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection = LoadBalancerCache::select_next_target_for_port_from(
        &snapshot,
        "u1",
        "key",
        8080,
        &targets[1],
        Some(&health),
    )
    .expect("port retry selection");

    assert_eq!(
        selection.port, 8080,
        "retry selection for a port override must not escape to another destination port"
    );
    assert_eq!(selection.host, "a");
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
    assert!(
        port_sequence
            .iter()
            .all(|host| matches!(host.as_str(), "a" | "b")),
        "port-specific random selection must stay on port 8080 targets: {port_sequence:?}"
    );

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
fn algorithm_port_override_without_hash_on_clears_upstream_hash_strategy() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::Random),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::ConsistentHashing,
        vec![target("a", 8080), target("b", 8080), target("c", 9090)],
        port_overrides,
    );
    upstream.hash_on = Some("cookie:srv".to_string());
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_from(&snapshot, "u1"),
        HashOnStrategy::Cookie("srv".to_string())
    );
    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_port_from(&snapshot, "u1", 8080),
        HashOnStrategy::Ip,
        "switching a port to a non-hash algorithm should clear upstream sticky hash state"
    );
    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_port_from(&snapshot, "u1", 9090),
        HashOnStrategy::Cookie("srv".to_string()),
        "ports without an override should keep the upstream strategy"
    );
}

#[test]
fn non_algorithm_port_override_does_not_inherit_upstream_hash_strategy() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            connect_timeout_ms: Some(250),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::ConsistentHashing,
        vec![target("a", 8080), target("b", 8080), target("c", 9090)],
        port_overrides,
    );
    upstream.hash_on = Some("header:x-user-id".to_string());
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_port_from(&snapshot, "u1", 8080),
        HashOnStrategy::Ip,
        "non-LB port overrides should not inherit upstream sticky hash state"
    );

    let port_sequence: Vec<String> = (0..2)
        .map(|_| {
            LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "same-key", 8080, None)
                .expect("port selection")
                .target
                .host
                .clone()
        })
        .collect();
    assert_eq!(
        port_sequence,
        vec!["a", "b"],
        "non-LB port overrides should use their own default round-robin lane"
    );
}

#[test]
fn consistent_hash_port_override_without_hash_on_preserves_upstream_hash_strategy() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            algorithm: Some(LoadBalancerAlgorithm::ConsistentHashing),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 8080), target("c", 9090)],
        port_overrides,
    );
    upstream.hash_on = Some("cookie:srv".to_string());
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::get_hash_on_strategy_for_port_from(&snapshot, "u1", 8080),
        HashOnStrategy::Cookie("srv".to_string()),
        "a consistent-hash port override should inherit the upstream hash key when none is set"
    );
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

#[test]
fn port_passive_ejection_cap_uses_only_targets_on_selected_port() {
    let port_passive = PassiveHealthCheck {
        unhealthy_threshold: 1,
        max_ejection_percent: Some(50),
        ..PassiveHealthCheck::default()
    };
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(port_passive.clone()),
            ..Default::default()
        },
    );
    let targets = vec![
        target("a", 8080),
        target("b", 8080),
        target("c", 9090),
        target("d", 9090),
    ];
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        targets.clone(),
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let checker = HealthChecker::new();
    checker.report_response("p1", &targets[0], 500, false, Some(&port_passive));
    checker.report_response("p1", &targets[1], 500, false, Some(&port_passive));
    let proxy_state = checker
        .passive_health
        .get("p1")
        .expect("passive health state created")
        .clone();
    proxy_state
        .unhealthy
        .insert(target_host_port_key(&targets[0]), 100);
    proxy_state
        .unhealthy
        .insert(target_host_port_key(&targets[1]), 200);

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: Some(proxy_state),
        max_ejection_percent: Some(50),
    };

    let selection =
        LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "key", 8080, Some(&health))
            .expect("port selection");

    assert!(
        !selection.is_fallback,
        "one of two passively ejected port targets should be re-admitted under a 50% port cap"
    );
    assert_eq!(selection.target.host, "a");
}

#[test]
fn port_passive_ejection_cap_uses_only_targets_on_selected_port_vec_path() {
    let port_passive = PassiveHealthCheck {
        unhealthy_threshold: 1,
        max_ejection_percent: Some(50),
        ..PassiveHealthCheck::default()
    };
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(port_passive.clone()),
            ..Default::default()
        },
    );
    let mut targets = vec![target("a", 8080), target("b", 8080)];
    targets.extend((0..128).map(|idx| target(&format!("other-{idx}"), 9090)));
    let upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        targets.clone(),
        port_overrides,
    );
    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    let checker = HealthChecker::new();
    checker.report_response("p1", &targets[0], 500, false, Some(&port_passive));
    checker.report_response("p1", &targets[1], 500, false, Some(&port_passive));
    let proxy_state = checker
        .passive_health
        .get("p1")
        .expect("passive health state created")
        .clone();
    proxy_state
        .unhealthy
        .insert(target_host_port_key(&targets[0]), 100);
    proxy_state
        .unhealthy
        .insert(target_host_port_key(&targets[1]), 200);

    let active_unhealthy: DashMap<String, u64> = DashMap::new();
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: Some(proxy_state),
        max_ejection_percent: Some(50),
    };

    let selection =
        LoadBalancerCache::select_target_for_port_from(&snapshot, "u1", "key", 8080, Some(&health))
            .expect("port selection");

    assert!(
        !selection.is_fallback,
        "Vec fallback should also apply the ejection cap to the selected port's target set"
    );
    assert_eq!(selection.target.host, "a");
}

#[test]
fn port_passive_override_without_max_ejection_does_not_inherit_upstream_cap() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        8080,
        UpstreamPortOverride {
            passive_health_check: Some(PassiveHealthCheck {
                unhealthy_threshold: 1,
                max_ejection_percent: None,
                ..PassiveHealthCheck::default()
            }),
            ..Default::default()
        },
    );
    let mut upstream = upstream_with_overrides(
        LoadBalancerAlgorithm::RoundRobin,
        vec![target("a", 8080), target("b", 9090)],
        port_overrides,
    );
    upstream.health_checks = Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            max_ejection_percent: Some(25),
            ..PassiveHealthCheck::default()
        }),
    });
    let mut config = GatewayConfig {
        proxies: vec![proxy_for_upstream()],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_port_overrides();
    let cache = LoadBalancerCache::new(&config);
    let snapshot = cache.load();

    assert_eq!(
        LoadBalancerCache::max_ejection_percent_for_port_from(
            &snapshot,
            "u1",
            &config.proxies[0],
            8080,
        ),
        None,
        "a port-level passive-health override owns the port cap even when it omits max_ejection_percent"
    );
    assert_eq!(
        LoadBalancerCache::max_ejection_percent_for_port_from(
            &snapshot,
            "u1",
            &config.proxies[0],
            9090,
        ),
        Some(25),
        "ports without a passive override should still inherit the upstream cap"
    );
}
