use std::collections::HashMap;

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{GatewayConfig, LoadBalancerAlgorithm, Upstream, UpstreamTarget};
use ferrum_edge::load_balancer::{HealthContext, LoadBalancerCache, target_key};

fn target(host: &str, locality: Option<&str>) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port: 8080,
        weight: 1,
        tags: HashMap::new(),
        locality: locality.map(str::to_string),
        path: None,
    }
}

fn upstream(source_locality: &str, targets: Vec<UpstreamTarget>) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: "u1".to_string(),
        name: Some("u1".to_string()),
        namespace: "ferrum".to_string(),
        targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: Some(source_locality.to_string()),
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

fn config(upstream: Upstream) -> GatewayConfig {
    GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    }
}

#[test]
fn locality_priority_prefers_exact_tier() {
    let upstream = upstream(
        "us-west/us-west-1/a",
        vec![
            target("exact.local", Some("us-west/us-west-1/a")),
            target("same-zone.local", Some("us-west/us-west-1/b")),
            target("same-region.local", Some("us-west/us-west-2/a")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(upstream));
    let snapshot = cache.load();

    for i in 0..8 {
        let selection =
            LoadBalancerCache::select_target_from(&snapshot, "u1", &format!("ctx-{i}"), None)
                .expect("target selected");
        assert_eq!(selection.target.host, "exact.local");
        assert!(!selection.is_fallback);
    }
}

#[test]
fn locality_priority_falls_back_to_zone_when_exact_unhealthy() {
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let upstream = upstream(
        "us-west/us-west-1/a",
        vec![
            exact.clone(),
            target("same-zone.local", Some("us-west/us-west-1/b")),
            target("same-region.local", Some("us-west/us-west-2/a")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(upstream));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("u1", &exact), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection = LoadBalancerCache::select_target_from(&snapshot, "u1", "ctx", Some(&health))
        .expect("target selected");

    assert_eq!(selection.target.host, "same-zone.local");
    assert!(!selection.is_fallback);
}

#[test]
fn locality_priority_falls_back_to_region_when_zone_unavailable() {
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let zone = target("same-zone.local", Some("us-west/us-west-1/b"));
    let upstream = upstream(
        "us-west/us-west-1/a",
        vec![
            exact.clone(),
            zone.clone(),
            target("same-region.local", Some("us-west/us-west-2/a")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(upstream));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("u1", &exact), 1);
    active_unhealthy.insert(target_key("u1", &zone), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection = LoadBalancerCache::select_target_from(&snapshot, "u1", "ctx", Some(&health))
        .expect("target selected");

    assert_eq!(selection.target.host, "same-region.local");
    assert!(!selection.is_fallback);
}
