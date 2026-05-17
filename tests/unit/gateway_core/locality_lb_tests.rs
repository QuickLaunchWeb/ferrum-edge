use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::Utc;
use dashmap::DashMap;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, LocalityDistribute, LocalityFailover, SubsetDefinition,
    Upstream, UpstreamLocalityLbSetting, UpstreamPortOverride, UpstreamTarget,
};
use ferrum_edge::load_balancer::{HealthContext, LoadBalancerCache, target_key};

fn target(host: &str, locality: Option<&str>) -> UpstreamTarget {
    target_on_port(host, 8080, locality)
}

fn target_on_port(host: &str, port: u16, locality: Option<&str>) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        weight: 1,
        tags: HashMap::new(),
        locality: locality.map(str::to_string),
        path: None,
    }
}

fn tagged_target(
    host: &str,
    port: u16,
    locality: Option<&str>,
    tag: (&str, &str),
) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        weight: 1,
        tags: HashMap::from([(tag.0.to_string(), tag.1.to_string())]),
        locality: locality.map(str::to_string),
        path: None,
    }
}

fn make_upstream(
    id: &str,
    algorithm: LoadBalancerAlgorithm,
    source_locality: Option<&str>,
    targets: Vec<UpstreamTarget>,
) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: id.to_string(),
        name: Some(id.to_string()),
        namespace: "ferrum".to_string(),
        targets,
        algorithm,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: source_locality.map(str::to_string),
        locality_lb_setting: None,
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

fn upstream(source_locality: &str, targets: Vec<UpstreamTarget>) -> Upstream {
    make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some(source_locality),
        targets,
    )
}

fn config(upstream: Upstream) -> GatewayConfig {
    GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    }
}

fn no_health() -> Option<&'static HealthContext<'static>> {
    None
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
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "u1",
            &format!("ctx-{i}"),
            no_health(),
        )
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

#[test]
fn locality_priority_falls_back_to_any_when_all_preferred_tiers_unhealthy() {
    // exact, zone, and region are all unhealthy; only the rank-3 "other"
    // target remains. Selection must still succeed — the locality filter
    // must not strand the upstream when no preferred-tier target survives.
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let zone = target("same-zone.local", Some("us-west/us-west-1/b"));
    let region = target("same-region.local", Some("us-west/us-west-2/a"));
    let upstream = upstream(
        "us-west/us-west-1/a",
        vec![
            exact.clone(),
            zone.clone(),
            region.clone(),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(upstream));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("u1", &exact), 1);
    active_unhealthy.insert(target_key("u1", &zone), 1);
    active_unhealthy.insert(target_key("u1", &region), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection = LoadBalancerCache::select_target_from(&snapshot, "u1", "ctx", Some(&health))
        .expect("target selected");
    assert_eq!(selection.target.host, "other.local");
    assert!(!selection.is_fallback);
}

#[test]
fn locality_priority_targets_without_locality_treated_as_no_preference() {
    // Mix targets that have locality with one that has none. With a healthy
    // exact-tier target available, the unannotated target is rank-3 and
    // must not be chosen. Removing the exact target lets the rank-3 target
    // share the residual pool (the function returns the original candidates
    // when no rank-0/1/2 candidates remain).
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let unannotated = target("unannotated.local", None);
    let upstream = upstream(
        "us-west/us-west-1/a",
        vec![exact.clone(), unannotated.clone()],
    );
    let cache = LoadBalancerCache::new(&config(upstream));
    let snapshot = cache.load();

    for i in 0..8 {
        let selection =
            LoadBalancerCache::select_target_from(&snapshot, "u1", &format!("a-{i}"), no_health())
                .expect("target selected");
        assert_eq!(
            selection.target.host, "exact.local",
            "exact-tier target must always win when healthy"
        );
    }

    // Knock the exact target out — unannotated should now be reachable as
    // the residual fallback (no rank 0/1/2 candidates left).
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("u1", &exact), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };
    let selection = LoadBalancerCache::select_target_from(&snapshot, "u1", "fb", Some(&health))
        .expect("target selected");
    assert_eq!(selection.target.host, "unannotated.local");
}

#[test]
fn locality_priority_applies_inside_subset_selection() {
    let exact = tagged_target("exact.local", 8080, Some("us-west/us-west-1/a"), ("v", "1"));
    let region = tagged_target(
        "same-region.local",
        8080,
        Some("us-west/us-west-2/a"),
        ("v", "1"),
    );
    let other = tagged_target(
        "other.local",
        8080,
        Some("eu-central/eu-central-1/a"),
        ("v", "1"),
    );
    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some("us-west/us-west-1/a"),
        vec![exact.clone(), region, other],
    );
    up.subsets = Some(vec![SubsetDefinition {
        name: "v1".into(),
        labels: HashMap::from([("v".to_string(), "1".to_string())]),
        traffic_policy: None,
    }]);

    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..6 {
        let selection = LoadBalancerCache::select_target_subset_from(
            &snapshot,
            "u1",
            &format!("k-{i}"),
            "v1",
            no_health(),
        )
        .expect("subset selection");
        assert_eq!(selection.target.host, "exact.local");
    }
}

#[test]
fn locality_priority_applies_inside_port_override_selection() {
    let exact = target_on_port("exact.local", 8080, Some("us-west/us-west-1/a"));
    let region = target_on_port("region.local", 8080, Some("us-west/us-west-2/a"));
    let mut port_overrides = HashMap::new();
    port_overrides.insert(8080, UpstreamPortOverride::default());

    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some("us-west/us-west-1/a"),
        vec![exact, region],
    );
    up.port_overrides = port_overrides;

    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..6 {
        let selection = LoadBalancerCache::select_target_for_port_from(
            &snapshot,
            "u1",
            &format!("p-{i}"),
            8080,
            no_health(),
        )
        .expect("port selection");
        assert_eq!(selection.target.host, "exact.local");
    }
}

#[test]
fn locality_priority_applies_to_port_subset_selection() {
    let exact = tagged_target("exact.local", 8080, Some("us-west/us-west-1/a"), ("v", "1"));
    let region = tagged_target(
        "region.local",
        8080,
        Some("us-west/us-west-2/a"),
        ("v", "1"),
    );
    let mut port_overrides = HashMap::new();
    port_overrides.insert(8080, UpstreamPortOverride::default());

    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some("us-west/us-west-1/a"),
        vec![exact.clone(), region],
    );
    up.subsets = Some(vec![SubsetDefinition {
        name: "v1".into(),
        labels: HashMap::from([("v".to_string(), "1".to_string())]),
        traffic_policy: None,
    }]);
    up.port_overrides = port_overrides;

    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..6 {
        let selection = LoadBalancerCache::select_target_for_port_subset_from(
            &snapshot,
            "u1",
            &format!("ps-{i}"),
            8080,
            "v1",
            no_health(),
        )
        .expect("port+subset selection");
        assert_eq!(selection.target.host, "exact.local");
    }
}

#[test]
fn locality_priority_applies_when_excluding_a_target() {
    // First select picks exact; retry path excludes exact and must fall
    // through to the next-best tier (zone), not jump to a rank-3 target.
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let zone = target("zone.local", Some("us-west/us-west-1/b"));
    let other = target("other.local", Some("eu-central/eu-central-1/a"));
    let up = upstream(
        "us-west/us-west-1/a",
        vec![exact.clone(), zone.clone(), other.clone()],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let next =
        LoadBalancerCache::select_next_target_from(&snapshot, "u1", "rk", &exact, no_health())
            .expect("retry selected");
    assert_eq!(
        next.host, "zone.local",
        "after excluding exact, locality preference must still skip the rank-3 target"
    );
}

#[test]
fn locality_priority_works_with_consistent_hashing() {
    // Same hash key must produce a stable selection inside the preferred
    // tier. Two healthy exact-tier targets — the hash-bound choice must be
    // reproducible across calls and never escape into the rank-2 tier.
    let exact_a = target("ex-a.local", Some("us-west/us-west-1/a"));
    let exact_b = target("ex-b.local", Some("us-west/us-west-1/a"));
    let region = target("region.local", Some("us-west/us-west-2/a"));
    let up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::ConsistentHashing,
        Some("us-west/us-west-1/a"),
        vec![exact_a, exact_b, region],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let preferred: HashSet<&str> = ["ex-a.local", "ex-b.local"].into_iter().collect();
    let first = LoadBalancerCache::select_target_from(&snapshot, "u1", "hash-key", no_health())
        .expect("hash selection");
    assert!(preferred.contains(first.target.host.as_str()));
    for _ in 0..5 {
        let again = LoadBalancerCache::select_target_from(&snapshot, "u1", "hash-key", no_health())
            .expect("hash selection");
        assert_eq!(
            again.target.host, first.target.host,
            "consistent hash must return the same target for the same key"
        );
    }
}

#[test]
fn locality_priority_vec_fallback_path_picks_preferred_tier_above_128_targets() {
    // Force the >128 Vec fallback path: 160 targets, half exact-tier, half
    // rank-3. After 32 rounds, every selection must come from the exact
    // tier (host name starts with "exact-").
    let mut targets = Vec::with_capacity(160);
    for i in 0..80 {
        targets.push(target(
            &format!("exact-{i}.local"),
            Some("us-west/us-west-1/a"),
        ));
    }
    for i in 0..80 {
        targets.push(target(
            &format!("other-{i}.local"),
            Some("eu-central/eu-central-1/a"),
        ));
    }
    let up = upstream("us-west/us-west-1/a", targets);
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..32 {
        let selection =
            LoadBalancerCache::select_target_from(&snapshot, "u1", &format!("k-{i}"), no_health())
                .expect("vec-fallback selection");
        assert!(
            selection.target.host.starts_with("exact-"),
            "Vec fallback selected non-preferred target {}",
            selection.target.host
        );
        assert!(!selection.is_fallback);
    }
}

#[test]
fn locality_priority_bitset_and_vec_paths_agree_on_preferred_set() {
    // Run the same logical upstream through both representations: a small
    // upstream (n=4, bitset path) and a large one synthesised from the same
    // template (n=200, Vec path). For round-robin selection on a healthy
    // set, every chosen target must come from the exact tier in both
    // representations.
    let small = upstream(
        "us-west/us-west-1/a",
        vec![
            target("ex-1.local", Some("us-west/us-west-1/a")),
            target("ex-2.local", Some("us-west/us-west-1/a")),
            target("zone.local", Some("us-west/us-west-1/b")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let mut big_targets = Vec::with_capacity(200);
    for i in 0..50 {
        big_targets.push(target(
            &format!("ex-{i}.local"),
            Some("us-west/us-west-1/a"),
        ));
    }
    for i in 0..50 {
        big_targets.push(target(
            &format!("zone-{i}.local"),
            Some("us-west/us-west-1/b"),
        ));
    }
    for i in 0..100 {
        big_targets.push(target(
            &format!("other-{i}.local"),
            Some("eu-central/eu-central-1/a"),
        ));
    }
    let big = upstream("us-west/us-west-1/a", big_targets);

    let small_cache = LoadBalancerCache::new(&config(small));
    let big_cache = LoadBalancerCache::new(&config(big));
    let small_snapshot = small_cache.load();
    let big_snapshot = big_cache.load();

    for i in 0..50 {
        let small_sel = LoadBalancerCache::select_target_from(
            &small_snapshot,
            "u1",
            &format!("p-{i}"),
            no_health(),
        )
        .expect("bitset selection");
        let big_sel = LoadBalancerCache::select_target_from(
            &big_snapshot,
            "u1",
            &format!("p-{i}"),
            no_health(),
        )
        .expect("vec selection");
        assert!(
            small_sel.target.host.starts_with("ex"),
            "bitset path selected non-preferred target: {}",
            small_sel.target.host
        );
        assert!(
            big_sel.target.host.starts_with("ex-"),
            "vec path selected non-preferred target: {}",
            big_sel.target.host
        );
    }
}

#[test]
fn locality_priority_disabled_when_source_locality_absent() {
    // No source locality means every target is rank-3 (no preference) and
    // round-robin distributes evenly across all healthy targets.
    let up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        None,
        vec![
            target("a.local", Some("us-west/us-west-1/a")),
            target("b.local", Some("us-west/us-west-1/b")),
            target("c.local", Some("eu-central/eu-central-1/a")),
        ],
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let mut seen: HashSet<String> = HashSet::new();
    for i in 0..30 {
        let selection =
            LoadBalancerCache::select_target_from(&snapshot, "u1", &format!("k-{i}"), no_health())
                .expect("selected");
        seen.insert(selection.target.host.clone());
    }
    assert_eq!(
        seen.len(),
        3,
        "without source locality, round-robin must visit every target — saw {:?}",
        seen
    );
}

// ── localityLbSetting.distribute ──────────────────────────────────────────

fn upstream_with_locality_lb(
    source_locality: &str,
    targets: Vec<UpstreamTarget>,
    setting: UpstreamLocalityLbSetting,
) -> Upstream {
    let mut up = make_upstream(
        "u1",
        LoadBalancerAlgorithm::RoundRobin,
        Some(source_locality),
        targets,
    );
    up.locality_lb_setting = Some(setting);
    up
}

#[test]
fn locality_distribute_overrides_priority_tier_with_weights() {
    // Source is `us-west/us-west-1/a`; distribute sends 80% to `us-west`
    // and 20% to `us-east`. Even though the exact-tier target is healthy,
    // distribute MUST override the priority preference (Istio semantics —
    // distribute and priority are mutually exclusive).
    let mut to = BTreeMap::new();
    to.insert("us-west".to_string(), 80);
    to.insert("us-east".to_string(), 20);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west-a.local", Some("us-west/us-west-1/a")),
            target("west-b.local", Some("us-west/us-west-2/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let mut by_target: HashMap<String, u32> = HashMap::new();
    for i in 0..2000 {
        let selection =
            LoadBalancerCache::select_target_from(&snapshot, "u1", &format!("d-{i}"), no_health())
                .expect("distribute selection");
        *by_target.entry(selection.target.host.clone()).or_default() += 1;
    }

    let west_a = by_target.get("west-a.local").copied().unwrap_or(0);
    let west_b = by_target.get("west-b.local").copied().unwrap_or(0);
    let east = by_target.get("east.local").copied().unwrap_or(0);
    let total = west_a + west_b + east;
    assert_eq!(total, 2000);

    // `us-west` is the 80% locality share, split across west-a and west-b;
    // `us-east` is the 20% locality share with one endpoint. Effective
    // endpoint ratios are therefore 0.4 / 0.4 / 0.2. Allow ±6% slack for
    // the golden-ratio PRNG.
    let west_a_ratio = f64::from(west_a) / f64::from(total);
    let west_b_ratio = f64::from(west_b) / f64::from(total);
    let east_ratio = f64::from(east) / f64::from(total);
    assert!(
        (west_a_ratio - 0.4).abs() < 0.06,
        "west-a ratio {west_a_ratio:.3} outside ±0.06 of 0.4"
    );
    assert!(
        (west_b_ratio - 0.4).abs() < 0.06,
        "west-b ratio {west_b_ratio:.3} outside ±0.06 of 0.4"
    );
    assert!(
        (east_ratio - 0.2).abs() < 0.04,
        "east ratio {east_ratio:.3} outside ±0.04 of 0.2"
    );
}

#[test]
fn locality_distribute_excludes_targets_with_zero_weight() {
    // distribute weights only `us-east`; the exact-tier `us-west` target
    // gets weight 0 and must NEVER be selected.
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..100 {
        let selection =
            LoadBalancerCache::select_target_from(&snapshot, "u1", &format!("k-{i}"), no_health())
                .expect("distribute selection");
        assert_eq!(
            selection.target.host, "east.local",
            "distribute weight 0 for west.local must exclude it from selection"
        );
    }
}

#[test]
fn locality_distribute_from_terminal_wildcard_matches_source_subzone() {
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/*".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..16 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "u1",
            &format!("wild-{i}"),
            no_health(),
        )
        .expect("wildcard distribute selection");
        assert_eq!(
            selection.target.host, "east.local",
            "terminal wildcard in distribute.from must activate distribute weighting"
        );
    }
}

#[test]
fn locality_distribute_falls_through_when_every_weighted_target_is_unhealthy() {
    // distribute weights east at 100. If the only east target is unhealthy
    // selection MUST fall through to the rest of the candidate set instead
    // of returning None (operators expect resilience, not silent outage).
    let east = target("east.local", Some("us-east/us-east-1/a"));
    let mut to = BTreeMap::new();
    to.insert("us-east".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("west.local", Some("us-west/us-west-1/a")),
            east.clone(),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("u1", &east), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection = LoadBalancerCache::select_target_from(&snapshot, "u1", "fb", Some(&health))
        .expect("fallthrough selection");
    assert_eq!(selection.target.host, "west.local");
}

#[test]
fn locality_distribute_no_matching_from_uses_priority_tier() {
    // distribute.from is `eu-central`, source is `us-west` — no entry
    // matches, so distribute does NOT activate and the existing priority
    // tier preference takes over.
    let mut to = BTreeMap::new();
    to.insert("eu-central".to_string(), 100);
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "eu-central/eu-central-1/a".to_string(),
            to,
        }],
        failover: Vec::new(),
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("exact.local", Some("us-west/us-west-1/a")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    for i in 0..16 {
        let selection =
            LoadBalancerCache::select_target_from(&snapshot, "u1", &format!("p-{i}"), no_health())
                .expect("priority selection");
        assert_eq!(
            selection.target.host, "exact.local",
            "distribute.from mismatch must leave priority tier preference intact"
        );
    }
}

// ── localityLbSetting.failover ────────────────────────────────────────────

#[test]
fn locality_failover_overrides_region_fallback_when_all_local_tiers_unhealthy() {
    // Source region `us-west`; failover routes to `us-east`. With exact,
    // zone, and region tiers all unhealthy, the failover region MUST win
    // over the unannotated rank-3 `eu` target.
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let zone = target("zone.local", Some("us-west/us-west-1/b"));
    let region = target("region.local", Some("us-west/us-west-2/a"));
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: Vec::new(),
        failover: vec![LocalityFailover {
            from: "us-west".to_string(),
            to: "us-east".to_string(),
        }],
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            exact.clone(),
            zone.clone(),
            region.clone(),
            target("eu.local", Some("eu-central/eu-central-1/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("u1", &exact), 1);
    active_unhealthy.insert(target_key("u1", &zone), 1);
    active_unhealthy.insert(target_key("u1", &region), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    for i in 0..6 {
        let selection = LoadBalancerCache::select_target_from(
            &snapshot,
            "u1",
            &format!("k-{i}"),
            Some(&health),
        )
        .expect("failover selection");
        assert_eq!(
            selection.target.host, "east.local",
            "failover region must win over rank-3 unannotated targets"
        );
    }
}

#[test]
fn locality_failover_does_not_apply_when_local_tier_is_healthy() {
    // Even with failover configured, a healthy exact-tier target wins.
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: Vec::new(),
        failover: vec![LocalityFailover {
            from: "us-west".to_string(),
            to: "us-east".to_string(),
        }],
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("exact.local", Some("us-west/us-west-1/a")),
            target("east.local", Some("us-east/us-east-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    for i in 0..16 {
        let selection =
            LoadBalancerCache::select_target_from(&snapshot, "u1", &format!("h-{i}"), no_health())
                .expect("priority selection");
        assert_eq!(
            selection.target.host, "exact.local",
            "failover must not preempt a healthy exact-tier target"
        );
    }
}

#[test]
fn locality_failover_falls_through_when_failover_region_is_also_empty() {
    // Failover region has no targets at all — selection must still succeed
    // by falling through to the rank-3 unannotated set.
    let exact = target("exact.local", Some("us-west/us-west-1/a"));
    let setting = UpstreamLocalityLbSetting {
        enabled: true,
        distribute: Vec::new(),
        failover: vec![LocalityFailover {
            from: "us-west".to_string(),
            to: "us-east".to_string(),
        }],
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            exact.clone(),
            target("eu.local", Some("eu-central/eu-central-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();
    let active_unhealthy = DashMap::new();
    active_unhealthy.insert(target_key("u1", &exact), 1);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let selection = LoadBalancerCache::select_target_from(&snapshot, "u1", "ft", Some(&health))
        .expect("fallthrough selection");
    assert_eq!(selection.target.host, "eu.local");
}

#[test]
fn locality_lb_enabled_false_disables_priority_distribute_and_failover() {
    // `enabled: false` matches Istio semantics — every locality-aware
    // path is suppressed and the configured algorithm picks across the
    // unfiltered candidate set.
    let setting = UpstreamLocalityLbSetting {
        enabled: false,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to: BTreeMap::from([("us-west".to_string(), 100)]),
        }],
        failover: vec![LocalityFailover {
            from: "us-west".to_string(),
            to: "us-east".to_string(),
        }],
    };
    let up = upstream_with_locality_lb(
        "us-west/us-west-1/a",
        vec![
            target("exact.local", Some("us-west/us-west-1/a")),
            target("other.local", Some("eu-central/eu-central-1/a")),
        ],
        setting,
    );
    let cache = LoadBalancerCache::new(&config(up));
    let snapshot = cache.load();

    let mut seen: HashSet<String> = HashSet::new();
    for i in 0..30 {
        let selection =
            LoadBalancerCache::select_target_from(&snapshot, "u1", &format!("k-{i}"), no_health())
                .expect("selected");
        seen.insert(selection.target.host.clone());
    }
    assert_eq!(
        seen.len(),
        2,
        "enabled=false must let RR visit both targets across the full set — saw {seen:?}"
    );
}
