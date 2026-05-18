//! Bench: `policy::evaluate_mesh_authorization_policies` over N synthetic
//! ALLOW policies. Request misses every rule, so the engine traverses every
//! policy before falling through to implicit-deny — worst case for the
//! current linear scan, which is what we want to measure.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use ferrum_edge::modes::mesh::config::{
    MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch,
};
use ferrum_edge::modes::mesh::policy::{MeshAuthzRequest, evaluate_mesh_authorization_policies};

fn build_policies(n: usize) -> Vec<MeshPolicy> {
    (0..n)
        .map(|i| MeshPolicy {
            name: format!("policy-{i}"),
            namespace: "default".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: vec![PrincipalMatch {
                    spiffe_id_pattern: Some(format!(
                        "spiffe://cluster.local/ns/default/sa/svc-{i}"
                    )),
                    namespace_pattern: None,
                    trust_domain: None,
                }],
                to: vec![RequestMatch {
                    methods: vec!["GET".to_string(), "POST".to_string()],
                    paths: vec!["/api/*".to_string()],
                    ..Default::default()
                }],
                action: PolicyAction::Allow,
                ..Default::default()
            }],
        })
        .collect()
}

fn bench_authz_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("authz_match");
    for &size in &[10usize, 100, 1_000, 10_000] {
        let policies = build_policies(size);
        // Request has no source_principal, so every rule's `from` clause
        // fails to match — we walk all N policies and return implicit-deny.
        let request = MeshAuthzRequest {
            method: Some("GET".to_string()),
            path: Some("/api/users".to_string()),
            host: Some("svc.default.svc.cluster.local".to_string()),
            port: Some(8080),
            ..Default::default()
        };
        group.bench_with_input(BenchmarkId::new("policies", size), &size, |b, _| {
            b.iter(|| {
                let decision = evaluate_mesh_authorization_policies(
                    black_box(policies.iter()),
                    black_box(&request),
                );
                black_box(decision);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_authz_match);
criterion_main!(benches);
