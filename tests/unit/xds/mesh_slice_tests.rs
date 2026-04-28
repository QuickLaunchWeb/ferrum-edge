//! `MeshSlice::for_workload` security-boundary tests.
//!
//! These belong with `xds_tests` because the slice computation is
//! the input to every per-node snapshot. The internal slice tests in
//! `src/config/mesh/slice.rs` cover the basic filtering rules; here we
//! exercise corner cases that would let workload A see workload B's
//! config (a security regression).

use ferrum_edge::config::mesh::{
    AppProtocol, MeshPolicy, MeshService, MeshSlice, PeerAuthentication, PolicyAction, PolicyScope,
    PrincipalMatch, RequestMatch, Workload, WorkloadPort, WorkloadSelector,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use std::collections::HashMap;
use std::str::FromStr;

fn td(s: &str) -> TrustDomain {
    TrustDomain::new(s).unwrap()
}

fn make_workload(spiffe: &str, ns: &str) -> Workload {
    let id = SpiffeId::from_str(spiffe).unwrap();
    let trust = id.trust_domain().clone();
    Workload {
        spiffe_id: id,
        selector: WorkloadSelector {
            labels: HashMap::new(),
            namespace: Some(ns.to_string()),
        },
        service_name: "x".into(),
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: None,
        }],
        trust_domain: trust,
        namespace: ns.into(),
    }
}

#[test]
fn slice_returns_none_for_unknown_workload() {
    assert!(
        MeshSlice::for_workload(
            &SpiffeId::from_str("spiffe://prod/ns/foo/sa/bar").unwrap(),
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .is_none()
    );
}

#[test]
fn workload_a_does_not_see_namespace_b_only_policies() {
    let a = make_workload("spiffe://prod/ns/a/sa/api", "a");
    let b = make_workload("spiffe://prod/ns/b/sa/api", "b");
    let policy_b_only = MeshPolicy {
        name: "b-only".into(),
        namespace: "b".into(),
        scope: PolicyScope::Namespace {
            namespace: "b".into(),
        },
        rules: vec![],
    };
    let slice = MeshSlice::for_workload(
        &a.spiffe_id,
        &[a.clone(), b.clone()],
        &[],
        &[policy_b_only],
        &[],
        &[],
        None,
    )
    .unwrap();
    assert!(
        slice.policies.is_empty(),
        "Workload A's slice must NOT include policies scoped only to namespace B"
    );
}

#[test]
fn workload_a_does_not_see_namespace_b_only_peer_authentications() {
    let a = make_workload("spiffe://prod/ns/a/sa/api", "a");
    let pa_b_only = PeerAuthentication {
        name: "b-only".into(),
        namespace: "b".into(),
        selector: None,
        mtls_mode: ferrum_edge::config::mesh::MtlsMode::Strict,
        port_overrides: HashMap::new(),
    };
    let slice = MeshSlice::for_workload(
        &a.spiffe_id,
        std::slice::from_ref(&a),
        &[],
        &[],
        &[pa_b_only],
        &[],
        None,
    )
    .unwrap();
    assert!(
        slice.peer_authentications.is_empty(),
        "Workload A's slice must NOT include PeerAuthentications from namespace B"
    );
}

#[test]
fn workload_in_other_namespace_sees_meshwide_policies() {
    let a = make_workload("spiffe://prod/ns/a/sa/api", "a");
    let global = MeshPolicy {
        name: "global".into(),
        namespace: "ferrum".into(),
        scope: PolicyScope::MeshWide,
        rules: vec![],
    };
    let slice = MeshSlice::for_workload(
        &a.spiffe_id,
        std::slice::from_ref(&a),
        &[],
        std::slice::from_ref(&global),
        &[],
        &[],
        None,
    )
    .unwrap();
    assert_eq!(slice.policies, vec![global]);
}

#[test]
fn slice_propagates_trust_bundles_unchanged() {
    use ferrum_edge::config::mesh::{TrustBundle, TrustBundleSet};
    let a = make_workload("spiffe://prod/ns/a/sa/api", "a");
    let bundle = TrustBundleSet {
        local: TrustBundle {
            trust_domain: td("prod"),
            x509_authorities: vec!["AAAA".into()],
            jwt_authorities: vec![],
            refresh_hint_seconds: None,
        },
        federated: vec![],
    };
    let slice = MeshSlice::for_workload(
        &a.spiffe_id,
        std::slice::from_ref(&a),
        &[],
        &[],
        &[],
        &[],
        Some(&bundle),
    )
    .unwrap();
    assert_eq!(slice.trust_bundles, Some(bundle));
}

#[test]
fn cross_namespace_from_principal_match_pulls_policy_into_slice() {
    // Frontend allows billing/api to call it.
    let billing = make_workload("spiffe://prod/ns/billing/sa/api", "billing");
    let frontend_policy = MeshPolicy {
        name: "frontend-allow-billing".into(),
        namespace: "frontend".into(),
        scope: PolicyScope::Namespace {
            namespace: "frontend".into(),
        },
        rules: vec![ferrum_edge::config::mesh::MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://prod/ns/billing/sa/*".into()),
                namespace_pattern: None,
                trust_domain: None,
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".into()],
                paths: vec![],
                hosts: vec![],
                headers: HashMap::new(),
                ports: vec![],
            }],
            when: vec![],
            action: PolicyAction::Allow,
        }],
    };
    let slice = MeshSlice::for_workload(
        &billing.spiffe_id,
        std::slice::from_ref(&billing),
        &[],
        std::slice::from_ref(&frontend_policy),
        &[],
        &[],
        None,
    )
    .unwrap();
    assert_eq!(
        slice.policies,
        vec![frontend_policy],
        "Billing workload needs the cross-namespace policy that names it in `from`"
    );
}

#[test]
fn slice_returns_only_same_namespace_services() {
    let a = make_workload("spiffe://prod/ns/a/sa/api", "a");
    let svc_a = MeshService {
        name: "a-svc".into(),
        namespace: "a".into(),
        ports: vec![],
        workloads: vec![],
        protocol_overrides: HashMap::new(),
    };
    let svc_b = MeshService {
        name: "b-svc".into(),
        namespace: "b".into(),
        ports: vec![],
        workloads: vec![],
        protocol_overrides: HashMap::new(),
    };
    let slice = MeshSlice::for_workload(
        &a.spiffe_id,
        std::slice::from_ref(&a),
        &[svc_a.clone(), svc_b],
        &[],
        &[],
        &[],
        None,
    )
    .unwrap();
    assert_eq!(slice.services, vec![svc_a]);
}
