//! Tests for PeerAuthentication mTLS mode resolution.
//!
//! Validates the `resolve_effective_mtls_mode` function and `MeshSlice`
//! convenience method for correct Istio-style scope precedence:
//! WorkloadSelector > Namespace > MeshWide, with port-level overrides.

use ferrum_edge::modes::mesh::config::{MtlsMode, PeerAuthentication, WorkloadSelector};
use ferrum_edge::modes::mesh::slice::{MeshSlice, resolve_effective_mtls_mode};
use std::collections::{BTreeMap, HashMap};

fn peer_auth(
    name: &str,
    namespace: &str,
    selector: Option<WorkloadSelector>,
    mode: MtlsMode,
    port_overrides: HashMap<u16, MtlsMode>,
) -> PeerAuthentication {
    PeerAuthentication {
        name: name.to_string(),
        namespace: namespace.to_string(),
        scope: None,
        selector,
        mtls_mode: mode,
        port_overrides,
    }
}

// ── Default behavior ─────────────────────────────────────────────────────

#[test]
fn default_is_permissive_when_no_policies() {
    let mode = resolve_effective_mtls_mode(&[], "default", &HashMap::<String, String>::new(), 8080);
    assert_eq!(mode, MtlsMode::Permissive);
}

// ── Scope precedence ─────────────────────────────────────────────────────

#[test]
fn namespace_scoped_policy_applies() {
    let policies = vec![peer_auth(
        "ns-strict",
        "default",
        None,
        MtlsMode::Strict,
        HashMap::new(),
    )];
    let mode = resolve_effective_mtls_mode(
        &policies,
        "default",
        &HashMap::<String, String>::new(),
        8080,
    );
    assert_eq!(mode, MtlsMode::Strict);
}

#[test]
fn workload_selector_overrides_namespace_scope() {
    let policies = vec![
        peer_auth(
            "ns-strict",
            "default",
            None,
            MtlsMode::Strict,
            HashMap::new(),
        ),
        peer_auth(
            "wl-disable",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "frontend".into())]),
                namespace: None,
            }),
            MtlsMode::Disable,
            HashMap::new(),
        ),
    ];
    let labels = HashMap::from([("app".to_string(), "frontend".to_string())]);
    let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
    assert_eq!(mode, MtlsMode::Disable);
}

#[test]
fn workload_selector_with_non_matching_labels_falls_through() {
    let policies = vec![
        peer_auth(
            "ns-strict",
            "default",
            None,
            MtlsMode::Strict,
            HashMap::new(),
        ),
        peer_auth(
            "wl-disable",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "backend".into())]),
                namespace: None,
            }),
            MtlsMode::Disable,
            HashMap::new(),
        ),
    ];
    // Workload has "app=frontend" so the selector "app=backend" does not match.
    let labels = HashMap::from([("app".to_string(), "frontend".to_string())]);
    let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
    // Falls back to the namespace-scoped policy.
    assert_eq!(mode, MtlsMode::Strict);
}

// ── Port-level overrides ─────────────────────────────────────────────────

#[test]
fn port_override_in_winning_policy() {
    let policies = vec![peer_auth(
        "ns-strict",
        "default",
        None,
        MtlsMode::Strict,
        HashMap::from([(443, MtlsMode::Permissive), (9090, MtlsMode::Disable)]),
    )];
    let labels = HashMap::<String, String>::new();

    assert_eq!(
        resolve_effective_mtls_mode(&policies, "default", &labels, 443),
        MtlsMode::Permissive,
    );
    assert_eq!(
        resolve_effective_mtls_mode(&policies, "default", &labels, 9090),
        MtlsMode::Disable,
    );
    // Non-overridden port uses the top-level mode.
    assert_eq!(
        resolve_effective_mtls_mode(&policies, "default", &labels, 8080),
        MtlsMode::Strict,
    );
}

#[test]
fn port_override_from_lower_scope_does_not_leak() {
    // The namespace policy has a port override for 8080, but the workload
    // selector policy wins and has no override for that port.
    let policies = vec![
        peer_auth(
            "ns-policy",
            "default",
            None,
            MtlsMode::Strict,
            HashMap::from([(8080, MtlsMode::Disable)]),
        ),
        peer_auth(
            "wl-policy",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "web".into())]),
                namespace: None,
            }),
            MtlsMode::Permissive,
            HashMap::new(),
        ),
    ];
    let labels = HashMap::from([("app".to_string(), "web".to_string())]);
    // Port 8080 is NOT Disable because the winning policy is wl-policy.
    assert_eq!(
        resolve_effective_mtls_mode(&policies, "default", &labels, 8080),
        MtlsMode::Permissive,
    );
}

// ── Namespace isolation ──────────────────────────────────────────────────

#[test]
fn policies_in_other_namespace_are_ignored() {
    let policies = vec![peer_auth(
        "other-ns",
        "production",
        None,
        MtlsMode::Strict,
        HashMap::new(),
    )];
    let mode = resolve_effective_mtls_mode(
        &policies,
        "default",
        &HashMap::<String, String>::new(),
        8080,
    );
    assert_eq!(mode, MtlsMode::Permissive);
}

// ── MeshSlice convenience method ─────────────────────────────────────────

#[test]
fn mesh_slice_resolve_method_integration() {
    let slice = MeshSlice {
        namespace: "prod".to_string(),
        labels: BTreeMap::from([
            ("app".to_string(), "api".to_string()),
            ("version".to_string(), "v2".to_string()),
        ]),
        peer_authentications: vec![
            peer_auth(
                "mesh-permissive",
                "prod",
                None,
                MtlsMode::Permissive,
                HashMap::new(),
            ),
            peer_auth(
                "api-strict",
                "prod",
                Some(WorkloadSelector {
                    labels: HashMap::from([("app".into(), "api".into())]),
                    namespace: None,
                }),
                MtlsMode::Strict,
                HashMap::from([(15006, MtlsMode::Permissive)]),
            ),
        ],
        ..MeshSlice::default()
    };

    // Workload selector wins -> Strict for most ports.
    assert_eq!(slice.resolve_effective_mtls_mode(8080), MtlsMode::Strict);
    // Port 15006 has an explicit override to Permissive.
    assert_eq!(
        slice.resolve_effective_mtls_mode(15006),
        MtlsMode::Permissive
    );
}

// ── Multiple workload-selector policies ──────────────────────────────────

#[test]
fn first_matching_workload_selector_wins_at_same_scope() {
    // Two workload-selector policies both match. First one wins.
    let policies = vec![
        peer_auth(
            "wl-strict",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "api".into())]),
                namespace: None,
            }),
            MtlsMode::Strict,
            HashMap::new(),
        ),
        peer_auth(
            "wl-disable",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "api".into())]),
                namespace: None,
            }),
            MtlsMode::Disable,
            HashMap::new(),
        ),
    ];
    let labels = HashMap::from([("app".to_string(), "api".to_string())]);
    let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
    assert_eq!(mode, MtlsMode::Strict);
}

// ── Empty selector labels ────────────────────────────────────────────────

#[test]
fn empty_selector_labels_is_namespace_scope() {
    // A WorkloadSelector with empty labels matches any workload. But it's
    // classified as namespace scope, not workload scope.
    let policies = vec![
        peer_auth(
            "empty-selector",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::new(),
                namespace: None,
            }),
            MtlsMode::Disable,
            HashMap::new(),
        ),
        peer_auth(
            "real-selector",
            "default",
            Some(WorkloadSelector {
                labels: HashMap::from([("app".into(), "web".into())]),
                namespace: None,
            }),
            MtlsMode::Strict,
            HashMap::new(),
        ),
    ];
    let labels = HashMap::from([("app".to_string(), "web".to_string())]);
    // The real workload-selector policy should win.
    let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
    assert_eq!(mode, MtlsMode::Strict);
}
