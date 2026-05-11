//! Tests for PeerAuthentication mTLS mode resolution via the public API.
//!
//! Inline tests in `src/modes/mesh/slice.rs` cover the private helpers
//! (`classify_peer_auth_scope`, `peer_auth_applies_to_workload`) and the
//! core resolution scenarios. This file exercises the public
//! `resolve_effective_mtls_mode` and `MeshSlice::resolve_effective_mtls_mode`
//! surface with scenarios that benefit from the external-crate perspective.

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

// ── Scope precedence (public API path) ──────────────────────────────────

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
    let labels = HashMap::from([("app".to_string(), "frontend".to_string())]);
    let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
    assert_eq!(mode, MtlsMode::Strict);
}

// ── Port-level override does not leak from lower scope ──────────────────

#[test]
fn port_override_from_lower_scope_does_not_leak() {
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
    assert_eq!(
        resolve_effective_mtls_mode(&policies, "default", &labels, 8080),
        MtlsMode::Permissive,
    );
}

// ── MeshSlice convenience method ────────────────────────────────────────

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

    assert_eq!(slice.resolve_effective_mtls_mode(8080), MtlsMode::Strict);
    assert_eq!(
        slice.resolve_effective_mtls_mode(15006),
        MtlsMode::Permissive
    );
}

// ── Same-scope tie-breaking ─────────────────────────────────────────────

#[test]
fn first_matching_workload_selector_wins_at_same_scope() {
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

// ── Empty selector labels ───────────────────────────────────────────────

#[test]
fn empty_selector_labels_is_namespace_scope() {
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
    let mode = resolve_effective_mtls_mode(&policies, "default", &labels, 8080);
    assert_eq!(mode, MtlsMode::Strict);
}
