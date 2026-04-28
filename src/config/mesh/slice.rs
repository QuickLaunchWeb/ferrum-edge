//! Per-workload mesh slice (Phase B).
//!
//! A [`MeshSlice`] is the subset of the canonical mesh model that one
//! workload needs in order to act as a sidecar / data plane: just its own
//! `Workload`, the `MeshService`s it can reach as a client, the
//! `MeshPolicy`s where its identity is `from` or `to`, the
//! `PeerAuthentication`s scoping it, the `ServiceEntry`s it consumes, and
//! the trust bundle.
//!
//! Slicing keeps fleet-scale CP load tractable. The full `GatewayConfig`
//! for a 10000-workload mesh is enormous; a sidecar with 10 peer services
//! does not need to receive that on every config reload. The slice is what
//! the native [`crate::grpc::cp_server::CpGrpcServer::mesh_subscribe`]
//! RPC streams to mesh data planes (Phase C).
//!
//! ## Per-node isolation as a security boundary
//!
//! The CP MUST compute the slice from the requesting workload's verified
//! identity (SPIFFE ID + trust domain). Workload A's slice never includes
//! workload B's `MeshPolicy` or `PeerAuthentication` even if they share a
//! namespace — that's information leakage. This module's
//! [`MeshSlice::for_workload`] is the single source of truth for that
//! computation; `mesh_subscribe` and the xDS server's per-node snapshot
//! both call into it.

use serde::{Deserialize, Serialize};

use super::{
    MeshPolicy, MeshService, PeerAuthentication, PolicyScope, ServiceEntry, ServiceEntryLocation,
    TrustBundleSet, Workload, WorkloadSelector,
};
use crate::identity::spiffe::{SpiffeId, TrustDomain};

/// A per-workload subset of the mesh model.
///
/// Serde-friendly: serialised as JSON for the
/// [`crate::grpc::proto::MeshConfigUpdate`] gRPC payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshSlice {
    /// The workload this slice is computed for.
    pub workload: Workload,
    /// `MeshService`s this workload may consume as a client. Empty when
    /// no policy authorises the workload to reach any service.
    #[serde(default)]
    pub services: Vec<MeshService>,
    /// `MeshPolicy`s where this workload appears in either `from` or `to`.
    /// The data plane needs both: the `to` rules tell it whom it must
    /// authenticate when accepting connections; the `from` rules tell it
    /// whom it should authorise when initiating connections.
    #[serde(default)]
    pub policies: Vec<MeshPolicy>,
    /// `PeerAuthentication`s whose selector matches this workload (or that
    /// are mesh-wide / namespace-wide and apply by scope).
    #[serde(default)]
    pub peer_authentications: Vec<PeerAuthentication>,
    /// `ServiceEntry`s in scope for this workload's namespace.
    #[serde(default)]
    pub service_entries: Vec<ServiceEntry>,
    /// Trust bundle for the workload's local trust domain plus any
    /// federated trust domains relevant to the services it can reach.
    /// `None` when the cluster has no trust bundles configured.
    #[serde(default)]
    pub trust_bundles: Option<TrustBundleSet>,
}

impl MeshSlice {
    /// Compute the slice for one workload identity.
    ///
    /// Inputs are the full mesh-model collections from a `GatewayConfig`.
    /// Returns `None` if the workload is not registered in the input set
    /// (caller should surface this as an authentication-style error).
    pub fn for_workload(
        spiffe_id: &SpiffeId,
        workloads: &[Workload],
        services: &[MeshService],
        policies: &[MeshPolicy],
        peer_auths: &[PeerAuthentication],
        service_entries: &[ServiceEntry],
        trust_bundles: Option<&TrustBundleSet>,
    ) -> Option<MeshSlice> {
        // 1) Find the workload — exact SPIFFE-ID match.
        let workload = workloads.iter().find(|w| &w.spiffe_id == spiffe_id)?;

        // 2) Services the workload can reach as a client.
        //
        // First-cut policy: same-namespace services + any service named in
        // a `RequestMatch.hosts` glob in a policy where this workload is
        // `from`. The Phase C data plane will refine this with full host
        // matching; for now we ship same-namespace + any ServiceEntry the
        // workload can reach.
        let svc_matches: Vec<MeshService> = services
            .iter()
            .filter(|svc| svc.namespace == workload.namespace)
            .cloned()
            .collect();

        // 3) Policies — keep the policy if either:
        //    - it scopes this workload (PolicyScope), or
        //    - any rule's `from` matches this SPIFFE ID, or
        //    - any rule's `to` would route to this workload (the
        //      identity-aware part of `to` is host-based, but we forward
        //      the rule when the policy's scope already targets us).
        //
        // Forwarding the rule is safe: the data plane re-evaluates per
        // request. False positives bloat the slice; false negatives are
        // a security issue. We err on the side of forwarding.
        let policy_matches: Vec<MeshPolicy> = policies
            .iter()
            .filter(|p| policy_applies_to_workload(p, workload))
            .cloned()
            .collect();

        // 4) PeerAuthentications — same scoping rules.
        let pa_matches: Vec<PeerAuthentication> = peer_auths
            .iter()
            .filter(|pa| peer_auth_applies_to_workload(pa, workload))
            .cloned()
            .collect();

        // 5) ServiceEntries — same-namespace + mesh-external (which by
        //    convention are global). MeshInternal entries are scoped to a
        //    namespace; MeshExternal entries are visible mesh-wide.
        let se_matches: Vec<ServiceEntry> = service_entries
            .iter()
            .filter(|se| {
                matches!(se.location, ServiceEntryLocation::MeshExternal)
                    || se.namespace == workload.namespace
            })
            .cloned()
            .collect();

        // 6) Trust bundles — forward as-is. The slice always carries the
        //    full federated set (trust bundles are global by definition).
        let tb_clone = trust_bundles.cloned();

        Some(MeshSlice {
            workload: workload.clone(),
            services: svc_matches,
            policies: policy_matches,
            peer_authentications: pa_matches,
            service_entries: se_matches,
            trust_bundles: tb_clone,
        })
    }
}

/// True when `policy.scope` targets `workload` OR any rule has the workload
/// in `from`.
pub(crate) fn policy_applies_to_workload(policy: &MeshPolicy, workload: &Workload) -> bool {
    if scope_matches(&policy.scope, workload) {
        return true;
    }
    // `from` may reference this workload via spiffe_id_pattern,
    // namespace_pattern, or trust_domain.
    for rule in &policy.rules {
        for principal in &rule.from {
            if principal_matches_workload(principal, workload) {
                return true;
            }
        }
    }
    false
}

/// True when `pa.selector` matches `workload` (or `selector` is None,
/// meaning the policy applies namespace-wide).
pub(crate) fn peer_auth_applies_to_workload(pa: &PeerAuthentication, workload: &Workload) -> bool {
    // Namespace must match for any peer authentication to apply.
    if pa.namespace != workload.namespace {
        return false;
    }
    match &pa.selector {
        None => true, // namespace-wide
        Some(sel) => selector_matches(sel, workload),
    }
}

fn scope_matches(scope: &PolicyScope, workload: &Workload) -> bool {
    match scope {
        PolicyScope::MeshWide => true,
        PolicyScope::Namespace { namespace } => namespace == &workload.namespace,
        PolicyScope::WorkloadSelector { selector } => selector_matches(selector, workload),
    }
}

fn selector_matches(selector: &WorkloadSelector, workload: &Workload) -> bool {
    if let Some(ns) = &selector.namespace
        && ns != &workload.namespace
    {
        return false;
    }
    // All selector labels must be present (and equal) in the workload's
    // selector labels. Empty selector matches every workload.
    for (k, v) in &selector.labels {
        match workload.selector.labels.get(k) {
            Some(wv) if wv == v => {}
            _ => return false,
        }
    }
    true
}

fn principal_matches_workload(principal: &super::PrincipalMatch, workload: &Workload) -> bool {
    if let Some(td) = &principal.trust_domain
        && td != &workload.trust_domain
    {
        return false;
    }
    if let Some(ns_pat) = &principal.namespace_pattern {
        match glob::Pattern::new(ns_pat) {
            Ok(p) if p.matches(&workload.namespace) => {}
            // Glob compile errors are surfaced by `validate_mesh_config`;
            // here we just say "no match" so a bad glob doesn't leak the
            // policy into the slice.
            _ => return false,
        }
    }
    if let Some(id_pat) = &principal.spiffe_id_pattern {
        match glob::Pattern::new(id_pat) {
            Ok(p) if p.matches(workload.spiffe_id.as_ref()) => {}
            _ => return false,
        }
    }
    true
}

// ── Trust-domain helpers (used by xDS translate, kept here so the slice
// model stays self-contained) ────────────────────────────────────────────

/// Returns the set of trust domains a workload's policies reference.
/// Used by the xDS translator to scope SDS validation contexts.
pub fn referenced_trust_domains<'a>(
    policies: &'a [MeshPolicy],
) -> impl Iterator<Item = &'a TrustDomain> + 'a {
    policies
        .iter()
        .flat_map(|p| p.rules.iter())
        .flat_map(|r| r.from.iter())
        .filter_map(|p| p.trust_domain.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::mesh::{
        AppProtocol, MeshRule, MeshService, MtlsMode, PeerAuthentication, PolicyAction,
        PolicyScope, PrincipalMatch, RequestMatch, ServiceEntry, ServiceEntryLocation, ServicePort,
        Workload, WorkloadPort, WorkloadSelector,
    };
    use std::collections::HashMap;

    fn td(s: &str) -> TrustDomain {
        TrustDomain::new(s).unwrap()
    }

    fn sid(s: &str) -> SpiffeId {
        SpiffeId::new(s.to_string()).unwrap()
    }

    fn make_workload(spiffe: &str, ns: &str, service: &str) -> Workload {
        Workload {
            spiffe_id: sid(spiffe),
            selector: WorkloadSelector {
                labels: HashMap::new(),
                namespace: Some(ns.to_string()),
            },
            service_name: service.to_string(),
            ports: vec![WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: None,
            }],
            trust_domain: td(spiffe
                .split("//")
                .nth(1)
                .unwrap()
                .split('/')
                .next()
                .unwrap()),
            namespace: ns.to_string(),
        }
    }

    #[test]
    fn slice_for_unregistered_workload_returns_none() {
        let result = MeshSlice::for_workload(
            &sid("spiffe://prod/ns/foo/sa/bar"),
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn slice_includes_only_same_namespace_services() {
        let wl = make_workload("spiffe://prod/ns/billing/sa/api", "billing", "api");
        let svc_billing = MeshService {
            name: "billing-svc".into(),
            namespace: "billing".into(),
            ports: vec![],
            workloads: vec![],
            protocol_overrides: HashMap::new(),
        };
        let svc_other = MeshService {
            name: "other-svc".into(),
            namespace: "other".into(),
            ports: vec![],
            workloads: vec![],
            protocol_overrides: HashMap::new(),
        };
        let slice = MeshSlice::for_workload(
            &wl.spiffe_id,
            std::slice::from_ref(&wl),
            &[svc_billing.clone(), svc_other],
            &[],
            &[],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(slice.services, vec![svc_billing]);
    }

    #[test]
    fn slice_filters_policies_by_workload_selector_scope() {
        let wl = make_workload("spiffe://prod/ns/billing/sa/api", "billing", "api");
        let policy_match = MeshPolicy {
            name: "p1".into(),
            namespace: "billing".into(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::new(),
                    namespace: Some("billing".into()),
                },
            },
            rules: vec![],
        };
        let policy_other = MeshPolicy {
            name: "p2".into(),
            namespace: "other".into(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::new(),
                    namespace: Some("other".into()),
                },
            },
            rules: vec![],
        };
        let slice = MeshSlice::for_workload(
            &wl.spiffe_id,
            std::slice::from_ref(&wl),
            &[],
            &[policy_match.clone(), policy_other],
            &[],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(slice.policies, vec![policy_match]);
    }

    #[test]
    fn slice_includes_meshwide_policies() {
        let wl = make_workload("spiffe://prod/ns/billing/sa/api", "billing", "api");
        let policy = MeshPolicy {
            name: "global".into(),
            namespace: "ferrum".into(),
            scope: PolicyScope::MeshWide,
            rules: vec![],
        };
        let slice = MeshSlice::for_workload(
            &wl.spiffe_id,
            std::slice::from_ref(&wl),
            &[],
            std::slice::from_ref(&policy),
            &[],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(slice.policies, vec![policy]);
    }

    #[test]
    fn slice_includes_policies_referencing_workload_in_from() {
        let wl = make_workload("spiffe://prod/ns/billing/sa/api", "billing", "api");
        let policy_other = MeshPolicy {
            name: "frontend-can-call-billing".into(),
            namespace: "frontend".into(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::new(),
                    namespace: Some("frontend".into()),
                },
            },
            rules: vec![MeshRule {
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
            &wl.spiffe_id,
            std::slice::from_ref(&wl),
            &[],
            std::slice::from_ref(&policy_other),
            &[],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(slice.policies, vec![policy_other]);
    }

    #[test]
    fn slice_filters_peer_auth_by_namespace() {
        let wl = make_workload("spiffe://prod/ns/billing/sa/api", "billing", "api");
        let pa_match = PeerAuthentication {
            name: "strict".into(),
            namespace: "billing".into(),
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        };
        let pa_other = PeerAuthentication {
            name: "permissive".into(),
            namespace: "other".into(),
            selector: None,
            mtls_mode: MtlsMode::Permissive,
            port_overrides: HashMap::new(),
        };
        let slice = MeshSlice::for_workload(
            &wl.spiffe_id,
            std::slice::from_ref(&wl),
            &[],
            &[],
            &[pa_match.clone(), pa_other],
            &[],
            None,
        )
        .unwrap();
        assert_eq!(slice.peer_authentications, vec![pa_match]);
    }

    #[test]
    fn slice_includes_meshexternal_service_entries_globally() {
        let wl = make_workload("spiffe://prod/ns/billing/sa/api", "billing", "api");
        let se_external = ServiceEntry {
            name: "ext".into(),
            namespace: "global".into(),
            hosts: vec!["example.com".into()],
            endpoints: vec![],
            resolution: super::super::Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 443,
                protocol: AppProtocol::Tls,
                name: None,
            }],
        };
        let se_internal_other = ServiceEntry {
            name: "internal-other".into(),
            namespace: "other".into(),
            hosts: vec!["internal.example.com".into()],
            endpoints: vec![],
            resolution: super::super::Resolution::Static,
            location: ServiceEntryLocation::MeshInternal,
            ports: vec![],
        };
        let slice = MeshSlice::for_workload(
            &wl.spiffe_id,
            std::slice::from_ref(&wl),
            &[],
            &[],
            &[],
            &[se_external.clone(), se_internal_other],
            None,
        )
        .unwrap();
        assert_eq!(slice.service_entries, vec![se_external]);
    }

    #[test]
    fn slice_workload_a_does_not_see_workload_b_only_policies() {
        // Sanity check for the per-node isolation security boundary.
        let wl_a = make_workload("spiffe://prod/ns/a/sa/api", "a", "api");
        let wl_b = make_workload("spiffe://prod/ns/b/sa/api", "b", "api");
        let policy_b_only = MeshPolicy {
            name: "b-only".into(),
            namespace: "b".into(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::new(),
                    namespace: Some("b".into()),
                },
            },
            rules: vec![],
        };
        let slice = MeshSlice::for_workload(
            &wl_a.spiffe_id,
            &[wl_a.clone(), wl_b.clone()],
            &[],
            &[policy_b_only],
            &[],
            &[],
            None,
        )
        .unwrap();
        assert!(
            slice.policies.is_empty(),
            "workload A must not see policies that target only workload B"
        );
    }
}
