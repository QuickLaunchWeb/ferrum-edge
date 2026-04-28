//! Translation from the canonical mesh model to xDS resources.
//!
//! Each sub-module owns one xDS resource type:
//! - [`lds`] — `Workload` → inbound + outbound `Listener`s
//! - [`rds`] — `MeshPolicy` request matchers → `RouteConfiguration`
//! - [`cds`] — `MeshService` → `Cluster`
//! - [`eds`] — `MeshService.workloads` → `ClusterLoadAssignment`
//! - [`sds`] — `SVID` + `TrustBundleSet` → `Secret` (TLSCertificate +
//!   ValidationContext)
//!
//! ## Naming
//!
//! Cluster / listener / route / secret names are derived from the mesh
//! model deterministically so translations are stable across reloads —
//! the same `MeshService` always produces the same `Cluster.name`.
//! Stable naming is what makes delta xDS efficient: a renamed resource
//! reads as "remove old + add new", which is more bytes on the wire.

pub mod cds;
pub mod eds;
pub mod lds;
pub mod rds;
pub mod sds;

use envoy_types::pb::envoy::config::cluster::v3::Cluster;
use envoy_types::pb::envoy::config::endpoint::v3::ClusterLoadAssignment;
use envoy_types::pb::envoy::config::listener::v3::Listener;
use envoy_types::pb::envoy::config::route::v3::RouteConfiguration;
use envoy_types::pb::envoy::extensions::transport_sockets::tls::v3::Secret;
use std::collections::HashMap;

/// LDS resources keyed by listener name.
pub type ListenerSet = HashMap<String, Listener>;
/// RDS resources keyed by route configuration name.
pub type RouteSet = HashMap<String, RouteConfiguration>;
/// CDS resources keyed by cluster name.
pub type ClusterSet = HashMap<String, Cluster>;
/// EDS resources keyed by cluster name (one per cluster).
pub type EndpointSet = HashMap<String, ClusterLoadAssignment>;
/// SDS resources keyed by secret name.
pub type SecretSet = HashMap<String, Secret>;

// ── Naming helpers ────────────────────────────────────────────────────

/// Cluster name for `(service_name, namespace, port)`. Mirrors Istio's
/// `outbound|<port>||<host>` shape so existing dashboards / tooling that
/// know the convention still work.
pub fn outbound_cluster_name(svc_name: &str, namespace: &str, port: u16) -> String {
    format!(
        "outbound|{}||{}.{}.svc.cluster.local",
        port, svc_name, namespace
    )
}

/// Inbound (listener-side) cluster name for the local workload's port.
///
/// Phase B foundation does not yet emit per-port inbound clusters (the
/// inbound listener routes to a single placeholder cluster — Phase C
/// adds per-port routing). Kept here so the helper exists for Phase C.
#[allow(dead_code)]
pub fn inbound_cluster_name(port: u16) -> String {
    format!("inbound|{}||", port)
}

/// Listener name for the workload's catch-all outbound listener (port
/// 15001 by Istio convention).
pub fn outbound_catchall_listener_name() -> &'static str {
    "virtualOutbound"
}

/// Listener name for the workload's catch-all inbound listener (port
/// 15006 by Istio convention).
pub fn inbound_catchall_listener_name() -> &'static str {
    "virtualInbound"
}

/// Route configuration name for an outbound listener targeting `port`.
pub fn outbound_route_name(port: u16) -> String {
    format!("{}", port)
}

/// SDS secret name for the workload's own SVID.
pub const DEFAULT_SDS_CERT_NAME: &str = "default";

/// SDS secret name for the workload's validation context (root CAs +
/// federated trust bundles).
pub const DEFAULT_SDS_VALIDATION_NAME: &str = "ROOTCA";

/// The Istio convention for sidecar inbound port. Phase B targets 15006
/// for compatibility; Phase C may revisit.
pub const SIDECAR_INBOUND_PORT: u16 = 15006;

/// The Istio convention for sidecar outbound catch-all port.
pub const SIDECAR_OUTBOUND_PORT: u16 = 15001;
