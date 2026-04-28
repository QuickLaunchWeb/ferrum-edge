//! xDS Aggregated Discovery Service (Phase B — Layer 3 mesh control protocol).
//!
//! This module implements an Envoy-compatible xDS server. It is the
//! primary mesh control protocol because every major mesh except Linkerd
//! uses xDS — Istio, Consul, Kuma, OSM, Cilium service mesh. For mesh
//! users xDS isn't a preference, it's the prerequisite. Tooling, debug
//! story, and operator muscle memory are all centred on it.
//!
//! ## Scope
//!
//! - [`AggregatedDiscoveryService`] handles both
//!   `StreamAggregatedResources` (state-of-the-world / SotW) and
//!   `DeltaAggregatedResources` (delta xDS).
//! - Resource types served: LDS / RDS / CDS / EDS / SDS.
//! - ACK/NACK state per `(node_id, type_url)`: tracks `version_info`,
//!   `nonce`, `error_detail`.
//! - Per-node snapshot isolation: workload A never sees workload B's
//!   config (security boundary, not optimisation).
//!
//! ## Lock-free hot path
//!
//! The xDS subscription dispatch is on a hot path — every subscribed
//! sidecar's stream wakes on every `GatewayConfig` reload. The snapshot
//! cache is `DashMap<NodeId, Arc<XdsSnapshot>>` swapped via `ArcSwap` per
//! node. We never hold a lock while writing to a gRPC stream.
//!
//! ## Wiring
//!
//! Phase B wires the xDS server only into the `cp` runtime mode, gated
//! by `FERRUM_XDS_ENABLED` (default `false`). Existing CP behaviour with
//! the gate off is byte-identical to before. Phase C will wire the
//! ferrum-mesh data plane to consume either xDS (this module) or the
//! native [`crate::grpc::cp_server::CpGrpcServer::mesh_subscribe`] RPC.
//!
//! ## envoy-types crate
//!
//! Proto types come from the [`envoy-types`](https://crates.io/crates/envoy-types)
//! crate (Apache-2.0). It tracks tonic 0.14 / prost 0.14 (matches Ferrum's
//! existing gRPC stack) and ships pre-generated Rust modules under
//! `envoy_types::pb::*`. Vendoring 30+ Envoy protos was the alternative;
//! the crate is small enough to be net-better for compile time and
//! maintenance.
//!
//! [`AggregatedDiscoveryService`]: server::FerrumXdsServer

use std::sync::Arc;

use arc_swap::ArcSwap;

pub mod delta;
pub mod node;
pub mod server;
pub mod snapshot;
pub mod translate;

#[cfg(test)]
mod tests;

pub use server::FerrumXdsServer;
pub use snapshot::XdsSnapshotCache;

// ── Type-URL constants ────────────────────────────────────────────────
//
// Envoy uses `type.googleapis.com/<package>.<message>` as a string-
// addressable resource type. The xDS protocol does not assign integer
// codes; the type_url string is the wire-level identifier. Hard-coding
// the values keeps the hot-path matcher allocation-free.

/// LDS — `envoy.config.listener.v3.Listener`.
pub const LISTENER_TYPE: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
/// RDS — `envoy.config.route.v3.RouteConfiguration`.
pub const ROUTE_TYPE: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
/// CDS — `envoy.config.cluster.v3.Cluster`.
pub const CLUSTER_TYPE: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
/// EDS — `envoy.config.endpoint.v3.ClusterLoadAssignment`.
pub const ENDPOINT_TYPE: &str =
    "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
/// SDS — `envoy.extensions.transport_sockets.tls.v3.Secret`.
pub const SECRET_TYPE: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";

/// All type URLs the server knows about, in stable enumeration order
/// (used for emitting initial snapshots and for `Display` debug paths).
#[allow(dead_code)]
pub const KNOWN_TYPE_URLS: &[&str] = &[
    LISTENER_TYPE,
    ROUTE_TYPE,
    CLUSTER_TYPE,
    ENDPOINT_TYPE,
    SECRET_TYPE,
];

/// Resource type tag used internally as a lock-free key into snapshot maps.
///
/// Avoids comparing the long `type_url` string on every push. Mapped
/// to/from the wire string via [`ResourceType::from_type_url`] /
/// [`ResourceType::type_url`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Listener,
    Route,
    Cluster,
    Endpoint,
    Secret,
}

impl ResourceType {
    pub fn from_type_url(s: &str) -> Option<ResourceType> {
        match s {
            LISTENER_TYPE => Some(ResourceType::Listener),
            ROUTE_TYPE => Some(ResourceType::Route),
            CLUSTER_TYPE => Some(ResourceType::Cluster),
            ENDPOINT_TYPE => Some(ResourceType::Endpoint),
            SECRET_TYPE => Some(ResourceType::Secret),
            _ => None,
        }
    }

    pub fn type_url(self) -> &'static str {
        match self {
            ResourceType::Listener => LISTENER_TYPE,
            ResourceType::Route => ROUTE_TYPE,
            ResourceType::Cluster => CLUSTER_TYPE,
            ResourceType::Endpoint => ENDPOINT_TYPE,
            ResourceType::Secret => SECRET_TYPE,
        }
    }

    #[allow(dead_code)]
    pub fn all() -> [ResourceType; 5] {
        [
            ResourceType::Listener,
            ResourceType::Route,
            ResourceType::Cluster,
            ResourceType::Endpoint,
            ResourceType::Secret,
        ]
    }
}

/// Shared registration state for the xDS server: holds the lock-free
/// per-node snapshot cache + the live `GatewayConfig` reference. The
/// caller (typically `modes/control_plane.rs`) constructs this once and
/// hands it to the server's gRPC service.
pub struct XdsState {
    pub config: Arc<ArcSwap<crate::config::types::GatewayConfig>>,
    pub snapshots: XdsSnapshotCache,
    pub broadcast: tokio::sync::broadcast::Sender<XdsRefreshSignal>,
}

/// Signal published on the broadcast channel whenever a new snapshot is
/// computed. Carries `(node_id, version)` so each subscribed gRPC stream
/// can decide whether the change concerns it.
///
/// Note: snapshots are computed lazily — when a sidecar first connects we
/// build its snapshot, and on every subsequent config reload we refresh
/// only the snapshots for nodes we currently track. Brand-new nodes do
/// not receive a refresh signal until they subscribe; their first
/// snapshot is computed inline on subscribe.
///
/// `version` is reserved for future use — Phase C may use it for
/// out-of-band debug introspection or for finer-grained per-resource
/// version tracking. The hot-path SotW + delta paths drive purely off
/// the snapshot's monotonic version.
#[derive(Debug, Clone)]
pub struct XdsRefreshSignal {
    pub node_id: String,
    #[allow(dead_code)]
    pub version: u64,
}
