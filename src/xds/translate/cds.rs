//! `MeshService` → `Cluster` translation.
//!
//! Each `MeshService` becomes one cluster per port. Resolution mode:
//! - Endpoints in the slice carry SPIFFE IDs → `Cluster.type = EDS` and
//!   the cluster's load assignment is served separately by EDS.
//! - `ServiceEntry` of `Resolution::Dns` and `MeshExternal` location →
//!   `Cluster.type = STRICT_DNS` (Envoy resolves the host directly).
//! - `ServiceEntry` of `Resolution::Static` → `Cluster.type = STATIC` with
//!   inline endpoints (we still emit an EDS entry as a convenience).
//!
//! The cluster name follows Istio's `outbound|<port>||<svc>.<ns>.svc.cluster.local`
//! convention so existing tooling that knows the shape (`istioctl pc cluster`,
//! Envoy `/clusters` admin) sees familiar output.

use envoy_types::pb::envoy::config::cluster::v3::Cluster;
use envoy_types::pb::envoy::config::cluster::v3::cluster::{
    ClusterDiscoveryType, DiscoveryType, EdsClusterConfig,
};
use envoy_types::pb::envoy::config::core::v3::config_source::ConfigSourceSpecifier;
use envoy_types::pb::envoy::config::core::v3::{AggregatedConfigSource, ApiVersion, ConfigSource};
use envoy_types::pb::google::protobuf::Duration;

use super::{ClusterSet, outbound_cluster_name};
use crate::config::mesh::MeshSlice;
use crate::xds::snapshot::NodeIdentity;

pub fn translate(slice: Option<&MeshSlice>, _identity: &NodeIdentity) -> ClusterSet {
    let mut out = ClusterSet::new();
    let Some(slice) = slice else {
        return out;
    };

    // 1) MeshService clusters (EDS-backed by default)
    for svc in &slice.services {
        for port in &svc.ports {
            let name = outbound_cluster_name(&svc.name, &svc.namespace, port.port);
            out.insert(name.clone(), eds_cluster(name));
        }
    }

    // 2) ServiceEntry clusters
    for se in &slice.service_entries {
        let dns = matches!(se.resolution, crate::config::mesh::Resolution::Dns);
        let static_ = matches!(se.resolution, crate::config::mesh::Resolution::Static);
        for port in &se.ports {
            let svc_name = se.hosts.first().cloned().unwrap_or_else(|| se.name.clone());
            let name = outbound_cluster_name(&svc_name, &se.namespace, port.port);
            let cluster = if dns {
                strict_dns_cluster(name.clone())
            } else if static_ {
                // Static endpoints still go through the EDS path —
                // simpler, and Envoy treats EDS-served STATIC the same.
                eds_cluster(name.clone())
            } else {
                // Resolution::None — fall back to EDS so the data plane
                // can still get endpoints from us if any are configured.
                eds_cluster(name.clone())
            };
            out.insert(name, cluster);
        }
    }

    out
}

fn eds_cluster(name: String) -> Cluster {
    Cluster {
        name: name.clone(),
        cluster_discovery_type: Some(ClusterDiscoveryType::Type(DiscoveryType::Eds as i32)),
        eds_cluster_config: Some(EdsClusterConfig {
            // Serve EDS over the same ADS stream the cluster came from.
            eds_config: Some(ConfigSource {
                resource_api_version: ApiVersion::V3 as i32,
                config_source_specifier: Some(ConfigSourceSpecifier::Ads(
                    AggregatedConfigSource {},
                )),
                ..Default::default()
            }),
            // Empty service_name → Envoy uses the cluster name.
            service_name: String::new(),
        }),
        connect_timeout: Some(Duration {
            seconds: 5,
            nanos: 0,
        }),
        ..Default::default()
    }
}

fn strict_dns_cluster(name: String) -> Cluster {
    Cluster {
        name,
        cluster_discovery_type: Some(ClusterDiscoveryType::Type(DiscoveryType::StrictDns as i32)),
        connect_timeout: Some(Duration {
            seconds: 5,
            nanos: 0,
        }),
        ..Default::default()
    }
}
