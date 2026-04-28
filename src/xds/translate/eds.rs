//! `MeshService.workloads` + `ServiceEntry.endpoints` →
//! `ClusterLoadAssignment` translation.
//!
//! One `ClusterLoadAssignment` per cluster (matched by name with the CDS
//! emission). Endpoints are wrapped in a single `LocalityLbEndpoints`
//! group at locality `{}` (default — Phase B doesn't model topology
//! yet; a Phase C add-on can populate `region/zone/sub_zone` from the
//! workload metadata for locality-aware load balancing).
//!
//! ## Address sourcing (Phase B foundation)
//!
//! `ServiceEntry.endpoints[*].address` is forwarded directly — it's
//! either an IP literal or a hostname that Envoy can resolve. For
//! `MeshService.workloads` (SPIFFE-ID-only), Phase B emits the cluster
//! name as a placeholder service hostname; Phase C will plug in the
//! real workload address resolved from the attestor.

use envoy_types::pb::envoy::config::core::v3::{
    Address, SocketAddress, address::Address as AddressKind, socket_address::PortSpecifier,
};
use envoy_types::pb::envoy::config::endpoint::v3::{
    ClusterLoadAssignment, Endpoint, LbEndpoint, LocalityLbEndpoints, lb_endpoint::HostIdentifier,
};

use super::{EndpointSet, outbound_cluster_name};
use crate::config::mesh::MeshSlice;
use crate::xds::snapshot::NodeIdentity;

pub fn translate(slice: Option<&MeshSlice>, _identity: &NodeIdentity) -> EndpointSet {
    let mut out = EndpointSet::new();
    let Some(slice) = slice else {
        return out;
    };

    // 1) MeshService → emit an EDS entry with placeholder endpoints.
    //    Phase C plugs in real addresses; for now we emit the structure
    //    so xDS clients see a valid (if empty-locality) ClusterLoadAssignment.
    for svc in &slice.services {
        for port in &svc.ports {
            let cluster_name = outbound_cluster_name(&svc.name, &svc.namespace, port.port);
            let endpoints: Vec<LbEndpoint> = svc
                .workloads
                .iter()
                .map(|wlref| {
                    // Placeholder: until the data plane resolves the
                    // workload's IP, emit the SPIFFE ID's last path
                    // segment (the SA name) as a stable hostname for the
                    // STRICT_DNS-style fallback. For EDS proper we'd
                    // want IPs; Phase C will populate from attestation.
                    let hint = wlref
                        .spiffe_id
                        .to_string()
                        .rsplit_once('/')
                        .map(|(_, last)| last.to_string())
                        .unwrap_or_else(|| svc.name.clone());
                    lb_endpoint(&hint, port.port)
                })
                .collect();
            out.insert(
                cluster_name.clone(),
                ClusterLoadAssignment {
                    cluster_name,
                    endpoints: vec![LocalityLbEndpoints {
                        lb_endpoints: endpoints,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
        }
    }

    // 2) ServiceEntry → endpoints (real addresses)
    for se in &slice.service_entries {
        for port in &se.ports {
            let svc_name = se.hosts.first().cloned().unwrap_or_else(|| se.name.clone());
            let cluster_name = outbound_cluster_name(&svc_name, &se.namespace, port.port);
            let endpoints: Vec<LbEndpoint> = se
                .endpoints
                .iter()
                .map(|ep| {
                    let port_value = ep.ports.values().copied().next().unwrap_or(port.port);
                    lb_endpoint(&ep.address, port_value)
                })
                .collect();
            // Even if endpoints is empty, emit the assignment so the
            // cluster doesn't appear unhealthy until DNS resolves.
            out.insert(
                cluster_name.clone(),
                ClusterLoadAssignment {
                    cluster_name,
                    endpoints: vec![LocalityLbEndpoints {
                        lb_endpoints: endpoints,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
        }
    }

    out
}

fn lb_endpoint(host: &str, port: u16) -> LbEndpoint {
    LbEndpoint {
        host_identifier: Some(HostIdentifier::Endpoint(Endpoint {
            address: Some(Address {
                address: Some(AddressKind::SocketAddress(SocketAddress {
                    address: host.to_string(),
                    port_specifier: Some(PortSpecifier::PortValue(port as u32)),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}
