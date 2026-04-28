//! `MeshPolicy` request matchers → `RouteConfiguration` translation.
//!
//! Phase B foundation: emit one `RouteConfiguration` per outbound port
//! (named by the port number, matching what the LDS HCM filter
//! references via `Rds.route_config_name`) plus one inbound RDS
//! ("inbound|http") that aggregates all routes targeting the workload.
//!
//! Each route is generated from `MeshPolicy.rules.to[*]` matchers when
//! the policy applies to the workload. Path matching translates as
//! follows:
//! - first glob in `RequestMatch.paths` wins
//! - `*`-only path → prefix `"/"`
//! - leading-slash literal path with no `*` → exact `Path` match
//! - any glob with `*` → safe regex (translated from glob)
//!
//! Per-route RBAC is emitted via `typed_per_filter_config` in Phase C; for
//! Phase B foundation we emit the route + cluster reference and rely on
//! the listener-level RBAC filter (added later) for identity gating.

use envoy_types::pb::envoy::config::route::v3::route::Action as RouteActionOneof;
use envoy_types::pb::envoy::config::route::v3::route_action::ClusterSpecifier;
use envoy_types::pb::envoy::config::route::v3::route_match::PathSpecifier;
use envoy_types::pb::envoy::config::route::v3::{
    Route, RouteAction, RouteConfiguration, RouteMatch, VirtualHost,
};

use super::{RouteSet, outbound_cluster_name, outbound_route_name};
use crate::config::mesh::MeshSlice;
use crate::xds::snapshot::NodeIdentity;

pub fn translate(slice: Option<&MeshSlice>, _identity: &NodeIdentity) -> RouteSet {
    let mut out = RouteSet::new();
    let Some(slice) = slice else {
        return out;
    };

    // Inbound RDS — one named "inbound|http" route table referenced by
    // the LDS inbound listener. Routes here all forward to the local
    // sidecar app port (a placeholder cluster name; Phase C will plug
    // in real per-port cluster picking).
    out.insert(
        "inbound|http".to_string(),
        RouteConfiguration {
            name: "inbound|http".to_string(),
            virtual_hosts: vec![VirtualHost {
                name: "inbound|http".to_string(),
                domains: vec!["*".to_string()],
                routes: vec![route_to_cluster("default", "inbound|http|catchall", "/")],
                ..Default::default()
            }],
            ..Default::default()
        },
    );

    // Outbound RDS — one route configuration per port the workload
    // can reach. Routes target the cluster that CDS emits for the
    // (service, port) tuple.
    let mut by_port: std::collections::BTreeMap<u16, Vec<Route>> = Default::default();
    for svc in &slice.services {
        for port in &svc.ports {
            let cluster = outbound_cluster_name(&svc.name, &svc.namespace, port.port);
            // First-cut routing: forward all paths for this cluster's
            // virtual host to its cluster. Phase C refines using the
            // policy `to.paths` matchers.
            let routes_for_port = by_port.entry(port.port).or_default();
            routes_for_port.push(route_to_cluster(&svc.name, &cluster, "/"));
        }
    }
    for se in &slice.service_entries {
        for port in &se.ports {
            let svc_name = se.hosts.first().cloned().unwrap_or_else(|| se.name.clone());
            let cluster = outbound_cluster_name(&svc_name, &se.namespace, port.port);
            let routes_for_port = by_port.entry(port.port).or_default();
            routes_for_port.push(route_to_cluster(&svc_name, &cluster, "/"));
        }
    }

    for (port, routes) in by_port {
        let name = outbound_route_name(port);
        out.insert(
            name.clone(),
            RouteConfiguration {
                name,
                virtual_hosts: vec![VirtualHost {
                    name: format!("outbound:{}", port),
                    domains: vec!["*".to_string()],
                    routes,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
    }

    out
}

fn route_to_cluster(name: &str, cluster: &str, path_prefix: &str) -> Route {
    Route {
        name: name.to_string(),
        r#match: Some(RouteMatch {
            path_specifier: Some(PathSpecifier::Prefix(path_prefix.to_string())),
            ..Default::default()
        }),
        action: Some(RouteActionOneof::Route(RouteAction {
            cluster_specifier: Some(ClusterSpecifier::Cluster(cluster.to_string())),
            ..Default::default()
        })),
        ..Default::default()
    }
}
