//! Build the synthetic `MeshSlice` JSON the CP stub returns.
//!
//! Hand-crafted JSON rather than deserialising via the
//! `ferrum-edge::modes::mesh::slice::MeshSlice` type. Hand-crafting keeps
//! this crate independent of the root `ferrum-edge` Cargo workspace.

use serde_json::{Value, json};

/// Build a synthetic mesh slice with:
///  - one MeshService `reviews.default` → 10.0.0.1
///  - one MeshService `details.default` → 10.0.0.2
///  - one wildcard ServiceEntry `*.headless.default.svc.cluster.local` →
///    10.0.0.99 (one-label wildcard).
pub fn build_synthetic_slice(node_id: &str, namespace: &str, version: &str) -> Value {
    json!({
        "node_id": node_id,
        "namespace": namespace,
        "version": version,
        "labels": {},
        "workloads": [
            {
                "spiffe_id": "spiffe://cluster.local/ns/default/sa/reviews",
                "selector": { "labels": {} },
                "service_name": "reviews",
                "addresses": ["10.0.0.1"],
                "ports": [{ "port": 9080, "protocol": "http" }],
                "trust_domain": "cluster.local",
                "namespace": "default"
            },
            {
                "spiffe_id": "spiffe://cluster.local/ns/default/sa/details",
                "selector": { "labels": {} },
                "service_name": "details",
                "addresses": ["10.0.0.2"],
                "ports": [{ "port": 9080, "protocol": "http" }],
                "trust_domain": "cluster.local",
                "namespace": "default"
            }
        ],
        "services": [
            {
                "name": "reviews",
                "namespace": "default",
                "ports": [{ "port": 9080, "protocol": "http" }],
                "workloads": [
                    { "spiffe_id": "spiffe://cluster.local/ns/default/sa/reviews" }
                ]
            },
            {
                "name": "details",
                "namespace": "default",
                "ports": [{ "port": 9080, "protocol": "http" }],
                "workloads": [
                    { "spiffe_id": "spiffe://cluster.local/ns/default/sa/details" }
                ]
            }
        ],
        "service_entries": [
            {
                "name": "headless-wildcard",
                "namespace": "default",
                "hosts": ["*.headless.default.svc.cluster.local"],
                "endpoints": [{ "address": "10.0.0.99" }],
                "location": "mesh_internal",
                "resolution": "static"
            }
        ]
    })
}

/// FQDNs the load generator queries, paired with their expected resolution
/// class.
pub fn workload_names() -> &'static [(&'static str, crate::metrics::NameClass)] {
    use crate::metrics::NameClass;
    &[
        ("reviews.default.svc.cluster.local", NameClass::MeshInternal),
        ("details.default.svc.cluster.local", NameClass::MeshInternal),
        (
            "pod-1.headless.default.svc.cluster.local",
            NameClass::MeshWildcard,
        ),
        (
            "pod-42.headless.default.svc.cluster.local",
            NameClass::MeshWildcard,
        ),
        ("example.com", NameClass::UpstreamForward),
        ("api.example.com", NameClass::UpstreamForward),
    ]
}
