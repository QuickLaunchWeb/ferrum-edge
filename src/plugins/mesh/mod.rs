//! Mesh-specific plugins and plugin helpers.

use std::collections::HashMap;

pub mod authz;
pub mod prometheus_helpers;
pub mod spiffe_identity;
pub mod workload_metrics;

/// Extract mesh-prefixed metadata entries as OpenTelemetry attribute pairs,
/// sorted by key for deterministic span output.
pub fn mesh_trace_attributes(metadata: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut attributes: Vec<_> = metadata
        .iter()
        .filter(|(key, _)| key.starts_with("mesh."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    attributes.sort_by(|left, right| left.0.cmp(&right.0));
    attributes
}
