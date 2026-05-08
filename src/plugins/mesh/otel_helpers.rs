//! OpenTelemetry helpers for mesh attributes.

use std::collections::HashMap;

pub fn mesh_trace_attributes(metadata: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut attributes: Vec<_> = metadata
        .iter()
        .filter(|(key, _)| key.starts_with("mesh."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    attributes.sort_by(|left, right| left.0.cmp(&right.0));
    attributes
}
