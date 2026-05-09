//! Prometheus helpers for Istio/GAMMA-style mesh metrics.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::plugins::TransactionSummary;
use crate::plugins::prometheus_metrics::{HistogramBuckets, escape_label_value};

/// Istio/GAMMA-style RED metric key for mesh HTTP-family requests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MeshRequestKey {
    pub source_workload: Arc<str>,
    pub source_namespace: Arc<str>,
    pub source_principal: Arc<str>,
    pub source_app: Arc<str>,
    pub source_service: Arc<str>,
    pub destination_workload: Arc<str>,
    pub destination_namespace: Arc<str>,
    pub destination_principal: Arc<str>,
    pub destination_app: Arc<str>,
    pub destination_service: Arc<str>,
    pub request_protocol: Arc<str>,
    pub response_code: u16,
    pub response_flags: Arc<str>,
    pub connection_security_policy: Arc<str>,
}

pub fn mesh_request_key(summary: &TransactionSummary) -> Option<MeshRequestKey> {
    if !summary.metadata.keys().any(|key| key.starts_with("mesh.")) {
        return None;
    }

    let source_workload = metadata_arc(&summary.metadata, "mesh.source.workload", "unknown");
    let source_namespace = metadata_arc(&summary.metadata, "mesh.source.namespace", "unknown");
    let source_principal = metadata_arc(&summary.metadata, "mesh.source.principal", "unknown");
    let source_app = metadata_arc_or_clone(&summary.metadata, "mesh.source.app", &source_workload);
    let source_service =
        metadata_arc_or_clone(&summary.metadata, "mesh.source.service", &source_workload);
    let destination_default = summary
        .proxy_name
        .as_deref()
        .or(summary.proxy_id.as_deref())
        .unwrap_or("unknown");
    let destination_workload = metadata_arc(
        &summary.metadata,
        "mesh.destination.workload",
        destination_default,
    );
    let destination_namespace =
        metadata_arc(&summary.metadata, "mesh.destination.namespace", "unknown");
    let destination_principal =
        metadata_arc(&summary.metadata, "mesh.destination.principal", "unknown");
    let destination_app = metadata_arc_or_clone(
        &summary.metadata,
        "mesh.destination.app",
        &destination_workload,
    );
    let destination_service = metadata_arc_or_clone(
        &summary.metadata,
        "mesh.destination.service",
        &destination_workload,
    );
    let request_protocol = metadata_arc_any(
        &summary.metadata,
        &["mesh.request_protocol", "request_protocol"],
        "http",
    );
    let response_flags = metadata_arc(
        &summary.metadata,
        "mesh.response_flags",
        inferred_response_flags(summary),
    );
    let connection_security_policy =
        metadata_arc(&summary.metadata, "mesh.connection_security_policy", "none");

    Some(MeshRequestKey {
        source_workload,
        source_namespace,
        source_principal,
        source_app,
        source_service,
        destination_workload,
        destination_namespace,
        destination_principal,
        destination_app,
        destination_service,
        request_protocol,
        response_code: summary.response_status_code,
        response_flags,
        connection_security_policy,
    })
}

fn metadata_arc(metadata: &HashMap<String, String>, key: &str, default: &str) -> Arc<str> {
    Arc::from(metadata.get(key).map(String::as_str).unwrap_or(default))
}

fn metadata_arc_any(metadata: &HashMap<String, String>, keys: &[&str], default: &str) -> Arc<str> {
    Arc::from(
        keys.iter()
            .find_map(|key| metadata.get(*key).map(String::as_str))
            .unwrap_or(default),
    )
}

fn metadata_arc_or_clone(
    metadata: &HashMap<String, String>,
    key: &str,
    default: &Arc<str>,
) -> Arc<str> {
    metadata
        .get(key)
        .map(|value| Arc::from(value.as_str()))
        .unwrap_or_else(|| Arc::clone(default))
}

fn inferred_response_flags(summary: &TransactionSummary) -> &'static str {
    if summary.client_disconnected {
        "DC"
    } else if summary.error_class.is_some() || summary.body_error_class.is_some() {
        "UF"
    } else {
        "-"
    }
}

pub fn render_mesh_histogram(
    output: &mut String,
    key: &MeshRequestKey,
    histogram: &HistogramBuckets,
) {
    for (i, boundary) in histogram.boundaries.iter().enumerate() {
        let le = boundary.to_string();
        let labels = mesh_label_fragment(key, Some(&le));
        let count = histogram.counts[i].load(Ordering::Relaxed);
        output.push_str(&format!(
            "ferrum_mesh_request_duration_ms_bucket{{{}}} {}\n",
            labels, count
        ));
    }
    let total_count = histogram.count.load(Ordering::Relaxed);
    let labels = mesh_label_fragment(key, Some("+Inf"));
    output.push_str(&format!(
        "ferrum_mesh_request_duration_ms_bucket{{{}}} {}\n",
        labels, total_count
    ));
    let labels = mesh_label_fragment(key, None);
    let sum = f64::from_bits(histogram.sum.load(Ordering::Relaxed));
    output.push_str(&format!(
        "ferrum_mesh_request_duration_ms_sum{{{}}} {:.2}\n",
        labels, sum
    ));
    output.push_str(&format!(
        "ferrum_mesh_request_duration_ms_count{{{}}} {}\n",
        labels, total_count
    ));
}

pub fn mesh_label_fragment(key: &MeshRequestKey, le: Option<&str>) -> String {
    let mut labels = format!(
        "source_workload=\"{}\",source_namespace=\"{}\",source_principal=\"{}\",source_app=\"{}\",source_service=\"{}\",destination_workload=\"{}\",destination_namespace=\"{}\",destination_principal=\"{}\",destination_app=\"{}\",destination_service=\"{}\",request_protocol=\"{}\",response_code=\"{}\",response_flags=\"{}\",connection_security_policy=\"{}\"",
        escape_label_value(&key.source_workload),
        escape_label_value(&key.source_namespace),
        escape_label_value(&key.source_principal),
        escape_label_value(&key.source_app),
        escape_label_value(&key.source_service),
        escape_label_value(&key.destination_workload),
        escape_label_value(&key.destination_namespace),
        escape_label_value(&key.destination_principal),
        escape_label_value(&key.destination_app),
        escape_label_value(&key.destination_service),
        escape_label_value(&key.request_protocol),
        key.response_code,
        escape_label_value(&key.response_flags),
        escape_label_value(&key.connection_security_policy)
    );
    if let Some(le) = le {
        labels.push_str(&format!(",le=\"{}\"", le));
    }
    labels
}
