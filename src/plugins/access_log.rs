//! Mesh identity-aware access log plugin.
//!
//! This is intentionally separate from `stdout_logging`: operators can enable
//! compact mesh access records without changing the existing transaction log
//! schema or sinks.

use async_trait::async_trait;
use serde_json::{Value, json};
use tracing::warn;

use super::{Plugin, StreamTransactionSummary, TransactionSummary};

pub struct AccessLog;

impl AccessLog {
    pub fn new(_config: &Value) -> Result<Self, String> {
        Ok(Self)
    }
}

#[async_trait]
impl Plugin for AccessLog {
    fn name(&self) -> &str {
        "access_log"
    }

    fn priority(&self) -> u16 {
        super::priority::ACCESS_LOG
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn log(&self, summary: &TransactionSummary) {
        let record = json!({
            "protocol": summary.metadata.get("request_protocol").map(String::as_str).unwrap_or("http"),
            "method": summary.http_method.as_str(),
            "path": summary.request_path.as_str(),
            "status": summary.response_status_code,
            "source_principal": summary.metadata.get("source_principal"),
            "source_namespace": summary.metadata.get("source_namespace"),
            "destination_service": summary.metadata.get("destination_service"),
            "destination_workload": summary.metadata.get("destination_workload"),
            "connection_security_policy": summary.metadata.get("connection_security_policy"),
            "duration_ms": summary.latency_total_ms,
            "request_bytes": summary.request_bytes,
            "response_bytes": summary.response_bytes,
        });
        match serde_json::to_string(&record) {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize HTTP mesh record: {e}"),
        }
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let record = json!({
            "protocol": summary.protocol.as_str(),
            "source_principal": summary.metadata.get("source_principal"),
            "source_namespace": summary.metadata.get("source_namespace"),
            "destination_service": summary.metadata.get("destination_service"),
            "destination_workload": summary.metadata.get("destination_workload"),
            "connection_security_policy": summary.metadata.get("connection_security_policy"),
            "listen_port": summary.listen_port,
            "bytes_sent": summary.bytes_sent,
            "bytes_received": summary.bytes_received,
            "duration_ms": summary.duration_ms,
            "disconnect_direction": summary.disconnect_direction,
            "disconnect_cause": summary.disconnect_cause,
        });
        match serde_json::to_string(&record) {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize stream mesh record: {e}"),
        }
    }
}
