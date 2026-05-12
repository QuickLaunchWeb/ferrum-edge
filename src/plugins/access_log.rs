//! Mesh access log plugin.
//!
//! Emits identity-aware access logs through tracing. It is additive to the
//! existing logging plugins and reads the standard transaction summaries.
//!
//! Optional filter support (from Telemetry CRD): status code ranges,
//! latency threshold, errors-only mode.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tracing::warn;

use super::utils::log_schema::{SchemaView, SummarySchema, resolve_schema};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

pub struct AccessLog {
    /// When set, only log transactions matching all filter predicates.
    filter: Option<Filter>,
    schema: Option<Arc<SummarySchema>>,
}

struct Filter {
    status_code_min: Option<u16>,
    status_code_max: Option<u16>,
    min_latency_ms: Option<u64>,
    errors_only: bool,
}

impl AccessLog {
    pub fn new(config: &Value) -> Result<Self, String> {
        let filter = match config.get("filter") {
            Some(f) if !f.is_null() => Some(Filter {
                status_code_min: parse_optional_u16(f, "status_code_min")?,
                status_code_max: parse_optional_u16(f, "status_code_max")?,
                min_latency_ms: f.get("min_latency_ms").and_then(Value::as_u64),
                errors_only: f
                    .get("errors_only")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }),
            _ => None,
        };
        let schema = resolve_schema(config, "access_log")?;
        Ok(Self { filter, schema })
    }

    fn should_log_http(&self, summary: &TransactionSummary) -> bool {
        let Some(filter) = &self.filter else {
            return true;
        };
        if let Some(min) = filter.status_code_min
            && summary.response_status_code < min
        {
            return false;
        }
        if let Some(max) = filter.status_code_max
            && summary.response_status_code > max
        {
            return false;
        }
        if let Some(min_ms) = filter.min_latency_ms
            && summary.latency_total_ms < (min_ms as f64)
        {
            return false;
        }
        if filter.errors_only && summary.error_class.is_none() {
            return false;
        }
        true
    }

    fn should_log_stream(&self, summary: &StreamTransactionSummary) -> bool {
        let Some(filter) = &self.filter else {
            return true;
        };
        if filter.status_code_min.is_some() || filter.status_code_max.is_some() {
            return false;
        }
        if let Some(min_ms) = filter.min_latency_ms
            && summary.duration_ms < (min_ms as f64)
        {
            return false;
        }
        if filter.errors_only && summary.error_class.is_none() && summary.connection_error.is_none()
        {
            return false;
        }
        true
    }
}

fn parse_optional_u16(config: &Value, key: &str) -> Result<Option<u16>, String> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_u64() else {
        return Err(format!("access_log: filter.{key} must be an integer"));
    };
    u16::try_from(raw)
        .map(Some)
        .map_err(|_| format!("access_log: filter.{key} must be between 0 and 65535"))
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
        if !self.should_log_http(summary) {
            return;
        }
        let result = match self.schema.as_ref().filter(|s| s.applies_to_http()) {
            Some(schema) => serde_json::to_string(&SchemaView { summary, schema }),
            None => serde_json::to_string(summary),
        };
        match result {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize transaction summary: {e}"),
        }
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if !self.should_log_stream(summary) {
            return;
        }
        let result = match self.schema.as_ref().filter(|s| s.applies_to_stream()) {
            Some(schema) => serde_json::to_string(&SchemaView { summary, schema }),
            None => serde_json::to_string(summary),
        };
        match result {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize stream summary: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn stream_summary() -> StreamTransactionSummary {
        StreamTransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: "proxy-1".to_string(),
            proxy_name: None,
            client_ip: "127.0.0.1".to_string(),
            consumer_username: None,
            auth_method: None,
            backend_target: "127.0.0.1:8080".to_string(),
            backend_resolved_ip: None,
            protocol: "tcp".to_string(),
            listen_port: 15432,
            duration_ms: 250.0,
            bytes_sent: 0,
            bytes_received: 0,
            connection_error: None,
            error_class: None,
            disconnect_direction: None,
            disconnect_cause: None,
            timestamp_connected: "2026-05-10T00:00:00Z".to_string(),
            timestamp_disconnected: "2026-05-10T00:00:01Z".to_string(),
            sni_hostname: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn stream_status_code_filter_does_not_match_without_status() {
        let plugin = AccessLog::new(&json!({
            "filter": {
                "status_code_min": 500
            }
        }))
        .expect("plugin config");

        assert!(!plugin.should_log_stream(&stream_summary()));
    }
}
