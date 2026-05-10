//! Mesh access log plugin.
//!
//! Emits identity-aware access logs through tracing. It is additive to the
//! existing logging plugins and reads the standard transaction summaries.
//!
//! Optional filter support (from Telemetry CRD): status code ranges,
//! latency threshold, errors-only mode.

use async_trait::async_trait;
use serde_json::Value;
use tracing::warn;

use super::{Plugin, StreamTransactionSummary, TransactionSummary};

pub struct AccessLog {
    /// When set, only log transactions matching all filter predicates.
    filter: Option<Filter>,
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
        Ok(Self { filter })
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
        match serde_json::to_string(summary) {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize transaction summary: {e}"),
        }
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if !self.should_log_stream(summary) {
            return;
        }
        match serde_json::to_string(summary) {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize stream summary: {e}"),
        }
    }
}
