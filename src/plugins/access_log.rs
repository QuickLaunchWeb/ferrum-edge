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
        let filter = config.get("filter").and_then(|f| {
            if f.is_null() {
                return None;
            }
            Some(Filter {
                status_code_min: f
                    .get("status_code_min")
                    .and_then(Value::as_u64)
                    .map(|v| v as u16),
                status_code_max: f
                    .get("status_code_max")
                    .and_then(Value::as_u64)
                    .map(|v| v as u16),
                min_latency_ms: f.get("min_latency_ms").and_then(Value::as_u64),
                errors_only: f
                    .get("errors_only")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        });
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
        // Stream summaries always logged — filter only applies to HTTP
        match serde_json::to_string(summary) {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize stream summary: {e}"),
        }
    }
}
