//! Mesh access log plugin.
//!
//! Emits identity-aware access logs through tracing. It is additive to the
//! existing logging plugins and reads the standard transaction summaries.

use async_trait::async_trait;
use serde_json::Value;
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
        match serde_json::to_string(summary) {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize transaction summary: {e}"),
        }
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        match serde_json::to_string(summary) {
            Ok(json) => tracing::info!(target: "mesh_access_log", "{}", json),
            Err(e) => warn!("access_log: failed to serialize stream summary: {e}"),
        }
    }
}
