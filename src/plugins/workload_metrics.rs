//! Mesh workload metrics shim.
//!
//! Phase C records identity-aware counters in-process without adding a global
//! metrics dependency or touching existing prometheus output. Phase E can wire
//! these counters into the published Istio/GAMMA metric families.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{Plugin, StreamTransactionSummary, TransactionSummary};

pub struct WorkloadMetrics {
    http_transactions: AtomicU64,
    stream_transactions: AtomicU64,
}

impl WorkloadMetrics {
    pub fn new(_config: &Value) -> Result<Self, String> {
        Ok(Self {
            http_transactions: AtomicU64::new(0),
            stream_transactions: AtomicU64::new(0),
        })
    }

    #[allow(dead_code)]
    #[doc(hidden)]
    pub fn http_transactions(&self) -> u64 {
        self.http_transactions.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Plugin for WorkloadMetrics {
    fn name(&self) -> &str {
        "workload_metrics"
    }

    fn priority(&self) -> u16 {
        super::priority::WORKLOAD_METRICS
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.http_transactions.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            target: "mesh_metrics",
            source_principal = ?summary.metadata.get("source_principal").map(String::as_str),
            destination_service = ?summary.metadata.get("destination_service").map(String::as_str),
            request_protocol = %summary
                .metadata
                .get("request_protocol")
                .map(String::as_str)
                .unwrap_or("http"),
            response_code = summary.response_status_code,
            "mesh workload HTTP transaction observed"
        );
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.stream_transactions.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            target: "mesh_metrics",
            source_principal = ?summary.metadata.get("source_principal").map(String::as_str),
            destination_service = ?summary.metadata.get("destination_service").map(String::as_str),
            request_protocol = %summary.protocol.as_str(),
            "mesh workload stream transaction observed"
        );
    }
}
