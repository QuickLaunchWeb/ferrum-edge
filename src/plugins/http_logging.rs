//! HTTP access logging plugin — batched async log shipping.
//!
//! Serializes `TransactionSummary` entries and sends them to a remote HTTP
//! endpoint in batches. Uses `BatchingLogger<LogEntry>` to decouple the proxy
//! hot path from network I/O: the `log()` hook enqueues the entry
//! non-blockingly, and a shared background task drains the queue in
//! configurable batch sizes with a flush interval timer.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type, and uses the shared `PluginHttpClient` for
//! connection pooling and DNS cache integration.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use tokio::time::Duration;
use tracing::warn;
use url::Url;

use super::utils::{BatchConfig, BatchingLogger, PluginHttpClient, RetryPolicy};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

/// Union type for log entries sent through the batched channel.
#[derive(Clone, serde::Serialize)]
#[serde(untagged)]
enum LogEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
}

#[derive(Clone)]
struct HttpFlushConfig {
    endpoint_url: String,
    custom_headers: Vec<(HeaderName, HeaderValue)>,
    http_client: PluginHttpClient,
}

pub struct HttpLogging {
    logger: BatchingLogger<LogEntry>,
    endpoint_hostname: Option<String>,
}

impl HttpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let endpoint_url = config["endpoint_url"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "http_logging: 'endpoint_url' is required — logs will have nowhere to send"
                    .to_string()
            })?
            .to_string();
        let parsed_url = Url::parse(&endpoint_url)
            .map_err(|e| format!("http_logging: invalid 'endpoint_url': {e}"))?;
        match parsed_url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(format!(
                    "http_logging: 'endpoint_url' must use http:// or https:// (got '{scheme}')"
                ));
            }
        }
        if parsed_url.host_str().is_none() {
            return Err(
                "http_logging: 'endpoint_url' must include a hostname or IP address".to_string(),
            );
        }

        let batch_size = config["batch_size"].as_u64().unwrap_or(50).max(1) as usize;
        let flush_interval_ms = config["flush_interval_ms"]
            .as_u64()
            .unwrap_or(1000)
            .max(100);
        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;

        // Build custom headers list from the `custom_headers` object.
        // Header names are validated and normalized to lowercase per RFC 7230.
        // Duplicate header names (case-insensitive) are deduplicated — last value wins.
        let mut custom_headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
        if let Some(map) = config["custom_headers"].as_object() {
            for (key, value) in map {
                let Some(v) = value.as_str() else {
                    warn!("http_logging: custom_headers['{key}'] has non-string value, skipping");
                    continue;
                };
                let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                    format!("http_logging: invalid custom_headers name '{key}': {e}")
                })?;
                let header_value = HeaderValue::from_str(v).map_err(|e| {
                    format!("http_logging: invalid custom_headers value for '{key}': {e}")
                })?;
                custom_headers.retain(|(existing, _)| *existing != header_name);
                custom_headers.push((header_name, header_value));
            }
        }

        let flush_config = HttpFlushConfig {
            endpoint_url,
            custom_headers,
            http_client,
        };
        let endpoint_hostname = parsed_url.host_str().map(|host| host.to_string());
        let logger = BatchingLogger::spawn(
            BatchConfig {
                batch_size,
                flush_interval: Duration::from_millis(flush_interval_ms),
                buffer_capacity,
                retry: RetryPolicy {
                    max_attempts: config["max_retries"].as_u64().unwrap_or(3) as u32 + 1,
                    delay: Duration::from_millis(config["retry_delay_ms"].as_u64().unwrap_or(1000)),
                },
                plugin_name: "http_logging",
            },
            move |batch| {
                let flush_config = flush_config.clone();
                async move { send_batch(&flush_config, batch).await }
            },
        );

        Ok(Self {
            logger,
            endpoint_hostname,
        })
    }
}

#[async_trait]
impl Plugin for HttpLogging {
    fn name(&self) -> &str {
        "http_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::HTTP_LOGGING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.logger.try_send(LogEntry::Stream(summary.clone()));
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.logger.try_send(LogEntry::Http(summary.clone()));
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.endpoint_hostname
            .as_ref()
            .map(|host| vec![host.clone()])
            .unwrap_or_default()
    }
}

async fn send_batch(cfg: &HttpFlushConfig, batch: Vec<LogEntry>) -> Result<(), String> {
    let entry_count = batch.len();
    let mut req = cfg.http_client.get().post(&cfg.endpoint_url).json(&batch);
    for (name, value) in &cfg.custom_headers {
        req = req.header(name.clone(), value.clone());
    }

    match cfg.http_client.execute(req, "http_logging").await {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => {
            let status = response.status();
            if status.is_client_error()
                && status != reqwest::StatusCode::REQUEST_TIMEOUT
                && status != reqwest::StatusCode::TOO_MANY_REQUESTS
            {
                warn!(
                    "HTTP logging batch discarded due to {} response ({} entries lost)",
                    status, entry_count,
                );
                Ok(())
            } else {
                Err(format!("HTTP logging batch failed with status {status}"))
            }
        }
        Err(error) => Err(format!("HTTP logging batch failed: {error}")),
    }
}
