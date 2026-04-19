//! Kafka access logging plugin — async log shipping to Apache Kafka.
//!
//! Serializes `TransactionSummary` entries and produces them to a Kafka topic.
//! Uses `BatchingLogger<LogEntry>` to decouple the proxy hot path from Kafka
//! I/O while keeping librdkafka responsible for its own internal batching,
//! compression, and delivery retries.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type.

use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{BaseRecord, DefaultProducerContext, Producer, ThreadedProducer};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::spawn_blocking;
use tracing::warn;

use super::utils::{BatchConfig, BatchingLogger, PluginHttpClient, RetryPolicy};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

/// Union type for log entries sent through the batched channel.
#[derive(Clone, serde::Serialize)]
#[serde(untagged)]
enum LogEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
}

/// Which `TransactionSummary` field to use as the Kafka partition key.
#[derive(Clone, Copy)]
enum KeyField {
    /// Partition by client IP (default) — groups a client's logs together.
    ClientIp,
    /// Partition by proxy/route ID.
    ProxyId,
    /// Null key — round-robin across partitions.
    None,
}

impl LogEntry {
    fn partition_key(&self, key_field: &KeyField) -> Option<String> {
        match (self, key_field) {
            (_, KeyField::None) => None,
            (LogEntry::Http(summary), KeyField::ClientIp) => Some(summary.client_ip.clone()),
            (LogEntry::Stream(summary), KeyField::ClientIp) => Some(summary.client_ip.clone()),
            (LogEntry::Http(summary), KeyField::ProxyId) => summary.matched_proxy_id.clone(),
            (LogEntry::Stream(summary), KeyField::ProxyId) => Some(summary.proxy_id.clone()),
        }
    }
}

struct KafkaFlushState {
    producer: ThreadedProducer<DefaultProducerContext>,
    flush_timeout: Duration,
}

impl Drop for KafkaFlushState {
    fn drop(&mut self) {
        let _ = self.producer.flush(self.flush_timeout);
    }
}

pub struct KafkaLogging {
    logger: BatchingLogger<LogEntry>,
    broker_hostnames: Vec<String>,
}

impl KafkaLogging {
    pub fn new(config: &Value, http_client: &PluginHttpClient) -> Result<Self, String> {
        let broker_list = config["broker_list"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "kafka_logging: 'broker_list' is required (comma-separated broker addresses)"
                    .to_string()
            })?;

        let topic = config["topic"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "kafka_logging: 'topic' is required".to_string())?
            .to_string();

        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;
        let flush_timeout_seconds = config["flush_timeout_seconds"].as_u64().unwrap_or(5).max(1);

        let key_field = match config["key_field"].as_str() {
            None => KeyField::ClientIp,
            Some("client_ip") => KeyField::ClientIp,
            Some("proxy_id") => KeyField::ProxyId,
            Some("none") => KeyField::None,
            Some(other) => {
                return Err(format!(
                    "kafka_logging: unsupported key_field '{other}' \
                     (use client_ip/proxy_id/none)"
                ));
            }
        };

        let mut kafka_config = ClientConfig::new();
        kafka_config.set("bootstrap.servers", broker_list);

        if let Some(value) = config["message_timeout_ms"].as_u64() {
            kafka_config.set("message.timeout.ms", value.to_string());
        }

        let compression = config["compression"].as_str().unwrap_or("lz4");
        match compression {
            "none" | "gzip" | "snappy" | "lz4" | "zstd" => {
                kafka_config.set("compression.type", compression);
            }
            other => {
                return Err(format!(
                    "kafka_logging: unsupported compression '{other}' \
                     (use none/gzip/snappy/lz4/zstd)"
                ));
            }
        }

        if let Some(acks) = config["acks"].as_str() {
            match acks {
                "0" | "1" | "all" | "-1" => {
                    kafka_config.set("acks", acks);
                }
                other => {
                    return Err(format!(
                        "kafka_logging: unsupported acks '{other}' (use 0/1/all)"
                    ));
                }
            }
        }

        if let Some(protocol) = config["security_protocol"].as_str() {
            kafka_config.set("security.protocol", protocol);
        }
        if let Some(mechanism) = config["sasl_mechanism"].as_str() {
            kafka_config.set("sasl.mechanism", mechanism);
        }
        if let Some(username) = config["sasl_username"].as_str() {
            kafka_config.set("sasl.username", username);
        }
        if let Some(password) = config["sasl_password"].as_str() {
            kafka_config.set("sasl.password", password);
        }

        if let Some(ca) = config["ssl_ca_location"].as_str() {
            kafka_config.set("ssl.ca.location", ca);
        } else if let Some(gateway_ca) = http_client.tls_ca_bundle_path() {
            kafka_config.set("ssl.ca.location", gateway_ca);
        }

        let ssl_no_verify = config["ssl_no_verify"]
            .as_bool()
            .unwrap_or(http_client.tls_no_verify());
        if ssl_no_verify {
            kafka_config.set("enable.ssl.certificate.verification", "false");
        }

        if let Some(cert) = config["ssl_certificate_location"].as_str() {
            kafka_config.set("ssl.certificate.location", cert);
        }
        if let Some(key) = config["ssl_key_location"].as_str() {
            kafka_config.set("ssl.key.location", key);
        }

        if let Some(props) = config["producer_config"].as_object() {
            for (key, value) in props {
                if let Some(prop) = value.as_str() {
                    kafka_config.set(key, prop);
                }
            }
        }

        let producer: ThreadedProducer<DefaultProducerContext> = kafka_config
            .create()
            .map_err(|error| format!("kafka_logging: failed to create Kafka producer: {error}"))?;

        let broker_hostnames: Vec<String> = broker_list
            .split(',')
            .filter_map(|broker| {
                let trimmed = broker.trim();
                let host = if trimmed.starts_with('[') {
                    trimmed
                        .split(']')
                        .next()
                        .map(|value| value.trim_start_matches('['))
                } else {
                    trimmed.split(':').next()
                };
                host.filter(|value| !value.is_empty() && value.parse::<std::net::IpAddr>().is_err())
                    .map(|value| value.to_string())
            })
            .collect();

        let state = Arc::new(KafkaFlushState {
            producer,
            flush_timeout: Duration::from_secs(flush_timeout_seconds),
        });
        let logger = BatchingLogger::spawn(
            BatchConfig {
                batch_size: 1,
                flush_interval: Duration::from_millis(1000),
                buffer_capacity,
                retry: RetryPolicy {
                    max_attempts: 1,
                    delay: Duration::from_millis(0),
                },
                plugin_name: "kafka_logging",
            },
            move |batch| {
                let state = Arc::clone(&state);
                let topic = topic.clone();
                async move { send_batch(&state, &topic, key_field, batch).await }
            },
        );

        Ok(Self {
            logger,
            broker_hostnames,
        })
    }
}

#[async_trait]
impl Plugin for KafkaLogging {
    fn name(&self) -> &str {
        "kafka_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::KAFKA_LOGGING
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
        self.broker_hostnames.clone()
    }
}

async fn send_batch(
    state: &Arc<KafkaFlushState>,
    topic: &str,
    key_field: KeyField,
    batch: Vec<LogEntry>,
) -> Result<(), String> {
    for entry in batch {
        let payload = match serde_json::to_string(&entry) {
            Ok(json) => json,
            Err(error) => {
                warn!("Kafka logging: failed to serialize log entry: {error}");
                continue;
            }
        };
        let key = entry.partition_key(&key_field);
        let state = Arc::clone(state);
        let topic = topic.to_string();

        spawn_blocking(move || {
            let enqueue_error = match key {
                Some(key) => state
                    .producer
                    .send(
                        BaseRecord::<str, str>::to(&topic)
                            .payload(&payload)
                            .key(key.as_str()),
                    )
                    .err()
                    .map(|(error, _)| error),
                None => state
                    .producer
                    .send(BaseRecord::<(), str>::to(&topic).payload(&payload))
                    .err()
                    .map(|(error, _)| error),
            };

            match enqueue_error {
                Some(error) => Err(format!("Kafka logging: failed to enqueue message: {error}")),
                None => Ok(()),
            }
        })
        .await
        .map_err(|error| format!("Kafka logging: producer task join failed: {error}"))??;
    }

    Ok(())
}
