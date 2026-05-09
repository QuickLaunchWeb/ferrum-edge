//! OpenTelemetry Tracing Plugin
//!
//! Provides W3C Trace Context propagation (traceparent/tracestate headers)
//! and exports spans to an OTLP-compatible collector via HTTP/JSON.
//!
//! When no endpoint is configured, the plugin runs in propagation-only mode:
//! it generates/propagates trace context headers without exporting spans.
//!
//! Optionally exports spans to an OTLP-compatible collector via HTTP/JSON
//! (OTLP/HTTP with JSON encoding, per the OpenTelemetry specification).

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::warn;
use url::Url;
use uuid::Uuid;

use super::mesh::mesh_trace_attributes;
use super::utils::PluginHttpClient;
use super::{Plugin, PluginResult, RequestContext, StreamTransactionSummary, TransactionSummary};

const TRACEPARENT_HEADER: &str = "traceparent";
const TRACESTATE_HEADER: &str = "tracestate";

pub struct OtelTracing {
    /// Service name for spans.
    service_name: String,
    /// Whether to generate trace IDs for requests without traceparent.
    generate_trace_id: bool,
    /// OTLP span sender (if endpoint is configured).
    otlp_sender: Option<mpsc::Sender<SpanData>>,
    /// OTLP endpoint hostname for DNS warmup.
    otlp_hostname: Option<String>,
}

/// Internal span data collected during the request lifecycle.
#[derive(Clone)]
struct SpanData {
    trace_id: String,
    span_id: String,
    parent_span_id: String,
    service_name: String,
    http_method: String,
    http_url: String,
    http_status_code: u16,
    client_ip: String,
    duration_ms: f64,
    gateway_processing_ms: f64,
    backend_ttfb_ms: f64,
    backend_ms: f64,
    plugin_execution_ms: f64,
    gateway_overhead_ms: f64,
    consumer: Option<String>,
    timestamp_received: String,
    // Rich attributes from TransactionSummary
    user_agent: Option<String>,
    proxy_id: Option<String>,
    matched_route: Option<String>,
    backend_target_url: Option<String>,
    backend_resolved_ip: Option<String>,
    error_class: Option<String>,
    response_streamed: bool,
    client_disconnected: bool,
    mesh_attributes: Vec<(String, String)>,
}

struct GeneratedTraceContext {
    trace_id: String,
    span_id: String,
    traceparent: String,
}

struct ParsedTraceParent<'a> {
    version: &'a str,
    trace_id: &'a str,
    parent_span_id: &'a str,
    flags: &'a str,
}

impl OtelTracing {
    pub fn new_with_http_client(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        let service_name = string_config(config, "service_name", "ferrum-edge")?;
        let generate_trace_id = bool_config(config, "generate_trace_id", true)?;

        let deployment_environment = optional_string_config(config, "deployment_environment")?;

        // Endpoint is optional — when absent, plugin runs in propagation-only mode
        let endpoint = optional_string_config(config, "endpoint")?;

        let (otlp_sender, otlp_hostname) = if let Some(endpoint) = endpoint {
            let otlp_hostname = validate_endpoint(&endpoint)?;
            let batch_size = usize_config(config, "batch_size", 50, 1)?;
            let flush_interval_ms = u64_config(config, "flush_interval_ms", 5000, 100)?;
            let buffer_capacity = usize_config(config, "buffer_capacity", 10000, 1)?;
            let authorization = optional_string_config(config, "authorization")?;

            // Parse custom headers from config
            let custom_headers = parse_custom_headers(config.get("headers"))?;

            let (sender, receiver) = mpsc::channel(buffer_capacity);

            let otlp_config = OtlpConfig {
                endpoint,
                authorization,
                custom_headers,
                http_client,
                batch_size,
                flush_interval: Duration::from_millis(flush_interval_ms),
                max_retries: u32_config(config, "max_retries", 2, 0)?,
                retry_delay: Duration::from_millis(u64_config(config, "retry_delay_ms", 1000, 0)?),
                service_name: service_name.clone(),
                deployment_environment: deployment_environment.clone(),
            };

            tokio::spawn(otlp_flush_loop(receiver, otlp_config));

            (Some(sender), Some(otlp_hostname))
        } else {
            (None, None)
        };

        Ok(Self {
            service_name,
            generate_trace_id,
            otlp_sender,
            otlp_hostname,
        })
    }

    /// Generate a W3C trace context without reparsing the generated header.
    fn generate_trace_context() -> GeneratedTraceContext {
        let trace_id = Self::generate_trace_id();
        let span_id = Self::generate_span_id();
        let traceparent = build_traceparent("00", &trace_id, &span_id, "01");
        GeneratedTraceContext {
            trace_id,
            span_id,
            traceparent,
        }
    }

    /// Parse a traceparent header into (version, trace_id, parent_span_id, flags).
    fn parse_traceparent(value: &str) -> Option<ParsedTraceParent<'_>> {
        let mut parts = value.split('-');
        let version = parts.next()?;
        let trace_id = parts.next()?;
        let parent_span_id = parts.next()?;
        let flags = parts.next()?;
        if parts.next().is_some() {
            return None;
        }

        if version.len() != 2
            || trace_id.len() != 32
            || parent_span_id.len() != 16
            || flags.len() != 2
            || version.eq_ignore_ascii_case("ff")
            || !version.chars().all(|c| c.is_ascii_hexdigit())
            || !trace_id.chars().all(|c| c.is_ascii_hexdigit())
            || !parent_span_id.chars().all(|c| c.is_ascii_hexdigit())
            || !flags.chars().all(|c| c.is_ascii_hexdigit())
            || trace_id.chars().all(|c| c == '0')
            || parent_span_id.chars().all(|c| c == '0')
        {
            return None;
        }

        Some(ParsedTraceParent {
            version,
            trace_id,
            parent_span_id,
            flags,
        })
    }

    /// Generate a new trace ID.
    fn generate_trace_id() -> String {
        hex_encode(Uuid::new_v4().as_bytes())
    }

    /// Generate a new span ID for the gateway hop.
    fn generate_span_id() -> String {
        hex_encode(&Uuid::new_v4().as_bytes()[..8])
    }
}

/// Backwards-compatible alias. Prefer `super::priority::OTEL_TRACING`.
#[allow(dead_code)]
pub const OTEL_TRACING_PRIORITY: u16 = super::priority::OTEL_TRACING;

#[async_trait]
impl Plugin for OtelTracing {
    fn name(&self) -> &str {
        "otel_tracing"
    }

    fn priority(&self) -> u16 {
        super::priority::OTEL_TRACING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut super::StreamConnectionContext,
    ) -> super::PluginResult {
        if self.generate_trace_id {
            let trace_id = Self::generate_trace_id();
            let span_id = Self::generate_span_id();
            ctx.insert_metadata("trace_id".to_string(), trace_id);
            ctx.insert_metadata("span_id".to_string(), span_id);
        }
        super::PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let trace_id = match summary.metadata.get("trace_id") {
            Some(id) => id,
            None => return,
        };
        let span_id = summary
            .metadata
            .get("span_id")
            .map(|s| s.as_str())
            .unwrap_or("");

        tracing::info!(
            target: "otel",
            service_name = %self.service_name,
            trace_id = %trace_id,
            span_id = %span_id,
            protocol = %summary.protocol,
            proxy_id = %summary.proxy_id,
            client_ip = %summary.client_ip,
            backend_target = %summary.backend_target,
            duration_ms = %summary.duration_ms,
            bytes_sent = %summary.bytes_sent,
            bytes_received = %summary.bytes_received,
            "stream trace"
        );
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Extract or generate trace context
        let traceparent = if let Some(existing) = ctx.headers.get(TRACEPARENT_HEADER) {
            if let Some(parsed) = Self::parse_traceparent(existing) {
                // Store incoming trace context
                ctx.metadata
                    .insert("trace_id".to_string(), parsed.trace_id.to_string());
                ctx.metadata.insert(
                    "parent_span_id".to_string(),
                    parsed.parent_span_id.to_string(),
                );

                // Generate new span ID for the gateway
                let gateway_span = Self::generate_span_id();
                ctx.metadata
                    .insert("span_id".to_string(), gateway_span.clone());

                build_traceparent(parsed.version, parsed.trace_id, &gateway_span, parsed.flags)
            } else {
                if !self.generate_trace_id {
                    return PluginResult::Continue;
                }

                let generated = Self::generate_trace_context();
                ctx.metadata
                    .insert("trace_id".to_string(), generated.trace_id);
                ctx.metadata
                    .insert("span_id".to_string(), generated.span_id);
                generated.traceparent
            }
        } else if self.generate_trace_id {
            let generated = Self::generate_trace_context();
            ctx.metadata
                .insert("trace_id".to_string(), generated.trace_id);
            ctx.metadata
                .insert("span_id".to_string(), generated.span_id);
            generated.traceparent
        } else {
            return PluginResult::Continue;
        };

        ctx.metadata
            .insert(TRACEPARENT_HEADER.to_string(), traceparent);

        // Preserve tracestate if present
        if let Some(tracestate) = ctx.headers.get(TRACESTATE_HEADER) {
            ctx.metadata
                .insert(TRACESTATE_HEADER.to_string(), tracestate.clone());
        }

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Inject traceparent into outgoing request
        if let Some(traceparent) = ctx.metadata.get(TRACEPARENT_HEADER) {
            headers.insert(TRACEPARENT_HEADER.to_string(), traceparent.clone());
        }
        if let Some(tracestate) = ctx.metadata.get(TRACESTATE_HEADER) {
            headers.insert(TRACESTATE_HEADER.to_string(), tracestate.clone());
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Echo traceparent to the client
        if let Some(traceparent) = ctx.metadata.get(TRACEPARENT_HEADER) {
            response_headers.insert(TRACEPARENT_HEADER.to_string(), traceparent.clone());
        }
        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn log(&self, summary: &TransactionSummary) {
        let trace_id = match summary.metadata.get("trace_id") {
            Some(id) => id,
            None => return,
        };

        let span_id = summary
            .metadata
            .get("span_id")
            .map(|s| s.as_str())
            .unwrap_or("");
        let parent_span_id = summary
            .metadata
            .get("parent_span_id")
            .map(|s| s.as_str())
            .unwrap_or("");

        // Always emit structured log
        tracing::info!(
            target: "otel",
            service_name = %self.service_name,
            trace_id = %trace_id,
            span_id = %span_id,
            parent_span_id = %parent_span_id,
            http_method = %summary.http_method,
            http_url = %summary.request_path,
            http_status_code = %summary.response_status_code,
            http_client_ip = %summary.client_ip,
            duration_ms = %summary.latency_total_ms,
            backend_ms = %summary.latency_backend_total_ms,
            "request trace"
        );

        // Send to OTLP exporter if configured
        if let Some(ref sender) = self.otlp_sender {
            let span_data = SpanData {
                trace_id: trace_id.clone(),
                span_id: span_id.to_string(),
                parent_span_id: parent_span_id.to_string(),
                service_name: self.service_name.clone(),
                http_method: summary.http_method.clone(),
                http_url: summary.request_path.clone(),
                http_status_code: summary.response_status_code,
                client_ip: summary.client_ip.clone(),
                duration_ms: summary.latency_total_ms,
                gateway_processing_ms: summary.latency_gateway_processing_ms,
                backend_ttfb_ms: summary.latency_backend_ttfb_ms,
                backend_ms: summary.latency_backend_total_ms,
                plugin_execution_ms: summary.latency_plugin_execution_ms,
                gateway_overhead_ms: summary.latency_gateway_overhead_ms,
                consumer: summary.consumer_username.clone(),
                timestamp_received: summary.timestamp_received.clone(),
                user_agent: summary.request_user_agent.clone(),
                proxy_id: summary.proxy_id.clone(),
                matched_route: summary.proxy_name.clone(),
                backend_target_url: summary.backend_target_url.clone(),
                backend_resolved_ip: summary.backend_resolved_ip.clone(),
                error_class: summary.error_class.as_ref().map(|e| format!("{e:?}")),
                response_streamed: summary.response_streamed,
                client_disconnected: summary.client_disconnected,
                mesh_attributes: mesh_trace_attributes(&summary.metadata),
            };

            if sender.try_send(span_data).is_err() {
                warn!("OTLP export buffer full — dropping span");
            }
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.otlp_hostname
            .as_ref()
            .map(|h| vec![h.clone()])
            .unwrap_or_default()
    }
}

// ─── OTLP HTTP/JSON Exporter ───────────────────────────────────────────

struct OtlpConfig {
    endpoint: String,
    authorization: Option<String>,
    custom_headers: Vec<(String, String)>,
    http_client: PluginHttpClient,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
    service_name: String,
    deployment_environment: Option<String>,
}

/// Parse custom headers from the `headers` config field.
/// Accepts an object like `{"x-honeycomb-team": "abc", "X-Scope-OrgID": "123"}`.
fn parse_custom_headers(value: Option<&Value>) -> Result<Vec<(String, String)>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Value::Object(map) = value else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        return Err("otel_tracing: 'headers' must be an object".to_string());
    };

    let mut headers = Vec::with_capacity(map.len());
    for (key, value) in map {
        if HeaderName::from_bytes(key.as_bytes()).is_err() {
            return Err(format!(
                "otel_tracing: 'headers' contains an invalid HTTP header name: {key:?}"
            ));
        }
        let Some(value) = value.as_str() else {
            return Err(format!(
                "otel_tracing: 'headers.{key}' must be a string value"
            ));
        };
        if HeaderValue::from_str(value).is_err() {
            return Err(format!(
                "otel_tracing: 'headers.{key}' contains characters not permitted in HTTP header values"
            ));
        }
        headers.push((key.clone(), value.to_string()));
    }
    Ok(headers)
}

async fn otlp_flush_loop(mut receiver: mpsc::Receiver<SpanData>, cfg: OtlpConfig) {
    let mut buffer: Vec<SpanData> = Vec::with_capacity(cfg.batch_size);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    timer.tick().await; // skip first immediate tick

    loop {
        tokio::select! {
            biased;

            msg = receiver.recv() => {
                match msg {
                    Some(span) => {
                        buffer.push(span);
                        if buffer.len() >= cfg.batch_size {
                            send_otlp_batch(&cfg, &buffer).await;
                            buffer.clear();
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            send_otlp_batch(&cfg, &buffer).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    send_otlp_batch(&cfg, &buffer).await;
                    buffer.clear();
                }
            }
        }
    }
}

async fn send_otlp_batch(cfg: &OtlpConfig, batch: &[SpanData]) {
    let total_attempts = cfg.max_retries + 1;
    let entry_count = batch.len();
    let payload = build_otlp_payload(
        &cfg.service_name,
        cfg.deployment_environment.as_deref(),
        batch,
    );

    for attempt in 1..=total_attempts {
        let mut req = cfg
            .http_client
            .get()
            .post(&cfg.endpoint)
            .header("Content-Type", "application/json")
            .json(&payload);

        if let Some(auth) = &cfg.authorization {
            req = req.header("Authorization", auth);
        }

        for (key, value) in &cfg.custom_headers {
            req = req.header(key.as_str(), value.as_str());
        }

        match cfg.http_client.execute(req, "otel_export").await {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => {
                let status = response.status();
                warn!(
                    "OTLP export failed with status {} (attempt {}/{})",
                    status, attempt, total_attempts,
                );
                // 4xx is a client error — retrying a malformed/unauthorized
                // payload just delays the drop. Bail immediately, except for
                // 408 (Request Timeout) and 429 (Too Many Requests) which are
                // transient and worth retrying within the configured budget.
                if status.is_client_error()
                    && status != reqwest::StatusCode::REQUEST_TIMEOUT
                    && status != reqwest::StatusCode::TOO_MANY_REQUESTS
                {
                    warn!(
                        "OTLP export batch discarded due to {} response ({} spans lost)",
                        status, entry_count,
                    );
                    return;
                }
            }
            Err(e) => {
                warn!(
                    "OTLP export failed: {} (attempt {}/{})",
                    e, attempt, total_attempts,
                );
            }
        }
        if attempt < total_attempts {
            tokio::time::sleep(cfg.retry_delay).await;
        }
    }

    warn!(
        "OTLP export batch discarded after {} attempts ({} spans lost)",
        total_attempts, entry_count,
    );
}

/// Build an OTLP/HTTP JSON payload conforming to the OpenTelemetry
/// Trace Export specification.
///
/// Format: ExportTraceServiceRequest with ResourceSpans → ScopeSpans → Spans.
/// See: https://opentelemetry.io/docs/specs/otlp/#otlphttp-request
fn build_otlp_payload(
    service_name: &str,
    deployment_environment: Option<&str>,
    spans: &[SpanData],
) -> Value {
    let otlp_spans: Vec<Value> = spans
        .iter()
        .map(|s| {
            // Convert trace_id (32 hex) and span_id (16 hex) to base64 byte arrays
            let trace_id_bytes = hex_to_base64(&s.trace_id);
            let span_id_bytes = hex_to_base64(&s.span_id);
            let parent_span_bytes = if s.parent_span_id.is_empty() {
                String::new()
            } else {
                hex_to_base64(&s.parent_span_id)
            };

            // Parse start time from ISO 8601 timestamp
            let start_ns = chrono::DateTime::parse_from_rfc3339(&s.timestamp_received)
                .map(|dt| dt.timestamp_nanos_opt().unwrap_or(0))
                .unwrap_or(0);
            let end_ns = start_ns + (s.duration_ms * 1_000_000.0) as i64;

            let mut attributes = vec![
                otlp_attribute("http.request.method", &s.http_method),
                otlp_attribute("url.path", &s.http_url),
                otlp_attribute_int("http.response.status_code", s.http_status_code as i64),
                otlp_attribute("client.address", &s.client_ip),
                otlp_attribute("service.name", &s.service_name),
                otlp_attribute_double("gateway.latency.total_ms", s.duration_ms),
                otlp_attribute_double("gateway.latency.processing_ms", s.gateway_processing_ms),
                otlp_attribute_double("gateway.latency.backend_ttfb_ms", s.backend_ttfb_ms),
            ];

            if s.backend_ms >= 0.0 {
                attributes.push(otlp_attribute_double(
                    "gateway.latency.backend_total_ms",
                    s.backend_ms,
                ));
            }
            attributes.push(otlp_attribute_double(
                "gateway.plugin_execution_ms",
                s.plugin_execution_ms,
            ));
            attributes.push(otlp_attribute_double(
                "gateway.overhead_ms",
                s.gateway_overhead_ms,
            ));
            if let Some(ref consumer) = s.consumer {
                attributes.push(otlp_attribute("enduser.id", consumer));
            }
            if let Some(ref ua) = s.user_agent {
                attributes.push(otlp_attribute("user_agent.original", ua));
            }
            if let Some(ref proxy_id) = s.proxy_id {
                attributes.push(otlp_attribute("gateway.proxy.id", proxy_id));
            }
            if let Some(ref route) = s.matched_route {
                attributes.push(otlp_attribute("http.route", route));
            }
            if let Some(ref target) = s.backend_target_url {
                attributes.push(otlp_attribute("server.address", target));
            }
            if let Some(ref resolved) = s.backend_resolved_ip {
                attributes.push(otlp_attribute("server.socket.address", resolved));
            }
            if s.response_streamed {
                attributes.push(otlp_attribute_bool("gateway.response.streamed", true));
            }
            if s.client_disconnected {
                attributes.push(otlp_attribute_bool("gateway.client.disconnected", true));
            }
            for (key, value) in &s.mesh_attributes {
                attributes.push(otlp_attribute(key, value));
            }

            // Build span events for error conditions
            let mut events = Vec::new();
            if let Some(ref error_class) = s.error_class {
                events.push(serde_json::json!({
                    "name": "exception",
                    "timeUnixNano": end_ns.to_string(),
                    "attributes": [
                        otlp_attribute("exception.type", "GatewayError"),
                        otlp_attribute("exception.message", error_class),
                    ]
                }));
            }
            if s.client_disconnected {
                events.push(serde_json::json!({
                    "name": "client.disconnect",
                    "timeUnixNano": end_ns.to_string(),
                    "attributes": []
                }));
            }

            let status_code = if s.http_status_code >= 500 {
                2 // ERROR
            } else {
                1 // OK (includes 4xx — client errors are not server errors)
            };

            let mut span = serde_json::json!({
                "traceId": trace_id_bytes,
                "spanId": span_id_bytes,
                "name": format!("{} {}", s.http_method, s.http_url),
                "kind": 2, // SPAN_KIND_SERVER
                "startTimeUnixNano": start_ns.to_string(),
                "endTimeUnixNano": end_ns.to_string(),
                "attributes": attributes,
                "status": {
                    "code": status_code
                }
            });

            if !parent_span_bytes.is_empty() {
                span["parentSpanId"] = Value::String(parent_span_bytes);
            }
            if !events.is_empty() {
                span["events"] = Value::Array(events);
            }

            span
        })
        .collect();

    // Build resource attributes
    let mut resource_attributes = vec![otlp_attribute("service.name", service_name)];
    resource_attributes.push(otlp_attribute("service.version", env!("CARGO_PKG_VERSION")));
    resource_attributes.push(otlp_attribute("telemetry.sdk.name", "ferrum-edge"));
    resource_attributes.push(otlp_attribute(
        "telemetry.sdk.version",
        env!("CARGO_PKG_VERSION"),
    ));
    if let Some(env) = deployment_environment {
        resource_attributes.push(otlp_attribute("deployment.environment", env));
    }

    serde_json::json!({
        "resourceSpans": [{
            "resource": {
                "attributes": resource_attributes
            },
            "scopeSpans": [{
                "scope": {
                    "name": "ferrum-edge",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "spans": otlp_spans
            }]
        }]
    })
}

fn string_config(config: &Value, key: &str, default: &str) -> Result<String, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default.to_string()),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(format!("otel_tracing: '{key}' must be a non-empty string"))
            } else {
                Ok(trimmed.to_string())
            }
        }
        Some(other) => Err(format!(
            "otel_tracing: '{key}' must be a string, got: {other}"
        )),
    }
}

fn optional_string_config(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Some(other) => Err(format!(
            "otel_tracing: '{key}' must be a string, got: {other}"
        )),
    }
}

fn bool_config(config: &Value, key: &str, default: bool) -> Result<bool, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!(
            "otel_tracing: '{key}' must be a boolean, got: {other}"
        )),
    }
}

fn u64_config(config: &Value, key: &str, default: u64, min: u64) -> Result<u64, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default.max(min)),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(|n| n.max(min))
            .ok_or_else(|| format!("otel_tracing: '{key}' must be a non-negative integer")),
        Some(other) => Err(format!(
            "otel_tracing: '{key}' must be a non-negative integer, got: {other}"
        )),
    }
}

fn usize_config(config: &Value, key: &str, default: usize, min: usize) -> Result<usize, String> {
    let value = u64_config(config, key, default as u64, min as u64)?;
    usize::try_from(value).map_err(|_| format!("otel_tracing: '{key}' is too large"))
}

fn u32_config(config: &Value, key: &str, default: u32, min: u32) -> Result<u32, String> {
    let value = u64_config(config, key, default as u64, min as u64)?;
    u32::try_from(value).map_err(|_| format!("otel_tracing: '{key}' is too large"))
}

fn validate_endpoint(endpoint: &str) -> Result<String, String> {
    let url = Url::parse(endpoint)
        .map_err(|e| format!("otel_tracing: 'endpoint' must be a valid URL: {e}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "otel_tracing: 'endpoint' scheme must be http or https, got: {scheme}"
            ));
        }
    }
    url.host_str()
        .filter(|host| !host.is_empty())
        .map(|host| host.to_string())
        .ok_or_else(|| "otel_tracing: 'endpoint' must include a hostname".to_string())
}

fn build_traceparent(version: &str, trace_id: &str, span_id: &str, flags: &str) -> String {
    let mut traceparent =
        String::with_capacity(version.len() + trace_id.len() + span_id.len() + flags.len() + 3);
    traceparent.push_str(version);
    traceparent.push('-');
    traceparent.push_str(trace_id);
    traceparent.push('-');
    traceparent.push_str(span_id);
    traceparent.push('-');
    traceparent.push_str(flags);
    traceparent
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn otlp_attribute(key: &str, value: &str) -> Value {
    serde_json::json!({
        "key": key,
        "value": { "stringValue": value }
    })
}

fn otlp_attribute_int(key: &str, value: i64) -> Value {
    serde_json::json!({
        "key": key,
        "value": { "intValue": value.to_string() }
    })
}

fn otlp_attribute_double(key: &str, value: f64) -> Value {
    serde_json::json!({
        "key": key,
        "value": { "doubleValue": value }
    })
}

fn otlp_attribute_bool(key: &str, value: bool) -> Value {
    serde_json::json!({
        "key": key,
        "value": { "boolValue": value }
    })
}

/// Convert a hex string to base64-encoded bytes (OTLP/HTTP JSON encoding).
///
/// Per the OpenTelemetry spec, `traceId` (16 bytes / 32 hex chars) and
/// `spanId` (8 bytes / 16 hex chars) are JSON-encoded as base64-standard
/// strings. Callers in this module always pass even-length hex (validated
/// upstream by `parse_traceparent` / produced by `generate_traceparent`),
/// but the implementation is robust against odd-length input — the trailing
/// half-byte is dropped rather than panicking on a slice out of bounds.
fn hex_to_base64(hex: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            let end = i + 2;
            if end > hex.len() {
                return None;
            }
            u8::from_str_radix(&hex[i..end], 16).ok()
        })
        .collect();

    STANDARD.encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_base64_decodes_even_length_input() {
        // Standard 16-byte trace_id (32 hex chars).
        let hex = "4bf92f3577b34da6a3ce929d0e0e4736";
        let encoded = hex_to_base64(hex);
        // base64.b64encode(bytes.fromhex(...)) == "S/kvNXezTaajzpKdDg5HNg=="
        assert_eq!(encoded, "S/kvNXezTaajzpKdDg5HNg==");
    }

    #[test]
    fn hex_to_base64_decodes_8_byte_span_id() {
        // Standard 8-byte span_id (16 hex chars).
        let hex = "00f067aa0ba902b7";
        let encoded = hex_to_base64(hex);
        assert_eq!(encoded, "APBnqgupArc=");
    }

    #[test]
    fn hex_to_base64_handles_empty_input() {
        assert_eq!(hex_to_base64(""), "");
    }

    #[test]
    fn hex_to_base64_handles_odd_length_without_panic() {
        // Defensive: odd-length should not panic. The trailing half-byte
        // is dropped (the final iteration would slice past hex.len() and
        // is filtered out via the `end > hex.len()` guard).
        let _ = hex_to_base64("abc");
        let _ = hex_to_base64("4bf92f3577b34da6a3ce929d0e0e473");
    }

    #[test]
    fn hex_to_base64_invalid_chars_filtered() {
        // Non-hex chars are filtered out via from_str_radix Err.
        let encoded = hex_to_base64("XX");
        assert_eq!(encoded, ""); // no valid bytes decoded
    }

    #[test]
    fn otlp_payload_includes_mesh_identity_attributes() {
        let span = SpanData {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            parent_span_id: String::new(),
            service_name: "ferrum-edge".to_string(),
            http_method: "GET".to_string(),
            http_url: "/".to_string(),
            http_status_code: 200,
            client_ip: "127.0.0.1".to_string(),
            duration_ms: 10.0,
            gateway_processing_ms: 1.0,
            backend_ttfb_ms: 2.0,
            backend_ms: 3.0,
            plugin_execution_ms: 1.0,
            gateway_overhead_ms: 1.0,
            consumer: None,
            timestamp_received: "2025-01-01T00:00:00Z".to_string(),
            user_agent: None,
            proxy_id: Some("proxy-a".to_string()),
            matched_route: Some("payments".to_string()),
            backend_target_url: None,
            backend_resolved_ip: None,
            error_class: None,
            response_streamed: false,
            client_disconnected: false,
            mesh_attributes: vec![
                (
                    "mesh.source.principal".to_string(),
                    "spiffe://cluster.local/ns/default/sa/frontend".to_string(),
                ),
                (
                    "mesh.destination.service".to_string(),
                    "payments".to_string(),
                ),
            ],
        };

        let payload = build_otlp_payload("ferrum-edge", None, &[span]);
        let attributes = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
            .as_array()
            .unwrap();

        assert!(attributes.iter().any(|attribute| {
            attribute["key"] == "mesh.source.principal"
                && attribute["value"]["stringValue"]
                    == "spiffe://cluster.local/ns/default/sa/frontend"
        }));
        assert!(attributes.iter().any(|attribute| {
            attribute["key"] == "mesh.destination.service"
                && attribute["value"]["stringValue"] == "payments"
        }));
    }
}
