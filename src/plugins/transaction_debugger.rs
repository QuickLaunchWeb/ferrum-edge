//! Transaction debugger plugin — detailed per-request diagnostics.
//!
//! Emits debug output via `tracing::debug!` on the `transaction_debug` target,
//! showing the request/response lifecycle: matched proxy, consumer identity,
//! plugin execution timing, backend connection details, and optionally
//! request/response body logging markers. Sensitive headers (Authorization,
//! Cookie, API keys) are automatically redacted. Intended for development and
//! troubleshooting — should not be enabled in production due to information
//! disclosure risk.

use async_trait::async_trait;
use http::header::HeaderName;
use serde_json::Value;
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext, StreamTransactionSummary, TransactionSummary};

/// Headers that contain sensitive credentials and must be redacted in debug output.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "www-authenticate",
    "x-forwarded-authorization",
];

/// Redaction placeholder for sensitive header values.
const REDACTED: &str = "***REDACTED***";

pub struct TransactionDebugger {
    log_request_body: bool,
    log_response_body: bool,
    /// Additional header names (lowercase) to redact beyond the built-in list.
    extra_redacted_headers: Vec<String>,
}

impl TransactionDebugger {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("transaction_debugger: config must be an object".to_string());
        }

        let extra_redacted_headers =
            optional_header_names(config, "redacted_headers")?.unwrap_or_default();

        Ok(Self {
            log_request_body: optional_bool(config, "log_request_body")?.unwrap_or(false),
            log_response_body: optional_bool(config, "log_response_body")?.unwrap_or(false),
            extra_redacted_headers,
        })
    }

    /// Returns true if the given header name should be redacted.
    /// Header names are normally lowercased by hyper, but tests/custom callers
    /// may provide different ASCII casing; compare case-insensitively without
    /// allocating.
    fn is_sensitive(&self, header_name: &str) -> bool {
        SENSITIVE_HEADERS
            .iter()
            .any(|h| header_name.eq_ignore_ascii_case(h))
            || self
                .extra_redacted_headers
                .iter()
                .any(|h| header_name.eq_ignore_ascii_case(h))
    }

    /// Create a redacted copy of headers for safe logging.
    fn redact_headers(&self, headers: &HashMap<String, String>) -> HashMap<String, String> {
        headers
            .iter()
            .map(|(k, v)| {
                if self.is_sensitive(k) {
                    (k.clone(), REDACTED.to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect()
    }
}

#[async_trait]
impl Plugin for TransactionDebugger {
    fn name(&self) -> &str {
        "transaction_debugger"
    }

    fn priority(&self) -> u16 {
        super::priority::TRANSACTION_DEBUGGER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            let safe_headers = self.redact_headers(&ctx.headers);
            tracing::debug!(target: "transaction_debug", method = %ctx.method, path = %ctx.path, client_ip = %ctx.client_ip, headers = ?safe_headers, "Incoming request");
            if self.log_request_body {
                tracing::debug!(target: "transaction_debug", "Request body logging enabled");
            }
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            let safe_headers = self.redact_headers(response_headers);
            tracing::debug!(target: "transaction_debug", status = response_status, method = %ctx.method, path = %ctx.path, headers = ?safe_headers, "Backend response");
            if self.log_response_body {
                tracing::debug!(target: "transaction_debug", "Response body logging enabled");
            }
        }
        PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if let Some(ref error) = summary.connection_error {
            tracing::debug!(
                target: "transaction_debug",
                protocol = %summary.protocol,
                proxy_id = %summary.proxy_id,
                listen_port = %summary.listen_port,
                backend_target = %summary.backend_target,
                error = %error,
                duration_ms = summary.duration_ms,
                bytes_sent = summary.bytes_sent,
                bytes_received = summary.bytes_received,
                "Stream disconnected with error",
            );
        } else {
            tracing::debug!(
                target: "transaction_debug",
                protocol = %summary.protocol,
                proxy_id = %summary.proxy_id,
                listen_port = %summary.listen_port,
                backend_target = %summary.backend_target,
                duration_ms = summary.duration_ms,
                bytes_sent = summary.bytes_sent,
                bytes_received = summary.bytes_received,
                "Stream disconnected",
            );
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        if let Some(ref error_class) = summary.error_class {
            tracing::debug!(
                target: "transaction_debug",
                method = %summary.http_method,
                path = %summary.request_path,
                status = summary.response_status_code,
                error_class = %error_class,
                latency_total_ms = summary.latency_total_ms,
                latency_plugin_ms = summary.latency_plugin_execution_ms,
                latency_gw_overhead_ms = summary.latency_gateway_overhead_ms,
                "Transaction completed with error",
            );
        } else {
            tracing::debug!(
                target: "transaction_debug",
                method = %summary.http_method,
                path = %summary.request_path,
                status = summary.response_status_code,
                latency_total_ms = summary.latency_total_ms,
                latency_plugin_ms = summary.latency_plugin_execution_ms,
                latency_gw_overhead_ms = summary.latency_gateway_overhead_ms,
                "Transaction completed",
            );
        }
    }
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("transaction_debugger: '{field}' must be a boolean"))
}

fn optional_header_names(
    config: &Value,
    field: &'static str,
) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("transaction_debugger: '{field}' must be an array"));
    };
    let mut headers = Vec::with_capacity(values.len());
    for (idx, value) in values.iter().enumerate() {
        let Some(raw) = value.as_str() else {
            return Err(format!(
                "transaction_debugger: '{field}[{idx}]' must be a string"
            ));
        };
        if raw.is_empty() {
            return Err(format!(
                "transaction_debugger: '{field}[{idx}]' must not be empty"
            ));
        }
        let raw = raw.to_ascii_lowercase();
        let name = HeaderName::from_bytes(raw.as_bytes()).map_err(|_| {
            format!("transaction_debugger: '{field}[{idx}]' is not a valid HTTP header name")
        })?;
        headers.push(name.as_str().to_string());
    }
    Ok(Some(headers))
}
