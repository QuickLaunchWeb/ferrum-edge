//! Serde wrapper that applies a [`SummarySchema`] at serialize time.
//!
//! `SchemaView<'a, T: SchemaSerializable>` implements [`serde::Serialize`]
//! by walking the compiled `fields` vec and dispatching native field
//! emission to the typed summary via the trait. Static and derived fields
//! are handled inline; metadata is delegated back through
//! `serialize_redacted_metadata` so redaction is preserved on every path.

use std::collections::HashSet;

use serde::Serializer;
use serde::ser::{Serialize, SerializeMap};

use super::{
    CollisionMode, DerivedKind, FieldSpec, MetadataPolicy, SummarySchema, TimestampFormat,
};
use crate::plugins::utils::log_helpers::SummaryLogEntry;
use crate::plugins::utils::metadata_redaction::{REDACTED_PLACEHOLDER, is_sensitive_metadata_key};
use crate::plugins::{StreamTransactionSummary, TransactionSummary};

/// Bridge between a typed summary and the schema serializer. Each native
/// field name is dispatched here so the typed value is emitted with
/// `serialize_entry` — no intermediate `serde_json::Value`.
pub trait SchemaSerializable {
    /// Emit a native field by its source name under `out_key`. No-op if
    /// `source` doesn't match a field on this struct (schema may include
    /// fields from the other summary type in `SummaryType::Both` mode).
    /// Native `skip_serializing_if` semantics are preserved.
    fn serialize_native<S>(
        &self,
        source: &'static str,
        out_key: &str,
        ts_format: TimestampFormat,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap;

    /// Emit a derived value under `out_key`. Returns `Ok(false)` when the
    /// kind doesn't apply to this summary type (e.g. `StatusClass` on a
    /// stream summary) so the caller knows whether the key was emitted.
    fn serialize_derived<S>(
        &self,
        kind: DerivedKind,
        out_key: &str,
        map: &mut S,
    ) -> Result<bool, S::Error>
    where
        S: SerializeMap;

    /// Emit metadata according to `policy`. Sensitive keys must be
    /// redacted; pass `emitted` so flatten can avoid colliding with
    /// already-emitted top-level keys.
    fn serialize_metadata<S>(
        &self,
        policy: &MetadataPolicy,
        emitted: &mut HashSet<String>,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap;
}

/// Schema-aware view over a typed summary.
pub struct SchemaView<'a, T: SchemaSerializable> {
    pub summary: &'a T,
    pub schema: &'a SummarySchema,
}

impl<'a, T: SchemaSerializable> Serialize for SchemaView<'a, T> {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = ser.serialize_map(None)?;

        // The emitted-key set is ONLY consulted by `flatten_metadata` for
        // collision detection. For `Nested` / `Omit` policies it is dead
        // weight — populating it for every native / static / derived
        // entry would force a `String` clone per field on every log call
        // and a per-call `HashSet` allocation. Gate it.
        let track_emitted = matches!(self.schema.metadata, MetadataPolicy::Flatten { .. });
        let mut emitted: HashSet<String> = if track_emitted {
            HashSet::with_capacity(self.schema.fields.len() + 8)
        } else {
            HashSet::new()
        };

        for spec in &self.schema.fields {
            match spec {
                FieldSpec::Native {
                    source,
                    out_key,
                    is_timestamp,
                } => {
                    let ts_format = if *is_timestamp {
                        self.schema.timestamp_format
                    } else {
                        TimestampFormat::Rfc3339
                    };
                    self.summary
                        .serialize_native(source, out_key, ts_format, &mut map)?;
                    if track_emitted {
                        emitted.insert(out_key.clone());
                    }
                }
                FieldSpec::Static { out_key, value } => {
                    map.serialize_entry(out_key, value)?;
                    if track_emitted {
                        emitted.insert(out_key.clone());
                    }
                }
                FieldSpec::Derived { out_key, kind } => {
                    let emitted_now = self.summary.serialize_derived(*kind, out_key, &mut map)?;
                    if track_emitted && emitted_now {
                        emitted.insert(out_key.clone());
                    }
                }
            }
        }

        self.summary
            .serialize_metadata(&self.schema.metadata, &mut emitted, &mut map)?;

        map.end()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn emit_timestamp<S: SerializeMap>(
    out_key: &str,
    rfc3339: &str,
    ts_format: TimestampFormat,
    map: &mut S,
) -> Result<(), S::Error> {
    match ts_format {
        TimestampFormat::Rfc3339 => map.serialize_entry(out_key, rfc3339),
        TimestampFormat::EpochMs => match chrono::DateTime::parse_from_rfc3339(rfc3339) {
            Ok(dt) => map.serialize_entry(out_key, &dt.timestamp_millis()),
            Err(_) => map.serialize_entry(out_key, rfc3339),
        },
        TimestampFormat::EpochS => match chrono::DateTime::parse_from_rfc3339(rfc3339) {
            Ok(dt) => map.serialize_entry(out_key, &dt.timestamp()),
            Err(_) => map.serialize_entry(out_key, rfc3339),
        },
    }
}

fn extract_host_from_url(s: &str) -> Option<&str> {
    // Strip scheme.
    let after_scheme = if let Some(idx) = s.find("://") {
        &s[idx + 3..]
    } else {
        s
    };
    // Take up to next `/`, `?`, or `#`.
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let host_port = &after_scheme[..end];
    if host_port.is_empty() {
        return None;
    }
    // Trim trailing port. IPv6 is bracketed: `[::1]:8080`.
    if let Some(rest) = host_port.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return Some(&rest[..end]);
    }
    Some(match host_port.rfind(':') {
        Some(idx) => &host_port[..idx],
        None => host_port,
    })
}

fn status_class(code: u16) -> &'static str {
    match code {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

fn flatten_key(key: &str, prefix: Option<&str>) -> String {
    match prefix {
        Some(p) => {
            let mut out = String::with_capacity(p.len() + key.len());
            out.push_str(p);
            out.push_str(key);
            out
        }
        None => key.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Impl for TransactionSummary
// ---------------------------------------------------------------------------

impl SchemaSerializable for TransactionSummary {
    fn serialize_native<S>(
        &self,
        source: &'static str,
        out_key: &str,
        ts_format: TimestampFormat,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        match source {
            "namespace" => map.serialize_entry(out_key, &self.namespace),
            "timestamp_received" => {
                emit_timestamp(out_key, &self.timestamp_received, ts_format, map)
            }
            "client_ip" => map.serialize_entry(out_key, &self.client_ip),
            "consumer_username" => map.serialize_entry(out_key, &self.consumer_username),
            "auth_method" => match self.auth_method {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "http_method" => map.serialize_entry(out_key, &self.http_method),
            "request_path" => map.serialize_entry(out_key, &self.request_path),
            "proxy_id" => match &self.proxy_id {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "proxy_name" => match &self.proxy_name {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "backend_target_url" => map.serialize_entry(out_key, &self.backend_target_url),
            "backend_resolved_ip" => match &self.backend_resolved_ip {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "response_status_code" => map.serialize_entry(out_key, &self.response_status_code),
            "latency_total_ms" => map.serialize_entry(out_key, &self.latency_total_ms),
            "latency_gateway_processing_ms" => {
                map.serialize_entry(out_key, &self.latency_gateway_processing_ms)
            }
            "latency_backend_ttfb_ms" => {
                map.serialize_entry(out_key, &self.latency_backend_ttfb_ms)
            }
            "latency_backend_total_ms" => {
                map.serialize_entry(out_key, &self.latency_backend_total_ms)
            }
            "latency_plugin_execution_ms" => {
                map.serialize_entry(out_key, &self.latency_plugin_execution_ms)
            }
            "latency_plugin_external_io_ms" => {
                map.serialize_entry(out_key, &self.latency_plugin_external_io_ms)
            }
            "latency_gateway_overhead_ms" => {
                map.serialize_entry(out_key, &self.latency_gateway_overhead_ms)
            }
            "request_user_agent" => map.serialize_entry(out_key, &self.request_user_agent),
            "response_streamed" => {
                if self.response_streamed {
                    map.serialize_entry(out_key, &true)
                } else {
                    Ok(())
                }
            }
            "client_disconnected" => {
                if self.client_disconnected {
                    map.serialize_entry(out_key, &true)
                } else {
                    Ok(())
                }
            }
            "error_class" => match &self.error_class {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "body_error_class" => match &self.body_error_class {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "body_completed" => {
                if self.body_completed {
                    map.serialize_entry(out_key, &true)
                } else {
                    Ok(())
                }
            }
            "request_bytes" => {
                if self.request_bytes != 0 {
                    map.serialize_entry(out_key, &self.request_bytes)
                } else {
                    Ok(())
                }
            }
            "response_bytes" => {
                if self.response_bytes != 0 {
                    map.serialize_entry(out_key, &self.response_bytes)
                } else {
                    Ok(())
                }
            }
            "mirror" => {
                if self.mirror {
                    map.serialize_entry(out_key, &true)
                } else {
                    Ok(())
                }
            }
            "metadata" => map.serialize_entry(out_key, &MetadataNested(&self.metadata)),
            // Unknown / stream-only sources are silently skipped — compile()
            // already validated names against the registry for the schema's
            // summary_type. SummaryType::Both schemas legitimately include
            // names that don't apply here.
            _ => Ok(()),
        }
    }

    fn serialize_derived<S>(
        &self,
        kind: DerivedKind,
        out_key: &str,
        map: &mut S,
    ) -> Result<bool, S::Error>
    where
        S: SerializeMap,
    {
        match kind {
            DerivedKind::StatusClass => {
                let s = status_class(self.response_status_code);
                map.serialize_entry(out_key, s)?;
                Ok(true)
            }
            DerivedKind::BackendHost => match &self.backend_target_url {
                Some(url) => match extract_host_from_url(url) {
                    Some(h) => {
                        map.serialize_entry(out_key, h)?;
                        Ok(true)
                    }
                    None => Ok(false),
                },
                None => Ok(false),
            },
            DerivedKind::SummaryKind => {
                map.serialize_entry(out_key, "http")?;
                Ok(true)
            }
            DerivedKind::Outcome => {
                let is_error = self.response_status_code >= 500
                    || self.error_class.is_some()
                    || self.body_error_class.is_some();
                map.serialize_entry(out_key, if is_error { "error" } else { "ok" })?;
                Ok(true)
            }
        }
    }

    fn serialize_metadata<S>(
        &self,
        policy: &MetadataPolicy,
        emitted: &mut HashSet<String>,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        match policy {
            MetadataPolicy::Nested => Ok(()), // already emitted in main loop
            MetadataPolicy::Omit => Ok(()),
            MetadataPolicy::Flatten {
                prefix,
                on_collision,
            } => flatten_metadata(
                &self.metadata,
                prefix.as_deref(),
                *on_collision,
                emitted,
                map,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Impl for StreamTransactionSummary
// ---------------------------------------------------------------------------

impl SchemaSerializable for StreamTransactionSummary {
    fn serialize_native<S>(
        &self,
        source: &'static str,
        out_key: &str,
        ts_format: TimestampFormat,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        match source {
            "namespace" => map.serialize_entry(out_key, &self.namespace),
            "proxy_id" => map.serialize_entry(out_key, &self.proxy_id),
            "proxy_name" => map.serialize_entry(out_key, &self.proxy_name),
            "client_ip" => map.serialize_entry(out_key, &self.client_ip),
            "consumer_username" => match &self.consumer_username {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "auth_method" => match self.auth_method {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "backend_target" => map.serialize_entry(out_key, &self.backend_target),
            "backend_resolved_ip" => match &self.backend_resolved_ip {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "protocol" => map.serialize_entry(out_key, &self.protocol),
            "listen_port" => map.serialize_entry(out_key, &self.listen_port),
            "duration_ms" => map.serialize_entry(out_key, &self.duration_ms),
            "bytes_sent" => map.serialize_entry(out_key, &self.bytes_sent),
            "bytes_received" => map.serialize_entry(out_key, &self.bytes_received),
            "connection_error" => map.serialize_entry(out_key, &self.connection_error),
            "error_class" => match &self.error_class {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "disconnect_direction" => match &self.disconnect_direction {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "disconnect_cause" => match &self.disconnect_cause {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "timestamp_connected" => {
                emit_timestamp(out_key, &self.timestamp_connected, ts_format, map)
            }
            "timestamp_disconnected" => {
                emit_timestamp(out_key, &self.timestamp_disconnected, ts_format, map)
            }
            "sni_hostname" => match &self.sni_hostname {
                Some(v) => map.serialize_entry(out_key, v),
                None => Ok(()),
            },
            "metadata" => {
                // Preserve the native "skip if empty" semantic.
                if !self.metadata.is_empty() {
                    map.serialize_entry(out_key, &MetadataNested(&self.metadata))?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn serialize_derived<S>(
        &self,
        kind: DerivedKind,
        out_key: &str,
        map: &mut S,
    ) -> Result<bool, S::Error>
    where
        S: SerializeMap,
    {
        use crate::plugins::DisconnectCause;
        match kind {
            DerivedKind::StatusClass => {
                // Stream summaries have no HTTP status — emit a stable
                // sentinel so dashboards don't see the key occasionally
                // missing.
                map.serialize_entry(out_key, "none")?;
                Ok(true)
            }
            DerivedKind::BackendHost => match extract_host_from_url(&self.backend_target) {
                Some(h) => {
                    map.serialize_entry(out_key, h)?;
                    Ok(true)
                }
                None => Ok(false),
            },
            DerivedKind::SummaryKind => {
                map.serialize_entry(out_key, "stream")?;
                Ok(true)
            }
            DerivedKind::Outcome => {
                let is_error = self.connection_error.is_some()
                    || self.error_class.is_some()
                    || matches!(self.disconnect_cause, Some(DisconnectCause::BackendError));
                map.serialize_entry(out_key, if is_error { "error" } else { "ok" })?;
                Ok(true)
            }
        }
    }

    fn serialize_metadata<S>(
        &self,
        policy: &MetadataPolicy,
        emitted: &mut HashSet<String>,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        match policy {
            MetadataPolicy::Nested => Ok(()),
            MetadataPolicy::Omit => Ok(()),
            MetadataPolicy::Flatten {
                prefix,
                on_collision,
            } => flatten_metadata(
                &self.metadata,
                prefix.as_deref(),
                *on_collision,
                emitted,
                map,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Metadata helpers
// ---------------------------------------------------------------------------

/// Wrapper that serializes a metadata HashMap with redaction. Used when
/// metadata is emitted as a nested object.
struct MetadataNested<'a>(&'a std::collections::HashMap<String, String>);

impl<'a> Serialize for MetadataNested<'a> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        crate::plugins::utils::metadata_redaction::serialize_redacted_metadata(self.0, ser)
    }
}

fn flatten_metadata<S>(
    metadata: &std::collections::HashMap<String, String>,
    prefix: Option<&str>,
    on_collision: CollisionMode,
    emitted: &mut HashSet<String>,
    map: &mut S,
) -> Result<(), S::Error>
where
    S: SerializeMap,
{
    for (key, value) in metadata {
        let out_key = flatten_key(key, prefix);
        if emitted.contains(&out_key) {
            match on_collision {
                CollisionMode::Skip => continue,
                CollisionMode::Overwrite => {
                    // JSON semantics: duplicate key emission — most parsers
                    // take the last value. Documented behavior.
                }
            }
        }
        if is_sensitive_metadata_key(key) {
            map.serialize_entry(&out_key, REDACTED_PLACEHOLDER)?;
        } else {
            map.serialize_entry(&out_key, value)?;
        }
        emitted.insert(out_key);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SummaryLogEntry view (for batched logging plugins)
// ---------------------------------------------------------------------------

/// Wraps a [`SummaryLogEntry`] with a schema; dispatches to the right
/// [`SchemaView`] based on the variant. When the schema's `summary_type`
/// doesn't cover this entry's variant, the entry is serialized in its
/// native format (the schema only customizes types it claims to handle).
pub struct SummaryLogEntryView<'a> {
    pub entry: &'a SummaryLogEntry,
    pub schema: &'a SummarySchema,
}

impl<'a> Serialize for SummaryLogEntryView<'a> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self.entry {
            SummaryLogEntry::Http(summary) => {
                if self.schema.applies_to_http() {
                    SchemaView {
                        summary,
                        schema: self.schema,
                    }
                    .serialize(ser)
                } else {
                    summary.serialize(ser)
                }
            }
            SummaryLogEntry::Stream(summary) => {
                if self.schema.applies_to_stream() {
                    SchemaView {
                        summary,
                        schema: self.schema,
                    }
                    .serialize(ser)
                } else {
                    summary.serialize(ser)
                }
            }
        }
    }
}

/// Wraps a slice of [`SummaryLogEntry`] values for batched logging
/// plugins (`http_logging`, `udp_logging`, `ws_logging`). Each entry is
/// rendered through [`SummaryLogEntryView`] when a schema is provided.
pub struct SummaryLogEntryBatchView<'a> {
    pub entries: &'a [SummaryLogEntry],
    pub schema: Option<&'a SummarySchema>,
}

impl<'a> Serialize for SummaryLogEntryBatchView<'a> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = ser.serialize_seq(Some(self.entries.len()))?;
        match self.schema {
            Some(schema) => {
                for entry in self.entries {
                    seq.serialize_element(&SummaryLogEntryView { entry, schema })?;
                }
            }
            None => {
                for entry in self.entries {
                    seq.serialize_element(entry)?;
                }
            }
        }
        seq.end()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{
        Direction, DisconnectCause, StreamTransactionSummary, TransactionSummary,
    };
    use serde_json::{Value, json};
    use std::collections::HashMap;

    fn http_summary() -> TransactionSummary {
        TransactionSummary {
            namespace: "ferrum".into(),
            timestamp_received: "2026-05-11T12:00:00Z".into(),
            client_ip: "10.0.0.1".into(),
            consumer_username: Some("alice".into()),
            http_method: "GET".into(),
            request_path: "/api/v1/things".into(),
            proxy_id: Some("p1".into()),
            proxy_name: Some("things-api".into()),
            backend_target_url: Some("https://backend.example.com:8443/things".into()),
            response_status_code: 200,
            latency_total_ms: 12.5,
            response_bytes: 1024,
            metadata: HashMap::from([
                ("trace_id".to_string(), "abc-123".to_string()),
                ("authorization".to_string(), "Bearer secret".to_string()),
            ]),
            ..TransactionSummary::default()
        }
    }

    fn stream_summary() -> StreamTransactionSummary {
        StreamTransactionSummary {
            namespace: "ferrum".into(),
            proxy_id: "tcp-p1".into(),
            proxy_name: Some("postgres-front".into()),
            client_ip: "10.0.0.2".into(),
            consumer_username: None,
            auth_method: None,
            backend_target: "10.5.0.10:5432".into(),
            backend_resolved_ip: None,
            protocol: "tcp".into(),
            listen_port: 5432,
            duration_ms: 100.0,
            bytes_sent: 200,
            bytes_received: 400,
            connection_error: None,
            error_class: None,
            disconnect_direction: Some(Direction::BackendToClient),
            disconnect_cause: Some(DisconnectCause::GracefulShutdown),
            timestamp_connected: "2026-05-11T12:00:00Z".into(),
            timestamp_disconnected: "2026-05-11T12:01:40Z".into(),
            sni_hostname: None,
            metadata: HashMap::from([("session_id".to_string(), "xyz".to_string())]),
        }
    }

    fn serialize_via(summary: &TransactionSummary, raw_schema: Value) -> Value {
        let schema = SummarySchema::compile(&raw_schema, "test").unwrap();
        let view = SchemaView {
            summary,
            schema: &schema,
        };
        serde_json::to_value(view).unwrap()
    }

    fn serialize_stream(summary: &StreamTransactionSummary, raw_schema: Value) -> Value {
        let schema = SummarySchema::compile(&raw_schema, "test").unwrap();
        let view = SchemaView {
            summary,
            schema: &schema,
        };
        serde_json::to_value(view).unwrap()
    }

    #[test]
    fn rename_emits_new_key() {
        let v = serialize_via(
            &http_summary(),
            json!({ "summary_type": "http", "rename": { "proxy_id": "route_id" } }),
        );
        assert_eq!(v.get("route_id").and_then(Value::as_str), Some("p1"));
        assert!(v.get("proxy_id").is_none());
    }

    #[test]
    fn omit_drops_field() {
        let v = serialize_via(
            &http_summary(),
            json!({ "summary_type": "http", "omit": ["namespace"] }),
        );
        assert!(v.get("namespace").is_none());
    }

    #[test]
    fn static_field_emitted_as_literal() {
        let v = serialize_via(
            &http_summary(),
            json!({
                "summary_type": "http",
                "static_fields": { "env": "production", "shard": 7 }
            }),
        );
        assert_eq!(v.get("env").and_then(Value::as_str), Some("production"));
        assert_eq!(v.get("shard").and_then(Value::as_u64), Some(7));
    }

    #[test]
    fn derived_status_class_2xx() {
        let v = serialize_via(
            &http_summary(),
            json!({
                "summary_type": "http",
                "derived_fields": [{ "name": "status_class", "kind": "status_class" }]
            }),
        );
        assert_eq!(v.get("status_class").and_then(Value::as_str), Some("2xx"));
    }

    #[test]
    fn derived_outcome_error_on_5xx() {
        let mut s = http_summary();
        s.response_status_code = 503;
        let v = serialize_via(
            &s,
            json!({
                "summary_type": "http",
                "derived_fields": [{ "name": "outcome", "kind": "outcome" }]
            }),
        );
        assert_eq!(v.get("outcome").and_then(Value::as_str), Some("error"));
    }

    #[test]
    fn derived_backend_host_extracts_host() {
        let v = serialize_via(
            &http_summary(),
            json!({
                "summary_type": "http",
                "derived_fields": [{ "name": "backend_host", "kind": "backend_host" }]
            }),
        );
        assert_eq!(
            v.get("backend_host").and_then(Value::as_str),
            Some("backend.example.com")
        );
    }

    #[test]
    fn derived_backend_host_ipv6_bracketed() {
        let mut s = http_summary();
        s.backend_target_url = Some("https://[2001:db8::1]:8443/path".into());
        let v = serialize_via(
            &s,
            json!({
                "summary_type": "http",
                "derived_fields": [{ "name": "backend_host", "kind": "backend_host" }]
            }),
        );
        assert_eq!(
            v.get("backend_host").and_then(Value::as_str),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn derived_summary_kind_http() {
        let v = serialize_via(
            &http_summary(),
            json!({
                "summary_type": "http",
                "derived_fields": [{ "name": "kind", "kind": "summary_kind" }]
            }),
        );
        assert_eq!(v.get("kind").and_then(Value::as_str), Some("http"));
    }

    #[test]
    fn derived_summary_kind_stream() {
        let v = serialize_stream(
            &stream_summary(),
            json!({
                "summary_type": "stream",
                "derived_fields": [{ "name": "kind", "kind": "summary_kind" }]
            }),
        );
        assert_eq!(v.get("kind").and_then(Value::as_str), Some("stream"));
    }

    #[test]
    fn metadata_nested_redacts_sensitive() {
        let v = serialize_via(&http_summary(), json!({ "summary_type": "http" }));
        let md = v.get("metadata").and_then(Value::as_object).unwrap();
        assert_eq!(
            md.get("authorization").and_then(Value::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(md.get("trace_id").and_then(Value::as_str), Some("abc-123"));
    }

    #[test]
    fn metadata_flatten_promotes_keys() {
        let v = serialize_via(
            &http_summary(),
            json!({
                "summary_type": "http",
                "metadata": { "mode": "flatten", "prefix": "meta_" }
            }),
        );
        assert_eq!(
            v.get("meta_trace_id").and_then(Value::as_str),
            Some("abc-123")
        );
        assert_eq!(
            v.get("meta_authorization").and_then(Value::as_str),
            Some("[REDACTED]")
        );
        // The nested object should NOT also be present.
        assert!(v.get("metadata").is_none());
    }

    #[test]
    fn metadata_omit_drops_completely() {
        let v = serialize_via(
            &http_summary(),
            json!({
                "summary_type": "http",
                "metadata": { "mode": "omit" }
            }),
        );
        assert!(v.get("metadata").is_none());
        assert!(v.get("trace_id").is_none());
        assert!(v.get("authorization").is_none());
    }

    #[test]
    fn metadata_flatten_skip_collision() {
        let mut s = http_summary();
        s.metadata
            .insert("env".to_string(), "from-metadata".to_string());
        let v = serialize_via(
            &s,
            json!({
                "summary_type": "http",
                "static_fields": { "env": "production" },
                "metadata": { "mode": "flatten", "on_collision": "skip" }
            }),
        );
        assert_eq!(v.get("env").and_then(Value::as_str), Some("production"));
    }

    #[test]
    fn order_with_wildcard_positions_first() {
        let v = serialize_via(
            &http_summary(),
            json!({
                "summary_type": "http",
                "order": ["timestamp_received", "response_status_code", "*"]
            }),
        );
        // Just smoke-check both fields present and the rest is there too.
        assert!(v.get("timestamp_received").is_some());
        assert!(v.get("response_status_code").is_some());
        assert!(v.get("namespace").is_some());
    }

    #[test]
    fn timestamp_epoch_ms_converts() {
        let v = serialize_via(
            &http_summary(),
            json!({
                "summary_type": "http",
                "timestamp_format": "epoch_ms"
            }),
        );
        let ts = v.get("timestamp_received").and_then(Value::as_i64).unwrap();
        // 2026-05-11T12:00:00Z = 1778500800 seconds since epoch = 1778500800000 ms.
        assert_eq!(ts, 1778500800000);
    }

    #[test]
    fn timestamp_epoch_s_converts() {
        let v = serialize_via(
            &http_summary(),
            json!({
                "summary_type": "http",
                "timestamp_format": "epoch_s"
            }),
        );
        let ts = v.get("timestamp_received").and_then(Value::as_i64).unwrap();
        assert_eq!(ts, 1778500800);
    }

    #[test]
    fn timestamp_parse_failure_falls_back_to_string() {
        let mut s = http_summary();
        s.timestamp_received = "not-a-date".into();
        let v = serialize_via(
            &s,
            json!({ "summary_type": "http", "timestamp_format": "epoch_ms" }),
        );
        assert_eq!(
            v.get("timestamp_received").and_then(Value::as_str),
            Some("not-a-date")
        );
    }

    #[test]
    fn http_only_field_silently_skipped_on_stream() {
        // schema_type=Both, applied to a stream summary — request_path
        // does not exist on stream and should be silently skipped.
        let v = serialize_stream(&stream_summary(), json!({ "summary_type": "both" }));
        assert!(v.get("request_path").is_none());
        // Stream-specific fields should still emit.
        assert!(v.get("bytes_sent").is_some());
    }

    #[test]
    fn stream_only_field_silently_skipped_on_http() {
        let v = serialize_via(&http_summary(), json!({ "summary_type": "both" }));
        assert!(v.get("bytes_sent").is_none());
        assert!(v.get("request_path").is_some());
    }

    #[test]
    fn redaction_cannot_be_bypassed_via_rename() {
        // Even when metadata is renamed via the schema, sensitive keys
        // inside it must still be redacted.
        let v = serialize_via(
            &http_summary(),
            json!({
                "summary_type": "http",
                "rename": { "metadata": "tags" }
            }),
        );
        let tags = v.get("tags").and_then(Value::as_object).unwrap();
        assert_eq!(
            tags.get("authorization").and_then(Value::as_str),
            Some("[REDACTED]")
        );
    }

    #[test]
    fn skip_serializing_if_preserved_for_zero_request_bytes() {
        // Default http_summary() has request_bytes = 0 → should be skipped.
        let v = serialize_via(&http_summary(), json!({ "summary_type": "http" }));
        assert!(v.get("request_bytes").is_none());
    }

    #[test]
    fn skip_serializing_if_preserved_for_false_mirror() {
        let v = serialize_via(&http_summary(), json!({ "summary_type": "http" }));
        assert!(v.get("mirror").is_none());
    }
}
