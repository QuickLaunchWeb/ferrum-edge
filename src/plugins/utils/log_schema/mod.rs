//! Customizable transaction-log output schema.
//!
//! Operators configure a `schema:` (or `schema_ref:`) block on any logging
//! plugin to rename, omit, reorder, or augment the fields in
//! [`crate::plugins::TransactionSummary`] / [`crate::plugins::StreamTransactionSummary`].
//!
//! Apply order at serialization time is driven by the compiled
//! [`SummarySchema::fields`] vec. Metadata redaction is preserved by routing
//! every metadata write through
//! [`crate::plugins::utils::metadata_redaction`]; sensitive keys cannot be
//! introduced via static or derived fields (the compiler rejects them).

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::plugins::utils::metadata_redaction::is_sensitive_metadata_key;

pub mod fields;
pub mod registry;
pub mod view;

// Re-exports for downstream consumers (integration tests, custom plugins,
// future admin endpoints). The binary itself reaches these through their
// submodule paths so an `unused_imports` lint would otherwise fire.
#[allow(unused_imports)]
pub use fields::{FieldMeta, HTTP_FIELDS, STREAM_FIELDS};
#[allow(unused_imports)]
pub use view::{SchemaSerializable, SchemaView, SummaryLogEntryBatchView, SummaryLogEntryView};

/// Which summary struct(s) a schema applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SummaryType {
    Http,
    Stream,
    #[default]
    Both,
}

impl SummaryType {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "http" => Ok(Self::Http),
            "stream" => Ok(Self::Stream),
            "both" => Ok(Self::Both),
            other => Err(format!(
                "schema: 'summary_type' must be 'http', 'stream', or 'both' (got '{other}')"
            )),
        }
    }
}

/// Compiled schema: the source of truth at serialize time.
#[derive(Debug, Clone)]
pub struct SummarySchema {
    pub summary_type: SummaryType,
    /// Fields in the order they are emitted. May include native, static,
    /// and derived entries. `metadata` is handled separately via
    /// `metadata` policy when [`MetadataPolicy::Flatten`] is set; in
    /// other modes it appears here as a native field.
    pub fields: Vec<FieldSpec>,
    pub metadata: MetadataPolicy,
    pub timestamp_format: TimestampFormat,
}

/// Compiled output-field spec.
#[derive(Debug, Clone)]
pub enum FieldSpec {
    Native {
        /// The native struct field name (matches a [`FieldMeta::name`]).
        source: &'static str,
        /// The output JSON key. Equals `source` unless renamed.
        out_key: String,
        is_timestamp: bool,
    },
    Static {
        out_key: String,
        value: Value,
    },
    Derived {
        out_key: String,
        kind: DerivedKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedKind {
    /// `"2xx"`/`"3xx"`/`"4xx"`/`"5xx"`/`"other"` from `response_status_code`.
    /// On stream summaries (no HTTP status), emits `"none"`.
    StatusClass,
    /// Hostname extracted from `backend_target_url` (HTTP) or
    /// `backend_target` (stream).
    BackendHost,
    /// `"http"` or `"stream"` — useful for unified pipelines.
    SummaryKind,
    /// `"ok"` / `"error"`. HTTP: status ≥ 500 or `error_class.is_some()` →
    /// `error`. Stream: any of `connection_error`, `error_class`,
    /// `disconnect_cause: BackendError` → `error`.
    Outcome,
}

impl DerivedKind {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "status_class" => Ok(Self::StatusClass),
            "backend_host" => Ok(Self::BackendHost),
            "summary_kind" => Ok(Self::SummaryKind),
            "outcome" => Ok(Self::Outcome),
            other => Err(format!(
                "schema: unknown derived kind '{other}' (valid: status_class, backend_host, summary_kind, outcome)"
            )),
        }
    }
}

/// How to render the `metadata` map.
#[derive(Debug, Clone, Default)]
pub enum MetadataPolicy {
    /// Emit `metadata` as a nested object under whatever out_key was
    /// chosen (default: `"metadata"`). Sensitive keys redacted.
    #[default]
    Nested,
    /// Omit the metadata map entirely from output.
    Omit,
    /// Promote each metadata key/value to a top-level entry.
    Flatten {
        prefix: Option<String>,
        on_collision: CollisionMode,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CollisionMode {
    /// Existing entry wins; the metadata entry is dropped silently.
    #[default]
    Skip,
    /// Metadata entry overwrites the existing one.
    Overwrite,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TimestampFormat {
    #[default]
    Rfc3339,
    EpochMs,
    EpochS,
}

impl TimestampFormat {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "rfc3339" => Ok(Self::Rfc3339),
            "epoch_ms" => Ok(Self::EpochMs),
            "epoch_s" => Ok(Self::EpochS),
            other => Err(format!(
                "schema: 'timestamp_format' must be 'rfc3339', 'epoch_ms', or 'epoch_s' (got '{other}')"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

impl SummarySchema {
    /// Compile a raw schema config into the runtime form.
    pub fn compile(raw: &Value, plugin_name: &str) -> Result<Arc<Self>, String> {
        if !raw.is_object() {
            return Err(format!("{plugin_name}: 'schema' must be an object"));
        }

        // Reject unknown top-level keys so typos surface immediately.
        const KNOWN_KEYS: &[&str] = &[
            "summary_type",
            "omit",
            "rename",
            "order",
            "static_fields",
            "derived_fields",
            "metadata",
            "timestamp_format",
        ];
        if let Some(obj) = raw.as_object() {
            for key in obj.keys() {
                if !KNOWN_KEYS.contains(&key.as_str()) {
                    return Err(format!(
                        "{plugin_name}: unknown schema key '{key}' (valid keys: {})",
                        KNOWN_KEYS.join(", ")
                    ));
                }
            }
        }

        let summary_type = match raw.get("summary_type") {
            Some(Value::String(s)) => SummaryType::parse(s)?,
            None => SummaryType::default(),
            Some(_) => {
                return Err(format!(
                    "{plugin_name}: schema 'summary_type' must be a string"
                ));
            }
        };

        let omit = parse_string_array(raw.get("omit"), plugin_name, "omit")?;
        for name in &omit {
            if fields::lookup(summary_type, name).is_none() {
                return Err(unknown_field_error(plugin_name, "omit", name, summary_type));
            }
        }

        let rename = parse_string_map(raw.get("rename"), plugin_name, "rename")?;
        for (source, target) in &rename {
            if fields::lookup(summary_type, source).is_none() {
                return Err(unknown_field_error(
                    plugin_name,
                    "rename",
                    source,
                    summary_type,
                ));
            }
            if omit.contains(source) {
                return Err(format!(
                    "{plugin_name}: schema field '{source}' is both omitted and renamed (rename target '{target}')"
                ));
            }
            if target.is_empty() {
                return Err(format!(
                    "{plugin_name}: schema rename target for '{source}' must be a non-empty string"
                ));
            }
            // The rename target is the operator-visible JSON key. If it
            // matches a sensitive-data substring, downstream log
            // redactors keyed on field name will silently drop legitimate
            // (non-sensitive) values. Reject so the operator picks a
            // different name. Mirrors the static_fields / derived_fields
            // check.
            if is_sensitive_metadata_key(target) {
                return Err(format!(
                    "{plugin_name}: schema rename target '{target}' (for source '{source}') matches a sensitive-data substring; pick a different name"
                ));
            }
        }

        let static_fields = parse_static_fields(raw.get("static_fields"), plugin_name)?;

        let derived_fields = parse_derived_fields(raw.get("derived_fields"), plugin_name)?;

        let metadata = parse_metadata_policy(raw.get("metadata"), plugin_name)?;

        let timestamp_format = match raw.get("timestamp_format") {
            Some(Value::String(s)) => TimestampFormat::parse(s)?,
            None => TimestampFormat::default(),
            Some(_) => {
                return Err(format!(
                    "{plugin_name}: schema 'timestamp_format' must be a string"
                ));
            }
        };

        // ------------------------------------------------------------------
        // Build the unordered FieldSpec set.
        // ------------------------------------------------------------------

        // Native fields, omit applied, rename applied. We preserve native
        // declaration order; reordering happens below if `order` is set.
        let native_specs: Vec<FieldSpec> = fields::fields_for(summary_type)
            .into_iter()
            .filter(|f| {
                // When metadata policy is Omit or Flatten, drop the native
                // metadata entry — it's handled separately by the serializer.
                if f.name == "metadata" && !matches!(metadata, MetadataPolicy::Nested) {
                    return false;
                }
                !omit.contains(&f.name.to_string())
            })
            .map(|f| {
                let out_key = rename
                    .get(f.name)
                    .cloned()
                    .unwrap_or_else(|| f.name.to_string());
                FieldSpec::Native {
                    source: f.name,
                    out_key,
                    is_timestamp: f.is_timestamp,
                }
            })
            .collect();

        let static_specs: Vec<FieldSpec> = static_fields
            .into_iter()
            .map(|(k, v)| FieldSpec::Static {
                out_key: k,
                value: v,
            })
            .collect();

        let derived_specs: Vec<FieldSpec> = derived_fields
            .into_iter()
            .map(|(name, kind)| FieldSpec::Derived {
                out_key: name,
                kind,
            })
            .collect();

        // ------------------------------------------------------------------
        // Duplicate-output-key check before reorder.
        // ------------------------------------------------------------------

        let all_specs: Vec<&FieldSpec> = native_specs
            .iter()
            .chain(static_specs.iter())
            .chain(derived_specs.iter())
            .collect();
        let mut seen: HashMap<&str, &str> = HashMap::new();
        for spec in &all_specs {
            let (out, kind) = spec_out_key_and_kind(spec);
            if let Some(prev_kind) = seen.insert(out, kind) {
                return Err(format!(
                    "{plugin_name}: duplicate output key '{out}' produced by {prev_kind} and {kind}"
                ));
            }
        }

        // ------------------------------------------------------------------
        // Apply `order` if present.
        // ------------------------------------------------------------------

        let fields = match raw.get("order") {
            Some(value) => {
                let order = parse_string_array(Some(value), plugin_name, "order")?;
                apply_order(
                    &order,
                    native_specs,
                    static_specs,
                    derived_specs,
                    plugin_name,
                )?
            }
            None => {
                // Default order: native, then static, then derived.
                let mut out = native_specs;
                out.extend(static_specs);
                out.extend(derived_specs);
                out
            }
        };

        Ok(Arc::new(SummarySchema {
            summary_type,
            fields,
            metadata,
            timestamp_format,
        }))
    }

    /// `true` when this schema's `summary_type` covers HTTP / gRPC /
    /// WebSocket summaries.
    pub fn applies_to_http(&self) -> bool {
        matches!(self.summary_type, SummaryType::Http | SummaryType::Both)
    }

    /// `true` when this schema's `summary_type` covers stream (TCP/UDP/DTLS)
    /// summaries.
    pub fn applies_to_stream(&self) -> bool {
        matches!(self.summary_type, SummaryType::Stream | SummaryType::Both)
    }

    /// Look up the rename target for a native field by source name.
    /// Returns the renamed output key if the field appears in `fields` with
    /// a different out_key, or `None` if no rename applies. Used by
    /// `statsd_logging` to rename tag keys.
    pub fn rename_for_tag(&self, native: &str) -> Option<&str> {
        for spec in &self.fields {
            if let FieldSpec::Native {
                source, out_key, ..
            } = spec
                && *source == native
                && out_key != native
            {
                return Some(out_key);
            }
        }
        None
    }

    /// `true` when a native field is omitted (either via `omit` or because
    /// it's not visible for this schema's summary_type). Used by
    /// `statsd_logging` to drop tags.
    pub fn omits_tag(&self, native: &str) -> bool {
        !self
            .fields
            .iter()
            .any(|s| matches!(s, FieldSpec::Native { source, .. } if *source == native))
    }
}

fn spec_out_key_and_kind(spec: &FieldSpec) -> (&str, &'static str) {
    match spec {
        FieldSpec::Native { out_key, .. } => (out_key.as_str(), "native"),
        FieldSpec::Static { out_key, .. } => (out_key.as_str(), "static_fields"),
        FieldSpec::Derived { out_key, .. } => (out_key.as_str(), "derived_fields"),
    }
}

fn unknown_field_error(
    plugin_name: &str,
    section: &str,
    name: &str,
    summary_type: SummaryType,
) -> String {
    let suggestion = fields::levenshtein_suggest(summary_type, name);
    match suggestion {
        Some(s) => format!(
            "{plugin_name}: schema {section} references unknown field '{name}' (did you mean '{s}'?)"
        ),
        None => format!("{plugin_name}: schema {section} references unknown field '{name}'"),
    }
}

fn parse_string_array(
    value: Option<&Value>,
    plugin_name: &str,
    key: &str,
) -> Result<Vec<String>, String> {
    let Some(v) = value else {
        return Ok(Vec::new());
    };
    let arr = v
        .as_array()
        .ok_or_else(|| format!("{plugin_name}: schema '{key}' must be an array of strings"))?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let s = entry
            .as_str()
            .ok_or_else(|| format!("{plugin_name}: schema '{key}' entries must be strings"))?;
        if s.is_empty() {
            return Err(format!(
                "{plugin_name}: schema '{key}' entries must be non-empty"
            ));
        }
        out.push(s.to_string());
    }
    Ok(out)
}

fn parse_string_map(
    value: Option<&Value>,
    plugin_name: &str,
    key: &str,
) -> Result<HashMap<String, String>, String> {
    let Some(v) = value else {
        return Ok(HashMap::new());
    };
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: schema '{key}' must be an object"))?;
    let mut out = HashMap::with_capacity(obj.len());
    for (k, val) in obj {
        let s = val.as_str().ok_or_else(|| {
            format!("{plugin_name}: schema '{key}' value for '{k}' must be a string")
        })?;
        out.insert(k.clone(), s.to_string());
    }
    Ok(out)
}

fn parse_static_fields(
    value: Option<&Value>,
    plugin_name: &str,
) -> Result<Vec<(String, Value)>, String> {
    let Some(v) = value else {
        return Ok(Vec::new());
    };
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: schema 'static_fields' must be an object"))?;
    let mut out = Vec::with_capacity(obj.len());
    for (k, val) in obj {
        if k.is_empty() {
            return Err(format!(
                "{plugin_name}: schema 'static_fields' keys must be non-empty"
            ));
        }
        if val.is_null() {
            return Err(format!(
                "{plugin_name}: schema 'static_fields' value for '{k}' must not be null (use 'omit' instead)"
            ));
        }
        if is_sensitive_metadata_key(k) {
            return Err(format!(
                "{plugin_name}: schema 'static_fields' key '{k}' matches a sensitive-data substring and would always be redacted; pick a different name"
            ));
        }
        // Defense in depth: walk nested structures, reject sensitive keys.
        reject_sensitive_in_value(val, plugin_name, k)?;
        out.push((k.clone(), val.clone()));
    }
    Ok(out)
}

fn reject_sensitive_in_value(value: &Value, plugin_name: &str, parent: &str) -> Result<(), String> {
    match value {
        Value::Object(obj) => {
            for (k, v) in obj {
                if is_sensitive_metadata_key(k) {
                    return Err(format!(
                        "{plugin_name}: schema 'static_fields' value for '{parent}' contains nested key '{k}' that matches a sensitive-data substring"
                    ));
                }
                reject_sensitive_in_value(v, plugin_name, parent)?;
            }
        }
        Value::Array(arr) => {
            for v in arr {
                reject_sensitive_in_value(v, plugin_name, parent)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_derived_fields(
    value: Option<&Value>,
    plugin_name: &str,
) -> Result<Vec<(String, DerivedKind)>, String> {
    let Some(v) = value else {
        return Ok(Vec::new());
    };
    let arr = v
        .as_array()
        .ok_or_else(|| format!("{plugin_name}: schema 'derived_fields' must be an array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let obj = entry.as_object().ok_or_else(|| {
            format!("{plugin_name}: schema 'derived_fields' entries must be objects")
        })?;
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                format!("{plugin_name}: schema 'derived_fields' entry missing non-empty 'name'")
            })?;
        let kind_str = obj.get("kind").and_then(Value::as_str).ok_or_else(|| {
            format!("{plugin_name}: schema 'derived_fields' entry '{name}' missing 'kind'")
        })?;
        let kind = DerivedKind::parse(kind_str)?;
        if is_sensitive_metadata_key(name) {
            return Err(format!(
                "{plugin_name}: schema 'derived_fields' name '{name}' matches a sensitive-data substring and would always be redacted; pick a different name"
            ));
        }
        out.push((name.to_string(), kind));
    }
    Ok(out)
}

fn parse_metadata_policy(
    value: Option<&Value>,
    plugin_name: &str,
) -> Result<MetadataPolicy, String> {
    let Some(v) = value else {
        return Ok(MetadataPolicy::default());
    };
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{plugin_name}: schema 'metadata' must be an object"))?;
    let mode = obj.get("mode").and_then(Value::as_str).unwrap_or("nested");
    match mode {
        "nested" => Ok(MetadataPolicy::Nested),
        "omit" => Ok(MetadataPolicy::Omit),
        "flatten" => {
            let prefix = match obj.get("prefix") {
                Some(Value::String(s)) if s.is_empty() => None,
                Some(Value::String(s)) => {
                    if s.chars().any(|c| c.is_control()) {
                        return Err(format!(
                            "{plugin_name}: schema 'metadata.prefix' must not contain control characters"
                        ));
                    }
                    Some(s.clone())
                }
                None => None,
                Some(_) => {
                    return Err(format!(
                        "{plugin_name}: schema 'metadata.prefix' must be a string"
                    ));
                }
            };
            let on_collision = match obj.get("on_collision") {
                Some(Value::String(s)) => match s.as_str() {
                    "skip" => CollisionMode::Skip,
                    "overwrite" => CollisionMode::Overwrite,
                    other => {
                        return Err(format!(
                            "{plugin_name}: schema 'metadata.on_collision' must be 'skip' or 'overwrite' (got '{other}')"
                        ));
                    }
                },
                None => CollisionMode::default(),
                Some(_) => {
                    return Err(format!(
                        "{plugin_name}: schema 'metadata.on_collision' must be a string"
                    ));
                }
            };
            Ok(MetadataPolicy::Flatten {
                prefix,
                on_collision,
            })
        }
        other => Err(format!(
            "{plugin_name}: schema 'metadata.mode' must be 'nested', 'omit', or 'flatten' (got '{other}')"
        )),
    }
}

/// Reorder the unordered field set according to operator-supplied `order`.
///
/// `*` is a wildcard that expands inline to all unlisted entries (native +
/// static + derived) in their natural order. Without `*`, every entry must
/// be listed explicitly or compilation fails.
fn apply_order(
    order: &[String],
    native: Vec<FieldSpec>,
    statics: Vec<FieldSpec>,
    derived: Vec<FieldSpec>,
    plugin_name: &str,
) -> Result<Vec<FieldSpec>, String> {
    // Combine, preserving natural insertion order.
    let mut all: Vec<FieldSpec> = native;
    all.extend(statics);
    all.extend(derived);

    // Build name → index lookup.
    let mut index: HashMap<String, usize> = HashMap::with_capacity(all.len());
    for (i, spec) in all.iter().enumerate() {
        index.insert(spec_out_key_and_kind(spec).0.to_string(), i);
    }

    // Validate order entries.
    let mut listed: Vec<bool> = vec![false; all.len()];
    let mut output_indices: Vec<Option<usize>> = Vec::with_capacity(order.len());
    let mut wildcard_seen = false;
    for entry in order {
        if entry == "*" {
            if wildcard_seen {
                return Err(format!(
                    "{plugin_name}: schema 'order' may only contain '*' once"
                ));
            }
            wildcard_seen = true;
            output_indices.push(None);
            continue;
        }
        let idx = index.get(entry).ok_or_else(|| {
            format!(
                "{plugin_name}: schema 'order' references unknown output key '{entry}' (must match a renamed/native/static/derived out_key, or use '*')"
            )
        })?;
        if listed[*idx] {
            return Err(format!(
                "{plugin_name}: schema 'order' lists '{entry}' more than once"
            ));
        }
        listed[*idx] = true;
        output_indices.push(Some(*idx));
    }

    if !wildcard_seen {
        let missing: Vec<&str> = all
            .iter()
            .zip(listed.iter())
            .filter(|(_, l)| !**l)
            .map(|(spec, _)| spec_out_key_and_kind(spec).0)
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "{plugin_name}: schema 'order' missing entries: {} (add them, or use '*' to catch the rest)",
                missing.join(", ")
            ));
        }
    }

    // Build final ordered vec. To allow ownership transfer from `all`,
    // we move into `Option<FieldSpec>` slots. The `listed` bitmap is the
    // authoritative "explicitly placed elsewhere" signal — wildcard
    // expansion must consult it rather than relying on `slot.is_some()`,
    // because listed entries appearing AFTER the wildcard are still
    // un-taken when the wildcard iteration runs.
    let mut slots: Vec<Option<FieldSpec>> = all.into_iter().map(Some).collect();
    let mut out: Vec<FieldSpec> = Vec::with_capacity(slots.len());
    for entry in output_indices {
        match entry {
            Some(i) => {
                out.push(slots[i].take().expect("listed index moved twice"));
            }
            None => {
                // Wildcard — append entries that are neither explicitly
                // listed (handled by their own Some(i) iteration) nor
                // already taken.
                for (i, slot) in slots.iter_mut().enumerate() {
                    if listed[i] {
                        continue;
                    }
                    if let Some(spec) = slot.take() {
                        out.push(spec);
                    }
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Plugin-facing helper: resolve a schema from plugin config.
// ---------------------------------------------------------------------------

/// Read either inline `schema` or `schema_ref` from a plugin config object
/// and return the compiled schema. Returns `Ok(None)` when neither key is
/// present.
///
/// Errors:
/// - Both `schema` and `schema_ref` present.
/// - `schema_ref` is not a string, or points to a name not registered.
/// - Inline `schema` fails to compile (rules in [`SummarySchema::compile`]).
pub fn resolve_schema(
    config: &Value,
    plugin_name: &str,
) -> Result<Option<Arc<SummarySchema>>, String> {
    let inline = config.get("schema");
    let by_ref = config.get("schema_ref");

    if inline.is_some() && by_ref.is_some() {
        return Err(format!(
            "{plugin_name}: 'schema' and 'schema_ref' are mutually exclusive"
        ));
    }

    if let Some(name) = by_ref {
        let name = name
            .as_str()
            .ok_or_else(|| format!("{plugin_name}: 'schema_ref' must be a string"))?;
        return registry::lookup_named(name)
            .map(Some)
            .ok_or_else(|| {
                format!(
                    "{plugin_name}: 'schema_ref' references unknown schema '{name}' (define it in a 'transaction_log_schema' plugin)"
                )
            });
    }

    if let Some(inline) = inline {
        return SummarySchema::compile(inline, plugin_name).map(Some);
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok(raw: Value) -> Arc<SummarySchema> {
        SummarySchema::compile(&raw, "test").expect("compile succeeded")
    }

    fn err(raw: Value) -> String {
        SummarySchema::compile(&raw, "test").expect_err("expected compile error")
    }

    #[test]
    fn empty_schema_compiles_to_native_defaults() {
        let s = ok(json!({}));
        assert_eq!(s.summary_type, SummaryType::Both);
        assert!(matches!(s.metadata, MetadataPolicy::Nested));
        assert_eq!(s.timestamp_format, TimestampFormat::Rfc3339);
        // Should have native fields from both, deduped.
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "namespace",
                ..
            }
        )));
    }

    #[test]
    fn rename_changes_out_key() {
        let s = ok(json!({
            "summary_type": "http",
            "rename": { "proxy_id": "route_id" }
        }));
        let proxy = s
            .fields
            .iter()
            .find_map(|f| match f {
                FieldSpec::Native {
                    source: "proxy_id",
                    out_key,
                    ..
                } => Some(out_key.clone()),
                _ => None,
            })
            .expect("proxy_id present");
        assert_eq!(proxy, "route_id");
    }

    #[test]
    fn omit_drops_field() {
        let s = ok(json!({
            "summary_type": "http",
            "omit": ["latency_plugin_external_io_ms"]
        }));
        assert!(!s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Native {
                source: "latency_plugin_external_io_ms",
                ..
            }
        )));
    }

    #[test]
    fn unknown_field_in_omit_rejected() {
        let e = err(json!({ "omit": ["typo"] }));
        assert!(e.contains("unknown field 'typo'"), "got: {e}");
    }

    #[test]
    fn unknown_field_offers_suggestion() {
        let e = err(json!({ "omit": ["proxy_idd"] }));
        assert!(e.contains("did you mean 'proxy_id'"), "got: {e}");
    }

    #[test]
    fn omit_and_rename_collision_rejected() {
        let e = err(json!({
            "omit": ["proxy_id"],
            "rename": { "proxy_id": "route_id" }
        }));
        assert!(e.contains("both omitted and renamed"), "got: {e}");
    }

    #[test]
    fn duplicate_output_key_rejected() {
        let e = err(json!({
            "rename": { "proxy_id": "namespace" }
        }));
        assert!(e.contains("duplicate output key 'namespace'"), "got: {e}");
    }

    #[test]
    fn http_schema_rejects_stream_only_field() {
        let e = err(json!({
            "summary_type": "http",
            "omit": ["bytes_sent"]
        }));
        assert!(e.contains("unknown field 'bytes_sent'"), "got: {e}");
    }

    #[test]
    fn stream_schema_rejects_http_only_field() {
        let e = err(json!({
            "summary_type": "stream",
            "rename": { "request_path": "path" }
        }));
        assert!(e.contains("unknown field 'request_path'"), "got: {e}");
    }

    #[test]
    fn both_schema_accepts_either_field() {
        ok(json!({
            "summary_type": "both",
            "omit": ["bytes_sent", "request_path"]
        }));
    }

    #[test]
    fn order_with_wildcard_positions_listed_keys() {
        let s = ok(json!({
            "summary_type": "http",
            "order": ["timestamp_received", "response_status_code", "*"]
        }));
        assert!(matches!(
            &s.fields[0],
            FieldSpec::Native {
                source: "timestamp_received",
                ..
            }
        ));
        assert!(matches!(
            &s.fields[1],
            FieldSpec::Native {
                source: "response_status_code",
                ..
            }
        ));
    }

    #[test]
    fn order_with_wildcard_followed_by_listed_keys() {
        // Regression for a bug where wildcard expansion consumed every
        // still-Some slot, including entries explicitly listed AFTER `*`,
        // causing the next listed-index `.take()` to panic.
        let s = ok(json!({
            "summary_type": "http",
            "order": ["namespace", "*", "response_status_code"]
        }));
        // First key must be the explicitly-placed leading entry.
        assert!(matches!(
            &s.fields[0],
            FieldSpec::Native {
                source: "namespace",
                ..
            }
        ));
        // Last key must be the explicitly-placed trailing entry.
        assert!(matches!(
            s.fields.last(),
            Some(FieldSpec::Native {
                source: "response_status_code",
                ..
            })
        ));
        // The wildcard span must not include either pinned entry — they
        // appear exactly once at their pinned positions.
        let ns_count = s
            .fields
            .iter()
            .filter(|f| {
                matches!(
                    f,
                    FieldSpec::Native {
                        source: "namespace",
                        ..
                    }
                )
            })
            .count();
        let status_count = s
            .fields
            .iter()
            .filter(|f| {
                matches!(
                    f,
                    FieldSpec::Native {
                        source: "response_status_code",
                        ..
                    }
                )
            })
            .count();
        assert_eq!(ns_count, 1, "namespace appears exactly once");
        assert_eq!(status_count, 1, "response_status_code appears exactly once");
        // And the schema must still cover every native HTTP field.
        assert_eq!(s.fields.len(), fields::HTTP_FIELDS.len());
    }

    #[test]
    fn order_without_wildcard_must_be_complete() {
        let e = err(json!({
            "summary_type": "http",
            "order": ["namespace", "client_ip"]
        }));
        assert!(e.contains("missing entries"), "got: {e}");
    }

    #[test]
    fn order_duplicate_entry_rejected() {
        let e = err(json!({
            "order": ["namespace", "namespace", "*"]
        }));
        assert!(e.contains("more than once"), "got: {e}");
    }

    #[test]
    fn order_unknown_key_rejected() {
        let e = err(json!({
            "order": ["not_a_field", "*"]
        }));
        assert!(e.contains("unknown output key 'not_a_field'"), "got: {e}");
    }

    #[test]
    fn order_with_two_wildcards_rejected() {
        let e = err(json!({
            "order": ["*", "*"]
        }));
        assert!(e.contains("'*' once"), "got: {e}");
    }

    #[test]
    fn static_field_sensitive_name_rejected() {
        let e = err(json!({
            "static_fields": { "x_authorization_copy": "redacted-please" }
        }));
        assert!(e.contains("matches a sensitive-data substring"), "got: {e}");
    }

    #[test]
    fn rename_target_sensitive_name_rejected() {
        let e = err(json!({
            "summary_type": "http",
            "rename": { "proxy_id": "x-auth-token" }
        }));
        assert!(e.contains("matches a sensitive-data substring"), "got: {e}");
    }

    #[test]
    fn static_field_nested_sensitive_rejected() {
        let e = err(json!({
            "static_fields": { "audit": { "authorization": "secret" } }
        }));
        assert!(e.contains("contains nested key"), "got: {e}");
    }

    #[test]
    fn static_field_null_rejected() {
        let e = err(json!({
            "static_fields": { "drop_me": null }
        }));
        assert!(e.contains("must not be null"), "got: {e}");
    }

    #[test]
    fn derived_field_unknown_kind_rejected() {
        let e = err(json!({
            "derived_fields": [{ "name": "x", "kind": "not_a_kind" }]
        }));
        assert!(e.contains("unknown derived kind"), "got: {e}");
    }

    #[test]
    fn derived_field_compiles() {
        let s = ok(json!({
            "summary_type": "http",
            "derived_fields": [
                { "name": "status_class", "kind": "status_class" },
                { "name": "outcome", "kind": "outcome" }
            ]
        }));
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Derived {
                kind: DerivedKind::StatusClass,
                ..
            }
        )));
        assert!(s.fields.iter().any(|f| matches!(
            f,
            FieldSpec::Derived {
                kind: DerivedKind::Outcome,
                ..
            }
        )));
    }

    #[test]
    fn metadata_flatten_with_prefix() {
        let s = ok(json!({
            "metadata": {
                "mode": "flatten",
                "prefix": "meta_",
                "on_collision": "overwrite"
            }
        }));
        let MetadataPolicy::Flatten {
            prefix,
            on_collision,
        } = &s.metadata
        else {
            panic!("expected Flatten");
        };
        assert_eq!(prefix.as_deref(), Some("meta_"));
        assert_eq!(*on_collision, CollisionMode::Overwrite);
    }

    #[test]
    fn metadata_flatten_empty_prefix_treated_as_none() {
        let s = ok(json!({
            "metadata": { "mode": "flatten", "prefix": "" }
        }));
        let MetadataPolicy::Flatten { prefix, .. } = &s.metadata else {
            panic!("expected Flatten");
        };
        assert!(prefix.is_none());
    }

    #[test]
    fn metadata_flatten_prefix_control_char_rejected() {
        let e = err(json!({
            "metadata": { "mode": "flatten", "prefix": "x\n" }
        }));
        assert!(e.contains("control characters"), "got: {e}");
    }

    #[test]
    fn unknown_top_level_key_rejected() {
        let e = err(json!({ "renaime": { "x": "y" } }));
        assert!(e.contains("unknown schema key 'renaime'"), "got: {e}");
    }

    #[test]
    fn timestamp_format_parsed() {
        let s = ok(json!({ "timestamp_format": "epoch_ms" }));
        assert_eq!(s.timestamp_format, TimestampFormat::EpochMs);
        let s = ok(json!({ "timestamp_format": "epoch_s" }));
        assert_eq!(s.timestamp_format, TimestampFormat::EpochS);
    }

    #[test]
    fn rename_for_tag_returns_renamed() {
        let s = ok(json!({
            "summary_type": "http",
            "rename": { "proxy_id": "route_id" }
        }));
        assert_eq!(s.rename_for_tag("proxy_id"), Some("route_id"));
        assert_eq!(s.rename_for_tag("namespace"), None);
    }

    #[test]
    fn omits_tag_detects_omission() {
        let s = ok(json!({
            "summary_type": "http",
            "omit": ["proxy_name"]
        }));
        assert!(s.omits_tag("proxy_name"));
        assert!(!s.omits_tag("proxy_id"));
    }

    #[test]
    fn resolve_schema_inline() {
        let cfg = json!({ "schema": { "summary_type": "http" } });
        let r = resolve_schema(&cfg, "test").unwrap();
        assert!(r.is_some());
    }

    #[test]
    fn resolve_schema_none_when_absent() {
        let cfg = json!({ "other": "field" });
        let r = resolve_schema(&cfg, "test").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn resolve_schema_both_present_rejected() {
        let cfg = json!({ "schema": {}, "schema_ref": "x" });
        let r = resolve_schema(&cfg, "test");
        assert!(r.is_err());
    }
}
