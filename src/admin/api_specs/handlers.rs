//! HTTP handlers for the `/api-specs` admin endpoints (Wave 3).
//!
//! Six endpoints:
//!   POST   /api-specs                     — submit new spec
//!   PUT    /api-specs/{id}                — replace existing spec
//!   GET    /api-specs                     — list (paginated)
//!   GET    /api-specs/{id}                — fetch one spec (with content negotiation)
//!   GET    /api-specs/by-proxy/{proxy_id} — lookup by proxy
//!   DELETE /api-specs/{id}                — delete

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::api_specs::{
    ExtractError, ExtractedBundle, SpecFormat, extract, hash_resource_bundle,
};
use crate::admin::spec_codec;
use crate::config::db_backend::{ApiSpecListFilter, ApiSpecSortBy, DatabaseBackend, SortOrder};
use crate::config::types::{ApiSpec, PluginAssociation};

// ---------------------------------------------------------------------------
// Internal error type
// ---------------------------------------------------------------------------

/// Handler-local error type that maps cleanly to HTTP statuses.
///
/// All arms are converted to `Response<Full<Bytes>>` before leaving this
/// module; callers never see `ApiSpecError` directly.
#[derive(Debug)]
enum ApiSpecError {
    /// Body too large (413)
    PayloadTooLarge(usize),
    /// Body collection error (non-size)
    BodyCollect(String),
    /// Extraction/parse error (400)
    Extract(ExtractError),
    /// Generic 400 (invalid query params, etc.)
    BadRequest(String),
    /// Validation failures (422)
    ValidationFailures {
        spec_version: String,
        failures: Vec<ValidationFailure>,
    },
    /// Resource not found (404)
    NotFound,
    /// Unique constraint / conflict (409)
    Conflict(String),
    /// MongoDB doc size limit (413)
    MongoDocTooLarge,
    /// FK or business-logic violation (422)
    Unprocessable(String),
    /// No DB configured (503)
    NoDatabase,
    /// Generic DB or internal error (500)
    Internal(String),
}

#[derive(Debug, serde::Serialize)]
struct ValidationFailure {
    resource_type: &'static str,
    id: String,
    errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Helper: map anyhow::Error from DB calls to ApiSpecError
// ---------------------------------------------------------------------------

fn classify_db_error(e: anyhow::Error) -> ApiSpecError {
    let msg = e.to_string();
    classify_db_error_str(&msg)
}

fn classify_db_error_str(msg: &str) -> ApiSpecError {
    let lower = msg.to_lowercase();
    if lower.contains("unique constraint")
        || lower.contains("duplicate key")
        || lower.contains("duplicate entry")
        || lower.contains("duplicate")
    {
        ApiSpecError::Conflict(msg.to_string())
    } else if msg.contains("MongoDB document limit") {
        ApiSpecError::MongoDocTooLarge
    } else if lower.contains("foreign key constraint")
        || lower.contains("foreign key")
        || lower.contains("references a")
    {
        ApiSpecError::Unprocessable(msg.to_string())
    } else {
        ApiSpecError::Internal(msg.to_string())
    }
}

// ---------------------------------------------------------------------------
// Helper: convert ApiSpecError → HTTP Response
// ---------------------------------------------------------------------------

fn error_response(err: ApiSpecError) -> Response<Full<Bytes>> {
    match err {
        ApiSpecError::PayloadTooLarge(max_mib) => json_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            &json!({"error": format!("Request body too large (max {} MiB)", max_mib)}),
        ),
        ApiSpecError::BodyCollect(msg) => json_resp(
            StatusCode::BAD_REQUEST,
            &json!({"error": format!("Failed to read request body: {}", msg)}),
        ),
        ApiSpecError::BadRequest(msg) => json_resp(StatusCode::BAD_REQUEST, &json!({"error": msg})),
        ApiSpecError::Extract(e) => {
            let code = extract_error_code(&e);
            // Parse-time errors (syntactically invalid or structurally missing
            // required fields) → 400 Bad Request.
            // Semantic-violation errors (valid structure but forbidden by
            // Ferrum policy) → 422 Unprocessable Entity, matching how the
            // ValidationFailures path behaves.
            let status = extract_error_status(&e);
            json_resp(
                status,
                &json!({
                    "error": "Spec parse failed",
                    "code": code,
                    "details": e.to_string()
                }),
            )
        }
        ApiSpecError::ValidationFailures {
            spec_version,
            failures,
        } => json_resp(
            StatusCode::UNPROCESSABLE_ENTITY,
            &json!({
                "error": "Spec validation failed",
                "spec_version": spec_version,
                "failures": failures
            }),
        ),
        ApiSpecError::NotFound => json_resp(
            StatusCode::NOT_FOUND,
            &json!({"error": "API spec not found"}),
        ),
        ApiSpecError::Conflict(msg) => json_resp(
            StatusCode::CONFLICT,
            &json!({"error": format!("Conflict: {}", msg)}),
        ),
        ApiSpecError::MongoDocTooLarge => json_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            &json!({"error": "Spec document exceeds MongoDB document size limit"}),
        ),
        ApiSpecError::Unprocessable(msg) => {
            json_resp(StatusCode::UNPROCESSABLE_ENTITY, &json!({"error": msg}))
        }
        ApiSpecError::NoDatabase => json_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database configured"}),
        ),
        ApiSpecError::Internal(msg) => {
            tracing::error!("api-specs internal error: {}", msg);
            json_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": "Internal server error"}),
            )
        }
    }
}

/// Short discriminant string for `ExtractError` variants.
fn extract_error_code(e: &ExtractError) -> &'static str {
    match e {
        ExtractError::InvalidJson(_) => "InvalidJson",
        ExtractError::InvalidYaml(_) => "InvalidYaml",
        ExtractError::UnknownVersion => "UnknownVersion",
        ExtractError::MissingProxyExtension => "MissingProxyExtension",
        ExtractError::MalformedExtension { .. } => "MalformedExtension",
        ExtractError::ConsumerExtensionNotAllowed => "ConsumerExtensionNotAllowed",
        ExtractError::PluginInvalidScope { .. } => "PluginInvalidScope",
        ExtractError::PluginProxyIdMismatch { .. } => "PluginProxyIdMismatch",
        ExtractError::PluginContainsCredentials { .. } => "PluginContainsCredentials",
        ExtractError::ProxyUpstreamIdMismatch { .. } => "ProxyUpstreamIdMismatch",
        ExtractError::InvalidTagName { .. } => "InvalidTagName",
    }
}

/// HTTP status code for an `ExtractError`.
///
/// Parse-time / structural errors → 400 Bad Request (the document is malformed
/// or missing required fields at the syntax level).
///
/// Semantic-violation errors → 422 Unprocessable Entity (the document is
/// syntactically valid but violates Ferrum policy rules, just like
/// `ValidationFailures` which already returns 422).
fn extract_error_status(e: &ExtractError) -> StatusCode {
    match e {
        // Parse-time / structural: 400
        ExtractError::InvalidJson(_)
        | ExtractError::InvalidYaml(_)
        | ExtractError::UnknownVersion
        | ExtractError::MissingProxyExtension
        | ExtractError::MalformedExtension { .. } => StatusCode::BAD_REQUEST,
        // Semantic violations: 422
        ExtractError::ConsumerExtensionNotAllowed
        | ExtractError::PluginInvalidScope { .. }
        | ExtractError::PluginProxyIdMismatch { .. }
        | ExtractError::PluginContainsCredentials { .. }
        | ExtractError::ProxyUpstreamIdMismatch { .. }
        | ExtractError::InvalidTagName { .. } => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

// ---------------------------------------------------------------------------
// Helper: parse Content-Type → SpecFormat
// ---------------------------------------------------------------------------

/// Parse the `Content-Type` header into a `SpecFormat` hint.
///
/// Accepts:
///   - `application/json`               → `Some(Json)`
///   - `application/yaml`               → `Some(Yaml)`
///   - `application/x-yaml`             → `Some(Yaml)`
///   - `text/yaml`                      → `Some(Yaml)`
///   - `text/x-yaml`                    → `Some(Yaml)`
///   - anything else / missing          → `None` (autodetect)
pub(super) fn parse_content_type(headers: &hyper::HeaderMap) -> Option<SpecFormat> {
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Strip parameters (e.g. `application/json; charset=utf-8`)
    let mime = ct.split(';').next().unwrap_or("").trim();
    match mime {
        "application/json" => Some(SpecFormat::Json),
        "application/yaml" | "application/x-yaml" | "text/yaml" | "text/x-yaml" => {
            Some(SpecFormat::Yaml)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helper: Accept header negotiation for GET responses
// ---------------------------------------------------------------------------

/// Resolve the response format from an `Accept` header vs the stored format.
///
/// Returns the `SpecFormat` the caller should use to serialise the body.
///
/// Rules:
/// - Missing, `*/*`, or matching stored format → stored format
/// - `application/json` and stored is YAML     → Json (convert)
/// - `application/yaml` / `text/yaml` etc. and stored is JSON → Yaml (convert)
/// - Unknown accept types                       → stored format (best-effort)
///
/// Uses a small media-range parser: splits on `,`, strips `q=` quality
/// parameters, trims whitespace, and compares exact tokens.  Wildcards
/// (`*/*`, `application/*`) accept the stored format.  Highest-quality
/// match wins; ties resolve to the first listed entry.
pub(super) fn negotiate_accept(headers: &hyper::HeaderMap, stored: SpecFormat) -> SpecFormat {
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if accept.is_empty() {
        return stored;
    }

    /// Quality weight for a media range, parsed from `;q=N.NNN`.
    /// Returns a value in `[0, 1000]` (1000 = q=1.0, default).
    fn parse_quality(params: &str) -> u32 {
        for param in params.split(';') {
            let p = param.trim();
            if let Some(rest) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")) {
                // Parse up to 3 decimal places; clamp to [0, 1000].
                if let Ok(f) = rest.parse::<f64>() {
                    return (f * 1000.0).round().clamp(0.0, 1000.0) as u32;
                }
            }
        }
        1000 // default q=1.0
    }

    let mut best_json: Option<u32> = None;
    let mut best_yaml: Option<u32> = None;
    let mut best_wildcard: Option<u32> = None;
    let mut best_stored: Option<u32> = None;

    for entry in accept.split(',') {
        // Split type/subtype from parameters.
        let mut parts = entry.splitn(2, ';');
        let media_type = parts.next().unwrap_or("").trim();
        let params = parts.next().unwrap_or("");
        let q = parse_quality(params);

        match media_type {
            "*/*" | "application/*" => {
                if best_wildcard.map_or(true, |prev| q > prev) {
                    best_wildcard = Some(q);
                }
            }
            "application/json" => {
                if best_json.map_or(true, |prev| q > prev) {
                    best_json = Some(q);
                }
            }
            "application/yaml" | "application/x-yaml" | "text/yaml" | "text/x-yaml" => {
                if best_yaml.map_or(true, |prev| q > prev) {
                    best_yaml = Some(q);
                }
            }
            m if m
                == match stored {
                    SpecFormat::Json => "application/json",
                    SpecFormat::Yaml => "application/yaml",
                } =>
            {
                if best_stored.map_or(true, |prev| q > prev) {
                    best_stored = Some(q);
                }
            }
            _ => {} // unknown media type — ignored
        }
    }

    // Determine the best-quality format.
    // Wildcard and "exact stored" both map to `stored`; they are treated
    // together as the same outcome.
    let stored_quality = best_stored.or(best_wildcard).unwrap_or(0);
    let json_quality = best_json.unwrap_or(0);
    let yaml_quality = best_yaml.unwrap_or(0);

    // If no explicit preference was found, default to stored format.
    if json_quality == 0 && yaml_quality == 0 && stored_quality == 0 {
        return stored;
    }

    if json_quality >= yaml_quality && json_quality >= stored_quality {
        SpecFormat::Json
    } else if yaml_quality >= json_quality && yaml_quality >= stored_quality {
        SpecFormat::Yaml
    } else {
        stored
    }
}

#[cfg(test)]
mod negotiate_accept_tests {
    use super::*;

    fn headers_with_accept(accept: &str) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            "accept",
            hyper::header::HeaderValue::from_str(accept).unwrap(),
        );
        h
    }

    #[test]
    fn negotiate_accept_exact_json() {
        let h = headers_with_accept("application/json");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Json,
            "application/json must select JSON even when stored is YAML"
        );
    }

    #[test]
    fn negotiate_accept_exact_yaml() {
        let h = headers_with_accept("application/yaml");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Json),
            SpecFormat::Yaml,
            "application/yaml must select YAML even when stored is JSON"
        );
    }

    #[test]
    fn negotiate_accept_does_not_match_jsonpath_plus_json() {
        // "application/jsonpath+json" contains "application/json" as a
        // substring; the old `contains()` check would have matched it.
        let h = headers_with_accept("application/jsonpath+json");
        // Unknown media type → fall back to stored format.
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Yaml,
            "application/jsonpath+json must NOT trigger JSON negotiation"
        );
    }

    #[test]
    fn negotiate_accept_wildcard() {
        let h = headers_with_accept("*/*");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Yaml,
            "*/* must return stored format"
        );
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Json),
            SpecFormat::Json,
            "*/* must return stored format"
        );
    }

    #[test]
    fn negotiate_accept_quality_ordering() {
        // YAML at q=0.9, JSON at q=1.0 — JSON wins.
        let h = headers_with_accept("application/yaml;q=0.9, application/json;q=1.0");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Json,
            "highest-quality type must win"
        );
        // JSON at q=0.5, YAML at q=0.9 — YAML wins.
        let h2 = headers_with_accept("application/json;q=0.5, application/yaml;q=0.9");
        assert_eq!(
            negotiate_accept(&h2, SpecFormat::Json),
            SpecFormat::Yaml,
            "highest-quality type must win"
        );
    }

    #[test]
    fn negotiate_accept_missing_or_empty_returns_stored_format() {
        let empty = hyper::HeaderMap::new();
        assert_eq!(
            negotiate_accept(&empty, SpecFormat::Json),
            SpecFormat::Json,
            "missing Accept must return stored format"
        );
        let h = headers_with_accept("");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Yaml,
            "empty Accept must return stored format"
        );
    }
}

/// Content-Type string for a `SpecFormat`.
fn content_type_for_format(fmt: SpecFormat) -> &'static str {
    match fmt {
        SpecFormat::Json => "application/json",
        SpecFormat::Yaml => "application/yaml",
    }
}

/// Convert spec bytes between formats.
///
/// Returns `Err` if the conversion fails (malformed source document).
fn convert_format(body: &[u8], from: SpecFormat, to: SpecFormat) -> Result<Vec<u8>, String> {
    if from == to {
        return Ok(body.to_vec());
    }
    match (from, to) {
        (SpecFormat::Yaml, SpecFormat::Json) => {
            let val: serde_yaml::Value = serde_yaml::from_slice(body)
                .map_err(|e| format!("YAML parse error during conversion: {e}"))?;
            let jv: serde_json::Value = serde_json::to_value(val)
                .map_err(|e| format!("YAML→JSON conversion error: {e}"))?;
            serde_json::to_vec_pretty(&jv).map_err(|e| format!("JSON serialization error: {e}"))
        }
        (SpecFormat::Json, SpecFormat::Yaml) => {
            let jv: serde_json::Value = serde_json::from_slice(body)
                .map_err(|e| format!("JSON parse error during conversion: {e}"))?;
            let yv: serde_yaml::Value = serde_json::from_value(jv)
                .map_err(|e| format!("JSON→YAML conversion error: {e}"))?;
            serde_yaml::to_string(&yv)
                .map(|s| s.into_bytes())
                .map_err(|e| format!("YAML serialization error: {e}"))
        }
        _ => unreachable!("same format handled above"),
    }
}

// ---------------------------------------------------------------------------
// Helper: collect body with a size limit
// ---------------------------------------------------------------------------

async fn collect_body(req: Request<Incoming>, max_mib: usize) -> Result<Vec<u8>, ApiSpecError> {
    let max_bytes = max_mib * 1024 * 1024;
    match Limited::new(req.into_body(), max_bytes).collect().await {
        Ok(collected) => Ok(collected.to_bytes().to_vec()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("length limit exceeded") {
                Err(ApiSpecError::PayloadTooLarge(max_mib))
            } else {
                Err(ApiSpecError::BodyCollect(msg))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: require DB
// ---------------------------------------------------------------------------

fn require_db(state: &AdminState) -> Result<&Arc<dyn DatabaseBackend>, ApiSpecError> {
    state.db.as_ref().ok_or(ApiSpecError::NoDatabase)
}

// ---------------------------------------------------------------------------
// ID assignment helpers (Fix 1 — PUT idempotency)
// ---------------------------------------------------------------------------

/// Assign IDs to bundle resources for the POST path.
///
/// For each resource (proxy, upstream, plugins) with an empty `id`, mints a
/// new UUID. Re-links cross-references so `plugin.proxy_id` and
/// `proxy.upstream_id` always reference the final IDs. Rebuilds the proxy
/// `plugins` association list to reference the final plugin IDs.
///
/// Also stamps server-side `created_at`/`updated_at` timestamps so any
/// operator-supplied timestamps in the spec document are ignored — the
/// polling cycle's incremental delta path uses `updated_at > since`, and
/// stale embedded timestamps would cause real config changes to be skipped.
fn assign_ids_for_post(bundle: &mut ExtractedBundle) {
    // Proxy
    if bundle.proxy.id.is_empty() {
        bundle.proxy.id = Uuid::new_v4().to_string();
    }

    // Upstream
    if let Some(ref mut u) = bundle.upstream {
        if u.id.is_empty() {
            u.id = Uuid::new_v4().to_string();
        }
    }

    // Plugins — assign IDs then re-link proxy_id
    for pc in &mut bundle.plugins {
        if pc.id.is_empty() {
            pc.id = Uuid::new_v4().to_string();
        }
        pc.proxy_id = Some(bundle.proxy.id.clone());
    }

    // Re-link proxy.upstream_id
    if let Some(ref u) = bundle.upstream {
        if bundle.proxy.upstream_id.as_deref().unwrap_or("").is_empty() {
            bundle.proxy.upstream_id = Some(u.id.clone());
        }
    }

    // Stamp server-side timestamps (Fix 1). Mirrors handle_write's convention:
    //   Create → set_created_at(now) + set_updated_at(now).
    // This overwrites any operator-embedded timestamps from the spec document.
    let now = Utc::now();
    bundle.proxy.created_at = now;
    bundle.proxy.updated_at = now;
    if let Some(ref mut u) = bundle.upstream {
        u.created_at = now;
        u.updated_at = now;
    }
    for pc in &mut bundle.plugins {
        pc.created_at = now;
        pc.updated_at = now;
    }

    // Rebuild proxy.plugins association list with final plugin IDs.
    // Preserve any operator-written associations pointing to pre-existing
    // plugins (non-empty IDs that are NOT in bundle.plugins are left as-is).
    let spec_plugin_ids: Vec<String> = bundle.plugins.iter().map(|p| p.id.clone()).collect();
    // Remove stale associations that used the now-replaced empty IDs, then
    // add the final ones. The simplest safe approach: keep associations whose
    // plugin_config_id is non-empty and NOT an empty-string leftover, then
    // merge in the spec-extracted final IDs.
    let mut assocs: Vec<PluginAssociation> = bundle
        .proxy
        .plugins
        .drain(..)
        .filter(|a| {
            // Keep operator-written associations to pre-existing plugins
            // (non-empty IDs that are not in the spec-extracted list).
            !a.plugin_config_id.is_empty() && !spec_plugin_ids.contains(&a.plugin_config_id)
        })
        .collect();
    for id in &spec_plugin_ids {
        if !assocs.iter().any(|a| &a.plugin_config_id == id) {
            assocs.push(PluginAssociation {
                plugin_config_id: id.clone(),
            });
        }
    }
    bundle.proxy.plugins = assocs;
}

/// Assign IDs to bundle resources for the PUT path, reusing existing stored
/// IDs where the spec leaves IDs empty so re-submitting the same ID-less spec
/// is idempotent.
///
/// Matching strategy:
/// - `proxy.id`: always use `existing_proxy_id` (the same-proxy-id rule
///   enforces this anyway; if the spec sets a non-matching proxy.id
///   explicitly, the immutability check catches it later).
/// - `upstream.id`: if empty, reuse existing `proxy.upstream_id` if `Some`
///   and non-empty, else mint UUID.
/// - `plugin.id`: if empty, match by canonical `(plugin_name, config_json,
///   priority_override)` tuple against existing spec-owned plugins (Fix 5).
///   If two extracted plugins share the same plugin_name with DIFFERENT
///   configs, explicit IDs are required — returns a structured error.
///   If they share the same name AND identical canonical config, falls back
///   to FIFO ordering (deterministic index pairing). If no match found, mints
///   a new UUID.
/// - For non-empty extracted IDs, leave as-is — operator opted in.
///
/// Also stamps server-side timestamps (Fix 1): `updated_at = now` always;
/// `created_at` is preserved from the stored row on PUT, or set to `now` for
/// genuinely new resources introduced by this PUT.
///
/// After ID assignment, re-links: `proxy.upstream_id = upstream.id` (if
/// present); `plugin.proxy_id = proxy.id`; rebuilds `proxy.plugins`
/// association list to reference the final plugin IDs.
async fn assign_ids_for_put(
    bundle: &mut ExtractedBundle,
    db: &Arc<dyn DatabaseBackend>,
    namespace: &str,
    existing_spec: &ApiSpec,
    spec_version: &str,
) -> Result<(), ApiSpecError> {
    // If proxy.id is empty (operator did not supply one), fill it in from
    // the existing spec so the resource hash + immutability check work correctly.
    // If the operator supplied a non-empty proxy.id, leave it; the immutability
    // check downstream will reject it if it differs from existing_spec.proxy_id.
    if bundle.proxy.id.is_empty() {
        bundle.proxy.id = existing_spec.proxy_id.clone();
    }

    // Load the existing proxy to get upstream_id and created_at.
    let existing_proxy = match db.get_proxy(&existing_spec.proxy_id).await {
        Ok(Some(p)) => Some(p),
        Ok(None) => None,
        Err(e) => return Err(classify_db_error(e)),
    };

    // Upstream ID: reuse existing if empty.
    if let Some(ref mut u) = bundle.upstream {
        if u.id.is_empty() {
            let reuse_id = existing_proxy
                .as_ref()
                .and_then(|p| p.upstream_id.as_deref())
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            u.id = reuse_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        }
    }

    // Load existing spec-owned plugins for canonical-tuple matching (Fix 5).
    let existing_plugins = match db
        .list_spec_owned_plugin_configs(namespace, &existing_spec.id)
        .await
    {
        Ok(v) => v,
        Err(e) => return Err(classify_db_error(e)),
    };

    // Build a map from canonical key → FIFO queue of existing plugins.
    // Canonical key = (plugin_name, sorted-keys config JSON, priority_override).
    let mut canonical_to_existing: std::collections::HashMap<
        (String, String, Option<u16>),
        std::collections::VecDeque<&crate::config::types::PluginConfig>,
    > = std::collections::HashMap::new();
    for ep in &existing_plugins {
        canonical_to_existing
            .entry(plugin_canonical_key(ep))
            .or_default()
            .push_back(ep);
    }

    // Count how many extracted (empty-id) plugins share each plugin_name, so
    // we can detect the ambiguous case: same name, different configs, both
    // without explicit IDs.  Use owned `String` keys so the map does not hold
    // borrows on bundle.plugins across the later mutable loop.
    let mut extracted_name_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for pc in &bundle.plugins {
        if pc.id.is_empty() {
            *extracted_name_counts
                .entry(pc.plugin_name.clone())
                .or_default() += 1;
        }
    }

    // Snapshot proxy_id before the mutable plugin loop to avoid split borrows.
    let proxy_id_snap = bundle.proxy.id.clone();

    // Assign plugin IDs (Fix 5 canonical matching).
    for pc in &mut bundle.plugins {
        if !pc.id.is_empty() {
            // Operator supplied an explicit ID — leave as-is.
            pc.proxy_id = Some(proxy_id_snap.clone());
            continue;
        }

        let key = plugin_canonical_key(pc);
        if let Some(q) = canonical_to_existing.get_mut(&key) {
            if let Some(matched) = q.pop_front() {
                // Exact canonical match — reuse the stored ID.
                pc.id = matched.id.clone();
                pc.proxy_id = Some(proxy_id_snap.clone());
                continue;
            }
        }

        // No exact canonical match. If this plugin_name has more than one
        // extracted instance without explicit IDs, we cannot safely assign
        // an existing ID without risking config-identity swaps. Reject with a
        // structured error so operators learn to use explicit IDs.
        if *extracted_name_counts.get(&pc.plugin_name).unwrap_or(&0) > 1 {
            return Err(ApiSpecError::ValidationFailures {
                spec_version: spec_version.to_string(),
                failures: vec![ValidationFailure {
                    resource_type: "plugin",
                    id: proxy_id_snap.clone(),
                    errors: vec![format!(
                        "duplicate plugin_name '{}' on PUT requires explicit ids to disambiguate; \
                         set a non-empty 'id' on each instance",
                        pc.plugin_name
                    )],
                }],
            });
        }

        // New plugin or config genuinely changed — mint a fresh UUID.
        pc.id = Uuid::new_v4().to_string();
        pc.proxy_id = Some(proxy_id_snap.clone());
    }

    // Re-link proxy.upstream_id.
    if let Some(ref u) = bundle.upstream {
        if bundle.proxy.upstream_id.as_deref().unwrap_or("").is_empty() {
            bundle.proxy.upstream_id = Some(u.id.clone());
        }
    }

    // Stamp server-side timestamps (Fix 1). Mirrors handle_write's convention:
    //   Update → set_updated_at(now), preserve created_at from stored row.
    let now = Utc::now();

    // Proxy: preserve stored created_at, refresh updated_at.
    bundle.proxy.updated_at = now;
    bundle.proxy.created_at = existing_proxy.as_ref().map(|p| p.created_at).unwrap_or(now);

    // Upstream: preserve existing created_at if the same ID is being reused.
    if let Some(ref mut u) = bundle.upstream {
        u.updated_at = now;
        // If the upstream ID matches what was previously stored, preserve its
        // created_at. Otherwise (new upstream) use now.
        let stored_upstream_id = existing_proxy
            .as_ref()
            .and_then(|p| p.upstream_id.as_deref())
            .unwrap_or("");
        if u.id == stored_upstream_id {
            // Fetch the stored upstream's created_at if available.
            if let Ok(Some(stored_upstream)) = db.get_upstream(&u.id).await {
                u.created_at = stored_upstream.created_at;
            } else {
                u.created_at = now;
            }
        } else {
            u.created_at = now;
        }
    }

    // Plugins: for each plugin, if we reused an existing stored ID, preserve
    // that plugin's created_at. For genuinely new plugins, use now.
    let existing_plugin_map: std::collections::HashMap<&str, &crate::config::types::PluginConfig> =
        existing_plugins
            .iter()
            .map(|ep| (ep.id.as_str(), ep))
            .collect();
    for pc in &mut bundle.plugins {
        pc.updated_at = now;
        pc.created_at = existing_plugin_map
            .get(pc.id.as_str())
            .map(|ep| ep.created_at)
            .unwrap_or(now);
    }

    // Rebuild proxy.plugins association list with final plugin IDs.
    let spec_plugin_ids: Vec<String> = bundle.plugins.iter().map(|p| p.id.clone()).collect();
    let mut assocs: Vec<PluginAssociation> = bundle
        .proxy
        .plugins
        .drain(..)
        .filter(|a| {
            !a.plugin_config_id.is_empty() && !spec_plugin_ids.contains(&a.plugin_config_id)
        })
        .collect();
    for id in &spec_plugin_ids {
        if !assocs.iter().any(|a| &a.plugin_config_id == id) {
            assocs.push(PluginAssociation {
                plugin_config_id: id.clone(),
            });
        }
    }
    bundle.proxy.plugins = assocs;

    Ok(())
}

/// Compute the canonical matching key for a plugin during PUT id-assignment.
///
/// The key is `(plugin_name, sorted-keys config JSON, priority_override)`.
/// Sorting JSON object keys via a `BTreeMap` round-trip ensures two configs
/// with the same key-value pairs but different insertion order compare equal,
/// which is necessary for idempotent re-submission of specs produced by
/// different tooling.
fn plugin_canonical_key(pc: &crate::config::types::PluginConfig) -> (String, String, Option<u16>) {
    let canonical_config = sort_json_keys(&pc.config);
    let config_str = serde_json::to_string(&canonical_config).unwrap_or_default();
    (pc.plugin_name.clone(), config_str, pc.priority_override)
}

/// Recursively sort all JSON object keys so that canonical comparison is
/// key-order-independent. Arrays are left in their original order (order
/// matters for arrays). Uses a `BTreeMap` round-trip for objects.
fn sort_json_keys(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(k, val)| (k.clone(), sort_json_keys(val)))
                .collect();
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_keys).collect())
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// Shared validate logic (POST and PUT share the validation pipeline)
// ---------------------------------------------------------------------------

struct ValidatedBundle {
    bundle: ExtractedBundle,
    metadata: crate::admin::api_specs::SpecMetadata,
}

/// Validate an already-extracted and ID-assigned bundle.
///
/// `existing_proxy_id` — when `Some`, the uniqueness checks exclude this proxy
/// (PUT path). `existing_upstream_id` — analogous for upstream name check.
/// `existing_proxy` — the stored proxy row for PUT requests; used to detect
/// listen_port / transport changes so the OS-level port-availability probe is
/// only fired when the port or transport actually changed.
async fn validate_bundle(
    mut bundle: ExtractedBundle,
    metadata: crate::admin::api_specs::SpecMetadata,
    namespace: &str,
    db: &dyn DatabaseBackend,
    state: &AdminState,
    existing_proxy_id: Option<&str>,
    existing_upstream_id: Option<&str>,
    existing_proxy: Option<&crate::config::types::Proxy>,
) -> Result<ValidatedBundle, ApiSpecError> {
    // ID assignment (minting UUIDs for empty IDs) is the caller's responsibility
    // (assign_ids_for_post / assign_ids_for_put) and happens BEFORE this
    // function is called. By the time we arrive here, all resource IDs are
    // non-empty. Malformed non-empty ids surface as ExtractError::MalformedExtension
    // → 400, consistent with other parse errors.

    // --- Normalize + validate bundle resources ---

    use crate::admin::crud::ValidationCtx;
    let vctx = ValidationCtx::from_state(state);
    let mut failures: Vec<ValidationFailure> = Vec::new();

    // Upstream
    if let Some(ref mut upstream) = bundle.upstream {
        upstream.normalize_fields();
        if let Err(e) = upstream.validate_fields() {
            failures.push(ValidationFailure {
                resource_type: "upstream",
                id: upstream.id.clone(),
                errors: e,
            });
        }
    }

    // Proxy
    {
        bundle.proxy.normalize_fields();
        let proxy = &bundle.proxy;

        let mut proxy_errors: Vec<String> = Vec::new();

        // validate_fields covers scheme, port, listen_path regex, etc.
        if let Err(e) = proxy.validate_fields() {
            proxy_errors.extend(e);
        }
        // Host entry validation
        for host in &proxy.hosts {
            if let Err(msg) = crate::config::types::validate_host_entry(host) {
                proxy_errors.push(format!("Invalid proxy hosts: {msg}"));
            }
        }
        // Stream proxy must have listen_port
        if proxy.dispatch_kind.is_stream() {
            match proxy.listen_port {
                None => proxy_errors.push(format!(
                    "Stream proxy (scheme {}) must have a listen_port",
                    proxy.scheme_display()
                )),
                Some(0) => proxy_errors.push("listen_port 0 must be >= 1".to_string()),
                Some(_) => {}
            }
        } else if proxy.listen_port.is_some() {
            proxy_errors.push(format!(
                "HTTP proxy (scheme {}) must not set listen_port",
                proxy.scheme_display()
            ));
        }

        if !proxy_errors.is_empty() {
            failures.push(ValidationFailure {
                resource_type: "proxy",
                id: proxy.id.clone(),
                errors: proxy_errors,
            });
        }
    }

    // Plugins
    for plugin in &bundle.plugins {
        let mut plugin_errors: Vec<String> = Vec::new();

        // Generic PluginConfig field constraints (Fix 3): priority_override
        // range, config JSON size, nesting depth.  Direct admin runs
        // validate_fields() on every PluginConfig before persistence; we
        // must do the same here.
        if let Err(errs) = plugin.validate_fields() {
            plugin_errors.extend(errs);
        }

        // Plugin-specific config schema validation.
        if let Err(e) = crate::plugins::validate_plugin_config(&plugin.plugin_name, &plugin.config)
        {
            plugin_errors.push(e);
        }

        if !plugin_errors.is_empty() {
            failures.push(ValidationFailure {
                resource_type: "plugin",
                id: plugin.id.clone(),
                errors: plugin_errors,
            });
        }
    }

    // Duplicate proxy plugin associations (Fix 4): detect operator-written
    // duplicate plugin_config_id entries in bundle.proxy.plugins.  SQL's
    // proxy_plugins(proxy_id, plugin_config_id) PK would conflict on insert;
    // MongoDB would persist duplicates and runtime validate_plugin_references
    // would reject.
    {
        let mut seen_assoc_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut dupe_assoc_ids: Vec<String> = Vec::new();
        for assoc in &bundle.proxy.plugins {
            if !seen_assoc_ids.insert(assoc.plugin_config_id.as_str()) {
                dupe_assoc_ids.push(assoc.plugin_config_id.clone());
            }
        }
        if !dupe_assoc_ids.is_empty() {
            failures.push(ValidationFailure {
                resource_type: "proxy_plugin_association",
                id: bundle.proxy.id.clone(),
                errors: dupe_assoc_ids
                    .iter()
                    .map(|id| format!("duplicate plugin_config_id '{id}' in proxy.plugins"))
                    .collect(),
            });
        }
    }

    // Proxy plugin associations (Fix 2) — validate any operator-written
    // associations in x-ferrum-proxy.plugins that reference pre-existing
    // plugins (spec-extracted plugins are in bundle.plugins and are always
    // OK; associations pointing to non-existent or wrong-proxy plugins are
    // rejected here rather than silently admitted and only caught at
    // load_full_config time).
    {
        // Filter to associations NOT covered by bundle.plugins (operator-written only).
        let new_plugin_ids: std::collections::HashSet<&str> =
            bundle.plugins.iter().map(|p| p.id.as_str()).collect();
        let extra_associations: Vec<&PluginAssociation> = bundle
            .proxy
            .plugins
            .iter()
            .filter(|a| !new_plugin_ids.contains(a.plugin_config_id.as_str()))
            .collect();

        if !extra_associations.is_empty() {
            let proxy_id = bundle.proxy.id.clone();
            let mut assoc_errors: Vec<String> = Vec::new();

            for assoc in &extra_associations {
                let pid = &assoc.plugin_config_id;
                match db.get_plugin_config(pid).await {
                    Ok(Some(existing)) => {
                        use crate::config::types::PluginScope;
                        match existing.scope {
                            PluginScope::Global => {
                                // Mirrors the system-wide invariant enforced by
                                // GatewayConfig::validate_plugin_references and SQL
                                // validate_proxy_plugin_associations: proxy
                                // associations may only reference proxy-scoped or
                                // proxy_group-scoped plugin configs. Global plugins
                                // apply implicitly via the plugin_cache and must
                                // remain unassociated.
                                assoc_errors.push(format!(
                                    "plugin_config_id '{}' has scope=global; global plugins must remain unassociated",
                                    pid
                                ));
                            }
                            PluginScope::ProxyGroup => {
                                // Any proxy may reference a ProxyGroup plugin.
                            }
                            PluginScope::Proxy => {
                                if existing.proxy_id.as_deref() != Some(proxy_id.as_str()) {
                                    assoc_errors.push(format!(
                                        "plugin_config_id '{}' belongs to proxy '{}', not '{}'",
                                        pid,
                                        existing.proxy_id.as_deref().unwrap_or("<none>"),
                                        proxy_id
                                    ));
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        assoc_errors.push(format!("plugin_config_id '{}' does not exist", pid));
                    }
                    Err(e) => return Err(classify_db_error(e)),
                }
            }

            if !assoc_errors.is_empty() {
                failures.push(ValidationFailure {
                    resource_type: "proxy_plugin_association",
                    id: proxy_id,
                    errors: assoc_errors,
                });
            }
        }
    }

    // DB cross-checks (only when no structural failures found — avoids spurious FK errors)
    if failures.is_empty() {
        let proxy = &bundle.proxy;

        // --- Fix 1: upstream_id existence check ---
        // Mirrors Proxy::after_validate in crud.rs: when the proxy references an
        // upstream by ID, verify the upstream actually exists.  If the bundle
        // includes its own upstream (x-ferrum-upstream) whose ID matches, we
        // accept it without a DB round-trip (it's about to be inserted).
        // Otherwise call check_upstream_exists and reject with 422 if missing.
        if let Some(ref upstream_id) = proxy.upstream_id {
            let bundled_id_matches = bundle
                .upstream
                .as_ref()
                .map(|u| u.id.as_str() == upstream_id.as_str())
                .unwrap_or(false);
            if !bundled_id_matches {
                match db.check_upstream_exists(upstream_id).await {
                    Ok(true) => {}
                    Ok(false) => failures.push(ValidationFailure {
                        resource_type: "proxy",
                        id: proxy.id.clone(),
                        errors: vec![format!("upstream_id '{upstream_id}' does not exist")],
                    }),
                    Err(e) => return Err(classify_db_error(e)),
                }
            }
        }

        if proxy.dispatch_kind.is_stream() {
            // Stream-family: validate port uniqueness, reserved-port conflict, and
            // OS-level port availability.
            // Mirrors Proxy::check_uniqueness + Proxy::after_validate in crud.rs.
            if let Some(port) = proxy.listen_port {
                // Port uniqueness (across all stream proxies in this namespace).
                match db
                    .check_listen_port_unique(namespace, port, existing_proxy_id)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => failures.push(ValidationFailure {
                        resource_type: "proxy",
                        id: proxy.id.clone(),
                        errors: vec![format!(
                            "listen_port {port} is already in use by another proxy"
                        )],
                    }),
                    Err(e) => return Err(classify_db_error(e)),
                }

                // Reserved gateway ports check (skip in CP mode — CP can't know each
                // DP's reserved ports; matches the Proxy::after_validate guard).
                if vctx.mode != "cp" && vctx.reserved_ports.contains(&port) {
                    failures.push(ValidationFailure {
                        resource_type: "proxy",
                        id: proxy.id.clone(),
                        errors: vec![format!(
                            "listen_port {port} conflicts with a gateway reserved port \
                             (proxy/admin/gRPC listener)"
                        )],
                    });
                }

                // --- Fix 2: OS-level port availability probe ---
                // Mirrors the Proxy::after_validate check in crud.rs.
                // Skip in CP mode — CP can't know each DP's OS bind state.
                // Skip on PUT when neither the port nor the transport changed.
                if vctx.mode != "cp" && failures.is_empty() {
                    let port_changed = existing_proxy.and_then(|p| p.listen_port) != Some(port);
                    let transport_changed = existing_proxy
                        .map(|p| p.dispatch_kind.is_udp() != proxy.dispatch_kind.is_udp())
                        .unwrap_or(false);
                    let should_probe =
                        existing_proxy.is_none() || port_changed || transport_changed;
                    if should_probe {
                        if let Err(error) = crate::admin::crud::check_port_available(
                            port,
                            vctx.stream_bind_address,
                            proxy.dispatch_kind.is_udp(),
                        )
                        .await
                        {
                            failures.push(ValidationFailure {
                                resource_type: "proxy",
                                id: proxy.id.clone(),
                                errors: vec![format!(
                                    "listen_port {port} is not available on the host: {error}"
                                )],
                            });
                        }
                    }
                }
            }
        } else {
            // HTTP-family: validate listen_path + hosts uniqueness.
            // Exclude self when replacing (PUT path passes existing proxy id).
            match db
                .check_listen_path_unique(
                    namespace,
                    proxy.listen_path.as_deref(),
                    &proxy.hosts,
                    existing_proxy_id,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => failures.push(ValidationFailure {
                    resource_type: "proxy",
                    id: proxy.id.clone(),
                    errors: vec![
                        "A proxy with overlapping hosts and listen_path already exists".to_string(),
                    ],
                }),
                Err(e) => return Err(classify_db_error(e)),
            }
        }

        if let Some(name) = proxy.name.as_deref() {
            match db
                .check_proxy_name_unique(namespace, name, existing_proxy_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => failures.push(ValidationFailure {
                    resource_type: "proxy",
                    id: proxy.id.clone(),
                    errors: vec![format!("Proxy name '{}' already exists", name)],
                }),
                Err(e) => return Err(classify_db_error(e)),
            }
        }

        if let Some(ref upstream) = bundle.upstream {
            if let Some(ref name) = upstream.name {
                // On PUT, exclude the spec's current upstream so a spec that
                // keeps the same upstream name doesn't collide with itself.
                match db
                    .check_upstream_name_unique(namespace, name, existing_upstream_id)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => failures.push(ValidationFailure {
                        resource_type: "upstream",
                        id: upstream.id.clone(),
                        errors: vec![format!("An upstream with name '{}' already exists", name)],
                    }),
                    Err(e) => return Err(classify_db_error(e)),
                }
            }
        }
    }

    if !failures.is_empty() {
        return Err(ApiSpecError::ValidationFailures {
            spec_version: metadata.version.clone(),
            failures,
        });
    }

    Ok(ValidatedBundle { bundle, metadata })
}

/// Build an `ApiSpec` row from body bytes, metadata, and bundle.
fn build_spec_row(
    id: String,
    proxy_id: String,
    namespace: String,
    body: &[u8],
    metadata: &crate::admin::api_specs::SpecMetadata,
    bundle: &crate::admin::api_specs::ExtractedBundle,
) -> Result<ApiSpec, ApiSpecError> {
    let spec_content = spec_codec::compress_gzip(body)
        .map_err(|e| ApiSpecError::Internal(format!("gzip compress failed: {e}")))?;
    let content_hash = spec_codec::sha256_hex(body);
    let resource_hash = hash_resource_bundle(bundle);
    let now = Utc::now();
    Ok(ApiSpec {
        id,
        namespace,
        proxy_id,
        spec_version: metadata.version.clone(),
        spec_format: metadata.format,
        spec_content,
        content_encoding: "gzip".to_string(),
        uncompressed_size: body.len() as u64,
        content_hash,
        title: metadata.title.clone(),
        info_version: metadata.info_version.clone(),
        description: metadata.description.clone(),
        contact_name: metadata.contact_name.clone(),
        contact_email: metadata.contact_email.clone(),
        license_name: metadata.license_name.clone(),
        license_identifier: metadata.license_identifier.clone(),
        tags: metadata.tags.clone(),
        server_urls: metadata.server_urls.clone(),
        operation_count: metadata.operation_count,
        resource_hash,
        created_at: now,
        updated_at: now,
    })
}

// ---------------------------------------------------------------------------
// Helper: build spec-fetch response with ETag + content negotiation
// ---------------------------------------------------------------------------

/// `max_decompress_bytes` is the upper bound on decompressed output bytes.
/// Guards against corrupt or adversarially inflated DB rows.  Callers should
/// pass `2 * admin_spec_max_body_size_mib * 1024 * 1024`.
fn spec_content_response(
    spec: &ApiSpec,
    request_headers: &hyper::HeaderMap,
    max_decompress_bytes: usize,
) -> Response<Full<Bytes>> {
    // Decompress with an output cap.  A corrupted or bomb-ratio row from the
    // DB would otherwise expand to GB on every admin GET.
    let raw = match spec_codec::decompress_gzip_capped(&spec.spec_content, max_decompress_bytes) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                "decompress_gzip_capped failed for spec {} (cap={} bytes): {}",
                spec.id,
                max_decompress_bytes,
                e
            );
            return json_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": "spec content corrupt or oversized"}),
            );
        }
    };

    // ETag
    let etag = format!("\"{}\"", spec.content_hash);

    // If-None-Match check
    if let Some(inm) = request_headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        && (inm == etag || inm == "*")
    {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", etag)
            .header("Cache-Control", "no-store")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
    }

    // Content negotiation
    let target_fmt = negotiate_accept(request_headers, spec.spec_format);
    let (body_bytes, ct) = if target_fmt == spec.spec_format {
        (raw, content_type_for_format(spec.spec_format))
    } else {
        match convert_format(&raw, spec.spec_format, target_fmt) {
            Ok(converted) => (converted, content_type_for_format(target_fmt)),
            Err(e) => {
                // Conversion failed — the stored document is corrupt or not valid
                // in the stored format.  Return 406 so the caller knows the
                // requested format is unavailable; silently serving the wrong
                // Content-Type would confuse clients.
                //
                // Note: this path is hard to trigger in practice because
                // documents are validated at submit time, but a DB row that was
                // corrupted after storage or a future serialisation bug could
                // reach here.
                tracing::warn!(
                    "format conversion ({:?} → {:?}) failed for spec {}: {}",
                    spec.spec_format,
                    target_fmt,
                    spec.id,
                    e
                );
                let stored_fmt_str = content_type_for_format(spec.spec_format);
                let accepted_fmt_str = content_type_for_format(target_fmt);
                return json_resp(
                    StatusCode::NOT_ACCEPTABLE,
                    &json!({
                        "error": format!(
                            "Cannot convert stored {} to requested {}; \
                             accept the stored format or request raw bytes via Accept: */*",
                            stored_fmt_str, accepted_fmt_str
                        )
                    }),
                );
            }
        }
    };

    let len = body_bytes.len();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", ct)
        .header("Content-Length", len.to_string())
        .header("ETag", etag)
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                "{\"error\":\"Internal Server Error\"}",
            )))
        })
}

// ---------------------------------------------------------------------------
// Helper: parse list filter from query string (Wave 5)
// ---------------------------------------------------------------------------

/// Parse `GET /api-specs` query parameters into an [`ApiSpecListFilter`].
///
/// Unknown parameters are silently ignored. Returns `Err` only for invalid
/// `sort_by` values (rejected with 400 to prevent accidental SQL-like injection).
fn parse_list_filter(uri: &hyper::Uri) -> Result<ApiSpecListFilter, ApiSpecError> {
    const DEFAULT_LIMIT: u32 = 50;
    const MAX_LIMIT: u32 = 200;

    let mut filter = ApiSpecListFilter {
        limit: DEFAULT_LIMIT,
        ..Default::default()
    };

    let Some(query) = uri.query() else {
        return Ok(filter);
    };

    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let val = parts.next().unwrap_or("");
        // URL-decode the value (simple percent-decoding for common chars)
        let val = percent_decode(val);

        match key {
            "limit" => {
                let parsed = val.parse::<u32>().unwrap_or(DEFAULT_LIMIT);
                filter.limit = parsed.clamp(1, MAX_LIMIT);
            }
            "offset" => {
                filter.offset = val.parse::<u32>().unwrap_or(0);
            }
            "proxy_id" if !val.is_empty() => {
                filter.proxy_id = Some(val);
            }
            "spec_version" if !val.is_empty() => {
                filter.spec_version_prefix = Some(val);
            }
            "title_contains" if !val.is_empty() => {
                filter.title_contains = Some(val);
            }
            "updated_since" if !val.is_empty() => {
                // Accept ISO-8601 / RFC-3339 format.
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&val) {
                    filter.updated_since = Some(dt.to_utc());
                }
                // Silently ignore unparseable values (best-effort).
            }
            "has_tag" if !val.is_empty() => {
                filter.has_tag = Some(val);
            }
            "sort_by" if !val.is_empty() => {
                filter.sort_by = match val.as_str() {
                    "updated_at" => ApiSpecSortBy::UpdatedAt,
                    "title" => ApiSpecSortBy::Title,
                    "operation_count" => ApiSpecSortBy::OperationCount,
                    "created_at" => ApiSpecSortBy::CreatedAt,
                    other => {
                        return Err(ApiSpecError::BadRequest(format!(
                            "invalid sort_by value '{}'; allowed: updated_at, title, operation_count, created_at",
                            other
                        )));
                    }
                };
            }
            "order" if !val.is_empty() => {
                filter.order = match val.as_str() {
                    "asc" => SortOrder::Asc,
                    "desc" => SortOrder::Desc,
                    other => {
                        return Err(ApiSpecError::BadRequest(format!(
                            "invalid order value '{}'; allowed: asc, desc",
                            other
                        )));
                    }
                };
            }
            _ => {}
        }
    }

    Ok(filter)
}

/// Simple percent-decode for query parameter values.
/// Only decodes `%XX` sequences; `+` is NOT decoded as space (RFC 3986 query semantics).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (
                char::from(bytes[i + 1]).to_digit(16),
                char::from(bytes[i + 2]).to_digit(16),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Small JSON response helper (avoids importing the private fn from admin::mod)
// ---------------------------------------------------------------------------

fn json_resp(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let body_str = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .body(Full::new(Bytes::from(body_str)))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                "{\"error\":\"Internal Server Error\"}",
            )))
        })
}

// ---------------------------------------------------------------------------
// POST /api-specs
// ---------------------------------------------------------------------------

pub async fn handle_post_api_spec(
    req: Request<Incoming>,
    state: &AdminState,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    let declared_format = parse_content_type(req.headers());
    let max_mib = state.admin_spec_max_body_size_mib;

    let body = match collect_body(req, max_mib).await {
        Ok(b) => b,
        Err(e) => return Ok(error_response(e)),
    };

    // Extract resources from the spec body.
    let (mut bundle, metadata) = match extract(&body, declared_format, namespace) {
        Ok(v) => v,
        Err(e) => return Ok(error_response(ApiSpecError::Extract(e))),
    };

    // Assign IDs for POST: mint UUIDs for every empty ID, re-link references.
    assign_ids_for_post(&mut bundle);

    // Validate: field checks + DB cross-checks (listen_path uniqueness, etc.)
    let ValidatedBundle { bundle, metadata } = match validate_bundle(
        bundle,
        metadata,
        namespace,
        db.as_ref(),
        state,
        None,
        None,
        None,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return Ok(error_response(e)),
    };

    let spec_id = Uuid::new_v4().to_string();
    let proxy_id = bundle.proxy.id.clone();

    let spec = match build_spec_row(
        spec_id.clone(),
        proxy_id.clone(),
        namespace.to_string(),
        &body,
        &metadata,
        &bundle,
    ) {
        Ok(s) => s,
        Err(e) => return Ok(error_response(e)),
    };

    match db.submit_api_spec_bundle(&bundle, &spec).await {
        Ok(()) => {}
        Err(e) => return Ok(error_response(classify_db_error(e))),
    }

    let resp_body = json!({
        "id": spec_id,
        "proxy_id": proxy_id,
        "content_hash": spec.content_hash,
        "spec_version": spec.spec_version,
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header("Content-Type", "application/json")
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .header("Location", format!("/api-specs/{}", spec_id))
        .body(Full::new(Bytes::from(
            serde_json::to_string(&resp_body).unwrap_or_default(),
        )))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                "{\"error\":\"Internal Server Error\"}",
            )))
        }))
}

// ---------------------------------------------------------------------------
// PUT /api-specs/{id}
// ---------------------------------------------------------------------------

pub async fn handle_put_api_spec(
    req: Request<Incoming>,
    state: &AdminState,
    namespace: &str,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    // Check spec exists and belongs to this namespace
    let existing_spec = match db.get_api_spec(namespace, id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(error_response(ApiSpecError::NotFound)),
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };

    let declared_format = parse_content_type(req.headers());
    let max_mib = state.admin_spec_max_body_size_mib;

    let body = match collect_body(req, max_mib).await {
        Ok(b) => b,
        Err(e) => return Ok(error_response(e)),
    };

    // Extract resources from the spec body.
    let (mut bundle, metadata) = match extract(&body, declared_format, namespace) {
        Ok(v) => v,
        Err(e) => return Ok(error_response(ApiSpecError::Extract(e))),
    };

    // Assign IDs for PUT: reuse existing stored IDs for empty-id resources so
    // re-submitting the same ID-less spec is idempotent (Fix 1). This must
    // happen BEFORE the proxy-id immutability check and hash comparison.
    if let Err(e) = assign_ids_for_put(
        &mut bundle,
        db,
        namespace,
        &existing_spec,
        &metadata.version,
    )
    .await
    {
        return Ok(error_response(e));
    }

    // Enforce that the new spec targets the same proxy as the existing spec.
    // PUT cannot change which proxy a spec belongs to.
    if bundle.proxy.id != existing_spec.proxy_id {
        return Ok(error_response(ApiSpecError::ValidationFailures {
            spec_version: metadata.version.clone(),
            failures: vec![ValidationFailure {
                resource_type: "proxy",
                id: bundle.proxy.id.clone(),
                errors: vec![format!(
                    "PUT cannot change proxy_id; existing spec is for proxy '{}'",
                    existing_spec.proxy_id
                )],
            }],
        }));
    }

    // Fetch the existing proxy row once so we can:
    //   1. Exclude the spec's own upstream from the name-uniqueness check
    //      (PUT with unchanged name must not self-collide).
    //   2. Detect listen_port / transport changes for the port-probe
    //      skip-on-unchanged logic (Fix 2).
    // Use the *stored* upstream_id — NOT the bundle's post-assignment
    // upstream.id, which can be operator-changed.
    let existing_proxy_row: Option<crate::config::types::Proxy> =
        match db.get_proxy(&existing_spec.proxy_id).await {
            Ok(p) => p,
            Err(e) => return Ok(error_response(classify_db_error(e))),
        };
    let existing_upstream_id: Option<&str> = existing_proxy_row
        .as_ref()
        .and_then(|p| p.upstream_id.as_deref());

    let ValidatedBundle { bundle, metadata } = match validate_bundle(
        bundle,
        metadata,
        namespace,
        db.as_ref(),
        state,
        Some(&existing_spec.proxy_id),
        existing_upstream_id,
        existing_proxy_row.as_ref(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return Ok(error_response(e)),
    };

    let proxy_id = bundle.proxy.id.clone();

    let mut spec = match build_spec_row(
        id.to_string(),
        proxy_id.clone(),
        namespace.to_string(),
        &body,
        &metadata,
        &bundle,
    ) {
        Ok(s) => s,
        Err(e) => return Ok(error_response(e)),
    };
    // Preserve original created_at
    spec.created_at = existing_spec.created_at;

    match db.replace_api_spec_bundle(&bundle, &spec).await {
        Ok(()) => {}
        Err(e) => return Ok(error_response(classify_db_error(e))),
    }

    let resp_body = json!({
        "id": id,
        "proxy_id": proxy_id,
        "content_hash": spec.content_hash,
        "spec_version": spec.spec_version,
    });

    Ok(json_resp(StatusCode::OK, &resp_body))
}

// ---------------------------------------------------------------------------
// GET /api-specs/{id}
// ---------------------------------------------------------------------------

pub async fn handle_get_api_spec(
    req: Request<Incoming>,
    state: &AdminState,
    namespace: &str,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    let spec = match db.get_api_spec(namespace, id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(error_response(ApiSpecError::NotFound)),
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };

    let max_decompress = 2 * state.admin_spec_max_body_size_mib * 1024 * 1024;
    Ok(spec_content_response(&spec, req.headers(), max_decompress))
}

// ---------------------------------------------------------------------------
// GET /api-specs/by-proxy/{proxy_id}
// ---------------------------------------------------------------------------

pub async fn handle_get_api_spec_by_proxy(
    req: Request<Incoming>,
    state: &AdminState,
    namespace: &str,
    proxy_id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    let spec = match db.get_api_spec_by_proxy(namespace, proxy_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(error_response(ApiSpecError::NotFound)),
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };

    let max_decompress = 2 * state.admin_spec_max_body_size_mib * 1024 * 1024;
    Ok(spec_content_response(&spec, req.headers(), max_decompress))
}

// ---------------------------------------------------------------------------
// GET /api-specs (list)
// ---------------------------------------------------------------------------

pub async fn handle_list_api_specs(
    req: Request<Incoming>,
    state: &AdminState,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    let filter = match parse_list_filter(req.uri()) {
        Ok(f) => f,
        Err(e) => return Ok(error_response(e)),
    };
    let limit = filter.limit as usize;
    let offset = filter.offset as usize;

    let specs = match db.list_api_specs(namespace, &filter).await {
        Ok(s) => s,
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };

    // Build summary items — intentionally OMIT spec_content (heavy blob) and
    // resource_hash (internal implementation detail, not for client display).
    let items: Vec<Value> = specs
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "proxy_id": s.proxy_id,
                "spec_version": s.spec_version,
                "spec_format": s.spec_format,
                "title": s.title,
                "info_version": s.info_version,
                "description": s.description,
                "contact_name": s.contact_name,
                "contact_email": s.contact_email,
                "license_name": s.license_name,
                "license_identifier": s.license_identifier,
                "tags": s.tags,
                "server_urls": s.server_urls,
                "operation_count": s.operation_count,
                "uncompressed_size": s.uncompressed_size,
                "content_hash": s.content_hash,
                "created_at": s.created_at,
                "updated_at": s.updated_at,
            })
        })
        .collect();

    let next_offset: Option<usize> = if items.len() == limit {
        Some(offset + limit)
    } else {
        None
    };

    let body = json!({
        "items": items,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
    });

    Ok(json_resp(StatusCode::OK, &body))
}

// ---------------------------------------------------------------------------
// DELETE /api-specs/{id}
// ---------------------------------------------------------------------------

pub async fn handle_delete_api_spec(
    state: &AdminState,
    namespace: &str,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    match db.delete_api_spec(namespace, id).await {
        Ok(true) => Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("Cache-Control", "no-store")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))),
        Ok(false) => Ok(error_response(ApiSpecError::NotFound)),
        Err(e) => Ok(error_response(classify_db_error(e))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    // -----------------------------------------------------------------------
    // Content-Type → SpecFormat parsing
    // -----------------------------------------------------------------------

    fn headers_with_ct(ct: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("content-type", ct.parse().unwrap());
        h
    }

    #[test]
    fn parse_content_type_json() {
        let h = headers_with_ct("application/json");
        assert_eq!(parse_content_type(&h), Some(SpecFormat::Json));
    }

    #[test]
    fn parse_content_type_json_with_charset() {
        let h = headers_with_ct("application/json; charset=utf-8");
        assert_eq!(parse_content_type(&h), Some(SpecFormat::Json));
    }

    #[test]
    fn parse_content_type_yaml_variants() {
        for ct in &[
            "application/yaml",
            "application/x-yaml",
            "text/yaml",
            "text/x-yaml",
        ] {
            let h = headers_with_ct(ct);
            assert_eq!(
                parse_content_type(&h),
                Some(SpecFormat::Yaml),
                "ct={ct} should map to Yaml"
            );
        }
    }

    #[test]
    fn parse_content_type_unknown_returns_none() {
        let h = headers_with_ct("text/plain");
        assert_eq!(parse_content_type(&h), None);
    }

    #[test]
    fn parse_content_type_missing_returns_none() {
        let h = HeaderMap::new();
        assert_eq!(parse_content_type(&h), None);
    }

    // -----------------------------------------------------------------------
    // Accept header negotiation
    // -----------------------------------------------------------------------

    fn headers_with_accept(accept: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("accept", accept.parse().unwrap());
        h
    }

    #[test]
    fn negotiate_accept_wildcard_returns_stored() {
        let h = headers_with_accept("*/*");
        assert_eq!(negotiate_accept(&h, SpecFormat::Yaml), SpecFormat::Yaml);
        assert_eq!(negotiate_accept(&h, SpecFormat::Json), SpecFormat::Json);
    }

    #[test]
    fn negotiate_accept_missing_returns_stored() {
        let h = HeaderMap::new();
        assert_eq!(negotiate_accept(&h, SpecFormat::Yaml), SpecFormat::Yaml);
    }

    #[test]
    fn negotiate_accept_json_with_yaml_stored_requests_json() {
        // Client wants JSON, stored is YAML → must convert
        let h = headers_with_accept("application/json");
        assert_eq!(negotiate_accept(&h, SpecFormat::Yaml), SpecFormat::Json);
    }

    #[test]
    fn negotiate_accept_yaml_with_json_stored_requests_yaml() {
        let h = headers_with_accept("application/yaml");
        assert_eq!(negotiate_accept(&h, SpecFormat::Json), SpecFormat::Yaml);
    }

    #[test]
    fn negotiate_accept_json_with_json_stored_is_identity() {
        let h = headers_with_accept("application/json");
        assert_eq!(negotiate_accept(&h, SpecFormat::Json), SpecFormat::Json);
    }

    // -----------------------------------------------------------------------
    // Format conversion
    // -----------------------------------------------------------------------

    #[test]
    fn convert_yaml_to_json_roundtrip() {
        let yaml = b"openapi: '3.0.3'\ninfo:\n  title: Test\n  version: '1.0'\n";
        let json_bytes = convert_format(yaml, SpecFormat::Yaml, SpecFormat::Json).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(val["openapi"].as_str(), Some("3.0.3"));
        assert_eq!(val["info"]["title"].as_str(), Some("Test"));
    }

    #[test]
    fn convert_json_to_yaml_roundtrip() {
        let json = br#"{"openapi":"3.0.3","info":{"title":"Test","version":"1.0"}}"#;
        let yaml_bytes = convert_format(json, SpecFormat::Json, SpecFormat::Yaml).unwrap();
        let val: serde_yaml::Value = serde_yaml::from_slice(&yaml_bytes).unwrap();
        let title = val["info"]["title"].as_str().unwrap_or("");
        assert_eq!(title, "Test");
    }

    #[test]
    fn convert_same_format_is_identity() {
        let input = b"hello world";
        assert_eq!(
            convert_format(input, SpecFormat::Json, SpecFormat::Json).unwrap(),
            input
        );
    }

    // -----------------------------------------------------------------------
    // Error → HTTP status mapping
    // -----------------------------------------------------------------------

    #[test]
    fn payload_too_large_maps_to_413() {
        let resp = error_response(ApiSpecError::PayloadTooLarge(25));
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn extract_error_maps_to_400() {
        let resp = error_response(ApiSpecError::Extract(ExtractError::MissingProxyExtension));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validation_failures_maps_to_422() {
        let resp = error_response(ApiSpecError::ValidationFailures {
            spec_version: "3.1.0".to_string(),
            failures: vec![],
        });
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn not_found_maps_to_404() {
        let resp = error_response(ApiSpecError::NotFound);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn conflict_maps_to_409() {
        let resp = error_response(ApiSpecError::Conflict("dup".to_string()));
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn mongo_doc_too_large_maps_to_413() {
        let resp = error_response(ApiSpecError::MongoDocTooLarge);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn no_database_maps_to_503() {
        let resp = error_response(ApiSpecError::NoDatabase);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn internal_maps_to_500() {
        let resp = error_response(ApiSpecError::Internal("boom".to_string()));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // DB error string classification
    // -----------------------------------------------------------------------

    #[test]
    fn classify_unique_constraint_as_conflict() {
        assert!(matches!(
            classify_db_error_str("UNIQUE constraint failed: proxies.id"),
            ApiSpecError::Conflict(_)
        ));
    }

    #[test]
    fn classify_duplicate_key_as_conflict() {
        assert!(matches!(
            classify_db_error_str("duplicate key value violates unique constraint"),
            ApiSpecError::Conflict(_)
        ));
    }

    #[test]
    fn classify_mongo_doc_limit() {
        assert!(matches!(
            classify_db_error_str("MongoDB document limit exceeded for collection"),
            ApiSpecError::MongoDocTooLarge
        ));
    }

    #[test]
    fn classify_generic_error_as_internal() {
        assert!(matches!(
            classify_db_error_str("connection reset by peer"),
            ApiSpecError::Internal(_)
        ));
    }

    // -----------------------------------------------------------------------
    // List param parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_list_filter_defaults() {
        let uri: hyper::Uri = "/api-specs".parse().unwrap();
        let f = parse_list_filter(&uri).expect("parse failed");
        assert_eq!(f.limit, 50);
        assert_eq!(f.offset, 0);
    }

    #[test]
    fn parse_list_filter_custom() {
        let uri: hyper::Uri = "/api-specs?limit=10&offset=20".parse().unwrap();
        let f = parse_list_filter(&uri).expect("parse failed");
        assert_eq!(f.limit, 10);
        assert_eq!(f.offset, 20);
    }

    #[test]
    fn parse_list_filter_clamps_max() {
        let uri: hyper::Uri = "/api-specs?limit=9999".parse().unwrap();
        let f = parse_list_filter(&uri).expect("parse failed");
        assert_eq!(f.limit, 200);
    }
}
