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
use crate::admin::api_specs::{ExtractError, SpecFormat, extract};
use crate::admin::spec_codec;
use crate::config::db_backend::DatabaseBackend;
use crate::config::types::ApiSpec;

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
        ApiSpecError::Extract(e) => {
            let code = extract_error_code(&e);
            json_resp(
                StatusCode::BAD_REQUEST,
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
/// - `Accept: */*, missing, or matching stored format` → stored format
/// - `Accept: application/json` and stored is YAML     → Json (convert)
/// - `Accept: application/yaml` and stored is JSON     → Yaml (convert)
/// - Unknown accept types                              → stored format (best-effort)
pub(super) fn negotiate_accept(headers: &hyper::HeaderMap, stored: SpecFormat) -> SpecFormat {
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("*/*");

    // Very lightweight; we only care about top-level type tokens.
    let wants_json = accept.contains("application/json");
    let wants_yaml = accept.contains("application/yaml")
        || accept.contains("application/x-yaml")
        || accept.contains("text/yaml")
        || accept.contains("text/x-yaml");

    match (wants_json, wants_yaml, stored) {
        (true, false, SpecFormat::Yaml) => SpecFormat::Json,
        (false, true, SpecFormat::Json) => SpecFormat::Yaml,
        _ => stored,
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
// Shared extract + validate logic (POST and PUT share most of the pipeline)
// ---------------------------------------------------------------------------

struct SubmitInput {
    body: Vec<u8>,
    declared_format: Option<SpecFormat>,
    namespace: String,
}

struct ValidatedBundle {
    bundle: crate::admin::api_specs::ExtractedBundle,
    metadata: crate::admin::api_specs::SpecMetadata,
}

async fn extract_and_validate(
    input: SubmitInput,
    db: &dyn DatabaseBackend,
    state: &AdminState,
    existing_proxy_id: Option<&str>, // None = create, Some(id) = update (skip self-conflict)
) -> Result<ValidatedBundle, ApiSpecError> {
    let (mut bundle, metadata) = extract(&input.body, input.declared_format, &input.namespace)
        .map_err(ApiSpecError::Extract)?;

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

    // DB cross-checks (only when no structural failures found — avoids spurious FK errors)
    if failures.is_empty() {
        let proxy = &bundle.proxy;
        // Namespace already stamped by extractor; set bind-address + reserved ports ctx
        let _ = &vctx; // vctx used for mode/ports; cross-check uses db directly

        if !proxy.dispatch_kind.is_stream() {
            // Exclude self when replacing (PUT path passes existing proxy id)
            match db
                .check_listen_path_unique(
                    &input.namespace,
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
                .check_proxy_name_unique(&input.namespace, name, existing_proxy_id)
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
            match db
                .check_upstream_name_unique(&input.namespace, &upstream.id, None)
                .await
            {
                Ok(true) => {}
                Ok(false) => failures.push(ValidationFailure {
                    resource_type: "upstream",
                    id: upstream.id.clone(),
                    errors: vec![format!(
                        "An upstream with id '{}' already exists",
                        upstream.id
                    )],
                }),
                Err(e) => return Err(classify_db_error(e)),
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

/// Build an `ApiSpec` row from body bytes + metadata.
fn build_spec_row(
    id: String,
    proxy_id: String,
    namespace: String,
    body: &[u8],
    metadata: &crate::admin::api_specs::SpecMetadata,
) -> Result<ApiSpec, ApiSpecError> {
    let spec_content = spec_codec::compress_gzip(body)
        .map_err(|e| ApiSpecError::Internal(format!("gzip compress failed: {e}")))?;
    let content_hash = spec_codec::sha256_hex(body);
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
        created_at: now,
        updated_at: now,
    })
}

// ---------------------------------------------------------------------------
// Helper: build spec-fetch response with ETag + content negotiation
// ---------------------------------------------------------------------------

fn spec_content_response(
    spec: &ApiSpec,
    request_headers: &hyper::HeaderMap,
) -> Response<Full<Bytes>> {
    // Decompress
    let raw = match spec_codec::decompress_gzip(&spec.spec_content) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("decompress_gzip failed for spec {}: {}", spec.id, e);
            return json_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": "Failed to decompress spec content"}),
            );
        }
    };

    // ETag
    let etag = format!("\"{}\"", spec.content_hash);

    // If-None-Match check
    if let Some(inm) = request_headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
    {
        if inm == etag || inm == "*" {
            return Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header("ETag", etag)
                .header("Cache-Control", "no-store")
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
        }
    }

    // Content negotiation
    let target_fmt = negotiate_accept(request_headers, spec.spec_format);
    let (body_bytes, ct) = if target_fmt == spec.spec_format {
        (raw, content_type_for_format(spec.spec_format))
    } else {
        match convert_format(&raw, spec.spec_format, target_fmt) {
            Ok(converted) => (converted, content_type_for_format(target_fmt)),
            Err(e) => {
                tracing::warn!("format conversion failed for spec {}: {}", spec.id, e);
                // Serve raw in stored format rather than 500
                (raw, content_type_for_format(spec.spec_format))
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
// Helper: parse limit/offset from query string for the list endpoint
// ---------------------------------------------------------------------------

fn parse_list_params(uri: &hyper::Uri) -> (usize, usize) {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;
    let mut limit = DEFAULT_LIMIT;
    let mut offset = 0usize;

    if let Some(query) = uri.query() {
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some("limit"), Some(v)) => {
                    let parsed = v.parse::<usize>().unwrap_or(DEFAULT_LIMIT);
                    limit = parsed.min(MAX_LIMIT).max(1);
                }
                (Some("offset"), Some(v)) => {
                    offset = v.parse::<usize>().unwrap_or(0);
                }
                _ => {}
            }
        }
    }
    (limit, offset)
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

    let input = SubmitInput {
        body: body.clone(),
        declared_format,
        namespace: namespace.to_string(),
    };

    let ValidatedBundle { bundle, metadata } =
        match extract_and_validate(input, db.as_ref(), state, None).await {
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

    // Pass existing proxy id so uniqueness checks exclude it
    let input = SubmitInput {
        body: body.clone(),
        declared_format,
        namespace: namespace.to_string(),
    };

    let ValidatedBundle { bundle, metadata } = match extract_and_validate(
        input,
        db.as_ref(),
        state,
        Some(&existing_spec.proxy_id),
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

    Ok(spec_content_response(&spec, req.headers()))
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

    Ok(spec_content_response(&spec, req.headers()))
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

    let (limit, offset) = parse_list_params(req.uri());

    let specs = match db
        .list_api_specs(namespace, limit as u32, offset as u32)
        .await
    {
        Ok(s) => s,
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };

    // Build summary items — intentionally OMIT spec_content (heavy blob).
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
    fn parse_list_params_defaults() {
        let uri: hyper::Uri = "/api-specs".parse().unwrap();
        let (limit, offset) = parse_list_params(&uri);
        assert_eq!(limit, 50);
        assert_eq!(offset, 0);
    }

    #[test]
    fn parse_list_params_custom() {
        let uri: hyper::Uri = "/api-specs?limit=10&offset=20".parse().unwrap();
        let (limit, offset) = parse_list_params(&uri);
        assert_eq!(limit, 10);
        assert_eq!(offset, 20);
    }

    #[test]
    fn parse_list_params_clamps_max() {
        let uri: hyper::Uri = "/api-specs?limit=9999".parse().unwrap();
        let (limit, _) = parse_list_params(&uri);
        assert_eq!(limit, 200);
    }
}
