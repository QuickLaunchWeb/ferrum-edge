use std::collections::HashSet;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::Map;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;

use crate::consumer_index::ConsumerIndex;

use super::RequestContext;
use super::utils::PluginHttpClient;
use super::utils::auth_flow::{self, AuthMechanism, ExtractedCredential, VerifyOutcome};
use super::utils::jwks_cache::get_or_create_jwks_store;
use super::utils::jwks_store::JwksKeyStore;

/// Default JWKS refresh interval: 15 minutes.
const DEFAULT_JWKS_REFRESH_INTERVAL_SECS: u64 = 900;

/// JWKS authentication plugin.
///
/// Validates Bearer tokens using public keys fetched from one or more
/// Identity Provider JWKS endpoints. Supports RSA (RS256/384/512) and
/// EC (ES256/384) algorithms.
///
/// ## Key features
///
/// - **Multiple identity providers**: Configure an array of `providers`,
///   each with its own issuer, JWKS URI, audience, and claim-based
///   authorization rules.
/// - **Claim-based authorization**: Per-provider `required_scopes` and
///   `required_roles` filter requests without needing a separate ACL plugin.
/// - **Consumer-optional flow**: When no matching `Consumer` exists in the
///   gateway, the plugin still sets `authenticated_identity` on the request
///   context for downstream use (logging, rate limiting, consumer header).
/// - **Shared JWKS cache**: Stores keyed by resolved `jwks_uri` are shared
///   across plugin instances — no duplicate fetches or refresh tasks.
///
/// ## Configuration
///
/// ```json
/// {
///   "providers": [
///     {
///       "issuer": "https://auth.example.com",
///       "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
///       "audience": "my-api",
///       "required_scopes": ["read:data"],
///       "required_roles": ["admin"],
///       "scope_claim": "scp",
///       "role_claim": "realm_access.roles",
///       "consumer_identity_claim": "preferred_username",
///       "consumer_header_claim": "email"
///     }
///   ],
///   "scope_claim": "scope",
///   "role_claim": "roles",
///   "consumer_identity_claim": "sub",
///   "consumer_header_claim": "email",
///   "jwks_refresh_interval_secs": 900
/// }
/// ```
pub struct JwksAuth {
    providers: Vec<JwksProvider>,
    /// Global default: JWT claim path containing scopes (default: `"scope"`).
    global_scope_claim: String,
    /// Global default: JWT claim path containing roles (default: `"roles"`).
    global_role_claim: String,
    /// JWT claim used for ConsumerIndex lookup and rate-limit key (default: `"sub"`).
    consumer_identity_claim: String,
    /// JWT claim value sent as `X-Consumer-Username` header to the backend.
    /// Defaults to `consumer_identity_claim` if not set separately.
    consumer_header_claim: String,
}

/// A single identity provider configuration.
struct JwksProvider {
    /// Expected `iss` claim value. Used to match incoming tokens to this provider.
    issuer: Option<String>,
    /// Expected `aud` claim value.
    audience: Option<String>,
    /// Scopes that must be present in the token (all required).
    required_scopes: Vec<String>,
    /// Roles that must be present in the token (any one suffices).
    required_roles: Vec<String>,
    /// Per-provider override for the scope claim path.
    scope_claim: Option<String>,
    /// Per-provider override for the role claim path.
    role_claim: Option<String>,
    /// Per-provider override for the consumer identity claim.
    consumer_identity_claim: Option<String>,
    /// Per-provider override for the consumer header claim.
    consumer_header_claim: Option<String>,
    /// Whether this provider requires tokens to include an `exp` claim.
    require_exp: bool,
    /// The JWKS key store (shared via global cache).
    jwks_store: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>>,
    /// Outbound hosts used by direct JWKS or discovery URLs.
    warmup_hostnames: Vec<String>,
}

impl JwksAuth {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| format!("jwks_auth: config must be an object, got: {config}"))?;

        let refresh_interval_secs = optional_u64(
            config_obj,
            "jwks_refresh_interval_secs",
            DEFAULT_JWKS_REFRESH_INTERVAL_SECS,
        )?;
        if refresh_interval_secs == 0 {
            return Err(
                "jwks_auth: 'jwks_refresh_interval_secs' must be greater than 0".to_string(),
            );
        }
        let refresh_interval = Duration::from_secs(refresh_interval_secs);

        let global_scope_claim = optional_claim_path(config_obj, "scope_claim", "scope")?;
        let global_role_claim = optional_claim_path(config_obj, "role_claim", "roles")?;
        let consumer_identity_claim =
            optional_claim_path(config_obj, "consumer_identity_claim", "sub")?;
        let global_require_exp = optional_bool(config_obj, "require_exp")?.unwrap_or(true);
        let consumer_header_claim = match config_obj.get("consumer_header_claim") {
            Some(value) => parse_claim_path_value("consumer_header_claim", value)?,
            None => consumer_identity_claim.clone(),
        };

        let providers_val = config_obj.get("providers").unwrap_or(&Value::Null);
        let Some(providers_arr) = providers_val.as_array() else {
            return Err("jwks_auth: 'providers' must be a non-empty array".to_string());
        };
        if providers_arr.is_empty() {
            return Err("jwks_auth: 'providers' array must not be empty".to_string());
        }

        let mut providers = Vec::with_capacity(providers_arr.len());

        for (idx, prov_cfg) in providers_arr.iter().enumerate() {
            let prov_obj = prov_cfg.as_object().ok_or_else(|| {
                format!("jwks_auth: provider[{idx}] must be an object, got: {prov_cfg}")
            })?;

            let jwks_endpoint = parse_url_field(prov_obj, "jwks_uri", idx)?;
            let discovery_endpoint = parse_url_field(prov_obj, "discovery_url", idx)?;
            let jwks_uri = jwks_endpoint.as_ref().map(|endpoint| endpoint.url.clone());
            let discovery_url = discovery_endpoint
                .as_ref()
                .map(|endpoint| endpoint.url.clone());

            if jwks_uri.is_none() && discovery_url.is_none() {
                return Err(format!(
                    "jwks_auth: provider[{}] requires either 'jwks_uri' or 'discovery_url'",
                    idx
                ));
            }

            let issuer = optional_non_empty_string(prov_obj, "issuer", idx)?;
            let audience = optional_non_empty_string(prov_obj, "audience", idx)?;

            let required_scopes = parse_string_array(prov_obj, "required_scopes", idx)?;
            let required_roles = parse_string_array(prov_obj, "required_roles", idx)?;

            let scope_claim = optional_provider_claim_path(prov_obj, "scope_claim", idx)?;
            let role_claim = optional_provider_claim_path(prov_obj, "role_claim", idx)?;
            let prov_consumer_identity_claim =
                optional_provider_claim_path(prov_obj, "consumer_identity_claim", idx)?;
            let prov_consumer_header_claim =
                optional_provider_claim_path(prov_obj, "consumer_header_claim", idx)?;
            let provider_require_exp =
                optional_bool(prov_obj, "require_exp")?.unwrap_or(global_require_exp);

            let mut warmup_hostnames = Vec::new();
            if let Some(endpoint) = jwks_endpoint.as_ref() {
                warmup_hostnames.push(endpoint.hostname.clone());
            }
            if let Some(endpoint) = discovery_endpoint.as_ref()
                && !warmup_hostnames
                    .iter()
                    .any(|host| host == &endpoint.hostname)
            {
                warmup_hostnames.push(endpoint.hostname.clone());
            }

            let jwks_store_slot: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>> =
                Arc::new(ArcSwap::from_pointee(None));

            if let Some(ref uri) = jwks_uri {
                // Direct jwks_uri — get-or-create shared store immediately
                let store = get_or_create_jwks_store(uri, &http_client, refresh_interval);
                jwks_store_slot.store(Arc::new(Some(store)));
            } else if let Some(ref disc_url) = discovery_url {
                // OIDC discovery — resolve jwks_uri asynchronously with
                // indefinite retries. The background task keeps trying with
                // exponential backoff (2s → 4s → … → 5min cap) until discovery
                // succeeds. Once resolved, the JwksKeyStore's own background
                // task starts immediately; the eager fetch below coalesces with
                // that task so keys are populated before publication without a
                // second successful JWKS request.
                //
                // This ensures a prolonged IdP outage during gateway startup
                // does not permanently disable the provider — it self-heals
                // as soon as the IdP comes back.
                //
                // Auth behavior while discovery is pending: tokens destined
                // for this provider are rejected with 401 (fail closed).
                let slot = jwks_store_slot.clone();
                let client = http_client.clone();
                let url = disc_url.clone();
                let interval = refresh_interval;
                tokio::spawn(async move {
                    const INITIAL_BACKOFF_SECS: u64 = 2;
                    const MAX_BACKOFF_SECS: u64 = 300;

                    let mut attempt: u32 = 0;
                    loop {
                        if attempt > 0 {
                            let backoff_secs = INITIAL_BACKOFF_SECS
                                .saturating_mul(1u64 << (attempt - 1).min(7))
                                .min(MAX_BACKOFF_SECS);
                            let backoff = Duration::from_secs(backoff_secs);
                            warn!(
                                "jwks_auth OIDC discovery attempt {} failed — retrying in {:?}",
                                attempt, backoff
                            );
                            tokio::time::sleep(backoff).await;
                        }
                        match discover_jwks_uri(&client, &url).await {
                            Ok(uri) => {
                                info!("jwks_auth OIDC discovery: resolved jwks_uri={}", uri);
                                let store = get_or_create_jwks_store(&uri, &client, interval);
                                if let Err(e) = store.fetch_keys_if_empty().await {
                                    warn!("jwks_auth OIDC: initial JWKS fetch failed: {}", e);
                                }
                                slot.store(Arc::new(Some(store)));
                                return;
                            }
                            Err(e) => {
                                if attempt == 0 {
                                    warn!(
                                        "jwks_auth OIDC discovery failed: {} — will keep retrying in background",
                                        e
                                    );
                                }
                            }
                        }
                        attempt = attempt.saturating_add(1);
                    }
                });
            }

            providers.push(JwksProvider {
                issuer,
                audience,
                required_scopes,
                required_roles,
                scope_claim,
                role_claim,
                consumer_identity_claim: prov_consumer_identity_claim,
                consumer_header_claim: prov_consumer_header_claim,
                require_exp: provider_require_exp,
                jwks_store: jwks_store_slot,
                warmup_hostnames,
            });
        }

        Ok(Self {
            providers,
            global_scope_claim,
            global_role_claim,
            consumer_identity_claim,
            consumer_header_claim,
        })
    }

    /// Eagerly fetch JWKS keys for all providers that have stores ready.
    /// Called by tests to pre-populate key stores before assertions.
    #[allow(dead_code)]
    pub async fn warmup_jwks(&self) {
        for prov in &self.providers {
            let guard = prov.jwks_store.load();
            if let Some(ref store) = **guard {
                match store.fetch_keys().await {
                    Ok(count) => {
                        info!("jwks_auth warmup: fetched {} keys", count);
                    }
                    Err(e) => warn!("jwks_auth warmup failed: {} — will retry in background", e),
                }
            }
        }
    }

    fn resolve_identity(
        &self,
        claims: &Value,
        provider: &JwksProvider,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let effective_identity_claim = provider
            .consumer_identity_claim
            .as_deref()
            .unwrap_or(&self.consumer_identity_claim);
        let effective_header_claim = provider
            .consumer_header_claim
            .as_deref()
            .unwrap_or(&self.consumer_header_claim);

        let identity = extract_claim_string(claims, effective_identity_claim);
        let header_value = if effective_header_claim == effective_identity_claim {
            identity.clone()
        } else {
            extract_claim_string(claims, effective_header_claim).or_else(|| identity.clone())
        };

        let consumer = if let Some(ref id) = identity {
            match consumer_index.find_by_identity(id) {
                Some(consumer) => {
                    debug!(
                        "jwks_auth: identified consumer '{}' via claim '{}'='{}'",
                        consumer.username, effective_identity_claim, id
                    );
                    Some(consumer)
                }
                None => {
                    debug!(
                        "jwks_auth: no consumer found for '{}'='{}' — using external identity",
                        effective_identity_claim, id
                    );
                    None
                }
            }
        } else {
            warn!(
                "jwks_auth: token valid but claim '{}' not present",
                effective_identity_claim
            );
            None
        };

        VerifyOutcome::success(consumer, identity, header_value)
    }

    /// Try to validate a token against all configured providers.
    ///
    /// Returns `Ok((claims, provider_index))` on first successful validation,
    /// or `Err(status_code, body)` if no provider validates the token.
    async fn validate_token(&self, token: &str) -> Result<(Value, usize), (u16, &'static str)> {
        // Peek at the unverified issuer to try matching a specific provider first
        let unverified_issuer = peek_issuer(token);

        // If we have an issuer, try matching providers with that issuer first
        if let Some(ref iss) = unverified_issuer {
            for (idx, prov) in self.providers.iter().enumerate() {
                if prov.issuer.as_deref() == Some(iss.as_str())
                    && let Some(claims) = try_validate_with_provider(prov, token).await
                {
                    return Ok((claims, idx));
                }
            }
        }

        // Fall through: try all providers (handles no-issuer tokens or issuer mismatch)
        for (idx, prov) in self.providers.iter().enumerate() {
            if let Some(claims) = try_validate_with_provider(prov, token).await {
                return Ok((claims, idx));
            }
        }

        Err((401, r#"{"error":"Invalid or unrecognized JWT"}"#))
    }

    /// Check required_scopes and required_roles for a matched provider.
    fn check_claims_authorization(
        &self,
        claims: &Value,
        provider: &JwksProvider,
    ) -> Result<(), (u16, String)> {
        // Check required scopes
        if !provider.required_scopes.is_empty() {
            let scope_claim_path = provider
                .scope_claim
                .as_deref()
                .unwrap_or(&self.global_scope_claim);
            let token_scopes = extract_claim_values(claims, scope_claim_path);

            for required in &provider.required_scopes {
                if !token_scopes.iter().any(|s| s == required) {
                    return Err((
                        403,
                        format!(
                            r#"{{"error":"Insufficient scope","required":"{}"}}"#,
                            html_escape(required)
                        ),
                    ));
                }
            }
        }

        // Check required roles (any one match suffices)
        if !provider.required_roles.is_empty() {
            let role_claim_path = provider
                .role_claim
                .as_deref()
                .unwrap_or(&self.global_role_claim);
            let token_roles = extract_claim_values(claims, role_claim_path);

            let has_match = provider
                .required_roles
                .iter()
                .any(|r| token_roles.iter().any(|tr| tr == r));

            if !has_match {
                return Err((403, r#"{"error":"Insufficient role"}"#.to_string()));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl AuthMechanism for JwksAuth {
    fn mechanism_name(&self) -> &'static str {
        "jwks_auth"
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        match ctx.headers.get("authorization") {
            None => ExtractedCredential::Missing,
            Some(value) if value.starts_with("Bearer ") || value.starts_with("bearer ") => {
                ExtractedCredential::BearerToken(value[7..].to_string())
            }
            Some(_) => ExtractedCredential::InvalidFormat(
                r#"{"error":"Missing Bearer token"}"#.to_string(),
            ),
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::BearerToken(token) = credential else {
            return VerifyOutcome::NotApplicable;
        };

        let (claims, provider_idx) = match self.validate_token(&token).await {
            Ok(result) => result,
            Err((status, body)) => {
                return if status == 403 {
                    VerifyOutcome::Forbidden(body.to_string())
                } else {
                    VerifyOutcome::InvalidFormat(body.to_string())
                };
            }
        };

        let provider = &self.providers[provider_idx];
        if let Err((status, body)) = self.check_claims_authorization(&claims, provider) {
            return if status == 403 {
                VerifyOutcome::Forbidden(body)
            } else {
                VerifyOutcome::Invalid(body)
            };
        }

        self.resolve_identity(&claims, provider, consumer_index)
    }
}

auth_flow::impl_auth_plugin!(
    JwksAuth,
    "jwks_auth",
    super::priority::JWKS_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth_external_identity;
    fn warmup_hostnames(&self) -> Vec<String> {
        let mut hosts = Vec::new();
        for prov in &self.providers {
            hosts.extend(prov.warmup_hostnames.iter().cloned());
            let guard = prov.jwks_store.load();
            if let Some(ref store) = **guard
                && let Some(host) = hostname_from_url(store.jwks_uri())
                && !hosts.iter().any(|known| known == &host)
            {
                hosts.push(host);
            }
        }
        hosts
    }

    fn active_jwks_uris(&self) -> Vec<String> {
        let mut uris = Vec::new();
        for prov in &self.providers {
            let guard = prov.jwks_store.load();
            if let Some(ref store) = **guard {
                uris.push(store.jwks_uri().to_string());
            }
        }
        uris
    }
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Try to validate a JWT against a single provider's JWKS store.
async fn try_validate_with_provider(provider: &JwksProvider, token: &str) -> Option<Value> {
    let guard = provider.jwks_store.load();
    let store = guard.as_ref().as_ref()?;

    if !store.has_keys() {
        debug!("jwks_auth: JWKS store has no cached keys; rejecting without hot-path fetch");
        return None;
    }

    let header = decode_header(token).ok()?;

    // Build validation params for this provider
    let build_validation = |algorithm: Algorithm| -> Validation {
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;
        if provider.require_exp {
            validation.required_spec_claims = HashSet::from(["exp".to_string()]);
        } else {
            validation.required_spec_claims.clear();
        }
        if let Some(ref iss) = provider.issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(ref aud) = provider.audience {
            validation.set_audience(&[aud]);
        }
        validation
    };

    // Try specific kid first
    if let Some(kid) = &header.kid {
        if let Some(cached_key) = store.get_key(kid) {
            let validation = build_validation(cached_key.algorithm);
            if let Ok(td) = decode::<Value>(token, &cached_key.decoding_key, &validation) {
                return Some(td.claims);
            }
        }
        debug!("JWKS key not found for kid={}, trying all keys", kid);
    }

    // Fallback: try all cached keys
    let all_keys = store.all_keys();
    for cached_key in all_keys.values() {
        let validation = build_validation(cached_key.algorithm);
        if let Ok(td) = decode::<Value>(token, &cached_key.decoding_key, &validation) {
            return Some(td.claims);
        }
    }

    None
}

/// Peek at the `iss` claim without signature verification.
///
/// Used to route the token to the correct provider before doing real validation.
fn peek_issuer(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_segment = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_segment)
        .ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract values from a JWT claim, supporting:
/// - Space-delimited strings: `"read:data write:data"` → `["read:data", "write:data"]`
/// - Arrays of strings: `["admin", "editor"]` → `["admin", "editor"]`
/// - Nested dot-notation paths: `"realm_access.roles"` navigates `{"realm_access": {"roles": [...]}}`
pub fn extract_claim_values(claims: &Value, claim_path: &str) -> Vec<String> {
    let value = resolve_claim_path(claims, claim_path);
    let Some(value) = value else {
        return Vec::new();
    };
    normalize_claim_to_vec(value)
}

/// Resolve a dot-notation path like `"realm_access.roles"` through nested JSON.
fn resolve_claim_path<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = claims;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Normalize a claim value to a Vec<String>:
/// - String → split on spaces
/// - Array → collect string elements
/// - Other → empty
fn normalize_claim_to_vec(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => s.split_whitespace().map(|s| s.to_string()).collect(),
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Extract a single string value from a claim path.
fn extract_claim_string(claims: &Value, claim_path: &str) -> Option<String> {
    let value = resolve_claim_path(claims, claim_path)?;
    value.as_str().map(|s| s.to_string())
}

/// Parse a JSON value as an array of strings, or empty vec if not present/valid.
struct ParsedEndpoint {
    url: String,
    hostname: String,
}

fn optional_u64(
    config: &Map<String, Value>,
    field: &str,
    default_value: u64,
) -> Result<u64, String> {
    let Some(value) = config.get(field) else {
        return Ok(default_value);
    };
    value
        .as_u64()
        .ok_or_else(|| format!("jwks_auth: '{field}' must be an unsigned integer, got: {value}"))
}

fn optional_bool(config: &Map<String, Value>, field: &str) -> Result<Option<bool>, String> {
    config
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("jwks_auth: '{field}' must be a boolean, got: {value}"))
        })
        .transpose()
}

fn optional_claim_path(
    config: &Map<String, Value>,
    field: &str,
    default_value: &str,
) -> Result<String, String> {
    match config.get(field) {
        Some(value) => parse_claim_path_value(field, value),
        None => Ok(default_value.to_string()),
    }
}

fn optional_provider_claim_path(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    parse_claim_path_value(&format!("provider[{provider_idx}].{field}"), value).map(Some)
}

fn parse_claim_path_value(field: &str, value: &Value) -> Result<String, String> {
    let raw = value
        .as_str()
        .ok_or_else(|| format!("jwks_auth: '{field}' must be a string, got: {value}"))?;
    let path = raw.trim();
    if path.is_empty() || path.split('.').any(str::is_empty) {
        return Err(format!(
            "jwks_auth: '{field}' must be a non-empty dot path without empty segments"
        ));
    }
    Ok(path.to_string())
}

fn optional_non_empty_string(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or_else(|| {
        format!("jwks_auth: 'provider[{provider_idx}].{field}' must be a string, got: {value}")
    })?;
    let value = raw.trim();
    if value.is_empty() {
        return Err(format!(
            "jwks_auth: 'provider[{provider_idx}].{field}' must not be empty"
        ));
    }
    Ok(Some(value.to_string()))
}

fn parse_url_field(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<ParsedEndpoint>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or_else(|| {
        format!("jwks_auth: 'provider[{provider_idx}].{field}' must be a URL string, got: {value}")
    })?;
    let url = raw.trim();
    if url.is_empty() {
        return Err(format!(
            "jwks_auth: 'provider[{provider_idx}].{field}' must not be empty"
        ));
    }
    let parsed = Url::parse(url).map_err(|e| {
        format!("jwks_auth: 'provider[{provider_idx}].{field}' is not a valid URL: {e}")
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "jwks_auth: 'provider[{provider_idx}].{field}' must use http or https, got: {scheme}"
            ));
        }
    }
    let hostname = parsed.host_str().ok_or_else(|| {
        format!("jwks_auth: 'provider[{provider_idx}].{field}' must include a hostname")
    })?;
    Ok(Some(ParsedEndpoint {
        url: url.to_string(),
        hostname: hostname.to_string(),
    }))
}

fn parse_string_array(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Vec<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let Some(arr) = value.as_array() else {
        return Err(format!(
            "jwks_auth: 'provider[{provider_idx}].{field}' must be an array of strings, got: {value}"
        ));
    };
    let mut values = Vec::with_capacity(arr.len());
    for (idx, entry) in arr.iter().enumerate() {
        let raw = entry.as_str().ok_or_else(|| {
            format!(
                "jwks_auth: 'provider[{provider_idx}].{field}[{idx}]' must be a string, got: {entry}"
            )
        })?;
        let value = raw.trim();
        if value.is_empty() {
            return Err(format!(
                "jwks_auth: 'provider[{provider_idx}].{field}[{idx}]' must not be empty"
            ));
        }
        values.push(value.to_string());
    }
    Ok(values)
}

/// Escape characters that could cause JSON injection in error response bodies.
fn html_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
}

/// Fetch the OIDC discovery document and extract the `jwks_uri` field.
async fn discover_jwks_uri(
    http_client: &PluginHttpClient,
    discovery_url: &str,
) -> Result<String, String> {
    let req = http_client.get().get(discovery_url);
    let response = http_client
        .execute(req, "jwks_auth_oidc_discovery")
        .await
        .map_err(|e| format!("OIDC discovery request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "OIDC discovery endpoint returned HTTP {}",
            response.status()
        ));
    }

    let body: Value = response
        .json()
        .await
        .map_err(|e| format!("OIDC discovery response parse failed: {}", e))?;

    body["jwks_uri"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "OIDC discovery document missing 'jwks_uri' field".to_string())
}

/// Extract the hostname from a URL string, if parseable.
fn hostname_from_url(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
}
