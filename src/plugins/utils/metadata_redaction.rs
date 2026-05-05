//! Central redaction for sensitive metadata keys before log serialization.
//!
//! Plugins (built-in or custom) can write arbitrary key/value pairs into
//! `TransactionSummary.metadata` and `StreamTransactionSummary.metadata`.
//! Without redaction, anything they put there — auth tokens, cookies, session
//! IDs, credential tokens — flows verbatim through every logging sink
//! (stdout, http, tcp, kafka, loki, udp, ws, statsd). That has bitten us
//! before with `transaction_debugger.rs` (which only redacts request HEADERS).
//!
//! This module is the single redaction layer. It is wired into the
//! `metadata` field of both summary structs via `#[serde(serialize_with = ...)]`
//! so every logger that calls `serde_json::to_string(summary)` gets the same
//! sanitized output, and there's no way for a new logger to forget to redact.
//!
//! Matching is case-insensitive against:
//!   * a built-in default list (`DEFAULT_SENSITIVE_METADATA_KEYS`);
//!   * an operator-extensible list parsed once from
//!     `FERRUM_LOG_REDACT_METADATA_KEYS` (comma-separated).
//!
//! Matching strategy: most built-in keys use substring-on-lowercased-key, so a
//! key like `request_authorization_header` redacts because it contains
//! `authorization`. Token keys are narrower: only singular `token` keys with a
//! credential/session/auth context redact. This keeps usage metrics like
//! `ai_total_tokens` visible while still protecting real token secrets.

use serde::Serializer;
use serde::ser::SerializeMap;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Default substrings (lowercase) that mark a metadata key as sensitive.
///
/// Substring match, not exact match — see module docs. Broad `token` matching
/// is intentionally excluded; token-shaped keys go through
/// `is_sensitive_token_metadata_key` so token-count metrics do not disappear.
pub const DEFAULT_SENSITIVE_METADATA_KEYS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "bearer",
    "password",
    "secret",
];

/// Key segments that make a singular `token` metadata key credential-shaped.
const SENSITIVE_TOKEN_CONTEXT_SEGMENTS: &[&str] = &[
    "access",
    "api",
    "auth",
    "authorization",
    "bearer",
    "client",
    "csrf",
    "github",
    "gitlab",
    "id",
    "identity",
    "jwt",
    "oauth",
    "oidc",
    "pat",
    "personal",
    "refresh",
    "request",
    "saml",
    "security",
    "session",
    "slack",
    "webhook",
    "xsrf",
];

/// Generic descriptors that commonly wrap a raw token key.
const TOKEN_VALUE_SEGMENTS: &[&str] = &["digest", "hash", "hashed", "raw", "sha256", "value"];

/// Placeholder string written in place of sensitive metadata values.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Operator-supplied extras parsed once from `FERRUM_LOG_REDACT_METADATA_KEYS`.
///
/// Stored lowercased and trimmed. `None`-equivalent: an empty `Vec`.
static EXTRA_REDACTED_KEYS: OnceLock<Vec<String>> = OnceLock::new();

/// Read the current operator-supplied redaction extras. The list is loaded
/// from `FERRUM_LOG_REDACT_METADATA_KEYS` on first call and cached.
fn extra_redacted_keys() -> &'static [String] {
    EXTRA_REDACTED_KEYS.get_or_init(parse_extras_from_env)
}

/// Parse the comma-separated extras env var into a normalized list.
/// Public for tests — production callers go through the `OnceLock`.
pub fn parse_extras_from_env() -> Vec<String> {
    std::env::var("FERRUM_LOG_REDACT_METADATA_KEYS")
        .map(|raw| parse_extras_list(&raw))
        .unwrap_or_default()
}

/// Parse a comma-separated extras string into a normalized lowercase list.
pub fn parse_extras_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|part| part.trim().to_ascii_lowercase())
        .filter(|part| !part.is_empty())
        .collect()
}

fn metadata_key_segments(key: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut previous_was_lower_or_digit = false;

    for ch in key.chars() {
        if !ch.is_ascii_alphanumeric() {
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            previous_was_lower_or_digit = false;
            continue;
        }

        if ch.is_ascii_uppercase() && previous_was_lower_or_digit && !current.is_empty() {
            segments.push(std::mem::take(&mut current));
        }

        current.push(ch.to_ascii_lowercase());
        previous_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }

    if !current.is_empty() {
        segments.push(current);
    }

    segments
}

fn segment_is_any(segment: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|candidate| segment == *candidate)
}

fn is_sensitive_token_metadata_key(key: &str) -> bool {
    let segments = metadata_key_segments(key);
    if !segments.iter().any(|segment| segment == "token") {
        return false;
    }

    if segments.len() == 1 {
        return true;
    }

    let has_sensitive_context = segments
        .iter()
        .any(|segment| segment_is_any(segment, SENSITIVE_TOKEN_CONTEXT_SEGMENTS));
    if has_sensitive_context {
        return true;
    }

    segments
        .iter()
        .filter(|segment| segment.as_str() != "token")
        .all(|segment| segment_is_any(segment, TOKEN_VALUE_SEGMENTS))
}

/// Returns true when the given metadata key matches any sensitive substring
/// from `DEFAULT_SENSITIVE_METADATA_KEYS` plus the supplied operator extras
/// (case-insensitive). The lower-level entry point used by tests; production
/// callers should use [`is_sensitive_metadata_key`].
pub fn is_sensitive_metadata_key_with_extras(key: &str, extras: &[String]) -> bool {
    let lowered = key.to_ascii_lowercase();
    if DEFAULT_SENSITIVE_METADATA_KEYS
        .iter()
        .any(|needle| lowered.contains(needle))
        || is_sensitive_token_metadata_key(key)
    {
        return true;
    }
    extras
        .iter()
        .any(|needle| lowered.contains(needle.as_str()))
}

/// Returns true when the given metadata key is sensitive against the global
/// (env-driven) extras list.
pub fn is_sensitive_metadata_key(key: &str) -> bool {
    is_sensitive_metadata_key_with_extras(key, extra_redacted_keys())
}

/// Serde `serialize_with` adapter for `HashMap<String, String>` metadata
/// fields on log summary structs. Replaces the value with
/// `REDACTED_PLACEHOLDER` for any key that matches a sensitive substring.
/// Non-sensitive keys pass through unchanged.
///
/// The serialized order is the natural HashMap iteration order — same as the
/// default `Serialize` impl for `HashMap`. Logs are not sorted by key today,
/// so this preserves existing dashboard semantics.
pub fn serialize_redacted_metadata<S>(
    metadata: &HashMap<String, String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(metadata.len()))?;
    for (key, value) in metadata {
        if is_sensitive_metadata_key(key) {
            map.serialize_entry(key, REDACTED_PLACEHOLDER)?;
        } else {
            map.serialize_entry(key, value)?;
        }
    }
    map.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_keys_match_case_insensitively() {
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras(
            "authorization",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "Authorization",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "AUTHORIZATION",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras("Cookie", &extras));
        assert!(is_sensitive_metadata_key_with_extras("Set-Cookie", &extras));
        assert!(is_sensitive_metadata_key_with_extras("X-Api-Key", &extras));
        assert!(is_sensitive_metadata_key_with_extras(
            "X-Auth-Token",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "X-CSRF-Token",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "session_token",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "user_password",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras("api_secret", &extras));
        assert!(is_sensitive_metadata_key_with_extras("Bearer", &extras));
    }

    #[test]
    fn substring_match_catches_prefixed_or_suffixed_keys() {
        // Custom plugins often namespace keys, so substring beats exact match.
        let extras: Vec<String> = Vec::new();
        assert!(is_sensitive_metadata_key_with_extras(
            "downstream_authorization",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "legacy.cookie.value",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "auth.bearer.value",
            &extras
        ));
        // `x-api-key` (hyphenated) only matches when the key uses hyphens.
        assert!(is_sensitive_metadata_key_with_extras("X-API-KEY", &extras));
    }

    #[test]
    fn token_secret_keys_match_without_redacting_token_metrics() {
        let extras: Vec<String> = Vec::new();

        for key in [
            "token",
            "token_value",
            "session_token_v2",
            "access_token",
            "refreshToken",
            "id-token",
            "apiToken",
            "csrf_token",
            "auth.session.token",
        ] {
            assert!(
                is_sensitive_metadata_key_with_extras(key, &extras),
                "{key} should be redacted"
            );
        }

        for key in [
            "ai_total_tokens",
            "ai_prompt_tokens",
            "ai_completion_tokens",
            "llm_total_tokens",
            "completion_tokens",
        ] {
            assert!(
                !is_sensitive_metadata_key_with_extras(key, &extras),
                "{key} should remain visible"
            );
        }
    }

    #[test]
    fn non_sensitive_keys_pass_through() {
        let extras: Vec<String> = Vec::new();
        assert!(!is_sensitive_metadata_key_with_extras(
            "correlation_id",
            &extras
        ));
        assert!(!is_sensitive_metadata_key_with_extras("trace_id", &extras));
        assert!(!is_sensitive_metadata_key_with_extras(
            "request_id",
            &extras
        ));
        assert!(!is_sensitive_metadata_key_with_extras(
            "backend_resolved_ip",
            &extras
        ));
        assert!(!is_sensitive_metadata_key_with_extras(
            "response_size_bytes",
            &extras
        ));
        assert!(!is_sensitive_metadata_key_with_extras(
            "ai_total_tokens",
            &extras
        ));
        assert!(!is_sensitive_metadata_key_with_extras("", &extras));
    }

    #[test]
    fn extras_match_case_insensitively() {
        let extras = parse_extras_list("custom_field, MY-SECRET ,session_id");
        assert_eq!(
            extras,
            vec![
                "custom_field".to_string(),
                "my-secret".to_string(),
                "session_id".to_string()
            ]
        );
        assert!(is_sensitive_metadata_key_with_extras(
            "custom_field",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "CUSTOM_FIELD",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras(
            "ns.my-secret.value",
            &extras
        ));
        assert!(is_sensitive_metadata_key_with_extras("session_id", &extras));
        assert!(!is_sensitive_metadata_key_with_extras(
            "benign_key",
            &extras
        ));
    }

    #[test]
    fn parse_extras_skips_empty_and_whitespace_entries() {
        let extras = parse_extras_list(" , a , , b ,  ");
        assert_eq!(extras, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn serialize_redacts_default_sensitive_keys() {
        let mut metadata = HashMap::new();
        metadata.insert("authorization".to_string(), "Bearer secret".to_string());
        metadata.insert("trace_id".to_string(), "abc-123".to_string());

        let json = serde_json::to_string(&MetadataWrapper(&metadata)).unwrap();

        assert!(
            json.contains(r#""authorization":"[REDACTED]""#),
            "authorization value should be redacted, got: {}",
            json
        );
        assert!(
            !json.contains("Bearer secret"),
            "raw bearer value must not leak, got: {}",
            json
        );
        assert!(
            json.contains(r#""trace_id":"abc-123""#),
            "trace_id should pass through, got: {}",
            json
        );
    }

    /// Test-only newtype wrapper so we can exercise `serialize_redacted_metadata`
    /// directly without depending on `TransactionSummary`'s full schema.
    struct MetadataWrapper<'a>(&'a HashMap<String, String>);
    impl<'a> serde::Serialize for MetadataWrapper<'a> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serialize_redacted_metadata(self.0, s)
        }
    }
}
