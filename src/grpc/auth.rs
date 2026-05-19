//! Shared authentication helpers for Ferrum control-plane gRPC surfaces.
//!
//! `ConfigSync` and xDS ADS are separate services, but both enforce the same
//! CP/DP security boundary: HS256 JWT in `authorization` metadata, standard
//! time claims required, and issuer pinned to `FERRUM_CP_DP_GRPC_JWT_ISSUER`.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use std::collections::HashSet;
use tonic::Status;

/// Namespaces a DP/mesh JWT bearer is authorised to subscribe to.
///
/// The `ns` claim is optional for back-compat with operator-minted tokens
/// that predate multi-namespace CPs. Carriers:
/// - `None` — token has no `ns` claim; the CP falls back to its scope check
///   (current behavior) unless `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true`.
/// - `Some(set)` — the bearer may only subscribe to the listed namespaces.
///
/// Tokens may carry the claim as either a single string (`"ns": "prod"`) or
/// an array (`"ns": ["prod","staging"]`). The verifier normalises both into
/// a `HashSet<String>` here so callers don't have to branch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowedNamespaces(pub Option<HashSet<String>>);

impl AllowedNamespaces {
    /// Empty (no claim present).
    pub fn empty() -> Self {
        Self(None)
    }

    /// True when the claim is present (any value, even empty array).
    pub fn is_present(&self) -> bool {
        self.0.is_some()
    }

    /// True when the bearer is authorised for `namespace`. Returns `false`
    /// when no claim is present — callers must combine with the back-compat
    /// fallback logic.
    pub fn allows(&self, namespace: &str) -> bool {
        match &self.0 {
            Some(set) => set.contains(namespace),
            None => false,
        }
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn verify_grpc_jwt_metadata(
    metadata: &tonic::metadata::MetadataMap,
    jwt_secret: &str,
    expected_issuer: &str,
) -> Result<(), Status> {
    verify_grpc_jwt_metadata_with_claims(metadata, jwt_secret, expected_issuer).map(|_| ())
}

/// Verify the JWT and return any `ns` claim it carried. Use this variant
/// whenever the caller needs the tenancy-claim path (CP `Subscribe`,
/// `GetFullConfig`, mesh `MeshSubscribe`, xDS ADS). The verification logic
/// is identical to [`verify_grpc_jwt_metadata`]; the only difference is the
/// extra claim extraction.
#[allow(clippy::result_large_err)]
pub(crate) fn verify_grpc_jwt_metadata_with_claims(
    metadata: &tonic::metadata::MetadataMap,
    jwt_secret: &str,
    expected_issuer: &str,
) -> Result<AllowedNamespaces, Status> {
    let token = metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.strip_prefix("Bearer ").unwrap_or(value))
        .ok_or_else(|| Status::unauthenticated("Missing authorization token"))?;

    let key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims = required_grpc_claims();
    validation.set_issuer(&[expected_issuer]);

    let token_data = decode::<Value>(token, &key, &validation)
        .map_err(|err| Status::unauthenticated(format!("Invalid token: {err}")))?;
    Ok(extract_ns_claim(&token_data.claims))
}

fn required_grpc_claims() -> HashSet<String> {
    ["exp", "iat", "sub", "iss"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Pull the `ns` claim out of the decoded JWT body. Accepted shapes:
/// - missing — `AllowedNamespaces::empty()`
/// - `"ns": "production"` — single-namespace claim, single-element set
/// - `"ns": ["production","staging"]` — multi-namespace claim
///
/// Non-string array entries are silently dropped (e.g. `"ns": [1, "prod"]`
/// yields `{"prod"}`). Non-string, non-array values (`"ns": 42`) reset to
/// `None` so the CP treats them as "no claim" and falls back to the
/// scope-only path — safer than rejecting the token entirely, which could
/// blackhole a fleet during a half-rolled-out claim change.
fn extract_ns_claim(claims: &Value) -> AllowedNamespaces {
    let raw = match claims.get("ns") {
        Some(v) => v,
        None => return AllowedNamespaces::empty(),
    };

    if let Some(s) = raw.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return AllowedNamespaces::empty();
        }
        let mut set = HashSet::new();
        set.insert(trimmed.to_string());
        return AllowedNamespaces(Some(set));
    }

    if let Some(arr) = raw.as_array() {
        let set: HashSet<String> = arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        return AllowedNamespaces(Some(set));
    }

    AllowedNamespaces::empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ns_claim_absent_yields_empty() {
        let claims = json!({ "sub": "node-a", "iss": "ferrum-edge-cp-dp" });
        assert_eq!(extract_ns_claim(&claims), AllowedNamespaces::empty());
    }

    #[test]
    fn ns_claim_string_normalised_to_single_element_set() {
        let claims = json!({ "ns": "production" });
        let allowed = extract_ns_claim(&claims);
        assert!(allowed.is_present());
        assert!(allowed.allows("production"));
        assert!(!allowed.allows("staging"));
    }

    #[test]
    fn ns_claim_array_normalised_to_set() {
        let claims = json!({ "ns": ["prod", "staging", "prod"] });
        let allowed = extract_ns_claim(&claims);
        let inner = allowed.0.expect("set should be present");
        assert_eq!(inner.len(), 2);
        assert!(inner.contains("prod"));
        assert!(inner.contains("staging"));
    }

    #[test]
    fn ns_claim_empty_string_treated_as_missing() {
        let claims = json!({ "ns": "  " });
        assert_eq!(extract_ns_claim(&claims), AllowedNamespaces::empty());
    }

    #[test]
    fn ns_claim_empty_array_is_present_but_empty() {
        // Empty array is still a "present" claim — operator explicitly
        // assigned no namespaces, which means the bearer can subscribe to
        // nothing. The CP rejects every namespace; we keep semantics
        // distinct from the missing-claim case.
        let claims = json!({ "ns": [] });
        let allowed = extract_ns_claim(&claims);
        assert!(allowed.is_present());
        assert!(!allowed.allows("prod"));
    }

    #[test]
    fn ns_claim_array_filters_non_strings_silently() {
        let claims = json!({ "ns": [1, "prod", null, "staging"] });
        let allowed = extract_ns_claim(&claims);
        let inner = allowed.0.expect("set should be present");
        assert_eq!(inner.len(), 2);
        assert!(inner.contains("prod"));
        assert!(inner.contains("staging"));
    }

    #[test]
    fn ns_claim_non_string_non_array_treated_as_missing() {
        // Operator misconfigured the claim type (e.g. number). Fall back to
        // "no claim" so the CP applies its scope-only check — safer than
        // wholesale token rejection mid-rollout.
        let claims = json!({ "ns": 42 });
        assert_eq!(extract_ns_claim(&claims), AllowedNamespaces::empty());
    }
}
