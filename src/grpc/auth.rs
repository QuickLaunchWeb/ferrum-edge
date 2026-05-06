//! Shared authentication helpers for Ferrum control-plane gRPC surfaces.
//!
//! `ConfigSync` and xDS ADS are separate services, but both enforce the same
//! CP/DP security boundary: HS256 JWT in `authorization` metadata, standard
//! time claims required, and issuer pinned to `FERRUM_CP_DP_GRPC_JWT_ISSUER`.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use std::collections::HashSet;
use tonic::Status;

#[allow(clippy::result_large_err)]
pub(crate) fn verify_grpc_jwt_metadata(
    metadata: &tonic::metadata::MetadataMap,
    jwt_secret: &str,
    expected_issuer: &str,
) -> Result<(), Status> {
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

    decode::<Value>(token, &key, &validation)
        .map_err(|err| Status::unauthenticated(format!("Invalid token: {err}")))?;
    Ok(())
}

fn required_grpc_claims() -> HashSet<String> {
    ["exp", "iat", "sub", "iss"]
        .into_iter()
        .map(str::to_string)
        .collect()
}
