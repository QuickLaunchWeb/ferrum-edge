//! Shared HMAC test helpers for functional tests that exercise HMAC
//! authentication (auth/ACL, credential rotation, etc.).

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Generate an HMAC-SHA256 signature for a request, matching the signing
/// string format expected by the `hmac_auth` plugin.
pub fn generate_hmac_signature(method: &str, path: &str, date: &str, secret: &str) -> String {
    let signing_string = format!("{}\n{}\n{}\n{}", method, path, date, empty_digest_header());
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("Failed to create HMAC instance");
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Return the SHA-256 digest header value for an empty body.
pub fn empty_digest_header() -> String {
    let digest = Sha256::digest([]);
    format!(
        "sha-256={}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}
