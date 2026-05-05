//! Istio-flavored HBONE helpers.
//!
//! HBONE is HTTP/2 CONNECT over mTLS. This module only handles the
//! connection metadata boundary for Phase C; the tunnel relay itself will grow
//! from this parser without changing plugin traits or request hot-path code.

#![allow(dead_code)]

use crate::identity::spiffe::SpiffeId;

pub const HBONE_DEFAULT_PORT: u16 = 15008;
pub const HBONE_BAGGAGE_HEADER: &str = "baggage";
pub const HBONE_METHOD: &str = "CONNECT";

const SOURCE_IDENTITY_KEYS: &[&str] = &[
    "source.principal",
    "source_principal",
    "source.identity",
    "src.identity",
    "ferrum.source_principal",
    "ferrum-source-principal",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HboneIdentity {
    pub source_principal: SpiffeId,
}

pub fn extract_source_identity_from_baggage(baggage: &str) -> Result<Option<SpiffeId>, String> {
    for item in baggage.split(',') {
        let Some((raw_key, raw_value)) = item.trim().split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        if !SOURCE_IDENTITY_KEYS
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
        {
            continue;
        }
        let encoded = raw_value
            .split(';')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let Some(encoded) = encoded else {
            return Err(format!("HBONE baggage key '{key}' has an empty value"));
        };
        let decoded = percent_encoding::percent_decode_str(encoded)
            .decode_utf8()
            .map_err(|e| format!("HBONE baggage key '{key}' is not valid UTF-8: {e}"))?;
        return SpiffeId::new(decoded.into_owned())
            .map(Some)
            .map_err(|e| format!("HBONE baggage key '{key}' has invalid SPIFFE ID: {e}"));
    }
    Ok(None)
}

pub fn identity_from_baggage(baggage: &str) -> Result<Option<HboneIdentity>, String> {
    extract_source_identity_from_baggage(baggage)
        .map(|id| id.map(|source_principal| HboneIdentity { source_principal }))
}

pub fn is_hbone_connect(method: &str) -> bool {
    method.eq_ignore_ascii_case(HBONE_METHOD)
}
