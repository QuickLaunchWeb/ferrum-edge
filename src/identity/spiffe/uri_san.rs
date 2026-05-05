//! Encode SPIFFE IDs as X.509 URI Subject Alternative Names, and extract them
//! from peer certificates.
//!
//! Per RFC 5280 §4.2.1.6 a `URI` GeneralName carries an IA5String (ASCII).
//! SPIFFE IDs are themselves ASCII (the parser rejects non-ASCII path
//! characters), so the conversion is byte-identical.
//!
//! On the **issue** side we hand the SPIFFE ID URI to `rcgen` as a
//! `SanType::URI`; rcgen handles the IA5String wrapping.
//!
//! On the **verify** side we parse the peer certificate with `x509-parser`
//! and walk the SAN extension's `general_names` looking for `URI` entries
//! whose value parses as a [`SpiffeId`]. We return only the FIRST such SAN —
//! per the SPIFFE X.509-SVID spec, an SVID has exactly one SPIFFE ID, and
//! certificates with multiple `spiffe://` URIs are explicitly forbidden, so
//! we simply pick the first and ignore the rest. (The on-the-wire layer that
//! validates SVID well-formedness will reject duplicates upstream.)

use rcgen::SanType;
use rcgen::string::Ia5String;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

use super::id::{SpiffeId, SpiffeIdError};

/// Errors raised when extracting a SPIFFE URI SAN from a peer certificate.
#[derive(Debug, thiserror::Error)]
pub enum UriSanError {
    #[error("certificate has no Subject Alternative Name extension")]
    NoSanExtension,
    #[error("certificate has no SPIFFE URI SAN")]
    NoSpiffeUri,
    #[error("SPIFFE URI SAN '{uri}' is invalid: {source}")]
    InvalidSpiffeId {
        uri: String,
        #[source]
        source: SpiffeIdError,
    },
    #[error("failed to parse certificate DER: {0}")]
    ParseFailure(String),
}

/// Build a [`SanType::URI`] for use in an `rcgen::CertificateParams::subject_alt_names`
/// list.
pub fn spiffe_id_to_san(id: &SpiffeId) -> Result<SanType, UriSanError> {
    let ia5 = Ia5String::try_from(id.as_str().to_string()).map_err(|e| {
        UriSanError::ParseFailure(format!(
            "SPIFFE URI '{}' is not a valid IA5 string: {}",
            id, e
        ))
    })?;
    Ok(SanType::URI(ia5))
}

/// Extract the FIRST SPIFFE URI SAN from a DER-encoded peer certificate.
///
/// Returns the parsed [`SpiffeId`], or one of:
/// - [`UriSanError::ParseFailure`] if the DER does not parse as X.509.
/// - [`UriSanError::NoSanExtension`] if the cert lacks a SAN extension.
/// - [`UriSanError::NoSpiffeUri`] if the SAN list contains no `spiffe://` URI.
/// - [`UriSanError::InvalidSpiffeId`] if a `spiffe://` URI is present but
///   malformed (this is a strict-mode error — callers may choose to log and
///   continue if they prefer, but the default is to reject).
pub fn extract_spiffe_id_from_cert(cert_der: &[u8]) -> Result<SpiffeId, UriSanError> {
    let (_, parsed) = X509Certificate::from_der(cert_der)
        .map_err(|e| UriSanError::ParseFailure(e.to_string()))?;
    extract_spiffe_id_from_parsed(&parsed)
}

/// Like [`extract_spiffe_id_from_cert`] but takes an already-parsed
/// `X509Certificate`. Useful inside hot paths where the certificate has
/// already been parsed for other reasons (e.g. the `mtls_auth` plugin).
pub fn extract_spiffe_id_from_parsed(cert: &X509Certificate<'_>) -> Result<SpiffeId, UriSanError> {
    let mut saw_san = false;
    let mut first_spiffe_uri: Option<String> = None;

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            saw_san = true;
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name
                    && uri.starts_with("spiffe://")
                    && first_spiffe_uri.is_none()
                {
                    first_spiffe_uri = Some((*uri).to_string());
                }
            }
        }
    }

    if !saw_san {
        return Err(UriSanError::NoSanExtension);
    }
    let uri = first_spiffe_uri.ok_or(UriSanError::NoSpiffeUri)?;
    SpiffeId::new(uri.clone()).map_err(|source| UriSanError::InvalidSpiffeId { uri, source })
}

/// Variant of [`extract_spiffe_id_from_cert`] returning `Option<SpiffeId>` —
/// `None` when the cert simply has no SPIFFE URI SAN (the common case for
/// non-mesh deployments).
///
/// Malformed `spiffe://` URIs are still treated as errors (returned via
/// `Err`); callers that want to silently ignore them can `.ok().flatten()`.
pub fn try_extract_spiffe_id(cert_der: &[u8]) -> Result<Option<SpiffeId>, UriSanError> {
    match extract_spiffe_id_from_cert(cert_der) {
        Ok(id) => Ok(Some(id)),
        Err(UriSanError::NoSanExtension) | Err(UriSanError::NoSpiffeUri) => Ok(None),
        Err(other) => Err(other),
    }
}

/// Parsed-cert variant of [`try_extract_spiffe_id`]: avoid double-parsing
/// when callers already have an `X509Certificate`.
pub fn try_extract_spiffe_id_from_parsed(
    cert: &X509Certificate<'_>,
) -> Result<Option<SpiffeId>, UriSanError> {
    match extract_spiffe_id_from_parsed(cert) {
        Ok(id) => Ok(Some(id)),
        Err(UriSanError::NoSanExtension) | Err(UriSanError::NoSpiffeUri) => Ok(None),
        Err(other) => Err(other),
    }
}
