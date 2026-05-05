//! URI-SAN encode/decode round-trip tests.
//!
//! Builds a self-signed certificate via `rcgen` carrying both a DNS SAN and
//! a SPIFFE URI SAN, then asserts that the extractor finds the SPIFFE URI
//! and parses it correctly.

use ferrum_edge::identity::spiffe::{
    SpiffeId, UriSanError, extract_spiffe_id_from_cert, spiffe_id_to_san, try_extract_spiffe_id,
};
use rcgen::{CertificateParams, KeyPair, SanType};

fn build_test_cert(spiffe_uri: Option<&str>, dns: Option<&str>) -> Vec<u8> {
    let mut params = CertificateParams::default();
    if let Some(uri) = spiffe_uri {
        let id = SpiffeId::new(uri).expect("test SPIFFE ID parses");
        params
            .subject_alt_names
            .push(spiffe_id_to_san(&id).expect("encode SAN"));
    }
    if let Some(dns_name) = dns {
        params.subject_alt_names.push(SanType::DnsName(
            rcgen::string::Ia5String::try_from(dns_name.to_string()).unwrap(),
        ));
    }
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
    let cert = params.self_signed(&key_pair).expect("self_signed");
    cert.der().to_vec()
}

#[test]
fn extract_spiffe_uri_san() {
    let der = build_test_cert(Some("spiffe://prod.example.com/ns/foo/sa/bar"), None);
    let id = extract_spiffe_id_from_cert(&der).expect("found SAN");
    assert_eq!(id.as_str(), "spiffe://prod.example.com/ns/foo/sa/bar");
    assert_eq!(id.trust_domain().as_str(), "prod.example.com");
}

#[test]
fn extract_picks_first_spiffe_uri_when_multiple_sans() {
    // DNS + URI mixed: the URI SAN must still be extracted.
    let der = build_test_cert(
        Some("spiffe://prod.example.com/ns/foo"),
        Some("foo.example.com"),
    );
    let id = extract_spiffe_id_from_cert(&der).expect("URI SAN found amid DNS SAN");
    assert_eq!(id.as_str(), "spiffe://prod.example.com/ns/foo");
}

#[test]
fn extract_returns_no_spiffe_uri_when_only_dns_san() {
    let der = build_test_cert(None, Some("foo.example.com"));
    let result = extract_spiffe_id_from_cert(&der);
    assert!(matches!(result, Err(UriSanError::NoSpiffeUri)));
}

#[test]
fn try_extract_returns_none_when_no_spiffe_uri() {
    let der = build_test_cert(None, Some("foo.example.com"));
    let extracted = try_extract_spiffe_id(&der).expect("Ok(None) for non-mesh certs");
    assert!(extracted.is_none());
}

#[test]
fn extract_returns_no_san_extension_when_truly_empty() {
    // An rcgen self-signed cert with no SANs has no SAN extension at all.
    let der = build_test_cert(None, None);
    let result = extract_spiffe_id_from_cert(&der);
    assert!(matches!(result, Err(UriSanError::NoSanExtension)));
}

#[test]
fn round_trip_preserves_full_uri() {
    let original = "spiffe://example.org/path/with/multiple/segments";
    let der = build_test_cert(Some(original), None);
    let id = extract_spiffe_id_from_cert(&der).unwrap();
    assert_eq!(id.as_str(), original);
}

#[test]
fn extract_rejects_corrupt_der() {
    let result = extract_spiffe_id_from_cert(&[0x00, 0x01, 0x02]);
    assert!(matches!(result, Err(UriSanError::ParseFailure(_))));
}
