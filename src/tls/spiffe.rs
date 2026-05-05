//! SPIFFE-aware rustls server / client configurations.
//!
//! Phase A exposes ready-to-use builders that Phase C will wire into mesh
//! listeners. They consume the `Arc<ArcSwap<Option<SvidBundle>>>` slot
//! produced by [`crate::identity::workload_api::fetch_loop`] /
//! [`crate::identity::rotation`] so cert rotation is lock-free and atomic
//! from the rustls resolver's perspective — no listener restart, no per-
//! request cloning of the bundle.
//!
//! The builders are deliberately additive: nothing in the codebase calls
//! them yet. Phase C plugs them into the mesh data-plane mode.
//!
//! ## Verifier semantics
//!
//! - **Inbound**: trust anchors come from the SVID bundle's local + federated
//!   trust bundles. We require client certs (mesh = mTLS-everywhere). The
//!   verifier walks each peer cert and:
//!   1. Validates the chain against the bundle.
//!   2. Extracts the URI SAN, parses it as a SPIFFE ID, and confirms the
//!      trust domain matches the local or a federated bundle.
//!
//! - **Outbound**: trust anchors come from the bundle. When the caller pins
//!   `expected_peer`, the verifier additionally requires the peer's URI SAN
//!   to match exactly — this is how an outbound mesh hop can pin "I expect
//!   service /ns/foo/sa/bar".

use arc_swap::ArcSwap;
use rustls::client::WantsClientCert;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{WantsServerCert, WebPkiClientVerifier};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::identity::spiffe::{SpiffeId, extract_spiffe_id_from_parsed};
use crate::identity::{SvidBundle, TrustBundleSet};

/// Errors raised by the SPIFFE TLS builders.
#[derive(Debug, thiserror::Error)]
pub enum SpiffeTlsError {
    #[error("SVID bundle has no leaf certificate")]
    NoLeafCert,
    #[error("SVID bundle is empty (rotation has not yet produced an SVID)")]
    NoSvid,
    #[error("rustls error: {0}")]
    Rustls(String),
    #[error("malformed certificate / key in SVID bundle: {0}")]
    BadKeyMaterial(String),
}

impl From<rustls::Error> for SpiffeTlsError {
    fn from(e: rustls::Error) -> Self {
        SpiffeTlsError::Rustls(e.to_string())
    }
}

/// Shared bundle slot type alias used by the rustls resolvers.
pub type SharedBundleSlot = Arc<ArcSwap<Option<SvidBundle>>>;

// ── Inbound (server-side) ─────────────────────────────────────────────────

/// Build a [`ServerConfig`] that:
/// - Presents the SVID currently in `bundle_slot` (re-read on every TLS handshake).
/// - Requires + verifies the peer's SVID against the trust bundle in the slot.
///
/// `peer_required` controls whether the resulting config rejects clients
/// that do not present a certificate (mesh-strict ⇒ `true`; permissive
/// modes use the lower-level [`build_spiffe_inbound_resolver`] directly).
pub fn build_spiffe_inbound_config(
    bundle_slot: SharedBundleSlot,
    peer_required: bool,
) -> Result<Arc<ServerConfig>, SpiffeTlsError> {
    let snapshot = bundle_slot.load_full();
    if snapshot.is_none() {
        return Err(SpiffeTlsError::NoSvid);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| SpiffeTlsError::Rustls(e.to_string()))?;

    let verifier = SpiffeClientCertVerifier::new(bundle_slot.clone(), peer_required);
    let server_resolver = SpiffeServerCertResolver::new(bundle_slot);

    let builder: rustls::ConfigBuilder<ServerConfig, WantsServerCert> =
        builder.with_client_cert_verifier(Arc::new(verifier));
    let cfg = builder.with_cert_resolver(Arc::new(server_resolver));
    Ok(Arc::new(cfg))
}

// ── Outbound (client-side) ────────────────────────────────────────────────

/// Build a [`ClientConfig`] that:
/// - Presents the SVID currently in `bundle_slot`.
/// - Validates the server's SVID against the trust bundle.
/// - Optionally pins the peer SPIFFE ID (`expected_peer`).
pub fn build_spiffe_outbound_config(
    bundle_slot: SharedBundleSlot,
    expected_peer: Option<SpiffeId>,
) -> Result<Arc<ClientConfig>, SpiffeTlsError> {
    if bundle_slot.load_full().is_none() {
        return Err(SpiffeTlsError::NoSvid);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| SpiffeTlsError::Rustls(e.to_string()))?;

    let verifier = SpiffeServerCertVerifier::new(bundle_slot.clone(), expected_peer);
    let resolver = SpiffeClientCertResolver::new(bundle_slot);

    let cfg: ClientConfig = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(resolver));
    Ok(Arc::new(cfg))
}

// ── Server cert resolver (presents our SVID) ──────────────────────────────

/// rustls server-side resolver that presents the SVID currently in the slot.
pub struct SpiffeServerCertResolver {
    slot: SharedBundleSlot,
}

impl SpiffeServerCertResolver {
    pub fn new(slot: SharedBundleSlot) -> Self {
        Self { slot }
    }

    fn build_cert_key(&self) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let snapshot = self.slot.load_full();
        let bundle = snapshot.as_ref().as_ref()?;
        match certified_key_from_bundle(bundle) {
            Ok(ck) => Some(Arc::new(ck)),
            Err(e) => {
                warn!(error = %e, "SPIFFE server resolver: failed to materialise CertifiedKey");
                None
            }
        }
    }
}

impl std::fmt::Debug for SpiffeServerCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeServerCertResolver").finish()
    }
}

impl rustls::server::ResolvesServerCert for SpiffeServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.build_cert_key()
    }
}

// ── Client cert resolver (presents our SVID outbound) ────────────────────

pub struct SpiffeClientCertResolver {
    slot: SharedBundleSlot,
}

impl SpiffeClientCertResolver {
    pub fn new(slot: SharedBundleSlot) -> Self {
        Self { slot }
    }
}

impl std::fmt::Debug for SpiffeClientCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeClientCertResolver").finish()
    }
}

impl rustls::client::ResolvesClientCert for SpiffeClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let snapshot = self.slot.load_full();
        let bundle = snapshot.as_ref().as_ref()?;
        certified_key_from_bundle(bundle)
            .map(Arc::new)
            .map_err(|e| {
                warn!(error = %e, "SPIFFE client resolver: failed to materialise CertifiedKey");
            })
            .ok()
    }

    fn has_certs(&self) -> bool {
        self.slot.load_full().is_some()
    }
}

// ── Verifiers ─────────────────────────────────────────────────────────────

/// Server-side verifier of inbound peer certificates.
struct SpiffeClientCertVerifier {
    slot: SharedBundleSlot,
    peer_required: bool,
    schemes: Vec<rustls::SignatureScheme>,
}

impl SpiffeClientCertVerifier {
    fn new(slot: SharedBundleSlot, peer_required: bool) -> Self {
        Self {
            slot,
            peer_required,
            schemes: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

impl std::fmt::Debug for SpiffeClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeClientCertVerifier").finish()
    }
}

impl rustls::server::danger::ClientCertVerifier for SpiffeClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let snapshot = self.slot.load_full();
        let bundle = snapshot.as_ref().as_ref().ok_or_else(|| {
            rustls::Error::General("SPIFFE inbound verifier: no SVID bundle yet".into())
        })?;
        verify_peer_against_bundle(&bundle.trust_bundles, end_entity, intermediates, None)
            .map(|_| rustls::server::danger::ClientCertVerified::assertion())
            .map_err(|e| rustls::Error::General(format!("SPIFFE inbound verify: {e}")))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.peer_required
    }

    fn offer_client_auth(&self) -> bool {
        true
    }
}

/// Client-side verifier of outbound server certificates.
struct SpiffeServerCertVerifier {
    slot: SharedBundleSlot,
    expected_peer: Option<SpiffeId>,
    schemes: Vec<rustls::SignatureScheme>,
}

impl SpiffeServerCertVerifier {
    fn new(slot: SharedBundleSlot, expected_peer: Option<SpiffeId>) -> Self {
        Self {
            slot,
            expected_peer,
            schemes: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

impl std::fmt::Debug for SpiffeServerCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeServerCertVerifier").finish()
    }
}

impl rustls::client::danger::ServerCertVerifier for SpiffeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let snapshot = self.slot.load_full();
        let bundle = snapshot.as_ref().as_ref().ok_or_else(|| {
            rustls::Error::General("SPIFFE outbound verifier: no SVID bundle yet".into())
        })?;
        verify_peer_against_bundle(
            &bundle.trust_bundles,
            end_entity,
            intermediates,
            self.expected_peer.as_ref(),
        )
        .map(|_| rustls::client::danger::ServerCertVerified::assertion())
        .map_err(|e| rustls::Error::General(format!("SPIFFE outbound verify: {e}")))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Build a [`rustls::sign::CertifiedKey`] from a `SvidBundle`, using ring's
/// signing-key abstraction.
fn certified_key_from_bundle(bundle: &SvidBundle) -> Result<rustls::sign::CertifiedKey, String> {
    if bundle.cert_chain_der.is_empty() {
        return Err("SVID bundle has empty cert chain".to_string());
    }
    let chain: Vec<CertificateDer<'static>> = bundle
        .cert_chain_der
        .iter()
        .map(|d| CertificateDer::from(d.clone()))
        .collect();
    let key = PrivateKeyDer::try_from(bundle.private_key_pkcs8_der.clone())
        .map_err(|e| format!("invalid private key: {e}"))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("ring sign init failed: {e}"))?;
    Ok(rustls::sign::CertifiedKey::new(chain, signing_key))
}

/// Validate `end_entity + intermediates` against `bundle.trust_bundles`,
/// extract the SPIFFE ID, and (optionally) match it against `expected_peer`.
///
/// Phase A keeps the chain verification simple: build a webpki verifier
/// from the bundle's roots and let it do the work. Future phases tie this
/// into the existing `build_server_verifier_with_crls` helper for CRL
/// support.
fn verify_peer_against_bundle(
    trust_bundles: &TrustBundleSet,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    expected_peer: Option<&SpiffeId>,
) -> Result<SpiffeId, String> {
    use x509_parser::prelude::*;

    let (_, parsed_leaf) = X509Certificate::from_der(end_entity)
        .map_err(|e| format!("leaf cert parse failed: {e}"))?;

    let peer_id = extract_spiffe_id_from_parsed(&parsed_leaf)
        .map_err(|e| format!("peer cert lacks valid SPIFFE URI SAN: {e}"))?;

    if let Some(expected) = expected_peer
        && expected != &peer_id
    {
        return Err(format!(
            "peer SPIFFE ID '{}' does not match expected '{}'",
            peer_id, expected
        ));
    }

    let bundle = trust_bundles.get(peer_id.trust_domain()).ok_or_else(|| {
        format!(
            "no trust bundle for peer's trust domain '{}'",
            peer_id.trust_domain()
        )
    })?;

    let mut roots = RootCertStore::empty();
    let added = roots.add_parsable_certificates(
        bundle
            .x509_authorities
            .iter()
            .map(|d| CertificateDer::from(d.clone())),
    );
    if added.0 == 0 {
        return Err("trust bundle for peer's domain has no usable roots".to_string());
    }

    // SPIFFE peer verification is chain-only: the peer's identity is its
    // SPIFFE URI SAN (extracted above), not a DNS / IP name. We deliberately
    // do NOT use `WebPkiServerVerifier` here — that path is server-name aware
    // and would reject any SVID whose DNS SANs don't match a placeholder
    // (some CAs emit SPIFFE SVIDs with extra DNS SANs alongside the URI SAN).
    //
    // `WebPkiClientVerifier` does the equivalent chain-up-to-trust-anchor
    // check without server-name matching, which is exactly the semantics we
    // want for both directions (inbound peer-cert and outbound peer-cert
    // share the same chain validation; the only direction-specific bit is
    // the optional `expected_peer` pin, handled above).
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|e| format!("webpki verifier build failed: {e}"))?;

    let now = UnixTime::now();
    rustls::server::danger::ClientCertVerifier::verify_client_cert(
        verifier.as_ref(),
        end_entity,
        intermediates,
        now,
    )
    .map_err(|e| format!("chain verify failed: {e}"))?;

    debug!(
        peer_id = %peer_id,
        "SPIFFE peer verified against trust bundle"
    );
    Ok(peer_id)
}

// re-export the ConfigBuilder marker types so the build steps above compile
// without doc warnings on unused import lints.
#[allow(dead_code)]
fn _marker_imports(_x: WantsServerCert, _y: WantsClientCert) {}

#[cfg(test)]
mod tests {
    //! Inline tests for `verify_peer_against_bundle`. The function is private
    //! so these live alongside the implementation rather than in
    //! `tests/unit/`. The synthetic SVIDs are issued via `rcgen` so the tests
    //! are hermetic.
    //!
    //! Specifically covered:
    //! - URI-SAN-only SVID passes (no DNS SAN, no name match attempted).
    //! - URI-SAN + extra DNS SAN SVID passes (chain-only validation tolerates
    //!   the DNS SAN that some CAs emit).
    //! - `expected_peer` pin matches and rejects mismatches.
    //! - Wrong trust domain rejects (no trust anchor in the bundle).
    use super::*;
    use crate::identity::TrustBundle;
    use crate::identity::spiffe::{TrustDomain, spiffe_id_to_san};
    use rcgen::string::Ia5String;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
    };

    /// Generate a self-signed root + (DER, PEM, key-PEM) tuple.
    fn synthetic_root(td: &TrustDomain) -> (Vec<u8>, String, String) {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("{}-test-root", td.as_str()));
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("keygen");
        let cert = params.self_signed(&kp).expect("self-signed root");
        let der = cert.der().to_vec();
        let pem = cert.pem();
        let key_pem = kp.serialize_pem();
        (der, pem, key_pem)
    }

    /// Issue a leaf SVID under the given root with only a SPIFFE URI SAN
    /// (and optionally an extra DNS SAN, to exercise the path some CAs use).
    fn issue_leaf(
        spiffe_id: &SpiffeId,
        root_pem: &str,
        root_key_pem: &str,
        extra_dns_san: Option<&str>,
    ) -> Vec<u8> {
        let issuer_kp = KeyPair::from_pem(root_key_pem).expect("re-parse root key");
        let issuer: Issuer<'static, KeyPair> =
            Issuer::from_ca_cert_pem(root_pem, issuer_kp).expect("issuer build");

        let mut params = CertificateParams::default();
        // SPIFFE recommends an empty subject; we follow that.
        params.distinguished_name = DistinguishedName::new();
        params
            .subject_alt_names
            .push(spiffe_id_to_san(spiffe_id).expect("spiffe SAN"));
        if let Some(dns) = extra_dns_san {
            params.subject_alt_names.push(SanType::DnsName(
                Ia5String::try_from(dns.to_string()).unwrap(),
            ));
        }
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::seconds(3600);

        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf keygen");
        let cert = params.signed_by(&leaf_kp, &issuer).expect("sign leaf");
        cert.der().to_vec()
    }

    fn bundle_for(td: TrustDomain, root_der: Vec<u8>) -> TrustBundleSet {
        TrustBundleSet::local_only(TrustBundle {
            trust_domain: td,
            x509_authorities: vec![root_der],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        })
    }

    #[test]
    fn verifies_uri_san_only_svid() {
        let td = TrustDomain::new("td.verify-test").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let leaf = issue_leaf(&id, &root_pem, &key_pem, None);
        let bundles = bundle_for(td, root_der);

        let result = verify_peer_against_bundle(&bundles, &CertificateDer::from(leaf), &[], None);
        let extracted = result.expect("URI-SAN-only SVID should pass verification");
        assert_eq!(extracted.as_str(), id.as_str());
    }

    #[test]
    fn verifies_svid_with_extra_dns_san() {
        // Some CAs emit SPIFFE SVIDs with both a URI SAN and a DNS SAN. The
        // chain-only verifier must tolerate this — the DNS SAN is irrelevant
        // to peer identity in mesh mode.
        let td = TrustDomain::new("td.dns-san").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let leaf = issue_leaf(&id, &root_pem, &key_pem, Some("foo.example.com"));
        let bundles = bundle_for(td, root_der);

        let result = verify_peer_against_bundle(&bundles, &CertificateDer::from(leaf), &[], None);
        let extracted = result.expect("URI+DNS SAN SVID should still verify");
        assert_eq!(extracted.as_str(), id.as_str());
    }

    #[test]
    fn pin_match_passes() {
        let td = TrustDomain::new("td.pin-match").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/svc/sa/a").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let leaf = issue_leaf(&id, &root_pem, &key_pem, None);
        let bundles = bundle_for(td, root_der);

        let result =
            verify_peer_against_bundle(&bundles, &CertificateDer::from(leaf), &[], Some(&id));
        assert!(result.is_ok());
    }

    #[test]
    fn pin_mismatch_rejects() {
        let td = TrustDomain::new("td.pin-mismatch").unwrap();
        let id = SpiffeId::from_parts(&td, "ns/svc/sa/a").unwrap();
        let other = SpiffeId::from_parts(&td, "ns/svc/sa/b").unwrap();
        let (root_der, root_pem, key_pem) = synthetic_root(&td);
        let leaf = issue_leaf(&id, &root_pem, &key_pem, None);
        let bundles = bundle_for(td, root_der);

        let result =
            verify_peer_against_bundle(&bundles, &CertificateDer::from(leaf), &[], Some(&other));
        let err = result.expect_err("pin mismatch must reject");
        assert!(err.contains("does not match expected"));
    }

    #[test]
    fn rejects_unknown_trust_domain() {
        // Bundle for `td.known` only. Leaf is in `td.foreign` with its own
        // root. No cross-trust — must reject.
        let known_td = TrustDomain::new("td.known").unwrap();
        let foreign_td = TrustDomain::new("td.foreign").unwrap();
        let foreign_id = SpiffeId::from_parts(&foreign_td, "ns/x/sa/y").unwrap();
        let (foreign_root_der, foreign_root_pem, foreign_key_pem) = synthetic_root(&foreign_td);
        let leaf = issue_leaf(&foreign_id, &foreign_root_pem, &foreign_key_pem, None);

        let (known_root_der, _, _) = synthetic_root(&known_td);
        let bundles = bundle_for(known_td, known_root_der);
        // Pretend we don't even have the foreign root.
        let _ = foreign_root_der;

        let result = verify_peer_against_bundle(&bundles, &CertificateDer::from(leaf), &[], None);
        assert!(result.is_err());
    }
}
