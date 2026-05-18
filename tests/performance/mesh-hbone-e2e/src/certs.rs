//! SPIFFE-shaped cert generation for the harness.
//!
//! Produces a CA, a gateway leaf SVID (`spiffe://cluster.local/ns/edge/sa/gateway`),
//! and a sidecar leaf SVID (`spiffe://cluster.local/ns/svc/sa/sidecar`). Both
//! leaves carry the SPIFFE URI as a URI SAN — the gateway's
//! `file_loader::load_svid_bundle_from_files` parses it the same way SPIRE-issued
//! SVIDs are parsed.

use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, SanType,
};

pub struct GeneratedCerts {
    pub ca_pem: String,
    pub gateway_cert_pem: String,
    pub gateway_key_pem: String,
    pub gateway_spiffe_id: String,
    pub sidecar_cert_pem: String,
    pub sidecar_key_pem: String,
    pub sidecar_spiffe_id: String,
}

pub fn generate(trust_domain: &str) -> Result<GeneratedCerts> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    // CA
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generating CA key")?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "hbone-e2e CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).context("self-signing CA")?;

    // Helper for leaf certs with a URI SAN matching the SPIFFE ID.
    fn leaf(
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
        spiffe_uri: &str,
    ) -> Result<(String, String)> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
        params
            .subject_alt_names
            .push(SanType::IpAddress(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(127, 0, 0, 1),
            )));
        params
            .subject_alt_names
            .push(SanType::URI(rcgen::Ia5String::try_from(
                spiffe_uri.to_string(),
            )?));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params.signed_by(&key, ca, ca_key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    let gateway_spiffe = format!("spiffe://{trust_domain}/ns/edge/sa/gateway");
    let (gateway_cert_pem, gateway_key_pem) = leaf(&ca_cert, &ca_key, &gateway_spiffe)?;

    let sidecar_spiffe = format!("spiffe://{trust_domain}/ns/svc/sa/sidecar");
    let (sidecar_cert_pem, sidecar_key_pem) = leaf(&ca_cert, &ca_key, &sidecar_spiffe)?;

    Ok(GeneratedCerts {
        ca_pem: ca_cert.pem(),
        gateway_cert_pem,
        gateway_key_pem,
        gateway_spiffe_id: gateway_spiffe,
        sidecar_cert_pem,
        sidecar_key_pem,
        sidecar_spiffe_id: sidecar_spiffe,
    })
}

pub fn write_to_dir(certs: &GeneratedCerts, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("ca.pem"), &certs.ca_pem)?;
    std::fs::write(dir.join("gateway-cert.pem"), &certs.gateway_cert_pem)?;
    std::fs::write(dir.join("gateway-key.pem"), &certs.gateway_key_pem)?;
    std::fs::write(dir.join("sidecar-cert.pem"), &certs.sidecar_cert_pem)?;
    std::fs::write(dir.join("sidecar-key.pem"), &certs.sidecar_key_pem)?;
    Ok(())
}
