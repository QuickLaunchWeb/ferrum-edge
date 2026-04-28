//! Internal-CA + bootstrap helper tests.
//!
//! Several of the gates here read process-wide env vars; cargo's test runner
//! parallelises by default, which would race those reads. We funnel every
//! env-touching test through `ENV_LOCK` so they serialise without bringing in
//! a `serial_test` dep.

use super::env_guard::EnvGuard;
use ferrum_edge::identity::ca::{
    CaError, CertificateAuthority, IssuanceRequest, bootstrap, internal,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};

fn dev_root_inside_guard(td: &str, guard: &EnvGuard) -> bootstrap::BootstrappedRoot {
    guard.set("FERRUM_MESH_PRODUCTION_MODE", "false");
    guard.set("FERRUM_MESH_CA_BOOTSTRAP_DEV", "true");
    let trust_domain = TrustDomain::new(td).unwrap();
    bootstrap::bootstrap_dev_root(bootstrap::BootstrapConfig::new(trust_domain))
        .expect("dev bootstrap succeeds")
}

fn dev_root(td: &str) -> bootstrap::BootstrappedRoot {
    let guard = EnvGuard::new(&[
        "FERRUM_MESH_PRODUCTION_MODE",
        "FERRUM_MESH_CA_BOOTSTRAP_DEV",
    ]);
    dev_root_inside_guard(td, &guard)
}

#[test]
fn bootstrap_emits_pem_root() {
    let root = dev_root("td.test");
    assert!(root.root_cert_pem.contains("-----BEGIN CERTIFICATE-----"));
    assert!(
        root.root_key_pem.contains("-----BEGIN PRIVATE KEY-----")
            || root.root_key_pem.contains("-----BEGIN EC PRIVATE KEY-----")
    );
    assert_eq!(root.trust_domain.as_str(), "td.test");
}

#[test]
fn bootstrap_refuses_in_production_mode() {
    let guard = EnvGuard::new(&[
        "FERRUM_MESH_PRODUCTION_MODE",
        "FERRUM_MESH_CA_BOOTSTRAP_DEV",
    ]);
    guard.set("FERRUM_MESH_PRODUCTION_MODE", "true");
    guard.set("FERRUM_MESH_CA_BOOTSTRAP_DEV", "true");
    let td = TrustDomain::new("td.test").unwrap();
    let result = bootstrap::bootstrap_dev_root(bootstrap::BootstrapConfig::new(td));
    assert!(matches!(result, Err(CaError::Config(_))));
}

#[test]
fn bootstrap_refuses_without_explicit_opt_in() {
    let guard = EnvGuard::new(&[
        "FERRUM_MESH_PRODUCTION_MODE",
        "FERRUM_MESH_CA_BOOTSTRAP_DEV",
    ]);
    guard.unset("FERRUM_MESH_PRODUCTION_MODE");
    guard.unset("FERRUM_MESH_CA_BOOTSTRAP_DEV");
    let td = TrustDomain::new("td.test").unwrap();
    let result = bootstrap::bootstrap_dev_root(bootstrap::BootstrapConfig::new(td));
    assert!(matches!(result, Err(CaError::Config(_))));
}

#[tokio::test]
async fn internal_ca_signs_generate_request() {
    let root = dev_root("td.internal-ca-test");
    let trust_domain = TrustDomain::new("td.internal-ca-test").unwrap();
    let cfg = internal::InternalCaConfig {
        root_cert_pem: root.root_cert_pem,
        root_key_pem: root.root_key_pem,
        trust_domain: trust_domain.clone(),
        bundle_refresh_hint_secs: Some(60),
        default_svid_ttl_secs: 600,
        max_svid_ttl_secs: 3600,
    };
    let ca = internal::InternalCa::new(cfg).expect("CA initialised");

    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let svid = ca
        .issue_svid(IssuanceRequest::Generate {
            spiffe_id: id.clone(),
            ttl_secs: 600,
        })
        .await
        .expect("generate succeeds");

    assert_eq!(svid.spiffe_id, id);
    assert!(!svid.cert_chain_der.is_empty());
    assert!(!svid.private_key_pkcs8_der.is_empty());

    // The issued cert must carry the SPIFFE URI SAN with the requested ID.
    let extracted =
        ferrum_edge::identity::spiffe::extract_spiffe_id_from_cert(&svid.cert_chain_der[0])
            .expect("issued cert has SPIFFE URI SAN");
    assert_eq!(extracted.as_str(), id.as_str());
}

#[tokio::test]
async fn internal_ca_rejects_csr_outside_trust_domain() {
    let root = dev_root("td.scope-test");
    let trust_domain = TrustDomain::new("td.scope-test").unwrap();
    let cfg = internal::InternalCaConfig {
        root_cert_pem: root.root_cert_pem,
        root_key_pem: root.root_key_pem,
        trust_domain,
        bundle_refresh_hint_secs: None,
        default_svid_ttl_secs: 600,
        max_svid_ttl_secs: 3600,
    };
    let ca = internal::InternalCa::new(cfg).unwrap();
    let foreign = SpiffeId::new("spiffe://other.test/ns/test/sa/foo").unwrap();
    let result = ca
        .issue_svid(IssuanceRequest::Generate {
            spiffe_id: foreign,
            ttl_secs: 60,
        })
        .await;
    assert!(matches!(result, Err(CaError::BadCsr(_))));
}

#[tokio::test]
async fn internal_ca_publishes_local_trust_bundle() {
    let root = dev_root("td.bundle-test");
    let trust_domain = TrustDomain::new("td.bundle-test").unwrap();
    let cfg = internal::InternalCaConfig {
        root_cert_pem: root.root_cert_pem,
        root_key_pem: root.root_key_pem,
        trust_domain: trust_domain.clone(),
        bundle_refresh_hint_secs: Some(120),
        default_svid_ttl_secs: 0,
        max_svid_ttl_secs: 0,
    };
    let ca = internal::InternalCa::new(cfg).unwrap();
    let bundle = ca.trust_bundle(&trust_domain).await.unwrap();
    assert_eq!(bundle.trust_domain, trust_domain);
    assert_eq!(bundle.roots_der.len(), 1);
    assert_eq!(bundle.refresh_hint_secs, Some(120));
}

#[tokio::test]
async fn internal_ca_rejects_unknown_trust_domain_for_bundle() {
    let root = dev_root("td.bundle-isolation");
    let trust_domain = TrustDomain::new("td.bundle-isolation").unwrap();
    let cfg = internal::InternalCaConfig {
        root_cert_pem: root.root_cert_pem,
        root_key_pem: root.root_key_pem,
        trust_domain,
        bundle_refresh_hint_secs: None,
        default_svid_ttl_secs: 600,
        max_svid_ttl_secs: 3600,
    };
    let ca = internal::InternalCa::new(cfg).unwrap();
    let other = TrustDomain::new("other-trust-domain.test").unwrap();
    let result = ca.trust_bundle(&other).await;
    assert!(matches!(result, Err(CaError::UnknownTrustDomain(_))));
}
