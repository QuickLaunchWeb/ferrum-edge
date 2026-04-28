//! Wrappers for delegating to an external certificate authority.
//!
//! Two flavors are scaffolded here:
//!
//! - [`VaultPkiCa`] — talks to a Vault PKI mount over HTTP and mints SVIDs
//!   by signing CSRs through `pki/sign-verbatim`. The actual HTTP wiring is
//!   left to the caller; in Phase A we expose only the trait shape and a
//!   placeholder constructor so later phases can drop in the implementation
//!   without breaking call sites.
//!
//! - [`CertManagerCa`] — issues `CertificateRequest` resources via the
//!   Kubernetes `cert-manager.io` API and waits for them to be signed by a
//!   `ClusterIssuer`/`Issuer`.
//!
//! Both wrappers are share-nothing: the [`InternalCa`](super::internal::InternalCa)
//! implementation does not leak through these wrappers.
//!
//! Future phases will replace the `unimplemented` bodies — the trait
//! signatures are stable so call sites in the workload-API server compile
//! against a single contract.

use async_trait::async_trait;

use super::{
    CaError, CertificateAuthority, IssuanceRequest, PublishedJwtAuthority, PublishedTrustBundle,
    SignedSvid,
};
use crate::identity::spiffe::TrustDomain;

/// Configuration for a Vault PKI-backed CA.
///
/// The Vault HTTP client is intentionally not constructed here; later
/// phases will plug in the existing [`crate::secrets::vault`] machinery.
#[derive(Debug, Clone)]
pub struct VaultPkiConfig {
    pub address: String,
    pub mount: String,
    pub role: String,
    pub trust_domain: TrustDomain,
}

/// Vault PKI-backed CA. Phase A: scaffolded — `issue_svid` returns
/// [`CaError::Upstream`] until the HTTP plumbing is added in a later phase.
pub struct VaultPkiCa {
    config: VaultPkiConfig,
}

impl VaultPkiCa {
    pub fn new(config: VaultPkiConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &VaultPkiConfig {
        &self.config
    }
}

#[async_trait]
impl CertificateAuthority for VaultPkiCa {
    async fn issue_svid(&self, _req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        Err(CaError::Upstream(format!(
            "Vault PKI CA at '{}' (mount='{}', role='{}') is not yet implemented (Phase B+)",
            self.config.address, self.config.mount, self.config.role
        )))
    }

    async fn trust_bundle(&self, _td: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        Err(CaError::Upstream(
            "Vault PKI trust bundle fetch not yet implemented (Phase B+)".to_string(),
        ))
    }

    async fn jwt_authorities(
        &self,
        _td: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        Ok(Vec::new())
    }
}

/// Configuration for a cert-manager-backed CA. Issuer reference uses the
/// cert-manager APIs; Phase A only models the inputs.
#[derive(Debug, Clone)]
pub struct CertManagerConfig {
    pub kubeconfig_path: Option<String>,
    pub issuer_name: String,
    pub issuer_kind: String, // "Issuer" | "ClusterIssuer"
    pub issuer_namespace: Option<String>,
    pub trust_domain: TrustDomain,
}

/// cert-manager-backed CA. Phase A: scaffolded.
pub struct CertManagerCa {
    config: CertManagerConfig,
}

impl CertManagerCa {
    pub fn new(config: CertManagerConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &CertManagerConfig {
        &self.config
    }
}

#[async_trait]
impl CertificateAuthority for CertManagerCa {
    async fn issue_svid(&self, _req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        Err(CaError::Upstream(format!(
            "cert-manager CA (issuer={}/{}) is not yet implemented (Phase B+)",
            self.config.issuer_kind, self.config.issuer_name
        )))
    }

    async fn trust_bundle(&self, _td: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        Err(CaError::Upstream(
            "cert-manager trust bundle fetch not yet implemented (Phase B+)".to_string(),
        ))
    }

    async fn jwt_authorities(
        &self,
        _td: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        Ok(Vec::new())
    }
}
