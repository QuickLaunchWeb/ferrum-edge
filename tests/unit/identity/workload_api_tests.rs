//! Workload-API client + server tests.
//!
//! We exercise the in-process service handler directly (without binding a
//! Unix socket) so the test stays portable across the supported targets.
//! End-to-end UDS round-trip tests live in `tests/integration/` (deferred to
//! later phases — Phase A only needs the trait wiring to compile and behave
//! correctly under unit-test scope).

use async_trait::async_trait;
use ferrum_edge::identity::attestation::{Attestor, PeerInfo, WorkloadIdentity};
use ferrum_edge::identity::ca::{
    CaError, CertificateAuthority, IssuanceRequest, PublishedJwtAuthority, PublishedTrustBundle,
    SignedSvid,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::identity::workload_api::server::WorkloadApiService;
use std::collections::HashMap;
use std::sync::Arc;

// ── CA stub ──────────────────────────────────────────────────────────────

struct StubCa {
    trust_domain: TrustDomain,
    /// Counter so each issuance produces a different "cert".
    counter: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl CertificateAuthority for StubCa {
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (id, ttl) = match req {
            IssuanceRequest::Generate {
                spiffe_id,
                ttl_secs,
            } => (spiffe_id, ttl_secs),
            IssuanceRequest::Csr {
                spiffe_id,
                ttl_secs,
                ..
            } => (spiffe_id, ttl_secs),
        };
        Ok(SignedSvid {
            spiffe_id: id,
            cert_chain_der: vec![format!("stub-cert-{n}").into_bytes()],
            private_key_pkcs8_der: b"stub-key".to_vec(),
            not_after: chrono::Utc::now() + chrono::Duration::seconds(ttl as i64),
        })
    }

    async fn trust_bundle(&self, td: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        if td != &self.trust_domain {
            return Err(CaError::UnknownTrustDomain(td.to_string()));
        }
        Ok(PublishedTrustBundle {
            trust_domain: self.trust_domain.clone(),
            roots_der: vec![b"stub-root".to_vec()],
            refresh_hint_secs: Some(60),
        })
    }

    async fn jwt_authorities(
        &self,
        _td: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        Ok(Vec::new())
    }
}

// ── Stub attestor ────────────────────────────────────────────────────────

struct StubAttestor {
    id: SpiffeId,
}

#[async_trait]
impl Attestor for StubAttestor {
    fn kind(&self) -> &'static str {
        "stub"
    }
    async fn attest(
        &self,
        _peer: &PeerInfo,
    ) -> Result<WorkloadIdentity, ferrum_edge::identity::attestation::AttestError> {
        Ok(WorkloadIdentity {
            spiffe_id: self.id.clone(),
            selectors: HashMap::new(),
            attestor_kind: "stub".to_string(),
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn workload_api_service_constructs_with_attestor_and_ca() {
    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id: id.clone() });

    let svc = WorkloadApiService::new(vec![attestor], ca, trust_domain.clone(), 600);
    assert_eq!(svc.trust_domain, trust_domain);
    assert_eq!(svc.svid_ttl_secs, 600);
    assert_eq!(svc.attestors.len(), 1);
}

#[tokio::test]
async fn attest_chain_returns_first_success() {
    use ferrum_edge::identity::attestation::{AttestError, attest_chain};
    let id = SpiffeId::new("spiffe://td/ns/foo").unwrap();

    struct Skip;
    #[async_trait::async_trait]
    impl Attestor for Skip {
        fn kind(&self) -> &'static str {
            "skip"
        }
        async fn attest(&self, _: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
            Err(AttestError::NotApplicable)
        }
    }

    let attestors: Vec<Arc<dyn Attestor>> =
        vec![Arc::new(Skip), Arc::new(StubAttestor { id: id.clone() })];
    let result = attest_chain(&attestors, &PeerInfo::default())
        .await
        .unwrap();
    assert_eq!(result.spiffe_id, id);
}

#[tokio::test]
async fn attest_chain_aggregates_failures() {
    use ferrum_edge::identity::attestation::{AttestError, attest_chain};

    struct Skip;
    #[async_trait::async_trait]
    impl Attestor for Skip {
        fn kind(&self) -> &'static str {
            "skip"
        }
        async fn attest(&self, _: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
            Err(AttestError::NotApplicable)
        }
    }

    let attestors: Vec<Arc<dyn Attestor>> = vec![Arc::new(Skip), Arc::new(Skip)];
    let result = attest_chain(&attestors, &PeerInfo::default()).await;
    assert!(matches!(result, Err(AttestError::Failed(_))));
}

#[tokio::test]
async fn attest_chain_rejects_empty() {
    use ferrum_edge::identity::attestation::{AttestError, attest_chain};
    let attestors: Vec<Arc<dyn Attestor>> = Vec::new();
    let result = attest_chain(&attestors, &PeerInfo::default()).await;
    assert!(matches!(result, Err(AttestError::Config(_))));
}
