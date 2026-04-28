//! In-process SPIFFE Workload API server.
//!
//! When Ferrum is acting as the SVID issuer, this server exposes the
//! Workload API over a Unix domain socket so local workloads (sidecars,
//! ambient ztunnels, plain processes on the host) can fetch SVIDs without
//! shipping a secret out-of-band.
//!
//! Architecture:
//!
//! 1. Listener: `tokio::net::UnixListener` bound to a configured path.
//! 2. Per-stream: gather peer creds + caller-supplied bearer token into
//!    [`PeerInfo`].
//! 3. Run the configured chain of [`Attestor`]s.
//! 4. Ask the [`CertificateAuthority`] to mint an SVID for the resulting
//!    SPIFFE ID and stream it back to the workload.
//!
//! Phase A wires up the gRPC service handlers and a `serve` entry point.
//! Listener bind / shutdown integration with the rest of the binary lands
//! in Phase C — Phase A keeps everything additive.

use async_trait::async_trait;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, warn};

use super::proto::spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer};
use super::proto::{
    JwtBundlesRequest, JwtBundlesResponse, JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest,
    ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse, X509svid, X509svidRequest,
    X509svidResponse,
};
use crate::identity::attestation::{Attestor, PeerInfo, attest_chain};
use crate::identity::ca::{CertificateAuthority, IssuanceRequest};
use crate::identity::spiffe::TrustDomain;

/// Workload API service implementation. Held as an `Arc` and cloned per RPC.
pub struct WorkloadApiService {
    pub attestors: Vec<Arc<dyn Attestor>>,
    pub ca: Arc<dyn CertificateAuthority>,
    pub trust_domain: TrustDomain,
    /// SVID lifetime (seconds) when an SVID is freshly minted in response to
    /// an attested workload. Falls back to the CA's clamp if higher.
    pub svid_ttl_secs: u64,
}

impl WorkloadApiService {
    pub fn new(
        attestors: Vec<Arc<dyn Attestor>>,
        ca: Arc<dyn CertificateAuthority>,
        trust_domain: TrustDomain,
        svid_ttl_secs: u64,
    ) -> Self {
        Self {
            attestors,
            ca,
            trust_domain,
            svid_ttl_secs,
        }
    }

    /// Wrap into a `tonic` server. Exposed so callers can register additional
    /// services on the same listener if they wish.
    pub fn into_server(self) -> SpiffeWorkloadApiServer<Self> {
        SpiffeWorkloadApiServer::new(self)
    }

    /// Extract `PeerInfo` from a tonic request. Phase A pulls the bearer
    /// token from the `authorization` metadata header (Bearer scheme); peer
    /// creds are surfaced by future Phase C wiring on the listener side.
    fn peer_info_from_request<T>(req: &Request<T>) -> PeerInfo {
        let mut info = PeerInfo::default();
        if let Some(auth) = req.metadata().get("authorization")
            && let Ok(s) = auth.to_str()
        {
            let trimmed = s.trim();
            let token = if let Some(rest) = trimmed.strip_prefix("Bearer ") {
                rest.trim().to_string()
            } else {
                trimmed.to_string()
            };
            if !token.is_empty() {
                info.bearer_token = Some(token);
            }
        }
        info
    }

    async fn attest(
        &self,
        peer: &PeerInfo,
    ) -> Result<crate::identity::attestation::WorkloadIdentity, Status> {
        match attest_chain(&self.attestors, peer).await {
            Ok(id) => {
                debug!(
                    spiffe_id = %id.spiffe_id,
                    attestor = %id.attestor_kind,
                    "workload attested"
                );
                Ok(id)
            }
            Err(e) => {
                warn!(error = %e, "workload attestation failed");
                Err(Status::permission_denied(format!(
                    "workload attestation failed: {e}"
                )))
            }
        }
    }

    async fn build_x509_svid_response(
        &self,
        identity: &crate::identity::attestation::WorkloadIdentity,
    ) -> Result<X509svidResponse, Status> {
        let svid = self
            .ca
            .issue_svid(IssuanceRequest::Generate {
                spiffe_id: identity.spiffe_id.clone(),
                ttl_secs: self.svid_ttl_secs,
            })
            .await
            .map_err(|e| {
                error!(error = %e, "CA failed to issue SVID");
                Status::internal(format!("CA failed: {e}"))
            })?;

        let bundle = self
            .ca
            .trust_bundle(&self.trust_domain)
            .await
            .map_err(|e| Status::internal(format!("CA bundle fetch failed: {e}")))?;

        let chain_concat: Vec<u8> = svid.cert_chain_der.iter().flatten().copied().collect();
        let bundle_concat: Vec<u8> = bundle.roots_der.iter().flatten().copied().collect();

        let proto_svid = X509svid {
            spiffe_id: svid.spiffe_id.to_string(),
            x509_svid: chain_concat,
            x509_svid_key: svid.private_key_pkcs8_der,
            bundle: bundle_concat,
            hint: svid.not_after.timestamp(),
        };

        Ok(X509svidResponse {
            svids: vec![proto_svid],
            federated_bundles: Default::default(),
            hint: bundle.refresh_hint_secs.unwrap_or(0) as i64,
        })
    }
}

#[async_trait]
impl SpiffeWorkloadApi for WorkloadApiService {
    type FetchX509SVIDStream =
        Pin<Box<dyn Stream<Item = Result<X509svidResponse, Status>> + Send + 'static>>;

    async fn fetch_x509svid(
        &self,
        request: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        let peer = Self::peer_info_from_request(&request);
        let identity = self.attest(&peer).await?;
        let response = self.build_x509_svid_response(&identity).await?;
        let stream = futures_util::stream::iter(vec![Ok(response)]);
        Ok(Response::new(Box::pin(stream)))
    }

    type FetchX509BundlesStream =
        Pin<Box<dyn Stream<Item = Result<X509BundlesResponse, Status>> + Send + 'static>>;

    async fn fetch_x509_bundles(
        &self,
        _request: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        let bundle = self
            .ca
            .trust_bundle(&self.trust_domain)
            .await
            .map_err(|e| Status::internal(format!("CA bundle fetch failed: {e}")))?;

        let mut bundles = std::collections::HashMap::new();
        let bundle_concat: Vec<u8> = bundle.roots_der.iter().flatten().copied().collect();
        bundles.insert(self.trust_domain.to_string(), bundle_concat);

        let response = X509BundlesResponse {
            hint: bundle.refresh_hint_secs.unwrap_or(0) as i64,
            bundles,
        };
        let stream = futures_util::stream::iter(vec![Ok(response)]);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn fetch_jwtsvid(
        &self,
        _request: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        // Phase A: JWT-SVID minting is intentionally unimplemented; later
        // phases plug into the CA's `jwt_authorities()`.
        Err(Status::unimplemented(
            "JWT-SVID issuance is deferred to a later mesh phase",
        ))
    }

    type FetchJWTBundlesStream =
        Pin<Box<dyn Stream<Item = Result<JwtBundlesResponse, Status>> + Send + 'static>>;

    async fn fetch_jwt_bundles(
        &self,
        _request: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        let response = JwtBundlesResponse {
            bundles: Default::default(),
        };
        let stream = futures_util::stream::iter(vec![Ok(response)]);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn validate_jwtsvid(
        &self,
        _request: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        Err(Status::unimplemented(
            "JWT-SVID validation is deferred to a later mesh phase",
        ))
    }
}
