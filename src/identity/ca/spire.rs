//! SPIRE Agent CA backend.
//!
//! Delegates SVID issuance and trust-bundle retrieval to a SPIRE Agent over
//! the SPIFFE Workload API (Unix domain socket). Unlike the internal CA that
//! holds a root key and signs locally, this backend delegates all crypto to
//! the agent — Ferrum never sees a CA private key.
//!
//! ## How it works
//!
//! The SPIRE Agent's Workload API streams X.509 SVIDs to registered
//! workloads. This CA backend opens the streaming `FetchX509SVID` RPC at
//! construction time, parks a background task that continuously feeds the
//! latest SVID + bundle into an `ArcSwap`, and serves `issue_svid` /
//! `trust_bundle` reads from that snapshot. The agent handles rotation —
//! when it pushes a fresh SVID, the snapshot is atomically replaced.
//!
//! ## Issuance semantics
//!
//! Because the SPIRE agent manages keys and certs, `issue_svid` does NOT
//! mint a new certificate on every call. Instead it returns the current
//! SVID from the agent-supplied snapshot. Callers that need per-workload
//! SVIDs (the in-process Workload API server) should use the internal CA
//! or Vault PKI backend instead.
//!
//! ## Configuration
//!
//! - `FERRUM_MESH_SPIRE_AGENT_SOCKET` — path to the SPIRE Agent UDS.
//!   Defaults to [`DEFAULT_SPIRE_AGENT_SOCKET`].

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tokio::sync::Notify;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use super::{
    CaError, CertificateAuthority, IssuanceRequest, PublishedJwtAuthority, PublishedTrustBundle,
    SignedSvid,
};
use crate::identity::SvidBundle;
use crate::identity::spiffe::TrustDomain;
use crate::identity::workload_api::client::WorkloadApiClient;

/// Default UDS path for the SPIRE Agent. Operators override via
/// `FERRUM_MESH_SPIRE_AGENT_SOCKET`.
pub const DEFAULT_SPIRE_AGENT_SOCKET: &str = "/run/spire/sockets/agent.sock";

/// Reconnect backoff floor.
const RECONNECT_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Reconnect backoff ceiling.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How long to wait for the first SVID from the agent before giving up.
const INITIAL_SVID_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for [`SpireAgentCa`].
#[derive(Debug, Clone)]
pub struct SpireAgentCaConfig {
    /// Path to the SPIRE Agent's Workload API UDS.
    pub socket_path: String,
    /// SVID lifetime hint (seconds). The SPIRE agent may ignore this — it
    /// controls the actual TTL. Stored so `issue_svid` can populate
    /// `SignedSvid.not_after` from the agent-issued leaf.
    pub cert_ttl_secs: u64,
}

impl Default for SpireAgentCaConfig {
    fn default() -> Self {
        Self {
            socket_path: DEFAULT_SPIRE_AGENT_SOCKET.to_string(),
            cert_ttl_secs: 3600,
        }
    }
}

/// Internal snapshot holding the latest agent-pushed SVID and bundles.
#[derive(Debug, Clone)]
struct AgentSnapshot {
    bundle: SvidBundle,
}

/// SPIRE-Agent-backed certificate authority.
///
/// Holds a shared snapshot of the latest SVID pushed by the agent over the
/// Workload API stream. A background task keeps the snapshot up to date;
/// all `CertificateAuthority` methods read from it lock-free.
pub struct SpireAgentCa {
    config: SpireAgentCaConfig,
    /// Latest snapshot. `None` until the first SVID arrives.
    current: Arc<ArcSwap<Option<AgentSnapshot>>>,
    /// Fires once the first SVID has been observed.
    first_ready: Arc<Notify>,
    first_received: Arc<std::sync::atomic::AtomicBool>,
}

impl SpireAgentCa {
    /// Build and start the background fetch loop. Returns once the first SVID
    /// has arrived from the agent (or after `INITIAL_SVID_TIMEOUT`).
    pub async fn new(config: SpireAgentCaConfig) -> Result<Self, CaError> {
        let current: Arc<ArcSwap<Option<AgentSnapshot>>> = Arc::new(ArcSwap::new(Arc::new(None)));
        let first_ready = Arc::new(Notify::new());
        let first_received = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let ca = Self {
            config: config.clone(),
            current: Arc::clone(&current),
            first_ready: Arc::clone(&first_ready),
            first_received: Arc::clone(&first_received),
        };

        // Spawn the background stream loop.
        tokio::spawn(stream_loop(
            config.socket_path.clone(),
            Arc::clone(&current),
            Arc::clone(&first_ready),
            Arc::clone(&first_received),
        ));

        // Wait for the first SVID with a timeout so startup does not hang
        // indefinitely when the agent is unreachable.
        let notified = first_ready.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if !first_received.load(std::sync::atomic::Ordering::Acquire) {
            match tokio::time::timeout(INITIAL_SVID_TIMEOUT, notified).await {
                Ok(()) => {
                    info!(
                        socket = %config.socket_path,
                        "SPIRE agent CA: received initial SVID"
                    );
                }
                Err(_) => {
                    warn!(
                        socket = %config.socket_path,
                        timeout_secs = INITIAL_SVID_TIMEOUT.as_secs(),
                        "SPIRE agent CA: timed out waiting for initial SVID — \
                         CA will serve once the agent pushes one"
                    );
                }
            }
        }

        Ok(ca)
    }

    /// Configuration this CA was built with.
    pub fn config(&self) -> &SpireAgentCaConfig {
        &self.config
    }

    /// Snapshot the current SVID bundle. Returns `None` before the first
    /// agent push.
    fn snapshot(&self) -> Option<AgentSnapshot> {
        let guard = self.current.load();
        guard.as_ref().clone()
    }

    /// Block until the first SVID arrives (or the timeout expires).
    ///
    /// Race-free: registers a waiter before checking the flag — same
    /// pattern as [`crate::identity::workload_api::fetch_loop::SvidFetchHandle`].
    pub async fn wait_for_first_svid(&self) {
        let notified = self.first_ready.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if self
            .first_received
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        notified.await;
    }
}

/// Background loop that keeps the snapshot up to date. Never returns
/// unless the task is cancelled.
async fn stream_loop(
    socket_path: String,
    current: Arc<ArcSwap<Option<AgentSnapshot>>>,
    first_ready: Arc<Notify>,
    first_received: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut backoff = RECONNECT_BACKOFF_INITIAL;

    loop {
        match WorkloadApiClient::connect(&socket_path).await {
            Ok(mut client) => match client.fetch_x509_svid_stream().await {
                Ok((mut stream, _first_signal)) => {
                    info!(socket = %socket_path, "SPIRE agent CA: stream established");
                    backoff = RECONNECT_BACKOFF_INITIAL;

                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(bundle) => {
                                debug!(
                                    spiffe_id = %bundle.spiffe_id,
                                    "SPIRE agent CA: received SVID"
                                );
                                let snapshot = AgentSnapshot { bundle };
                                current.store(Arc::new(Some(snapshot)));

                                let was_first =
                                    first_received.swap(true, std::sync::atomic::Ordering::AcqRel);
                                if !was_first {
                                    first_ready.notify_waiters();
                                }
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "SPIRE agent CA: stream error — reconnecting"
                                );
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "SPIRE agent CA: stream RPC failed"
                    );
                }
            },
            Err(e) => {
                error!(
                    error = %e,
                    socket = %socket_path,
                    "SPIRE agent CA: failed to connect"
                );
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

/// Extract `not_after` from the leaf certificate in a snapshot.
fn leaf_not_after(cert_chain_der: &[Vec<u8>]) -> Result<chrono::DateTime<chrono::Utc>, CaError> {
    use x509_parser::prelude::*;

    let leaf = cert_chain_der
        .first()
        .ok_or_else(|| CaError::Internal("SPIRE agent returned empty cert chain".to_string()))?;
    let (_, parsed) = X509Certificate::from_der(leaf)
        .map_err(|e| CaError::Internal(format!("failed to parse SPIRE leaf cert: {e}")))?;
    chrono::DateTime::<chrono::Utc>::from_timestamp(parsed.validity().not_after.timestamp(), 0)
        .ok_or_else(|| {
            CaError::Internal(
                "SPIRE leaf cert notAfter is outside supported timestamp range".to_string(),
            )
        })
}

#[async_trait]
impl CertificateAuthority for SpireAgentCa {
    /// Return the current SVID from the agent snapshot.
    ///
    /// Unlike the internal CA, this does NOT mint a fresh cert — the SPIRE
    /// agent controls issuance. The returned `SignedSvid` always reflects the
    /// latest agent-pushed SVID.
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        let snap = self.snapshot().ok_or_else(|| {
            CaError::Upstream(
                "SPIRE agent has not yet pushed an SVID — is the agent running and \
                 is this workload registered?"
                    .to_string(),
            )
        })?;

        // Validate that the requested SPIFFE ID matches the agent-issued one.
        let requested_id = match &req {
            IssuanceRequest::Csr { spiffe_id, .. } => spiffe_id,
            IssuanceRequest::Generate { spiffe_id, .. } => spiffe_id,
        };

        if requested_id != &snap.bundle.spiffe_id {
            return Err(CaError::BadCsr(format!(
                "requested SPIFFE ID '{}' does not match agent-issued SVID '{}'; \
                 the SPIRE agent controls identity assignment",
                requested_id, snap.bundle.spiffe_id
            )));
        }

        let not_after = leaf_not_after(&snap.bundle.cert_chain_der)?;

        Ok(SignedSvid {
            spiffe_id: snap.bundle.spiffe_id.clone(),
            cert_chain_der: snap.bundle.cert_chain_der.clone(),
            private_key_pkcs8_der: snap.bundle.private_key_pkcs8_der.clone(),
            not_after,
        })
    }

    async fn trust_bundle(&self, td: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        let snap = self.snapshot().ok_or_else(|| {
            CaError::Upstream("SPIRE agent has not yet pushed trust bundles".to_string())
        })?;

        // Check local bundle first, then federated.
        let bundle = snap
            .bundle
            .trust_bundles
            .get(td)
            .ok_or_else(|| CaError::UnknownTrustDomain(td.to_string()))?;

        Ok(PublishedTrustBundle {
            trust_domain: bundle.trust_domain.clone(),
            roots_der: bundle.x509_authorities.clone(),
            refresh_hint_secs: bundle.refresh_hint_seconds,
        })
    }

    async fn jwt_authorities(
        &self,
        td: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        let snap = self.snapshot().ok_or_else(|| {
            CaError::Upstream("SPIRE agent has not yet pushed trust bundles".to_string())
        })?;

        let bundle = snap
            .bundle
            .trust_bundles
            .get(td)
            .ok_or_else(|| CaError::UnknownTrustDomain(td.to_string()))?;

        Ok(bundle
            .jwt_authorities
            .iter()
            .map(|ja| PublishedJwtAuthority {
                trust_domain: td.clone(),
                key_id: ja.key_id.clone(),
                public_key_pem: ja.public_key_pem.clone(),
            })
            .collect())
    }
}
