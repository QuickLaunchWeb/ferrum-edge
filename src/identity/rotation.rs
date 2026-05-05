//! SVID rotation task.
//!
//! Periodically inspects the current [`SvidBundle`] and asks the local
//! [`CertificateAuthority`] for a fresh SVID once the current one has
//! crossed half its validity window. The new bundle is hot-swapped via
//! `ArcSwap` so concurrent readers (TLS resolvers) see the swap atomically.
//!
//! This module is intended for the **Ferrum-as-issuer** flow. The
//! **SPIRE-agent flow** uses [`workload_api::fetch_loop`] instead — the
//! agent handles rotation and pushes new SVIDs through its streaming RPC.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use x509_parser::prelude::*;

use crate::identity::{
    SvidBundle, TrustBundle, TrustBundleSet,
    ca::{IssuanceRequest, SharedCa},
    spiffe::SpiffeId,
};

/// Minimum interval between rotation checks. Even when an SVID has only
/// seconds left to live we don't want to busy-loop.
const MIN_TICK: Duration = Duration::from_secs(5);
/// Maximum interval between rotation checks. Long-lived SVIDs (24h) get
/// re-checked once per minute to handle clock-skew gracefully.
const MAX_TICK: Duration = Duration::from_secs(60);

/// Configuration for the rotation task.
pub struct RotationConfig {
    /// CA used to mint replacement SVIDs.
    pub ca: SharedCa,
    /// SPIFFE ID this rotation task is responsible for.
    pub spiffe_id: SpiffeId,
    /// SVID lifetime to request from the CA.
    pub svid_ttl_secs: u64,
    /// Shared bundle slot. Readers (TLS resolvers) load from this.
    pub current: Arc<ArcSwap<Option<SvidBundle>>>,
    /// Trigger rotation once the current SVID has aged past this fraction
    /// (0.0..=1.0) of its validity window. Default 0.5.
    pub rotate_at_fraction: f64,
}

impl RotationConfig {
    pub fn new(ca: SharedCa, spiffe_id: SpiffeId, svid_ttl_secs: u64) -> Self {
        Self {
            ca,
            spiffe_id,
            svid_ttl_secs,
            current: Arc::new(ArcSwap::new(Arc::new(None))),
            rotate_at_fraction: 0.5,
        }
    }
}

/// Spawn the rotation task. Returns a `JoinHandle`; drop to stop.
pub fn spawn_rotation(config: RotationConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(rotation_main(config))
}

async fn rotation_main(config: RotationConfig) {
    // Mint an initial SVID so callers can bind listeners.
    if let Err(e) = mint_and_install(&config).await {
        error!(error = %e, "initial SVID issuance failed — rotation task continues");
    }

    loop {
        let snapshot = config.current.load_full();
        let next_tick = match snapshot.as_ref() {
            Some(bundle) => decide_next_tick(bundle, config.rotate_at_fraction),
            None => Duration::from_secs(1),
        };
        sleep(next_tick).await;

        let snapshot = config.current.load_full();
        let needs_rotation = match snapshot.as_ref() {
            Some(bundle) => is_due_for_rotation(bundle, config.rotate_at_fraction),
            None => true,
        };
        if !needs_rotation {
            continue;
        }
        match mint_and_install(&config).await {
            Ok(()) => info!(spiffe_id = %config.spiffe_id, "SVID rotated"),
            Err(e) => warn!(error = %e, spiffe_id = %config.spiffe_id, "SVID rotation failed"),
        }
    }
}

async fn mint_and_install(config: &RotationConfig) -> Result<(), String> {
    let svid = config
        .ca
        .issue_svid(IssuanceRequest::Generate {
            spiffe_id: config.spiffe_id.clone(),
            ttl_secs: config.svid_ttl_secs,
        })
        .await
        .map_err(|e| e.to_string())?;
    let bundle = config
        .ca
        .trust_bundle(config.spiffe_id.trust_domain())
        .await
        .map_err(|e| e.to_string())?;

    let svid_bundle = SvidBundle {
        spiffe_id: svid.spiffe_id.clone(),
        cert_chain_der: svid.cert_chain_der,
        private_key_pkcs8_der: svid.private_key_pkcs8_der,
        trust_bundles: TrustBundleSet {
            local: TrustBundle {
                trust_domain: bundle.trust_domain.clone(),
                x509_authorities: bundle.roots_der.clone(),
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: bundle.refresh_hint_secs,
            },
            federated: Default::default(),
        },
    };
    debug!(spiffe_id = %svid.spiffe_id, "rotation: minted fresh SVID");
    config.current.store(Arc::new(Some(svid_bundle)));
    Ok(())
}

/// Inspect the leaf certificate of a bundle and decide how long to sleep
/// before checking rotation again. The result is bounded by
/// [`MIN_TICK`]/[`MAX_TICK`].
pub fn decide_next_tick(bundle: &SvidBundle, rotate_at_fraction: f64) -> Duration {
    let (not_before, not_after) = match leaf_validity(bundle) {
        Some(v) => v,
        None => return MIN_TICK,
    };
    let total = (not_after - not_before).num_seconds().max(1);
    let rotate_at =
        not_before + chrono::Duration::seconds((total as f64 * rotate_at_fraction) as i64);
    let now = Utc::now();
    let until_rotate = (rotate_at - now).num_seconds();
    let next_tick = if until_rotate <= 0 {
        MIN_TICK
    } else {
        Duration::from_secs(until_rotate as u64)
    };
    next_tick.clamp(MIN_TICK, MAX_TICK)
}

/// `true` iff the bundle's leaf is past its rotation threshold.
pub fn is_due_for_rotation(bundle: &SvidBundle, rotate_at_fraction: f64) -> bool {
    let (not_before, not_after) = match leaf_validity(bundle) {
        Some(v) => v,
        None => return true,
    };
    let total = (not_after - not_before).num_seconds().max(1);
    let rotate_at =
        not_before + chrono::Duration::seconds((total as f64 * rotate_at_fraction) as i64);
    Utc::now() >= rotate_at
}

fn leaf_validity(bundle: &SvidBundle) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let leaf = bundle.cert_chain_der.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf).ok()?;
    let validity = parsed.validity();
    let not_before = DateTime::<Utc>::from_timestamp(validity.not_before.timestamp(), 0)?;
    let not_after = DateTime::<Utc>::from_timestamp(validity.not_after.timestamp(), 0)?;
    Some((not_before, not_after))
}
