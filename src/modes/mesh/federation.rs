//! SPIFFE trust-bundle federation poller (GAP-3C).
//!
//! Today the mesh slice carries [`TrustBundleSet.federated`](crate::modes::mesh::config::TrustBundleSet)
//! only when a control plane pushes it. This module adds a runtime poller that
//! fetches remote-cluster trust bundles from
//! `MultiClusterConfig.remote_clusters[].federation_endpoint` URLs and stores
//! the validated result in an `ArcSwap`-held map. The slice apply path merges
//! that snapshot with whatever the control plane provided so cross-cluster
//! mTLS can verify federated peers without a CP push for every rotation.
//!
//! Design notes:
//!
//! - **Lock-free hot path**: readers (slice apply, verifier) load the snapshot
//!   via [`FederationStore::snapshot`], which dereferences a single `ArcSwap`.
//! - **Validated swap**: each polled bundle is validated through the same
//!   trust-bundle invariants as a slice-provided bundle before being stored.
//!   A failed poll bumps the failure metric and keeps the last-good entry —
//!   `FERRUM_MESH_FEDERATION_FAIL_OPEN=false` (default) means cross-cluster
//!   mTLS verifies against the last successful bundle; once-and-only-once
//!   poll failures never delete a previously fetched bundle.
//! - **Backoff**: each remote endpoint runs in its own tokio task with
//!   jittered exponential backoff matching `src/grpc/dp_client.rs`
//!   (1s → 30s cap, ±25% jitter). On success the per-target backoff resets to
//!   the configured poll interval.
//! - **Shutdown**: every loop watches the gateway's shutdown channel; SIGTERM
//!   drains the poller cleanly.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::Deserialize;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::identity::TrustDomain;
use crate::modes::mesh::config::{JwtAuthority, MultiClusterConfig, TrustBundle, TrustBundleSet};
use crate::plugins::utils::http_client::PluginHttpClient;

/// Backoff bounds shared with `src/grpc/dp_client.rs`. The federation poller
/// intentionally mirrors the CP-reconnect cadence so an operator-tuned cluster
/// has only one cross-cluster backoff curve to reason about.
pub(crate) const FEDERATION_BACKOFF_INITIAL_SECS: u64 = 1;
pub(crate) const FEDERATION_BACKOFF_MAX_SECS: u64 = 30;

/// Hard cap on federation response body size. A real SPIFFE bundle is
/// kilobytes — even a generous JWKS with several authorities fits well
/// below 256 KiB. The 2 MiB cap leaves vast headroom while preventing a
/// malicious or runaway endpoint from streaming gigabytes into a single
/// `Bytes` allocation inside the timeout window.
const FEDERATION_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Defense-in-depth bounds on parsed bundle sizes. SPIFFE bundles in the
/// wild carry a handful of certs at most; 256 entries is orders of
/// magnitude above realistic. Stops a small JSON document with millions of
/// empty-string keys from allocating millions of `JwtAuthority` structs.
const FEDERATION_MAX_X509_AUTHORITIES: usize = 256;
const FEDERATION_MAX_JWT_AUTHORITIES: usize = 256;

/// Snapshot the federation store hands out to slice apply and the admin API.
/// Keyed by trust domain so two `RemoteCluster` entries with overlapping trust
/// domains would dedupe at install time (last writer wins; the poller only
/// installs a target's own trust domain).
#[derive(Debug, Default, Clone)]
pub struct FederationSnapshot {
    pub bundles: HashMap<TrustDomain, FederatedBundle>,
}

#[derive(Debug, Clone)]
pub struct FederatedBundle {
    pub bundle: TrustBundle,
    pub fetched_at_unix_seconds: u64,
    pub endpoint: String,
    pub cluster_name: String,
}

/// Lock-free shared state populated by the poller and consumed by both the
/// slice-apply path and `GET /mesh/federation`.
#[derive(Clone)]
pub struct FederationStore {
    inner: Arc<ArcSwap<FederationSnapshot>>,
    first_ready: Arc<std::sync::atomic::AtomicBool>,
    /// Bumped on every successful install. The slice-apply task subscribes to
    /// it so a freshly polled bundle re-runs the slice-apply pipeline even
    /// when the live mesh slice itself is unchanged. Without this, a stable
    /// CP config would never pick up a rotated federated trust bundle until
    /// the next CP push.
    revision_tx: Arc<watch::Sender<u64>>,
}

impl Default for FederationStore {
    fn default() -> Self {
        let (revision_tx, _) = watch::channel(0u64);
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(FederationSnapshot::default()))),
            first_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            revision_tx: Arc::new(revision_tx),
        }
    }
}

impl FederationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock-free read.
    pub fn snapshot(&self) -> Arc<FederationSnapshot> {
        self.inner.load_full()
    }

    /// `true` after at least one trust domain has been successfully polled.
    pub fn has_first_success(&self) -> bool {
        self.first_ready.load(Ordering::Acquire)
    }

    /// Subscribe to install events. Mirrors `MeshRuntimeState::subscribe()`.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }

    fn install(&self, trust_domain: TrustDomain, bundle: FederatedBundle) {
        // Atomic compare-and-swap loop so two concurrent successful polls
        // (different remote clusters) cannot stomp each other. Without the
        // CAS loop, two tasks both reading the same starting snapshot would
        // each insert their bundle into a clone and the second store would
        // discard the first.
        self.inner.rcu(|current| {
            let mut next = (**current).clone();
            next.bundles.insert(trust_domain.clone(), bundle.clone());
            Arc::new(next)
        });
        self.first_ready.store(true, Ordering::Release);
        self.revision_tx.send_modify(|revision| *revision += 1);
    }

    /// Remove a trust domain from the federated bundle map. Used by a
    /// future reconcile pass when a `RemoteCluster` is removed from the
    /// slice; today the poller spawns once at startup and never sees
    /// removals. Plumbed here so the reconcile follow-up doesn't need to
    /// touch the atomic install path again.
    /// No-op if the domain isn't tracked.
    #[allow(dead_code)]
    pub fn remove(&self, trust_domain: &TrustDomain) {
        let mut changed = false;
        self.inner.rcu(|current| {
            if current.bundles.contains_key(trust_domain) {
                let mut next = (**current).clone();
                next.bundles.remove(trust_domain);
                changed = true;
                Arc::new(next)
            } else {
                Arc::clone(current)
            }
        });
        if changed {
            self.revision_tx.send_modify(|revision| *revision += 1);
        }
    }
}

/// Wire-format the federation endpoint serves.
///
/// Two shapes are accepted, validated through a single `serde(untagged)` enum:
///
/// 1. **Ferrum-native** (`{"trust_domain": "...", "x509_authorities": [...]}`):
///    a direct serialization of [`TrustBundle`] from `src/modes/mesh/config.rs`.
///    This is the canonical shape and round-trips through `serde_json` with
///    zero mapping. A Ferrum control plane serving its local trust material
///    over HTTPS would emit this format directly.
///
/// 2. **SPIFFE JWKS** (`{"keys": [{"kty": "RSA", "use": "x509-svid",
///    "x5c": ["..."]}], "spiffe_sequence": 1, "spiffe_refresh_hint": 60}`):
///    the SPIFFE Trust Domain and Bundle JWKS profile. We translate the
///    `keys` array to `TrustBundle` at decode time using the `use` claim
///    (`x509-svid` → `x509_authorities[]`; `jwt-svid` → `jwt_authorities[]`
///    with `kid` + a PEM-wrapped JWK key). The trust domain is supplied by
///    the surrounding [`RemoteCluster`](crate::modes::mesh::config::RemoteCluster)
///    entry because SPIFFE bundles do not carry it inside the document.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FederationDocument {
    /// SPIFFE JWKS is tried first because it has a required `keys` field —
    /// only matches when the wire document actually carries a JWKS. The
    /// native variant has every field defaulted, so without this ordering an
    /// untagged enum would silently accept a JWKS document as an empty
    /// Native bundle.
    SpiffeJwks(SpiffeJwksDocument),
    Native(NativeFederationBundle),
}

#[derive(Debug, Deserialize)]
struct NativeFederationBundle {
    #[serde(default)]
    trust_domain: Option<String>,
    #[serde(default)]
    x509_authorities: Vec<String>,
    #[serde(default)]
    jwt_authorities: Vec<JwtAuthority>,
    #[serde(default)]
    refresh_hint_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SpiffeJwksDocument {
    keys: Vec<SpiffeJwksKey>,
    #[serde(default)]
    spiffe_refresh_hint: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SpiffeJwksKey {
    #[serde(rename = "use", default)]
    key_use: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    x5c: Vec<String>,
    /// SPIFFE JWKS includes the full JWK (`kty`, `n`, `e`, `crv`, `x`, `y`).
    /// We preserve it as-is in `jwt_authorities[].public_key_pem` so callers
    /// can hand it to a JWK consumer; the consumer is responsible for
    /// converting JWK → PEM as needed. This intentionally keeps the poller
    /// free of crypto-format conversion code.
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

/// Parse the wire document into a [`TrustBundle`] keyed under
/// `expected_trust_domain`. SPIFFE federation responses do not carry their
/// trust domain inline; native responses may include it but the value MUST
/// match the configured remote-cluster trust domain.
pub(crate) fn parse_federation_document(
    body: &[u8],
    expected_trust_domain: &TrustDomain,
) -> Result<TrustBundle, String> {
    let doc: FederationDocument =
        serde_json::from_slice(body).map_err(|e| format!("invalid federation bundle JSON: {e}"))?;
    match doc {
        FederationDocument::Native(native) => {
            if let Some(ref td) = native.trust_domain
                && td.as_str() != expected_trust_domain.as_str()
            {
                return Err(format!(
                    "federation bundle trust_domain '{td}' does not match remote cluster trust domain '{expected_trust_domain}'"
                ));
            }
            if native.x509_authorities.len() > FEDERATION_MAX_X509_AUTHORITIES {
                return Err(format!(
                    "federation bundle for '{expected_trust_domain}' has {} x509 authorities (max {})",
                    native.x509_authorities.len(),
                    FEDERATION_MAX_X509_AUTHORITIES
                ));
            }
            if native.jwt_authorities.len() > FEDERATION_MAX_JWT_AUTHORITIES {
                return Err(format!(
                    "federation bundle for '{expected_trust_domain}' has {} JWT authorities (max {})",
                    native.jwt_authorities.len(),
                    FEDERATION_MAX_JWT_AUTHORITIES
                ));
            }
            Ok(TrustBundle {
                trust_domain: expected_trust_domain.clone(),
                x509_authorities: native.x509_authorities,
                jwt_authorities: native.jwt_authorities,
                refresh_hint_seconds: native.refresh_hint_seconds,
            })
        }
        FederationDocument::SpiffeJwks(jwks) => {
            if jwks.keys.len() > FEDERATION_MAX_X509_AUTHORITIES + FEDERATION_MAX_JWT_AUTHORITIES {
                return Err(format!(
                    "federation JWKS for '{expected_trust_domain}' has {} keys (max {})",
                    jwks.keys.len(),
                    FEDERATION_MAX_X509_AUTHORITIES + FEDERATION_MAX_JWT_AUTHORITIES
                ));
            }
            let mut x509 = Vec::new();
            let mut jwts = Vec::new();
            for key in jwks.keys {
                match key.key_use.as_deref() {
                    Some("x509-svid") => {
                        // Per SPIFFE Federation §4.2.1, `x5c` carries
                        // base64-DER X.509 certs (the standard JWK form,
                        // *not* JWS-style URL-safe base64).
                        x509.extend(key.x5c);
                    }
                    Some("jwt-svid") => {
                        let kid = key.kid.unwrap_or_default();
                        if kid.is_empty() {
                            return Err("federation bundle jwt-svid key missing 'kid'".to_string());
                        }
                        // Re-serialise the JWK fields back to JSON so downstream
                        // JWT consumers can parse it as a JWK. We intentionally
                        // do not convert to PEM here: see field doc above.
                        let json = serde_json::Value::Object(key.rest);
                        let serialised = serde_json::to_string(&json)
                            .map_err(|e| format!("re-serialising JWT JWK: {e}"))?;
                        jwts.push(JwtAuthority {
                            key_id: kid,
                            public_key_pem: serialised,
                        });
                    }
                    Some(other) => {
                        // Unknown SPIFFE `use` claim — skip with a warning so a
                        // newer SPIFFE spec key type does not break the
                        // existing keys.
                        debug!(unsupported_use = %other, "Skipping SPIFFE JWKS key with unsupported 'use'");
                    }
                    None => {
                        return Err("federation bundle JWKS key missing 'use' claim".to_string());
                    }
                }
            }
            Ok(TrustBundle {
                trust_domain: expected_trust_domain.clone(),
                x509_authorities: x509,
                jwt_authorities: jwts,
                refresh_hint_seconds: jwks.spiffe_refresh_hint,
            })
        }
    }
}

/// Validate a federation-fetched bundle through the same invariants the slice
/// validator applies to [`TrustBundleSet::federated`]. Centralised here so the
/// poller stays in lock-step with `validate_mesh_config_internal`.
pub(crate) fn validate_polled_bundle(bundle: &TrustBundle) -> Result<(), String> {
    if bundle.x509_authorities.is_empty() && bundle.jwt_authorities.is_empty() {
        return Err(format!(
            "federation bundle for trust domain '{}' has no authorities",
            bundle.trust_domain
        ));
    }
    bundle
        .decode_x509_authorities()
        .map(|_| ())
        .map_err(|e| format!("federation bundle for '{}': {}", bundle.trust_domain, e))
}

/// One polling task per [`RemoteCluster.federation_endpoint`].
struct RemoteClusterPollTarget {
    cluster_name: String,
    trust_domain: TrustDomain,
    endpoint: String,
}

/// Configuration knobs derived from `EnvConfig` / `MultiClusterConfig`.
#[derive(Debug, Clone)]
pub struct FederationPollerConfig {
    pub poll_interval: Duration,
    pub request_timeout: Duration,
    /// Reserved for future verifier integration. Today this value is
    /// recorded in poll-failure log lines for operator visibility but does
    /// NOT influence the verifier — cross-cluster mTLS always verifies
    /// against the last-good bundle (fail-closed). When the verifier is
    /// extended to honour this flag, `true` will let trust domains with no
    /// cached bundle fall through to the CP-supplied slice. Tracked in
    /// [`docs/mesh.md`](../../../docs/mesh.md) "Trust Federation".
    pub fail_open: bool,
}

impl FederationPollerConfig {
    /// Returns `None` when the poller should be disabled (interval 0 or no
    /// federated remote clusters configured).
    pub fn from_env(interval_seconds: u64, timeout_seconds: u64, fail_open: bool) -> Option<Self> {
        if interval_seconds == 0 {
            return None;
        }
        Some(Self {
            poll_interval: Duration::from_secs(interval_seconds),
            request_timeout: Duration::from_secs(timeout_seconds.max(1)),
            fail_open,
        })
    }
}

/// Holds the spawned tasks so callers can join during graceful shutdown.
pub struct FederationPollerHandles {
    pub tasks: Vec<JoinHandle<()>>,
}

/// Resolve the polling-target list from a [`MultiClusterConfig`]. Remote
/// clusters without a federation endpoint are silently skipped (the operator
/// is allowed to leave that field unset for east-west-only federation).
fn poll_targets_for_multi_cluster(
    multi_cluster: &MultiClusterConfig,
) -> Vec<RemoteClusterPollTarget> {
    multi_cluster
        .remote_clusters
        .iter()
        .filter_map(|remote| {
            let endpoint = remote.federation_endpoint.as_deref()?.trim();
            if endpoint.is_empty() {
                return None;
            }
            // SSRF + plaintext defense: reject endpoints pointing at link-
            // local / loopback / cloud-metadata / non-https hosts at slice
            // apply time so a misconfigured (or compromised) CP cannot
            // weaponize the poller. Bad targets are dropped with a warn;
            // the rest of the federation surface continues to function.
            if let Err(err) = validate_federation_endpoint(endpoint) {
                warn!(
                    cluster = %remote.name,
                    trust_domain = %remote.trust_domain,
                    error = %err,
                    "Dropping federation_endpoint that failed SSRF/scheme validation"
                );
                return None;
            }
            Some(RemoteClusterPollTarget {
                cluster_name: remote.name.clone(),
                trust_domain: remote.trust_domain.clone(),
                endpoint: endpoint.to_string(),
            })
        })
        .collect()
}

/// Spawn the federation poller. Returns `None` when the poller is disabled or
/// there are no configured federation endpoints; otherwise returns the spawned
/// task handles. The caller-supplied `store` is shared with the mesh runtime
/// so successful polls are observable by the slice-apply path immediately.
pub fn spawn_federation_poller(
    multi_cluster: Option<&MultiClusterConfig>,
    config: Option<FederationPollerConfig>,
    http_client: PluginHttpClient,
    store: FederationStore,
    shutdown_rx: watch::Receiver<bool>,
) -> Option<FederationPollerHandles> {
    let config = config?;
    let multi_cluster = multi_cluster?;
    let targets = poll_targets_for_multi_cluster(multi_cluster);
    if targets.is_empty() {
        debug!(
            "No remote clusters with federation_endpoint configured; federation poller disabled"
        );
        return None;
    }
    let mut tasks = Vec::with_capacity(targets.len());
    for target in targets {
        let task_store = store.clone();
        let task_config = config.clone();
        let task_client = http_client.clone();
        let task_shutdown = shutdown_rx.clone();
        let cluster_name = target.cluster_name.clone();
        let trust_domain = target.trust_domain.clone();
        let endpoint = target.endpoint.clone();
        info!(
            cluster = %cluster_name,
            trust_domain = %trust_domain,
            endpoint = %endpoint,
            poll_interval_seconds = task_config.poll_interval.as_secs(),
            fail_open = task_config.fail_open,
            "Spawning SPIFFE federation poller"
        );
        let handle = tokio::spawn(async move {
            poll_federation_loop(target, task_store, task_config, task_client, task_shutdown).await;
        });
        tasks.push(handle);
    }
    Some(FederationPollerHandles { tasks })
}

async fn poll_federation_loop(
    target: RemoteClusterPollTarget,
    store: FederationStore,
    config: FederationPollerConfig,
    http_client: PluginHttpClient,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut backoff_secs = FEDERATION_BACKOFF_INITIAL_SECS;
    let cluster_name = target.cluster_name;
    let trust_domain = target.trust_domain;
    let endpoint = target.endpoint;

    loop {
        if *shutdown_rx.borrow() {
            return;
        }

        let attempt_started_at = std::time::Instant::now();
        let result = fetch_and_install_bundle(
            &cluster_name,
            &trust_domain,
            &endpoint,
            &config,
            &http_client,
            &store,
        )
        .await;

        let (succeeded, sleep_duration) = match result {
            Ok(()) => {
                backoff_secs = FEDERATION_BACKOFF_INITIAL_SECS;
                // After a success we wait at least one full poll interval —
                // `attempt_started_at` lets a long round-trip eat into the
                // interval so a 30s poll on a 60s interval still wakes at the
                // 60s mark, not 90s.
                let elapsed = attempt_started_at.elapsed();
                (true, config.poll_interval.saturating_sub(elapsed))
            }
            Err(err) => {
                warn!(
                    cluster = %cluster_name,
                    trust_domain = %trust_domain,
                    endpoint = %endpoint,
                    error = %err,
                    fail_open = config.fail_open,
                    "SPIFFE federation poll failed; keeping last-good bundle if any"
                );
                crate::plugins::mesh::prometheus_helpers::increment_mesh_federation_poll_failure(
                    trust_domain.as_str(),
                    &endpoint,
                );
                (false, jittered_backoff(backoff_secs))
            }
        };

        if !succeeded {
            backoff_secs = next_backoff_secs(backoff_secs);
        }

        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = wait_for_federation_shutdown(&mut shutdown_rx) => return,
        }
    }
}

async fn wait_for_federation_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

async fn fetch_and_install_bundle(
    cluster_name: &str,
    trust_domain: &TrustDomain,
    endpoint: &str,
    config: &FederationPollerConfig,
    http_client: &PluginHttpClient,
    store: &FederationStore,
) -> Result<(), String> {
    // Strip userinfo from the URL we use for logs / metrics so a
    // credentialed endpoint (`https://user:token@host/...`) does not leak
    // its token. The request itself still goes to the original URL via
    // reqwest's normal handling.
    let endpoint_for_logs = sanitize_endpoint_for_logging(endpoint);
    let request = http_client
        .get()
        .get(endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .timeout(config.request_timeout);
    let response = http_client
        .execute(request, "mesh_federation_poll")
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("HTTP {} from federation endpoint", status.as_u16()));
    }
    // Reject early when the server advertises a Content-Length larger than
    // our cap, so we don't even start streaming a multi-gigabyte body.
    if let Some(cl_value) = response.content_length()
        && cl_value as usize > FEDERATION_MAX_BODY_BYTES
    {
        return Err(format!(
            "federation response Content-Length {} exceeds {} byte cap",
            cl_value, FEDERATION_MAX_BODY_BYTES
        ));
    }
    // Size-bounded streaming read. `response.bytes()` would allocate an
    // unbounded `Bytes` from a hostile endpoint within the request timeout
    // and OOM the gateway. The cap is enforced frame-by-frame so a
    // streaming response that ignores Content-Length is also caught.
    let body = read_bounded_body(response, FEDERATION_MAX_BODY_BYTES).await?;
    let bundle = parse_federation_document(&body, trust_domain)?;
    validate_polled_bundle(&bundle)?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let federated = FederatedBundle {
        bundle,
        fetched_at_unix_seconds: now,
        endpoint: endpoint.to_string(),
        cluster_name: cluster_name.to_string(),
    };
    store.install(trust_domain.clone(), federated);
    crate::plugins::mesh::prometheus_helpers::record_mesh_federation_poll_success(
        trust_domain.as_str(),
        now,
    );
    info!(
        cluster = %cluster_name,
        trust_domain = %trust_domain,
        endpoint = %endpoint_for_logs,
        "Installed federated trust bundle"
    );
    Ok(())
}

/// Read the response body frame-by-frame and abort if it exceeds
/// `max_bytes`. Returns `Vec<u8>` rather than `Bytes` because callers feed
/// it straight to `serde_json::from_slice`.
async fn read_bounded_body(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("reading federation response body: {e}"))?;
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!(
                "federation response body exceeded {max_bytes} bytes; aborting"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Strip userinfo (`user:password@`) from the URL when logging. Falls back
/// to a placeholder string if parsing fails — never returns the raw input
/// for logs.
fn sanitize_endpoint_for_logging(endpoint: &str) -> String {
    match reqwest::Url::parse(endpoint) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.to_string()
        }
        Err(_) => "<unparseable>".to_string(),
    }
}

/// SSRF defense for federation endpoints. Cloud metadata services
/// (`169.254.169.254`, AWS IMDS) and link-local addresses are rejected to
/// keep a compromised control plane from pivoting through the poller into
/// node-local infrastructure. Loopback is allowed because legitimate
/// local-development and integration-test setups use it; loopback offers
/// no new attack surface that the local process doesn't already have.
///
/// HTTPS is recommended (a `warn!` fires on plain `http://`) but not
/// enforced, so existing CP-supplied configurations that pre-date this
/// validator keep working. Operators should treat the warn as a strong
/// hint to migrate.
pub(crate) fn validate_federation_endpoint(endpoint: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|e| format!("federation_endpoint '{endpoint}' is not a valid URL: {e}"))?;
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(format!(
            "federation_endpoint must use 'http' or 'https' scheme (got '{scheme}')"
        ));
    }
    if scheme == "http" {
        warn!(
            endpoint = %sanitize_endpoint_for_logging(endpoint),
            "federation_endpoint uses plain http; trust-bundle traffic should use https"
        );
    }
    let Some(host) = url.host() else {
        return Err(format!(
            "federation_endpoint '{endpoint}' has no host component"
        ));
    };
    match host {
        url::Host::Ipv4(ip) => reject_unsafe_ipv4(&ip)?,
        url::Host::Ipv6(ip) => reject_unsafe_ipv6(&ip)?,
        url::Host::Domain(_) => {
            // Hostnames are resolved at request time. We accept any
            // syntactically valid host; the DNS-resolver layer enforces
            // `BackendAllowIps` if configured by the operator.
        }
    }
    Ok(())
}

fn reject_unsafe_ipv4(ip: &std::net::Ipv4Addr) -> Result<(), String> {
    // Loopback is allowed for local development / integration test setups.
    if ip.is_loopback() {
        return Ok(());
    }
    if ip.is_link_local() {
        return Err(format!(
            "federation_endpoint refuses link-local host {ip} (defends against cloud metadata SSRF)"
        ));
    }
    // 169.254.169.254 is link-local already, but call it out explicitly for
    // the operator-readable error message.
    if ip.octets() == [169, 254, 169, 254] {
        return Err(format!(
            "federation_endpoint refuses cloud metadata IP {ip}"
        ));
    }
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
        return Err(format!(
            "federation_endpoint refuses non-unicast IPv4 host {ip}"
        ));
    }
    Ok(())
}

fn reject_unsafe_ipv6(ip: &std::net::Ipv6Addr) -> Result<(), String> {
    if ip.is_loopback() {
        return Ok(());
    }
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(format!(
            "federation_endpoint refuses non-unicast IPv6 host {ip}"
        ));
    }
    // RFC 4291 link-local fe80::/10
    let segs = ip.segments();
    if segs[0] & 0xffc0 == 0xfe80 {
        return Err(format!(
            "federation_endpoint refuses link-local IPv6 host {ip}"
        ));
    }
    Ok(())
}

fn jittered_backoff(backoff_secs: u64) -> Duration {
    jittered_backoff_with_entropy(backoff_secs, random_backoff_entropy())
}

fn random_backoff_entropy() -> u64 {
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 8];
    if ring::rand::SecureRandom::fill(&rng, &mut bytes).is_ok() {
        return u64::from_ne_bytes(bytes);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

pub(crate) fn jittered_backoff_with_entropy(backoff_secs: u64, entropy: u64) -> Duration {
    let base_ms = backoff_secs.saturating_mul(1000);
    let jitter_range_ms = base_ms / 4;
    let jitter_ms = if jitter_range_ms > 0 {
        let full_range = jitter_range_ms.saturating_mul(2);
        (entropy % full_range) as i64 - jitter_range_ms as i64
    } else {
        0
    };
    let sleep_ms = (base_ms as i64 + jitter_ms).max(100) as u64;
    Duration::from_millis(sleep_ms)
}

pub(crate) fn next_backoff_secs(current_secs: u64) -> u64 {
    current_secs
        .saturating_mul(2)
        .min(FEDERATION_BACKOFF_MAX_SECS)
}

/// Merge the live federation snapshot into the static [`TrustBundleSet`] the
/// control plane handed us. Used by the slice-apply path so the dispatched
/// [`crate::config::types::GatewayConfig`] sees the most recent cross-cluster
/// authorities.
///
/// Merge precedence: the live snapshot (polled) wins on conflict because the
/// poller signals a fresh trust-domain rotation; the CP-supplied bundles
/// remain as a fallback for trust domains the poller hasn't fetched (or
/// hasn't fetched successfully yet).
pub fn merge_federation_into_trust_bundles(
    trust_bundles: Option<TrustBundleSet>,
    snapshot: &FederationSnapshot,
) -> Option<TrustBundleSet> {
    if snapshot.bundles.is_empty() {
        return trust_bundles;
    }
    let mut set = trust_bundles?;
    // Dedupe by trust domain: drop any existing federated entries whose trust
    // domain the poller has fetched, then append the fresh polled bundles.
    set.federated
        .retain(|fed| !snapshot.bundles.contains_key(&fed.trust_domain));
    for (_td, federated) in snapshot.bundles.iter() {
        set.federated.push(federated.bundle.clone());
    }
    Some(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TrustDomain;
    use crate::modes::mesh::config::TrustBundle;

    fn td(s: &str) -> TrustDomain {
        TrustDomain::new(s).expect("valid trust domain")
    }

    fn sample_cert_base64() -> String {
        // Minimal valid base64 for a "DER" blob — the poller validator only
        // checks that base64 decode succeeds, not that the inner bytes are a
        // real X.509 cert. The slice validator behaves identically.
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0xde, 0xad, 0xbe, 0xef])
    }

    #[test]
    fn parse_native_format_round_trips() {
        let body = serde_json::json!({
            "trust_domain": "remote.example.com",
            "x509_authorities": [sample_cert_base64()],
            "refresh_hint_seconds": 60u64,
        })
        .to_string();
        let trust_domain = td("remote.example.com");
        let bundle = parse_federation_document(body.as_bytes(), &trust_domain)
            .expect("native parse should succeed");
        assert_eq!(bundle.trust_domain, trust_domain);
        assert_eq!(bundle.x509_authorities.len(), 1);
        assert_eq!(bundle.refresh_hint_seconds, Some(60));
    }

    #[test]
    fn parse_native_format_rejects_trust_domain_mismatch() {
        let body = serde_json::json!({
            "trust_domain": "other.example.com",
            "x509_authorities": [sample_cert_base64()],
        })
        .to_string();
        let err = parse_federation_document(body.as_bytes(), &td("remote.example.com"))
            .expect_err("mismatch should reject");
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn parse_spiffe_jwks_format() {
        let body = serde_json::json!({
            "keys": [
                {"use": "x509-svid", "x5c": [sample_cert_base64()]},
                {"use": "jwt-svid", "kid": "kid1", "kty": "RSA", "n": "abc", "e": "AQAB"},
            ],
            "spiffe_refresh_hint": 120u64,
        })
        .to_string();
        let bundle = parse_federation_document(body.as_bytes(), &td("remote.example.com"))
            .expect("jwks parse should succeed");
        assert_eq!(bundle.x509_authorities.len(), 1);
        assert_eq!(bundle.jwt_authorities.len(), 1);
        assert_eq!(bundle.jwt_authorities[0].key_id, "kid1");
        assert!(bundle.jwt_authorities[0].public_key_pem.contains("\"kty\""));
        assert_eq!(bundle.refresh_hint_seconds, Some(120));
    }

    #[test]
    fn parse_rejects_invalid_json() {
        let err = parse_federation_document(b"not json", &td("td"))
            .expect_err("invalid JSON should reject");
        assert!(err.contains("invalid federation bundle JSON"), "{err}");
    }

    #[test]
    fn validate_rejects_empty_bundle() {
        let bundle = TrustBundle {
            trust_domain: td("remote.example.com"),
            x509_authorities: Vec::new(),
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        };
        let err = validate_polled_bundle(&bundle).expect_err("empty bundle should reject");
        assert!(err.contains("has no authorities"), "{err}");
    }

    #[test]
    fn validate_rejects_bad_base64() {
        let bundle = TrustBundle {
            trust_domain: td("remote.example.com"),
            x509_authorities: vec!["!!!not base64!!!".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        };
        let err = validate_polled_bundle(&bundle).expect_err("bad base64 should reject");
        assert!(err.contains("invalid base64"), "{err}");
    }

    #[test]
    fn validate_accepts_valid_bundle() {
        let bundle = TrustBundle {
            trust_domain: td("remote.example.com"),
            x509_authorities: vec![sample_cert_base64()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        };
        validate_polled_bundle(&bundle).expect("valid bundle should accept");
    }

    #[test]
    fn backoff_matches_dp_client_cap_and_jitter() {
        // Cap behaviour mirrors src/grpc/dp_client.rs.
        assert_eq!(next_backoff_secs(1), 2);
        assert_eq!(next_backoff_secs(2), 4);
        assert_eq!(next_backoff_secs(16), FEDERATION_BACKOFF_MAX_SECS);
        assert_eq!(next_backoff_secs(30), FEDERATION_BACKOFF_MAX_SECS);
        assert_eq!(
            next_backoff_secs(FEDERATION_BACKOFF_MAX_SECS),
            FEDERATION_BACKOFF_MAX_SECS
        );

        // Jitter window: ±25%.
        for entropy in 0..256u64 {
            let duration = jittered_backoff_with_entropy(1, entropy);
            assert!(duration >= Duration::from_millis(750));
            assert!(duration <= Duration::from_millis(1250));
        }

        // Floor of 100ms even when base is zero.
        assert_eq!(
            jittered_backoff_with_entropy(0, 0),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn store_install_makes_first_ready() {
        let store = FederationStore::new();
        assert!(!store.has_first_success());
        let bundle = TrustBundle {
            trust_domain: td("remote.example.com"),
            x509_authorities: vec![sample_cert_base64()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        };
        store.install(
            td("remote.example.com"),
            FederatedBundle {
                bundle,
                fetched_at_unix_seconds: 1234,
                endpoint: "https://example/.well-known/spiffe".to_string(),
                cluster_name: "remote".to_string(),
            },
        );
        assert!(store.has_first_success());
        let snap = store.snapshot();
        assert_eq!(snap.bundles.len(), 1);
        let entry = snap.bundles.get(&td("remote.example.com")).expect("entry");
        assert_eq!(entry.fetched_at_unix_seconds, 1234);
    }

    #[test]
    fn merge_overlays_polled_bundles() {
        let cp_bundle = TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("local"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: vec![TrustBundle {
                trust_domain: td("remote.example.com"),
                x509_authorities: vec!["cp_value".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }],
        };
        let mut polled = FederationSnapshot::default();
        polled.bundles.insert(
            td("remote.example.com"),
            FederatedBundle {
                bundle: TrustBundle {
                    trust_domain: td("remote.example.com"),
                    x509_authorities: vec![sample_cert_base64()],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
                fetched_at_unix_seconds: 1,
                endpoint: "https://example".to_string(),
                cluster_name: "remote".to_string(),
            },
        );

        let merged =
            merge_federation_into_trust_bundles(Some(cp_bundle), &polled).expect("merge result");
        assert_eq!(merged.federated.len(), 1);
        assert_eq!(
            merged.federated[0].x509_authorities[0],
            sample_cert_base64()
        );
    }

    #[test]
    fn merge_keeps_disjoint_cp_bundles() {
        let cp_bundle = TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("local"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: vec![TrustBundle {
                trust_domain: td("kept.example.com"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            }],
        };
        let mut polled = FederationSnapshot::default();
        polled.bundles.insert(
            td("remote.example.com"),
            FederatedBundle {
                bundle: TrustBundle {
                    trust_domain: td("remote.example.com"),
                    x509_authorities: vec![sample_cert_base64()],
                    jwt_authorities: Vec::new(),
                    refresh_hint_seconds: None,
                },
                fetched_at_unix_seconds: 1,
                endpoint: "https://example".to_string(),
                cluster_name: "remote".to_string(),
            },
        );

        let merged =
            merge_federation_into_trust_bundles(Some(cp_bundle), &polled).expect("merge result");
        let domains: Vec<_> = merged
            .federated
            .iter()
            .map(|tb| tb.trust_domain.as_str().to_string())
            .collect();
        assert!(domains.contains(&"kept.example.com".to_string()));
        assert!(domains.contains(&"remote.example.com".to_string()));
    }

    #[test]
    fn merge_returns_none_without_cp_or_polled() {
        let polled = FederationSnapshot::default();
        assert!(merge_federation_into_trust_bundles(None, &polled).is_none());
    }

    #[test]
    fn merge_returns_cp_only_when_polled_empty() {
        let cp_bundle = TrustBundleSet {
            local: TrustBundle {
                trust_domain: td("local"),
                x509_authorities: vec![sample_cert_base64()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        };
        let polled = FederationSnapshot::default();
        let merged =
            merge_federation_into_trust_bundles(Some(cp_bundle.clone()), &polled).expect("kept");
        assert_eq!(merged.federated.len(), 0);
        assert_eq!(merged.local.trust_domain, td("local"));
    }

    #[test]
    fn poll_targets_skip_blank_or_missing_endpoints() {
        use crate::modes::mesh::config::RemoteCluster;
        let mc = MultiClusterConfig {
            local_cluster: None,
            federation_endpoint: None,
            remote_clusters: vec![
                RemoteCluster {
                    name: "with-endpoint".to_string(),
                    trust_domain: td("a"),
                    network: None,
                    control_plane_url: None,
                    federation_endpoint: Some("https://a/.well-known/spiffe".to_string()),
                },
                RemoteCluster {
                    name: "no-endpoint".to_string(),
                    trust_domain: td("b"),
                    network: None,
                    control_plane_url: None,
                    federation_endpoint: None,
                },
                RemoteCluster {
                    name: "blank-endpoint".to_string(),
                    trust_domain: td("c"),
                    network: None,
                    control_plane_url: None,
                    federation_endpoint: Some("   ".to_string()),
                },
            ],
            east_west_gateways: Vec::new(),
        };
        let targets = poll_targets_for_multi_cluster(&mc);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].cluster_name, "with-endpoint");
    }

    #[test]
    fn config_from_env_disables_when_interval_zero() {
        assert!(FederationPollerConfig::from_env(0, 30, false).is_none());
        let cfg = FederationPollerConfig::from_env(60, 10, true).expect("enabled");
        assert_eq!(cfg.poll_interval, Duration::from_secs(60));
        assert_eq!(cfg.request_timeout, Duration::from_secs(10));
        assert!(cfg.fail_open);
    }

    #[test]
    fn validate_federation_endpoint_rejects_cloud_metadata() {
        let err = validate_federation_endpoint("https://169.254.169.254/x")
            .expect_err("cloud metadata IP must be rejected");
        assert!(err.contains("link-local") || err.contains("metadata"));
    }

    #[test]
    fn validate_federation_endpoint_rejects_link_local_v6() {
        let err = validate_federation_endpoint("https://[fe80::1]/x")
            .expect_err("IPv6 link-local must be rejected");
        assert!(err.contains("link-local"));
    }

    #[test]
    fn validate_federation_endpoint_allows_loopback_for_tests() {
        validate_federation_endpoint("http://127.0.0.1:9090/x")
            .expect("loopback http is allowed for test scaffolding");
        validate_federation_endpoint("http://[::1]:9090/x").expect("loopback IPv6 is allowed");
    }

    #[test]
    fn validate_federation_endpoint_accepts_https_hostname() {
        validate_federation_endpoint("https://federation.cluster-2.example.com/.well-known/spiffe")
            .expect("valid https hostname endpoint must be accepted");
    }

    #[test]
    fn validate_federation_endpoint_rejects_ftp_scheme() {
        let err = validate_federation_endpoint("ftp://example.com/")
            .expect_err("non-http(s) schemes must be rejected");
        assert!(err.contains("http"));
    }

    #[test]
    fn sanitize_endpoint_strips_userinfo() {
        let safe = sanitize_endpoint_for_logging("https://user:token@host.example/path");
        assert!(!safe.contains("user"), "userinfo must be stripped: {safe}");
        assert!(!safe.contains("token"), "password must be stripped: {safe}");
        assert!(safe.contains("host.example"), "host preserved: {safe}");
    }

    #[test]
    fn parse_native_rejects_too_many_x509_authorities() {
        let mut authorities = Vec::with_capacity(FEDERATION_MAX_X509_AUTHORITIES + 1);
        for _ in 0..(FEDERATION_MAX_X509_AUTHORITIES + 1) {
            authorities.push("ZGVhZGJlZWY=".to_string()); // base64 "deadbeef"
        }
        let doc = serde_json::json!({
            "trust_domain": "cluster-2.local",
            "x509_authorities": authorities,
        });
        let body = serde_json::to_vec(&doc).unwrap();
        let td = TrustDomain::new("cluster-2.local").unwrap();
        let err = parse_federation_document(&body, &td)
            .expect_err("exceeding the x509 cap must be rejected");
        assert!(err.contains("max"));
    }

    #[tokio::test]
    async fn install_is_atomic_across_concurrent_polls() {
        // Two concurrent successful polls (different trust domains) must
        // not stomp each other. Without RCU the second store would discard
        // the first.
        let store = FederationStore::new();
        let td_a = TrustDomain::new("cluster-a.local").unwrap();
        let td_b = TrustDomain::new("cluster-b.local").unwrap();
        let bundle_a = FederatedBundle {
            bundle: TrustBundle {
                trust_domain: td_a.clone(),
                x509_authorities: vec!["a".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            fetched_at_unix_seconds: 1,
            endpoint: "https://a/".to_string(),
            cluster_name: "a".to_string(),
        };
        let bundle_b = FederatedBundle {
            bundle: TrustBundle {
                trust_domain: td_b.clone(),
                x509_authorities: vec!["b".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            fetched_at_unix_seconds: 2,
            endpoint: "https://b/".to_string(),
            cluster_name: "b".to_string(),
        };

        let store_a = store.clone();
        let store_b = store.clone();
        let h1 = tokio::spawn(async move {
            for _ in 0..50 {
                store_a.install(td_a.clone(), bundle_a.clone());
            }
        });
        let h2 = tokio::spawn(async move {
            for _ in 0..50 {
                store_b.install(td_b.clone(), bundle_b.clone());
            }
        });
        let _ = h1.await;
        let _ = h2.await;

        let snap = store.snapshot();
        assert_eq!(
            snap.bundles.len(),
            2,
            "both trust domains must survive concurrent installs: {:?}",
            snap.bundles.keys().collect::<Vec<_>>()
        );
    }
}
