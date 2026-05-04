//! Data Plane gRPC client — subscribes to the CP's config stream.
//!
//! The outer reconnect loop (`start_dp_client_with_shutdown`) uses exponential
//! backoff with jitter (1s → 2s → 4s → … → 30s cap, ±25% jitter) to avoid
//! thundering-herd reconnection storms when many DPs restart simultaneously.
//! Inside the stream handler, two message types:
//! - `update_type=0` (FULL_SNAPSHOT): replaces the entire `GatewayConfig`
//! - `update_type=1` (DELTA): applies incremental changes via `apply_incremental()`
//!
//! Multi-CP failover: `cp_urls` is a priority-ordered list. The DP connects to
//! the first (primary) URL and fails over to subsequent URLs when unreachable.
//! When connected to a fallback CP and `primary_retry_secs > 0`, the DP
//! periodically disconnects from the fallback to retry the primary.
//!
//! SNI is extracted from the CP URL so TLS certificate validation works
//! correctly even when connecting via IP address with a hostname-based cert.
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tonic::metadata::MetadataValue;
use tonic::transport::channel::ClientTlsConfig;
use tonic::transport::{Certificate, Channel, Identity};
use tracing::{error, info, warn};

use super::proto::SubscribeRequest;
use super::proto::config_sync_client::ConfigSyncClient;
use crate::FERRUM_VERSION;
use crate::config::db_loader::IncrementalResult;
use crate::config::types::GatewayConfig;
use crate::proxy::ProxyState;

/// Tracks the DP's connection status to its Control Plane.
/// Shared between the DP gRPC client and the admin API (`GET /cluster`).
#[derive(Clone, Serialize)]
pub struct DpCpConnectionState {
    /// Whether the gRPC stream to a CP is currently active.
    pub connected: bool,
    /// URL of the CP this DP is currently connected to (or last attempted).
    pub cp_url: String,
    /// Whether the current CP is the primary (index 0) or a fallback.
    pub is_primary: bool,
    /// Timestamp of the last config update received from CP.
    pub last_config_received_at: Option<DateTime<Utc>>,
    /// When the current connection was established (None if disconnected).
    pub connected_since: Option<DateTime<Utc>>,
}

impl DpCpConnectionState {
    pub fn new_disconnected(cp_url: &str) -> Self {
        Self {
            connected: false,
            cp_url: cp_url.to_string(),
            is_primary: true,
            last_config_received_at: None,
            connected_since: None,
        }
    }
}

/// Newtype for the shared CP/DP gRPC JWT secret (`FERRUM_CP_DP_GRPC_JWT_SECRET`).
///
/// This wrapper exists so the compiler catches callers who accidentally pass a
/// pre-signed JWT token where a shared secret is now expected. Before this change
/// both were `String`, so the old code compiled silently with the wrong value.
///
/// The wrapper also carries the expected `iss` claim
/// (`FERRUM_CP_DP_GRPC_JWT_ISSUER`) since the secret and issuer always travel
/// together: every token minted with this secret needs to bear the configured
/// issuer or the CP will reject it.
#[derive(Clone, Debug)]
pub struct GrpcJwtSecret {
    secret: String,
    issuer: String,
}

impl GrpcJwtSecret {
    /// Create a `GrpcJwtSecret` with the default issuer
    /// (`crate::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER`).
    ///
    /// Used by tests and library callers; production binary code path uses
    /// [`GrpcJwtSecret::with_issuer`] so the operator-configured
    /// `FERRUM_CP_DP_GRPC_JWT_ISSUER` is honored.
    #[allow(dead_code)]
    pub fn new(secret: String) -> Self {
        Self::with_issuer(
            secret,
            crate::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER.to_string(),
        )
    }

    /// Create a `GrpcJwtSecret` with an operator-configured issuer.
    pub fn with_issuer(secret: String, issuer: String) -> Self {
        Self { secret, issuer }
    }

    pub fn as_str(&self) -> &str {
        &self.secret
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// TLS configuration for the DP gRPC client.
#[derive(Clone, Default)]
pub struct DpGrpcTlsConfig {
    /// CA certificate PEM bytes for verifying CP server cert.
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Client certificate PEM bytes for mTLS.
    pub client_cert_pem: Option<Vec<u8>>,
    /// Client private key PEM bytes for mTLS.
    pub client_key_pem: Option<Vec<u8>>,
    /// Skip server certificate verification (testing only).
    /// When true and no `ca_cert_pem` is set, the client accepts any server cert.
    #[allow(dead_code)]
    pub no_verify: bool,
}

/// JWT token lifetime for DP-generated tokens (59 minutes, under the 1-hour ceiling).
const DP_JWT_TTL_SECONDS: i64 = 3540;

/// Generate a short-lived HS256 JWT for authenticating the DP to the CP using
/// the default issuer (`DEFAULT_CP_DP_JWT_ISSUER`).
///
/// Most production callers should prefer [`generate_dp_jwt_with_issuer`] so
/// the operator-configured `FERRUM_CP_DP_GRPC_JWT_ISSUER` is honored. This
/// helper is kept for tests and library callers that want the default behavior
/// without threading the issuer through.
#[allow(dead_code)]
pub fn generate_dp_jwt(secret: &str, node_id: &str) -> Result<String, anyhow::Error> {
    generate_dp_jwt_with_issuer(
        secret,
        node_id,
        crate::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER,
    )
}

/// Generate a short-lived HS256 JWT for authenticating the DP to the CP.
///
/// The token is signed with the shared `FERRUM_CP_DP_GRPC_JWT_SECRET` and
/// includes `sub`, `iat`, `exp`, `iss`, and `role` claims. The `iss` claim
/// is set to `issuer` (operator-configured via `FERRUM_CP_DP_GRPC_JWT_ISSUER`,
/// default `"ferrum-edge-cp-dp"`) and MUST match the value the CP expects —
/// the CP rejects any token with a different `iss`. A fresh token is minted
/// on each gRPC connection attempt so that tokens captured from the wire
/// are only valid for ~59 minutes.
pub fn generate_dp_jwt_with_issuer(
    secret: &str,
    node_id: &str,
    issuer: &str,
) -> Result<String, anyhow::Error> {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "sub": node_id,
        "iat": now,
        "exp": now + DP_JWT_TTL_SECONDS,
        "iss": issuer,
        "role": "data_plane",
    });
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

/// Connect to the Control Plane with an optional shutdown signal.
///
/// Accepts a single CP URL for backward compatibility. For multi-CP failover,
/// use [`start_dp_client_with_shutdown_and_startup_ready`] with a `Vec`.
#[allow(dead_code)] // Used by tests and library callers; binary startup uses the startup-aware variant.
pub async fn start_dp_client_with_shutdown(
    cp_url: String,
    jwt_secret: GrpcJwtSecret,
    proxy_state: ProxyState,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    tls_config: Option<DpGrpcTlsConfig>,
    namespace: String,
) {
    start_dp_client_with_shutdown_and_startup_ready(
        vec![cp_url],
        jwt_secret,
        proxy_state,
        shutdown_rx,
        tls_config,
        None,
        namespace,
        0,
        None,
    )
    .await;
}

/// Connect to Control Plane(s) with multi-CP failover and optional startup readiness.
///
/// `cp_urls` is a priority-ordered list of CP gRPC URLs. The DP connects to the
/// first (primary) URL and fails over to subsequent URLs when unreachable. When
/// connected to a fallback CP and `primary_retry_secs > 0`, the DP periodically
/// disconnects from the fallback and retries the primary CP.
#[allow(clippy::too_many_arguments)]
pub async fn start_dp_client_with_shutdown_and_startup_ready(
    cp_urls: Vec<String>,
    jwt_secret: GrpcJwtSecret,
    proxy_state: ProxyState,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    tls_config: Option<DpGrpcTlsConfig>,
    startup_ready: Option<Arc<AtomicBool>>,
    namespace: String,
    primary_retry_secs: u64,
    connection_state: Option<Arc<ArcSwap<DpCpConnectionState>>>,
) {
    if cp_urls.is_empty() {
        error!("No CP URLs configured — cannot start DP client");
        return;
    }

    let node_id = uuid::Uuid::new_v4().to_string();
    let cp_count = cp_urls.len();

    if cp_count > 1 {
        info!(
            "DP client starting with {} CP URLs (failover enabled): {}",
            cp_count,
            cp_urls
                .iter()
                .enumerate()
                .map(|(i, u)| if i == 0 {
                    format!("{} (primary)", u)
                } else {
                    u.to_string()
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else {
        info!(
            "DP client starting, connecting to CP at {}",
            cp_urls.first().map(|s| s.as_str()).unwrap_or("(none)")
        );
    }

    const BACKOFF_INITIAL_SECS: u64 = 1;
    const BACKOFF_MAX_SECS: u64 = 30;
    let mut current_cp_index: usize = 0;
    let mut backoff_secs = BACKOFF_INITIAL_SECS;
    let mut full_cycle_count: u32 = 0;

    loop {
        if let Some(ref rx) = shutdown_rx
            && *rx.borrow()
        {
            info!("DP client shutting down");
            return;
        }

        let cp_url = &cp_urls[current_cp_index];
        let is_primary = current_cp_index == 0;
        let is_fallback = !is_primary && cp_count > 1;

        if is_fallback {
            info!(
                "Connecting to fallback CP [{}/{}] at {}",
                current_cp_index + 1,
                cp_count,
                cp_url
            );
        } else if cp_count > 1 {
            info!("Connecting to primary CP at {}", cp_url);
        }

        // When connected to a fallback CP and primary_retry_secs > 0,
        // race the stream against a timer to periodically retry the primary.
        // The timer is only armed after startup readiness (initial snapshot applied)
        // to avoid disconnecting from the fallback before the DP has any config.
        //
        // Known limitation: should_race_primary is evaluated once per connection
        // attempt, not continuously. If startup_ready flips from false to true
        // while the fallback stream is running (first snapshot applied mid-stream),
        // the primary-retry timer is NOT armed until the fallback stream ends
        // (disconnect or error). This is acceptable: the fallback is actively
        // serving valid config, and the primary will be retried on the next
        // reconnect cycle when the outer loop re-evaluates.
        //
        // Acquire pairs with the Release store in connect_and_subscribe_with_startup_ready
        // (and the admin /health endpoint reads with Acquire too). On x86 all loads are
        // acquire-fenced by the hardware, but on ARM/AArch64 Relaxed could theoretically
        // delay visibility of the store, so we use Acquire/Release consistently.
        let should_race_primary = is_fallback
            && primary_retry_secs > 0
            && startup_ready
                .as_ref()
                .is_none_or(|r| r.load(Ordering::Acquire));
        let result = if should_race_primary {
            tokio::select! {
                res = connect_and_subscribe_with_startup_ready(
                    cp_url,
                    &jwt_secret,
                    &node_id,
                    &proxy_state,
                    tls_config.as_ref(),
                    startup_ready.clone(),
                    &namespace,
                    connection_state.as_ref(),
                    is_primary,
                ) => res,
                _ = tokio::time::sleep(Duration::from_secs(primary_retry_secs)) => {
                    info!(
                        "Primary CP retry interval ({}s) elapsed; disconnecting from \
                         fallback CP [{}/{}] to retry primary",
                        primary_retry_secs,
                        current_cp_index + 1,
                        cp_count,
                    );
                    // Mark disconnected before switching — record fallback CP as last attempted
                    update_state_disconnected(&connection_state, cp_url, is_primary);
                    current_cp_index = 0;
                    backoff_secs = BACKOFF_INITIAL_SECS;
                    continue;
                }
            }
        } else {
            connect_and_subscribe_with_startup_ready(
                cp_url,
                &jwt_secret,
                &node_id,
                &proxy_state,
                tls_config.as_ref(),
                startup_ready.clone(),
                &namespace,
                connection_state.as_ref(),
                is_primary,
            )
            .await
        };

        match result {
            Ok(_) => {
                warn!(
                    "CP [{}/{}] connection stream ended ({}), will reconnect...",
                    current_cp_index + 1,
                    cp_count,
                    cp_url
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);
                // On clean disconnect, try primary first if we were on a fallback
                if is_fallback {
                    info!("Stream ended on fallback CP; will retry primary CP first");
                    current_cp_index = 0;
                }
                backoff_secs = BACKOFF_INITIAL_SECS;
            }
            Err(e) => {
                error!(
                    "CP [{}/{}] connection error ({}): {}",
                    current_cp_index + 1,
                    cp_count,
                    cp_url,
                    e
                );
                update_state_disconnected(&connection_state, cp_url, is_primary);

                if cp_count > 1 {
                    let next_index = (current_cp_index + 1) % cp_count;
                    if next_index == 0 {
                        full_cycle_count += 1;
                        warn!(
                            "All {} CP URLs exhausted (cycle {}), restarting from primary",
                            cp_count, full_cycle_count
                        );
                        // Keep accumulated backoff when cycling back
                    } else {
                        // Fresh start on next CP
                        backoff_secs = BACKOFF_INITIAL_SECS;
                    }
                    current_cp_index = next_index;
                }
            }
        }

        // Apply ±25% jitter to the backoff to desynchronize reconnection attempts.
        let base_ms = backoff_secs * 1000;
        let jitter_range_ms = base_ms / 4;
        let jitter_ms = if jitter_range_ms > 0 {
            let full_range = jitter_range_ms * 2;
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64;
            (nanos % full_range) as i64 - jitter_range_ms as i64
        } else {
            0
        };
        let sleep_ms = base_ms as i64 + jitter_ms;
        let sleep_duration = Duration::from_millis(sleep_ms.max(100) as u64);

        if let Some(ref rx) = shutdown_rx {
            let mut rx_clone = rx.clone();
            tokio::select! {
                _ = tokio::time::sleep(sleep_duration) => {}
                _ = async {
                    while !*rx_clone.borrow() {
                        if rx_clone.changed().await.is_err() { return; }
                    }
                } => {
                    info!("DP client shutting down");
                    return;
                }
            }
        } else {
            tokio::time::sleep(sleep_duration).await;
        }

        backoff_secs = (backoff_secs * 2).min(BACKOFF_MAX_SECS);
    }
}

/// Helper: mark connection state as disconnected with the last attempted CP target.
fn update_state_disconnected(
    connection_state: &Option<Arc<ArcSwap<DpCpConnectionState>>>,
    cp_url: &str,
    is_primary: bool,
) {
    if let Some(cs) = connection_state {
        let prev = cs.load();
        cs.store(Arc::new(DpCpConnectionState {
            connected: false,
            cp_url: cp_url.to_string(),
            is_primary,
            last_config_received_at: prev.last_config_received_at,
            connected_since: None,
        }));
    }
}

/// Helper: update last_config_received_at timestamp on successful config application.
fn update_state_config_received(connection_state: Option<&Arc<ArcSwap<DpCpConnectionState>>>) {
    if let Some(cs) = connection_state {
        let prev = cs.load();
        cs.store(Arc::new(DpCpConnectionState {
            connected: true,
            cp_url: prev.cp_url.clone(),
            is_primary: prev.is_primary,
            last_config_received_at: Some(Utc::now()),
            connected_since: prev.connected_since,
        }));
    }
}

#[allow(dead_code)] // Used by tests and library callers; binary startup uses the startup-aware variant.
pub async fn connect_and_subscribe(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    node_id: &str,
    proxy_state: &ProxyState,
    tls_config: Option<&DpGrpcTlsConfig>,
    namespace: &str,
) -> Result<(), anyhow::Error> {
    connect_and_subscribe_with_startup_ready(
        cp_url,
        jwt_secret,
        node_id,
        proxy_state,
        tls_config,
        None,
        namespace,
        None,
        true,
    )
    .await
}

/// Connect to CP and optionally flip startup readiness after the first applied snapshot.
#[allow(clippy::too_many_arguments)]
pub async fn connect_and_subscribe_with_startup_ready(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    node_id: &str,
    proxy_state: &ProxyState,
    tls_config: Option<&DpGrpcTlsConfig>,
    startup_ready: Option<Arc<AtomicBool>>,
    namespace: &str,
    connection_state: Option<&Arc<ArcSwap<DpCpConnectionState>>>,
    is_primary: bool,
) -> Result<(), anyhow::Error> {
    let mut endpoint =
        Channel::from_shared(cp_url.to_string())?.connect_timeout(Duration::from_secs(10));

    // Apply TLS configuration if the URL uses https:// or TLS config is provided
    if let Some(tls) = tls_config {
        let mut client_tls = ClientTlsConfig::new();

        if let Some(ref ca_pem) = tls.ca_cert_pem {
            client_tls = client_tls.ca_certificate(Certificate::from_pem(ca_pem));
        }

        if let (Some(cert_pem), Some(key_pem)) = (&tls.client_cert_pem, &tls.client_key_pem) {
            client_tls = client_tls.identity(Identity::from_pem(cert_pem, key_pem));
        }

        // Extract domain from URL for TLS SNI
        if let Ok(uri) = cp_url.parse::<http::Uri>()
            && let Some(host) = uri.host()
        {
            client_tls = client_tls.domain_name(host);
        }

        endpoint = endpoint.tls_config(client_tls)?;
    }

    let channel = endpoint.connect().await?;

    // Mint a fresh short-lived JWT for this connection attempt. The `iss`
    // claim is set from the operator-configured issuer carried alongside
    // the shared secret; the CP rejects any token with a mismatched `iss`.
    let auth_token =
        generate_dp_jwt_with_issuer(jwt_secret.as_str(), node_id, jwt_secret.issuer())?;
    info!(
        "Generated fresh DP JWT (TTL={}s, iss='{}') for CP authentication",
        DP_JWT_TTL_SECONDS,
        jwt_secret.issuer()
    );
    let token: MetadataValue<_> = format!("Bearer {}", auth_token).parse()?;

    #[allow(clippy::result_large_err)]
    let mut client =
        ConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    info!(
        "Connected to CP, subscribing for config updates (DP v{})",
        FERRUM_VERSION
    );

    let request = tonic::Request::new(SubscribeRequest {
        node_id: node_id.to_string(),
        ferrum_version: FERRUM_VERSION.to_string(),
        namespace: namespace.to_string(),
    });

    let mut stream = client.subscribe(request).await?.into_inner();
    let mut initial_snapshot_applied = startup_ready.is_none();

    // Mark connected
    if let Some(cs) = connection_state {
        let now = Utc::now();
        cs.store(Arc::new(DpCpConnectionState {
            connected: true,
            cp_url: cp_url.to_string(),
            is_primary,
            last_config_received_at: None,
            connected_since: Some(now),
        }));
    }

    while let Some(update) = stream.message().await? {
        info!(
            "Received config update (type={}, version={}, cp_version={})",
            update.update_type, update.version, update.ferrum_version
        );

        // Validate CP version compatibility before applying any config.
        if !update.ferrum_version.is_empty()
            && let Err(msg) = check_cp_version_compatibility(&update.ferrum_version)
        {
            error!("{}", msg);
            return Err(anyhow::anyhow!(msg));
        }

        match update.update_type {
            0 => {
                // FULL_SNAPSHOT — replace entire config
                match serde_json::from_str::<GatewayConfig>(&update.config_json) {
                    Ok(mut config) => {
                        // Defense in depth: even though the CP-side
                        // namespace check should prevent any
                        // cross-namespace resources from reaching this
                        // DP, filter again locally so a CP regression or
                        // buggy/malicious snapshot can't leak resources
                        // from another tenant into this DP's
                        // GatewayConfig. See `filter_config_to_namespace`.
                        let filtered = filter_config_to_namespace(&mut config, namespace);
                        if filtered > 0 {
                            warn!(
                                "DP namespace filter '{}' excluded {} cross-namespace resources from CP snapshot — \
                                 the CP should have filtered these (verify CP namespace matches DP)",
                                namespace, filtered
                            );
                        }
                        config.normalize_fields();
                        config.resolve_upstream_tls();
                        if let Err(errors) = config.validate_all_fields_with_ip_policy(
                            proxy_state.env_config.tls_cert_expiry_warning_days,
                            &proxy_state.env_config.backend_allow_ips,
                        ) {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid field values");
                            continue;
                        }
                        if let Err(errors) = config.validate_hosts() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid hosts");
                            continue;
                        }
                        if let Err(errors) = config.validate_regex_listen_paths() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid regex listen_paths");
                            continue;
                        }
                        if let Err(errors) = config.validate_unique_listen_paths() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with conflicting listen paths");
                            continue;
                        }
                        if let Err(errors) = config.validate_stream_proxies() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid stream proxy config");
                            continue;
                        }
                        if let Err(errors) = config.validate_upstream_references() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid upstream references");
                            continue;
                        }
                        if let Err(errors) = config.validate_plugin_references() {
                            for msg in &errors {
                                error!("CP config rejected — {}", msg);
                            }
                            error!("Ignoring config update with invalid plugin references");
                            continue;
                        }
                        proxy_state.update_config(config);
                        update_state_config_received(connection_state);
                        if !initial_snapshot_applied {
                            proxy_state
                                .stream_listener_manager
                                .wait_until_started(Duration::from_secs(10))
                                .await?;
                            // Block DP readiness on the first capability
                            // classification. Without this the `/health`
                            // endpoint would flip to ready while the
                            // registry is still empty, so an L4 LB could
                            // route traffic to an H3-only HTTPS backend
                            // and the cross-protocol bridge would 502
                            // until the background refresh landed.
                            // Subsequent CP snapshots don't take this
                            // path — `update_config` already spawns a
                            // coalesced background refresh for them.
                            proxy_state.refresh_backend_capabilities().await;
                            if let Some(ref startup_ready) = startup_ready {
                                startup_ready.store(true, Ordering::Release);
                            }
                            initial_snapshot_applied = true;
                            info!(
                                "DP startup complete; backend capabilities classified; /health now reports ready"
                            );
                        }
                        info!("Full configuration snapshot applied from CP");
                    }
                    Err(e) => {
                        error!("Failed to parse full config update: {}", e);
                    }
                }
            }
            1 => {
                // DELTA — apply incremental changes only
                match serde_json::from_str::<IncrementalResult>(&update.config_json) {
                    Ok(mut result) => {
                        // Defense in depth: filter cross-namespace
                        // additions/modifications before applying. See
                        // `filter_incremental_to_namespace`.
                        let filtered = filter_incremental_to_namespace(&mut result, namespace);
                        if filtered > 0 {
                            warn!(
                                "DP namespace filter '{}' excluded {} cross-namespace resources from CP delta",
                                namespace, filtered
                            );
                        }
                        if proxy_state.apply_incremental(result).await {
                            update_state_config_received(connection_state);
                            info!("Incremental config delta applied from CP");
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse delta update: {}", e);
                    }
                }
            }
            other => {
                warn!("Unknown config update type {}, ignoring", other);
            }
        }
    }

    Ok(())
}

/// Defense-in-depth: filter a full config snapshot to only the DP's
/// configured namespace before applying.
///
/// The CP-side `check_namespace` guard already rejects DP subscriptions that
/// advertise a mismatched namespace, so under normal operation this filter
/// is a no-op (the snapshot the CP sends is already single-namespace).
/// We still run it because:
///
/// 1. A future bug or regression on the CP side that re-enables
///    cross-namespace serving would silently leak resources to the DP.
///    The DP enforcing its own namespace bound prevents that.
/// 2. The serialization is JSON, so a malicious or buggy CP could craft
///    a snapshot whose `proxies[i].namespace != requested_namespace`.
///    Belt-and-braces is cheap.
///
/// Returns the number of resources filtered out so the caller can warn.
fn filter_config_to_namespace(config: &mut GatewayConfig, namespace: &str) -> usize {
    let pre = (
        config.proxies.len(),
        config.consumers.len(),
        config.plugin_configs.len(),
        config.upstreams.len(),
    );
    config.proxies.retain(|p| p.namespace == namespace);
    config.consumers.retain(|c| c.namespace == namespace);
    config.plugin_configs.retain(|pc| pc.namespace == namespace);
    config.upstreams.retain(|u| u.namespace == namespace);
    (pre.0 - config.proxies.len())
        + (pre.1 - config.consumers.len())
        + (pre.2 - config.plugin_configs.len())
        + (pre.3 - config.upstreams.len())
}

/// Defense-in-depth filter for incremental deltas. Applied to
/// `added_or_modified_*` vectors only; removal IDs are namespace-agnostic
/// and harmless on the DP side because they only delete resources the DP
/// already has (which were themselves filtered through this same check).
///
/// Returns the number of resources filtered out so the caller can warn.
fn filter_incremental_to_namespace(result: &mut IncrementalResult, namespace: &str) -> usize {
    let pre = (
        result.added_or_modified_proxies.len(),
        result.added_or_modified_consumers.len(),
        result.added_or_modified_plugin_configs.len(),
        result.added_or_modified_upstreams.len(),
    );
    result
        .added_or_modified_proxies
        .retain(|p| p.namespace == namespace);
    result
        .added_or_modified_consumers
        .retain(|c| c.namespace == namespace);
    result
        .added_or_modified_plugin_configs
        .retain(|pc| pc.namespace == namespace);
    result
        .added_or_modified_upstreams
        .retain(|u| u.namespace == namespace);
    (pre.0 - result.added_or_modified_proxies.len())
        + (pre.1 - result.added_or_modified_consumers.len())
        + (pre.2 - result.added_or_modified_plugin_configs.len())
        + (pre.3 - result.added_or_modified_upstreams.len())
}

/// Check whether the CP's reported version is compatible with this DP.
///
/// Major and minor versions must match. Patch-level differences are allowed.
fn check_cp_version_compatibility(cp_version: &str) -> Result<(), String> {
    let dp_parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
    let cp_parts: Vec<&str> = cp_version.split('.').collect();

    if dp_parts.len() < 2 || cp_parts.len() < 2 {
        warn!(
            "Unable to parse version for compatibility check (DP={}, CP={}), allowing connection",
            FERRUM_VERSION, cp_version
        );
        return Ok(());
    }

    if dp_parts[0] != cp_parts[0] || dp_parts[1] != cp_parts[1] {
        return Err(format!(
            "Version mismatch: DP is v{} but CP is v{}. \
             Major and minor versions must match. \
             Upgrade the CP first, then upgrade DPs to the same major.minor version.",
            FERRUM_VERSION, cp_version
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Inline tests for the DP-side namespace filter helpers. These are
    //! private functions, so they live alongside the implementation rather
    //! than in `tests/`. The end-to-end behavior is exercised by
    //! `tests/integration/cp_dp_grpc_tests.rs` via
    //! `test_dp_filters_cross_namespace_resources_from_snapshot`.
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn proxy_in_namespace(id: &str, ns: &str) -> crate::config::types::Proxy {
        serde_json::from_value(json!({
            "id": id,
            "namespace": ns,
            "backend_host": "example.com",
            "backend_port": 443,
        }))
        .expect("proxy fixture should deserialize")
    }

    fn upstream_in_namespace(id: &str, ns: &str) -> crate::config::types::Upstream {
        serde_json::from_value(json!({
            "id": id,
            "namespace": ns,
            "targets": [{"host": "example.com", "port": 443, "weight": 100}],
            "algorithm": "round_robin",
        }))
        .expect("upstream fixture should deserialize")
    }

    fn consumer_in_namespace(id: &str, ns: &str) -> crate::config::types::Consumer {
        serde_json::from_value(json!({
            "id": id,
            "namespace": ns,
            "username": id,
            "credentials": {},
        }))
        .expect("consumer fixture should deserialize")
    }

    fn plugin_config_in_namespace(id: &str, ns: &str) -> crate::config::types::PluginConfig {
        serde_json::from_value(json!({
            "id": id,
            "namespace": ns,
            "plugin_name": "rate_limiting",
            "config": {},
            "scope": "global",
        }))
        .expect("plugin_config fixture should deserialize")
    }

    #[test]
    fn filter_config_keeps_matching_namespace_only() {
        let mut cfg = GatewayConfig {
            version: "1".to_string(),
            proxies: vec![
                proxy_in_namespace("p-prod", "production"),
                proxy_in_namespace("p-staging", "staging"),
                proxy_in_namespace("p-prod-2", "production"),
            ],
            consumers: vec![
                consumer_in_namespace("c-prod", "production"),
                consumer_in_namespace("c-staging", "staging"),
            ],
            plugin_configs: vec![
                plugin_config_in_namespace("pc-prod", "production"),
                plugin_config_in_namespace("pc-staging", "staging"),
            ],
            upstreams: vec![
                upstream_in_namespace("u-prod", "production"),
                upstream_in_namespace("u-staging", "staging"),
            ],
            loaded_at: Utc::now(),
            known_namespaces: Vec::new(),
        };

        let filtered = filter_config_to_namespace(&mut cfg, "production");
        assert_eq!(filtered, 4, "1 proxy + 1 consumer + 1 plugin + 1 upstream");

        assert_eq!(cfg.proxies.len(), 2);
        assert!(cfg.proxies.iter().all(|p| p.namespace == "production"));
        assert_eq!(cfg.consumers.len(), 1);
        assert_eq!(cfg.consumers[0].namespace, "production");
        assert_eq!(cfg.plugin_configs.len(), 1);
        assert_eq!(cfg.plugin_configs[0].namespace, "production");
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.upstreams[0].namespace, "production");
    }

    #[test]
    fn filter_config_returns_zero_when_clean() {
        let mut cfg = GatewayConfig {
            version: "1".to_string(),
            proxies: vec![proxy_in_namespace("p-prod", "production")],
            consumers: vec![],
            plugin_configs: vec![],
            upstreams: vec![],
            loaded_at: Utc::now(),
            known_namespaces: Vec::new(),
        };
        assert_eq!(filter_config_to_namespace(&mut cfg, "production"), 0);
        assert_eq!(cfg.proxies.len(), 1);
    }

    #[test]
    fn filter_incremental_keeps_matching_namespace_only() {
        let mut delta = IncrementalResult {
            added_or_modified_proxies: vec![
                proxy_in_namespace("p-prod", "production"),
                proxy_in_namespace("p-staging", "staging"),
            ],
            removed_proxy_ids: vec!["doesnt-matter".to_string()],
            added_or_modified_consumers: vec![consumer_in_namespace("c-staging", "staging")],
            removed_consumer_ids: vec![],
            added_or_modified_plugin_configs: vec![plugin_config_in_namespace(
                "pc-prod",
                "production",
            )],
            removed_plugin_config_ids: vec![],
            added_or_modified_upstreams: vec![
                upstream_in_namespace("u-prod", "production"),
                upstream_in_namespace("u-staging", "staging"),
            ],
            removed_upstream_ids: vec![],
            poll_timestamp: Utc::now(),
        };

        let filtered = filter_incremental_to_namespace(&mut delta, "production");
        assert_eq!(filtered, 3, "1 proxy + 1 consumer + 1 upstream filtered");

        assert_eq!(delta.added_or_modified_proxies.len(), 1);
        assert_eq!(delta.added_or_modified_proxies[0].namespace, "production");
        assert!(delta.added_or_modified_consumers.is_empty());
        assert_eq!(delta.added_or_modified_plugin_configs.len(), 1);
        assert_eq!(delta.added_or_modified_upstreams.len(), 1);

        // Removal IDs are intentionally NOT filtered — the DP only has
        // resources in its own namespace anyway, so deleting an unknown ID
        // is harmless.
        assert_eq!(delta.removed_proxy_ids.len(), 1);
    }

    #[test]
    fn filter_incremental_returns_zero_when_empty() {
        let mut delta = IncrementalResult {
            added_or_modified_proxies: vec![],
            removed_proxy_ids: vec![],
            added_or_modified_consumers: vec![],
            removed_consumer_ids: vec![],
            added_or_modified_plugin_configs: vec![],
            removed_plugin_config_ids: vec![],
            added_or_modified_upstreams: vec![],
            removed_upstream_ids: vec![],
            poll_timestamp: Utc::now(),
        };
        assert_eq!(filter_incremental_to_namespace(&mut delta, "production"), 0);
    }
}
