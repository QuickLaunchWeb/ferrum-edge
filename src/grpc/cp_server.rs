//! Control Plane gRPC server implementing the `ConfigSync` service.
//!
//! Provides two RPCs:
//! - `Subscribe` — server-streaming: DP connects and receives a `FULL_SNAPSHOT`
//!   (update_type=0), then incremental `DELTA` updates (update_type=1) as config changes.
//!   If a DP lags behind the broadcast channel (default capacity 128, configurable
//!   via `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`), it receives a fresh
//!   full snapshot instead of the missed deltas.
//! - `GetFullConfig` — unary: returns the current full config snapshot on demand.
//!
//! Authentication: HS256 JWT in the `authorization` gRPC metadata key.
//! Required claims: `exp`, `iat`, `sub`, `iss`. The `iss` claim must exactly
//! match the configured expected issuer (`FERRUM_CP_DP_GRPC_JWT_ISSUER`,
//! default `"ferrum-edge-cp-dp"`); this prevents a token minted with the same
//! shared secret for a different audience (e.g. the admin API JWT secret if
//! it was reused) from authenticating to the gRPC channel. The CP enforces
//! `major.minor` version compatibility — a DP running a different minor
//! version is rejected.
//!
//! Issuer rotation: changing `FERRUM_CP_DP_GRPC_JWT_ISSUER` is a breaking
//! change. The CP rejects any token whose `iss` does not match its expected
//! value, so the CP and all DPs must roll together. Pre-deployment, decide
//! whether to roll DPs first (CP keeps accepting old issuer until upgraded)
//! or CP first (CP must temporarily accept multiple issuers — not currently
//! supported, so prefer DPs-first) and plan accordingly.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use super::auth::verify_grpc_jwt_metadata;
use super::proto::config_sync_server::{ConfigSync, ConfigSyncServer};
use super::proto::{ConfigUpdate, FullConfigRequest, FullConfigResponse, SubscribeRequest};
use crate::FERRUM_VERSION;
use crate::config::types::{GatewayConfig, default_namespace};

/// Metadata about a connected Data Plane node.
#[derive(Clone, Serialize)]
pub struct DpNodeInfo {
    pub node_id: String,
    pub version: String,
    pub namespace: String,
    pub connected_at: DateTime<Utc>,
    pub last_update_at: DateTime<Utc>,
}

/// Registry of connected DP nodes. Shared between the gRPC server and the
/// admin API so that `GET /cluster` can report live connection state.
#[derive(Default)]
pub struct DpNodeRegistry {
    nodes: DashMap<String, DpNodeInfo>,
}

impl DpNodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
        }
    }

    pub fn insert(&self, info: DpNodeInfo) {
        self.nodes.insert(info.node_id.clone(), info);
    }

    /// Remove a node only if its `connected_at` matches the expected timestamp.
    /// This prevents a stale stream drop from removing a newer reconnection's entry.
    pub fn remove_if_stale(&self, node_id: &str, expected_connected_at: DateTime<Utc>) {
        self.nodes.remove_if(node_id, |_, info| {
            info.connected_at == expected_connected_at
        });
    }

    /// Update `last_update_at` for all connected nodes (called after broadcast).
    pub fn touch_all(&self) {
        let now = Utc::now();
        for mut entry in self.nodes.iter_mut() {
            entry.last_update_at = now;
        }
    }

    /// Return a snapshot of all connected nodes.
    pub fn snapshot(&self) -> Vec<DpNodeInfo> {
        self.nodes
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Number of connected node IDs.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.snapshot().len()
    }

    /// Whether the registry has no connected node IDs.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// A stream wrapper that removes the DP node from the registry when the
/// gRPC stream is dropped (i.e. the DP disconnects). Uses `connected_at`
/// to guard against stale drops: if the DP reconnects before the old stream
/// is dropped, the old drop will not remove the newer entry.
struct TrackedStream<S> {
    inner: Pin<Box<S>>,
    registry: Arc<DpNodeRegistry>,
    node_id: String,
    connected_at: DateTime<Utc>,
}

impl<S> Drop for TrackedStream<S> {
    fn drop(&mut self) {
        self.registry
            .remove_if_stale(&self.node_id, self.connected_at);
        info!("DP node '{}' disconnected (stream dropped)", self.node_id);
    }
}

impl<S> tokio_stream::Stream for TrackedStream<S>
where
    S: tokio_stream::Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// Default expected issuer for CP/DP gRPC JWTs. Operators override via
/// `FERRUM_CP_DP_GRPC_JWT_ISSUER`. Kept as a `pub const` so the DP token
/// minter can fall back to the same constant when constructing tokens
/// without an `EnvConfig` in scope (tests, library callers).
pub const DEFAULT_CP_DP_JWT_ISSUER: &str = "ferrum-edge-cp-dp";

/// CP gRPC server state.
pub struct CpGrpcServer {
    config: Arc<ArcSwap<GatewayConfig>>,
    jwt_secret: String,
    /// Expected `iss` claim on inbound DP tokens. Tokens whose `iss` does not
    /// exactly match this string are rejected with `unauthenticated`.
    expected_issuer: String,
    update_tx: broadcast::Sender<ConfigUpdate>,
    registry: Arc<DpNodeRegistry>,
    /// CP's configured namespace (`FERRUM_NAMESPACE`). Connecting DPs must
    /// advertise the same namespace, or `Subscribe` / `GetFullConfig` is
    /// rejected with `failed_precondition`. A single CP serves a single
    /// namespace; multi-namespace deployments require multiple CP instances.
    namespace: String,
}

impl CpGrpcServer {
    /// Create a new CP gRPC server with the default broadcast channel capacity (128)
    /// plus the default expected issuer and namespace.
    ///
    /// Used by tests. Production code calls `with_channel_capacity` (or
    /// `with_channel_capacity_and_registry`) directly so it can thread the
    /// operator-configured capacity, issuer, and namespace through from `EnvConfig`.
    #[allow(dead_code)]
    pub fn new(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::with_channel_capacity(config, jwt_secret, 128)
    }

    #[allow(dead_code)]
    pub fn with_channel_capacity(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::with_channel_capacity_and_registry(
            config,
            jwt_secret,
            channel_capacity,
            Arc::new(DpNodeRegistry::new()),
        )
    }

    pub fn with_channel_capacity_and_registry(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
        registry: Arc<DpNodeRegistry>,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::with_channel_capacity_registry_issuer_and_namespace(
            config,
            jwt_secret,
            channel_capacity,
            registry,
            DEFAULT_CP_DP_JWT_ISSUER.to_string(),
            default_namespace(),
        )
    }

    /// Constructor that threads through the operator-configured expected issuer
    /// (`FERRUM_CP_DP_GRPC_JWT_ISSUER`) and uses the default namespace.
    #[allow(dead_code)]
    pub fn with_channel_capacity_registry_and_issuer(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
        registry: Arc<DpNodeRegistry>,
        expected_issuer: String,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::with_channel_capacity_registry_issuer_and_namespace(
            config,
            jwt_secret,
            channel_capacity,
            registry,
            expected_issuer,
            default_namespace(),
        )
    }

    /// Constructor that threads through the CP's configured namespace and uses
    /// the default CP/DP JWT issuer.
    #[allow(dead_code)]
    pub fn with_channel_capacity_registry_and_namespace(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
        registry: Arc<DpNodeRegistry>,
        namespace: String,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        Self::with_channel_capacity_registry_issuer_and_namespace(
            config,
            jwt_secret,
            channel_capacity,
            registry,
            DEFAULT_CP_DP_JWT_ISSUER.to_string(),
            namespace,
        )
    }

    /// Production-grade constructor that threads through both the operator-
    /// configured expected issuer (`FERRUM_CP_DP_GRPC_JWT_ISSUER`) and the
    /// CP namespace (`FERRUM_NAMESPACE`).
    pub fn with_channel_capacity_registry_issuer_and_namespace(
        config: Arc<ArcSwap<GatewayConfig>>,
        jwt_secret: String,
        channel_capacity: usize,
        registry: Arc<DpNodeRegistry>,
        expected_issuer: String,
        namespace: String,
    ) -> (Self, broadcast::Sender<ConfigUpdate>) {
        let (tx, _) = broadcast::channel(channel_capacity.max(1));
        let tx_clone = tx.clone();
        (
            Self {
                config,
                jwt_secret,
                expected_issuer,
                update_tx: tx,
                registry,
                namespace,
            },
            tx_clone,
        )
    }

    /// Reject DP subscriptions that advertise a namespace different from the
    /// CP's configured namespace. Without this check the CP would happily
    /// stream `production`-namespace config to a DP that booted with
    /// `FERRUM_NAMESPACE=staging`, silently leaking configuration across
    /// tenant boundaries. A single CP serves a single namespace today;
    /// operators running multiple namespaces must run multiple CP instances.
    #[allow(clippy::result_large_err)]
    fn check_namespace(&self, dp_namespace: &str) -> Result<(), Status> {
        if dp_namespace != self.namespace {
            return Err(Status::failed_precondition(format!(
                "DP namespace '{}' does not match CP namespace '{}'. \
                 A single CP serves a single namespace; deploy a separate CP \
                 instance per namespace.",
                dp_namespace, self.namespace
            )));
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn verify_jwt_metadata(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
        verify_grpc_jwt_metadata(metadata, &self.jwt_secret, &self.expected_issuer)
    }

    pub fn into_service(self) -> ConfigSyncServer<Self> {
        ConfigSyncServer::new(self)
    }

    /// Check whether the DP's reported version is compatible with this CP.
    ///
    /// Compatibility rule: major and minor versions must match. Patch-level
    /// differences are always allowed (bug-fix releases don't change the
    /// config schema or gRPC wire format).
    #[allow(clippy::result_large_err)]
    pub(crate) fn check_version_compatibility(dp_version: &str) -> Result<(), Status> {
        // Empty version means old DP that predates the version field — reject.
        if dp_version.is_empty() {
            return Err(Status::failed_precondition(format!(
                "DP did not report its version. CP is running Ferrum Edge v{}. \
                 Upgrade the DP to a version that supports version negotiation.",
                FERRUM_VERSION
            )));
        }

        let cp_parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
        let dp_parts: Vec<&str> = dp_version.split('.').collect();

        if cp_parts.len() < 2 || dp_parts.len() < 2 {
            warn!(
                "Unable to parse version for compatibility check (CP={}, DP={}), allowing connection",
                FERRUM_VERSION, dp_version
            );
            return Ok(());
        }

        if cp_parts[0] != dp_parts[0] || cp_parts[1] != dp_parts[1] {
            return Err(Status::failed_precondition(format!(
                "Version mismatch: CP is v{} but DP is v{}. \
                 Major and minor versions must match. \
                 Upgrade the CP first, then upgrade DPs to the same major.minor version.",
                FERRUM_VERSION, dp_version
            )));
        }

        if cp_parts.get(2) != dp_parts.get(2) {
            info!(
                "DP v{} connected to CP v{} (patch difference OK)",
                dp_version, FERRUM_VERSION
            );
        }

        Ok(())
    }

    /// Broadcast a full config snapshot to all connected DPs.
    pub fn broadcast_update_with_registry(
        tx: &broadcast::Sender<ConfigUpdate>,
        config: &GatewayConfig,
        registry: &DpNodeRegistry,
    ) {
        Self::broadcast_update(tx, config);
        registry.touch_all();
    }

    /// Broadcast a full config snapshot to all connected DPs.
    pub fn broadcast_update(tx: &broadcast::Sender<ConfigUpdate>, config: &GatewayConfig) {
        let config_json = match serde_json::to_string(config) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize config for broadcast: {}", e);
                return;
            }
        };
        let update = ConfigUpdate {
            update_type: 0, // FULL_SNAPSHOT
            config_json,
            version: config.loaded_at.to_rfc3339(),
            timestamp: chrono::Utc::now().timestamp(),
            ferrum_version: FERRUM_VERSION.to_string(),
        };
        let _ = tx.send(update);
    }

    /// Broadcast an incremental delta to all connected DPs (with registry update).
    pub fn broadcast_delta_with_registry(
        tx: &broadcast::Sender<ConfigUpdate>,
        result: &crate::config::db_loader::IncrementalResult,
        version: &str,
        registry: &DpNodeRegistry,
    ) {
        Self::broadcast_delta(tx, result, version);
        registry.touch_all();
    }

    /// Broadcast an incremental delta to all connected DPs.
    ///
    /// Sends only the resources that changed (added/modified/removed) instead
    /// of the full config. DPs apply the delta via `ProxyState::apply_incremental`.
    pub fn broadcast_delta(
        tx: &broadcast::Sender<ConfigUpdate>,
        result: &crate::config::db_loader::IncrementalResult,
        version: &str,
    ) {
        let config_json = match serde_json::to_string(result) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize delta for broadcast: {}", e);
                return;
            }
        };
        let update = ConfigUpdate {
            update_type: 1, // DELTA
            config_json,
            version: version.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            ferrum_version: FERRUM_VERSION.to_string(),
        };
        let _ = tx.send(update);
    }
}

#[tonic::async_trait]
impl ConfigSync for CpGrpcServer {
    type SubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ConfigUpdate, Status>> + Send>>;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        self.verify_jwt_metadata(request.metadata())?;

        let inner = request.into_inner();
        let node_id = inner.node_id;
        let dp_version = inner.ferrum_version;
        let dp_namespace = inner.namespace;

        // Reject DPs with incompatible versions before streaming any config.
        Self::check_version_compatibility(&dp_version)?;
        // Reject DPs that advertise a different namespace than the CP
        // serves — otherwise the CP would leak cross-namespace config to
        // mismatched DPs (multi-tenant security gap).
        self.check_namespace(&dp_namespace)?;

        info!(
            "DP node '{}' (v{}) subscribed for config updates (namespace='{}')",
            node_id, dp_version, dp_namespace
        );

        // Register the DP in the node registry (removed on stream drop).
        let now = Utc::now();
        self.registry.insert(DpNodeInfo {
            node_id: node_id.clone(),
            version: dp_version.clone(),
            namespace: dp_namespace.clone(),
            connected_at: now,
            last_update_at: now,
        });

        // Register the receiver before loading the initial snapshot so a
        // concurrent CP broadcast is either captured by this stream or already
        // reflected in the loaded snapshot.
        let rx = self.update_tx.subscribe();

        // Send initial full config
        let config = self.config.load_full();
        let config_json = serde_json::to_string(config.as_ref()).map_err(|e| {
            error!("Failed to serialize config in subscribe: {}", e);
            Status::internal("Failed to serialize configuration")
        })?;
        let initial = ConfigUpdate {
            update_type: 0, // FULL_SNAPSHOT
            config_json,
            version: config.loaded_at.to_rfc3339(),
            timestamp: chrono::Utc::now().timestamp(),
            ferrum_version: FERRUM_VERSION.to_string(),
        };

        let config_for_recovery = self.config.clone();
        let stream = BroadcastStream::new(rx).filter_map(move |result| match result {
            Ok(update) => Some(Ok(update)),
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                warn!(
                    "DP config stream lagged behind by {} updates — sending full snapshot to recover",
                    n
                );
                // Send a full config snapshot so the DP recovers from missed deltas.
                let current = config_for_recovery.load_full();
                match serde_json::to_string(current.as_ref()) {
                    Ok(config_json) => Some(Ok(ConfigUpdate {
                        update_type: 0, // FULL_SNAPSHOT
                        config_json,
                        version: current.loaded_at.to_rfc3339(),
                        timestamp: chrono::Utc::now().timestamp(),
                        ferrum_version: FERRUM_VERSION.to_string(),
                    })),
                    Err(e) => {
                        error!("Failed to serialize recovery snapshot: {}", e);
                        None
                    }
                }
            }
        });

        // Prepend initial config, then wrap in TrackedStream so the DP is
        // automatically de-registered when the gRPC stream is dropped.
        let initial_stream = tokio_stream::once(Ok(initial));
        let combined = initial_stream.chain(stream);
        let tracked = TrackedStream {
            inner: Box::pin(combined),
            registry: self.registry.clone(),
            node_id,
            connected_at: now,
        };

        Ok(Response::new(Box::pin(tracked)))
    }

    async fn get_full_config(
        &self,
        request: Request<FullConfigRequest>,
    ) -> Result<Response<FullConfigResponse>, Status> {
        self.verify_jwt_metadata(request.metadata())?;

        let req = request.get_ref();
        let dp_version = &req.ferrum_version;
        Self::check_version_compatibility(dp_version)?;
        // Same cross-namespace guard as `Subscribe` — without it
        // `GetFullConfig` would leak the wrong namespace's snapshot.
        self.check_namespace(&req.namespace)?;

        info!(
            "DP '{}' (v{}) requested full config (namespace='{}')",
            req.node_id, dp_version, req.namespace
        );

        let config = self.config.load_full();
        let config_json = serde_json::to_string(config.as_ref()).map_err(|e| {
            error!("Failed to serialize config in get_full_config: {}", e);
            Status::internal("Failed to serialize configuration")
        })?;

        Ok(Response::new(FullConfigResponse {
            config_json,
            version: config.loaded_at.to_rfc3339(),
            ferrum_version: FERRUM_VERSION.to_string(),
        }))
    }
}

// Version compatibility is tested inline because `check_version_compatibility` is private.
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn registry_info(node_id: &str, version: &str, connected_at: DateTime<Utc>) -> DpNodeInfo {
        DpNodeInfo {
            node_id: node_id.to_string(),
            version: version.to_string(),
            namespace: "ferrum".to_string(),
            connected_at,
            last_update_at: connected_at,
        }
    }

    #[test]
    fn registry_insert_replaces_same_dp_node() {
        let registry = DpNodeRegistry::new();
        let first_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let second_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "old-version", first_connected_at));
        registry.insert(registry_info("node-a", "new-version", second_connected_at));

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "new-version");
        assert_eq!(snapshot[0].connected_at, second_connected_at);
    }

    #[test]
    fn registry_stale_drop_does_not_remove_newer_dp_entry() {
        let registry = DpNodeRegistry::new();
        let old_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let new_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "old-version", old_connected_at));
        registry.insert(registry_info("node-a", "new-version", new_connected_at));
        registry.remove_if_stale("node-a", old_connected_at);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "new-version");
        assert_eq!(snapshot[0].connected_at, new_connected_at);
    }

    #[test]
    fn version_check_same_version_ok() {
        assert!(CpGrpcServer::check_version_compatibility(FERRUM_VERSION).is_ok());
    }

    #[test]
    fn version_check_empty_version_rejected() {
        let result = CpGrpcServer::check_version_compatibility("");
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn version_check_same_major_minor_different_patch_ok() {
        let parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
        if parts.len() >= 3 {
            let patch: u32 = parts[2].parse().unwrap_or(0);
            let modified = format!("{}.{}.{}", parts[0], parts[1], patch + 1);
            assert!(CpGrpcServer::check_version_compatibility(&modified).is_ok());
        }
    }

    #[test]
    fn version_check_different_minor_rejected() {
        let parts: Vec<&str> = FERRUM_VERSION.split('.').collect();
        if parts.len() >= 2 {
            let minor: u32 = parts[1].parse().unwrap_or(0);
            let modified = format!("{}.{}.0", parts[0], minor + 1);
            let result = CpGrpcServer::check_version_compatibility(&modified);
            assert!(result.is_err());
        }
    }

    #[test]
    fn version_check_unparseable_version_allowed() {
        // Single-component version is unparseable (< 2 parts), so it's allowed
        assert!(CpGrpcServer::check_version_compatibility("1").is_ok());
    }

    fn cp_with_namespace(namespace: &str) -> CpGrpcServer {
        let cfg = Arc::new(ArcSwap::new(Arc::new(GatewayConfig::default())));
        let (server, _tx) = CpGrpcServer::with_channel_capacity_registry_and_namespace(
            cfg,
            "test-secret".to_string(),
            128,
            Arc::new(DpNodeRegistry::new()),
            namespace.to_string(),
        );
        server
    }

    #[test]
    fn check_namespace_accepts_match() {
        let server = cp_with_namespace("production");
        assert!(server.check_namespace("production").is_ok());
    }

    #[test]
    fn check_namespace_rejects_mismatch_with_both_namespaces_in_message() {
        let server = cp_with_namespace("production");
        let err = server.check_namespace("staging").unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let msg = err.message();
        assert!(
            msg.contains("staging") && msg.contains("production"),
            "error message should mention both namespaces, got: {}",
            msg
        );
    }

    #[test]
    fn check_namespace_rejects_empty_dp_namespace_against_default() {
        // Empty DP namespace must not silently match the default; tests
        // that the comparison is strict equality, not "default if empty".
        let server = cp_with_namespace("ferrum");
        assert!(server.check_namespace("").is_err());
    }
}
