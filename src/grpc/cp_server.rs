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
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Serialize;
use serde_json::Value;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use super::proto::config_sync_server::{ConfigSync, ConfigSyncServer};
use super::proto::{
    ConfigUpdate, FullConfigRequest, FullConfigResponse, MeshConfigUpdate, MeshSubscribeRequest,
    SubscribeRequest,
};
use crate::FERRUM_VERSION;
use crate::config::incremental_apply::apply_incremental_to_config_snapshot;
use crate::config::types::{GatewayConfig, default_namespace};
use crate::xds::{MeshSlice, MeshSliceRequest};

/// Metadata about a connected Data Plane node.
#[derive(Clone, Serialize)]
pub struct DpNodeInfo {
    pub node_id: String,
    pub version: String,
    pub namespace: String,
    pub connected_at: DateTime<Utc>,
    pub last_update_at: DateTime<Utc>,
}

/// Registry of connected DP and mesh config-stream nodes. Shared between the
/// gRPC server and the admin API so that `GET /cluster` can report live
/// connection state.
#[derive(Default)]
pub struct DpNodeRegistry {
    nodes: DashMap<String, DpNodeRegistryEntry>,
}

#[derive(Clone, Default)]
struct DpNodeRegistryEntry {
    dp: Option<DpNodeInfo>,
    mesh: Option<DpNodeInfo>,
}

impl DpNodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
        }
    }

    pub fn insert(&self, info: DpNodeInfo) {
        self.insert_for_stream(info, RegistryStreamKind::Dp);
    }

    pub fn insert_mesh(&self, info: DpNodeInfo) {
        self.insert_for_stream(info, RegistryStreamKind::Mesh);
    }

    /// Remove a node only if its `connected_at` matches the expected timestamp.
    /// This prevents a stale stream drop from removing a newer reconnection's entry.
    pub fn remove_if_stale(&self, node_id: &str, expected_connected_at: DateTime<Utc>) {
        self.remove_if_stale_for_stream(node_id, expected_connected_at, RegistryStreamKind::Dp);
    }

    /// Update `last_update_at` for all connected nodes (called after broadcast).
    pub fn touch_all(&self) {
        let now = Utc::now();
        for mut entry in self.nodes.iter_mut() {
            if let Some(dp) = entry.dp.as_mut() {
                dp.last_update_at = now;
            }
            if let Some(mesh) = entry.mesh.as_mut() {
                mesh.last_update_at = now;
            }
        }
    }

    /// Return a snapshot of all connected nodes.
    pub fn snapshot(&self) -> Vec<DpNodeInfo> {
        self.nodes
            .iter()
            .filter_map(|entry| entry.value().snapshot_info())
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
        self.len() == 0
    }

    fn remove_mesh_if_stale(&self, node_id: &str, expected_connected_at: DateTime<Utc>) {
        self.remove_if_stale_for_stream(node_id, expected_connected_at, RegistryStreamKind::Mesh);
    }

    fn insert_for_stream(&self, info: DpNodeInfo, kind: RegistryStreamKind) {
        let node_id = info.node_id.clone();
        self.nodes
            .entry(node_id)
            .and_modify(|entry| entry.set(kind, info.clone()))
            .or_insert_with(|| {
                let mut entry = DpNodeRegistryEntry::default();
                entry.set(kind, info);
                entry
            });
    }

    fn remove_if_stale_for_stream(
        &self,
        node_id: &str,
        expected_connected_at: DateTime<Utc>,
        kind: RegistryStreamKind,
    ) {
        let should_remove_entry = if let Some(mut entry) = self.nodes.get_mut(node_id) {
            entry.remove_if_stale(kind, expected_connected_at);
            entry.is_empty()
        } else {
            false
        };
        if should_remove_entry {
            self.nodes.remove_if(node_id, |_, entry| entry.is_empty());
        }
    }
}

impl DpNodeRegistryEntry {
    fn set(&mut self, kind: RegistryStreamKind, info: DpNodeInfo) {
        match kind {
            RegistryStreamKind::Dp => self.dp = Some(info),
            RegistryStreamKind::Mesh => self.mesh = Some(info),
        }
    }

    fn remove_if_stale(&mut self, kind: RegistryStreamKind, expected_connected_at: DateTime<Utc>) {
        let slot = match kind {
            RegistryStreamKind::Dp => &mut self.dp,
            RegistryStreamKind::Mesh => &mut self.mesh,
        };
        if slot
            .as_ref()
            .is_some_and(|info| info.connected_at == expected_connected_at)
        {
            *slot = None;
        }
    }

    fn snapshot_info(&self) -> Option<DpNodeInfo> {
        self.dp.clone().or_else(|| self.mesh.clone())
    }

    fn is_empty(&self) -> bool {
        self.dp.is_none() && self.mesh.is_none()
    }
}

#[derive(Clone, Copy)]
enum RegistryStreamKind {
    Dp,
    Mesh,
}

impl RegistryStreamKind {
    fn label(self) -> &'static str {
        match self {
            Self::Dp => "DP",
            Self::Mesh => "Mesh",
        }
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
    stream_kind: RegistryStreamKind,
}

impl<S> Drop for TrackedStream<S> {
    fn drop(&mut self) {
        match self.stream_kind {
            RegistryStreamKind::Dp => self
                .registry
                .remove_if_stale(&self.node_id, self.connected_at),
            RegistryStreamKind::Mesh => self
                .registry
                .remove_mesh_if_stale(&self.node_id, self.connected_at),
        }
        info!(
            "{} node '{}' disconnected (stream dropped)",
            self.stream_kind.label(),
            self.node_id
        );
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
        let token = metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.strip_prefix("Bearer ").unwrap_or(s))
            .ok_or_else(|| Status::unauthenticated("Missing authorization token"))?;

        let key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        // Require standard claims to prevent minimal/forged tokens from authenticating.
        // `iss` is required AND constrained to the expected issuer below: a token
        // signed with the same shared secret but bearing a different `iss` (e.g.
        // a leaked admin-API token if the secret was reused, or a token minted
        // for an unrelated audience) is rejected here.
        validation.required_spec_claims = {
            let mut claims = std::collections::HashSet::new();
            claims.insert("exp".to_string());
            claims.insert("iat".to_string());
            claims.insert("sub".to_string());
            claims.insert("iss".to_string());
            claims
        };
        validation.set_issuer(&[self.expected_issuer.as_str()]);

        decode::<Value>(token, &key, &validation)
            .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

        Ok(())
    }

    pub fn into_service(self) -> ConfigSyncServer<Self> {
        ConfigSyncServer::new(self)
    }

    #[allow(clippy::result_large_err)]
    fn build_mesh_config_update_from_slice(slice: MeshSlice) -> Result<MeshConfigUpdate, Status> {
        let version = slice.version.clone();
        let mesh_slice_json = serde_json::to_string(&slice).map_err(|e| {
            error!("Failed to serialize mesh slice: {}", e);
            Status::internal("Failed to serialize mesh slice")
        })?;
        Ok(MeshConfigUpdate {
            version,
            timestamp: chrono::Utc::now().timestamp(),
            mesh_slice_json,
            ferrum_version: FERRUM_VERSION.to_string(),
        })
    }

    #[allow(clippy::result_large_err)]
    fn build_mesh_config_update_if_changed(
        config: &GatewayConfig,
        slice_request: MeshSliceRequest,
        previous_slice: &MeshSlice,
    ) -> Result<(MeshSlice, Option<MeshConfigUpdate>), Status> {
        let next_slice = MeshSlice::from_gateway_config(config, slice_request);
        if mesh_slice_content_equal(previous_slice, &next_slice) {
            return Ok((next_slice, None));
        }
        let update = Self::build_mesh_config_update_from_slice(next_slice.clone())?;
        Ok((next_slice, Some(update)))
    }

    fn apply_mesh_delta_to_stream_config(
        stream_config: &mut GatewayConfig,
        delta: crate::config::db_loader::IncrementalResult,
        slice_request: MeshSliceRequest,
        previous_slice: &MeshSlice,
    ) -> Result<(MeshSlice, Option<MeshConfigUpdate>), Status> {
        let mut candidate = stream_config.clone();
        apply_incremental_to_config_snapshot(&mut candidate, delta);
        candidate.normalize_fields();
        let result =
            Self::build_mesh_config_update_if_changed(&candidate, slice_request, previous_slice)?;
        *stream_config = candidate;
        Ok(result)
    }

    /// Check whether the DP's reported version is compatible with this CP.
    ///
    /// Compatibility rule: major and minor versions must match. Patch-level
    /// differences are always allowed (bug-fix releases don't change the
    /// config schema or gRPC wire format).
    #[allow(clippy::result_large_err)]
    fn check_version_compatibility(dp_version: &str) -> Result<(), Status> {
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
    type MeshSubscribeStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<MeshConfigUpdate, Status>> + Send>>;

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

        let rx = self.update_tx.subscribe();
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
            stream_kind: RegistryStreamKind::Dp,
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

    async fn mesh_subscribe(
        &self,
        request: Request<MeshSubscribeRequest>,
    ) -> Result<Response<Self::MeshSubscribeStream>, Status> {
        self.verify_jwt_metadata(request.metadata())?;

        let inner = request.into_inner();
        Self::check_version_compatibility(&inner.ferrum_version)?;
        self.check_namespace(&inner.namespace)?;
        if inner.node_id.is_empty() {
            return Err(Status::invalid_argument(
                "MeshSubscribe node_id is required",
            ));
        }

        info!(
            "Mesh node '{}' (v{}) subscribed for mesh config (namespace='{}')",
            inner.node_id, inner.ferrum_version, inner.namespace
        );

        let node_id = inner.node_id;
        let node_version = inner.ferrum_version;
        let node_namespace = inner.namespace;

        let slice_request = MeshSliceRequest::from_native(
            node_id.clone(),
            node_namespace.clone(),
            inner.workload_spiffe_id,
            inner.labels,
        );
        let config = self.config.load_full();
        let initial_slice = MeshSlice::from_gateway_config(config.as_ref(), slice_request.clone());
        let initial = Self::build_mesh_config_update_from_slice(initial_slice.clone())?;

        let now = Utc::now();
        self.registry.insert_mesh(DpNodeInfo {
            node_id: node_id.clone(),
            version: node_version,
            namespace: node_namespace,
            connected_at: now,
            last_update_at: now,
        });

        let mut stream_config = config.as_ref().clone();
        let mut previous_slice = initial_slice;
        let rx = self.update_tx.subscribe();
        let config_for_recovery = self.config.clone();
        let stream = BroadcastStream::new(rx).filter_map(move |result| {
            let slice_request = slice_request.clone();
            match result {
                Ok(update) if update.update_type == 0 => {
                    match serde_json::from_str::<GatewayConfig>(&update.config_json) {
                        Ok(mut config) => {
                            config.normalize_fields();
                            match Self::build_mesh_config_update_if_changed(
                                &config,
                                slice_request,
                                &previous_slice,
                            ) {
                                Ok((next_slice, Some(mesh_update))) => {
                                    stream_config = config;
                                    previous_slice = next_slice;
                                    Some(Ok(mesh_update))
                                }
                                Ok((_, None)) => {
                                    stream_config = config;
                                    None
                                }
                                Err(e) => Some(Err(e)),
                            }
                        }
                        Err(e) => {
                            warn!("Failed to deserialize full config for mesh stream: {}", e);
                            None
                        }
                    }
                }
                Ok(update) if update.update_type == 1 => {
                    match serde_json::from_str::<crate::config::db_loader::IncrementalResult>(
                        &update.config_json,
                    ) {
                        Ok(delta) => {
                            Self::apply_mesh_delta_to_stream_config(
                                &mut stream_config,
                                delta,
                                slice_request,
                                &previous_slice,
                            )
                            .ok()
                            .and_then(|(next_slice, maybe_update)| {
                                if maybe_update.is_some() {
                                    previous_slice = next_slice;
                                }
                                maybe_update.map(Ok)
                            })
                        }
                        Err(e) => {
                            warn!("Failed to deserialize delta config for mesh stream: {}", e);
                            None
                        }
                    }
                }
                Ok(update) => {
                    warn!(
                        "Ignoring unknown mesh config update type: {}",
                        update.update_type
                    );
                    None
                }
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                    warn!(
                        "Mesh config stream lagged behind by {} updates — sending full mesh slice to recover",
                        n
                    );
                    let current = config_for_recovery.load_full();
                    match Self::build_mesh_config_update_if_changed(
                        current.as_ref(),
                        slice_request,
                        &previous_slice,
                    ) {
                        Ok((next_slice, Some(update))) => {
                            stream_config = current.as_ref().clone();
                            previous_slice = next_slice;
                            Some(Ok(update))
                        }
                        Ok((_, None)) => {
                            stream_config = current.as_ref().clone();
                            None
                        }
                        Err(e) => Some(Err(e)),
                    }
                }
            }
        });

        let initial_stream = tokio_stream::once(Ok(initial));
        let combined = initial_stream.chain(stream);
        let tracked = TrackedStream {
            inner: Box::pin(combined),
            registry: self.registry.clone(),
            node_id,
            connected_at: now,
            stream_kind: RegistryStreamKind::Mesh,
        };
        Ok(Response::new(Box::pin(tracked)))
    }
}

fn mesh_slice_content_equal(previous: &MeshSlice, next: &MeshSlice) -> bool {
    previous.node_id == next.node_id
        && previous.namespace == next.namespace
        && previous.workload_spiffe_id == next.workload_spiffe_id
        && previous.labels == next.labels
        && previous.workloads == next.workloads
        && previous.services == next.services
        && previous.mesh_policies == next.mesh_policies
        && previous.peer_authentications == next.peer_authentications
        && previous.service_entries == next.service_entries
        && previous.trust_bundles == next.trust_bundles
}

// Version compatibility is tested inline because `check_version_compatibility` is private.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::db_loader::IncrementalResult;
    use crate::config::mesh::{AppProtocol, MeshConfig, MeshService, ServicePort};
    use crate::xds::MeshSlice;
    use chrono::{TimeZone, Utc};

    fn mesh_config_with_service(version_second: u32) -> GatewayConfig {
        mesh_config_with_named_service("api", version_second)
    }

    fn mesh_config_with_named_service(name: &str, version_second: u32) -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![MeshService {
                    name: name.to_string(),
                    namespace: "ferrum".to_string(),
                    ports: vec![ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: Some("http".to_string()),
                    }],
                    workloads: Vec::new(),
                    protocol_overrides: std::collections::HashMap::new(),
                }],
                ..MeshConfig::default()
            })),
            loaded_at: Utc
                .with_ymd_and_hms(2026, 5, 5, 12, 0, version_second)
                .unwrap(),
            ..GatewayConfig::default()
        }
    }

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
    fn registry_mesh_insert_does_not_clobber_dp_snapshot() {
        let registry = DpNodeRegistry::new();
        let dp_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let mesh_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "dp-version", dp_connected_at));
        registry.insert_mesh(registry_info("node-a", "mesh-version", mesh_connected_at));

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].node_id, "node-a");
        assert_eq!(snapshot[0].version, "dp-version");
        assert_eq!(snapshot[0].connected_at, dp_connected_at);
    }

    #[test]
    fn registry_mesh_drop_does_not_remove_active_dp_entry() {
        let registry = DpNodeRegistry::new();
        let dp_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let mesh_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "dp-version", dp_connected_at));
        registry.insert_mesh(registry_info("node-a", "mesh-version", mesh_connected_at));
        registry.remove_mesh_if_stale("node-a", mesh_connected_at);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "dp-version");
        assert_eq!(snapshot[0].connected_at, dp_connected_at);
    }

    #[test]
    fn registry_dp_drop_keeps_active_mesh_entry_visible() {
        let registry = DpNodeRegistry::new();
        let dp_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let mesh_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "dp-version", dp_connected_at));
        registry.insert_mesh(registry_info("node-a", "mesh-version", mesh_connected_at));
        registry.remove_if_stale("node-a", dp_connected_at);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "mesh-version");
        assert_eq!(snapshot[0].connected_at, mesh_connected_at);
    }

    #[test]
    fn registry_mesh_only_entry_is_visible_and_removable() {
        let registry = DpNodeRegistry::new();
        let mesh_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert_mesh(registry_info("node-a", "mesh-version", mesh_connected_at));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.snapshot()[0].version, "mesh-version");

        registry.remove_mesh_if_stale("node-a", mesh_connected_at);
        assert!(registry.is_empty());
    }

    #[test]
    fn mesh_delta_update_skips_unchanged_mesh_slice_content() {
        let mut stream_config = mesh_config_with_service(0);
        let poll_timestamp = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 42).unwrap();
        let delta = IncrementalResult {
            added_or_modified_proxies: Vec::new(),
            removed_proxy_ids: Vec::new(),
            added_or_modified_consumers: Vec::new(),
            removed_consumer_ids: Vec::new(),
            added_or_modified_plugin_configs: Vec::new(),
            removed_plugin_config_ids: Vec::new(),
            added_or_modified_upstreams: Vec::new(),
            removed_upstream_ids: vec!["stale-upstream".to_string()],
            poll_timestamp,
        };
        let slice_request = MeshSliceRequest::from_native(
            "node-a".to_string(),
            "ferrum".to_string(),
            String::new(),
            std::collections::HashMap::new(),
        );
        let previous_slice = MeshSlice::from_gateway_config(&stream_config, slice_request.clone());
        let (next_slice, update) = CpGrpcServer::apply_mesh_delta_to_stream_config(
            &mut stream_config,
            delta,
            slice_request,
            &previous_slice,
        )
        .expect("mesh delta should build");

        assert!(update.is_none());
        assert_eq!(stream_config.loaded_at, poll_timestamp);
        assert_eq!(next_slice.version, poll_timestamp.to_rfc3339());
        assert_eq!(next_slice.services.len(), 1);
    }

    #[test]
    fn mesh_full_update_emits_when_mesh_slice_content_changes() {
        let stream_config = mesh_config_with_named_service("stream-local", 0);
        let next_config = mesh_config_with_named_service("new-service", 43);
        let slice_request = MeshSliceRequest::from_native(
            "node-a".to_string(),
            "ferrum".to_string(),
            String::new(),
            std::collections::HashMap::new(),
        );
        let previous_slice = MeshSlice::from_gateway_config(&stream_config, slice_request.clone());
        let (_next_slice, update) = CpGrpcServer::build_mesh_config_update_if_changed(
            &next_config,
            slice_request,
            &previous_slice,
        )
        .expect("mesh full update should build");
        let update = update.expect("changed mesh content should emit an update");
        let slice: MeshSlice =
            serde_json::from_str(&update.mesh_slice_json).expect("mesh slice should deserialize");

        assert_eq!(slice.version, next_config.loaded_at.to_rfc3339());
        assert_eq!(slice.services[0].name, "new-service");
        assert_eq!(
            stream_config.mesh.as_ref().unwrap().services[0].name,
            "stream-local"
        );
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
