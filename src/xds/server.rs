//! gRPC `AggregatedDiscoveryService` implementation.
//!
//! Both `StreamAggregatedResources` (SotW) and
//! `DeltaAggregatedResources` (delta) are wired through the same
//! [`FerrumXdsServer`] state. Each gRPC stream gets its own
//! [`StreamSubscription`] map (one entry per type_url) so per-type
//! ACK/NACK state is isolated.
//!
//! ## Stream lifecycle
//!
//! 1. Client opens stream → server reads first request, parses
//!    `Node`, looks up or builds the per-node snapshot.
//! 2. Server emits one response per type_url the client asked about
//!    (LDS / CDS for "wildcard" subscriptions; RDS / EDS / SDS for
//!    name-scoped).
//! 3. Client ACKs (or NACKs) each response with the matching nonce.
//! 4. Whenever `GatewayConfig` reloads, the broadcast channel signals
//!    every active stream; streams whose node snapshot changed re-emit.
//! 5. Stream drop → snapshot stays in cache (cheap to keep; cheaper to
//!    re-use on reconnect than re-slice the full config).

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use envoy_types::pb::envoy::service::discovery::v3::aggregated_discovery_service_server::{
    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
};
use envoy_types::pb::envoy::service::discovery::v3::{
    DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

use super::delta;
use super::node::ParsedNode;
use super::snapshot::{NodeIdentity, StreamSubscription, XdsSnapshot};
use super::{ResourceType, XdsState};

/// Capacity of the per-stream response channel. The xDS protocol is
/// strictly sequential (one outstanding response per type per stream)
/// so a small buffer is sufficient; anything larger just means lagged
/// responses pile up in memory.
const STREAM_RESPONSE_BUFFER: usize = 16;

/// Server state for the Ferrum xDS ADS service.
///
/// Holds an `Arc` to the shared [`XdsState`] (snapshot cache + live
/// `GatewayConfig` reference) plus the JWT secret for authenticating
/// xDS clients.
pub struct FerrumXdsServer {
    state: Arc<XdsState>,
    jwt_secret: Option<String>,
    /// When true, refuse subscriptions that arrive without a
    /// JWT-validated client. Populated from `FERRUM_XDS_REQUIRE_AUTHENTICATED_CLIENT`.
    require_auth: bool,
}

impl FerrumXdsServer {
    pub fn new(state: Arc<XdsState>, jwt_secret: Option<String>, require_auth: bool) -> Self {
        Self {
            state,
            jwt_secret,
            require_auth,
        }
    }

    pub fn into_service(self) -> AggregatedDiscoveryServiceServer<Self> {
        AggregatedDiscoveryServiceServer::new(self)
    }

    fn verify_jwt(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
        let Some(secret) = self.jwt_secret.as_ref() else {
            if self.require_auth {
                return Err(Status::unauthenticated(
                    "xDS server requires authentication but no JWT secret is configured",
                ));
            }
            return Ok(());
        };
        let token = match metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.strip_prefix("Bearer ").unwrap_or(s))
        {
            Some(t) => t,
            None => {
                if self.require_auth {
                    return Err(Status::unauthenticated("Missing authorization token"));
                }
                return Ok(());
            }
        };
        let key = DecodingKey::from_secret(secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        decode::<Value>(token, &key, &validation)
            .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;
        Ok(())
    }
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for FerrumXdsServer {
    type StreamAggregatedResourcesStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<DiscoveryResponse, Status>> + Send>>;

    async fn stream_aggregated_resources(
        &self,
        request: Request<Streaming<DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
        self.verify_jwt(request.metadata())?;

        let mut req_stream = request.into_inner();
        let (tx, rx) =
            tokio::sync::mpsc::channel::<Result<DiscoveryResponse, Status>>(STREAM_RESPONSE_BUFFER);

        let state = self.state.clone();
        let mut broadcast_rx = state.broadcast.subscribe();

        tokio::spawn(async move {
            // Per-stream ACK/NACK state per type_url.
            let mut subs: HashMap<ResourceType, StreamSubscription> = HashMap::new();
            // Identity is established on the first message; subsequent
            // messages on the same stream are guaranteed to carry the
            // same node (per xDS spec).
            let mut identity: Option<NodeIdentity> = None;

            loop {
                tokio::select! {
                    biased;
                    incoming = req_stream.next() => {
                        match incoming {
                            Some(Ok(req)) => {
                                if let Err(e) = handle_request(
                                    req,
                                    &state,
                                    &mut identity,
                                    &mut subs,
                                    &tx,
                                ).await {
                                    let _ = tx.send(Err(e)).await;
                                    break;
                                }
                            }
                            Some(Err(e)) => {
                                warn!("xDS stream client error: {}", e);
                                let _ = tx.send(Err(e)).await;
                                break;
                            }
                            None => {
                                // Stream closed by client.
                                if let Some(id) = identity.as_ref() {
                                    info!("xDS stream closed for node '{}'", id.node_id);
                                    state.snapshots.evict(&id.node_id);
                                }
                                break;
                            }
                        }
                    }
                    refresh = broadcast_rx.recv() => {
                        match refresh {
                            Ok(signal) => {
                                if let Some(id) = identity.as_ref()
                                    && signal.node_id == id.node_id
                                    && let Err(e) = emit_all_subscribed(
                                        &state, id, &mut subs, &tx,
                                    ).await
                                {
                                    let _ = tx.send(Err(e)).await;
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                // Mesh xDS streams that lag the broadcast just resync
                                // by re-reading the latest snapshot — they cannot
                                // miss a config update because the snapshot itself is
                                // monotonic.
                                debug!("xDS broadcast lagged by {} updates — re-emitting from snapshot", n);
                                if let Some(id) = identity.as_ref()
                                    && let Err(e) = emit_all_subscribed(
                                        &state, id, &mut subs, &tx,
                                    ).await {
                                    let _ = tx.send(Err(e)).await;
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                // Server shutting down.
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    type DeltaAggregatedResourcesStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<DeltaDiscoveryResponse, Status>> + Send>>;

    async fn delta_aggregated_resources(
        &self,
        request: Request<Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        self.verify_jwt(request.metadata())?;

        let mut req_stream = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<DeltaDiscoveryResponse, Status>>(
            STREAM_RESPONSE_BUFFER,
        );

        let state = self.state.clone();
        let mut broadcast_rx = state.broadcast.subscribe();

        tokio::spawn(async move {
            let mut subs: HashMap<ResourceType, StreamSubscription> = HashMap::new();
            let mut identity: Option<NodeIdentity> = None;
            // For delta we also need to remember the *previous* snapshot
            // to diff against. Per type because each type ACKs
            // independently.
            let mut prev_snapshots: HashMap<ResourceType, Arc<XdsSnapshot>> = HashMap::new();

            loop {
                tokio::select! {
                    biased;
                    incoming = req_stream.next() => {
                        match incoming {
                            Some(Ok(req)) => {
                                if let Err(e) = handle_delta_request(
                                    req,
                                    &state,
                                    &mut identity,
                                    &mut subs,
                                    &mut prev_snapshots,
                                    &tx,
                                ).await {
                                    let _ = tx.send(Err(e)).await;
                                    break;
                                }
                            }
                            Some(Err(e)) => {
                                warn!("xDS delta stream client error: {}", e);
                                let _ = tx.send(Err(e)).await;
                                break;
                            }
                            None => {
                                if let Some(id) = identity.as_ref() {
                                    info!("xDS delta stream closed for node '{}'", id.node_id);
                                    state.snapshots.evict(&id.node_id);
                                }
                                break;
                            }
                        }
                    }
                    refresh = broadcast_rx.recv() => {
                        match refresh {
                            Ok(signal) => {
                                if let Some(id) = identity.as_ref()
                                    && signal.node_id == id.node_id
                                    && let Err(e) = emit_delta_for_subscribed(
                                        &state, id, &mut subs, &mut prev_snapshots, &tx,
                                    ).await
                                {
                                    let _ = tx.send(Err(e)).await;
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                debug!("xDS delta broadcast lagged by {} updates", n);
                                if let Some(id) = identity.as_ref()
                                    && let Err(e) = emit_delta_for_subscribed(
                                        &state, id, &mut subs, &mut prev_snapshots, &tx,
                                    ).await {
                                    let _ = tx.send(Err(e)).await;
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

async fn handle_request(
    req: DiscoveryRequest,
    state: &Arc<XdsState>,
    identity: &mut Option<NodeIdentity>,
    subs: &mut HashMap<ResourceType, StreamSubscription>,
    tx: &tokio::sync::mpsc::Sender<Result<DiscoveryResponse, Status>>,
) -> Result<(), Status> {
    // Establish identity from the first message. Subsequent messages may
    // omit `node` (per xDS spec — the server caches per-stream).
    if identity.is_none() {
        let Some(node) = req.node.as_ref() else {
            return Err(Status::invalid_argument(
                "first request on xDS stream must carry Node",
            ));
        };
        let parsed = ParsedNode::from_envoy(node)
            .map_err(|e| Status::invalid_argument(format!("invalid xDS Node: {}", e)))?;
        let new_identity = NodeIdentity {
            node_id: parsed.id.clone(),
            namespace: parsed.namespace.clone(),
            spiffe_id: parsed.spiffe_id.clone(),
        };
        info!(
            "xDS SotW stream opened: node='{}' namespace='{}' spiffe_id={}",
            new_identity.node_id,
            new_identity.namespace,
            new_identity
                .spiffe_id
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<none>".into())
        );
        *identity = Some(new_identity);
    }
    let identity = identity.as_ref().expect("identity initialised above");

    let Some(ty) = ResourceType::from_type_url(&req.type_url) else {
        // Unknown type_url — Envoy accepts an empty response.
        debug!(
            "xDS request for unknown type_url '{}', ignoring",
            req.type_url
        );
        return Ok(());
    };

    let sub = subs.entry(ty).or_default();
    // Track subscription set
    if !req.resource_names.is_empty() {
        sub.subscribed = Some(req.resource_names.iter().cloned().collect());
    } else {
        sub.subscribed = None;
    }
    // Record ACK / NACK
    let error = req.error_detail.as_ref().map(|s| s.message.clone());
    sub.record_client_message(Some(&req.response_nonce), &req.version_info, error.clone());
    if error.is_some() {
        warn!(
            "xDS NACK from node '{}' for {}: {:?}",
            identity.node_id,
            ty.type_url(),
            error
        );
        // No response on NACK — client retries with a new request.
        return Ok(());
    }

    // Build / fetch the snapshot.
    let config = state.config.load_full();
    let (snapshot, _changed) = state
        .snapshots
        .ensure_snapshot(identity.clone(), config.as_ref());

    // Suppress redundant emissions.
    let new_version = format!("{}", snapshot.version);
    if !sub.should_emit(&new_version) {
        return Ok(());
    }

    let nonce = mint_nonce();
    let response = DiscoveryResponse {
        version_info: new_version.clone(),
        resources: delta::pack_all(&snapshot, ty),
        type_url: ty.type_url().to_string(),
        nonce: nonce.clone(),
        ..Default::default()
    };
    sub.last_sent_version = Some(new_version);
    sub.last_sent_nonce = Some(nonce);
    if tx.send(Ok(response)).await.is_err() {
        return Err(Status::cancelled("client stream closed"));
    }
    Ok(())
}

async fn handle_delta_request(
    req: DeltaDiscoveryRequest,
    state: &Arc<XdsState>,
    identity: &mut Option<NodeIdentity>,
    subs: &mut HashMap<ResourceType, StreamSubscription>,
    prev_snapshots: &mut HashMap<ResourceType, Arc<XdsSnapshot>>,
    tx: &tokio::sync::mpsc::Sender<Result<DeltaDiscoveryResponse, Status>>,
) -> Result<(), Status> {
    if identity.is_none() {
        let Some(node) = req.node.as_ref() else {
            return Err(Status::invalid_argument(
                "first request on xDS delta stream must carry Node",
            ));
        };
        let parsed = ParsedNode::from_envoy(node)
            .map_err(|e| Status::invalid_argument(format!("invalid xDS Node: {}", e)))?;
        let new_identity = NodeIdentity {
            node_id: parsed.id.clone(),
            namespace: parsed.namespace.clone(),
            spiffe_id: parsed.spiffe_id.clone(),
        };
        info!(
            "xDS delta stream opened: node='{}' namespace='{}'",
            new_identity.node_id, new_identity.namespace
        );
        *identity = Some(new_identity);
    }
    let identity = identity.as_ref().expect("identity initialised above");

    let Some(ty) = ResourceType::from_type_url(&req.type_url) else {
        debug!(
            "xDS delta request for unknown type_url '{}', ignoring",
            req.type_url
        );
        return Ok(());
    };

    let sub = subs.entry(ty).or_default();
    // Apply add/remove subscription deltas.
    let mut current = sub.subscribed.clone().unwrap_or_default();
    for name in &req.resource_names_subscribe {
        current.insert(name.clone());
    }
    for name in &req.resource_names_unsubscribe {
        current.remove(name);
    }
    sub.subscribed = if current.is_empty() {
        None
    } else {
        Some(current)
    };

    let error = req.error_detail.as_ref().map(|s| s.message.clone());
    if error.is_some() {
        sub.last_was_nack = true;
        sub.last_error_detail = error.clone();
        warn!(
            "xDS NACK (delta) from node '{}' for {}: {:?}",
            identity.node_id,
            ty.type_url(),
            error
        );
        return Ok(());
    } else if !req.response_nonce.is_empty() {
        sub.last_was_nack = false;
        sub.last_error_detail = None;
        // Treat any non-NACK message with a nonce as an ACK.
        if sub.last_sent_nonce.as_deref() == Some(&req.response_nonce) {
            sub.last_acked_version = sub.last_sent_version.clone();
        }
    }

    // Compute the diff against the previously sent snapshot for this type.
    let config = state.config.load_full();
    let (curr_snapshot, _changed) = state
        .snapshots
        .ensure_snapshot(identity.clone(), config.as_ref());
    let prev = prev_snapshots.get(&ty).map(|s| s.as_ref());
    let diff = delta::diff(prev, &curr_snapshot, ty, sub.subscribed.as_ref());
    if diff.is_empty() && prev.is_some() {
        // Nothing to send.
        return Ok(());
    }

    let nonce = mint_nonce();
    let response = DeltaDiscoveryResponse {
        system_version_info: format!("{}", curr_snapshot.version),
        resources: diff.added_or_modified,
        type_url: ty.type_url().to_string(),
        removed_resources: diff.removed,
        nonce: nonce.clone(),
        ..Default::default()
    };
    sub.last_sent_version = Some(format!("{}", curr_snapshot.version));
    sub.last_sent_nonce = Some(nonce);
    prev_snapshots.insert(ty, curr_snapshot);
    if tx.send(Ok(response)).await.is_err() {
        return Err(Status::cancelled("client delta stream closed"));
    }
    Ok(())
}

async fn emit_all_subscribed(
    state: &Arc<XdsState>,
    identity: &NodeIdentity,
    subs: &mut HashMap<ResourceType, StreamSubscription>,
    tx: &tokio::sync::mpsc::Sender<Result<DiscoveryResponse, Status>>,
) -> Result<(), Status> {
    let config = state.config.load_full();
    // We always rebuild here. The CP may have already called
    // `recompute_all` before the broadcast hit us, in which case
    // `ensure_snapshot` returns `changed=false` even though the snapshot
    // does represent a new resource set relative to what THIS stream
    // last sent. Per-stream `should_emit(new_version)` is the correct
    // gate — it compares the snapshot version against `last_sent_version`,
    // not against the previously-cached snapshot version.
    let (snapshot, _changed) = state
        .snapshots
        .ensure_snapshot(identity.clone(), config.as_ref());
    for (ty, sub) in subs.iter_mut() {
        let new_version = format!("{}", snapshot.version);
        if !sub.should_emit(&new_version) {
            continue;
        }
        let nonce = mint_nonce();
        let response = DiscoveryResponse {
            version_info: new_version.clone(),
            resources: delta::pack_all(&snapshot, *ty),
            type_url: ty.type_url().to_string(),
            nonce: nonce.clone(),
            ..Default::default()
        };
        sub.last_sent_version = Some(new_version);
        sub.last_sent_nonce = Some(nonce);
        if tx.send(Ok(response)).await.is_err() {
            return Err(Status::cancelled("client stream closed"));
        }
    }
    Ok(())
}

async fn emit_delta_for_subscribed(
    state: &Arc<XdsState>,
    identity: &NodeIdentity,
    subs: &mut HashMap<ResourceType, StreamSubscription>,
    prev_snapshots: &mut HashMap<ResourceType, Arc<XdsSnapshot>>,
    tx: &tokio::sync::mpsc::Sender<Result<DeltaDiscoveryResponse, Status>>,
) -> Result<(), Status> {
    let config = state.config.load_full();
    // Always rebuild and diff per type. The CP may have already called
    // `recompute_all` before this broadcast — `ensure_snapshot` would
    // then report `changed=false` even though the per-type diff against
    // `prev_snapshots` (this stream's last-sent set) is non-empty.
    let (snapshot, _changed) = state
        .snapshots
        .ensure_snapshot(identity.clone(), config.as_ref());
    for (ty, sub) in subs.iter_mut() {
        let prev = prev_snapshots.get(ty).map(|s| s.as_ref());
        let diff = delta::diff(prev, &snapshot, *ty, sub.subscribed.as_ref());
        if diff.is_empty() {
            continue;
        }
        let new_version = format!("{}", snapshot.version);
        let nonce = mint_nonce();
        let response = DeltaDiscoveryResponse {
            system_version_info: new_version.clone(),
            resources: diff.added_or_modified,
            type_url: ty.type_url().to_string(),
            removed_resources: diff.removed,
            nonce: nonce.clone(),
            ..Default::default()
        };
        sub.last_sent_version = Some(new_version);
        sub.last_sent_nonce = Some(nonce);
        prev_snapshots.insert(*ty, snapshot.clone());
        if tx.send(Ok(response)).await.is_err() {
            return Err(Status::cancelled("client delta stream closed"));
        }
    }
    Ok(())
}

fn mint_nonce() -> String {
    // 16 bytes of randomness, hex-encoded — same shape as Envoy's pilot
    // emits, fits in a metadata field. Falls back to a UUID if the
    // system RNG is unavailable (vanishingly unlikely on every
    // supported platform).
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 16];
    if rng.fill(&mut bytes).is_ok() {
        hex::encode(bytes)
    } else {
        uuid::Uuid::new_v4().to_string()
    }
}
