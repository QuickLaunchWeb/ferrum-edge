use arc_swap::ArcSwap;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

use super::nonce::{AckOutcome, XdsNonceTracker};
use super::proto::aggregated_discovery_service_server::{
    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
};
use super::proto::{
    ControlPlane, DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest,
    DiscoveryResponse,
};
use super::slice::{MeshSlice, MeshSliceRequest};
use super::snapshot::{XdsSnapshot, XdsSnapshotCache};
use super::translator::translate_mesh_slice_to_snapshot;
use crate::FERRUM_VERSION;
use crate::config::types::GatewayConfig;
use crate::grpc::cp_server::CpGrpcServer;
use crate::grpc::proto::ConfigUpdate;

#[derive(Debug, Clone, PartialEq, Eq)]
struct XdsSubscription {
    node_id: String,
    type_url: String,
    resource_names: Vec<String>,
    wildcard: bool,
    legacy_wildcard: bool,
}

/// Envoy ADS implementation for Phase B.
#[derive(Clone)]
pub struct XdsAdsServer {
    config: Arc<ArcSwap<GatewayConfig>>,
    update_tx: broadcast::Sender<ConfigUpdate>,
    jwt_secret: String,
    expected_issuer: String,
    namespace: String,
    snapshot_cache: Arc<XdsSnapshotCache>,
    nonce_tracker: Arc<XdsNonceTracker>,
    active_streams: Arc<XdsStreamRegistry>,
}

#[derive(Default)]
struct XdsStreamRegistry {
    // ADS stream counts are outside the proxy hot path and exist only when
    // FERRUM_XDS_ENABLED=true, so default DashMap sharding is intentional here.
    counts: DashMap<String, usize>,
}

impl XdsStreamRegistry {
    fn register(&self, node_id: &str) {
        match self.counts.entry(node_id.to_string()) {
            Entry::Occupied(mut entry) => {
                *entry.get_mut() += 1;
            }
            Entry::Vacant(entry) => {
                entry.insert(1);
            }
        }
    }

    fn unregister(&self, node_id: &str) -> bool {
        match self.counts.entry(node_id.to_string()) {
            Entry::Occupied(mut entry) => {
                if *entry.get() > 1 {
                    *entry.get_mut() -= 1;
                    false
                } else {
                    entry.remove();
                    true
                }
            }
            Entry::Vacant(_) => true,
        }
    }
}

struct XdsStreamGuard {
    node_id: Option<String>,
    snapshot_cache: Arc<XdsSnapshotCache>,
    nonce_tracker: Arc<XdsNonceTracker>,
    active_streams: Arc<XdsStreamRegistry>,
}

impl XdsStreamGuard {
    fn new(
        snapshot_cache: Arc<XdsSnapshotCache>,
        nonce_tracker: Arc<XdsNonceTracker>,
        active_streams: Arc<XdsStreamRegistry>,
    ) -> Self {
        Self {
            node_id: None,
            snapshot_cache,
            nonce_tracker,
            active_streams,
        }
    }

    fn set_node_id(&mut self, node_id: &str) {
        if self.node_id.as_deref() == Some(node_id) {
            return;
        }
        self.clear_current();
        self.active_streams.register(node_id);
        self.node_id = Some(node_id.to_string());
    }

    fn clear_current(&mut self) {
        let Some(node_id) = self.node_id.take() else {
            return;
        };
        if self.active_streams.unregister(&node_id) {
            self.snapshot_cache.remove(&node_id);
            self.nonce_tracker.remove_node(&node_id);
        }
    }
}

impl Drop for XdsStreamGuard {
    fn drop(&mut self) {
        self.clear_current();
    }
}

impl XdsAdsServer {
    pub fn new(
        config: Arc<ArcSwap<GatewayConfig>>,
        update_tx: broadcast::Sender<ConfigUpdate>,
        jwt_secret: String,
        expected_issuer: String,
        namespace: String,
    ) -> Self {
        Self {
            config,
            update_tx,
            jwt_secret,
            expected_issuer,
            namespace,
            snapshot_cache: Arc::new(XdsSnapshotCache::new()),
            nonce_tracker: Arc::new(XdsNonceTracker::new()),
            active_streams: Arc::new(XdsStreamRegistry::default()),
        }
    }

    pub fn into_service(self) -> AggregatedDiscoveryServiceServer<Self> {
        AggregatedDiscoveryServiceServer::new(self)
    }

    pub fn snapshot_cache(&self) -> Arc<XdsSnapshotCache> {
        self.snapshot_cache.clone()
    }

    pub fn nonce_tracker(&self) -> Arc<XdsNonceTracker> {
        self.nonce_tracker.clone()
    }

    #[allow(clippy::result_large_err)]
    fn verify_jwt_metadata(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
        let token = metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.strip_prefix("Bearer ").unwrap_or(value))
            .ok_or_else(|| Status::unauthenticated("Missing authorization token"))?;

        let key = DecodingKey::from_secret(self.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
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
            .map_err(|err| Status::unauthenticated(format!("Invalid token: {err}")))?;
        Ok(())
    }

    fn rebuild_snapshot(&self, node_id: &str) -> XdsSnapshot {
        let config = self.config.load_full();
        self.rebuild_snapshot_from_config(node_id, config.as_ref())
    }

    fn rebuild_snapshot_from_config(&self, node_id: &str, config: &GatewayConfig) -> XdsSnapshot {
        let request = MeshSliceRequest::from_xds_node(node_id.to_string(), self.namespace.clone());
        let slice = MeshSlice::from_gateway_config(config, request);
        translate_mesh_slice_to_snapshot(&slice)
    }

    fn snapshot_for_config(&self, node_id: &str, config: &GatewayConfig) -> Arc<XdsSnapshot> {
        let version = config.loaded_at.to_rfc3339();
        if let Some(snapshot) = self.snapshot_cache.get(node_id)
            && snapshot.version == version
        {
            return snapshot;
        }

        self.snapshot_cache
            .insert(self.rebuild_snapshot_from_config(node_id, config))
    }

    fn stream_guard(&self) -> XdsStreamGuard {
        XdsStreamGuard::new(
            self.snapshot_cache.clone(),
            self.nonce_tracker.clone(),
            self.active_streams.clone(),
        )
    }

    fn sotw_response(
        &self,
        snapshot: &XdsSnapshot,
        subscription: &XdsSubscription,
    ) -> DiscoveryResponse {
        let nonce = self.nonce_tracker.issue_nonce(
            &snapshot.node_id,
            &subscription.type_url,
            &snapshot.version,
        );
        DiscoveryResponse {
            version_info: snapshot.version.clone(),
            resources: snapshot
                .filtered_resources(
                    &subscription.type_url,
                    &subscription.resource_names,
                    subscription.wildcard,
                )
                .into_iter()
                .map(|resource| resource.to_any())
                .collect(),
            canary: false,
            type_url: subscription.type_url.clone(),
            nonce,
            control_plane: Some(ControlPlane {
                identifier: format!("ferrum-edge/{FERRUM_VERSION}"),
            }),
        }
    }

    fn delta_response(
        &self,
        snapshot: &XdsSnapshot,
        previous: Option<&XdsSnapshot>,
        subscription: &XdsSubscription,
        initial_resource_versions: &HashMap<String, String>,
        explicitly_subscribed_names: &[String],
    ) -> DeltaDiscoveryResponse {
        let nonce = self.nonce_tracker.issue_nonce(
            &snapshot.node_id,
            &subscription.type_url,
            &snapshot.version,
        );
        let resources = snapshot.filtered_resources(
            &subscription.type_url,
            &subscription.resource_names,
            subscription.wildcard,
        );
        let current_names: HashSet<String> = snapshot
            .resources(&subscription.type_url)
            .into_iter()
            .map(|r| r.name)
            .collect();
        let mut removed_resources = if initial_resource_versions.is_empty() {
            previous
                .map(|prev| prev.removed_resource_names(snapshot, &subscription.type_url))
                .unwrap_or_default()
        } else {
            let mut removed: Vec<String> = initial_resource_versions
                .keys()
                .filter(|name| !current_names.contains(*name))
                .cloned()
                .collect();
            removed.sort();
            removed.dedup();
            removed
        };
        if !subscription.wildcard && !removed_resources.is_empty() {
            if subscription.resource_names.is_empty() {
                removed_resources.clear();
            } else {
                let wanted: HashSet<&str> = subscription
                    .resource_names
                    .iter()
                    .map(String::as_str)
                    .collect();
                removed_resources.retain(|name| wanted.contains(name.as_str()));
            }
        }
        let subscribed: HashSet<&str> = subscription
            .resource_names
            .iter()
            .map(String::as_str)
            .collect();
        for name in explicitly_subscribed_names {
            if name == "*"
                || current_names.contains(name)
                || (!subscription.wildcard && !subscribed.contains(name.as_str()))
            {
                continue;
            }
            removed_resources.push(name.clone());
        }
        removed_resources.sort();
        removed_resources.dedup();
        DeltaDiscoveryResponse {
            system_version_info: snapshot.version.clone(),
            resources: resources
                .into_iter()
                .map(|resource| resource.to_delta_resource())
                .collect(),
            type_url: subscription.type_url.clone(),
            nonce,
            removed_resources,
        }
    }

    fn sotw_responses_for_subscriptions(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
    ) -> Vec<DiscoveryResponse> {
        let config = self.config.load_full();
        self.sotw_responses_for_subscriptions_from_config(node_id, subscriptions, config.as_ref())
    }

    fn sotw_responses_for_subscriptions_from_config(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        config: &GatewayConfig,
    ) -> Vec<DiscoveryResponse> {
        let previous = self.snapshot_cache.get(node_id);
        let snapshot = self.snapshot_for_config(node_id, config);
        subscriptions
            .values()
            .filter(|subscription| {
                subscription_resources_changed(previous.as_deref(), &snapshot, subscription)
            })
            .map(|subscription| self.sotw_response(&snapshot, subscription))
            .collect()
    }

    fn sotw_response_for_request(
        &self,
        node_id: &str,
        config: &GatewayConfig,
        subscriptions: &mut HashMap<String, XdsSubscription>,
        request: &DiscoveryRequest,
    ) -> Option<DiscoveryResponse> {
        if !request.response_nonce.is_empty() {
            match self.record_sotw_ack(node_id, request) {
                AckOutcome::Acked => debug!(
                    node_id = %node_id,
                    type_url = %request.type_url,
                    "xDS ACK accepted"
                ),
                AckOutcome::Nacked { message } => {
                    warn!(
                        node_id = %node_id,
                        type_url = %request.type_url,
                        error = %message,
                        "xDS NACK received"
                    );
                }
                outcome => {
                    warn!(
                        node_id = %node_id,
                        type_url = %request.type_url,
                        outcome = ?outcome,
                        "xDS ACK ignored"
                    );
                }
            }
        }

        let previous_subscription = subscriptions.get(&request.type_url).cloned();
        let subscription = build_sotw_subscription(
            previous_subscription.as_ref(),
            node_id,
            &request.type_url,
            &request.resource_names,
        );
        let resource_names_changed = previous_subscription
            .as_ref()
            .is_none_or(|previous| previous != &subscription);
        subscriptions.insert(request.type_url.clone(), subscription.clone());
        if should_send_sotw_response(request, resource_names_changed) {
            let snapshot = self.snapshot_for_config(node_id, config);
            if !request.response_nonce.is_empty()
                && !subscription_change_affects_resources(
                    &snapshot,
                    previous_subscription.as_ref(),
                    &subscription,
                )
            {
                return None;
            }
            Some(self.sotw_response(&snapshot, &subscription))
        } else {
            None
        }
    }

    fn delta_responses_for_subscriptions(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
    ) -> Vec<DeltaDiscoveryResponse> {
        let config = self.config.load_full();
        self.delta_responses_for_subscriptions_from_config(node_id, subscriptions, config.as_ref())
    }

    fn delta_responses_for_subscriptions_from_config(
        &self,
        node_id: &str,
        subscriptions: &HashMap<String, XdsSubscription>,
        config: &GatewayConfig,
    ) -> Vec<DeltaDiscoveryResponse> {
        let previous = self.snapshot_cache.get(node_id);
        let snapshot = self.snapshot_for_config(node_id, config);
        subscriptions
            .values()
            .filter(|subscription| {
                subscription_resources_changed(previous.as_deref(), &snapshot, subscription)
            })
            .map(|subscription| {
                self.delta_response(
                    &snapshot,
                    previous.as_deref(),
                    subscription,
                    &HashMap::new(),
                    &[],
                )
            })
            .collect()
    }

    fn record_sotw_ack(&self, node_id: &str, request: &DiscoveryRequest) -> AckOutcome {
        let error_message = request
            .error_detail
            .as_ref()
            .filter(|detail| detail.code != 0 || !detail.message.is_empty())
            .map(|detail| detail.message.as_str());
        self.nonce_tracker.record_response(
            node_id,
            &request.type_url,
            &request.response_nonce,
            &request.version_info,
            error_message,
        )
    }

    fn record_delta_ack(&self, node_id: &str, request: &DeltaDiscoveryRequest) -> AckOutcome {
        let error_message = request
            .error_detail
            .as_ref()
            .filter(|detail| detail.code != 0 || !detail.message.is_empty())
            .map(|detail| detail.message.as_str());
        self.nonce_tracker.record_response(
            node_id,
            &request.type_url,
            &request.response_nonce,
            "",
            error_message,
        )
    }

    fn apply_update_to_stream_config(
        stream_config: &mut GatewayConfig,
        update: &ConfigUpdate,
    ) -> bool {
        match update.update_type {
            0 => match serde_json::from_str::<GatewayConfig>(&update.config_json) {
                Ok(mut config) => {
                    config.normalize_fields();
                    *stream_config = config;
                    true
                }
                Err(err) => {
                    warn!("Failed to deserialize full config for xDS stream: {}", err);
                    false
                }
            },
            1 => match serde_json::from_str::<crate::config::db_loader::IncrementalResult>(
                &update.config_json,
            ) {
                Ok(delta) => {
                    CpGrpcServer::apply_incremental_to_config_snapshot(stream_config, delta);
                    stream_config.normalize_fields();
                    true
                }
                Err(err) => {
                    warn!("Failed to deserialize delta config for xDS stream: {}", err);
                    false
                }
            },
            update_type => {
                warn!("Ignoring unknown xDS config update type: {}", update_type);
                false
            }
        }
    }

    fn catch_up_pending_updates(
        &self,
        updates: &mut broadcast::Receiver<ConfigUpdate>,
        stream_config: &mut GatewayConfig,
    ) {
        loop {
            match updates.try_recv() {
                Ok(update) => {
                    Self::apply_update_to_stream_config(stream_config, &update);
                }
                Err(broadcast::error::TryRecvError::Empty) => return,
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    warn!(
                        "xDS ADS stream lagged by {} config updates while catching up; using current shared snapshot",
                        n
                    );
                    let current = self.config.load_full();
                    *stream_config = current.as_ref().clone();
                }
                Err(broadcast::error::TryRecvError::Closed) => return,
            }
        }
    }
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for XdsAdsServer {
    type StreamAggregatedResourcesStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<DiscoveryResponse, Status>> + Send>>;
    type DeltaAggregatedResourcesStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<DeltaDiscoveryResponse, Status>> + Send>>;

    async fn stream_aggregated_resources(
        &self,
        request: Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
        self.verify_jwt_metadata(request.metadata())?;

        let mut requests = request.into_inner();
        let server = self.clone();
        let mut updates = server.update_tx.subscribe();
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            let mut stream_guard = server.stream_guard();
            let mut node_id: Option<String> = None;
            let mut subscriptions: HashMap<String, XdsSubscription> = HashMap::new();
            let mut stream_config = server.config.load_full().as_ref().clone();
            loop {
                tokio::select! {
                    maybe_request = requests.next() => {
                        let Some(request) = maybe_request else {
                            return;
                        };
                        let request = match request {
                            Ok(request) => request,
                            Err(err) => {
                                let _ = tx.send(Err(Status::internal(format!("ADS request stream error: {err}")))).await;
                                return;
                            }
                        };
                        let current_node_id = match resolve_stream_node_id(
                            node_id.as_deref(),
                            request.node.as_ref().and_then(|node| non_empty_string(&node.id)),
                        ) {
                            Ok(node_id) => node_id,
                            Err(status) => {
                                let _ = tx.send(Err(status)).await;
                                return;
                            }
                        };
                        if node_id.is_none() {
                            stream_guard.set_node_id(&current_node_id);
                            node_id = Some(current_node_id.clone());
                        };

                        if request.type_url.is_empty() {
                            let _ = tx.send(Err(Status::invalid_argument("xDS type_url is required"))).await;
                            return;
                        }
                        if subscriptions.is_empty() {
                            server.catch_up_pending_updates(&mut updates, &mut stream_config);
                        }

                        let send_failed = if let Some(response) = server.sotw_response_for_request(
                            &current_node_id,
                            &stream_config,
                            &mut subscriptions,
                            &request,
                        )
                        {
                            tx.send(Ok(response)).await.is_err()
                        } else {
                            false
                        };
                        if send_failed {
                            return;
                        }
                    }
                    update = updates.recv() => {
                        match update {
                            Ok(update) => {
                                if !Self::apply_update_to_stream_config(&mut stream_config, &update) {
                                    continue;
                                }
                                let Some(current_node_id) = node_id.as_ref() else {
                                    continue;
                                };
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                for response in server.sotw_responses_for_subscriptions_from_config(
                                    current_node_id,
                                    &subscriptions,
                                    &stream_config,
                                ) {
                                    if tx.send(Ok(response)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("xDS ADS stream lagged by {} config updates; sending fresh snapshots", n);
                                let current = server.config.load_full();
                                stream_config = current.as_ref().clone();
                                let Some(current_node_id) = node_id.as_ref() else {
                                    continue;
                                };
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                for response in server.sotw_responses_for_subscriptions_from_config(
                                    current_node_id,
                                    &subscriptions,
                                    &stream_config,
                                ) {
                                    if tx.send(Ok(response)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn delta_aggregated_resources(
        &self,
        request: Request<tonic::Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        self.verify_jwt_metadata(request.metadata())?;

        let mut requests = request.into_inner();
        let server = self.clone();
        let mut updates = server.update_tx.subscribe();
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            let mut stream_guard = server.stream_guard();
            let mut node_id: Option<String> = None;
            let mut subscriptions: HashMap<String, XdsSubscription> = HashMap::new();
            let mut stream_config = server.config.load_full().as_ref().clone();
            loop {
                tokio::select! {
                    maybe_request = requests.next() => {
                        let Some(request) = maybe_request else {
                            return;
                        };
                        let request = match request {
                            Ok(request) => request,
                            Err(err) => {
                                let _ = tx.send(Err(Status::internal(format!("Delta ADS request stream error: {err}")))).await;
                                return;
                            }
                        };
                        let current_node_id = match resolve_stream_node_id(
                            node_id.as_deref(),
                            request.node.as_ref().and_then(|node| non_empty_string(&node.id)),
                        ) {
                            Ok(node_id) => node_id,
                            Err(status) => {
                                let _ = tx.send(Err(status)).await;
                                return;
                            }
                        };
                        if node_id.is_none() {
                            stream_guard.set_node_id(&current_node_id);
                            node_id = Some(current_node_id.clone());
                        };

                        if request.type_url.is_empty() {
                            let _ = tx.send(Err(Status::invalid_argument("xDS type_url is required"))).await;
                            return;
                        }
                        if subscriptions.is_empty() {
                            server.catch_up_pending_updates(&mut updates, &mut stream_config);
                        }

                        if !request.response_nonce.is_empty() {
                            match server.record_delta_ack(&current_node_id, &request) {
                                AckOutcome::Acked | AckOutcome::VersionDrift { .. } => debug!(
                                    node_id = %current_node_id,
                                    type_url = %request.type_url,
                                    "xDS delta ACK accepted"
                                ),
                                AckOutcome::Nacked { message } => {
                                    warn!(
                                        node_id = %current_node_id,
                                        type_url = %request.type_url,
                                        error = %message,
                                        "xDS delta NACK received"
                                    );
                                }
                                outcome => {
                                    warn!(
                                        node_id = %current_node_id,
                                        type_url = %request.type_url,
                                        outcome = ?outcome,
                                        "xDS delta ACK ignored"
                                    );
                                }
                            }
                        }

                        let previous_subscription = subscriptions.get(&request.type_url);
                        let (subscription, resource_names_changed, explicit_subscription_request) =
                            build_delta_subscription(
                                previous_subscription,
                                &current_node_id,
                                &request.type_url,
                                &request.resource_names_subscribe,
                                &request.resource_names_unsubscribe,
                            );
                        subscriptions.insert(request.type_url.clone(), subscription.clone());
                        if should_send_delta_response(
                            &request,
                            resource_names_changed,
                            explicit_subscription_request,
                        ) {
                            let previous = server.snapshot_cache.get(&current_node_id);
                            let snapshot =
                                server.snapshot_for_config(&current_node_id, &stream_config);
                            let response = server.delta_response(
                                &snapshot,
                                previous.as_deref(),
                                &subscription,
                                &request.initial_resource_versions,
                                &request.resource_names_subscribe,
                            );
                            if tx.send(Ok(response)).await.is_err() {
                                return;
                            }
                        }
                    }
                    update = updates.recv() => {
                        match update {
                            Ok(update) => {
                                if !Self::apply_update_to_stream_config(&mut stream_config, &update) {
                                    continue;
                                }
                                let Some(current_node_id) = node_id.as_ref() else {
                                    continue;
                                };
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                for response in server.delta_responses_for_subscriptions_from_config(
                                    current_node_id,
                                    &subscriptions,
                                    &stream_config,
                                ) {
                                    if tx.send(Ok(response)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("xDS delta ADS stream lagged by {} config updates; sending fresh snapshots", n);
                                let current = server.config.load_full();
                                stream_config = current.as_ref().clone();
                                let Some(current_node_id) = node_id.as_ref() else {
                                    continue;
                                };
                                if subscriptions.is_empty() {
                                    continue;
                                }
                                for response in server.delta_responses_for_subscriptions_from_config(
                                    current_node_id,
                                    &subscriptions,
                                    &stream_config,
                                ) {
                                    if tx.send(Ok(response)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

fn non_empty_string(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn resolve_stream_node_id(
    current: Option<&str>,
    requested: Option<String>,
) -> Result<String, Status> {
    match (current, requested) {
        (None, Some(requested)) => Ok(requested),
        (None, None) => Err(Status::invalid_argument("xDS Node.id is required")),
        (Some(current), None) => Ok(current.to_string()),
        (Some(current), Some(requested)) if requested == current => Ok(requested),
        (Some(current), Some(requested)) => Err(Status::invalid_argument(format!(
            "xDS Node.id cannot change on an established stream: {current} -> {requested}"
        ))),
    }
}

fn subscription_resources_changed(
    previous: Option<&XdsSnapshot>,
    snapshot: &XdsSnapshot,
    subscription: &XdsSubscription,
) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    let previous_resources = previous.filtered_resources(
        &subscription.type_url,
        &subscription.resource_names,
        subscription.wildcard,
    );
    let next_resources = snapshot.filtered_resources(
        &subscription.type_url,
        &subscription.resource_names,
        subscription.wildcard,
    );
    !resources_equal_ignoring_version(&previous_resources, &next_resources)
}

fn subscription_change_affects_resources(
    snapshot: &XdsSnapshot,
    previous: Option<&XdsSubscription>,
    next: &XdsSubscription,
) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    let previous_resources = snapshot.filtered_resources(
        &previous.type_url,
        &previous.resource_names,
        previous.wildcard,
    );
    let next_resources =
        snapshot.filtered_resources(&next.type_url, &next.resource_names, next.wildcard);
    !resources_equal_ignoring_version(&previous_resources, &next_resources)
}

fn resources_equal_ignoring_version(
    left: &[super::snapshot::XdsResource],
    right: &[super::snapshot::XdsResource],
) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.name == right.name && left.type_url == right.type_url && left.value == right.value
        })
}

fn build_sotw_subscription(
    previous: Option<&XdsSubscription>,
    node_id: &str,
    type_url: &str,
    resource_names: &[String],
) -> XdsSubscription {
    let has_wildcard = resource_names.iter().any(|name| name == "*");
    let legacy_wildcard = resource_names.is_empty()
        && !has_wildcard
        && previous.is_none_or(|subscription| {
            subscription.legacy_wildcard && subscription.resource_names.is_empty()
        });
    let mut resource_names = resource_names
        .iter()
        .filter(|name| name.as_str() != "*")
        .cloned()
        .collect::<Vec<_>>();
    resource_names.sort();
    resource_names.dedup();

    XdsSubscription {
        node_id: node_id.to_string(),
        type_url: type_url.to_string(),
        resource_names,
        wildcard: has_wildcard || legacy_wildcard,
        legacy_wildcard,
    }
}

fn build_delta_subscription(
    previous: Option<&XdsSubscription>,
    node_id: &str,
    type_url: &str,
    resource_names_subscribe: &[String],
    resource_names_unsubscribe: &[String],
) -> (XdsSubscription, bool, bool) {
    let explicit_subscription_request =
        !resource_names_subscribe.is_empty() || !resource_names_unsubscribe.is_empty();
    let mut resource_names = previous
        .map(|subscription| subscription.resource_names.clone())
        .unwrap_or_default();
    let mut wildcard = previous
        .map(|subscription| subscription.wildcard)
        .unwrap_or(!explicit_subscription_request);
    let mut legacy_wildcard = previous
        .map(|subscription| subscription.legacy_wildcard)
        .unwrap_or(!explicit_subscription_request);

    for name in resource_names_subscribe {
        if name == "*" {
            wildcard = true;
            legacy_wildcard = false;
            continue;
        }
        if !resource_names.contains(name) {
            resource_names.push(name.clone());
        }
    }
    if !resource_names_subscribe.is_empty() {
        resource_names.sort();
    }
    if !resource_names_unsubscribe.is_empty() {
        let removed: HashSet<&str> = resource_names_unsubscribe
            .iter()
            .map(String::as_str)
            .collect();
        if removed.contains("*") {
            wildcard = false;
            legacy_wildcard = false;
        }
        resource_names.retain(|name| !removed.contains(name.as_str()));
    }

    let subscription = XdsSubscription {
        node_id: node_id.to_string(),
        type_url: type_url.to_string(),
        resource_names,
        wildcard,
        legacy_wildcard,
    };
    let changed = previous.is_none_or(|previous| previous != &subscription);
    (subscription, changed, explicit_subscription_request)
}

fn should_send_sotw_response(request: &DiscoveryRequest, resource_names_changed: bool) -> bool {
    request.response_nonce.is_empty() || resource_names_changed
}

fn should_send_delta_response(
    request: &DeltaDiscoveryRequest,
    resource_names_changed: bool,
    explicit_subscription_request: bool,
) -> bool {
    request.response_nonce.is_empty()
        || resource_names_changed
        || explicit_subscription_request
        || !request.initial_resource_versions.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::db_loader::IncrementalResult;
    use crate::config::mesh::{AppProtocol, MeshConfig, MeshService, ServicePort};
    use chrono::{TimeZone, Utc};
    use prost::Message;

    fn gateway_config_with_service(include_service: bool, version_second: u32) -> GatewayConfig {
        if include_service {
            gateway_config_with_named_service("api", version_second)
        } else {
            GatewayConfig {
                mesh: Some(Box::new(MeshConfig {
                    services: Vec::new(),
                    ..MeshConfig::default()
                })),
                loaded_at: Utc
                    .with_ymd_and_hms(2026, 5, 5, 12, 0, version_second)
                    .unwrap(),
                ..GatewayConfig::default()
            }
        }
    }

    fn gateway_config_with_named_service(name: &str, version_second: u32) -> GatewayConfig {
        gateway_config_with_services(&[name], version_second)
    }

    fn gateway_config_with_services(names: &[&str], version_second: u32) -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: names.iter().map(|name| mesh_service(name)).collect(),
                ..MeshConfig::default()
            })),
            loaded_at: Utc
                .with_ymd_and_hms(2026, 5, 5, 12, 0, version_second)
                .unwrap(),
            ..GatewayConfig::default()
        }
    }

    fn mesh_service(name: &str) -> MeshService {
        MeshService {
            name: name.to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }
    }

    fn cluster_names(response: &DiscoveryResponse) -> Vec<String> {
        response
            .resources
            .iter()
            .map(|resource| {
                super::super::proto::Cluster::decode(resource.value.as_slice())
                    .expect("cluster resource should decode")
                    .name
            })
            .collect()
    }

    fn delta_cluster_names(response: &DeltaDiscoveryResponse) -> Vec<String> {
        response
            .resources
            .iter()
            .map(|resource| {
                let resource = resource
                    .resource
                    .as_ref()
                    .expect("delta resource should carry an Any payload");
                super::super::proto::Cluster::decode(resource.value.as_slice())
                    .expect("cluster resource should decode")
                    .name
            })
            .collect()
    }

    fn empty_delta(version_second: u32) -> IncrementalResult {
        IncrementalResult {
            added_or_modified_proxies: Vec::new(),
            removed_proxy_ids: Vec::new(),
            added_or_modified_consumers: Vec::new(),
            removed_consumer_ids: Vec::new(),
            added_or_modified_plugin_configs: Vec::new(),
            removed_plugin_config_ids: Vec::new(),
            added_or_modified_upstreams: Vec::new(),
            removed_upstream_ids: Vec::new(),
            poll_timestamp: Utc
                .with_ymd_and_hms(2026, 5, 5, 12, 0, version_second)
                .unwrap(),
        }
    }

    fn config_update(update_type: i32, config_json: String, version: String) -> ConfigUpdate {
        ConfigUpdate {
            update_type,
            config_json,
            version,
            timestamp: 0,
            ferrum_version: crate::FERRUM_VERSION.to_string(),
        }
    }

    fn full_config_update(config: &GatewayConfig) -> ConfigUpdate {
        config_update(
            0,
            serde_json::to_string(config).expect("full config should serialize"),
            config.loaded_at.to_rfc3339(),
        )
    }

    fn delta_config_update(delta: &IncrementalResult) -> ConfigUpdate {
        config_update(
            1,
            serde_json::to_string(delta).expect("delta config should serialize"),
            delta.poll_timestamp.to_rfc3339(),
        )
    }

    fn test_server(config: GatewayConfig) -> XdsAdsServer {
        let (tx, _) = broadcast::channel(1);
        XdsAdsServer::new(
            Arc::new(ArcSwap::from_pointee(config)),
            tx,
            "x".repeat(32),
            "issuer".to_string(),
            "default".to_string(),
        )
    }

    fn cds_subscription() -> HashMap<String, XdsSubscription> {
        HashMap::from([(
            super::super::translator::CDS_TYPE_URL.to_string(),
            XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
                legacy_wildcard: true,
            },
        )])
    }

    #[test]
    fn resolve_stream_node_id_rejects_mid_stream_mutation() {
        assert_eq!(
            resolve_stream_node_id(None, Some("node-a".to_string())).unwrap(),
            "node-a"
        );
        assert_eq!(
            resolve_stream_node_id(Some("node-a"), None).unwrap(),
            "node-a"
        );
        assert!(resolve_stream_node_id(Some("node-a"), Some("node-a".to_string())).is_ok());
        assert!(resolve_stream_node_id(Some("node-a"), Some("node-b".to_string())).is_err());
    }

    #[test]
    fn sotw_lag_recovery_rebuilds_and_sends_current_snapshot() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();

        let initial = server.sotw_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].resources.len(), 1);

        server
            .config
            .store(Arc::new(gateway_config_with_service(false, 1)));
        let recovered = server.sotw_responses_for_subscriptions("node-a", &subscriptions);

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].resources.len(), 0);
        assert_ne!(recovered[0].nonce, initial[0].nonce);
    }

    #[test]
    fn sotw_update_skips_unchanged_effective_resources() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();

        let initial = server.sotw_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);

        server
            .config
            .store(Arc::new(gateway_config_with_service(true, 1)));
        let unchanged = server.sotw_responses_for_subscriptions("node-a", &subscriptions);

        assert!(unchanged.is_empty());
    }

    #[test]
    fn sotw_update_uses_broadcast_payload_before_shared_config_swap() {
        let server = test_server(gateway_config_with_named_service("old", 0));
        let subscriptions = cds_subscription();
        let initial = server.sotw_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(
            cluster_names(&initial[0]),
            vec!["cluster/default/old/8080".to_string()]
        );

        let mut stream_config = gateway_config_with_named_service("old", 0);
        let update_config = gateway_config_with_named_service("new", 1);
        let update = full_config_update(&update_config);

        assert!(XdsAdsServer::apply_update_to_stream_config(
            &mut stream_config,
            &update
        ));
        let responses = server.sotw_responses_for_subscriptions_from_config(
            "node-a",
            &subscriptions,
            &stream_config,
        );

        assert_eq!(responses.len(), 1);
        assert_eq!(
            cluster_names(&responses[0]),
            vec!["cluster/default/new/8080".to_string()]
        );
    }

    #[test]
    fn stream_config_delta_update_uses_broadcast_payload_version() {
        let mut stream_config = gateway_config_with_service(true, 0);
        let delta = empty_delta(42);
        let update = delta_config_update(&delta);

        assert!(XdsAdsServer::apply_update_to_stream_config(
            &mut stream_config,
            &update
        ));

        assert_eq!(stream_config.loaded_at, delta.poll_timestamp);
    }

    #[test]
    fn pending_update_before_first_sotw_request_updates_stream_config() {
        let old_config = gateway_config_with_named_service("old", 0);
        let server = test_server(old_config.clone());
        let mut updates = server.update_tx.subscribe();
        let new_config = gateway_config_with_named_service("new", 1);
        server
            .update_tx
            .send(full_config_update(&new_config))
            .expect("pending update should send");
        let mut stream_config = old_config;
        server.catch_up_pending_updates(&mut updates, &mut stream_config);
        let mut subscriptions = HashMap::new();
        let request = DiscoveryRequest {
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            ..DiscoveryRequest::default()
        };

        let response = server
            .sotw_response_for_request("node-a", &stream_config, &mut subscriptions, &request)
            .expect("first SotW request should receive the caught-up snapshot");

        assert_eq!(
            cluster_names(&response),
            vec!["cluster/default/new/8080".to_string()]
        );
    }

    #[test]
    fn pending_update_before_first_delta_request_updates_stream_config() {
        let old_config = gateway_config_with_named_service("old", 0);
        let server = test_server(old_config.clone());
        let mut updates = server.update_tx.subscribe();
        let new_config = gateway_config_with_named_service("new", 1);
        server
            .update_tx
            .send(full_config_update(&new_config))
            .expect("pending update should send");
        let mut stream_config = old_config;
        server.catch_up_pending_updates(&mut updates, &mut stream_config);
        let request = DeltaDiscoveryRequest {
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            ..DeltaDiscoveryRequest::default()
        };
        let (subscription, _, _) = build_delta_subscription(
            None,
            "node-a",
            &request.type_url,
            &request.resource_names_subscribe,
            &request.resource_names_unsubscribe,
        );
        let previous = server.snapshot_cache.get("node-a");
        let snapshot = server.snapshot_for_config("node-a", &stream_config);

        let response = server.delta_response(
            &snapshot,
            previous.as_deref(),
            &subscription,
            &request.initial_resource_versions,
            &request.resource_names_subscribe,
        );

        assert_eq!(
            delta_cluster_names(&response),
            vec!["cluster/default/new/8080".to_string()]
        );
    }

    #[test]
    fn sotw_subscription_change_skips_response_when_effective_resources_match() {
        let config = gateway_config_with_service(true, 0);
        let server = test_server(config.clone());
        let mut subscriptions = cds_subscription();
        let snapshot = server.snapshot_for_config("node-a", &config);
        assert_eq!(
            snapshot
                .resources(super::super::translator::CDS_TYPE_URL)
                .len(),
            1
        );
        let name = "cluster/default/api/8080".to_string();
        let request = DiscoveryRequest {
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            response_nonce: "stale-or-unknown".to_string(),
            resource_names: vec![name.clone()],
            ..DiscoveryRequest::default()
        };

        let response =
            server.sotw_response_for_request("node-a", &config, &mut subscriptions, &request);

        assert!(response.is_none());
        let subscription = subscriptions
            .get(super::super::translator::CDS_TYPE_URL)
            .expect("subscription should be tracked");
        assert!(!subscription.wildcard);
        assert_eq!(subscription.resource_names, vec![name]);
    }

    #[test]
    fn sotw_ack_outcome_still_applies_effective_subscription_change() {
        let config = gateway_config_with_services(&["api", "admin"], 0);
        let server = test_server(config.clone());
        let mut subscriptions = cds_subscription();
        let name = "cluster/default/api/8080".to_string();
        let request = DiscoveryRequest {
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            response_nonce: "stale-or-unknown".to_string(),
            resource_names: vec![name.clone()],
            ..DiscoveryRequest::default()
        };

        let response = server
            .sotw_response_for_request("node-a", &config, &mut subscriptions, &request)
            .expect("subscription update should send the requested resource");

        let subscription = subscriptions
            .get(super::super::translator::CDS_TYPE_URL)
            .expect("subscription should be tracked");
        assert!(!subscription.wildcard);
        assert_eq!(subscription.resource_names, vec![name]);
        assert_eq!(response.resources.len(), 1);
    }

    #[test]
    fn delta_lag_recovery_reports_removed_resources() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();

        let initial = server.delta_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].resources.len(), 1);
        assert!(initial[0].removed_resources.is_empty());

        server
            .config
            .store(Arc::new(gateway_config_with_service(false, 1)));
        let recovered = server.delta_responses_for_subscriptions("node-a", &subscriptions);

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].resources.len(), 0);
        assert_eq!(
            recovered[0].removed_resources,
            vec!["cluster/default/api/8080".to_string()]
        );
    }

    #[test]
    fn delta_update_skips_unchanged_effective_resources() {
        let server = test_server(gateway_config_with_service(true, 0));
        let subscriptions = cds_subscription();

        let initial = server.delta_responses_for_subscriptions("node-a", &subscriptions);
        assert_eq!(initial.len(), 1);

        server
            .config
            .store(Arc::new(gateway_config_with_service(true, 1)));
        let unchanged = server.delta_responses_for_subscriptions("node-a", &subscriptions);

        assert!(unchanged.is_empty());
    }

    #[test]
    fn delta_initial_resource_versions_drive_removals_even_with_cached_snapshot() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        server.snapshot_cache.insert(snapshot.clone());
        let cached_previous = server.snapshot_cache.get("node-a");
        let initial_resource_versions = HashMap::from([(
            "cluster/default/stale/8080".to_string(),
            "v-old".to_string(),
        )]);

        let response = server.delta_response(
            &snapshot,
            cached_previous.as_deref(),
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: true,
                legacy_wildcard: true,
            },
            &initial_resource_versions,
            &[],
        );

        assert_eq!(
            response.removed_resources,
            vec!["cluster/default/stale/8080".to_string()]
        );
    }

    #[test]
    fn delta_explicit_empty_subscription_returns_no_resources() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        let response = server.delta_response(
            &snapshot,
            None,
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: Vec::new(),
                wildcard: false,
                legacy_wildcard: false,
            },
            &HashMap::new(),
            &[],
        );

        assert!(response.resources.is_empty());
        assert!(response.removed_resources.is_empty());
    }

    #[test]
    fn delta_subscription_resubscribe_is_explicit_without_state_change() {
        let previous = XdsSubscription {
            node_id: "node-a".to_string(),
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names: vec!["cluster/default/api/8080".to_string()],
            wildcard: false,
            legacy_wildcard: false,
        };
        let (subscription, changed, explicit) = build_delta_subscription(
            Some(&previous),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &["cluster/default/api/8080".to_string()],
            &[],
        );

        assert_eq!(subscription, previous);
        assert!(!changed);
        assert!(explicit);

        let request = DeltaDiscoveryRequest {
            response_nonce: "stale-nonce".to_string(),
            resource_names_subscribe: vec!["cluster/default/api/8080".to_string()],
            ..DeltaDiscoveryRequest::default()
        };
        assert!(should_send_delta_response(&request, changed, explicit));
    }

    #[test]
    fn sotw_empty_after_explicit_subscription_is_not_wildcard() {
        let previous = build_sotw_subscription(
            None,
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &["cluster/default/api/8080".to_string()],
        );
        let subscription = build_sotw_subscription(
            Some(&previous),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &[],
        );

        assert!(!subscription.wildcard);
        assert!(subscription.resource_names.is_empty());
    }

    #[test]
    fn sotw_empty_after_explicit_wildcard_is_unsubscribe_all() {
        let previous = build_sotw_subscription(
            None,
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &["*".to_string()],
        );
        assert!(previous.wildcard);
        assert!(!previous.legacy_wildcard);
        assert!(previous.resource_names.is_empty());

        let subscription = build_sotw_subscription(
            Some(&previous),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &[],
        );

        assert!(!subscription.wildcard);
        assert!(!subscription.legacy_wildcard);
        assert!(subscription.resource_names.is_empty());
    }

    #[test]
    fn delta_named_subscription_keeps_existing_wildcard_until_star_unsubscribed() {
        let previous = XdsSubscription {
            node_id: "node-a".to_string(),
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names: Vec::new(),
            wildcard: true,
            legacy_wildcard: true,
        };
        let (subscription, changed, explicit) = build_delta_subscription(
            Some(&previous),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &["cluster/default/api/8080".to_string()],
            &[],
        );

        assert!(changed);
        assert!(explicit);
        assert!(subscription.wildcard);
        assert_eq!(
            subscription.resource_names,
            vec!["cluster/default/api/8080".to_string()]
        );

        let (subscription, changed, explicit) = build_delta_subscription(
            Some(&subscription),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &[],
            &["*".to_string()],
        );

        assert!(changed);
        assert!(explicit);
        assert!(!subscription.wildcard);
        assert_eq!(
            subscription.resource_names,
            vec!["cluster/default/api/8080".to_string()]
        );
    }

    #[test]
    fn delta_explicit_missing_subscription_returns_removed_resource() {
        let server = test_server(gateway_config_with_service(false, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        let subscribed = "cluster/default/missing/8080".to_string();
        let response = server.delta_response(
            &snapshot,
            None,
            &XdsSubscription {
                node_id: "node-a".to_string(),
                type_url: super::super::translator::CDS_TYPE_URL.to_string(),
                resource_names: vec![subscribed.clone()],
                wildcard: false,
                legacy_wildcard: false,
            },
            &HashMap::new(),
            std::slice::from_ref(&subscribed),
        );

        assert!(response.resources.is_empty());
        assert_eq!(response.removed_resources, vec![subscribed]);
    }

    #[test]
    fn delta_subscription_unsubscribe_all_is_empty_not_wildcard() {
        let previous = XdsSubscription {
            node_id: "node-a".to_string(),
            type_url: super::super::translator::CDS_TYPE_URL.to_string(),
            resource_names: vec!["cluster/default/api/8080".to_string()],
            wildcard: false,
            legacy_wildcard: false,
        };
        let (subscription, changed, explicit) = build_delta_subscription(
            Some(&previous),
            "node-a",
            super::super::translator::CDS_TYPE_URL,
            &[],
            &["cluster/default/api/8080".to_string()],
        );

        assert!(changed);
        assert!(explicit);
        assert!(!subscription.wildcard);
        assert!(subscription.resource_names.is_empty());
    }

    #[test]
    fn stream_guard_cleans_node_state_when_last_stream_exits() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        server.snapshot_cache.insert(snapshot);
        server
            .nonce_tracker
            .issue_nonce("node-a", super::super::translator::CDS_TYPE_URL, "v1");

        {
            let mut guard = server.stream_guard();
            guard.set_node_id("node-a");
            assert!(server.snapshot_cache.get("node-a").is_some());
            assert_eq!(server.nonce_tracker.len(), 1);
        }

        assert!(server.snapshot_cache.get("node-a").is_none());
        assert!(server.nonce_tracker.is_empty());
    }

    #[test]
    fn stream_guard_keeps_node_state_until_all_streams_exit() {
        let server = test_server(gateway_config_with_service(true, 0));
        let snapshot = server.rebuild_snapshot("node-a");
        server.snapshot_cache.insert(snapshot);
        server
            .nonce_tracker
            .issue_nonce("node-a", super::super::translator::CDS_TYPE_URL, "v1");

        let mut first = server.stream_guard();
        first.set_node_id("node-a");
        let mut second = server.stream_guard();
        second.set_node_id("node-a");

        drop(first);
        assert!(server.snapshot_cache.get("node-a").is_some());
        assert_eq!(server.nonce_tracker.len(), 1);

        drop(second);
        assert!(server.snapshot_cache.get("node-a").is_none());
        assert!(server.nonce_tracker.is_empty());
    }
}
