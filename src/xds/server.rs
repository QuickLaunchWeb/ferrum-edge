use arc_swap::ArcSwap;
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
use crate::grpc::proto::ConfigUpdate;

#[derive(Debug, Clone, PartialEq, Eq)]
struct XdsSubscription {
    node_id: String,
    type_url: String,
    resource_names: Vec<String>,
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
        let request = MeshSliceRequest::from_xds_node(node_id.to_string(), self.namespace.clone());
        let slice = MeshSlice::from_gateway_config(config.as_ref(), request);
        translate_mesh_slice_to_snapshot(&slice)
    }

    fn sotw_response(
        &self,
        snapshot: &XdsSnapshot,
        type_url: &str,
        resource_names: &[String],
    ) -> DiscoveryResponse {
        let nonce = self
            .nonce_tracker
            .issue_nonce(&snapshot.node_id, type_url, &snapshot.version);
        DiscoveryResponse {
            version_info: snapshot.version.clone(),
            resources: snapshot
                .filtered_resources(type_url, resource_names)
                .into_iter()
                .map(|resource| resource.to_any())
                .collect(),
            canary: false,
            type_url: type_url.to_string(),
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
        type_url: &str,
        resource_names: &[String],
        initial_resource_versions: &HashMap<String, String>,
    ) -> DeltaDiscoveryResponse {
        let nonce = self
            .nonce_tracker
            .issue_nonce(&snapshot.node_id, type_url, &snapshot.version);
        let resources = snapshot.filtered_resources(type_url, resource_names);
        let mut removed_resources = previous
            .map(|prev| prev.removed_resource_names(snapshot, type_url))
            .unwrap_or_default();
        if previous.is_none() && !initial_resource_versions.is_empty() {
            let current_names: HashSet<String> = snapshot
                .resources(type_url)
                .into_iter()
                .map(|r| r.name)
                .collect();
            removed_resources.extend(
                initial_resource_versions
                    .keys()
                    .filter(|name| !current_names.contains(*name))
                    .cloned(),
            );
            removed_resources.sort();
            removed_resources.dedup();
        }
        if !resource_names.is_empty() && !removed_resources.is_empty() {
            let wanted: HashSet<&str> = resource_names.iter().map(String::as_str).collect();
            removed_resources.retain(|name| wanted.contains(name.as_str()));
        }
        DeltaDiscoveryResponse {
            system_version_info: snapshot.version.clone(),
            resources: resources
                .into_iter()
                .map(|resource| resource.to_delta_resource())
                .collect(),
            type_url: type_url.to_string(),
            nonce,
            removed_resources,
        }
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
            let mut node_id: Option<String> = None;
            let mut subscriptions: HashMap<String, XdsSubscription> = HashMap::new();
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
                        let next_node_id = request
                            .node
                            .as_ref()
                            .and_then(|node| non_empty_string(&node.id))
                            .or_else(|| node_id.clone());
                        let Some(current_node_id) = next_node_id else {
                            let _ = tx.send(Err(Status::invalid_argument("xDS Node.id is required"))).await;
                            return;
                        };
                        node_id = Some(current_node_id.clone());

                        if request.type_url.is_empty() {
                            let _ = tx.send(Err(Status::invalid_argument("xDS type_url is required"))).await;
                            return;
                        }

                        let previous_subscription = subscriptions.get(&request.type_url).cloned();
                        if !request.response_nonce.is_empty() {
                            match server.record_sotw_ack(&current_node_id, &request) {
                                AckOutcome::Acked => debug!(
                                    node_id = %current_node_id,
                                    type_url = %request.type_url,
                                    "xDS ACK accepted"
                                ),
                                AckOutcome::Nacked { message } => {
                                    warn!(
                                        node_id = %current_node_id,
                                        type_url = %request.type_url,
                                        error = %message,
                                        "xDS NACK received"
                                    );
                                    continue;
                                }
                                outcome => {
                                    warn!(
                                        node_id = %current_node_id,
                                        type_url = %request.type_url,
                                        outcome = ?outcome,
                                        "xDS ACK ignored"
                                    );
                                    continue;
                                }
                            }
                        }

                        let subscription = XdsSubscription {
                            node_id: current_node_id.clone(),
                            type_url: request.type_url.clone(),
                            resource_names: request.resource_names.clone(),
                        };
                        let resource_names_changed = previous_subscription
                            .as_ref()
                            .is_none_or(|previous| previous.resource_names != subscription.resource_names);
                        subscriptions.insert(request.type_url.clone(), subscription.clone());
                        if request.response_nonce.is_empty() || resource_names_changed {
                            let snapshot = server.rebuild_snapshot(&current_node_id);
                            server.snapshot_cache.insert(snapshot.clone());
                            let response = server.sotw_response(
                                &snapshot,
                                &subscription.type_url,
                                &subscription.resource_names,
                            );
                            if tx.send(Ok(response)).await.is_err() {
                                return;
                            }
                        }
                    }
                    update = updates.recv(), if !subscriptions.is_empty() => {
                        match update {
                            Ok(_) => {
                                let Some(current_node_id) = node_id.as_ref() else {
                                    continue;
                                };
                                let snapshot = server.rebuild_snapshot(current_node_id);
                                server.snapshot_cache.insert(snapshot.clone());
                                for subscription in subscriptions.values() {
                                    let response = server.sotw_response(
                                        &snapshot,
                                        &subscription.type_url,
                                        &subscription.resource_names,
                                    );
                                    if tx.send(Ok(response)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("xDS ADS stream lagged by {} config updates; sending fresh snapshots", n);
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
            let mut node_id: Option<String> = None;
            let mut subscriptions: HashMap<String, XdsSubscription> = HashMap::new();
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
                        let next_node_id = request
                            .node
                            .as_ref()
                            .and_then(|node| non_empty_string(&node.id))
                            .or_else(|| node_id.clone());
                        let Some(current_node_id) = next_node_id else {
                            let _ = tx.send(Err(Status::invalid_argument("xDS Node.id is required"))).await;
                            return;
                        };
                        node_id = Some(current_node_id.clone());

                        if request.type_url.is_empty() {
                            let _ = tx.send(Err(Status::invalid_argument("xDS type_url is required"))).await;
                            return;
                        }

                        let previous_subscription = subscriptions.get(&request.type_url).cloned();
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
                                    continue;
                                }
                                outcome => {
                                    warn!(
                                        node_id = %current_node_id,
                                        type_url = %request.type_url,
                                        outcome = ?outcome,
                                        "xDS delta ACK ignored"
                                    );
                                    continue;
                                }
                            }
                        }

                        let mut resource_names = subscriptions
                            .get(&request.type_url)
                            .map(|subscription| subscription.resource_names.clone())
                            .unwrap_or_default();
                        if !request.resource_names_subscribe.is_empty() {
                            for name in &request.resource_names_subscribe {
                                if !resource_names.contains(name) {
                                    resource_names.push(name.clone());
                                }
                            }
                            resource_names.sort();
                        }
                        if !request.resource_names_unsubscribe.is_empty() {
                            let removed: HashSet<&str> = request
                                .resource_names_unsubscribe
                                .iter()
                                .map(String::as_str)
                                .collect();
                            resource_names.retain(|name| !removed.contains(name.as_str()));
                        }

                        let subscription = XdsSubscription {
                            node_id: current_node_id.clone(),
                            type_url: request.type_url.clone(),
                            resource_names,
                        };
                        let resource_names_changed = previous_subscription
                            .as_ref()
                            .is_none_or(|previous| previous.resource_names != subscription.resource_names);
                        subscriptions.insert(request.type_url.clone(), subscription.clone());
                        if request.response_nonce.is_empty()
                            || resource_names_changed
                            || !request.initial_resource_versions.is_empty()
                        {
                            let previous = server.snapshot_cache.get(&current_node_id);
                            let snapshot = server.rebuild_snapshot(&current_node_id);
                            server.snapshot_cache.insert(snapshot.clone());
                            let response = server.delta_response(
                                &snapshot,
                                previous.as_deref(),
                                &subscription.type_url,
                                &subscription.resource_names,
                                &request.initial_resource_versions,
                            );
                            if tx.send(Ok(response)).await.is_err() {
                                return;
                            }
                        }
                    }
                    update = updates.recv(), if !subscriptions.is_empty() => {
                        match update {
                            Ok(_) => {
                                let Some(current_node_id) = node_id.as_ref() else {
                                    continue;
                                };
                                let previous = server.snapshot_cache.get(current_node_id);
                                let snapshot = server.rebuild_snapshot(current_node_id);
                                server.snapshot_cache.insert(snapshot.clone());
                                for subscription in subscriptions.values() {
                                    let response = server.delta_response(
                                        &snapshot,
                                        previous.as_deref(),
                                        &subscription.type_url,
                                        &subscription.resource_names,
                                        &HashMap::new(),
                                    );
                                    if tx.send(Ok(response)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("xDS delta ADS stream lagged by {} config updates; sending fresh snapshots", n);
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
