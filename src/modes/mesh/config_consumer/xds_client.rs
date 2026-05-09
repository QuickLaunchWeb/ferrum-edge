use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use prost::Message;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use super::common::{
    BACKOFF_INITIAL_SECS, jittered_backoff, next_backoff_secs, sleep_or_shutdown, tonic_tls_config,
    wait_for_shutdown,
};
use crate::config::mesh::{AppProtocol, MeshService, ServicePort, TrustBundle, TrustBundleSet};
use crate::grpc::dp_client::{DpGrpcTlsConfig, GrpcJwtSecret, generate_dp_jwt_with_issuer};
use crate::identity::TrustDomain;
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::xds::proto::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::xds::proto::{self, DiscoveryRequest, Node, Status};
use crate::xds::slice::MeshSlice;
use crate::xds::translator::{
    CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, SDS_TYPE_URL, XDS_TYPE_URLS,
};

const INITIAL_TYPE_URL_ORDER: [&str; 5] = [
    CDS_TYPE_URL,
    EDS_TYPE_URL,
    LDS_TYPE_URL,
    RDS_TYPE_URL,
    SDS_TYPE_URL,
];

type BearerToken = MetadataValue<tonic::metadata::Ascii>;

/// xDS ADS client settings for mesh mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdsClientConfig {
    pub cp_urls: Vec<String>,
    pub node_id: String,
    pub cluster: String,
    pub namespace: String,
    pub workload_spiffe_id: Option<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct ClientSubscriptionState {
    subscriptions: HashMap<String, TypeSubscription>,
}

#[derive(Debug, Clone, Default)]
struct TypeSubscription {
    last_acked_version: Option<String>,
    last_received_version: Option<String>,
    last_received_nonce: Option<String>,
    has_initial_response: bool,
}

impl ClientSubscriptionState {
    fn new() -> Self {
        Self {
            subscriptions: XDS_TYPE_URLS
                .iter()
                .map(|type_url| ((*type_url).to_string(), TypeSubscription::default()))
                .collect(),
        }
    }

    fn build_initial_requests(node_id: &str, cluster: &str) -> Vec<DiscoveryRequest> {
        INITIAL_TYPE_URL_ORDER
            .iter()
            .map(|type_url| DiscoveryRequest {
                version_info: String::new(),
                node: Some(Node {
                    id: node_id.to_string(),
                    cluster: cluster.to_string(),
                    metadata: Vec::new(),
                }),
                resource_names: Vec::new(),
                type_url: (*type_url).to_string(),
                response_nonce: String::new(),
                error_detail: None,
            })
            .collect()
    }

    fn record_response(&mut self, type_url: &str, version_info: &str, nonce: &str) {
        let subscription = self.subscriptions.entry(type_url.to_string()).or_default();
        subscription.last_received_version = Some(version_info.to_string());
        subscription.last_received_nonce = Some(nonce.to_string());
        subscription.has_initial_response = true;
    }

    fn build_ack(&self, type_url: &str) -> DiscoveryRequest {
        let subscription = self.subscriptions.get(type_url);
        DiscoveryRequest {
            version_info: subscription
                .and_then(|sub| sub.last_received_version.clone())
                .unwrap_or_default(),
            node: None,
            resource_names: Vec::new(),
            type_url: type_url.to_string(),
            response_nonce: subscription
                .and_then(|sub| sub.last_received_nonce.clone())
                .unwrap_or_default(),
            error_detail: None,
        }
    }

    fn build_nack(&self, type_url: &str, error_msg: impl Into<String>) -> DiscoveryRequest {
        let subscription = self.subscriptions.get(type_url);
        DiscoveryRequest {
            version_info: subscription
                .and_then(|sub| sub.last_acked_version.clone())
                .unwrap_or_default(),
            node: None,
            resource_names: Vec::new(),
            type_url: type_url.to_string(),
            response_nonce: subscription
                .and_then(|sub| sub.last_received_nonce.clone())
                .unwrap_or_default(),
            error_detail: Some(Status {
                code: 3,
                message: error_msg.into(),
                details: Vec::new(),
            }),
        }
    }

    fn mark_acked(&mut self, type_url: &str) {
        if let Some(subscription) = self.subscriptions.get_mut(type_url) {
            subscription.last_acked_version = subscription.last_received_version.clone();
        }
    }

    fn all_types_have_initial_response(&self) -> bool {
        XDS_TYPE_URLS.iter().all(|type_url| {
            self.subscriptions
                .get(*type_url)
                .is_some_and(|subscription| subscription.has_initial_response)
        })
    }
}

#[derive(Debug, Clone, Default)]
struct ResourceAccumulator {
    resources_by_type: HashMap<String, Vec<AccumulatedResource>>,
    versions_by_type: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AccumulatedResource {
    name: String,
    #[allow(dead_code)]
    value: Vec<u8>,
}

impl ResourceAccumulator {
    fn new() -> Self {
        Self::default()
    }

    fn apply_sotw_response(
        &mut self,
        type_url: &str,
        resources: &[proto::Any],
        version: &str,
    ) -> Result<(), String> {
        if !is_known_type_url(type_url) {
            return Err(format!("unknown xDS type_url '{type_url}'"));
        }

        let mut accumulated = Vec::with_capacity(resources.len());
        for resource in resources {
            if !resource.type_url.is_empty() && resource.type_url != type_url {
                return Err(format!(
                    "resource type_url '{}' does not match response type_url '{}'",
                    resource.type_url, type_url
                ));
            }
            let name = decode_resource_name(type_url, &resource.value)?;
            if name.is_empty() {
                return Err(format!(
                    "xDS resource for type_url '{type_url}' has an empty name"
                ));
            }
            accumulated.push(AccumulatedResource {
                name,
                value: resource.value.clone(),
            });
        }

        self.resources_by_type
            .insert(type_url.to_string(), accumulated);
        self.versions_by_type
            .insert(type_url.to_string(), version.to_string());
        Ok(())
    }

    fn resources(&self, type_url: &str) -> &[AccumulatedResource] {
        self.resources_by_type
            .get(type_url)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn has_all_types(&self) -> bool {
        XDS_TYPE_URLS
            .iter()
            .all(|type_url| self.versions_by_type.contains_key(*type_url))
    }

    fn try_build_mesh_slice(&self, config: &XdsClientConfig) -> Result<Option<MeshSlice>, String> {
        if !self.has_all_types() {
            return Ok(None);
        }
        reverse_translate(self, config).map(Some)
    }
}

/// Maintain a live xDS ADS stream with simple multi-CP failover.
pub async fn start_xds_client_with_shutdown(
    cp_urls: Vec<String>,
    jwt_secret: GrpcJwtSecret,
    config: XdsClientConfig,
    state: MeshRuntimeState,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<DpGrpcTlsConfig>,
) {
    let cp_urls = if cp_urls.is_empty() {
        config.cp_urls.clone()
    } else {
        cp_urls
    };
    if cp_urls.is_empty() {
        error!("No CP URLs configured — cannot start xDS mesh client");
        return;
    }

    let mut current_cp_index = 0usize;
    let mut backoff_secs = BACKOFF_INITIAL_SECS;

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cluster = %config.cluster,
        cp_urls = cp_urls.len(),
        "xDS mesh client starting"
    );

    loop {
        if *shutdown_rx.borrow() {
            info!("xDS mesh client shutting down");
            return;
        }

        let cp_url = &cp_urls[current_cp_index];
        let mut stream_shutdown_rx = shutdown_rx.clone();
        let result = tokio::select! {
            result = connect_ads(
                cp_url,
                &jwt_secret,
                &config,
                state.clone(),
                tls_config.as_ref(),
            ) => result,
            _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                info!("xDS mesh client shutting down");
                return;
            }
        };

        let increase_backoff = match result {
            Ok(()) => {
                warn!(
                    cp_url = %cp_url,
                    "xDS ADS stream ended; will reconnect"
                );
                current_cp_index = 0;
                backoff_secs = BACKOFF_INITIAL_SECS;
                false
            }
            Err(e) => {
                error!(
                    cp_url = %cp_url,
                    error = %e,
                    "xDS ADS connection failed"
                );
                current_cp_index = (current_cp_index + 1) % cp_urls.len();
                true
            }
        };

        let sleep_duration = jittered_backoff(backoff_secs);
        if sleep_or_shutdown(sleep_duration, shutdown_rx.clone()).await {
            info!("xDS mesh client shutting down");
            return;
        }
        backoff_secs = next_backoff_secs(backoff_secs, increase_backoff);
    }
}

async fn connect_ads(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    config: &XdsClientConfig,
    state: MeshRuntimeState,
    tls_config: Option<&DpGrpcTlsConfig>,
) -> Result<(), anyhow::Error> {
    let mut endpoint =
        Channel::from_shared(cp_url.to_string())?.connect_timeout(Duration::from_secs(10));

    if let Some(tls) = tls_config {
        let mut client_tls = tonic_tls_config(tls);
        if let Ok(uri) = cp_url.parse::<http::Uri>()
            && let Some(host) = uri.host()
        {
            client_tls = client_tls.domain_name(host);
        }
        endpoint = endpoint.tls_config(client_tls)?;
    }

    let channel = endpoint.connect().await?;
    let auth_token =
        generate_dp_jwt_with_issuer(jwt_secret.as_str(), &config.node_id, jwt_secret.issuer())?;
    let token: BearerToken = format!("Bearer {auth_token}").parse()?;
    let consumer = XdsConfigConsumer::new(config.clone(), state);

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cluster = %config.cluster,
        cp_url = %cp_url,
        "Connected to CP, subscribing for xDS ADS config"
    );

    run_ads_stream_with_auth(channel, Some(token), config, &consumer).await
}

#[allow(dead_code)]
async fn run_ads_stream(
    channel: Channel,
    config: &XdsClientConfig,
    consumer: &XdsConfigConsumer,
) -> Result<(), anyhow::Error> {
    run_ads_stream_with_auth(channel, None, config, consumer).await
}

async fn run_ads_stream_with_auth(
    channel: Channel,
    auth_token: Option<BearerToken>,
    config: &XdsClientConfig,
    consumer: &XdsConfigConsumer,
) -> Result<(), anyhow::Error> {
    #[allow(clippy::result_large_err)]
    let mut client = AggregatedDiscoveryServiceClient::with_interceptor(
        channel,
        move |mut req: tonic::Request<()>| {
            if let Some(token) = auth_token.clone() {
                req.metadata_mut().insert("authorization", token);
            }
            Ok(req)
        },
    );

    let (tx, rx) = mpsc::channel(16);
    let request_stream = ReceiverStream::new(rx);
    let mut response_stream = client
        .stream_aggregated_resources(request_stream)
        .await?
        .into_inner();

    let mut subscriptions = ClientSubscriptionState::new();
    for request in ClientSubscriptionState::build_initial_requests(&config.node_id, &config.cluster)
    {
        tx.send(request)
            .await
            .map_err(|_| anyhow::anyhow!("xDS ADS request stream closed before initial request"))?;
    }

    let mut accumulator = ResourceAccumulator::new();
    while let Some(response) = response_stream.message().await? {
        let type_url = response.type_url.clone();
        if !is_known_type_url(&type_url) {
            return Err(anyhow::anyhow!(
                "unknown xDS response type_url '{type_url}'"
            ));
        }

        debug!(
            node_id = %config.node_id,
            type_url = %type_url,
            version = %response.version_info,
            nonce = %response.nonce,
            resources = response.resources.len(),
            "Received xDS ADS response"
        );

        subscriptions.record_response(&type_url, &response.version_info, &response.nonce);
        let apply_result =
            accumulator.apply_sotw_response(&type_url, &response.resources, &response.version_info);
        let slice_result = apply_result.and_then(|_| accumulator.try_build_mesh_slice(config));

        match slice_result {
            Ok(Some(slice)) => {
                let version = slice.version.clone();
                consumer.apply_slice(slice);
                send_ads_request(&tx, subscriptions.build_ack(&type_url)).await?;
                subscriptions.mark_acked(&type_url);
                info!(
                    node_id = %config.node_id,
                    namespace = %config.namespace,
                    version = %version,
                    type_url = %type_url,
                    all_types_ready = subscriptions.all_types_have_initial_response(),
                    "Applied xDS ADS update"
                );
            }
            Ok(None) => {
                send_ads_request(&tx, subscriptions.build_ack(&type_url)).await?;
                subscriptions.mark_acked(&type_url);
                debug!(
                    node_id = %config.node_id,
                    type_url = %type_url,
                    "ACKed xDS ADS response while waiting for remaining resource types"
                );
            }
            Err(e) => {
                warn!(
                    node_id = %config.node_id,
                    type_url = %type_url,
                    error = %e,
                    "NACKing invalid xDS ADS response"
                );
                send_ads_request(&tx, subscriptions.build_nack(&type_url, e)).await?;
            }
        }
    }

    Ok(())
}

async fn send_ads_request(
    tx: &mpsc::Sender<DiscoveryRequest>,
    request: DiscoveryRequest,
) -> Result<(), anyhow::Error> {
    tx.send(request)
        .await
        .map_err(|_| anyhow::anyhow!("xDS ADS request stream closed"))
}

#[derive(Clone)]
pub struct XdsConfigConsumer {
    config: XdsClientConfig,
    state: MeshRuntimeState,
}

impl XdsConfigConsumer {
    pub fn new(config: XdsClientConfig, state: MeshRuntimeState) -> Self {
        Self { config, state }
    }

    pub fn config(&self) -> &XdsClientConfig {
        &self.config
    }

    pub fn state(&self) -> &MeshRuntimeState {
        &self.state
    }

    pub fn apply_slice(&self, slice: MeshSlice) {
        self.state.install_slice(slice);
    }
}

fn reverse_translate(
    accumulator: &ResourceAccumulator,
    config: &XdsClientConfig,
) -> Result<MeshSlice, String> {
    let mut service_ports: BTreeMap<(String, String), BTreeSet<u16>> = BTreeMap::new();

    for type_url in [CDS_TYPE_URL, EDS_TYPE_URL] {
        for resource in accumulator.resources(type_url) {
            let parsed = parse_service_port_resource_name(&resource.name, "cluster")?;
            service_ports
                .entry((parsed.namespace, parsed.service))
                .or_default()
                .insert(parsed.port);
        }
    }

    for resource in accumulator.resources(LDS_TYPE_URL) {
        let parsed = parse_service_port_resource_name(&resource.name, "listener")?;
        service_ports
            .entry((parsed.namespace, parsed.service))
            .or_default()
            .insert(parsed.port);
    }

    for resource in accumulator.resources(RDS_TYPE_URL) {
        let parsed = parse_route_resource_name(&resource.name)?;
        if !service_ports.contains_key(&(parsed.namespace.clone(), parsed.service.clone())) {
            return Err(format!(
                "route resource '{}' references service '{}/{}' with no cluster/listener resource",
                resource.name, parsed.namespace, parsed.service
            ));
        }
    }

    let services = service_ports
        .into_iter()
        .map(|((namespace, name), ports)| MeshService {
            name,
            namespace,
            ports: ports
                .into_iter()
                .map(|port| ServicePort {
                    port,
                    protocol: AppProtocol::Unknown,
                    name: None,
                })
                .collect(),
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        })
        .collect();

    let mut trust_domains = Vec::new();
    for resource in accumulator.resources(SDS_TYPE_URL) {
        trust_domains.push(parse_spiffe_bundle_secret_name(&resource.name)?);
    }

    Ok(MeshSlice {
        node_id: config.node_id.clone(),
        namespace: config.namespace.clone(),
        workload_spiffe_id: config.workload_spiffe_id.clone(),
        labels: config.labels.clone(),
        version: accumulator
            .versions_by_type
            .get(CDS_TYPE_URL)
            .cloned()
            .unwrap_or_default(),
        workloads: Vec::new(),
        services,
        mesh_policies: Vec::new(),
        peer_authentications: Vec::new(),
        service_entries: Vec::new(),
        trust_bundles: build_trust_bundle_set(trust_domains, config)?,
        multi_cluster: None,
    })
}

fn decode_resource_name(type_url: &str, value: &[u8]) -> Result<String, String> {
    match type_url {
        CDS_TYPE_URL => proto::Cluster::decode(value)
            .map(|resource| resource.name)
            .map_err(|e| format!("failed to decode Cluster resource: {e}")),
        EDS_TYPE_URL => proto::ClusterLoadAssignment::decode(value)
            .map(|resource| resource.cluster_name)
            .map_err(|e| format!("failed to decode ClusterLoadAssignment resource: {e}")),
        LDS_TYPE_URL => proto::Listener::decode(value)
            .map(|resource| resource.name)
            .map_err(|e| format!("failed to decode Listener resource: {e}")),
        RDS_TYPE_URL => proto::RouteConfiguration::decode(value)
            .map(|resource| resource.name)
            .map_err(|e| format!("failed to decode RouteConfiguration resource: {e}")),
        SDS_TYPE_URL => proto::Secret::decode(value)
            .map(|resource| resource.name)
            .map_err(|e| format!("failed to decode Secret resource: {e}")),
        other => Err(format!("unknown xDS type_url '{other}'")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServicePortResourceName {
    namespace: String,
    service: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceResourceName {
    namespace: String,
    service: String,
}

fn parse_service_port_resource_name(
    name: &str,
    expected_prefix: &str,
) -> Result<ServicePortResourceName, String> {
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() != 4 || parts[0] != expected_prefix {
        return Err(format!(
            "resource name '{name}' must use '{expected_prefix}/{{namespace}}/{{service}}/{{port}}'"
        ));
    }
    let namespace = parts[1];
    let service = parts[2];
    if namespace.is_empty() || service.is_empty() {
        return Err(format!(
            "resource name '{name}' must include non-empty namespace and service"
        ));
    }
    let port = parts[3].parse::<u16>().map_err(|e| {
        format!(
            "resource name '{name}' has invalid port '{}': {e}",
            parts[3]
        )
    })?;
    if port == 0 {
        return Err(format!("resource name '{name}' must use a non-zero port"));
    }
    Ok(ServicePortResourceName {
        namespace: namespace.to_string(),
        service: service.to_string(),
        port,
    })
}

fn parse_route_resource_name(name: &str) -> Result<ServiceResourceName, String> {
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() != 3 || parts[0] != "route" {
        return Err(format!(
            "resource name '{name}' must use 'route/{{namespace}}/{{service}}'"
        ));
    }
    let namespace = parts[1];
    let service = parts[2];
    if namespace.is_empty() || service.is_empty() {
        return Err(format!(
            "resource name '{name}' must include non-empty namespace and service"
        ));
    }
    Ok(ServiceResourceName {
        namespace: namespace.to_string(),
        service: service.to_string(),
    })
}

fn parse_spiffe_bundle_secret_name(name: &str) -> Result<String, String> {
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() != 3 || parts[0] != "secret" || parts[1] != "spiffe-bundle" {
        return Err(format!(
            "resource name '{name}' must use 'secret/spiffe-bundle/{{trust_domain}}'"
        ));
    }
    let trust_domain = parts[2];
    if trust_domain.is_empty() {
        return Err(format!(
            "resource name '{name}' must include a trust domain"
        ));
    }
    Ok(trust_domain.to_string())
}

fn build_trust_bundle_set(
    mut trust_domains: Vec<String>,
    config: &XdsClientConfig,
) -> Result<Option<TrustBundleSet>, String> {
    if trust_domains.is_empty() {
        return Ok(None);
    }

    trust_domains.sort();
    trust_domains.dedup();

    let local_trust_domain = preferred_local_trust_domain(&trust_domains, config)
        .unwrap_or_else(|| trust_domains[0].clone());
    let local = empty_trust_bundle(&local_trust_domain)?;
    let federated = trust_domains
        .into_iter()
        .filter(|trust_domain| trust_domain != &local_trust_domain)
        .map(|trust_domain| empty_trust_bundle(&trust_domain))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Some(TrustBundleSet { local, federated }))
}

fn preferred_local_trust_domain(
    trust_domains: &[String],
    config: &XdsClientConfig,
) -> Option<String> {
    if let Some(workload_spiffe_id) = config.workload_spiffe_id.as_deref()
        && let Some(trust_domain) = trust_domain_from_spiffe_id(workload_spiffe_id)
        && trust_domains
            .iter()
            .any(|candidate| candidate == trust_domain)
    {
        return Some(trust_domain.to_string());
    }

    if trust_domains
        .iter()
        .any(|candidate| candidate == "cluster.local")
    {
        return Some("cluster.local".to_string());
    }

    None
}

fn trust_domain_from_spiffe_id(spiffe_id: &str) -> Option<&str> {
    let rest = spiffe_id.strip_prefix("spiffe://")?;
    rest.split('/')
        .next()
        .filter(|trust_domain| !trust_domain.is_empty())
}

fn empty_trust_bundle(trust_domain: &str) -> Result<TrustBundle, String> {
    Ok(TrustBundle {
        trust_domain: TrustDomain::new(trust_domain)
            .map_err(|e| format!("invalid trust domain '{trust_domain}': {e}"))?,
        x509_authorities: Vec::new(),
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    })
}

fn is_known_type_url(type_url: &str) -> bool {
    XDS_TYPE_URLS.contains(&type_url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xds::translator::translate_mesh_slice_to_snapshot;

    fn test_config() -> XdsClientConfig {
        XdsClientConfig {
            cp_urls: vec!["http://cp:50051".to_string()],
            node_id: "node-a".to_string(),
            cluster: "default".to_string(),
            namespace: "default".to_string(),
            workload_spiffe_id: None,
            labels: BTreeMap::new(),
        }
    }

    fn any_resource(type_url: &str, name: &str) -> proto::Any {
        let value = match type_url {
            CDS_TYPE_URL => proto::Cluster {
                name: name.to_string(),
            }
            .encode_to_vec(),
            EDS_TYPE_URL => proto::ClusterLoadAssignment {
                cluster_name: name.to_string(),
            }
            .encode_to_vec(),
            LDS_TYPE_URL => proto::Listener {
                name: name.to_string(),
            }
            .encode_to_vec(),
            RDS_TYPE_URL => proto::RouteConfiguration {
                name: name.to_string(),
            }
            .encode_to_vec(),
            SDS_TYPE_URL => proto::Secret {
                name: name.to_string(),
            }
            .encode_to_vec(),
            other => panic!("unknown test type_url: {other}"),
        };
        proto::Any {
            type_url: type_url.to_string(),
            value,
        }
    }

    fn apply_all_empty(accumulator: &mut ResourceAccumulator) {
        for type_url in XDS_TYPE_URLS {
            if !accumulator.versions_by_type.contains_key(type_url) {
                accumulator
                    .apply_sotw_response(type_url, &[], "v1")
                    .expect("empty response applies");
            }
        }
    }

    fn service_port_map(slice: &MeshSlice) -> BTreeMap<(String, String), Vec<u16>> {
        slice
            .services
            .iter()
            .map(|service| {
                let mut ports: Vec<u16> = service.ports.iter().map(|port| port.port).collect();
                ports.sort_unstable();
                ((service.namespace.clone(), service.name.clone()), ports)
            })
            .collect()
    }

    #[test]
    fn initial_requests_are_ordered_cds_first() {
        let requests = ClientSubscriptionState::build_initial_requests("node-a", "default");
        let type_urls: Vec<&str> = requests
            .iter()
            .map(|request| request.type_url.as_str())
            .collect();

        assert_eq!(
            type_urls,
            vec![
                CDS_TYPE_URL,
                EDS_TYPE_URL,
                LDS_TYPE_URL,
                RDS_TYPE_URL,
                SDS_TYPE_URL
            ]
        );
        assert!(requests.iter().all(|request| request.node.is_some()));
        assert!(
            requests
                .iter()
                .all(|request| request.resource_names.is_empty())
        );
    }

    #[test]
    fn ack_echoes_nonce_and_version() {
        let mut state = ClientSubscriptionState::new();
        state.record_response(CDS_TYPE_URL, "v1", "n1");

        let ack = state.build_ack(CDS_TYPE_URL);

        assert_eq!(ack.type_url, CDS_TYPE_URL);
        assert_eq!(ack.version_info, "v1");
        assert_eq!(ack.response_nonce, "n1");
        assert!(ack.error_detail.is_none());
        assert!(ack.resource_names.is_empty());
        assert!(ack.node.is_none());
    }

    #[test]
    fn nack_preserves_old_version() {
        let mut state = ClientSubscriptionState::new();
        state.record_response(CDS_TYPE_URL, "v1", "n1");
        state.mark_acked(CDS_TYPE_URL);
        state.record_response(CDS_TYPE_URL, "v2", "n2");

        let nack = state.build_nack(CDS_TYPE_URL, "bad config");

        assert_eq!(nack.version_info, "v1");
        assert_eq!(nack.response_nonce, "n2");
    }

    #[test]
    fn nack_includes_error_detail() {
        let mut state = ClientSubscriptionState::new();
        state.record_response(CDS_TYPE_URL, "v1", "n1");

        let nack = state.build_nack(CDS_TYPE_URL, "bad config");
        let detail = nack.error_detail.expect("NACK includes error detail");

        assert_eq!(detail.code, 3);
        assert_eq!(detail.message, "bad config");
    }

    #[test]
    fn accumulator_replaces_resources_on_sotw() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("first response applies");
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/admin/9090")],
                "v2",
            )
            .expect("second response applies");

        let resources = accumulator.resources(CDS_TYPE_URL);
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].name, "cluster/default/admin/9090");
        assert_eq!(
            accumulator.versions_by_type.get(CDS_TYPE_URL).unwrap(),
            "v2"
        );
    }

    #[test]
    fn accumulator_requires_all_types() {
        let mut accumulator = ResourceAccumulator::new();
        for type_url in [CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL] {
            accumulator
                .apply_sotw_response(type_url, &[], "v1")
                .expect("response applies");
        }

        assert!(!accumulator.has_all_types());
        accumulator
            .apply_sotw_response(SDS_TYPE_URL, &[], "v1")
            .expect("response applies");
        assert!(accumulator.has_all_types());
    }

    #[test]
    fn reverse_translate_cluster_name() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("response applies");
        apply_all_empty(&mut accumulator);

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("all types are present");

        assert_eq!(slice.services.len(), 1);
        assert_eq!(slice.services[0].name, "api");
        assert_eq!(slice.services[0].namespace, "default");
        assert_eq!(slice.services[0].ports[0].port, 8080);
    }

    #[test]
    fn reverse_translate_deduplicates_services() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                CDS_TYPE_URL,
                &[any_resource(CDS_TYPE_URL, "cluster/default/api/8080")],
                "v1",
            )
            .expect("CDS response applies");
        accumulator
            .apply_sotw_response(
                LDS_TYPE_URL,
                &[any_resource(LDS_TYPE_URL, "listener/default/api/9090")],
                "v1",
            )
            .expect("LDS response applies");
        apply_all_empty(&mut accumulator);

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("all types are present");

        assert_eq!(
            service_port_map(&slice).get(&("default".to_string(), "api".to_string())),
            Some(&vec![8080, 9090])
        );
    }

    #[test]
    fn reverse_translate_sds_trust_domain() {
        let mut accumulator = ResourceAccumulator::new();
        accumulator
            .apply_sotw_response(
                SDS_TYPE_URL,
                &[any_resource(
                    SDS_TYPE_URL,
                    "secret/spiffe-bundle/cluster.local",
                )],
                "v1",
            )
            .expect("SDS response applies");
        apply_all_empty(&mut accumulator);

        let slice = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("all types are present");
        let bundles = slice.trust_bundles.expect("trust bundle set is present");

        assert_eq!(bundles.local.trust_domain.as_str(), "cluster.local");
    }

    #[test]
    fn reverse_translate_handles_empty() {
        let accumulator = ResourceAccumulator::new();

        assert!(
            accumulator
                .try_build_mesh_slice(&test_config())
                .expect("empty accumulator is valid")
                .is_none()
        );
    }

    #[test]
    fn round_trip_through_translator() {
        let original = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            version: "v1".to_string(),
            services: vec![MeshService {
                name: "api".to_string(),
                namespace: "default".to_string(),
                ports: vec![
                    ServicePort {
                        port: 8080,
                        protocol: AppProtocol::Http,
                        name: Some("http".to_string()),
                    },
                    ServicePort {
                        port: 9090,
                        protocol: AppProtocol::Grpc,
                        name: Some("grpc".to_string()),
                    },
                ],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        };
        let snapshot = translate_mesh_slice_to_snapshot(&original);
        let mut accumulator = ResourceAccumulator::new();

        for type_url in XDS_TYPE_URLS {
            let resources: Vec<proto::Any> = snapshot
                .resources(type_url)
                .iter()
                .map(|resource| resource.to_any())
                .collect();
            accumulator
                .apply_sotw_response(type_url, &resources, &snapshot.version)
                .expect("snapshot resources apply");
        }

        let translated = accumulator
            .try_build_mesh_slice(&test_config())
            .expect("reverse translate succeeds")
            .expect("all types are present");

        assert_eq!(service_port_map(&translated), service_port_map(&original));
    }
}
