use std::collections::HashMap;
use std::time::Duration;

use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, Identity};
use tracing::{error, info, warn};

use crate::grpc::dp_client::{
    DpGrpcTlsConfig, GrpcJwtSecret, check_cp_version_compatibility, generate_dp_jwt_with_issuer,
};
use crate::grpc::proto::config_sync_client::ConfigSyncClient;
use crate::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::xds::slice::MeshSlice;

/// Phase B shell for Ferrum-native MeshSubscribe consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeMeshClientConfig {
    pub node_id: String,
    pub namespace: String,
    pub workload_spiffe_id: Option<String>,
    pub labels: HashMap<String, String>,
}

impl NativeMeshClientConfig {
    pub fn subscribe_request(&self, ferrum_version: &str) -> MeshSubscribeRequest {
        MeshSubscribeRequest {
            node_id: self.node_id.clone(),
            ferrum_version: ferrum_version.to_string(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone().unwrap_or_default(),
            labels: self.labels.clone(),
        }
    }
}

/// Maintain a live native `MeshSubscribe` stream with simple multi-CP failover.
pub async fn start_native_mesh_client_with_shutdown(
    cp_urls: Vec<String>,
    jwt_secret: GrpcJwtSecret,
    config: NativeMeshClientConfig,
    state: MeshRuntimeState,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<DpGrpcTlsConfig>,
) {
    if cp_urls.is_empty() {
        error!("No CP URLs configured — cannot start native mesh client");
        return;
    }

    const BACKOFF_INITIAL_SECS: u64 = 1;
    const BACKOFF_MAX_SECS: u64 = 30;
    let mut current_cp_index = 0usize;
    let mut backoff_secs = BACKOFF_INITIAL_SECS;

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cp_urls = cp_urls.len(),
        "Native mesh client starting"
    );

    loop {
        if *shutdown_rx.borrow() {
            info!("Native mesh client shutting down");
            return;
        }

        let cp_url = &cp_urls[current_cp_index];
        let consumer = NativeMeshConfigConsumer::new(state.clone());
        let mut stream_shutdown_rx = shutdown_rx.clone();
        let result = tokio::select! {
            result = connect_mesh_subscribe(
                cp_url,
                &jwt_secret,
                &config,
                &consumer,
                tls_config.as_ref(),
            ) => result,
            _ = wait_for_shutdown(&mut stream_shutdown_rx) => {
                info!("Native mesh client shutting down");
                return;
            }
        };

        match result {
            Ok(()) => {
                warn!(
                    cp_url = %cp_url,
                    "Native MeshSubscribe stream ended; will reconnect"
                );
                current_cp_index = 0;
                backoff_secs = BACKOFF_INITIAL_SECS;
            }
            Err(e) => {
                error!(
                    cp_url = %cp_url,
                    error = %e,
                    "Native MeshSubscribe connection failed"
                );
                current_cp_index = (current_cp_index + 1) % cp_urls.len();
            }
        }

        let sleep_duration = jittered_backoff(backoff_secs);
        if sleep_or_shutdown(sleep_duration, shutdown_rx.clone()).await {
            info!("Native mesh client shutting down");
            return;
        }
        backoff_secs = (backoff_secs * 2).min(BACKOFF_MAX_SECS);
    }
}

async fn connect_mesh_subscribe(
    cp_url: &str,
    jwt_secret: &GrpcJwtSecret,
    config: &NativeMeshClientConfig,
    consumer: &NativeMeshConfigConsumer,
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
    let token: MetadataValue<_> = format!("Bearer {auth_token}").parse()?;

    #[allow(clippy::result_large_err)]
    let mut client =
        ConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    info!(
        node_id = %config.node_id,
        namespace = %config.namespace,
        cp_url = %cp_url,
        "Connected to CP, subscribing for native mesh config"
    );

    let request = tonic::Request::new(config.subscribe_request(crate::FERRUM_VERSION));
    let mut stream = client.mesh_subscribe(request).await?.into_inner();

    while let Some(update) = stream.message().await? {
        if !update.ferrum_version.is_empty()
            && let Err(msg) = check_cp_version_compatibility(&update.ferrum_version)
        {
            return Err(anyhow::anyhow!(msg));
        }

        let version = update.version.clone();
        match consumer.apply_update(update) {
            Ok(slice) => {
                info!(
                    node_id = %slice.node_id,
                    namespace = %slice.namespace,
                    version = %slice.version,
                    "Applied native MeshSubscribe update"
                );
            }
            Err(e) => {
                warn!(
                    version = %version,
                    error = %e,
                    "Ignoring invalid native MeshSubscribe update"
                );
            }
        }
    }

    Ok(())
}

fn tonic_tls_config(tls: &DpGrpcTlsConfig) -> tonic::transport::ClientTlsConfig {
    let mut client_tls = tonic::transport::ClientTlsConfig::new();

    if let Some(ref ca_pem) = tls.ca_cert_pem {
        client_tls = client_tls.ca_certificate(Certificate::from_pem(ca_pem));
    }

    if let (Some(cert_pem), Some(key_pem)) = (&tls.client_cert_pem, &tls.client_key_pem) {
        client_tls = client_tls.identity(Identity::from_pem(cert_pem, key_pem));
    }

    client_tls
}

fn jittered_backoff(backoff_secs: u64) -> Duration {
    let base_ms = backoff_secs.saturating_mul(1000);
    let jitter_range_ms = base_ms / 4;
    let jitter_ms = if jitter_range_ms > 0 {
        let full_range = jitter_range_ms.saturating_mul(2);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        (nanos % full_range) as i64 - jitter_range_ms as i64
    } else {
        0
    };
    let sleep_ms = (base_ms as i64 + jitter_ms).max(100) as u64;
    Duration::from_millis(sleep_ms)
}

async fn sleep_or_shutdown(
    duration: Duration,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = wait_for_shutdown(&mut shutdown_rx) => true,
    }
}

async fn wait_for_shutdown(shutdown_rx: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

/// Applies native `MeshSubscribe` updates into the shared mesh runtime state.
#[derive(Clone)]
pub struct NativeMeshConfigConsumer {
    state: MeshRuntimeState,
}

impl NativeMeshConfigConsumer {
    pub fn new(state: MeshRuntimeState) -> Self {
        Self { state }
    }

    pub fn state(&self) -> &MeshRuntimeState {
        &self.state
    }

    pub fn apply_update(&self, update: MeshConfigUpdate) -> Result<MeshSlice, String> {
        let slice = serde_json::from_str::<MeshSlice>(&update.mesh_slice_json)
            .map_err(|e| format!("invalid MeshSubscribe slice JSON: {e}"))?;
        self.state.install_slice(slice.clone());
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_update_installs_mesh_slice() {
        let state = MeshRuntimeState::new();
        let consumer = NativeMeshConfigConsumer::new(state.clone());
        let update = MeshConfigUpdate {
            version: "v1".to_string(),
            timestamp: 1,
            mesh_slice_json: serde_json::to_string(&MeshSlice {
                node_id: "node-a".to_string(),
                version: "v1".to_string(),
                ..MeshSlice::default()
            })
            .expect("mesh slice serializes"),
            ferrum_version: crate::FERRUM_VERSION.to_string(),
        };

        let slice = consumer.apply_update(update).expect("update applies");

        assert_eq!(slice.node_id, "node-a");
        assert!(state.has_first_slice());
        assert_eq!(
            state
                .snapshot()
                .as_ref()
                .as_ref()
                .map(|slice| slice.version.as_str()),
            Some("v1")
        );
    }
}
