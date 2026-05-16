//! Kubernetes CRD controller (Layer 8).
//!
//! Watches Istio + Gateway API CRDs via kube-rs reflectors and feeds them
//! through `config_sources::k8s::translate_k8s_objects()` into the canonical
//! Layer 2 mesh model. Enabled in CP mode with `FERRUM_K8S_CONTROLLER_ENABLED=true`.

pub mod convert;
pub mod metrics;
pub mod reconciler;
pub mod resource_store;
pub mod watcher;

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::{broadcast, watch};
use tracing::{error, info};

use crate::config::types::GatewayConfig;
use crate::grpc::cp_server::DpNodeRegistry;
use crate::grpc::mesh_registry::MeshNodeRegistry;
use crate::grpc::mesh_server::MeshConfigBroadcast;
use crate::grpc::proto::ConfigUpdate;
use metrics::ControllerMetrics;
use reconciler::{ReconcileBroadcasters, ReconcilerConfig, spawn_reconcile_loop};
use resource_store::ResourceStoreSet;
use watcher::{WatcherSelection, spawn_crd_reprobe_task, start_crd_watchers};

pub struct K8sControllerConfig {
    pub namespace: String,
    pub trust_domain: String,
    pub cluster_domain: String,
    pub istio_root_namespace: String,
    pub watch_namespaces: Vec<String>,
    pub watch_istio: bool,
    pub watch_gateway_api: bool,
    pub pod_discovery_enabled: bool,
    pub watch_node_locality: bool,
    pub debounce_ms: u64,
    pub full_sync_interval_secs: u64,
    pub kubeconfig_path: Option<String>,
    /// `FERRUM_MESH_VS_HEADER_ROUTING_EXPERIMENTAL` — when true, the Istio
    /// VirtualService translator emits a `mesh_route_dispatch` plugin
    /// instance for routes with method/header/query-param predicates.
    /// Default false (existing predicate-drop behavior).
    pub vs_header_routing_experimental: bool,
}

pub struct K8sControllerHandle {
    pub metrics: Arc<ControllerMetrics>,
    watcher_handles: Vec<tokio::task::JoinHandle<()>>,
    reconciler_handle: tokio::task::JoinHandle<()>,
    reprobe_handle: tokio::task::JoinHandle<()>,
}

impl K8sControllerHandle {
    pub async fn join(self) {
        for handle in self.watcher_handles {
            let _ = handle.await;
        }
        let _ = self.reconciler_handle.await;
        let _ = self.reprobe_handle.await;
    }
}

pub async fn start_k8s_controller(
    controller_config: K8sControllerConfig,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    update_tx: broadcast::Sender<ConfigUpdate>,
    dp_registry: Arc<DpNodeRegistry>,
    mesh_update_tx: broadcast::Sender<MeshConfigBroadcast>,
    mesh_registry: Arc<MeshNodeRegistry>,
    shutdown: watch::Receiver<bool>,
) -> Result<K8sControllerHandle, anyhow::Error> {
    info!(
        watch_istio = controller_config.watch_istio,
        watch_gateway_api = controller_config.watch_gateway_api,
        pod_discovery_enabled = controller_config.pod_discovery_enabled,
        watch_node_locality = controller_config.watch_node_locality,
        watch_namespaces = ?controller_config.watch_namespaces,
        namespace = controller_config.namespace,
        "Starting Kubernetes controller"
    );

    let client = build_kube_client(&controller_config.kubeconfig_path).await?;

    let store_set = Arc::new(tokio::sync::Mutex::new(ResourceStoreSet::new()));
    let metrics = Arc::new(ControllerMetrics::new());
    let watcher_selection = WatcherSelection {
        watch_istio: controller_config.watch_istio,
        watch_gateway_api: controller_config.watch_gateway_api,
        watch_core: controller_config.pod_discovery_enabled,
        watch_node_locality: controller_config.watch_node_locality,
    };

    let watcher_handles = start_crd_watchers(
        client.clone(),
        store_set.clone(),
        watcher_selection,
        controller_config.watch_namespaces.clone(),
        shutdown.clone(),
    )
    .await;

    info!(watchers = watcher_handles.len(), "CRD watchers started");

    let reconciler_config = ReconcilerConfig {
        namespace: controller_config.namespace,
        trust_domain: controller_config.trust_domain,
        cluster_domain: controller_config.cluster_domain,
        istio_root_namespace: controller_config.istio_root_namespace,
        watch_namespaces: controller_config.watch_namespaces.clone(),
        debounce_ms: controller_config.debounce_ms,
        full_sync_interval_secs: controller_config.full_sync_interval_secs,
        vs_header_routing_experimental: controller_config.vs_header_routing_experimental,
        pod_discovery_enabled: controller_config.pod_discovery_enabled,
    };

    let reconciler_handle = spawn_reconcile_loop(
        store_set.clone(),
        config_arc,
        ReconcileBroadcasters {
            update_tx,
            dp_registry,
            mesh_update_tx,
            mesh_registry,
        },
        reconciler_config,
        metrics.clone(),
        shutdown.clone(),
    );

    let reprobe_handle = spawn_crd_reprobe_task(
        client,
        store_set,
        watcher_selection,
        controller_config.watch_namespaces,
        shutdown,
        Duration::from_secs(300),
    );

    Ok(K8sControllerHandle {
        metrics,
        watcher_handles,
        reconciler_handle,
        reprobe_handle,
    })
}

async fn build_kube_client(
    kubeconfig_path: &Option<String>,
) -> Result<kube::Client, anyhow::Error> {
    let config = if let Some(path) = kubeconfig_path {
        info!(path, "Loading kubeconfig from explicit path");
        let kubeconfig = kube::config::Kubeconfig::read_from(path)?;
        kube::Config::from_custom_kubeconfig(kubeconfig, &Default::default()).await?
    } else {
        match kube::Config::incluster() {
            Ok(c) => {
                info!("Using in-cluster Kubernetes config");
                c
            }
            Err(in_cluster_err) => match kube::Config::infer().await {
                Ok(c) => {
                    info!("Using inferred kubeconfig (not in-cluster)");
                    c
                }
                Err(infer_err) => {
                    error!(
                        in_cluster_error = %in_cluster_err,
                        infer_error = %infer_err,
                        "Failed to build Kubernetes client config"
                    );
                    return Err(anyhow::anyhow!(
                        "Cannot create Kubernetes client: in-cluster failed ({in_cluster_err}), \
                         kubeconfig inference failed ({infer_err}). \
                         Set FERRUM_K8S_KUBECONFIG_PATH for out-of-cluster use."
                    ));
                }
            },
        }
    };

    Ok(kube::Client::try_from(config)?)
}
