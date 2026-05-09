use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::{broadcast, watch};
use tracing::{debug, error, info, warn};

use crate::config::types::GatewayConfig;
use crate::config_sources::k8s::{
    K8sObject, K8sTranslateError, K8sTranslation, K8sTranslationOptions,
    translate_k8s_objects_with_filter,
};
use crate::grpc::cp_server::{CpGrpcServer, DpNodeRegistry};
use crate::grpc::proto::ConfigUpdate;
use crate::identity::spiffe::TrustDomain;
use crate::k8s_controller::metrics::ControllerMetrics;
use crate::k8s_controller::resource_store::ResourceStoreSet;

pub struct ReconcilerConfig {
    pub namespace: String,
    pub trust_domain: String,
    pub watch_namespaces: Vec<String>,
    pub debounce_ms: u64,
    pub full_sync_interval_secs: u64,
}

pub fn spawn_reconcile_loop(
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    update_tx: broadcast::Sender<ConfigUpdate>,
    dp_registry: Arc<DpNodeRegistry>,
    reconciler_config: ReconcilerConfig,
    metrics: Arc<ControllerMetrics>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut change_rx = {
            let set = store_set.lock().await;
            set.subscribe()
        };

        let debounce = Duration::from_millis(reconciler_config.debounce_ms);
        let full_sync_interval = Duration::from_secs(reconciler_config.full_sync_interval_secs);
        let mut full_sync_timer = tokio::time::interval(full_sync_interval);
        full_sync_timer.tick().await; // skip first immediate tick

        let trust_domain = match TrustDomain::new(&reconciler_config.trust_domain) {
            Ok(td) => td,
            Err(e) => {
                error!(
                    trust_domain = reconciler_config.trust_domain,
                    error = %e,
                    "Invalid trust domain for K8s controller, stopping reconciler"
                );
                return;
            }
        };

        // Initial reconciliation — block until first success.
        do_reconcile(
            &store_set,
            ReconcileContext {
                config_arc: &config_arc,
                update_tx: &update_tx,
                dp_registry: &dp_registry,
                namespace: &reconciler_config.namespace,
                watch_namespaces: &reconciler_config.watch_namespaces,
                trust_domain: &trust_domain,
                metrics: &metrics,
            },
        )
        .await;

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("K8s reconciler shutting down");
                        return;
                    }
                }
                _ = full_sync_timer.tick() => {
                    debug!("Periodic full-sync reconciliation");
                    metrics.full_syncs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    do_reconcile(
                        &store_set,
                        ReconcileContext {
                            config_arc: &config_arc,
                            update_tx: &update_tx,
                            dp_registry: &dp_registry,
                            namespace: &reconciler_config.namespace,
                            watch_namespaces: &reconciler_config.watch_namespaces,
                            trust_domain: &trust_domain,
                            metrics: &metrics,
                        },
                    ).await;
                }
                result = change_rx.changed() => {
                    if result.is_err() {
                        info!("Change channel closed, stopping reconciler");
                        return;
                    }
                    // Debounce: wait for events to settle before reconciling.
                    debounce_events(&mut change_rx, debounce).await;
                    do_reconcile(
                        &store_set,
                        ReconcileContext {
                            config_arc: &config_arc,
                            update_tx: &update_tx,
                            dp_registry: &dp_registry,
                            namespace: &reconciler_config.namespace,
                            watch_namespaces: &reconciler_config.watch_namespaces,
                            trust_domain: &trust_domain,
                            metrics: &metrics,
                        },
                    ).await;
                }
            }
        }
    })
}

async fn debounce_events(change_rx: &mut watch::Receiver<u64>, window: Duration) {
    let deadline = tokio::time::Instant::now() + window;
    let hard_cap = tokio::time::Instant::now() + window * 4;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() || tokio::time::Instant::now() >= hard_cap {
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep(remaining) => break,
            result = change_rx.changed() => {
                if result.is_err() {
                    break;
                }
                // More events arriving — continue debouncing up to hard cap.
            }
        }
    }
}

struct ReconcileContext<'a> {
    config_arc: &'a Arc<ArcSwap<GatewayConfig>>,
    update_tx: &'a broadcast::Sender<ConfigUpdate>,
    dp_registry: &'a Arc<DpNodeRegistry>,
    namespace: &'a str,
    watch_namespaces: &'a [String],
    trust_domain: &'a TrustDomain,
    metrics: &'a ControllerMetrics,
}

async fn do_reconcile(
    store_set: &Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    ctx: ReconcileContext<'_>,
) {
    let start = std::time::Instant::now();
    ctx.metrics
        .reconciliations
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let objects = {
        let set = store_set.lock().await;
        set.snapshot_all()
    };

    let resource_count = objects.len();
    debug!(resource_count, "Starting reconciliation");

    let options = K8sTranslationOptions::new(ctx.namespace.to_string(), ctx.trust_domain.clone())
        .with_source_namespaces(ctx.watch_namespaces.to_vec());
    let Some(translation) = translate_with_skip_retries(&objects, options, ctx.metrics) else {
        return;
    };

    for warning in &translation.warnings {
        warn!(warning, "K8s translation warning");
    }

    // Merge with existing non-K8s-sourced config. For now, the K8s controller
    // fully owns the GatewayConfig when enabled — DB-sourced config is managed
    // by the polling loop separately.
    let new_config = translation.config;
    let old_config = ctx.config_arc.load();

    let changed = new_config.proxies.len() != old_config.proxies.len()
        || new_config.upstreams.len() != old_config.upstreams.len()
        || new_config.consumers.len() != old_config.consumers.len()
        || new_config.plugin_configs.len() != old_config.plugin_configs.len()
        || new_config
            .mesh
            .as_ref()
            .map(|m| m.as_ref() != old_config.mesh.as_deref().unwrap_or(&Default::default()))
            .unwrap_or(old_config.mesh.is_some());

    if !changed {
        debug!("No config changes detected, skipping swap");
        let elapsed = start.elapsed();
        ctx.metrics.last_reconcile_duration_ms.store(
            elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        return;
    }

    ctx.config_arc.store(Arc::new(new_config.clone()));

    // Notify DPs of the config change.
    CpGrpcServer::broadcast_update_with_registry(ctx.update_tx, &new_config, ctx.dp_registry);

    let elapsed = start.elapsed();
    ctx.metrics.last_reconcile_duration_ms.store(
        elapsed.as_millis() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );

    info!(
        resource_count,
        proxies = ctx.config_arc.load().proxies.len(),
        upstreams = ctx.config_arc.load().upstreams.len(),
        elapsed_ms = elapsed.as_millis() as u64,
        "Reconciliation complete"
    );
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct K8sResourceKey {
    kind: String,
    namespace: String,
    name: String,
}

impl K8sResourceKey {
    fn from_object(object: &K8sObject) -> Self {
        Self {
            kind: object.kind.clone(),
            namespace: object.metadata.namespace.clone(),
            name: object.metadata.name.clone(),
        }
    }

    fn from_error(error: &K8sTranslateError) -> Self {
        match error {
            K8sTranslateError::Unsupported(resource) => Self {
                kind: resource.kind.clone(),
                namespace: resource.namespace.clone(),
                name: resource.name.clone(),
            },
            K8sTranslateError::InvalidResource {
                kind,
                namespace,
                name,
                ..
            } => Self {
                kind: kind.clone(),
                namespace: namespace.clone(),
                name: name.clone(),
            },
        }
    }
}

fn translate_with_skip_retries(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    metrics: &ControllerMetrics,
) -> Option<K8sTranslation> {
    let mut skipped = std::collections::HashSet::new();

    loop {
        let translation = translate_k8s_objects_with_filter(objects, options.clone(), |object| {
            !skipped.contains(&K8sResourceKey::from_object(object))
        });

        match translation {
            Ok(translation) => return Some(translation),
            Err(error) => {
                metrics
                    .errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                log_skipped_resource(&error);

                let key = K8sResourceKey::from_error(&error);
                if !skipped.insert(key) {
                    error!(error = %error, "K8s translation failed repeatedly on the same resource");
                    return None;
                }
            }
        }
    }
}

fn log_skipped_resource(error: &K8sTranslateError) {
    match error {
        K8sTranslateError::Unsupported(resource) => {
            warn!(
                kind = resource.kind,
                namespace = resource.namespace,
                name = resource.name,
                reason = resource.reason,
                "Unsupported K8s resource skipped"
            );
        }
        K8sTranslateError::InvalidResource {
            kind,
            namespace,
            name,
            message,
        } => {
            warn!(
                kind,
                namespace, name, message, "Invalid K8s resource, skipping"
            );
        }
    }
}
