use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::{broadcast, watch};
use tracing::{debug, error, info, warn};

use crate::config::types::GatewayConfig;
use crate::config_sources::k8s::{K8sTranslateError, K8sTranslationOptions, translate_k8s_objects};
use crate::identity::spiffe::TrustDomain;
use crate::k8s_controller::metrics::ControllerMetrics;
use crate::k8s_controller::resource_store::ResourceStoreSet;

pub struct ReconcilerConfig {
    pub namespace: String,
    pub trust_domain: String,
    pub debounce_ms: u64,
    pub full_sync_interval_secs: u64,
}

pub fn spawn_reconcile_loop(
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    update_tx: broadcast::Sender<()>,
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
            &config_arc,
            &update_tx,
            &reconciler_config.namespace,
            &trust_domain,
            &metrics,
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
                        &config_arc,
                        &update_tx,
                        &reconciler_config.namespace,
                        &trust_domain,
                        &metrics,
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
                        &config_arc,
                        &update_tx,
                        &reconciler_config.namespace,
                        &trust_domain,
                        &metrics,
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

async fn do_reconcile(
    store_set: &Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    config_arc: &Arc<ArcSwap<GatewayConfig>>,
    update_tx: &broadcast::Sender<()>,
    namespace: &str,
    trust_domain: &TrustDomain,
    metrics: &ControllerMetrics,
) {
    let start = std::time::Instant::now();
    metrics
        .reconciliations
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let objects = {
        let set = store_set.lock().await;
        set.snapshot_all()
    };

    let resource_count = objects.len();
    debug!(resource_count, "Starting reconciliation");

    let options = K8sTranslationOptions::new(namespace.to_string(), trust_domain.clone());

    let translation = match translate_k8s_objects(&objects, options) {
        Ok(t) => t,
        Err(K8sTranslateError::Unsupported(ref resource)) => {
            warn!(
                kind = resource.kind,
                namespace = resource.namespace,
                name = resource.name,
                reason = resource.reason,
                "Unsupported K8s resource skipped"
            );
            metrics
                .errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Retry without the offending resource.
            let filtered: Vec<_> = objects
                .into_iter()
                .filter(|obj| {
                    !(obj.kind == resource.kind
                        && obj.metadata.namespace == resource.namespace
                        && obj.metadata.name == resource.name)
                })
                .collect();
            let retry_options =
                K8sTranslationOptions::new(namespace.to_string(), trust_domain.clone());
            match translate_k8s_objects(&filtered, retry_options) {
                Ok(t) => t,
                Err(e) => {
                    error!(error = %e, "K8s translation failed after filtering unsupported resource");
                    metrics
                        .errors
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            }
        }
        Err(K8sTranslateError::InvalidResource {
            ref kind,
            ref namespace,
            ref name,
            ref message,
        }) => {
            warn!(
                kind,
                namespace, name, message, "Invalid K8s resource, skipping"
            );
            metrics
                .errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let filtered: Vec<_> = objects
                .into_iter()
                .filter(|obj| {
                    !(obj.kind == *kind
                        && obj.metadata.namespace == *namespace
                        && obj.metadata.name == *name)
                })
                .collect();
            let retry_options =
                K8sTranslationOptions::new(namespace.to_string(), trust_domain.clone());
            match translate_k8s_objects(&filtered, retry_options) {
                Ok(t) => t,
                Err(e) => {
                    error!(error = %e, "K8s translation failed after filtering invalid resource");
                    metrics
                        .errors
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            }
        }
    };

    for warning in &translation.warnings {
        warn!(warning, "K8s translation warning");
    }

    // Merge with existing non-K8s-sourced config. For now, the K8s controller
    // fully owns the GatewayConfig when enabled — DB-sourced config is managed
    // by the polling loop separately.
    let new_config = translation.config;
    let old_config = config_arc.load();

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
        metrics.last_reconcile_duration_ms.store(
            elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        return;
    }

    config_arc.store(Arc::new(new_config));

    // Notify DPs of the config change.
    let _ = update_tx.send(());

    let elapsed = start.elapsed();
    metrics.last_reconcile_duration_ms.store(
        elapsed.as_millis() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );

    info!(
        resource_count,
        proxies = config_arc.load().proxies.len(),
        upstreams = config_arc.load().upstreams.len(),
        elapsed_ms = elapsed.as_millis() as u64,
        "Reconciliation complete"
    );
}
