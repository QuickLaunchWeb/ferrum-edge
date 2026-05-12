use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde_json::Value;
use tokio::sync::{broadcast, watch};
use tracing::{debug, error, info, warn};

use crate::config::types::GatewayConfig;
use crate::config_sources::k8s::{
    K8sObject, K8sTranslateError, K8sTranslation, K8sTranslationOptions,
    translate_k8s_objects_with_filter,
};
use crate::grpc::cp_server::{CpGrpcServer, DpNodeRegistry};
use crate::grpc::mesh_registry::MeshNodeRegistry;
use crate::grpc::mesh_server::{MeshConfigBroadcast, MeshGrpcServer};
use crate::grpc::proto::ConfigUpdate;
use crate::identity::spiffe::TrustDomain;
use crate::k8s_controller::metrics::ControllerMetrics;
use crate::k8s_controller::resource_store::ResourceStoreSet;

const INITIAL_STORE_READINESS_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ReconcilerConfig {
    pub namespace: String,
    pub trust_domain: String,
    pub cluster_domain: String,
    pub watch_namespaces: Vec<String>,
    pub debounce_ms: u64,
    pub full_sync_interval_secs: u64,
}

pub struct ReconcileBroadcasters {
    pub update_tx: broadcast::Sender<ConfigUpdate>,
    pub dp_registry: Arc<DpNodeRegistry>,
    pub mesh_update_tx: broadcast::Sender<MeshConfigBroadcast>,
    pub mesh_registry: Arc<MeshNodeRegistry>,
}

pub fn spawn_reconcile_loop(
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    broadcasters: ReconcileBroadcasters,
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
        let full_sync_interval =
            full_sync_interval_duration(reconciler_config.full_sync_interval_secs);
        if reconciler_config.full_sync_interval_secs == 0 {
            warn!(
                "FERRUM_K8S_FULL_SYNC_INTERVAL_SECS=0 is invalid, clamping K8s full-sync interval to 1s"
            );
        }
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

        if !wait_for_initial_store_readiness(&store_set, &mut change_rx, &mut shutdown).await {
            return;
        }

        // Initial reconciliation — block until first success.
        do_reconcile(
            &store_set,
            ReconcileContext {
                config_arc: &config_arc,
                update_tx: &broadcasters.update_tx,
                dp_registry: &broadcasters.dp_registry,
                mesh_update_tx: &broadcasters.mesh_update_tx,
                mesh_registry: &broadcasters.mesh_registry,
                namespace: &reconciler_config.namespace,
                cluster_domain: &reconciler_config.cluster_domain,
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
                            update_tx: &broadcasters.update_tx,
                            dp_registry: &broadcasters.dp_registry,
                            mesh_update_tx: &broadcasters.mesh_update_tx,
                            mesh_registry: &broadcasters.mesh_registry,
                            namespace: &reconciler_config.namespace,
                            cluster_domain: &reconciler_config.cluster_domain,
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
                            update_tx: &broadcasters.update_tx,
                            dp_registry: &broadcasters.dp_registry,
                            mesh_update_tx: &broadcasters.mesh_update_tx,
                            mesh_registry: &broadcasters.mesh_registry,
                            namespace: &reconciler_config.namespace,
                            cluster_domain: &reconciler_config.cluster_domain,
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
    let started = tokio::time::Instant::now();
    let mut deadline = started + window;
    let hard_cap = started + window * 4;

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
                deadline = refresh_debounce_deadline(tokio::time::Instant::now(), window, hard_cap);
            }
        }
    }
}

fn refresh_debounce_deadline(
    now: tokio::time::Instant,
    window: Duration,
    hard_cap: tokio::time::Instant,
) -> tokio::time::Instant {
    let next_deadline = now + window;
    if next_deadline < hard_cap {
        next_deadline
    } else {
        hard_cap
    }
}

fn full_sync_interval_duration(configured_secs: u64) -> Duration {
    Duration::from_secs(configured_secs.max(1))
}

async fn wait_for_initial_store_readiness(
    store_set: &Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    change_rx: &mut watch::Receiver<u64>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    wait_for_initial_store_readiness_with_timeout(
        store_set,
        change_rx,
        shutdown,
        INITIAL_STORE_READINESS_TIMEOUT,
    )
    .await
}

async fn wait_for_initial_store_readiness_with_timeout(
    store_set: &Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    change_rx: &mut watch::Receiver<u64>,
    shutdown: &mut watch::Receiver<bool>,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        if tokio::time::Instant::now() >= deadline {
            warn!(
                timeout_ms = timeout.as_millis(),
                "Timed out waiting for initial K8s reflector stores; reconciling available state"
            );
            return true;
        }

        let stores = {
            let set = store_set.lock().await;
            set.stores()
        };

        if !stores.is_empty() {
            for store in stores {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    warn!(
                        timeout_ms = timeout.as_millis(),
                        "Timed out waiting for initial K8s reflector stores; reconciling available state"
                    );
                    return true;
                }
                tokio::select! {
                    result = tokio::time::timeout(remaining, store.wait_until_ready()) => {
                        match result {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                warn!(
                                    error = %e,
                                    "K8s reflector store failed before initial readiness; reconciling available state"
                                );
                                return true;
                            }
                            Err(_) => {
                                warn!(
                                    timeout_ms = timeout.as_millis(),
                                    "Timed out waiting for initial K8s reflector stores; reconciling available state"
                                );
                                return true;
                            }
                        }
                    }
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            info!("K8s reconciler shutting down before initial store readiness");
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!("K8s reconciler shutting down before any CRD stores became available");
                    return false;
                }
            }
            _ = tokio::time::sleep(deadline.saturating_duration_since(tokio::time::Instant::now())) => {
                warn!(
                    timeout_ms = timeout.as_millis(),
                    "Timed out waiting for initial K8s CRD stores; reconciling available state"
                );
                return true;
            }
            changed = change_rx.changed() => {
                if changed.is_err() {
                    info!("K8s CRD store change channel closed before initial readiness");
                    return false;
                }
            }
        }
    }
}

struct ReconcileContext<'a> {
    config_arc: &'a Arc<ArcSwap<GatewayConfig>>,
    update_tx: &'a broadcast::Sender<ConfigUpdate>,
    dp_registry: &'a Arc<DpNodeRegistry>,
    mesh_update_tx: &'a broadcast::Sender<MeshConfigBroadcast>,
    mesh_registry: &'a Arc<MeshNodeRegistry>,
    namespace: &'a str,
    cluster_domain: &'a str,
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
        .with_cluster_domain(ctx.cluster_domain.to_string())
        .with_source_namespaces(ctx.watch_namespaces.to_vec());
    let Some(translation) = translate_with_skip_retries(&objects, options, ctx.metrics) else {
        return;
    };

    for warning in &translation.warnings {
        warn!(warning, "K8s translation warning");
    }

    let managed_namespaces = managed_k8s_namespaces(
        ctx.namespace,
        ctx.watch_namespaces,
        &translation.config.known_namespaces,
    );
    let Some(new_config) =
        swap_merged_k8s_translation(ctx.config_arc, &translation.config, &managed_namespaces)
    else {
        debug!("No config changes detected, skipping swap");
        let elapsed = start.elapsed();
        ctx.metrics.last_reconcile_duration_ms.store(
            elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        return;
    };

    // Notify DPs and mesh subscribers of the config change.
    CpGrpcServer::broadcast_update_with_registry(ctx.update_tx, &new_config, ctx.dp_registry);
    MeshGrpcServer::broadcast_full_with_registry(
        ctx.mesh_update_tx,
        new_config.clone(),
        ctx.mesh_registry,
    );

    let elapsed = start.elapsed();
    ctx.metrics.last_reconcile_duration_ms.store(
        elapsed.as_millis() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );

    info!(
        resource_count,
        proxies = new_config.proxies.len(),
        upstreams = new_config.upstreams.len(),
        elapsed_ms = elapsed.as_millis() as u64,
        "Reconciliation complete"
    );
}

fn swap_merged_k8s_translation(
    config_arc: &ArcSwap<GatewayConfig>,
    k8s_config: &GatewayConfig,
    managed_namespaces: &BTreeSet<String>,
) -> Option<Arc<GatewayConfig>> {
    let mut old_config = config_arc.load();

    loop {
        let new_config = Arc::new(merge_k8s_translation(
            old_config.as_ref(),
            k8s_config,
            managed_namespaces,
        ));
        if !gateway_config_content_changed(&new_config, old_config.as_ref()) {
            return None;
        }

        let previous = config_arc.compare_and_swap(&*old_config, new_config.clone());
        if Arc::ptr_eq(&*old_config, &*previous) {
            return Some(new_config);
        }

        old_config = previous;
    }
}

fn gateway_config_content_changed(new_config: &GatewayConfig, old_config: &GatewayConfig) -> bool {
    stable_config_value(new_config) != stable_config_value(old_config)
}

const K8S_MANAGED_PROXY_ID_PREFIXES: &[&str] = &["gwapi-route-", "gwapi-l4-", "istio-vs-"];
const K8S_MANAGED_UPSTREAM_ID_PREFIXES: &[&str] = &["gwapi-route-upstream-", "istio-vs-upstream-"];

fn managed_k8s_namespaces(
    namespace: &str,
    watch_namespaces: &[String],
    k8s_known_namespaces: &[String],
) -> BTreeSet<String> {
    if watch_namespaces.is_empty() {
        return BTreeSet::new();
    }

    let mut namespaces: BTreeSet<String> = watch_namespaces.iter().cloned().collect();
    namespaces.extend(k8s_known_namespaces.iter().cloned());
    if namespaces.is_empty() {
        namespaces.insert(namespace.to_string());
    }
    namespaces
}

fn namespace_is_managed(namespace: &str, managed_namespaces: &BTreeSet<String>) -> bool {
    managed_namespaces.is_empty() || managed_namespaces.contains(namespace)
}

fn merge_k8s_translation(
    active: &GatewayConfig,
    k8s_config: &GatewayConfig,
    managed_namespaces: &BTreeSet<String>,
) -> GatewayConfig {
    let mut merged = active.clone();

    merged.proxies.retain(|proxy| {
        !(namespace_is_managed(&proxy.namespace, managed_namespaces)
            && has_any_prefix(&proxy.id, K8S_MANAGED_PROXY_ID_PREFIXES))
    });
    merged.upstreams.retain(|upstream| {
        !(namespace_is_managed(&upstream.namespace, managed_namespaces)
            && has_any_prefix(&upstream.id, K8S_MANAGED_UPSTREAM_ID_PREFIXES))
    });

    merged.proxies.extend(k8s_config.proxies.clone());
    merged.upstreams.extend(k8s_config.upstreams.clone());

    let mut namespaces: BTreeSet<String> = merged.known_namespaces.iter().cloned().collect();
    namespaces.extend(k8s_config.known_namespaces.iter().cloned());
    merged.known_namespaces = namespaces.into_iter().collect();

    if k8s_config.mesh.is_some() {
        merged.mesh = k8s_config.mesh.clone();
    }

    merged.normalize_fields();
    merged
}

fn has_any_prefix(id: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| id.starts_with(prefix))
}

fn stable_config_value(config: &GatewayConfig) -> Value {
    let mut value = serde_json::json!({
        "version": &config.version,
        "proxies": &config.proxies,
        "consumers": &config.consumers,
        "plugin_configs": &config.plugin_configs,
        "upstreams": &config.upstreams,
        "known_namespaces": &config.known_namespaces,
        "mesh": &config.mesh,
    });
    strip_volatile_timestamps(&mut value);
    sort_top_level_collection(&mut value, "proxies", "id");
    sort_top_level_collection(&mut value, "consumers", "id");
    sort_top_level_collection(&mut value, "plugin_configs", "id");
    sort_top_level_collection(&mut value, "upstreams", "id");
    sort_string_array(&mut value, "known_namespaces");
    value
}

fn strip_volatile_timestamps(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("loaded_at");
            map.remove("created_at");
            map.remove("updated_at");
            for child in map.values_mut() {
                strip_volatile_timestamps(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_volatile_timestamps(item);
            }
        }
        _ => {}
    }
}

fn sort_top_level_collection(value: &mut Value, field: &str, key: &str) {
    let Some(items) = value.get_mut(field).and_then(Value::as_array_mut) else {
        return;
    };

    items.sort_by(|left, right| {
        let left_key = left.get(key).and_then(Value::as_str).unwrap_or_default();
        let right_key = right.get(key).and_then(Value::as_str).unwrap_or_default();
        left_key.cmp(right_key)
    });
}

fn sort_string_array(value: &mut Value, field: &str) {
    let Some(items) = value.get_mut(field).and_then(Value::as_array_mut) else {
        return;
    };

    items.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{PluginConfig, PluginScope, Proxy, Upstream};
    use crate::k8s_controller::resource_store::CrdResourceStore;
    use crate::modes::mesh::config::MeshConfig;
    use chrono::{Duration as ChronoDuration, Utc};
    use kube::api::ApiResource;
    use kube::runtime::reflector;
    use serde_json::json;

    fn plugin_config(id: &str, config: Value) -> PluginConfig {
        PluginConfig {
            id: id.to_string(),
            plugin_name: "rate_limiting".to_string(),
            namespace: "ferrum".to_string(),
            config,
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn proxy(id: &str, backend_host: &str) -> Proxy {
        serde_json::from_value(json!({
            "id": id,
            "namespace": "ferrum",
            "hosts": ["example.com"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": backend_host,
            "backend_port": 80
        }))
        .expect("test proxy should deserialize")
    }

    fn upstream(id: &str, host: &str) -> Upstream {
        serde_json::from_value(json!({
            "id": id,
            "namespace": "ferrum",
            "name": id,
            "targets": [{
                "host": host,
                "port": 80,
                "weight": 1
            }]
        }))
        .expect("test upstream should deserialize")
    }

    #[test]
    fn content_change_detects_same_count_plugin_edit() {
        let mut old_config = GatewayConfig::default();
        old_config
            .plugin_configs
            .push(plugin_config("rate", json!({"max_requests": 100})));
        let mut new_config = old_config.clone();
        new_config.plugin_configs[0].config = json!({"max_requests": 200});

        assert!(gateway_config_content_changed(&new_config, &old_config));
    }

    #[test]
    fn content_change_ignores_volatile_timestamps() {
        let mut old_config = GatewayConfig::default();
        old_config
            .plugin_configs
            .push(plugin_config("rate", json!({"max_requests": 100})));
        let mut new_config = old_config.clone();
        new_config.loaded_at = old_config.loaded_at + ChronoDuration::seconds(5);
        new_config.plugin_configs[0].updated_at =
            old_config.plugin_configs[0].updated_at + ChronoDuration::seconds(5);

        assert!(!gateway_config_content_changed(&new_config, &old_config));
    }

    #[test]
    fn content_change_ignores_top_level_resource_order() {
        let mut old_config = GatewayConfig::default();
        old_config
            .plugin_configs
            .push(plugin_config("b", json!({"value": 2})));
        old_config
            .plugin_configs
            .push(plugin_config("a", json!({"value": 1})));
        let mut new_config = old_config.clone();
        new_config.plugin_configs.reverse();

        assert!(!gateway_config_content_changed(&new_config, &old_config));
    }

    #[test]
    fn merge_k8s_translation_preserves_db_resources_and_replaces_k8s_overlay() {
        let mut active = GatewayConfig::default();
        active.proxies.push(proxy("db-proxy", "db.internal"));
        active
            .proxies
            .push(proxy("gwapi-route-ferrum-old-0", "old.internal"));
        active.upstreams.push(upstream(
            "gwapi-route-upstream-ferrum-old-0",
            "old.internal",
        ));
        active.known_namespaces.push("db".to_string());

        let mut k8s = GatewayConfig::default();
        k8s.proxies
            .push(proxy("gwapi-route-ferrum-new-0", "new.internal"));
        k8s.upstreams.push(upstream(
            "gwapi-route-upstream-ferrum-new-0",
            "new.internal",
        ));
        k8s.known_namespaces.push("k8s".to_string());

        let managed = BTreeSet::from(["ferrum".to_string()]);
        let merged = merge_k8s_translation(&active, &k8s, &managed);

        assert!(merged.proxies.iter().any(|proxy| proxy.id == "db-proxy"));
        assert!(
            merged
                .proxies
                .iter()
                .any(|proxy| proxy.id == "gwapi-route-ferrum-new-0")
        );
        assert!(
            merged
                .proxies
                .iter()
                .all(|proxy| proxy.id != "gwapi-route-ferrum-old-0")
        );
        assert!(
            merged
                .upstreams
                .iter()
                .all(|upstream| upstream.id != "gwapi-route-upstream-ferrum-old-0")
        );
        assert!(merged.known_namespaces.contains(&"db".to_string()));
        assert!(merged.known_namespaces.contains(&"k8s".to_string()));
    }

    #[test]
    fn merge_k8s_translation_preserves_existing_mesh_when_k8s_has_none() {
        let mut active = GatewayConfig {
            mesh: Some(Box::new(MeshConfig::default())),
            ..GatewayConfig::default()
        };
        active.mesh.as_mut().expect("mesh exists").services.push(
            crate::modes::mesh::config::MeshService {
                name: "stale".to_string(),
                namespace: "ferrum".to_string(),
                ports: Vec::new(),
                workloads: Vec::new(),
                protocol_overrides: std::collections::HashMap::new(),
            },
        );

        let k8s = GatewayConfig::default();

        let managed = BTreeSet::from(["ferrum".to_string()]);
        let merged = merge_k8s_translation(&active, &k8s, &managed);

        assert!(merged.mesh.is_some());
    }

    #[test]
    fn merge_k8s_translation_preserves_prefixed_operator_resources_outside_managed_namespaces() {
        let mut active = GatewayConfig::default();
        active
            .proxies
            .push(proxy("gwapi-route-operator-owned", "db.internal"));
        active.proxies[0].namespace = "ops".to_string();
        active.upstreams.push(upstream(
            "gwapi-route-upstream-operator-owned",
            "db.internal",
        ));
        active.upstreams[0].namespace = "ops".to_string();

        let k8s = GatewayConfig::default();
        let managed = BTreeSet::from(["ferrum".to_string()]);
        let merged = merge_k8s_translation(&active, &k8s, &managed);

        assert!(
            merged
                .proxies
                .iter()
                .any(|proxy| proxy.id == "gwapi-route-operator-owned")
        );
        assert!(
            merged
                .upstreams
                .iter()
                .any(|upstream| upstream.id == "gwapi-route-upstream-operator-owned")
        );
    }

    #[test]
    fn merge_k8s_translation_prunes_k8s_overlay_from_all_namespaces_when_watch_all() {
        let mut active = GatewayConfig::default();
        active
            .proxies
            .push(proxy("gwapi-route-default-old-0", "old.default.internal"));
        active.proxies[0].namespace = "default".to_string();
        active
            .proxies
            .push(proxy("gwapi-route-prod-old-0", "old.prod.internal"));
        active.proxies[1].namespace = "prod".to_string();
        active.upstreams.push(upstream(
            "gwapi-route-upstream-default-old-0",
            "old.default.internal",
        ));
        active.upstreams[0].namespace = "default".to_string();
        active.upstreams.push(upstream(
            "gwapi-route-upstream-prod-old-0",
            "old.prod.internal",
        ));
        active.upstreams[1].namespace = "prod".to_string();

        let k8s = GatewayConfig::default();
        let managed = BTreeSet::new();
        let merged = merge_k8s_translation(&active, &k8s, &managed);

        assert!(merged.proxies.is_empty());
        assert!(merged.upstreams.is_empty());
    }

    #[test]
    fn full_sync_interval_zero_is_clamped_before_timer_creation() {
        assert_eq!(full_sync_interval_duration(0), Duration::from_secs(1));
        assert_eq!(full_sync_interval_duration(300), Duration::from_secs(300));
    }

    #[test]
    fn debounce_deadline_refreshes_without_exceeding_hard_cap() {
        let start = tokio::time::Instant::now();
        let window = Duration::from_millis(100);
        let hard_cap = start + Duration::from_millis(250);

        assert_eq!(
            refresh_debounce_deadline(start + Duration::from_millis(50), window, hard_cap),
            start + Duration::from_millis(150)
        );
        assert_eq!(
            refresh_debounce_deadline(start + Duration::from_millis(200), window, hard_cap),
            hard_cap
        );
    }

    #[tokio::test]
    async fn initial_readiness_timeout_reconciles_available_state_for_never_ready_store() {
        let ar = ApiResource {
            group: "example.com".to_string(),
            version: "v1".to_string(),
            api_version: "example.com/v1".to_string(),
            kind: "Widget".to_string(),
            plural: "widgets".to_string(),
        };
        let writer = reflector::store::Writer::new(ar);
        let store = Arc::new(CrdResourceStore::new(
            "example.com/v1".to_string(),
            "Widget".to_string(),
            writer.as_reader(),
        ));

        let mut set = ResourceStoreSet::new();
        assert!(set.add_store(store));
        let store_set = Arc::new(tokio::sync::Mutex::new(set));
        let mut change_rx = {
            let set = store_set.lock().await;
            set.subscribe()
        };
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let ready = wait_for_initial_store_readiness_with_timeout(
            &store_set,
            &mut change_rx,
            &mut shutdown_rx,
            Duration::from_millis(5),
        )
        .await;

        assert!(
            ready,
            "timed-out readiness should continue with available stores"
        );
    }
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
