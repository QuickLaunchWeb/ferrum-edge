//! Service discovery for dynamic upstream target resolution.
//!
//! Provides background polling of external service registries (DNS-SD,
//! Kubernetes, Consul) to discover backend targets for upstreams. Discovered
//! targets are merged with static targets and pushed into the LoadBalancerCache
//! via atomic updates, keeping the hot proxy path lock-free.

pub mod consul;
pub mod dns_sd;
pub mod kubernetes;

use crate::config::types::{GatewayConfig, SdProvider, ServiceDiscoveryConfig, UpstreamTarget};
use crate::dns::DnsCache;
use crate::health_check::HealthChecker;
use crate::load_balancer::LoadBalancerCache;
use crate::plugins::PluginHttpClient;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Trait for service discovery providers.
#[async_trait::async_trait]
pub trait ServiceDiscoverer: Send + Sync {
    /// Discover current targets from the external registry.
    async fn discover(&self) -> Result<Vec<UpstreamTarget>, anyhow::Error>;
    /// Human-readable provider name for logging.
    fn provider_name(&self) -> &str;
}

/// Manages background service discovery tasks for all upstreams.
///
/// Each upstream with a `service_discovery` config gets a dedicated background
/// task that periodically polls its provider and updates the LoadBalancerCache
/// when targets change.
pub struct ServiceDiscoveryManager {
    tasks: DashMap<String, JoinHandle<()>>,
    load_balancer_cache: Arc<LoadBalancerCache>,
    dns_cache: DnsCache,
    health_checker: Arc<HealthChecker>,
    /// Shared HTTP client for Kubernetes and Consul discovery calls.
    /// Inherits the gateway's pool config, DNS cache, trust store, and
    /// `FERRUM_TLS_NO_VERIFY` setting.
    http_client: PluginHttpClient,
}

impl ServiceDiscoveryManager {
    pub fn new(
        load_balancer_cache: Arc<LoadBalancerCache>,
        dns_cache: DnsCache,
        health_checker: Arc<HealthChecker>,
        http_client: PluginHttpClient,
    ) -> Self {
        Self {
            tasks: DashMap::new(),
            load_balancer_cache,
            dns_cache,
            health_checker,
            http_client,
        }
    }

    /// Start service discovery tasks for all upstreams in the config that have
    /// service discovery configured.
    pub fn start(
        &self,
        config: &GatewayConfig,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        for upstream in &config.upstreams {
            if let Some(sd_config) = &upstream.service_discovery {
                self.start_upstream_task(
                    &upstream.id,
                    sd_config,
                    &upstream.targets,
                    upstream.algorithm,
                    upstream.hash_on.clone(),
                    shutdown_rx.clone(),
                );
            }
        }
    }

    /// Reconcile running tasks with the current config. Stops tasks for removed
    /// upstreams and starts tasks for new/modified upstreams.
    pub fn reconcile(
        &self,
        config: &GatewayConfig,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        // Collect upstream IDs that should have SD tasks
        let desired: std::collections::HashSet<String> = config
            .upstreams
            .iter()
            .filter(|u| u.service_discovery.is_some())
            .map(|u| u.id.clone())
            .collect();

        // Stop tasks for removed upstreams
        let current_ids: Vec<String> = self.tasks.iter().map(|e| e.key().clone()).collect();
        for id in &current_ids {
            if !desired.contains(id)
                && let Some((_, handle)) = self.tasks.remove(id)
            {
                handle.abort();
                debug!(
                    "Service discovery: stopped task for removed upstream {}",
                    id
                );
            }
        }

        // Start/restart tasks for upstreams with SD config
        for upstream in &config.upstreams {
            if let Some(sd_config) = &upstream.service_discovery {
                // Stop existing task if any (config may have changed)
                if let Some((_, handle)) = self.tasks.remove(&upstream.id) {
                    handle.abort();
                }
                self.start_upstream_task(
                    &upstream.id,
                    sd_config,
                    &upstream.targets,
                    upstream.algorithm,
                    upstream.hash_on.clone(),
                    shutdown_rx.clone(),
                );
            }
        }
    }

    /// Stop all running service discovery tasks.
    pub fn stop(&self) {
        for entry in self.tasks.iter() {
            entry.value().abort();
        }
        self.tasks.clear();
        info!("Service discovery: all tasks stopped");
    }

    fn start_upstream_task(
        &self,
        upstream_id: &str,
        sd_config: &ServiceDiscoveryConfig,
        static_targets: &[UpstreamTarget],
        algorithm: crate::config::types::LoadBalancerAlgorithm,
        hash_on: Option<String>,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        let discoverer: Box<dyn ServiceDiscoverer> = match sd_config.provider {
            SdProvider::DnsSd => {
                if let Some(dns_config) = &sd_config.dns_sd {
                    Box::new(dns_sd::DnsSdDiscoverer::new(
                        self.dns_cache.clone(),
                        dns_config.service_name.clone(),
                        sd_config.default_weight,
                    ))
                } else {
                    warn!(
                        "Service discovery: upstream {} has dns_sd provider but no dns_sd config",
                        upstream_id
                    );
                    return;
                }
            }
            SdProvider::Kubernetes => {
                if let Some(k8s_config) = &sd_config.kubernetes {
                    Box::new(kubernetes::KubernetesDiscoverer::new(
                        self.http_client.get().clone(),
                        k8s_config.namespace.clone(),
                        k8s_config.service_name.clone(),
                        k8s_config.port_name.clone(),
                        k8s_config.label_selector.clone(),
                        sd_config.default_weight,
                    ))
                } else {
                    warn!(
                        "Service discovery: upstream {} has kubernetes provider but no kubernetes config",
                        upstream_id
                    );
                    return;
                }
            }
            SdProvider::Consul => {
                if let Some(consul_config) = &sd_config.consul {
                    Box::new(consul::ConsulDiscoverer::new(
                        self.http_client.get().clone(),
                        consul_config.address.clone(),
                        consul_config.service_name.clone(),
                        consul_config.datacenter.clone(),
                        consul_config.tag.clone(),
                        consul_config.healthy_only,
                        consul_config.token.clone(),
                        sd_config.default_weight,
                    ))
                } else {
                    warn!(
                        "Service discovery: upstream {} has consul provider but no consul config",
                        upstream_id
                    );
                    return;
                }
            }
        };

        let poll_interval = match sd_config.provider {
            SdProvider::DnsSd => sd_config
                .dns_sd
                .as_ref()
                .map_or(30, |c| c.poll_interval_seconds),
            SdProvider::Kubernetes => sd_config
                .kubernetes
                .as_ref()
                .map_or(30, |c| c.poll_interval_seconds),
            SdProvider::Consul => sd_config
                .consul
                .as_ref()
                .map_or(30, |c| c.poll_interval_seconds),
        };

        let upstream_id_owned = upstream_id.to_string();
        let lb_cache = self.load_balancer_cache.clone();
        let static_targets = static_targets.to_vec();
        let dns_cache = self.dns_cache.clone();
        let health_checker = self.health_checker.clone();

        let handle = tokio::spawn(async move {
            run_discovery_loop(
                &upstream_id_owned,
                discoverer,
                &lb_cache,
                &static_targets,
                algorithm,
                hash_on,
                poll_interval,
                shutdown_rx,
                &dns_cache,
                &health_checker,
            )
            .await;
        });

        self.tasks.insert(upstream_id.to_string(), handle);
        info!(
            "Service discovery: started {} task for upstream {} (poll interval: {}s)",
            sd_config.provider.as_str(),
            upstream_id,
            poll_interval,
        );
    }
}

impl Drop for ServiceDiscoveryManager {
    fn drop(&mut self) {
        self.stop();
    }
}

impl SdProvider {
    pub fn as_str(&self) -> &str {
        match self {
            SdProvider::DnsSd => "dns_sd",
            SdProvider::Kubernetes => "kubernetes",
            SdProvider::Consul => "consul",
        }
    }
}

/// Wait for a shutdown signal on a watch channel.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Background discovery loop for a single upstream.
#[allow(clippy::too_many_arguments)]
async fn run_discovery_loop(
    upstream_id: &str,
    discoverer: Box<dyn ServiceDiscoverer>,
    lb_cache: &LoadBalancerCache,
    static_targets: &[UpstreamTarget],
    algorithm: crate::config::types::LoadBalancerAlgorithm,
    hash_on: Option<String>,
    poll_interval_seconds: u64,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    dns_cache: &DnsCache,
    health_checker: &HealthChecker,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_interval_seconds));
    let mut last_discovered: Vec<UpstreamTarget> = Vec::new();

    loop {
        // Wait for next tick or shutdown
        if let Some(ref rx) = shutdown_rx {
            tokio::select! {
                _ = interval.tick() => {}
                _ = wait_for_shutdown(rx.clone()) => {
                    info!("Service discovery: shutting down task for upstream {}", upstream_id);
                    return;
                }
            }
        } else {
            interval.tick().await;
        }

        // Discover targets
        match discoverer.discover().await {
            Ok(discovered) => {
                // Check if targets changed
                if !targets_equal(&discovered, &last_discovered) {
                    info!(
                        "Service discovery [{}]: upstream {} targets changed ({} -> {} discovered targets)",
                        discoverer.provider_name(),
                        upstream_id,
                        last_discovered.len(),
                        discovered.len(),
                    );

                    // Merge static + discovered targets
                    let merged = merge_targets(static_targets, &discovered);

                    // DNS warmup for new hostnames
                    let hostnames: Vec<(String, Option<String>, Option<u64>)> = discovered
                        .iter()
                        .map(|t| (t.host.clone(), None, None))
                        .collect();
                    if !hostnames.is_empty() {
                        dns_cache.warmup(hostnames).await;
                    }

                    // Update the load balancer cache atomically
                    lb_cache.update_targets(
                        upstream_id,
                        merged.clone(),
                        algorithm,
                        hash_on.clone(),
                    );

                    // Clean up stale health state for targets that were removed
                    health_checker.remove_stale_targets(&merged);

                    last_discovered = discovered;
                }
            }
            Err(e) => {
                warn!(
                    "Service discovery [{}]: upstream {} discovery failed: {}. Keeping last-known targets.",
                    discoverer.provider_name(),
                    upstream_id,
                    e,
                );
            }
        }
    }
}

/// Check if two target lists are equivalent (same host:port pairs, ignoring order).
pub fn targets_equal(a: &[UpstreamTarget], b: &[UpstreamTarget]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut a_keys: Vec<String> = a.iter().map(|t| format!("{}:{}", t.host, t.port)).collect();
    let mut b_keys: Vec<String> = b.iter().map(|t| format!("{}:{}", t.host, t.port)).collect();
    a_keys.sort();
    b_keys.sort();
    a_keys == b_keys
}

/// Merge static targets with discovered targets. If a discovered target has the
/// same host:port as a static target, the static target takes precedence (its
/// weight and tags are preserved).
pub fn merge_targets(
    static_targets: &[UpstreamTarget],
    discovered: &[UpstreamTarget],
) -> Vec<UpstreamTarget> {
    let static_keys: std::collections::HashSet<String> = static_targets
        .iter()
        .map(|t| format!("{}:{}", t.host, t.port))
        .collect();

    let mut merged = static_targets.to_vec();
    for target in discovered {
        let key = format!("{}:{}", target.host, target.port);
        if !static_keys.contains(&key) {
            merged.push(target.clone());
        }
    }
    merged
}
