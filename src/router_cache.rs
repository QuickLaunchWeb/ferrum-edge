//! Router cache for high-performance proxy route lookups.
//!
//! Pre-sorts routes by listen_path length (longest first) at config load time,
//! with two-tier host+path matching: exact host → wildcard host → catch-all.
//! Caches (host, path) → proxy lookups in a bounded DashMap for O(1) repeated hits.
//! Route table rebuilds happen atomically via ArcSwap when config changes —
//! never on the hot request path.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

use crate::config::types::{GatewayConfig, Proxy, wildcard_matches};

/// A pre-sorted route entry for longest-prefix matching.
struct RouteEntry {
    listen_path: String,
    proxy: Arc<Proxy>,
}

/// Pre-computed host-based route index.
///
/// Routes are partitioned into three tiers searched in priority order:
/// 1. Exact host match (HashMap O(1) lookup)
/// 2. Wildcard host match (linear scan of wildcard patterns — typically very few)
/// 3. Catch-all (proxies with empty `hosts` — today's behavior)
///
/// Within each tier, routes are sorted by listen_path length descending
/// for longest-prefix matching.
struct HostRouteTable {
    /// Exact host → sorted route entries (longest listen_path first).
    exact_hosts: HashMap<String, Vec<RouteEntry>>,
    /// Wildcard suffix entries, e.g., ("*.example.com", routes).
    /// Sorted by pattern length descending so more-specific wildcards match first.
    wildcard_hosts: Vec<(String, Vec<RouteEntry>)>,
    /// Catch-all routes (proxies with empty `hosts`).
    catch_all: Vec<RouteEntry>,
}

/// High-performance router cache with pre-sorted route table and path lookup cache.
///
/// The route table is rebuilt atomically (via ArcSwap) whenever configuration changes,
/// keeping the rebuild off the hot request path. Repeated lookups hit a DashMap
/// cache for O(1) performance. Negative lookups (no route matched) are also cached
/// to prevent O(n) rescans from scanner traffic.
pub struct RouterCache {
    /// Pre-computed host-based route index.
    route_table: ArcSwap<HostRouteTable>,
    /// Bounded cache: "host\0path" → matched proxy for O(1) repeated lookups.
    /// `None` entries represent negative cache (no route matched),
    /// preventing O(n) rescans from scanner/bot traffic.
    path_cache: DashMap<String, Option<Arc<Proxy>>>,
    /// Maximum entries in path_cache before eviction.
    max_cache_entries: usize,
    /// Monotonic counter used for random-sample eviction (avoids clearing entire cache).
    eviction_counter: AtomicU64,
}

impl RouterCache {
    /// Build a new RouterCache from the given config.
    ///
    /// Routes are partitioned by host tier and pre-sorted by listen_path length
    /// descending so the first `starts_with` match is always the longest prefix match.
    pub fn new(config: &GatewayConfig, max_cache_entries: usize) -> Self {
        let table = Self::build_route_table(config);
        Self {
            route_table: ArcSwap::new(Arc::new(table)),
            path_cache: DashMap::with_capacity(max_cache_entries),
            max_cache_entries,
            eviction_counter: AtomicU64::new(0),
        }
    }

    /// Atomically rebuild the route table from new config and clear the path cache.
    ///
    /// Called by `ProxyState::update_config()` when database polling or SIGHUP
    /// delivers a new configuration. Lock-free for readers — in-flight requests
    /// continue using the previous table until they complete.
    pub fn rebuild(&self, config: &GatewayConfig) {
        let table = Self::build_route_table(config);
        self.route_table.store(Arc::new(table));
        self.path_cache.clear();
        debug!(
            "Router cache rebuilt: {} routes, path cache cleared",
            config.proxies.len()
        );
    }

    /// Find the matching proxy for a request host and path.
    ///
    /// Priority order:
    /// 1. Exact host + longest path prefix
    /// 2. Wildcard host + longest path prefix
    /// 3. Catch-all (no hosts) + longest path prefix
    ///
    /// Results are cached (including misses) for O(1) repeated lookups.
    pub fn find_proxy(&self, host: Option<&str>, path: &str) -> Option<Arc<Proxy>> {
        let cache_key = make_cache_key(host, path);

        // Fast path: check the cache (includes negative entries)
        if let Some(entry) = self.path_cache.get(&cache_key) {
            return entry.value().clone();
        }

        // Slow path: search the host route table in priority order
        let table = self.route_table.load();
        let result = Self::search_route_table(&table, host, path);

        // Cache both hits AND misses. Negative cache entries (None) prevent
        // O(n) rescans for repeated scanner/bot traffic hitting non-existent
        // paths. Bounded by max_cache_entries with eviction.
        if self.path_cache.len() >= self.max_cache_entries {
            self.evict_sample();
        }
        self.path_cache
            .insert(cache_key, result.as_ref().map(Arc::clone));

        result
    }

    /// Search the route table for a matching proxy.
    fn search_route_table(
        table: &HostRouteTable,
        host: Option<&str>,
        path: &str,
    ) -> Option<Arc<Proxy>> {
        if let Some(host) = host {
            // 1. Exact host match
            if let Some(routes) = table.exact_hosts.get(host)
                && let Some(proxy) = find_path_match(routes, path)
            {
                return Some(proxy);
            }

            // 2. Wildcard host match
            for (pattern, routes) in &table.wildcard_hosts {
                if wildcard_matches(pattern, host)
                    && let Some(proxy) = find_path_match(routes, path)
                {
                    return Some(proxy);
                }
            }
        }

        // 3. Catch-all (no host restriction)
        find_path_match(&table.catch_all, path)
    }

    /// Number of entries currently in the path lookup cache (for testing).
    #[allow(dead_code)]
    pub fn cache_len(&self) -> usize {
        self.path_cache.len()
    }

    /// Number of routes in the pre-sorted route table (for testing).
    #[allow(dead_code)]
    pub fn route_count(&self) -> usize {
        let table = self.route_table.load();
        let exact_count: usize = table.exact_hosts.values().map(|v| v.len()).sum();
        let wildcard_count: usize = table.wildcard_hosts.iter().map(|(_, v)| v.len()).sum();
        exact_count + wildcard_count + table.catch_all.len()
    }

    /// Evict ~25% of cache entries using counter-based pseudo-random sampling.
    /// Much better than clearing the entire cache because the remaining 75%
    /// of hot entries continue to serve O(1) hits, avoiding a thundering herd
    /// of O(routes) scans.
    fn evict_sample(&self) {
        let target_removals = self.max_cache_entries / 4;
        let seed = self.eviction_counter.fetch_add(1, Ordering::Relaxed);
        let mut removed = 0;

        // DashMap shards provide pseudo-random iteration order; we just
        // remove the first `target_removals` entries we encounter.
        // Use retain for efficient bulk removal.
        let mut keep_count = 0u64;
        self.path_cache.retain(|_, _| {
            if removed >= target_removals {
                return true;
            }
            // Use a simple hash of the counter to decide which entries to evict.
            // This provides a roughly uniform eviction pattern.
            keep_count += 1;
            if (keep_count.wrapping_mul(seed.wrapping_add(7))).is_multiple_of(4) {
                removed += 1;
                false
            } else {
                true
            }
        });

        debug!(
            "Router path cache evicted {} entries (was at capacity {})",
            removed, self.max_cache_entries
        );
    }

    /// Incrementally update the route table and surgically invalidate only
    /// the path cache entries affected by changed routes.
    ///
    /// The route table itself is rebuilt (cheap O(n log n) sort) because
    /// insertion order matters for longest-prefix matching. But the path
    /// cache — which is the expensive thing to lose — is preserved for all
    /// unaffected routes. Only paths that `starts_with` a changed
    /// listen_path are evicted, so the hot 99% of cache entries survive.
    pub fn apply_delta(&self, config: &GatewayConfig, affected_listen_paths: &[String]) {
        // Rebuild the sorted route table (cheap, O(n log n))
        let table = Self::build_route_table(config);
        self.route_table.store(Arc::new(table));

        if affected_listen_paths.is_empty() {
            return;
        }

        // Surgically invalidate path cache entries affected by changed routes.
        // The cache key format is "host\0path", so we extract the path portion
        // (after the NUL separator) for prefix matching against affected listen_paths.
        let before = self.path_cache.len();
        self.path_cache.retain(|cached_key, _| {
            let cached_path = cached_key
                .find('\0')
                .map(|i| &cached_key[i + 1..])
                .unwrap_or(cached_key.as_str());
            !affected_listen_paths
                .iter()
                .any(|lp| cached_path.starts_with(lp.as_str()) || lp.starts_with(cached_path))
        });
        let evicted = before - self.path_cache.len();
        if evicted > 0 {
            debug!(
                "Router cache: route table rebuilt ({} routes), surgically evicted {} of {} path cache entries",
                config.proxies.len(),
                evicted,
                before
            );
        }
    }

    /// Build a pre-computed host route table from config.
    ///
    /// Partitions proxies into exact-host, wildcard-host, and catch-all tiers.
    /// Within each tier, routes are sorted by listen_path length descending.
    fn build_route_table(config: &GatewayConfig) -> HostRouteTable {
        let mut exact_hosts: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        let mut wildcard_hosts: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        let mut catch_all: Vec<RouteEntry> = Vec::new();

        for proxy in config
            .proxies
            .iter()
            .filter(|p| !p.backend_protocol.is_stream_proxy())
        {
            let arc_proxy = Arc::new(proxy.clone());

            if proxy.hosts.is_empty() {
                // Catch-all: no host restriction
                catch_all.push(RouteEntry {
                    listen_path: proxy.listen_path.clone(),
                    proxy: Arc::clone(&arc_proxy),
                });
            } else {
                // Register under each host
                for host in &proxy.hosts {
                    let entry = RouteEntry {
                        listen_path: proxy.listen_path.clone(),
                        proxy: Arc::clone(&arc_proxy),
                    };
                    if host.starts_with("*.") {
                        wildcard_hosts.entry(host.clone()).or_default().push(entry);
                    } else {
                        exact_hosts.entry(host.clone()).or_default().push(entry);
                    }
                }
            }
        }

        // Sort each route list by listen_path length descending (longest first)
        for routes in exact_hosts.values_mut() {
            routes.sort_by(|a, b| b.listen_path.len().cmp(&a.listen_path.len()));
        }
        let mut wildcard_vec: Vec<(String, Vec<RouteEntry>)> = wildcard_hosts.into_iter().collect();
        for (_, routes) in &mut wildcard_vec {
            routes.sort_by(|a, b| b.listen_path.len().cmp(&a.listen_path.len()));
        }
        // Sort wildcard patterns by length descending (more-specific wildcards first)
        wildcard_vec.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        catch_all.sort_by(|a, b| b.listen_path.len().cmp(&a.listen_path.len()));

        HostRouteTable {
            exact_hosts,
            wildcard_hosts: wildcard_vec,
            catch_all,
        }
    }
}

/// Find the first path-matching route in a pre-sorted route list.
fn find_path_match(routes: &[RouteEntry], path: &str) -> Option<Arc<Proxy>> {
    routes
        .iter()
        .find(|entry| {
            if path == entry.listen_path {
                true
            } else if path.starts_with(&entry.listen_path) {
                entry.listen_path.ends_with('/')
                    || path.as_bytes().get(entry.listen_path.len()) == Some(&b'/')
                    || path.as_bytes().get(entry.listen_path.len()) == Some(&b'?')
            } else {
                false
            }
        })
        .map(|entry| Arc::clone(&entry.proxy))
}

/// Build a cache key from host and path.
/// Uses NUL separator which cannot appear in hostnames or URL paths.
fn make_cache_key(host: Option<&str>, path: &str) -> String {
    match host {
        Some(h) => format!("{}\0{}", h, path),
        None => format!("\0{}", path),
    }
}
