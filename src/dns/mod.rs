use dashmap::DashMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// A cached DNS entry with TTL.
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
}

/// Asynchronous DNS resolver with in-memory caching.
#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<DashMap<String, DnsCacheEntry>>,
    global_overrides: HashMap<String, String>,
    default_ttl: Duration,
}

impl DnsCache {
    pub fn new(default_ttl_seconds: u64, global_overrides: HashMap<String, String>) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            global_overrides,
            default_ttl: Duration::from_secs(default_ttl_seconds),
        }
    }

    /// Resolve a hostname to an IP address, using cache, overrides, or actual DNS.
    pub async fn resolve(
        &self,
        hostname: &str,
        per_proxy_override: Option<&str>,
        per_proxy_ttl: Option<u64>,
    ) -> Result<IpAddr, anyhow::Error> {
        // Check per-proxy static override first
        if let Some(ip_str) = per_proxy_override {
            let addr: IpAddr = ip_str.parse()?;
            return Ok(addr);
        }

        // Check global overrides
        if let Some(ip_str) = self.global_overrides.get(hostname) {
            let addr: IpAddr = ip_str.parse()?;
            return Ok(addr);
        }

        // Check cache
        if let Some(entry) = self.cache.get(hostname) {
            if entry.expires_at > Instant::now() && !entry.addresses.is_empty() {
                return Ok(entry.addresses[0]);
            }
        }

        // Perform actual DNS resolution
        let addrs = self.do_resolve(hostname).await?;
        if addrs.is_empty() {
            anyhow::bail!("DNS resolution returned no addresses for {}", hostname);
        }

        let ttl = per_proxy_ttl
            .map(Duration::from_secs)
            .unwrap_or(self.default_ttl);

        self.cache.insert(
            hostname.to_string(),
            DnsCacheEntry {
                addresses: addrs.clone(),
                expires_at: Instant::now() + ttl,
            },
        );

        debug!("DNS resolved {} -> {:?} (ttl={:?})", hostname, addrs[0], ttl);
        Ok(addrs[0])
    }

    async fn do_resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, anyhow::Error> {
        // Try parsing as IP first
        if let Ok(addr) = hostname.parse::<IpAddr>() {
            return Ok(vec![addr]);
        }

        // Use tokio's built-in DNS resolution
        let addrs: Vec<IpAddr> = tokio::net::lookup_host(format!("{}:0", hostname))
            .await?
            .map(|sa| sa.ip())
            .collect();

        Ok(addrs)
    }

    /// Warmup: resolve all hostnames from the config at startup.
    pub async fn warmup(&self, hostnames: Vec<(String, Option<String>, Option<u64>)>) {
        info!("DNS warmup: resolving {} hostnames", hostnames.len());
        let mut handles = Vec::new();

        for (host, override_ip, ttl) in hostnames {
            let cache = self.clone();
            handles.push(tokio::spawn(async move {
                match cache.resolve(&host, override_ip.as_deref(), ttl).await {
                    Ok(addr) => debug!("DNS warmup: {} -> {}", host, addr),
                    Err(e) => warn!("DNS warmup failed for {}: {}", host, e),
                }
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }

        info!("DNS warmup complete");
    }
}
