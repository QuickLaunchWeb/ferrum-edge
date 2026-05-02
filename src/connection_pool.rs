//! Connection pool manager for HTTP/HTTPS/WebSocket backend clients.
//!
//! Provides `reqwest::Client` reuse keyed by connection identity (destination,
//! protocol, DNS override, TLS trust, mTLS credentials). Each unique key gets
//! one `reqwest::Client` which internally manages its own TCP connection pool.
//!
//! All clients use the gateway's shared `DnsCache` as their resolver, keeping
//! DNS lookups off the hot request path. A shared pool shell in `src/pool/`
//! handles the DashMap, key-buffer fast path, and idle cleanup.

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use crate::dns::{DnsCache, DnsCacheResolver};
use crate::pool::{GenericPool, PoolManager};
use crate::tls::TlsPolicy;
use crate::tls::backend::{BackendTlsConfigBuilder, BackendTlsConfigCache};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
struct ReqwestPoolManager {
    global_config: PoolConfig,
    global_env_config: crate::config::EnvConfig,
    dns_cache: DnsCache,
    tls_policy: Option<Arc<TlsPolicy>>,
    crls: crate::tls::CrlList,
    backend_h3_tls_configs: BackendTlsConfigCache,
}

impl ReqwestPoolManager {
    fn pool_key_owned(&self, proxy: &Proxy) -> String {
        let mut key = String::with_capacity(128);
        self.build_key(proxy, &proxy.backend_host, proxy.backend_port, 0, &mut key);
        key
    }

    async fn create_client(&self, proxy: &Proxy, config: &PoolConfig) -> Result<reqwest::Client> {
        let dns_resolver = Arc::new(DnsCacheResolver::new(self.dns_cache.clone()));

        let mut client_builder = BackendTlsConfigBuilder {
            proxy,
            policy: self.tls_policy.as_deref(),
            global_ca: self
                .global_env_config
                .tls_ca_bundle_path
                .as_deref()
                .map(Path::new),
            global_no_verify: self.global_env_config.tls_no_verify,
            global_client_cert: self
                .global_env_config
                .backend_tls_client_cert_path
                .as_deref()
                .map(Path::new),
            global_client_key: self
                .global_env_config
                .backend_tls_client_key_path
                .as_deref()
                .map(Path::new),
            crls: &self.crls,
        }
        .build_reqwest()
        .map_err(|e| anyhow::anyhow!("Failed to build reqwest backend TLS config: {}", e))?
        .dns_resolver(dns_resolver)
        .tcp_nodelay(true)
        .pool_max_idle_per_host(config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(config.idle_timeout_seconds));

        // NOTE: Neither `backend_connect_timeout_ms` nor `backend_read_timeout_ms`
        // is baked into the client here. The `reqwest::Client` is shared across
        // all proxies whose pool key resolves to the same identity (same
        // backend, TLS, DNS override). Baking a timeout into the shared client
        // means the first proxy to create the client would dictate the timeout
        // for every other proxy reusing it — cross-route policy leakage.
        //
        // Both timeouts are applied per-request on the dispatch side via
        // `RequestBuilder::connect_timeout()` and `RequestBuilder::timeout()`
        // which override the (absent) client defaults. The connect-timeout
        // override is provided by a vendored copy of reqwest 0.13.2 with
        // PR seanmonstar/reqwest#3017 applied (see
        // `docs/upstream-reqwest-patches/001-per-request-connect-timeout/`
        // for the lifecycle and retirement plan).

        if config.enable_http_keep_alive {
            client_builder =
                client_builder.tcp_keepalive(Duration::from_secs(config.tcp_keepalive_seconds));
        }

        if config.enable_http2 {
            client_builder = client_builder
                .http2_keep_alive_interval(Duration::from_secs(
                    config.http2_keep_alive_interval_seconds,
                ))
                .http2_keep_alive_timeout(Duration::from_secs(
                    config.http2_keep_alive_timeout_seconds,
                ))
                .http2_initial_stream_window_size(config.http2_initial_stream_window_size)
                .http2_initial_connection_window_size(config.http2_initial_connection_window_size)
                .http2_adaptive_window(config.http2_adaptive_window)
                .http2_max_frame_size(config.http2_max_frame_size);
        }

        if let Some(ref dns_override) = proxy.dns_override
            && let Ok(ip) = dns_override.parse::<std::net::IpAddr>()
        {
            let socket_addr = SocketAddr::new(ip, proxy.backend_port);
            client_builder = client_builder.resolve(&proxy.backend_host, socket_addr);
        }

        Ok(client_builder.build()?)
    }
}

#[async_trait]
impl PoolManager for ReqwestPoolManager {
    type Connection = reqwest::Client;

    fn build_key(&self, proxy: &Proxy, host: &str, port: u16, _shard: usize, buf: &mut String) {
        use std::fmt::Write;
        buf.clear();

        if let Some(ref upstream_id) = proxy.upstream_id {
            let _ = write!(buf, "u={}|", upstream_id);
        } else {
            let _ = write!(buf, "d={}:{}|", host, port);
        }
        // Pool keys partition by scheme discriminant so two proxies with different
        // wire schemes (http vs https, tcp vs tcps, etc.) don't share a client.
        // `u8::MAX` is a stable sentinel for the rare "scheme not yet resolved"
        // case — `normalize_fields()` populates `backend_scheme` before any
        // request hits the pool, so this arm is defensive.
        debug_assert!(
            proxy.backend_scheme.is_some(),
            "backend_scheme should be resolved before HTTP pool key generation"
        );
        let scheme_disc = proxy.backend_scheme.map(|s| s as u8).unwrap_or(u8::MAX);
        let _ = write!(buf, "{}|", scheme_disc);
        buf.push_str(proxy.dns_override.as_deref().unwrap_or_default());
        buf.push('|');
        buf.push_str(
            proxy
                .resolved_tls
                .server_ca_cert_path
                .as_deref()
                .unwrap_or_default(),
        );
        buf.push('|');
        buf.push_str(
            proxy
                .resolved_tls
                .client_cert_path
                .as_deref()
                .or(self
                    .global_env_config
                    .backend_tls_client_cert_path
                    .as_deref())
                .unwrap_or_default(),
        );
        buf.push('|');
        // The client *key* path is part of connection identity for the same
        // reason as the cert path: two proxies that share `client_cert_path`
        // but use different `client_key_path` produce different rustls client
        // configs. Without this segment they collide on the same pool entry
        // and the second proxy's handshake silently uses the first proxy's
        // private key. Mirrors the H3 pool key
        // (`src/http3/client.rs::write_pool_key_with_host`) and the backend
        // capability registry key
        // (`src/proxy/backend_capabilities.rs::write_capability_key`).
        buf.push_str(
            proxy
                .resolved_tls
                .client_key_path
                .as_deref()
                .or(self
                    .global_env_config
                    .backend_tls_client_key_path
                    .as_deref())
                .unwrap_or_default(),
        );
        buf.push('|');
        let verify = proxy.resolved_tls.verify_server_cert && !self.global_env_config.tls_no_verify;
        buf.push(if verify { '1' } else { '0' });
    }

    async fn create(&self, _key: &str, proxy: &Proxy) -> Result<reqwest::Client> {
        let config = self.global_config.for_proxy(proxy);
        self.create_client(proxy, &config).await
    }

    fn is_healthy(&self, _conn: &Self::Connection) -> bool {
        true
    }

    fn destroy(&self, conn: Self::Connection) {
        drop(conn);
    }
}

/// Connection pool manager for reusing HTTP clients.
pub struct ConnectionPool {
    pool: Arc<GenericPool<ReqwestPoolManager>>,
}

impl ConnectionPool {
    /// Create a new connection pool manager with global configuration.
    pub fn new(
        global_config: PoolConfig,
        mtls_config: crate::config::EnvConfig,
        dns_cache: DnsCache,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
    ) -> Self {
        let cleanup_interval =
            Duration::from_secs(mtls_config.pool_cleanup_interval_seconds.max(1));
        let manager = Arc::new(ReqwestPoolManager {
            global_config: global_config.clone(),
            global_env_config: mtls_config,
            dns_cache,
            tls_policy,
            crls,
            backend_h3_tls_configs: BackendTlsConfigCache::new(),
        });

        Self {
            pool: GenericPool::new(manager, global_config, cleanup_interval),
        }
    }

    /// Get or create a client for the given proxy using global defaults + proxy overrides.
    pub async fn get_client(&self, proxy: &Proxy) -> Result<reqwest::Client> {
        self.pool
            .get(proxy, &proxy.backend_host, proxy.backend_port, 0)
            .await
    }

    /// Expose the pool key for warmup deduplication.
    ///
    /// `warmup_connection_pools` composes this with the per-target
    /// `host:port` to dedup reqwest HEAD warmup tasks. Including the
    /// pool key (which carries the TLS-aware client identity:
    /// `{dest}|{proto}|{dns_override}|{ca}|{mtls_cert}|{mtls_key}|{verify}`)
    /// in the dedup means proxies that share `(scheme, host, port)` but
    /// have divergent TLS configs each get their own warmup task —
    /// matching the fact that they end up with separate
    /// `reqwest::Client`s at runtime.
    pub fn pool_key_for_warmup(&self, proxy: &Proxy) -> String {
        self.pool.manager().pool_key_owned(proxy)
    }

    /// Get the global pool configuration.
    pub fn global_pool_config(&self) -> &PoolConfig {
        &self.pool.manager().global_config
    }

    /// Get pool statistics for monitoring.
    pub fn get_stats(&self) -> PoolStats {
        let stats = self.pool.stats();
        let entries_per_host = self
            .pool
            .keys_snapshot()
            .into_iter()
            .map(|key| (key, 1usize))
            .collect();

        PoolStats {
            total_pools: stats.size,
            entries_per_host,
            max_idle_per_host: stats.max_idle_per_host,
            idle_timeout_seconds: stats.idle_timeout_seconds,
        }
    }

    /// Get TLS configuration for HTTP/3 backend connections.
    pub fn get_tls_config_for_backend(
        &self,
        proxy: &Proxy,
    ) -> Result<Arc<rustls::ClientConfig>, anyhow::Error> {
        let manager = self.pool.manager();
        manager
            .backend_h3_tls_configs
            .get_or_try_build(manager.pool_key_owned(proxy), || {
                let mut client_config = BackendTlsConfigBuilder {
                    proxy,
                    policy: manager.tls_policy.as_deref(),
                    global_ca: manager
                        .global_env_config
                        .tls_ca_bundle_path
                        .as_deref()
                        .map(Path::new),
                    global_no_verify: manager.global_env_config.tls_no_verify,
                    global_client_cert: manager
                        .global_env_config
                        .backend_tls_client_cert_path
                        .as_deref()
                        .map(Path::new),
                    global_client_key: manager
                        .global_env_config
                        .backend_tls_client_key_path
                        .as_deref()
                        .map(Path::new),
                    crls: &manager.crls,
                }
                .build_rustls_quic()
                .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 backend TLS config: {}", e))?;

                client_config.alpn_protocols = vec![b"h3".to_vec()];
                Ok(client_config)
            })
    }

    /// Clear all pooled connections.
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.pool.clear();
    }
}

/// Connection pool statistics.
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_pools: usize,
    pub entries_per_host: HashMap<String, usize>,
    pub max_idle_per_host: usize,
    pub idle_timeout_seconds: u64,
}

impl std::fmt::Display for PoolStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Connection Pool Statistics:")?;
        writeln!(f, "  Total pooled connections: {}", self.total_pools)?;
        writeln!(f, "  Max idle per host: {}", self.max_idle_per_host)?;
        writeln!(f, "  Idle timeout: {}s", self.idle_timeout_seconds)?;
        writeln!(f, "  Connections per host:")?;
        for (host, count) in &self.entries_per_host {
            writeln!(f, "    {}: {}", host, count)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Inline tests for the private `ReqwestPoolManager::build_key` helper.
    //!
    //! `build_key` is a `PoolManager` trait impl on a private struct, so it
    //! cannot be exercised from `tests/`. The cases below pin the
    //! connection-identity contract documented in CLAUDE.md ("Connection
    //! Pool Keys"): every TLS field that affects the rustls handshake — and
    //! in particular `client_key_path` — must produce a distinct key.
    use super::*;
    use crate::config::EnvConfig;
    use crate::config::types::{
        AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy, default_namespace,
    };
    use crate::dns::{DnsCache, DnsConfig};
    use crate::pool::PoolManager;
    use chrono::Utc;

    fn proxy_for_pool_key(client_cert_path: Option<&str>, client_key_path: Option<&str>) -> Proxy {
        Proxy {
            id: "test".into(),
            namespace: default_namespace(),
            name: None,
            hosts: vec![],
            listen_path: Some("/test".to_string()),
            backend_scheme: Some(BackendScheme::Https),
            dispatch_kind: DispatchKind::from(BackendScheme::Https),
            backend_host: "backend.example.com".into(),
            backend_port: 443,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 5000,
            backend_read_timeout_ms: 30000,
            backend_write_timeout_ms: 30000,
            backend_tls_client_cert_path: client_cert_path.map(str::to_string),
            backend_tls_client_key_path: client_key_path.map(str::to_string),
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: BackendTlsConfig {
                client_cert_path: client_cert_path.map(str::to_string),
                client_key_path: client_key_path.map(str::to_string),
                server_ca_cert_path: None,
                verify_server_cert: true,
            },
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::Single,
            plugins: vec![],
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            pool_tcp_keepalive_seconds: None,
            upstream_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: Default::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            tcp_idle_timeout_seconds: Some(300),
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn manager_with_env(env_config: EnvConfig) -> ReqwestPoolManager {
        ReqwestPoolManager {
            global_config: PoolConfig::default(),
            global_env_config: env_config,
            dns_cache: DnsCache::new(DnsConfig::default()),
            tls_policy: None,
            crls: Arc::new(Vec::new()),
            backend_h3_tls_configs: BackendTlsConfigCache::new(),
        }
    }

    /// Two proxies sharing the same `client_cert_path` but with distinct
    /// `client_key_path` values must NOT collide on the same reqwest pool
    /// entry. Without `client_key_path` in the key, the second proxy
    /// silently reuses the first proxy's reqwest::Client (wrong private
    /// key for the rustls handshake). Mirrors the H3 pool key contract in
    /// `src/http3/client.rs::write_pool_key_with_host`.
    #[test]
    fn http1_pool_key_distinguishes_client_key_path() {
        let manager = manager_with_env(EnvConfig::default());
        let proxy_a = proxy_for_pool_key(Some("/etc/certs/shared.pem"), Some("/etc/keys/k1.pem"));
        let proxy_b = proxy_for_pool_key(Some("/etc/certs/shared.pem"), Some("/etc/keys/k2.pem"));

        let mut key_a = String::new();
        manager.build_key(
            &proxy_a,
            &proxy_a.backend_host,
            proxy_a.backend_port,
            0,
            &mut key_a,
        );
        let mut key_b = String::new();
        manager.build_key(
            &proxy_b,
            &proxy_b.backend_host,
            proxy_b.backend_port,
            0,
            &mut key_b,
        );

        assert_ne!(
            key_a, key_b,
            "HTTP/1.1 pool key must differentiate proxies with the same cert \
             but different client key paths — got identical key {:?}",
            key_a
        );
    }

    /// Env-fallback parity with the cert path: when a proxy leaves
    /// `client_key_path` unset and only the global env var differs, the keys
    /// must split. The HTTP/1.1 builder threads `EnvConfig::backend_tls_client_key_path`
    /// through `build_key` for exactly this reason — same as the cert path.
    /// Two managers with different env keys but otherwise-identical state
    /// must produce distinct pool keys for the same proxy.
    #[test]
    fn http1_pool_key_distinguishes_env_client_key_path() {
        let env_a = EnvConfig {
            backend_tls_client_cert_path: Some("/etc/certs/shared.pem".into()),
            backend_tls_client_key_path: Some("/etc/keys/k1.pem".into()),
            ..EnvConfig::default()
        };
        let env_b = EnvConfig {
            backend_tls_client_cert_path: Some("/etc/certs/shared.pem".into()),
            backend_tls_client_key_path: Some("/etc/keys/k2.pem".into()),
            ..EnvConfig::default()
        };

        let manager_a = manager_with_env(env_a);
        let manager_b = manager_with_env(env_b);
        let proxy = proxy_for_pool_key(None, None);

        let mut key_a = String::new();
        manager_a.build_key(
            &proxy,
            &proxy.backend_host,
            proxy.backend_port,
            0,
            &mut key_a,
        );
        let mut key_b = String::new();
        manager_b.build_key(
            &proxy,
            &proxy.backend_host,
            proxy.backend_port,
            0,
            &mut key_b,
        );

        assert_ne!(
            key_a, key_b,
            "HTTP/1.1 pool key must include the env-fallback client_key_path \
             — got identical key {:?}",
            key_a
        );
    }

    /// Backwards-compat: when neither proxy nor env sets a cert/key path,
    /// the new key-path segment is the empty string and non-mTLS proxies
    /// still share the same pool entry. Guards against accidentally
    /// fragmenting the pool for the most common (no-mTLS) configuration.
    #[test]
    fn http1_pool_key_unchanged_when_no_mtls_configured() {
        let manager = manager_with_env(EnvConfig::default());
        let proxy_a = proxy_for_pool_key(None, None);
        let proxy_b = proxy_for_pool_key(None, None);

        let mut key_a = String::new();
        manager.build_key(
            &proxy_a,
            &proxy_a.backend_host,
            proxy_a.backend_port,
            0,
            &mut key_a,
        );
        let mut key_b = String::new();
        manager.build_key(
            &proxy_b,
            &proxy_b.backend_host,
            proxy_b.backend_port,
            0,
            &mut key_b,
        );

        assert_eq!(
            key_a, key_b,
            "Two no-mTLS HTTP/1.1 proxies must share a pool entry — \
             fragmentation would destroy connection reuse"
        );
    }
}
