//! Request Deduplication Plugin
//!
//! Prevents duplicate API calls by tracking idempotency keys. When a request
//! arrives with an idempotency key header (e.g., `Idempotency-Key`) and the
//! same key was seen within the configured TTL, the plugin returns the cached
//! response instead of forwarding to the backend.
//!
//! Supports two storage modes:
//! - **local** (default): In-memory `DashMap` with TTL-based eviction. Suitable
//!   for single-instance deployments.
//! - **redis**: Centralized storage via Redis/Valkey/DragonflyDB/KeyDB/Garnet.
//!   Enables deduplication across multiple gateway instances. Uses the shared
//!   `RedisRateLimitClient` infrastructure with automatic local fallback when
//!   Redis is unreachable.
//!
//! Only applies to non-safe HTTP methods (POST, PUT, PATCH by default).

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use http::{HeaderName, Method};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

use super::utils::cache_headers::sanitize_cached_headers;
use super::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

/// A cached response stored for deduplication replay.
#[derive(Debug, Clone)]
struct CachedResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Bytes,
    inserted_at: Instant,
}

/// In-flight marker to handle concurrent duplicate requests.
///
/// `InFlight` carries the timestamp it was inserted so stale markers (from
/// requests that died after `before_proxy` but before `on_final_response_body`,
/// e.g., backend timeout, downstream plugin reject, dropped connection) can be
/// detected and replaced rather than indefinitely returning 409 Conflict.
#[derive(Debug, Clone)]
enum DeduplicationEntry {
    /// Request is currently being processed. `started_at` allows stale-marker
    /// detection so abandoned in-flight entries don't permanently block retries.
    InFlight { started_at: Instant },
    /// Response has been cached.
    Completed(CachedResponse),
}

enum LocalDeduplicationAction {
    Fresh,
    Replay(CachedResponse),
    Conflict,
}

pub struct RequestDeduplication {
    /// Header name to read the idempotency key from.
    header_name: String,
    /// Time-to-live for cached responses.
    ttl: Duration,
    /// How long an `InFlight` marker remains valid before being treated as
    /// stale and replaced by a new request. Must be set at or above the
    /// longest backend request that should be protected from concurrent
    /// duplicate execution; set too low, slow legitimate requests could have
    /// duplicate retries bypass the in-flight lock and re-execute side-effecting
    /// operations. Defaults to `ttl_seconds`.
    inflight_ttl: Duration,
    /// Maximum number of cached entries (local mode).
    max_entries: usize,
    /// HTTP methods to apply deduplication to.
    applicable_methods: Vec<String>,
    /// Whether to scope keys by authenticated consumer identity.
    scope_by_consumer: bool,
    /// Whether to require the idempotency header (reject if missing).
    enforce_required: bool,
    /// Local in-memory cache.
    local_cache: Arc<DashMap<String, DeduplicationEntry>>,
    /// Optional Redis client for centralized deduplication.
    redis_client: Option<Arc<RedisRateLimitClient>>,
    /// Counter for background cleanup scheduling.
    last_cleanup: AtomicU64,
}

impl RequestDeduplication {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("request_deduplication: config must be an object".to_string());
        }

        let header_name = parse_header_name(
            optional_string(config, "header_name")?.unwrap_or("Idempotency-Key"),
        )?;

        let ttl_seconds = optional_positive_u64(config, "ttl_seconds")?.unwrap_or(300);
        let ttl = Duration::from_secs(ttl_seconds);

        let inflight_ttl_seconds =
            optional_positive_u64(config, "inflight_ttl_seconds")?.unwrap_or(ttl_seconds);
        let inflight_ttl = Duration::from_secs(inflight_ttl_seconds);

        let max_entries = optional_positive_usize(config, "max_entries")?.unwrap_or(10_000);

        let applicable_methods = parse_applicable_methods(config)?;
        let scope_by_consumer = optional_bool(config, "scope_by_consumer")?.unwrap_or(true);
        let enforce_required = optional_bool(config, "enforce_required")?.unwrap_or(false);

        // Build optional Redis client
        let default_prefix = default_redis_key_prefix(http_client.namespace());
        let redis_client =
            RedisConfig::from_plugin_config(config, &default_prefix)?.map(|redis_config| {
                let dns_cache = http_client.dns_cache();
                let tls_no_verify = http_client.tls_no_verify();
                let tls_ca_bundle_path = http_client.tls_ca_bundle_path();
                Arc::new(RedisRateLimitClient::new(
                    redis_config,
                    dns_cache.cloned(),
                    tls_no_verify,
                    tls_ca_bundle_path,
                ))
            });

        Ok(Self {
            header_name,
            ttl,
            inflight_ttl,
            max_entries,
            applicable_methods,
            scope_by_consumer,
            enforce_required,
            local_cache: Arc::new(DashMap::new()),
            redis_client,
            last_cleanup: AtomicU64::new(0),
        })
    }

    /// Build the deduplication key from the request context and idempotency value.
    fn build_key(&self, ctx: &RequestContext, idempotency_value: &str) -> String {
        let proxy_id = ctx
            .matched_proxy
            .as_ref()
            .map(|p| p.id.as_str())
            .unwrap_or("_");

        if self.scope_by_consumer
            && let Some(identity) = ctx.effective_identity()
        {
            let mut key = String::with_capacity(
                proxy_id.len() + identity.len() + idempotency_value.len() + 2,
            );
            key.push_str(proxy_id);
            key.push(':');
            key.push_str(identity);
            key.push(':');
            key.push_str(idempotency_value);
            return key;
        }

        let mut key = String::with_capacity(proxy_id.len() + idempotency_value.len() + 1);
        key.push_str(proxy_id);
        key.push(':');
        key.push_str(idempotency_value);
        key
    }

    fn local_lookup_or_mark_inflight(&self, key: &str, now: Instant) -> LocalDeduplicationAction {
        match self.local_cache.entry(key.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(DeduplicationEntry::InFlight { started_at: now });
                LocalDeduplicationAction::Fresh
            }
            Entry::Occupied(mut entry) => match entry.get() {
                DeduplicationEntry::Completed(cached) => {
                    if now.duration_since(cached.inserted_at) < self.ttl {
                        LocalDeduplicationAction::Replay(cached.clone())
                    } else {
                        entry.insert(DeduplicationEntry::InFlight { started_at: now });
                        LocalDeduplicationAction::Fresh
                    }
                }
                DeduplicationEntry::InFlight { started_at } => {
                    if now.duration_since(*started_at) >= self.inflight_ttl {
                        entry.insert(DeduplicationEntry::InFlight { started_at: now });
                        LocalDeduplicationAction::Fresh
                    } else {
                        LocalDeduplicationAction::Conflict
                    }
                }
            },
        }
    }

    /// Try to retrieve a cached response from Redis.
    async fn redis_get(&self, key: &str) -> Option<CachedResponse> {
        let redis = self.redis_client.as_ref()?;
        if !redis.is_available() {
            return None;
        }

        let redis_key = redis.make_key(&[key]);
        let data = match redis.get_bytes(&redis_key).await {
            Ok(Some(d)) => d,
            Ok(None) => return None,
            Err(()) => return None,
        };

        serde_json::from_slice::<SerializableCachedResponse>(&data)
            .ok()
            .map(|s| CachedResponse {
                status_code: s.status_code,
                headers: s.headers,
                body: Bytes::from(s.body),
                inserted_at: Instant::now(), // Not meaningful for Redis entries
            })
    }

    /// Store a cached response in Redis with TTL.
    async fn redis_set(&self, key: &str, response: &CachedResponse) {
        let Some(redis) = self.redis_client.as_ref() else {
            return;
        };
        if !redis.is_available() {
            return;
        }

        let serializable = SerializableCachedResponse {
            status_code: response.status_code,
            headers: response.headers.clone(),
            body: response.body.to_vec(),
        };

        let data = match serde_json::to_vec(&serializable) {
            Ok(d) => d,
            Err(_) => return,
        };

        let redis_key = redis.make_key(&[key]);
        let ttl_seconds = self.ttl.as_secs().max(1);
        if let Err(()) = redis
            .set_bytes_with_expire(&redis_key, &data, ttl_seconds)
            .await
        {
            debug!("request_deduplication: Redis SET failed");
        }
    }

    /// Evict expired entries from local cache.
    fn cleanup_local_cache(&self) {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Only run cleanup every 30 seconds
        let last = self.last_cleanup.load(Ordering::Relaxed);
        let over_capacity = self.local_cache.len() > self.max_entries;
        if !over_capacity && now_epoch.saturating_sub(last) < 30 {
            return;
        }
        if self
            .last_cleanup
            .compare_exchange(last, now_epoch, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return; // Another thread is doing cleanup
        }

        let now = Instant::now();
        self.local_cache.retain(|_, entry| match entry {
            DeduplicationEntry::Completed(cached) => {
                now.duration_since(cached.inserted_at) < self.ttl
            }
            // Drop in-flight markers that have exceeded inflight_ttl — the
            // originating request must have died (timeout, downstream reject,
            // connection drop) without ever reaching `on_final_response_body`.
            // Without this, duplicate requests would receive 409 Conflict
            // forever (until LRU max-entries eviction).
            DeduplicationEntry::InFlight { started_at } => {
                now.duration_since(*started_at) < self.inflight_ttl
            }
        });

        // Enforce max entries by removing oldest Completed entries first. Active
        // (non-stale) InFlight markers are NEVER evicted by LRU because evicting
        // them would release the in-flight lock while the original request is
        // still executing — a duplicate retry for that key would then bypass the
        // lock and re-execute side-effecting operations. Stale InFlight markers
        // (age >= inflight_ttl) are already dropped by the retain() above. This
        // means max_entries can be temporarily exceeded if the cache is
        // saturated with active in-flight work; correctness (no duplicate
        // writes) is strictly preferred over hitting the memory cap.
        if self.local_cache.len() > self.max_entries {
            let mut completed_with_time: Vec<(String, Instant)> = self
                .local_cache
                .iter()
                .filter_map(|entry| match entry.value() {
                    DeduplicationEntry::Completed(cached) => {
                        Some((entry.key().clone(), cached.inserted_at))
                    }
                    DeduplicationEntry::InFlight { .. } => None,
                })
                .collect();
            completed_with_time.sort_by_key(|(_, t)| *t);

            let to_remove = self.local_cache.len().saturating_sub(self.max_entries);
            for (key, _) in completed_with_time.into_iter().take(to_remove) {
                self.local_cache.remove(&key);
            }
        }
    }
}

/// Serializable form of CachedResponse for Redis storage.
#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableCachedResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("request_deduplication: '{field}' must be a string"))
}

fn optional_positive_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "request_deduplication: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "request_deduplication: '{field}' must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = optional_positive_u64(config, field)? else {
        return Ok(None);
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("request_deduplication: '{field}' is too large for this platform"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("request_deduplication: '{field}' must be a boolean"))
}

fn parse_header_name(value: &str) -> Result<String, String> {
    HeaderName::from_bytes(value.as_bytes())
        .map(|name| name.as_str().to_string())
        .map_err(|_| {
            "request_deduplication: 'header_name' must be a valid HTTP header name".to_string()
        })
}

fn parse_applicable_methods(config: &Value) -> Result<Vec<String>, String> {
    let Some(value) = config.get("applicable_methods") else {
        return Ok(vec![
            "POST".to_string(),
            "PUT".to_string(),
            "PATCH".to_string(),
        ]);
    };
    let Some(methods) = value.as_array() else {
        return Err(
            "request_deduplication: 'applicable_methods' must be an array of method strings"
                .to_string(),
        );
    };
    if methods.is_empty() {
        return Err("request_deduplication: applicable_methods must not be empty".to_string());
    }

    let mut parsed = Vec::with_capacity(methods.len());
    for method in methods {
        let Some(method) = method.as_str() else {
            return Err(
                "request_deduplication: 'applicable_methods' must contain only strings".to_string(),
            );
        };
        let method = method.trim();
        if method.is_empty() || Method::from_bytes(method.as_bytes()).is_err() {
            return Err(
                "request_deduplication: 'applicable_methods' contains an invalid HTTP method"
                    .to_string(),
            );
        }
        parsed.push(method.to_ascii_uppercase());
    }

    Ok(parsed)
}

fn default_redis_key_prefix(namespace: &str) -> String {
    let mut prefix = String::with_capacity(namespace.len() + 6);
    prefix.push_str(namespace);
    prefix.push_str(":dedup");
    prefix
}

fn missing_idempotency_body(header_name: &str) -> String {
    let mut message = String::with_capacity(41 + header_name.len());
    message.push_str("Missing required idempotency header: ");
    message.push_str(header_name);
    serde_json::json!({ "error": message }).to_string()
}

#[async_trait]
impl Plugin for RequestDeduplication {
    fn name(&self) -> &str {
        "request_deduplication"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_DEDUPLICATION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only apply to configured methods
        if !self
            .applicable_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&ctx.method))
        {
            return PluginResult::Continue;
        }

        let key = {
            // Get idempotency key from headers. Keep the borrow scoped so no
            // header-map borrow survives across Redis/cache awaits below.
            let idempotency_value = match headers.get(&self.header_name) {
                Some(value) if !value.is_empty() => value.as_str(),
                _ => {
                    if self.enforce_required {
                        return PluginResult::Reject {
                            status_code: 400,
                            body: missing_idempotency_body(&self.header_name),
                            headers: HashMap::new(),
                        };
                    }
                    return PluginResult::Continue;
                }
            };
            self.build_key(ctx, idempotency_value)
        };

        // Periodic cleanup
        self.cleanup_local_cache();

        // Check Redis first (centralized dedup across instances)
        if self.redis_client.is_some()
            && let Some(cached) = self.redis_get(&key).await
        {
            debug!("request_deduplication: Redis cache hit, replaying response");
            // Defense-in-depth: re-sanitize on replay even though insert
            // already strips. A stored entry written before this fix landed,
            // or by a peer running an older binary against a shared Redis,
            // could still carry session-bearing headers.
            let mut response_headers = sanitize_cached_headers(&cached.headers);
            response_headers.insert("x-idempotent-replayed".to_string(), "true".to_string());
            return PluginResult::RejectBinary {
                status_code: cached.status_code,
                body: cached.body.clone(),
                headers: response_headers,
            };
        }

        // Check local cache and mark fresh keys as in-flight atomically under
        // the DashMap entry lock. This prevents two concurrent first requests
        // with the same idempotency key from both reaching the backend.
        match self.local_lookup_or_mark_inflight(&key, Instant::now()) {
            LocalDeduplicationAction::Replay(cached) => {
                debug!("request_deduplication: local cache hit, replaying response");
                // Defense-in-depth: re-sanitize on replay even though insert
                // already strips. Cheap (single HashMap pass) and protects
                // against any future code path that populates the cache without
                // going through `on_final_response_body`.
                let mut response_headers = sanitize_cached_headers(&cached.headers);
                response_headers.insert("x-idempotent-replayed".to_string(), "true".to_string());
                return PluginResult::RejectBinary {
                    status_code: cached.status_code,
                    body: cached.body.clone(),
                    headers: response_headers,
                };
            }
            LocalDeduplicationAction::Conflict => {
                return PluginResult::Reject {
                    status_code: 409,
                    body:
                        r#"{"error":"A request with this idempotency key is already in progress"}"#
                            .to_string(),
                    headers: HashMap::new(),
                };
            }
            LocalDeduplicationAction::Fresh => {}
        }

        // Store the key in metadata so on_final_response_body can cache the response
        ctx.metadata.insert("_dedup_key".to_string(), key);

        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only cache if we have a dedup key from before_proxy
        let key = match ctx.metadata.get("_dedup_key") {
            Some(k) => k.clone(),
            None => return PluginResult::Continue,
        };

        // Strip session-bearing headers (Set-Cookie, Authorization, trace
        // IDs, rate-limit counters, etc.) before persisting. Replaying a
        // verbatim `Set-Cookie: session=...` to a second client sharing the
        // same idempotency key — possible when `scope_by_consumer=false`,
        // for anonymous traffic, or for any user whose session has rotated
        // since the cached response was captured — is a session-hijack /
        // pinned-stale-cookie vector. Mirrors `ai_semantic_cache`'s
        // sanitization on store. See [`super::utils::cache_headers`].
        let safe_headers = sanitize_cached_headers(response_headers);

        let cached = CachedResponse {
            status_code: response_status,
            headers: safe_headers,
            body: Bytes::from(body.to_vec()),
            inserted_at: Instant::now(),
        };

        // Store in local cache
        self.local_cache
            .insert(key.clone(), DeduplicationEntry::Completed(cached.clone()));

        // Also store in Redis if available
        if self.redis_client.is_some() {
            self.redis_set(&key, &cached).await;
        }

        PluginResult::Continue
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        if let Some(ref redis) = self.redis_client {
            redis.warmup_hostname().into_iter().collect()
        } else {
            Vec::new()
        }
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.local_cache.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::PluginHttpClient;
    use serde_json::json;

    /// LRU eviction under `max_entries` pressure must NOT evict active in-flight
    /// markers. Evicting a live InFlight entry would release the in-flight lock
    /// while the original request is still executing, so a duplicate retry for
    /// the same idempotency key would bypass the lock and re-execute the
    /// side-effecting operation.
    #[test]
    fn cleanup_preserves_active_inflight_over_max_entries() {
        let config = json!({ "max_entries": 2 });
        let plugin = match RequestDeduplication::new(&config, PluginHttpClient::default()) {
            Ok(plugin) => plugin,
            Err(error) => panic!("request_deduplication config should be valid: {error}"),
        };

        // 3 active in-flight markers, cap is 2 → over limit.
        let now = Instant::now();
        for i in 0..3 {
            plugin.local_cache.insert(
                format!("inflight-{i}"),
                DeduplicationEntry::InFlight { started_at: now },
            );
        }
        assert_eq!(plugin.local_cache.len(), 3);

        // Force cleanup to run (bypass the 30s gate).
        plugin.last_cleanup.store(0, Ordering::Relaxed);
        plugin.cleanup_local_cache();

        // All 3 active in-flight entries must still be present — LRU eviction
        // is not allowed to drop active locks.
        assert_eq!(plugin.local_cache.len(), 3);
        for i in 0..3 {
            assert!(plugin.local_cache.contains_key(&format!("inflight-{i}")));
        }
    }

    /// Completed entries ARE LRU-eligible. When over `max_entries`, the oldest
    /// Completed entries get evicted while active InFlight markers are kept.
    #[test]
    fn cleanup_evicts_oldest_completed_preserves_inflight() {
        let config = json!({ "max_entries": 2 });
        let plugin = match RequestDeduplication::new(&config, PluginHttpClient::default()) {
            Ok(plugin) => plugin,
            Err(error) => panic!("request_deduplication config should be valid: {error}"),
        };

        let now = Instant::now();
        // 1 active in-flight
        plugin.local_cache.insert(
            "inflight-key".to_string(),
            DeduplicationEntry::InFlight { started_at: now },
        );
        // 3 completed entries with increasing age (oldest first)
        for i in 0..3 {
            let inserted = now - Duration::from_secs(10 - i);
            plugin.local_cache.insert(
                format!("completed-{i}"),
                DeduplicationEntry::Completed(CachedResponse {
                    status_code: 200,
                    headers: HashMap::new(),
                    body: Bytes::new(),
                    inserted_at: inserted,
                }),
            );
        }
        assert_eq!(plugin.local_cache.len(), 4);

        plugin.last_cleanup.store(0, Ordering::Relaxed);
        plugin.cleanup_local_cache();

        // Cap is 2. InFlight kept. 2 oldest Completed evicted, 1 newest Completed kept.
        assert!(plugin.local_cache.contains_key("inflight-key"));
        assert!(!plugin.local_cache.contains_key("completed-0"));
        assert!(!plugin.local_cache.contains_key("completed-1"));
        assert!(plugin.local_cache.contains_key("completed-2"));
    }
}
