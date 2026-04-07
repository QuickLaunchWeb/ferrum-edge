//! Ferrum Edge — A high-performance edge proxy built in Rust.
//!
//! This crate re-exports the public API surface used by integration tests,
//! functional tests, and custom plugins. The binary entry point is in `main.rs`;
//! this `lib.rs` simply makes internal modules accessible to external test crates
//! without duplicating module declarations.

/// The Ferrum Edge binary/crate version (sourced from Cargo.toml at compile time).
pub const FERRUM_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod admin;
pub mod circuit_breaker;
pub mod config;
pub mod config_delta;
pub mod connection_pool;
pub mod consumer_index;
#[path = "../custom_plugins/mod.rs"]
pub mod custom_plugins;
pub mod dns;
pub mod dtls;
pub mod grpc;
pub mod health_check;
pub mod http3;
pub mod load_balancer;
pub mod modes;
pub mod plugin_cache;
pub mod plugins;
pub mod proxy;
pub mod retry;
pub mod router_cache;
pub mod secrets;
pub mod service_discovery;
pub mod startup;
pub mod tls;

pub use config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
pub use consumer_index::ConsumerIndex;
pub use load_balancer::LoadBalancerCache;
pub use plugin_cache::PluginCache;
pub use proxy::{build_backend_url, build_backend_url_with_target};
pub use router_cache::{RouteMatch, RouterCache};

/// Test-only re-exports of crate-private items.
///
/// External test crates (`tests/unit/`) access implementation-internal helpers
/// through this module rather than requiring those helpers to be fully `pub`.
/// The leading underscore signals that this module is not part of the public API.
#[doc(hidden)]
pub mod _test_support {
    // ── proxy/tcp_proxy ──────────────────────────────────────────────────────
    pub use crate::proxy::tcp_proxy::classify_stream_error;

    // ── plugins/ws_rate_limiting ─────────────────────────────────────────────
    /// Create a fresh `WsRateLimiting` instance and return its Redis scope key.
    /// Each call returns a key from a new instance (unique UUID prefix), so two
    /// consecutive calls with the same arguments will return different keys.
    pub fn ws_rate_limiter_scope_key(proxy_id: &str, connection_id: u64) -> String {
        use crate::plugins::utils::http_client::PluginHttpClient;
        use crate::plugins::ws_rate_limiting::WsRateLimiting;
        WsRateLimiting::new(&serde_json::json!({}), PluginHttpClient::default())
            .unwrap()
            .redis_connection_scope_key(proxy_id, connection_id)
    }

    // ── plugins/utils/redis_rate_limiter ─────────────────────────────────────
    pub use crate::plugins::utils::redis_rate_limiter::RedisConfig;

    pub fn redis_config_url_with_ip(config: &RedisConfig, ip: std::net::IpAddr) -> String {
        config.url_with_resolved_ip(ip)
    }

    // ── config/db_loader ─────────────────────────────────────────────────────
    pub use crate::config::db_loader::DbPoolConfig;
    pub use crate::config::db_loader::{
        diff_removed as db_diff_removed, parse_auth_mode, parse_protocol,
    };

    pub fn db_append_connect_timeout(url: &str, db_type: &str, timeout: u64) -> String {
        crate::config::db_loader::DatabaseStore::append_connect_timeout(url, db_type, timeout)
    }

    // ── plugins/grpc_web ─────────────────────────────────────────────────────
    pub use crate::plugins::grpc_web::parse_grpc_frames;
    pub use crate::plugins::grpc_web::{
        GRPC_FRAME_DATA, GRPC_FRAME_TRAILER, build_trailer_frame, is_grpc_web_content_type,
        is_grpc_web_text, response_content_type,
    };

    // ── proxy/mod ────────────────────────────────────────────────────────────
    pub use crate::proxy::{
        NormalizedRejectResponse, apply_request_body_plugins, can_use_direct_http2_pool,
        extract_grpc_reject_message, insert_grpc_error_metadata,
        map_http_reject_status_to_grpc_status, normalize_reject_response, request_may_have_body,
    };
}
