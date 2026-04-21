//! Response Size Limiting Plugin
//!
//! Enforces per-proxy response body size limits that are lower than the global
//! `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`. Rejects responses that exceed the
//! configured `max_bytes` with HTTP 502 Bad Gateway.
//!
//! Two enforcement paths:
//! 1. **Content-Length fast path** (`after_proxy`): rejects immediately when the
//!    backend response Content-Length header declares a body larger than allowed.
//! 2. **Final body check** (`on_final_response_body`): when response buffering is
//!    active (either from `require_buffered_check: true` or because another plugin
//!    requires buffering), the final client-visible byte length is verified after
//!    any body transforms have run.
//!
//! Set `require_buffered_check: true` to force response body buffering so that
//! chunked/streaming responses without Content-Length are also checked. This adds
//! memory overhead — only enable when needed.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::utils::size_limit::{
    SizeLimiter, content_length_over_limit, reject_with_limit, required_positive_u64,
};
use super::{Plugin, PluginResult, RequestContext};

pub struct ResponseSizeLimiting {
    max_bytes: u64,
    require_buffered_check: bool,
}

impl ResponseSizeLimiting {
    pub fn new(config: &Value) -> Result<Self, String> {
        let max_bytes = required_positive_u64(config, "max_bytes", "response_size_limiting")?;
        let require_buffered_check = config["require_buffered_check"].as_bool().unwrap_or(false);

        Ok(Self {
            max_bytes,
            require_buffered_check,
        })
    }
}

impl SizeLimiter for ResponseSizeLimiting {
    fn plugin_name(&self) -> &'static str {
        "response_size_limiting"
    }

    fn max_size_bytes(&self) -> u128 {
        self.max_bytes as u128
    }
}

#[async_trait]
impl Plugin for ResponseSizeLimiting {
    fn name(&self) -> &str {
        "response_size_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::RESPONSE_SIZE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.require_buffered_check && self.is_enabled()
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.is_enabled() {
            return PluginResult::Continue;
        }

        // Fast path: check Content-Length response header
        if let Some(len) = content_length_over_limit(response_headers, self.max_size_bytes()) {
            debug!(
                plugin = self.plugin_name(),
                content_length = len,
                max_bytes = self.max_size_bytes(),
                "Response rejected: Content-Length exceeds limit"
            );
            return reject_with_limit(502, "Response body too large", self.max_size_bytes());
        }

        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.is_enabled() {
            return PluginResult::Continue;
        }

        let len = body.len() as u64;
        if self.exceeds_limit(len as u128) {
            debug!(
                plugin = self.plugin_name(),
                body_len = len,
                max_bytes = self.max_size_bytes(),
                "Response rejected: buffered body exceeds limit"
            );
            return reject_with_limit(502, "Response body too large", self.max_size_bytes());
        }

        PluginResult::Continue
    }
}
