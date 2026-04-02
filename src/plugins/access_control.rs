//! Access Control List (ACL) plugin — post-authentication authorization.
//!
//! Runs in the `authorize` phase after authentication plugins have identified
//! the caller. By default this plugin is consumer-based only:
//! 1. **Consumer-based**: Allow/deny lists checked by consumer username (O(1) HashSet).
//! 2. **Optional external-auth bypass**: `allow_authenticated_identity` permits
//!    requests that have `ctx.authenticated_identity` set but no mapped Consumer.
//!
//! IP-based access control lives in the `ip_restriction` plugin so all client-IP
//! enforcement is centralized in one place.
//!
//! Evaluation order: consumer deny → consumer allow.
//! If no rules match, the request is allowed (open by default).

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::warn;

use super::{Plugin, PluginResult, RequestContext};

pub struct AccessControl {
    /// O(1) consumer allow list (empty = no restriction).
    allowed_consumers: HashSet<String>,
    /// O(1) consumer deny list.
    disallowed_consumers: HashSet<String>,
    /// When true, allow requests authenticated by an external auth plugin
    /// (for example `jwks_auth`) even if no gateway Consumer was mapped.
    allow_authenticated_identity: bool,
}

impl AccessControl {
    pub fn new(config: &Value) -> Result<Self, String> {
        let allowed: HashSet<String> = config["allowed_consumers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let disallowed: HashSet<String> = config["disallowed_consumers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let allow_authenticated_identity = config["allow_authenticated_identity"]
            .as_bool()
            .unwrap_or(false);

        if allowed.is_empty() && disallowed.is_empty() && !allow_authenticated_identity {
            return Err(
                "access_control: at least one of 'allowed_consumers', 'disallowed_consumers', or 'allow_authenticated_identity=true' is required".to_string()
            );
        }

        Ok(Self {
            allowed_consumers: allowed,
            disallowed_consumers: disallowed,
            allow_authenticated_identity,
        })
    }
}

#[async_trait]
impl Plugin for AccessControl {
    fn name(&self) -> &str {
        "access_control"
    }

    fn priority(&self) -> u16 {
        super::priority::ACCESS_CONTROL
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_PROTOCOLS
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        let consumer = match &ctx.identified_consumer {
            Some(c) => c,
            None => {
                if self.allow_authenticated_identity && ctx.authenticated_identity.is_some() {
                    return PluginResult::Continue;
                }
                warn!(client_ip = %ctx.client_ip, plugin = "access_control", reason = "no_consumer", "No consumer identified for access control");
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"No consumer identified"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let username = &consumer.username;

        // O(1) check: consumer deny list
        if self.disallowed_consumers.contains(username) {
            warn!(consumer = %username, client_ip = %ctx.client_ip, plugin = "access_control", reason = "consumer_disallowed", "Consumer rejected by access control");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }

        // O(1) check: consumer allow list (if configured, consumer must be in it)
        if !self.allowed_consumers.is_empty() && !self.allowed_consumers.contains(username) {
            warn!(consumer = %username, client_ip = %ctx.client_ip, plugin = "access_control", reason = "consumer_not_allowed", "Consumer not in allow list");
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
    }
}
