use async_trait::async_trait;
use serde_json::Value;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

pub struct AccessControl {
    allowed_consumers: Vec<String>,
    disallowed_consumers: Vec<String>,
}

impl AccessControl {
    pub fn new(config: &Value) -> Self {
        let allowed = config["allowed_consumers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let disallowed = config["disallowed_consumers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            allowed_consumers: allowed,
            disallowed_consumers: disallowed,
        }
    }
}

#[async_trait]
impl Plugin for AccessControl {
    fn name(&self) -> &str {
        "access_control"
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        let consumer = match &ctx.identified_consumer {
            Some(c) => c,
            None => {
                debug!("access_control: no consumer identified, rejecting");
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"No consumer identified"}"#.into(),
                };
            }
        };

        let username = &consumer.username;

        // Check disallowed first
        if self.disallowed_consumers.contains(username) {
            debug!("access_control: consumer '{}' is disallowed", username);
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
            };
        }

        // If allowed list is configured, consumer must be in it
        if !self.allowed_consumers.is_empty() && !self.allowed_consumers.contains(username) {
            debug!(
                "access_control: consumer '{}' not in allowed list",
                username
            );
            return PluginResult::Reject {
                status_code: 403,
                body: r#"{"error":"Consumer is not allowed"}"#.into(),
            };
        }

        PluginResult::Continue
    }
}
