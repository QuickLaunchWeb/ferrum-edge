use async_trait::async_trait;
use serde_json::Value;
use tracing::debug;

use crate::config::types::Consumer;

use super::{Plugin, PluginResult, RequestContext};

pub struct KeyAuth {
    key_location: String,
}

impl KeyAuth {
    pub fn new(config: &Value) -> Self {
        Self {
            key_location: config["key_location"]
                .as_str()
                .unwrap_or("header:X-API-Key")
                .to_string(),
        }
    }

    fn extract_key(&self, ctx: &RequestContext) -> Option<String> {
        if self.key_location.starts_with("header:") {
            let header_name = &self.key_location["header:".len()..];
            ctx.headers.get(&header_name.to_lowercase()).cloned()
        } else if self.key_location.starts_with("query:") {
            let param_name = &self.key_location["query:".len()..];
            ctx.query_params.get(param_name).cloned()
        } else {
            ctx.headers.get("x-api-key").cloned()
        }
    }
}

#[async_trait]
impl Plugin for KeyAuth {
    fn name(&self) -> &str {
        "key_auth"
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumers: &[Consumer],
    ) -> PluginResult {
        let api_key = match self.extract_key(ctx) {
            Some(k) => k,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing API key"}"#.into(),
                };
            }
        };

        for consumer in consumers {
            if let Some(key_creds) = consumer.credentials.get("keyauth") {
                if let Some(key) = key_creds.get("key").and_then(|s| s.as_str()) {
                    if key == api_key {
                        if ctx.identified_consumer.is_none() {
                            debug!("key_auth: identified consumer '{}'", consumer.username);
                            ctx.identified_consumer = Some(consumer.clone());
                        }
                        return PluginResult::Continue;
                    }
                }
            }
        }

        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"Invalid API key"}"#.into(),
        }
    }
}
