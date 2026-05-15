//! Discord webhook channel.
//!
//! Posts an `embeds`-shaped JSON payload to a Discord-compatible webhook.

use std::sync::Arc;

use serde_json::{Value, json};
use url::Url;

use crate::plugins::utils::http_client::PluginHttpClient;

use super::super::notification::Notification;
use super::{redacted_endpoint_url, resolve_optional_string};

#[derive(Debug, Clone)]
pub struct DiscordChannel {
    name: Arc<str>,
    webhook_url: Arc<str>,
    username: Option<Arc<str>>,
}

impl DiscordChannel {
    pub fn new(name: &str, value: &Value) -> Result<Self, String> {
        let webhook_url =
            resolve_optional_string(value, "webhook_url", "webhook_url_env", name)?
                .ok_or_else(|| format!("channel '{name}' (discord): 'webhook_url' is required"))?;
        validate_webhook_url(&webhook_url, name)?;
        let username = take_optional_string(value, "username", name)?;
        Ok(Self {
            name: Arc::from(name),
            webhook_url: Arc::from(webhook_url),
            username: username.map(Arc::from),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn webhook_url(&self) -> &str {
        &self.webhook_url
    }

    pub fn build_payload(&self, n: &Notification) -> Value {
        let fields: Vec<Value> = n
            .fields
            .iter()
            .map(|f| {
                json!({
                    "name": f.name,
                    "value": f.value,
                    "inline": f.short,
                })
            })
            .collect();
        let mut embed = json!({
            "title": n.title,
            "description": n.body,
            "color": n.severity.discord_color(),
            "timestamp": n.fired_at.to_rfc3339(),
            "fields": fields,
        });
        if let Some(source) = n.source.as_deref() {
            embed["footer"] = json!({ "text": source });
        }
        let mut payload = json!({ "embeds": [embed] });
        if let Some(u) = self.username.as_deref() {
            payload["username"] = json!(u);
        }
        payload
    }

    pub async fn dispatch(
        &self,
        notification: &Notification,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        let payload = self.build_payload(notification);
        let redacted_url = redacted_endpoint_url(&self.webhook_url);
        let req = http.get().post(self.webhook_url.as_ref()).json(&payload);
        let resp = http
            .execute_redacted(req, "notification_discord", &redacted_url)
            .await
            .map_err(|e| format!("discord dispatch failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "discord dispatch returned non-success status {}",
                resp.status()
            ));
        }
        Ok(())
    }
}

fn take_optional_string(value: &Value, key: &str, channel: &str) -> Result<Option<String>, String> {
    match value.get(key) {
        Some(v) => v
            .as_str()
            .map(|s| s.to_string())
            .map(Some)
            .ok_or_else(|| format!("channel '{channel}' (discord): '{key}' must be a string")),
        None => Ok(None),
    }
}

fn validate_webhook_url(url: &str, channel: &str) -> Result<(), String> {
    let parsed = Url::parse(url)
        .map_err(|e| format!("channel '{channel}' (discord): invalid 'webhook_url': {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        s => {
            return Err(format!(
                "channel '{channel}' (discord): 'webhook_url' must use http:// or https:// (got '{s}')"
            ));
        }
    }
    if parsed.host_str().is_none() {
        return Err(format!(
            "channel '{channel}' (discord): 'webhook_url' must include a hostname"
        ));
    }
    Ok(())
}
