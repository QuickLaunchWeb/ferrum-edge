//! Notification channel implementations.
//!
//! Each channel takes a generic [`Notification`] and projects it into its own
//! payload shape. The [`NotificationChannel`] enum provides a uniform
//! `dispatch` surface so callers can hand a list of `Arc<NotificationChannel>`
//! to [`crate::notifications::dispatch::dispatch`] without caring which
//! transport each one uses.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::plugins::utils::http_client::PluginHttpClient;

use super::notification::Notification;

pub mod discord;
pub mod slack;
pub mod teams;
pub mod webhook;

#[allow(unused_imports)]
pub use discord::DiscordChannel;
#[allow(unused_imports)]
pub use slack::SlackChannel;
#[allow(unused_imports)]
pub use teams::TeamsChannel;
#[allow(unused_imports)]
pub use webhook::{HttpMethod, NOTIFICATION_TEMPLATE_VARS, WebhookChannel};

#[derive(Debug, Clone)]
pub enum NotificationChannel {
    Slack(SlackChannel),
    Teams(TeamsChannel),
    Discord(DiscordChannel),
    Webhook(WebhookChannel),
}

#[allow(dead_code)] // Public dispatch surface for non-plugin callers + tests.
impl NotificationChannel {
    pub fn name(&self) -> &str {
        match self {
            Self::Slack(c) => c.name(),
            Self::Teams(c) => c.name(),
            Self::Discord(c) => c.name(),
            Self::Webhook(c) => c.name(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Slack(_) => "slack",
            Self::Teams(_) => "teams",
            Self::Discord(_) => "discord",
            Self::Webhook(_) => "webhook",
        }
    }

    /// Dispatch with no extra template variables. Convenience for callers
    /// that don't need to inject domain-specific context (today: anything
    /// except the proxy_alerts plugin).
    pub async fn dispatch(
        &self,
        notification: &Notification,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        let extras: HashMap<String, String> = HashMap::new();
        self.dispatch_with_vars(notification, &extras, http).await
    }

    /// Dispatch with an extra template-variable map. Variables are only
    /// consumed by the [`WebhookChannel`] (other channels ignore them).
    pub async fn dispatch_with_vars(
        &self,
        notification: &Notification,
        extras: &HashMap<String, String>,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        match self {
            Self::Slack(c) => c.dispatch(notification, http).await,
            Self::Teams(c) => c.dispatch(notification, http).await,
            Self::Discord(c) => c.dispatch(notification, http).await,
            Self::Webhook(c) => c.dispatch_with_vars(notification, extras, http).await,
        }
    }
}

/// Parse a `{ name -> ChannelDef }` JSON object into typed channels.
///
/// Returns an error on:
/// - Empty map.
/// - Channel name not matching `[A-Za-z0-9_-]+`.
/// - Missing or unknown `"type"` discriminant.
/// - Per-channel validation failure (URL parse, missing required fields).
pub fn parse_channels(value: &Value) -> Result<HashMap<String, Arc<NotificationChannel>>, String> {
    let map = value
        .as_object()
        .ok_or_else(|| "'channels' must be an object".to_string())?;
    if map.is_empty() {
        return Err("'channels' must contain at least one channel".to_string());
    }
    let mut out = HashMap::with_capacity(map.len());
    for (name, def) in map {
        validate_channel_name(name)?;
        let channel = build_channel(name, def)?;
        out.insert(name.clone(), Arc::new(channel));
    }
    Ok(out)
}

fn validate_channel_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("channel name must not be empty".to_string());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "channel name '{name}' must match [A-Za-z0-9_-]+ (got disallowed characters)"
        ));
    }
    Ok(())
}

fn build_channel(name: &str, def: &Value) -> Result<NotificationChannel, String> {
    let obj = def
        .as_object()
        .ok_or_else(|| format!("channel '{name}': definition must be an object"))?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("channel '{name}': 'type' is required"))?;
    match kind {
        "slack" => Ok(NotificationChannel::Slack(SlackChannel::new(name, def)?)),
        "teams" => Ok(NotificationChannel::Teams(TeamsChannel::new(name, def)?)),
        "discord" => Ok(NotificationChannel::Discord(DiscordChannel::new(
            name, def,
        )?)),
        "webhook" => Ok(NotificationChannel::Webhook(WebhookChannel::new(
            name, def,
        )?)),
        other => Err(format!(
            "channel '{name}': unknown 'type' '{other}' (expected one of: slack, teams, discord, webhook)"
        )),
    }
}

/// Helper used by every channel that accepts either an inline value or a
/// `*_env`-suffixed env-var reference. Returns the resolved string when one
/// of the two is set; returns `Ok(None)` when neither is present.
///
/// Env-var resolution feeds through the gateway's existing secret resolver
/// (`src/secrets/`) — any `_FILE`/`_VAULT`/`_AWS`/`_AZURE`/`_GCP` suffix
/// applied at startup will already have populated the named env var by the
/// time channels are constructed.
pub(super) fn resolve_optional_string(
    value: &Value,
    key: &str,
    env_key: &str,
    channel: &str,
) -> Result<Option<String>, String> {
    if let Some(v) = value.get(key) {
        let s = v
            .as_str()
            .ok_or_else(|| format!("channel '{channel}': '{key}' must be a string"))?;
        if s.is_empty() {
            return Err(format!("channel '{channel}': '{key}' must not be empty"));
        }
        return Ok(Some(s.to_string()));
    }
    if let Some(v) = value.get(env_key) {
        let env_name = v
            .as_str()
            .ok_or_else(|| format!("channel '{channel}': '{env_key}' must be a string"))?;
        if env_name.is_empty() {
            return Err(format!(
                "channel '{channel}': '{env_key}' must not be empty"
            ));
        }
        let resolved = std::env::var(env_name).map_err(|_| {
            format!(
                "channel '{channel}': env var '{env_name}' (referenced by '{env_key}') is not set"
            )
        })?;
        if resolved.is_empty() {
            return Err(format!(
                "channel '{channel}': env var '{env_name}' resolved to empty string"
            ));
        }
        return Ok(Some(resolved));
    }
    Ok(None)
}
