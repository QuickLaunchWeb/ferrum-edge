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
use url::Url;

use crate::plugins::utils::http_client::PluginHttpClient;
use crate::plugins::utils::response_body::{BoundedReadError, measure_response_body_bounded};

use super::notification::Notification;

pub mod discord;
pub mod slack;
pub mod teams;
pub mod webhook;

const RESPONSE_BODY_DRAIN_LIMIT_BYTES: usize = 1024 * 1024;

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

    pub fn warmup_hostnames(&self) -> Vec<String> {
        match self {
            Self::Slack(c) => hostname_from_url(c.webhook_url()),
            Self::Teams(c) => hostname_from_url(c.webhook_url()),
            Self::Discord(c) => hostname_from_url(c.webhook_url()),
            Self::Webhook(c) => hostname_from_url(c.url()),
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

pub(super) fn validate_webhook_url(url: &str, channel: &str, kind: &str) -> Result<(), String> {
    let parsed = Url::parse(url)
        .map_err(|e| format!("channel '{channel}' ({kind}): invalid 'webhook_url': {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        s => {
            return Err(format!(
                "channel '{channel}' ({kind}): 'webhook_url' must use http:// or https:// (got '{s}')"
            ));
        }
    }
    if parsed.host_str().is_none() {
        return Err(format!(
            "channel '{channel}' ({kind}): 'webhook_url' must include a hostname"
        ));
    }
    Ok(())
}

/// Redact a webhook endpoint for logs/errors. Incoming webhook credentials
/// commonly live in the URL path or query string, so keep only scheme/host/port.
pub(super) fn redacted_endpoint_url(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "redacted-url".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.set_path("/redacted");
    url.to_string()
}

pub(super) async fn drain_response_body_redacted(
    resp: reqwest::Response,
    channel: &str,
    redacted_url: &str,
) -> Result<(), String> {
    if let Some(content_length) = resp.content_length()
        && content_length > RESPONSE_BODY_DRAIN_LIMIT_BYTES as u64
    {
        return Err(format!(
            "{channel} dispatch response body length {content_length} exceeds drain limit {RESPONSE_BODY_DRAIN_LIMIT_BYTES} bytes reading response from {redacted_url}"
        ));
    }

    measure_response_body_bounded(resp, RESPONSE_BODY_DRAIN_LIMIT_BYTES)
        .await
        .map(|_| ())
        .map_err(|e| match e {
            BoundedReadError::LimitExceeded {
                read_so_far,
                max_bytes,
            } => format!(
                "{channel} dispatch response body exceeded drain limit {max_bytes} bytes after reading {read_so_far} bytes from {redacted_url}"
            ),
            BoundedReadError::Stream(e) => {
                format!(
                    "{channel} dispatch body read failed: {} reading response from {redacted_url}",
                    reqwest_error_class(&e)
                )
            }
        })
}

fn reqwest_error_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect error"
    } else if error.is_body() {
        "body error"
    } else if error.is_decode() {
        "decode error"
    } else if error.is_status() {
        "status error"
    } else if error.is_redirect() {
        "redirect error"
    } else if error.is_request() {
        "request error"
    } else {
        "error"
    }
}

fn hostname_from_url(raw: &str) -> Vec<String> {
    Url::parse(raw)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .into_iter()
        .collect()
}
