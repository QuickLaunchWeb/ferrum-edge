//! `proxy_alerts` — observes proxy traffic and dispatches notifications when
//! configured rules breach their thresholds.
//!
//! Hooks into the `log()`, `on_stream_disconnect()`, and selected
//! `on_ws_disconnect()` lifecycle phases (after the request/connection has
//! completed). Per-rule sliding windows track matched/total counts (or
//! latency observations); on threshold breach the plugin builds a generic
//! [`Notification`] and dispatches it to the rule's configured channels via
//! the shared `crate::notifications` layer.
//!
//! Architecture notes:
//! - **Channels are reusable**: live in `src/notifications/channels/`. Other
//!   subsystems (overload manager, mesh policy, future plugins) can use the
//!   same channel implementations without depending on `proxy_alerts`.
//! - **Per-`(rule, proxy, channel)` cooldown** prevents repeated dispatches
//!   without suppressing unrelated proxies that share a global/group rule.
//! - **Per-`(rule, proxy)` recovery state machine** dispatches a one-shot
//!   `Resolve` event once a rule's window stays below threshold for the
//!   configured `resolved_window_seconds`.
//! - **Bounded-concurrency dispatch**: `tokio::Semaphore`. When exhausted,
//!   alerts are dropped with a `warn!` rather than queued — alert storms
//!   during a partial channel outage should be visible, not buffered.
//! - **Quiet hours**: optional UTC time-of-day windows where `Trigger`
//!   alerts are suppressed (without consuming the cooldown gate). `Resolve`
//!   events still fire so operators don't miss recovery during off hours.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

use crate::notifications::{EventAction, NotificationChannel};
use crate::plugins::utils::http_client::PluginHttpClient;

use super::{
    ALL_PROTOCOLS, Plugin, ProxyProtocol, StreamTransactionSummary, TransactionSummary,
    WsDisconnectContext,
};

pub mod config;
pub mod cooldown;
pub mod render;
pub mod rules;
pub mod windows;

use config::{ProxyAlertsConfig, QuietHourWindow};
use cooldown::{CooldownGate, LifecycleOutcome, RecoveryGate, RuleState};
use rules::{Rule, RuleObservation, SampleInput};
use windows::{WindowStore, current_epoch_ms};

pub struct ProxyAlerts {
    rules: Arc<Vec<Rule>>,
    channel_by_id: Arc<HashMap<u32, Arc<NotificationChannel>>>,
    windows: Arc<WindowStore>,
    cooldowns: Arc<CooldownGate>,
    recovery: Arc<RecoveryGate>,
    dispatch_sem: Arc<Semaphore>,
    http_client: PluginHttpClient,
    enabled: AtomicBool,
    quiet_hours: Arc<Vec<QuietHourWindow>>,
    /// Eviction sweep handle for runtime plugin instances. `None` when the
    /// plugin was instantiated by an offline validation path without a Tokio
    /// runtime.
    eviction_handle: Option<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for ProxyAlerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyAlerts")
            .field("rules", &self.rules.len())
            .field("channels", &self.channel_by_id.len())
            .field("enabled", &self.enabled.load(Ordering::Acquire))
            .field("quiet_hours", &self.quiet_hours.len())
            .finish()
    }
}

impl ProxyAlerts {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let parsed = ProxyAlertsConfig::parse(config)?;

        let rule_specs = parsed
            .rules
            .iter()
            .map(|r| (r.id(), r.window_spec()))
            .collect();
        let windows = Arc::new(WindowStore::new(rule_specs));
        let eviction_handle = windows.start_eviction_task();

        let dispatch_sem = Arc::new(Semaphore::new(parsed.max_concurrent_dispatches));

        Ok(Self {
            rules: parsed.rules,
            channel_by_id: parsed.channel_by_id,
            windows,
            cooldowns: Arc::new(CooldownGate::new()),
            recovery: Arc::new(RecoveryGate::new()),
            dispatch_sem,
            http_client,
            enabled: AtomicBool::new(parsed.enabled),
            quiet_hours: Arc::new(parsed.quiet_hours),
            eviction_handle,
        })
    }

    fn handle(&self, sample: SampleInput<'_>) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let now_ms = current_epoch_ms();
        let now = Utc::now();
        let in_quiet = self.quiet_hours.iter().any(|w| w.matches(now));
        for rule in self.rules.iter() {
            let Some(observation) = rule.observe(sample, &self.windows, now_ms) else {
                continue;
            };
            self.process_observation(rule, &observation, sample, now_ms, now, in_quiet);
        }
    }

    fn process_observation(
        &self,
        rule: &Rule,
        observation: &RuleObservation,
        sample: SampleInput<'_>,
        now_ms: u64,
        now: chrono::DateTime<chrono::Utc>,
        in_quiet: bool,
    ) {
        let proxy_id = sample.proxy_id().unwrap_or("");
        if observation.breach
            && in_quiet
            && matches!(
                self.recovery.current_state(rule.id(), proxy_id),
                None | Some(RuleState::Healthy)
            )
        {
            return;
        }
        let recovery_ms = rule
            .common()
            .recovery
            .as_ref()
            .map(|r| r.resolved_window_ms)
            .unwrap_or(0);
        let outcome =
            self.recovery
                .evaluate(rule.id(), proxy_id, observation.breach, recovery_ms, now_ms);
        let Some(event_action) = lifecycle_event_action(outcome) else {
            self.recovery
                .observe(rule.id(), proxy_id, observation.breach, recovery_ms, now_ms);
            return;
        };
        if event_action == EventAction::Trigger && in_quiet {
            return;
        }
        let mut dispatches: Option<Vec<(Arc<NotificationChannel>, OwnedSemaphorePermit)>> = None;
        let mut cooldown_suppressed = false;
        for &channel_id in &rule.common().channel_ids {
            let Some(channel) = self.channel_by_id.get(&channel_id) else {
                continue;
            };
            let Some(permit) = self.try_acquire_dispatch_permit(channel.name()) else {
                continue;
            };
            let cooldown_ok = match event_action {
                EventAction::Resolve => true,
                _ => self.cooldowns.try_acquire(
                    rule.id(),
                    proxy_id,
                    channel_id,
                    rule.common().cooldown_ms,
                    now_ms,
                ),
            };
            if !cooldown_ok {
                cooldown_suppressed = true;
                continue;
            }
            dispatches
                .get_or_insert_with(Vec::new)
                .push((Arc::clone(channel), permit));
        }
        let Some(dispatches) = dispatches else {
            if cooldown_suppressed && matches!(outcome, LifecycleOutcome::StillActive) {
                self.recovery
                    .observe(rule.id(), proxy_id, observation.breach, recovery_ms, now_ms);
            }
            return;
        };
        let committed_outcome =
            self.recovery
                .observe(rule.id(), proxy_id, observation.breach, recovery_ms, now_ms);
        if lifecycle_event_action(committed_outcome) != Some(event_action) {
            return;
        }
        let notification = render::build_notification(rule, observation, sample, event_action, now);
        let extras = render::build_webhook_vars(rule, observation, sample, event_action, now);
        let notification = Arc::new(notification);
        let extras = Arc::new(extras);
        for (channel, permit) in dispatches {
            self.spawn_dispatch(
                channel,
                Arc::clone(&notification),
                Arc::clone(&extras),
                permit,
            );
        }
    }

    fn try_acquire_dispatch_permit(&self, channel_name: &str) -> Option<OwnedSemaphorePermit> {
        match Arc::clone(&self.dispatch_sem).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                warn!(
                    plugin = "proxy_alerts",
                    channel = %channel_name,
                    "notification dispatch backpressure: dropping alert"
                );
                None
            }
        }
    }

    fn spawn_dispatch(
        &self,
        channel: Arc<NotificationChannel>,
        notification: Arc<crate::notifications::Notification>,
        extras: Arc<HashMap<String, String>>,
        permit: OwnedSemaphorePermit,
    ) {
        let http = self.http_client.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = channel
                .dispatch_with_vars(&notification, &extras, &http)
                .await
            {
                warn!(
                    plugin = "proxy_alerts",
                    channel = %channel.name(),
                    error = %e,
                    "notification dispatch failed"
                );
            }
        });
    }
}

impl Drop for ProxyAlerts {
    fn drop(&mut self) {
        if let Some(handle) = self.eviction_handle.take() {
            handle.abort();
        }
    }
}

fn lifecycle_event_action(outcome: LifecycleOutcome) -> Option<EventAction> {
    match outcome {
        LifecycleOutcome::Trigger | LifecycleOutcome::StillActive => Some(EventAction::Trigger),
        LifecycleOutcome::Resolve => Some(EventAction::Resolve),
        LifecycleOutcome::EnteringRecovery
        | LifecycleOutcome::Reactivate
        | LifecycleOutcome::Quiet => None,
    }
}

#[async_trait]
impl Plugin for ProxyAlerts {
    fn name(&self) -> &str {
        "proxy_alerts"
    }

    fn priority(&self) -> u16 {
        super::priority::PROXY_ALERTS
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS
    }

    async fn log(&self, summary: &TransactionSummary) {
        if summary.mirror {
            return;
        }
        self.handle(SampleInput::Http(summary));
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.handle(SampleInput::Stream(summary));
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        self.rules.iter().any(Rule::observes_ws_disconnect)
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        self.handle(SampleInput::WebSocket(ctx));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::plugins::utils::http_client::PluginHttpClient;
    use crate::plugins::{Plugin, TransactionSummary};

    use super::*;

    #[tokio::test]
    async fn log_skips_mirror_summaries_before_alert_windows() {
        let cfg = json!({
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "status", "type": "status_code_count",
                  "status_codes": [500], "threshold_count": 100,
                  "cooldown_seconds": 1, "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 500,
            mirror: true,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;
        assert_eq!(
            plugin.windows.snapshot_count(0, "p1", current_epoch_ms()),
            (0, 0)
        );

        let mut primary_summary = summary;
        primary_summary.mirror = false;
        plugin.log(&primary_summary).await;
        assert_eq!(
            plugin.windows.snapshot_count(0, "p1", current_epoch_ms()),
            (1, 1)
        );
    }

    #[tokio::test]
    async fn dispatch_backpressure_does_not_consume_trigger_cooldown() {
        let cfg = json!({
            "max_concurrent_dispatches": 1,
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "status", "type": "status_code_count",
                  "status_codes": [500], "threshold_count": 1,
                  "cooldown_seconds": 60, "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        let _held_permit = plugin
            .dispatch_sem
            .clone()
            .try_acquire_owned()
            .expect("test should reserve the only dispatch permit");
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 500,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;

        assert!(
            plugin
                .cooldowns
                .try_acquire(0, "p1", 0, 60_000, current_epoch_ms()),
            "a dropped dispatch must not arm the trigger cooldown"
        );
    }

    #[tokio::test]
    async fn dispatch_backpressure_does_not_activate_unsent_trigger() {
        let cfg = json!({
            "max_concurrent_dispatches": 1,
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "status", "type": "status_code_count",
                  "status_codes": [500], "threshold_count": 1,
                  "cooldown_seconds": 60, "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        let held_permit = plugin
            .dispatch_sem
            .clone()
            .try_acquire_owned()
            .expect("test should reserve the only dispatch permit");
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 500,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;
        assert_eq!(plugin.recovery.current_state(0, "p1"), None);

        drop(held_permit);
        plugin.log(&summary).await;
        assert!(matches!(
            plugin.recovery.current_state(0, "p1"),
            Some(RuleState::Active { .. })
        ));
    }

    #[tokio::test]
    async fn cooldown_suppressed_initial_trigger_does_not_activate_incident() {
        let cfg = json!({
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "status", "type": "status_code_count",
                  "status_codes": [500], "threshold_count": 1,
                  "cooldown_seconds": 60,
                  "recovery": { "resolved_window_seconds": 5 },
                  "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        let now_ms = current_epoch_ms();
        assert!(plugin.cooldowns.try_acquire(0, "p1", 0, 60_000, now_ms));
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 500,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;

        assert_eq!(
            plugin.recovery.current_state(0, "p1"),
            None,
            "a first trigger suppressed by cooldown must not create a resolvable incident"
        );
    }

    #[tokio::test]
    async fn dispatch_backpressure_does_not_resolve_unsent_recovery() {
        let cfg = json!({
            "max_concurrent_dispatches": 1,
            "channels": {
                "c": { "type": "webhook", "url": "http://127.0.0.1/alert", "body_template": "x" }
            },
            "rules": [
                { "name": "errors", "type": "error_rate",
                  "status_codes": [500], "threshold_percent": 60.0,
                  "min_request_count": 1,
                  "recovery": { "resolved_window_seconds": 5 },
                  "channels": ["c"] }
            ]
        });
        let plugin = ProxyAlerts::new(&cfg, PluginHttpClient::default()).unwrap();
        plugin.recovery.observe(0, "p1", true, 5_000, 1);
        plugin.recovery.observe(0, "p1", false, 5_000, 2);
        assert!(matches!(
            plugin.recovery.current_state(0, "p1"),
            Some(RuleState::Recovering { .. })
        ));

        let held_permit = plugin
            .dispatch_sem
            .clone()
            .try_acquire_owned()
            .expect("test should reserve the only dispatch permit");
        let summary = TransactionSummary {
            namespace: "ferrum".to_string(),
            proxy_id: Some("p1".to_string()),
            proxy_name: Some("api".to_string()),
            response_status_code: 200,
            ..TransactionSummary::default()
        };

        plugin.log(&summary).await;
        assert!(matches!(
            plugin.recovery.current_state(0, "p1"),
            Some(RuleState::Recovering { .. })
        ));

        drop(held_permit);
        plugin.log(&summary).await;
        assert_eq!(
            plugin.recovery.current_state(0, "p1"),
            Some(RuleState::Healthy)
        );
    }
}
