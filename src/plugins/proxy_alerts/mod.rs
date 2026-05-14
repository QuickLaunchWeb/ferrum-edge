//! `proxy_alerts` — observes proxy traffic and dispatches notifications when
//! configured rules breach their thresholds.
//!
//! Hooks into the `log()` and `on_stream_disconnect()` lifecycle phases (after
//! the request/connection has completed). Per-rule sliding windows track
//! matched/total counts (or latency observations); on threshold breach the
//! plugin builds a generic [`Notification`] and dispatches it to the rule's
//! configured channels via the shared `crate::notifications` layer.
//!
//! Architecture notes:
//! - **Channels are reusable**: live in `src/notifications/channels/`. Other
//!   subsystems (overload manager, mesh policy, future plugins) can use the
//!   same channel implementations without depending on `proxy_alerts`.
//! - **Per-`(rule, channel)` cooldown** prevents repeated dispatches.
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
use tokio::sync::Semaphore;
use tracing::warn;

use crate::notifications::{EventAction, NotificationChannel};
use crate::plugins::utils::http_client::PluginHttpClient;

use super::{ALL_PROTOCOLS, Plugin, ProxyProtocol, StreamTransactionSummary, TransactionSummary};

pub mod config;
pub mod cooldown;
pub mod render;
pub mod rules;
pub mod windows;

use config::{ProxyAlertsConfig, QuietHourWindow};
use cooldown::{CooldownGate, LifecycleOutcome, RecoveryGate};
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
    /// Eviction sweep handle; held to keep the task alive for the plugin's
    /// lifetime (cancelled when the plugin is dropped).
    _eviction_handle: tokio::task::JoinHandle<()>,
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
            _eviction_handle: eviction_handle,
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
        let recovery_ms = rule
            .common()
            .recovery
            .as_ref()
            .map(|r| r.resolved_window_ms)
            .unwrap_or(0);
        let outcome =
            self.recovery
                .observe(rule.id(), proxy_id, observation.breach, recovery_ms, now_ms);
        let event_action = match outcome {
            LifecycleOutcome::Trigger | LifecycleOutcome::StillActive => EventAction::Trigger,
            LifecycleOutcome::Resolve => EventAction::Resolve,
            LifecycleOutcome::EnteringRecovery
            | LifecycleOutcome::Reactivate
            | LifecycleOutcome::Quiet => return,
        };
        if event_action == EventAction::Trigger && in_quiet {
            return;
        }
        let notification = render::build_notification(rule, observation, sample, event_action, now);
        let extras = render::build_webhook_vars(rule, observation, sample, event_action, now);
        let notification = Arc::new(notification);
        let extras = Arc::new(extras);
        for &channel_id in &rule.common().channel_ids {
            let Some(channel) = self.channel_by_id.get(&channel_id) else {
                continue;
            };
            let cooldown_ok = match event_action {
                EventAction::Resolve => true,
                _ => self.cooldowns.try_acquire(
                    rule.id(),
                    channel_id,
                    rule.common().cooldown_ms,
                    now_ms,
                ),
            };
            if !cooldown_ok {
                continue;
            }
            self.spawn_dispatch(
                Arc::clone(channel),
                Arc::clone(&notification),
                Arc::clone(&extras),
            );
        }
    }

    fn spawn_dispatch(
        &self,
        channel: Arc<NotificationChannel>,
        notification: Arc<crate::notifications::Notification>,
        extras: Arc<HashMap<String, String>>,
    ) {
        let permit = match Arc::clone(&self.dispatch_sem).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    plugin = "proxy_alerts",
                    channel = %channel.name(),
                    "notification dispatch backpressure: dropping alert"
                );
                return;
            }
        };
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
        self.handle(SampleInput::Http(summary));
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.handle(SampleInput::Stream(summary));
    }
}
