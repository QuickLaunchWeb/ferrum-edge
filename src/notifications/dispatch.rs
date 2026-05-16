//! Bounded-concurrency notification dispatch.
//!
//! `dispatch` fans a [`Notification`] out to each target channel under a
//! caller-supplied `Semaphore`. Each channel send runs on its own
//! `tokio::spawn` so a slow webhook can never block the caller (typically a
//! plugin's `log()` hook on the request lifecycle); when the semaphore is
//! exhausted the alert is dropped with a `warn!` rather than queued — alert
//! storms during a partial channel outage should be visible, not buffered.
//!
//! Each caller (the `proxy_alerts` plugin, future overload-manager, etc.)
//! owns its own `Semaphore` so dispatch budgets do not interact.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing::warn;

use crate::plugins::utils::http_client::PluginHttpClient;

use super::channels::NotificationChannel;
use super::notification::Notification;

/// Fan `notification` out to every channel in `targets`.
///
/// - `sem` bounds total concurrent dispatches across this caller's targets.
/// - `http` is reused for every webhook-shaped channel.
/// - `log_source` is a static label (`"proxy_alerts"`, etc.) included in
///   warning logs so operators can attribute drops/failures to the right
///   subsystem without grepping channel internals.
#[allow(dead_code)] // Reusable helper for non-plugin callers (overload
// manager, mesh policy, custom plugins). The proxy_alerts plugin spawns
// dispatches directly because it carries per-channel cooldown state and
// per-rule webhook template extras that are out of scope for the generic
// helper.
pub fn dispatch(
    notification: Arc<Notification>,
    targets: &[Arc<NotificationChannel>],
    sem: &Arc<Semaphore>,
    http: &PluginHttpClient,
    log_source: &'static str,
) {
    for channel in targets {
        let permit = match Arc::clone(sem).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    source = log_source,
                    channel = %channel.name(),
                    "notification dispatch backpressure: dropping notification"
                );
                continue;
            }
        };
        let n = Arc::clone(&notification);
        let chan = Arc::clone(channel);
        let http = http.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = chan.dispatch(&n, &http).await {
                warn!(
                    source = log_source,
                    channel = %chan.name(),
                    error = %e,
                    "notification dispatch failed"
                );
            }
        });
    }
}
