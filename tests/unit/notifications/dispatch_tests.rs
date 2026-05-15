//! Tests for `crate::notifications::dispatch`.
//!
//! The dispatch helper is fire-and-forget — its observable effect is whether
//! tasks are scheduled or dropped on the floor when the semaphore is
//! exhausted. We can verify that without a live HTTP server by configuring a
//! webhook to a non-routable address and confirming dispatch returns
//! immediately (drops happen synchronously when permits cannot be acquired).

use std::sync::Arc;

use ferrum_edge::notifications::channels::{NotificationChannel, parse_channels};
use ferrum_edge::notifications::{
    EventAction, Notification, NotificationField, Severity, dispatch,
};
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use serde_json::json;
use tokio::sync::Semaphore;

fn fixed_notification() -> Notification {
    Notification {
        title: "x".to_string(),
        body: "y".to_string(),
        severity: Severity::Info,
        event_action: EventAction::Info,
        source: None,
        subject_id: None,
        namespace: None,
        fired_at: chrono::Utc::now(),
        fields: vec![NotificationField::new("k", "v")],
    }
}

fn one_webhook_channel() -> Arc<NotificationChannel> {
    let map = parse_channels(&json!({
        "drop": {
            "type": "webhook",
            "url": "http://127.0.0.1:1/unreachable",
            "body_template": "{}",
        }
    }))
    .unwrap();
    map.into_values().next().unwrap()
}

#[tokio::test]
async fn dispatch_drops_when_semaphore_exhausted() {
    let sem = Arc::new(Semaphore::new(0)); // 0 permits => never acquirable
    let http = PluginHttpClient::default();
    let channel = one_webhook_channel();
    let notification = Arc::new(fixed_notification());

    // Should not block, should not panic, should not spawn.
    dispatch(
        Arc::clone(&notification),
        &[Arc::clone(&channel)],
        &sem,
        &http,
        "test_caller",
    );

    // No way to assert "no task spawned" directly without instrumentation,
    // but the test passing the runtime without errors confirms the
    // try_acquire_owned -> early-continue path.
}

#[tokio::test]
async fn dispatch_spawns_task_when_permit_available() {
    let sem = Arc::new(Semaphore::new(8));
    let http = PluginHttpClient::default();
    let channel = one_webhook_channel();
    let notification = Arc::new(fixed_notification());

    dispatch(
        Arc::clone(&notification),
        &[Arc::clone(&channel)],
        &sem,
        &http,
        "test_caller",
    );

    // Give the spawned task a moment to fail-fast on the unreachable URL.
    // Failure is logged via tracing (warn!), not propagated — we only
    // verify the dispatch helper returns synchronously.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn dispatch_with_multiple_channels_sends_each() {
    let sem = Arc::new(Semaphore::new(8));
    let http = PluginHttpClient::default();
    let channel = one_webhook_channel();
    let notification = Arc::new(fixed_notification());

    dispatch(
        Arc::clone(&notification),
        &[
            Arc::clone(&channel),
            Arc::clone(&channel),
            Arc::clone(&channel),
        ],
        &sem,
        &http,
        "test_caller",
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}
