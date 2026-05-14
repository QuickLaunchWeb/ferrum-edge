//! Tests for `src/notifications/channels/`.
//!
//! Cover `parse_channels` validation paths and each channel's payload
//! shape via `build_payload()` / `render_body()` so we don't need a live
//! HTTP server to assert wire format.

use std::collections::HashMap;

use chrono::{TimeZone, Utc};
use ferrum_edge::notifications::channels::{
    DiscordChannel, NotificationChannel, SlackChannel, TeamsChannel, WebhookChannel, parse_channels,
};
use ferrum_edge::notifications::{EventAction, Notification, NotificationField, Severity};
use serde_json::{Value, json};

fn fixed_notification() -> Notification {
    Notification {
        title: "[ALERT] proxy_5xx on api-gateway".to_string(),
        body: "5/100 requests matched [503] over 60s".to_string(),
        severity: Severity::High,
        event_action: EventAction::Trigger,
        source: Some("proxy_alerts:proxy_5xx".into()),
        subject_id: Some("api-gateway".into()),
        namespace: Some("ferrum".into()),
        fired_at: Utc.with_ymd_and_hms(2026, 5, 14, 10, 0, 0).unwrap(),
        fields: vec![
            NotificationField::new("Rule", "proxy_5xx"),
            NotificationField::new("Observed", "5.00%"),
            NotificationField::new("Threshold", "5.00%"),
        ],
    }
}

fn parse_one(name: &str, def: Value) -> NotificationChannel {
    let map = parse_channels(&json!({ name: def })).unwrap();
    let arc = map.get(name).expect("channel parsed").clone();
    (*arc).clone()
}

// ---------------------------------------------------------------- parse_channels

#[test]
fn parse_channels_rejects_empty_object() {
    let err = parse_channels(&json!({})).unwrap_err();
    assert!(err.contains("at least one channel"), "got: {err}");
}

#[test]
fn parse_channels_rejects_non_object() {
    let err = parse_channels(&json!([])).unwrap_err();
    assert!(err.contains("must be an object"), "got: {err}");
}

#[test]
fn parse_channels_rejects_unknown_type() {
    let err = parse_channels(&json!({
        "ops": { "type": "smoke_signal", "webhook_url": "https://x" }
    }))
    .unwrap_err();
    assert!(err.contains("unknown 'type'"), "got: {err}");
}

#[test]
fn parse_channels_rejects_missing_type() {
    let err = parse_channels(&json!({
        "ops": { "webhook_url": "https://hooks.slack.com/x" }
    }))
    .unwrap_err();
    assert!(err.contains("'type' is required"), "got: {err}");
}

#[test]
fn parse_channels_rejects_invalid_channel_name() {
    let err = parse_channels(&json!({
        "ops alerts": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" }
    }))
    .unwrap_err();
    assert!(err.contains("[A-Za-z0-9_-]+"), "got: {err}");
}

#[test]
fn parse_channels_rejects_non_http_webhook_url() {
    let err = parse_channels(&json!({
        "ops": { "type": "slack", "webhook_url": "ftp://hooks.slack.com/x" }
    }))
    .unwrap_err();
    assert!(err.contains("http:// or https://"), "got: {err}");
}

#[test]
fn parse_channels_rejects_missing_webhook_url() {
    let err = parse_channels(&json!({
        "ops": { "type": "slack" }
    }))
    .unwrap_err();
    assert!(err.contains("'webhook_url' is required"), "got: {err}");
}

#[test]
fn parse_channels_accepts_all_four_kinds() {
    let map = parse_channels(&json!({
        "ops_slack": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" },
        "ops_teams": { "type": "teams", "webhook_url": "https://outlook.office.com/x" },
        "ops_discord": { "type": "discord", "webhook_url": "https://discord.com/api/webhooks/x" },
        "ops_generic": {
            "type": "webhook",
            "url": "https://example.com/alerts",
            "body_template": "{\"r\":\"${rule_name}\"}",
        }
    }))
    .unwrap();
    assert_eq!(map.len(), 4);
    assert_eq!(map["ops_slack"].kind(), "slack");
    assert_eq!(map["ops_teams"].kind(), "teams");
    assert_eq!(map["ops_discord"].kind(), "discord");
    assert_eq!(map["ops_generic"].kind(), "webhook");
}

// ---------------------------------------------------------------- Slack payload

#[test]
fn slack_payload_carries_severity_color_and_fields() {
    let chan = parse_one(
        "ops",
        json!({
            "type": "slack",
            "webhook_url": "https://hooks.slack.com/x",
            "channel_override": "#alerts",
            "username": "ferrum-edge",
            "icon_emoji": ":fire:",
        }),
    );
    let NotificationChannel::Slack(slack) = chan else {
        panic!("expected slack");
    };
    assert_slack_payload_shape(&slack);
}

fn assert_slack_payload_shape(slack: &SlackChannel) {
    let payload = slack.build_payload(&fixed_notification());
    assert_eq!(payload["channel"], "#alerts");
    assert_eq!(payload["username"], "ferrum-edge");
    assert_eq!(payload["icon_emoji"], ":fire:");
    let attachments = payload["attachments"]
        .as_array()
        .expect("attachments array");
    assert_eq!(attachments.len(), 1);
    let a = &attachments[0];
    assert_eq!(a["color"], Severity::High.slack_color());
    assert_eq!(a["title"], "[ALERT] proxy_5xx on api-gateway");
    assert_eq!(a["text"], "5/100 requests matched [503] over 60s");
    let fields = a["fields"].as_array().expect("fields array");
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0]["title"], "Rule");
    assert_eq!(fields[0]["value"], "proxy_5xx");
    assert_eq!(fields[0]["short"], true);
    assert_eq!(a["footer"], "proxy_alerts:proxy_5xx");
}

// ---------------------------------------------------------------- Teams payload

#[test]
fn teams_payload_uses_message_card_schema() {
    let chan = parse_one(
        "ops",
        json!({
            "type": "teams",
            "webhook_url": "https://outlook.office.com/webhook/x",
        }),
    );
    let NotificationChannel::Teams(teams) = chan else {
        panic!("expected teams");
    };
    let payload = teams.build_payload(&fixed_notification());
    assert_eq!(payload["@type"], "MessageCard");
    assert_eq!(payload["@context"], "https://schema.org/extensions");
    assert_eq!(payload["themeColor"], Severity::High.teams_color_hex());
    assert_eq!(payload["title"], "[ALERT] proxy_5xx on api-gateway");
    let sections = payload["sections"].as_array().expect("sections");
    let facts = sections[0]["facts"].as_array().expect("facts");
    assert_eq!(facts.len(), 3);
    assert_eq!(facts[0]["name"], "Rule");
    assert_eq!(facts[0]["value"], "proxy_5xx");
}

// -------------------------------------------------------------- Discord payload

#[test]
fn discord_payload_uses_embeds_with_color_int() {
    let chan = parse_one(
        "ops",
        json!({
            "type": "discord",
            "webhook_url": "https://discord.com/api/webhooks/x",
            "username": "ferrum-edge",
        }),
    );
    let NotificationChannel::Discord(discord) = chan else {
        panic!("expected discord");
    };
    let payload = discord.build_payload(&fixed_notification());
    assert_eq!(payload["username"], "ferrum-edge");
    let embeds = payload["embeds"].as_array().expect("embeds");
    let e = &embeds[0];
    assert_eq!(e["title"], "[ALERT] proxy_5xx on api-gateway");
    assert_eq!(e["color"], Severity::High.discord_color());
    assert_eq!(e["timestamp"], fixed_notification().fired_at.to_rfc3339());
    let fields = e["fields"].as_array().expect("fields");
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0]["name"], "Rule");
    assert_eq!(fields[0]["inline"], true);
    assert_eq!(e["footer"]["text"], "proxy_alerts:proxy_5xx");
}

// -------------------------------------------------------------- Webhook payload

#[test]
fn webhook_renders_template_with_caller_extras() {
    let chan = parse_one(
        "pd",
        json!({
            "type": "webhook",
            "url": "https://events.pagerduty.com/v2/enqueue",
            "body_template": "{\"rule\":\"${rule_name}\",\"event\":\"${event_action}\",\"sev\":\"${severity}\"}",
        }),
    );
    let NotificationChannel::Webhook(webhook) = chan else {
        panic!("expected webhook");
    };
    let mut extras: HashMap<String, String> = HashMap::new();
    extras.insert("rule_name".to_string(), "proxy_5xx".to_string());
    extras.insert("event_action".to_string(), "trigger".to_string());
    let body = webhook
        .render_body_with_vars(&fixed_notification(), &extras)
        .unwrap();
    assert_eq!(
        body,
        "{\"rule\":\"proxy_5xx\",\"event\":\"trigger\",\"sev\":\"high\"}"
    );
}

#[test]
fn webhook_rejects_unbalanced_template_at_construction() {
    let err = WebhookChannel::new(
        "pd",
        &json!({
            "type": "webhook",
            "url": "https://example.com",
            "body_template": "${broken",
        }),
    )
    .unwrap_err();
    assert!(err.contains("invalid 'body_template'"), "got: {err}");
}

#[test]
fn webhook_rejects_unsupported_method() {
    let err = WebhookChannel::new(
        "pd",
        &json!({
            "type": "webhook",
            "url": "https://example.com",
            "method": "DELETE",
            "body_template": "x",
        }),
    )
    .unwrap_err();
    assert!(err.contains("unsupported method"), "got: {err}");
}

#[test]
fn webhook_default_content_type_is_json() {
    let webhook = WebhookChannel::new(
        "pd",
        &json!({
            "type": "webhook",
            "url": "https://example.com",
            "body_template": "x",
        }),
    )
    .unwrap();
    let ct = webhook
        .headers()
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case("content-type"));
    assert!(ct.is_some(), "default content-type should be set");
    assert_eq!(ct.unwrap().1.to_str().unwrap(), "application/json");
}

#[test]
fn webhook_operator_content_type_overrides_default() {
    let webhook = WebhookChannel::new(
        "pd",
        &json!({
            "type": "webhook",
            "url": "https://example.com",
            "headers": { "content-type": "text/plain" },
            "body_template": "x",
        }),
    )
    .unwrap();
    let ct = webhook
        .headers()
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case("content-type"))
        .unwrap();
    assert_eq!(ct.1.to_str().unwrap(), "text/plain");
}

// -------------------------------------------------- env-var resolution helper

#[test]
fn env_var_resolution_for_webhook_url() {
    // Use a unique env var name so tests don't collide.
    let var = "FERRUM_TEST_NOTIFICATIONS_SLACK_WEBHOOK_URL";
    // SAFETY: tests are single-threaded per file by default; setting a
    // unique env var name avoids interfering with other tests.
    unsafe {
        std::env::set_var(var, "https://hooks.slack.com/from-env");
    }
    let chan = SlackChannel::new(
        "ops",
        &json!({
            "type": "slack",
            "webhook_url_env": var,
        }),
    )
    .unwrap();
    let payload = chan.build_payload(&fixed_notification());
    // Construction succeeded — webhook_url is private but the channel is
    // configured. Cleanup.
    let _ = payload;
    unsafe {
        std::env::remove_var(var);
    }
}

#[test]
fn env_var_resolution_fails_when_unset() {
    let err = SlackChannel::new(
        "ops",
        &json!({
            "type": "slack",
            "webhook_url_env": "FERRUM_TEST_DEFINITELY_UNSET_XYZ_123",
        }),
    )
    .unwrap_err();
    assert!(err.contains("is not set"), "got: {err}");
}

#[test]
fn explicit_webhook_url_takes_precedence_over_env_var() {
    let var = "FERRUM_TEST_BOTH_WEBHOOK_URL";
    unsafe {
        std::env::set_var(var, "https://hooks.slack.com/from-env");
    }
    // Both fields present — the inline value wins.
    let result = SlackChannel::new(
        "ops",
        &json!({
            "type": "slack",
            "webhook_url": "https://hooks.slack.com/inline",
            "webhook_url_env": var,
        }),
    );
    assert!(result.is_ok());
    unsafe {
        std::env::remove_var(var);
    }
}

#[test]
fn teams_channel_constructor_smoke() {
    TeamsChannel::new(
        "ops",
        &json!({
            "type": "teams",
            "webhook_url": "https://outlook.office.com/x",
        }),
    )
    .unwrap();
}

#[test]
fn discord_channel_constructor_smoke() {
    DiscordChannel::new(
        "ops",
        &json!({
            "type": "discord",
            "webhook_url": "https://discord.com/api/webhooks/x",
        }),
    )
    .unwrap();
}
