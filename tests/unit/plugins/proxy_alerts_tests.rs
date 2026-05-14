//! Tests for the `proxy_alerts` plugin.
//!
//! Coverage:
//! - Config validation (empty channels/rules, unknown channel refs, range
//!   checks per rule type, severity strings, error class strings).
//! - Bucketed sliding-window correctness (record/snapshot under synthetic
//!   `now_ms`).
//! - Cooldown gate per `(rule_id, channel_id)`.
//! - Recovery state machine transitions (Healthy → Active → Recovering →
//!   Healthy / Recovering → Active flap).
//! - Plugin construction wires everything end-to-end.

use ferrum_edge::plugins::proxy_alerts::ProxyAlerts;
use ferrum_edge::plugins::proxy_alerts::cooldown::{
    CooldownGate, LifecycleOutcome, RecoveryGate, RuleState,
};
use ferrum_edge::plugins::proxy_alerts::windows::{BucketedCounter, BucketedLatencyHistogram};
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin};
use serde_json::json;

fn http_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn minimal_config() -> serde_json::Value {
    json!({
        "channels": {
            "ops_slack": {
                "type": "slack",
                "webhook_url": "https://hooks.slack.com/services/x/y/z"
            }
        },
        "rules": [
            {
                "name": "proxy_5xx",
                "type": "error_rate",
                "status_codes": [500, 502, 503],
                "window_seconds": 60,
                "threshold_percent": 5.0,
                "min_request_count": 10,
                "channels": ["ops_slack"]
            }
        ]
    })
}

// ----------------------------------------------- Construction / config validation

#[test]
fn rejects_non_object_config() {
    let err = ProxyAlerts::new(&json!([]), http_client()).unwrap_err();
    assert!(err.contains("must be an object"), "got: {err}");
}

#[test]
fn rejects_missing_channels() {
    let err = ProxyAlerts::new(&json!({ "rules": [] }), http_client()).unwrap_err();
    assert!(err.contains("'channels' is required"), "got: {err}");
}

#[test]
fn rejects_empty_channels() {
    let err = ProxyAlerts::new(
        &json!({
            "channels": {},
            "rules": []
        }),
        http_client(),
    )
    .unwrap_err();
    assert!(err.contains("at least one channel"), "got: {err}");
}

#[test]
fn rejects_missing_rules() {
    let err = ProxyAlerts::new(
        &json!({
            "channels": {
                "ops_slack": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            }
        }),
        http_client(),
    )
    .unwrap_err();
    assert!(err.contains("'rules' is required"), "got: {err}");
}

#[test]
fn rejects_empty_rules_array() {
    let err = ProxyAlerts::new(
        &json!({
            "channels": {
                "ops_slack": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/x"
                }
            },
            "rules": []
        }),
        http_client(),
    )
    .unwrap_err();
    assert!(err.contains("at least one rule"), "got: {err}");
}

#[test]
fn rejects_unknown_channel_reference() {
    let mut cfg = minimal_config();
    cfg["rules"][0]["channels"] = json!(["does_not_exist"]);
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("unknown channel"), "got: {err}");
}

#[test]
fn rejects_duplicate_rule_name() {
    let cfg = json!({
        "channels": {
            "c": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" }
        },
        "rules": [
            {
                "name": "r1", "type": "error_rate", "status_codes": [500],
                "threshold_percent": 5.0, "channels": ["c"]
            },
            {
                "name": "r1", "type": "error_rate", "status_codes": [500],
                "threshold_percent": 5.0, "channels": ["c"]
            }
        ]
    });
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("duplicate rule name"), "got: {err}");
}

#[test]
fn rejects_window_seconds_out_of_range() {
    let mut cfg = minimal_config();
    cfg["rules"][0]["window_seconds"] = json!(2);
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("'window_seconds' must be"), "got: {err}");
}

#[test]
fn rejects_threshold_percent_out_of_range() {
    let mut cfg = minimal_config();
    cfg["rules"][0]["threshold_percent"] = json!(150.0);
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("'threshold_percent' must be"), "got: {err}");
}

#[test]
fn rejects_unknown_severity() {
    let mut cfg = minimal_config();
    cfg["rules"][0]["severity"] = json!("urgent");
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("unknown severity"), "got: {err}");
}

#[test]
fn rejects_unknown_error_class_in_rule() {
    let cfg = json!({
        "channels": {
            "c": { "type": "slack", "webhook_url": "https://hooks.slack.com/x" }
        },
        "rules": [
            {
                "name": "r1", "type": "error_class",
                "classes": ["timewarp"],
                "threshold_count": 5,
                "channels": ["c"]
            }
        ]
    });
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("unknown error class"), "got: {err}");
}

#[test]
fn rejects_invalid_quiet_hours_time() {
    let mut cfg = minimal_config();
    cfg["quiet_hours_utc"] = json!([{ "from": "25:00", "to": "06:00" }]);
    let err = ProxyAlerts::new(&cfg, http_client()).unwrap_err();
    assert!(err.contains("hour 25"), "got: {err}");
}

#[tokio::test]
async fn accepts_valid_minimal_config() {
    let plugin = ProxyAlerts::new(&minimal_config(), http_client()).unwrap();
    assert_eq!(plugin.name(), "proxy_alerts");
    assert_eq!(plugin.priority(), 9250);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn accepts_all_rule_types() {
    let cfg = json!({
        "channels": {
            "c": { "type": "webhook", "url": "https://example.com", "body_template": "x" }
        },
        "rules": [
            { "name": "r1", "type": "error_rate", "status_codes": [500],
              "threshold_percent": 5.0, "channels": ["c"] },
            { "name": "r2", "type": "status_code_count", "status_codes": [401, 403],
              "threshold_count": 100, "channels": ["c"] },
            { "name": "r3", "type": "latency_percentile", "metric": "backend_total_ms",
              "percentile": 95, "threshold_ms": 1000, "channels": ["c"] },
            { "name": "r4", "type": "error_class", "classes": ["connection_refused", "tls_error"],
              "threshold_count": 10, "channels": ["c"] },
            { "name": "r5", "type": "stream_disconnect_cause", "causes": ["backend_error"],
              "threshold_count": 5, "channels": ["c"] }
        ]
    });
    let plugin = ProxyAlerts::new(&cfg, http_client()).unwrap();
    assert_eq!(plugin.name(), "proxy_alerts");
}

// -------------------------------------------------------------- BucketedCounter

#[test]
fn bucketed_counter_records_and_aggregates_within_window() {
    let counter = BucketedCounter::new(60); // 60s = 6s buckets * 10
    let base = 1_000_000u64;
    counter.record(true, base);
    counter.record(false, base + 10);
    counter.record(true, base + 1000);
    let (matched, total) = counter.snapshot(base + 1500);
    assert_eq!(matched, 2);
    assert_eq!(total, 3);
}

#[test]
fn bucketed_counter_drops_buckets_older_than_window() {
    let counter = BucketedCounter::new(10); // 10s window, 1s buckets
    let base = 1_000_000u64;
    counter.record(true, base);
    // Roll forward past the entire window. Each bucket reset clears its
    // counters individually as new tags arrive.
    let (matched_inside, total_inside) = counter.snapshot(base + 5_000);
    assert_eq!(matched_inside, 1);
    assert_eq!(total_inside, 1);
    // Record a new sample 30s later; the only currently-valid bucket is the
    // one we just wrote to (older buckets were never re-tagged so they
    // appear stale to snapshot()).
    counter.record(false, base + 30_000);
    let (matched_after, total_after) = counter.snapshot(base + 30_500);
    assert_eq!(matched_after, 0, "old matched count must drop out");
    assert_eq!(total_after, 1);
}

// ----------------------------------------------- BucketedLatencyHistogram

#[test]
fn latency_histogram_estimates_p95_within_known_bucket() {
    let h = BucketedLatencyHistogram::new(60);
    let base = 2_000_000u64;
    // 100 samples: 95 small (<= 100ms) + 5 large (>= 1000ms).
    for i in 0..95 {
        h.record(50.0, base + i);
    }
    for i in 0..5 {
        h.record(1500.0, base + 95 + i);
    }
    let (p95, total) = h.percentile(95, base + 1000);
    assert_eq!(total, 100);
    // The 95th sample falls in bucket [50, 100) (95 samples at 50ms land
    // in that bucket). The estimate returned is the bucket's upper bound:
    // 100ms — i.e., "p95 is at most 100ms." This is a conservative
    // overestimate compared to the true p95 (50ms), which is the right
    // direction for alerting (slight bias against firing).
    assert_eq!(p95, Some(100.0));
}

#[test]
fn latency_histogram_returns_none_when_empty() {
    let h = BucketedLatencyHistogram::new(60);
    let (p, total) = h.percentile(95, 100);
    assert_eq!(p, None);
    assert_eq!(total, 0);
}

// ------------------------------------------------------------- CooldownGate

#[test]
fn cooldown_gate_first_acquire_succeeds() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, 10, 60_000, 100));
}

#[test]
fn cooldown_gate_blocks_within_window() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, 10, 60_000, 100));
    assert!(!gate.try_acquire(1, 10, 60_000, 100 + 30_000));
}

#[test]
fn cooldown_gate_releases_after_window() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, 10, 60_000, 100));
    assert!(gate.try_acquire(1, 10, 60_000, 100 + 60_001));
}

#[test]
fn cooldown_gate_per_channel_independent() {
    let gate = CooldownGate::new();
    assert!(gate.try_acquire(1, 10, 60_000, 100));
    // Same rule, different channel: should not be blocked.
    assert!(gate.try_acquire(1, 11, 60_000, 100 + 1));
}

// -------------------------------------------------------------- RecoveryGate

#[test]
fn recovery_healthy_to_active_emits_trigger() {
    let gate = RecoveryGate::new();
    let outcome = gate.observe(1, "p", true, 60_000, 1_000);
    assert_eq!(outcome, LifecycleOutcome::Trigger);
    assert_eq!(
        gate.current_state(1, "p"),
        Some(RuleState::Active { fired_at_ms: 1_000 })
    );
}

#[test]
fn recovery_active_to_active_returns_still_active() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 60_000, 1_000);
    let outcome = gate.observe(1, "p", true, 60_000, 2_000);
    assert_eq!(outcome, LifecycleOutcome::StillActive);
}

#[test]
fn recovery_active_to_recovering_then_resolve() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 60_000, 1_000);
    let entering = gate.observe(1, "p", false, 60_000, 2_000);
    assert_eq!(entering, LifecycleOutcome::EnteringRecovery);
    // Same call within recovery window: still quiet.
    let quiet = gate.observe(1, "p", false, 60_000, 30_000);
    assert_eq!(quiet, LifecycleOutcome::Quiet);
    // After recovery window has elapsed (resolved_window_ms = 60_000 from
    // the EnteringRecovery timestamp 2_000): observe at 2_000 + 60_000 =
    // 62_000.
    let resolve = gate.observe(1, "p", false, 60_000, 62_000);
    assert_eq!(resolve, LifecycleOutcome::Resolve);
    assert_eq!(gate.current_state(1, "p"), Some(RuleState::Healthy));
}

#[test]
fn recovery_recovering_to_active_when_breach_returns_during_window() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 60_000, 1_000); // Active
    gate.observe(1, "p", false, 60_000, 2_000); // Recovering
    let reactivate = gate.observe(1, "p", true, 60_000, 3_000);
    assert_eq!(reactivate, LifecycleOutcome::Reactivate);
    assert!(matches!(
        gate.current_state(1, "p"),
        Some(RuleState::Active { .. })
    ));
}

#[test]
fn recovery_disabled_when_recovery_ms_is_zero() {
    let gate = RecoveryGate::new();
    gate.observe(1, "p", true, 0, 1_000);
    gate.observe(1, "p", false, 0, 2_000);
    // Recovering, but recovery_ms = 0 means no Resolve will fire.
    let outcome = gate.observe(1, "p", false, 0, 1_000_000);
    assert_eq!(outcome, LifecycleOutcome::Quiet);
}
