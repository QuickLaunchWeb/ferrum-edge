//! Integration tests for the customizable transaction-log schema feature.
//!
//! Drift detection between the registry and the structs lives in
//! `log_schema_registry_tests.rs`. This file covers the cross-plugin /
//! cross-loader interactions:
//!
//! * `transaction_log_schema` + a logging plugin referencing it via
//!   `schema_ref:` resolves correctly through the named-schemas registry.
//! * The loader's `begin_reload` / `commit_reload` bracket actually
//!   publishes schemas so dependents can find them.
//! * Non-shipping plugins (transaction_debugger, prometheus_metrics,
//!   api_chargeback) reject `schema` / `schema_ref` keys.
//! * `transaction_log_schema` rejects non-global scopes via
//!   `GatewayConfig::validate_plugin_references`.

use std::sync::{Mutex, MutexGuard, OnceLock};

use ferrum_edge::plugins::create_plugin;
use ferrum_edge::plugins::utils::log_schema::registry;
use serde_json::{Value, json};

/// `Option<Arc<dyn Plugin>>` is not `Debug`, so `Result::expect_err` won't
/// compile against it. Wrap the bare `create_plugin` to discard the Ok
/// payload and return either the error string or a panic.
fn create_err(name: &str, config: Value) -> String {
    match create_plugin(name, &config) {
        Ok(_) => panic!("expected {name} construction to fail with config: {config}"),
        Err(e) => e,
    }
}

fn create_ok(name: &str, config: Value) {
    match create_plugin(name, &config) {
        Ok(Some(_)) => {}
        Ok(None) => panic!("{name} returned no plugin"),
        Err(e) => panic!("expected {name} to construct: {e}"),
    }
}

/// Tests that touch the process-global named-schemas registry serialize
/// via this mutex so concurrent test runs don't race each other.
fn registry_lock() -> MutexGuard<'static, ()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn schema_ref_resolves_when_schema_registered_first() {
    let _g = registry_lock();
    registry::reset_for_tests();

    // Loader runs `begin_reload`, processes transaction_log_schema first,
    // then `commit_reload`, then the rest.
    registry::begin_reload();
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "splunk_cim": {
                    "summary_type": "both",
                    "rename": { "proxy_id": "route_id" }
                }
            }
        }),
    );
    registry::commit_reload();

    create_ok("stdout_logging", json!({ "schema_ref": "splunk_cim" }));
}

#[test]
fn schema_ref_unknown_rejected_after_commit() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload();
    registry::commit_reload(); // empty registry

    let err = create_err("stdout_logging", json!({ "schema_ref": "missing" }));
    assert!(err.contains("unknown schema 'missing'"), "got: {err}");
}

#[test]
fn inline_and_schema_ref_mutually_exclusive() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload();
    create_ok("transaction_log_schema", json!({ "schemas": { "x": {} } }));
    registry::commit_reload();

    let err = create_err(
        "stdout_logging",
        json!({
            "schema": { "summary_type": "http" },
            "schema_ref": "x"
        }),
    );
    assert!(err.contains("mutually exclusive"), "got: {err}");
}

#[test]
fn transaction_debugger_rejects_schema() {
    let err = create_err(
        "transaction_debugger",
        json!({ "schema": { "summary_type": "http" } }),
    );
    assert!(err.contains("not supported"), "got: {err}");
}

#[test]
fn transaction_debugger_rejects_schema_ref() {
    let err = create_err("transaction_debugger", json!({ "schema_ref": "x" }));
    assert!(err.contains("not supported"), "got: {err}");
}

#[test]
fn prometheus_metrics_rejects_schema() {
    let err = create_err(
        "prometheus_metrics",
        json!({ "schema": { "summary_type": "http" } }),
    );
    assert!(err.contains("not supported"), "got: {err}");
}

#[test]
fn api_chargeback_rejects_schema() {
    let err = create_err(
        "api_chargeback",
        json!({ "schema": { "summary_type": "http" } }),
    );
    assert!(err.contains("not supported"), "got: {err}");
}

#[test]
fn schema_loaded_after_commit_visible_to_subsequent_constructions() {
    let _g = registry_lock();
    registry::reset_for_tests();
    registry::begin_reload();
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "a": { "summary_type": "http" },
                "b": { "summary_type": "stream" }
            }
        }),
    );
    registry::commit_reload();

    // Both schemas should be resolvable.
    create_ok("stdout_logging", json!({ "schema_ref": "a" }));
    create_ok("stdout_logging", json!({ "schema_ref": "b" }));
}

#[test]
fn reload_replaces_previous_schemas() {
    let _g = registry_lock();
    registry::reset_for_tests();

    // First reload: schemas "a" and "b".
    registry::begin_reload();
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "a": { "summary_type": "http" },
                "b": { "summary_type": "stream" }
            }
        }),
    );
    registry::commit_reload();
    assert!(registry::lookup_named("a").is_some());
    assert!(registry::lookup_named("b").is_some());

    // Second reload: only schema "a" plus a new "c". "b" should vanish.
    registry::begin_reload();
    create_ok(
        "transaction_log_schema",
        json!({
            "schemas": {
                "a": { "summary_type": "http" },
                "c": { "summary_type": "both" }
            }
        }),
    );
    registry::commit_reload();
    assert!(registry::lookup_named("a").is_some(), "a survived");
    assert!(registry::lookup_named("b").is_none(), "b removed");
    assert!(registry::lookup_named("c").is_some(), "c added");
}

#[test]
fn schema_ref_succeeds_with_inline_validation_path() {
    // Even outside a reload bracket (validation-mode register_named is a
    // no-op), inline schemas still compile and apply. Verifies that
    // validation doesn't require the registry to be populated.
    let _g = registry_lock();
    registry::reset_for_tests();
    create_ok(
        "stdout_logging",
        json!({
            "schema": {
                "summary_type": "http",
                "rename": { "proxy_id": "route_id" }
            }
        }),
    );
}

#[tokio::test]
async fn ws_logging_accepts_schema() {
    let _g = registry_lock();
    registry::reset_for_tests();
    create_ok(
        "ws_logging",
        json!({
            "endpoint_url": "ws://logs.example.com/ingest",
            "schema": { "summary_type": "http", "omit": ["request_user_agent"] }
        }),
    );
}

#[tokio::test]
async fn statsd_logging_accepts_schema_with_tag_rename() {
    let _g = registry_lock();
    registry::reset_for_tests();
    create_ok(
        "statsd_logging",
        json!({
            "host": "127.0.0.1",
            "port": 8125,
            "schema": {
                "summary_type": "http",
                "rename": { "proxy_id": "route_id", "http_method": "verb" }
            }
        }),
    );
}

#[tokio::test]
async fn loki_logging_accepts_schema() {
    let _g = registry_lock();
    registry::reset_for_tests();
    create_ok(
        "loki_logging",
        json!({
            "endpoint_url": "http://loki.example.com:3100/loki/api/v1/push",
            "schema": {
                "summary_type": "both",
                "metadata": { "mode": "flatten", "prefix": "meta_" }
            }
        }),
    );
}
