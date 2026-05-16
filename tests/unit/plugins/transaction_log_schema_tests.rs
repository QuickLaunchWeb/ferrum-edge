//! Tests for the `transaction_log_schema` plugin — the config-only plugin
//! that registers named [`SummarySchema`] definitions for other logging
//! plugins to resolve via `schema_ref:`.
//!
//! These tests exercise the construction-time validation path. Tests that
//! touch the process-global named-schemas registry hold the reload-bracket
//! serializer for their entire scope so parallel sibling tests booting
//! gateways don't stomp the registry between the test's writes and its
//! assertions.

use ferrum_edge::plugins::transaction_log_schema::TransactionLogSchema;
use ferrum_edge::plugins::utils::log_schema::registry;
use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, priority, validate_plugin_config};
use serde_json::json;

/// Hold the reload-bracket serializer across both writes and assertions
/// so parallel tests that boot gateways (and therefore drive their own
/// `begin_reload` / `commit_reload`) cannot stomp the registry mid-test.
fn registry_lock() -> registry::ReloadBracketTestGuard {
    registry::lock_for_tests()
}

// ── Plugin identity ─────────────────────────────────────────────────

#[test]
fn test_plugin_identity() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let plugin = TransactionLogSchema::new(&json!({
        "schemas": { "splunk_cim": { "summary_type": "both" } }
    }))
    .expect("plugin constructs with a single valid schema");
    assert_eq!(plugin.name(), "transaction_log_schema");
    assert_eq!(plugin.priority(), priority::TRANSACTION_LOG_SCHEMA);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

// ── Valid construction ──────────────────────────────────────────────

#[test]
fn test_valid_config_with_named_schemas_constructs() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let plugin = TransactionLogSchema::new(&json!({
        "schemas": {
            "splunk_cim": {
                "summary_type": "both",
                "rename": { "proxy_id": "route_id" }
            },
            "datadog": {
                "summary_type": "http",
                "static_fields": { "source": "ferrum-edge" }
            }
        }
    }))
    .expect("plugin constructs with multiple valid schemas");
    assert_eq!(plugin.schemas().len(), 2);
    assert!(plugin.schemas().contains_key("splunk_cim"));
    assert!(plugin.schemas().contains_key("datadog"));
}

#[test]
fn test_schema_with_rename_omit_and_derived_fields_constructs() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let plugin = TransactionLogSchema::new(&json!({
        "schemas": {
            "rich_schema": {
                "summary_type": "http",
                "rename": { "proxy_id": "route_id" },
                "omit": ["latency_plugin_external_io_ms"],
                "derived_fields": [
                    { "name": "status_class", "kind": "status_class" },
                    { "name": "outcome", "kind": "outcome" }
                ]
            }
        }
    }))
    .expect("plugin constructs with rename, omit, and derived_fields");
    assert_eq!(plugin.schemas().len(), 1);
}

#[test]
fn test_validate_plugin_config_path_accepts_valid_config() {
    // Validation path used by file_loader / db_loader / admin handlers.
    let _g = registry_lock();
    registry::reset_for_tests();
    validate_plugin_config(
        "transaction_log_schema",
        &json!({
            "schemas": { "datadog": { "summary_type": "http" } }
        }),
    )
    .expect("validate_plugin_config accepts a valid schema config");
}

// ── Missing / empty schemas list ────────────────────────────────────

#[test]
fn test_missing_schemas_key_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err =
        TransactionLogSchema::new(&json!({})).expect_err("missing 'schemas' must be rejected");
    assert!(err.contains("'schemas' is required"), "got: {err}");
}

#[test]
fn test_empty_schemas_object_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({ "schemas": {} }))
        .expect_err("empty 'schemas' object must be rejected");
    assert!(err.contains("at least one"), "got: {err}");
}

#[test]
fn test_empty_schemas_via_validate_plugin_config_rejected() {
    // Same validation surface used by file_loader / admin API.
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = validate_plugin_config("transaction_log_schema", &json!({ "schemas": {} }))
        .expect_err("validate_plugin_config rejects empty schemas");
    assert!(err.contains("at least one"), "got: {err}");
}

#[test]
fn test_schemas_not_object_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({ "schemas": [] }))
        .expect_err("array-typed 'schemas' must be rejected");
    assert!(err.contains("must be an object"), "got: {err}");
}

// ── Empty schema name ───────────────────────────────────────────────

#[test]
fn test_empty_schema_name_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": { "": { "summary_type": "http" } }
    }))
    .expect_err("empty schema name must be rejected");
    assert!(err.contains("non-empty"), "got: {err}");
}

// ── Invalid inner schema definitions ────────────────────────────────

#[test]
fn test_invalid_inner_schema_unknown_field_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "bad": { "omit": ["not_a_real_field"] }
        }
    }))
    .expect_err("schema with unknown field must be rejected");
    // The compile error is prefixed with the schema entry label.
    assert!(err.contains("[bad]"), "got: {err}");
    assert!(
        err.contains("unknown field 'not_a_real_field'"),
        "got: {err}"
    );
}

#[test]
fn test_invalid_inner_schema_unknown_top_level_key_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "typo": { "renaime": { "proxy_id": "route_id" } }
        }
    }))
    .expect_err("schema with typo'd top-level key must be rejected");
    assert!(err.contains("[typo]"), "got: {err}");
    assert!(err.contains("unknown schema key 'renaime'"), "got: {err}");
}

#[test]
fn test_invalid_inner_schema_bad_summary_type_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "bad": { "summary_type": "not_a_summary_type" }
        }
    }))
    .expect_err("schema with bogus summary_type must be rejected");
    assert!(
        err.contains("'summary_type' must be 'http', 'stream', or 'both'"),
        "got: {err}"
    );
}

#[test]
fn test_invalid_inner_schema_omit_rename_conflict_rejected() {
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "bad": {
                "summary_type": "http",
                "omit": ["proxy_id"],
                "rename": { "proxy_id": "route_id" }
            }
        }
    }))
    .expect_err("schema with both omit and rename for the same field must be rejected");
    assert!(err.contains("both omitted and renamed"), "got: {err}");
}

// ── Multi-entry: first valid, second invalid is rejected ────────────

#[test]
fn test_multi_entry_with_one_invalid_rejects_whole_config() {
    // The invalid entry must fail the whole construction — no silent skip.
    let _g = registry_lock();
    registry::reset_for_tests();
    let err = TransactionLogSchema::new(&json!({
        "schemas": {
            "good": { "summary_type": "http" },
            "bad":  { "omit": ["not_a_real_field"] }
        }
    }))
    .expect_err("config containing an invalid schema must be rejected");
    assert!(err.contains("[bad]"), "got: {err}");
}

// ── Registry interaction: validation-mode is a no-op ────────────────

#[test]
fn test_construction_without_reload_bracket_does_not_pollute_registry() {
    // Mirrors the admin-API single-plugin validation path: no
    // begin_reload bracket is open, so register_named must be a no-op and
    // the live registry must remain empty.
    let _g = registry_lock();
    registry::reset_for_tests();
    let plugin = TransactionLogSchema::new(&json!({
        "schemas": {
            "datadog": { "summary_type": "http" }
        }
    }))
    .expect("plugin constructs without a reload bracket");
    // The plugin owns its compiled schema...
    assert!(plugin.schemas().contains_key("datadog"));
    // ...but the live (committed) registry remains empty.
    assert!(registry::lookup_named("datadog").is_none());
}
