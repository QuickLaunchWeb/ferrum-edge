//! Drift detection between `HTTP_FIELDS` / `STREAM_FIELDS` registries and
//! the actual `TransactionSummary` / `StreamTransactionSummary` structs.
//!
//! If you add a field to either summary struct and forget to add it to the
//! corresponding registry, this test fails with the missing field name.
//! If you remove a field, this test fails with the stale registry entry.
//!
//! Without this guard, the schema compiler would silently accept omits /
//! renames against non-existent fields (or reject valid ones), and
//! operators would get confusing errors.

use std::collections::{HashMap, HashSet};

use ferrum_edge::plugins::utils::log_schema::{HTTP_FIELDS, STREAM_FIELDS};
use ferrum_edge::plugins::{
    Direction, DisconnectCause, StreamTransactionSummary, TransactionSummary,
};
use ferrum_edge::retry::ErrorClass;

/// Populate every field of `TransactionSummary` so all serde
/// `skip_serializing_if` guards are bypassed and every key appears in the
/// serialized output.
fn fully_populated_http() -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".into(),
        timestamp_received: "2026-05-11T12:00:00Z".into(),
        client_ip: "10.0.0.1".into(),
        consumer_username: Some("alice".into()),
        auth_method: Some("jwt_auth"),
        http_method: "GET".into(),
        request_path: "/things".into(),
        proxy_id: Some("p1".into()),
        proxy_name: Some("things-api".into()),
        backend_target_url: Some("https://backend:8443/things".into()),
        backend_resolved_ip: Some("10.5.0.10".into()),
        response_status_code: 200,
        latency_total_ms: 12.5,
        latency_gateway_processing_ms: 1.0,
        latency_backend_ttfb_ms: 3.0,
        latency_backend_total_ms: 8.0,
        latency_plugin_execution_ms: 0.5,
        latency_plugin_external_io_ms: 0.1,
        latency_gateway_overhead_ms: 0.4,
        request_user_agent: Some("curl/8.0".into()),
        response_streamed: true,
        client_disconnected: true,
        error_class: Some(ErrorClass::ConnectionTimeout),
        body_error_class: Some(ErrorClass::ConnectionReset),
        body_completed: true,
        request_bytes: 100,
        response_bytes: 200,
        mirror: true,
        metadata: HashMap::from([("trace_id".to_string(), "abc".to_string())]),
    }
}

fn fully_populated_stream() -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".into(),
        proxy_id: "p2".into(),
        proxy_name: Some("db-front".into()),
        client_ip: "10.0.0.2".into(),
        consumer_username: Some("svc-account".into()),
        auth_method: Some("mtls_auth"),
        backend_target: "10.5.0.20:5432".into(),
        backend_resolved_ip: Some("10.5.0.20".into()),
        protocol: "tcp".into(),
        listen_port: 5432,
        duration_ms: 100.0,
        bytes_sent: 200,
        bytes_received: 400,
        connection_error: Some("ECONNRESET".into()),
        error_class: Some(ErrorClass::ConnectionReset),
        disconnect_direction: Some(Direction::BackendToClient),
        disconnect_cause: Some(DisconnectCause::GracefulShutdown),
        timestamp_connected: "2026-05-11T12:00:00Z".into(),
        timestamp_disconnected: "2026-05-11T12:01:40Z".into(),
        sni_hostname: Some("db.internal".into()),
        metadata: HashMap::from([("session_id".to_string(), "xyz".to_string())]),
    }
}

#[test]
fn http_fields_registry_matches_struct() {
    let summary = fully_populated_http();
    let value = serde_json::to_value(&summary).expect("serialize");
    let emitted: HashSet<String> = value.as_object().expect("object").keys().cloned().collect();

    let registered: HashSet<String> = HTTP_FIELDS.iter().map(|f| f.name.to_string()).collect();

    let missing_from_registry: Vec<&String> = emitted.difference(&registered).collect();
    let missing_from_struct: Vec<&String> = registered.difference(&emitted).collect();

    assert!(
        missing_from_registry.is_empty() && missing_from_struct.is_empty(),
        "TransactionSummary <-> HTTP_FIELDS drift detected.\n  In struct but missing from registry: {:?}\n  In registry but missing from struct: {:?}",
        missing_from_registry,
        missing_from_struct,
    );
}

#[test]
fn stream_fields_registry_matches_struct() {
    let summary = fully_populated_stream();
    let value = serde_json::to_value(&summary).expect("serialize");
    let emitted: HashSet<String> = value.as_object().expect("object").keys().cloned().collect();

    let registered: HashSet<String> = STREAM_FIELDS.iter().map(|f| f.name.to_string()).collect();

    let missing_from_registry: Vec<&String> = emitted.difference(&registered).collect();
    let missing_from_struct: Vec<&String> = registered.difference(&emitted).collect();

    assert!(
        missing_from_registry.is_empty() && missing_from_struct.is_empty(),
        "StreamTransactionSummary <-> STREAM_FIELDS drift detected.\n  In struct but missing from registry: {:?}\n  In registry but missing from struct: {:?}",
        missing_from_registry,
        missing_from_struct,
    );
}

#[test]
fn http_fields_declaration_order_matches_struct() {
    let summary = fully_populated_http();
    let value = serde_json::to_value(&summary).expect("serialize");
    let obj = value.as_object().expect("object");

    // serde_json::Map preserves insertion order (which matches struct field
    // declaration order). Build a parallel vec of emitted keys and check
    // each one shows up in HTTP_FIELDS in the same relative order.
    let emitted_order: Vec<&str> = obj.keys().map(String::as_str).collect();
    let registry_order: Vec<&str> = HTTP_FIELDS.iter().map(|f| f.name).collect();

    // Quick check: same length (the other tests would have caught mismatches).
    assert_eq!(emitted_order.len(), registry_order.len());
    for (i, name) in emitted_order.iter().enumerate() {
        assert_eq!(
            registry_order[i], *name,
            "HTTP_FIELDS order mismatch at index {i}: expected '{}', got '{name}'",
            registry_order[i]
        );
    }
}

#[test]
fn stream_fields_declaration_order_matches_struct() {
    let summary = fully_populated_stream();
    let value = serde_json::to_value(&summary).expect("serialize");
    let obj = value.as_object().expect("object");

    let emitted_order: Vec<&str> = obj.keys().map(String::as_str).collect();
    let registry_order: Vec<&str> = STREAM_FIELDS.iter().map(|f| f.name).collect();

    assert_eq!(emitted_order.len(), registry_order.len());
    for (i, name) in emitted_order.iter().enumerate() {
        assert_eq!(
            registry_order[i], *name,
            "STREAM_FIELDS order mismatch at index {i}: expected '{}', got '{name}'",
            registry_order[i]
        );
    }
}
