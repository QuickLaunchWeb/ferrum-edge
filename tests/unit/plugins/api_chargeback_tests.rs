//! Tests for api_chargeback plugin

use ferrum_edge::plugins::api_chargeback::{ApiChargeback, ChargebackRegistry, ProtocolFamily};
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Direction, DisconnectCause, Plugin, StreamTransactionSummary, TransactionSummary,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

fn make_summary(
    proxy_id: &str,
    proxy_name: &str,
    consumer: Option<&str>,
    status: u16,
) -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: "2025-01-01T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: consumer.map(|c| c.to_string()),
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/test".to_string(),
        proxy_id: Some(proxy_id.to_string()),
        proxy_name: Some(proxy_name.to_string()),
        backend_target: Some("http://localhost:3000".to_string()),
        backend_resolved_ip: None,
        response_status_code: status,
        latency_total_ms: 50.0,
        latency_gateway_processing_ms: 5.0,
        latency_backend_ttfb_ms: 45.0,
        latency_backend_total_ms: 40.0,
        latency_plugin_execution_ms: 2.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 3.0,
        request_user_agent: Some("test-agent".to_string()),
        response_streamed: false,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: false,
        bytes_sent: 0,
        bytes_received: 0,
        mirror: false,
        metadata: HashMap::new(),
    }
}

fn make_summary_with_bytes(
    proxy_id: &str,
    proxy_name: &str,
    consumer: Option<&str>,
    status: u16,
    bytes_sent: u64,
    bytes_received: u64,
) -> TransactionSummary {
    let mut summary = make_summary(proxy_id, proxy_name, consumer, status);
    summary.bytes_sent = bytes_sent;
    summary.bytes_received = bytes_received;
    summary
}

fn make_stream_summary(
    proxy_id: &str,
    proxy_name: &str,
    consumer: Option<&str>,
    protocol: &str,
    bytes_sent: u64,
    bytes_received: u64,
) -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: proxy_id.to_string(),
        proxy_name: Some(proxy_name.to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: consumer.map(|c| c.to_string()),
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: protocol.to_string(),
        listen_port: 5000,
        duration_ms: 1234.0,
        bytes_sent,
        bytes_received,
        connection_error: None,
        error_class: None,
        disconnect_direction: Some(Direction::ClientToBackend),
        disconnect_cause: Some(DisconnectCause::GracefulShutdown),
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

/// Build the same key format used by the registry internally.
fn make_key(consumer: &str, proxy_id: &str, status_code: u16) -> String {
    format!("{}|{}|{}", consumer, proxy_id, status_code)
}

// --- Plugin config validation tests ---

#[test]
fn test_valid_config() {
    let config = json!({
        "currency": "EUR",
        "pricing_tiers": [
            {
                "status_codes": [200, 201],
                "price_per_call": 0.00001
            }
        ]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    assert_eq!(plugin.name(), "api_chargeback");
    assert_eq!(plugin.priority(), 9350);
    // Now supports all protocols so it sees stream summaries via on_stream_disconnect.
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[test]
fn test_invalid_config_shapes_rejected() {
    let cases = [
        json!(null),
        json!({"currency": 100, "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"currency": "  ", "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"render_cache_ttl_seconds": "5", "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"stale_entry_ttl_seconds": false, "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"cache_invalidation_min_age_ms": [], "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"cleanup_interval_seconds": "300", "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.001}]}),
        json!({"pricing_tiers": [42]}),
    ];

    for config in cases {
        assert!(
            ApiChargeback::new(&config, "ferrum").is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[test]
fn test_missing_all_pricing_blocks_rejected() {
    // No pricing_tiers, no bandwidth_pricing, no stream_connection_pricing.
    let config = json!({ "currency": "USD" });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("at least one"));
}

#[test]
fn test_empty_pricing_tiers() {
    let config = json!({ "pricing_tiers": [] });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("at least one"));
}

#[test]
fn test_missing_status_codes_in_tier() {
    let config = json!({
        "pricing_tiers": [{ "price_per_call": 0.001 }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("status_codes"));
}

#[test]
fn test_missing_price_in_tier() {
    let config = json!({
        "pricing_tiers": [{ "status_codes": [200] }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("price_per_call"));
}

#[test]
fn test_negative_price_rejected() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": -0.001
        }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("non-negative"));
}

#[test]
fn test_extreme_tunables_do_not_overflow() {
    let config = json!({
        "render_cache_ttl_seconds": u64::MAX,
        "stale_entry_ttl_seconds": u64::MAX,
        "cache_invalidation_min_age_ms": u64::MAX,
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": 0.001
        }]
    });

    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    assert_eq!(plugin.name(), "api_chargeback");
}

#[test]
fn test_duplicate_status_code_across_tiers() {
    let config = json!({
        "pricing_tiers": [
            { "status_codes": [200], "price_per_call": 0.001 },
            { "status_codes": [200, 201], "price_per_call": 0.002 }
        ]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("200"));
    assert!(err.contains("multiple pricing tiers"));
}

#[test]
fn test_empty_status_codes_in_tier() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [],
            "price_per_call": 0.001
        }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_status_code_out_of_range() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [70000],
            "price_per_call": 0.001
        }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("invalid HTTP status code"));
}

#[test]
fn test_status_code_below_100_rejected() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [99],
            "price_per_call": 0.001
        }]
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("invalid HTTP status code"));
}

#[test]
fn test_default_currency_is_usd() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": 0.00001
        }]
    });
    // Plugin creation succeeds with default currency
    ApiChargeback::new(&config, "ferrum").unwrap();
}

// --- Bandwidth / stream config validation ---

#[tokio::test]
async fn test_bandwidth_only_config_records_bytes() {
    let config = json!({
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.0000001,
            "price_per_byte_received": 0.0000002
        }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    let summary = make_summary_with_bytes(
        "bw-only-proxy",
        "API",
        Some("bw-only-user"),
        404,
        1_000_000,
        2_000_000,
    );
    plugin.log(&summary).await;
    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let entry = registry
        .entries
        .get(&make_key("bw-only-user", "bw-only-proxy", 404))
        .expect("bandwidth-only entry recorded");
    let charge_sent = f64::from_bits(entry.bandwidth_charge_sent_bits.load(Ordering::Relaxed));
    let charge_recv = f64::from_bits(entry.bandwidth_charge_received_bits.load(Ordering::Relaxed));
    assert!((charge_sent - 0.1).abs() < 1e-10);
    assert!((charge_recv - 0.4).abs() < 1e-10);
}

#[tokio::test]
async fn test_stream_only_config_charges_connection() {
    let config = json!({
        "stream_connection_pricing": { "price_per_connection": 0.0005 }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    let summary = make_stream_summary(
        "stream-only-proxy",
        "TCP API",
        Some("stream-only-user"),
        "tcp",
        0,
        0,
    );
    plugin.on_stream_disconnect(&summary).await;
    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let entry = registry
        .entries
        .get(&make_key("stream-only-user", "stream-only-proxy", 0))
        .expect("stream-only entry recorded");
    assert_eq!(entry.protocol_family, ProtocolFamily::Stream);
    let charge = f64::from_bits(entry.charge_total_bits.load(Ordering::Relaxed));
    assert!((charge - 0.0005).abs() < 1e-12);
}

#[test]
fn test_bandwidth_pricing_rejects_unknown_key() {
    let config = json!({
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.001,
            "unexpected": true
        }
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("unknown key"));
}

#[test]
fn test_bandwidth_pricing_rejects_negative() {
    let config = json!({
        "bandwidth_pricing": { "price_per_byte_sent": -0.001 }
    });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("non-negative"));
}

#[test]
fn test_stream_connection_pricing_requires_price() {
    let config = json!({ "stream_connection_pricing": {} });
    let err = ApiChargeback::new(&config, "ferrum").err().unwrap();
    assert!(err.contains("price_per_connection"));
}

#[tokio::test]
async fn test_combined_pricing_applies_both_call_and_bandwidth_charges() {
    let config = json!({
        "currency": "USD",
        "pricing_tiers": [
            { "status_codes": [200], "price_per_call": 0.001 }
        ],
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.000001,
            "price_per_byte_received": 0.000002
        },
        "stream_connection_pricing": { "price_per_connection": 0.0005 }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    let summary = make_summary_with_bytes(
        "combined-proxy",
        "API",
        Some("combined-user"),
        200,
        1_000,
        2_000,
    );
    plugin.log(&summary).await;
    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let entry = registry
        .entries
        .get(&make_key("combined-user", "combined-proxy", 200))
        .expect("combined entry recorded");
    let call_charge = f64::from_bits(entry.charge_total_bits.load(Ordering::Relaxed));
    let bw_sent = f64::from_bits(entry.bandwidth_charge_sent_bits.load(Ordering::Relaxed));
    let bw_recv = f64::from_bits(entry.bandwidth_charge_received_bits.load(Ordering::Relaxed));
    assert!((call_charge - 0.001).abs() < 1e-12);
    assert!((bw_sent - 0.001).abs() < 1e-12); // 1_000 * 0.000001
    assert!((bw_recv - 0.004).abs() < 1e-12); // 2_000 * 0.000002
}

// --- Registry tests ---

#[test]
fn test_registry_records_charge() {
    let registry = ChargebackRegistry::new();
    registry.record_http("user-1", "proxy-a", "My API", 200, 0.00001, 0, 0, 0.0, 0.0);

    let key = make_key("user-1", "proxy-a", 200);
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 1);
    let charge = f64::from_bits(entry.charge_total_bits.load(Ordering::Relaxed));
    assert!((charge - 0.00001).abs() < 1e-15);
    // Verify render metadata is stored correctly
    assert_eq!(&*entry.consumer, "user-1");
    assert_eq!(&*entry.proxy_id, "proxy-a");
    assert_eq!(&*entry.proxy_name, "My API");
    assert_eq!(entry.status_code, 200);
    assert_eq!(entry.protocol_family, ProtocolFamily::Http);
}

#[test]
fn test_registry_accumulates_charges() {
    let registry = ChargebackRegistry::new();
    for _ in 0..1000 {
        registry.record_http("user-1", "proxy-a", "My API", 200, 0.00001, 0, 0, 0.0, 0.0);
    }

    let key = make_key("user-1", "proxy-a", 200);
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 1000);
    let charge = f64::from_bits(entry.charge_total_bits.load(Ordering::Relaxed));
    assert!((charge - 0.01).abs() < 1e-10);
}

#[test]
fn test_registry_zero_alloc_hot_path() {
    let registry = ChargebackRegistry::new();
    registry.record_http("user-1", "proxy-a", "API", 200, 0.001, 0, 0, 0.0, 0.0);
    registry.record_http("user-1", "proxy-a", "API", 200, 0.001, 0, 0, 0.0, 0.0);
    registry.record_http("user-1", "proxy-a", "API", 200, 0.001, 0, 0, 0.0, 0.0);

    assert_eq!(registry.entries.len(), 1);
    let key = make_key("user-1", "proxy-a", 200);
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 3);
}

#[test]
fn test_registry_separates_by_consumer() {
    let registry = ChargebackRegistry::new();
    registry.record_http("user-1", "proxy-a", "API", 200, 0.001, 0, 0, 0.0, 0.0);
    registry.record_http("user-2", "proxy-a", "API", 200, 0.002, 0, 0, 0.0, 0.0);

    assert_eq!(registry.entries.len(), 2);
}

#[test]
fn test_registry_separates_by_status_code() {
    let registry = ChargebackRegistry::new();
    registry.record_http("user-1", "proxy-a", "API", 200, 0.001, 0, 0, 0.0, 0.0);
    registry.record_http("user-1", "proxy-a", "API", 201, 0.002, 0, 0, 0.0, 0.0);

    assert_eq!(registry.entries.len(), 2);
}

#[test]
fn test_registry_stale_eviction() {
    let registry = ChargebackRegistry::new();
    registry.record_http("user-1", "proxy-a", "API", 200, 0.001, 0, 0, 0.0, 0.0);

    // Evict with zero TTL should remove everything
    let evicted = registry.evict_stale(0);
    assert_eq!(evicted, 1);
    assert!(registry.entries.is_empty());
}

#[test]
fn test_registry_records_bandwidth_for_http() {
    let registry = ChargebackRegistry::new();
    registry.record_http(
        "alice", "proxy-1", "API", 200, 0.0, 1_000_000, 2_000_000, 0.0000001, 0.0000002,
    );

    let key = make_key("alice", "proxy-1", 200);
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.bytes_sent_total.load(Ordering::Relaxed), 1_000_000);
    assert_eq!(
        entry.bytes_received_total.load(Ordering::Relaxed),
        2_000_000
    );
    let bw_sent = f64::from_bits(entry.bandwidth_charge_sent_bits.load(Ordering::Relaxed));
    let bw_recv = f64::from_bits(entry.bandwidth_charge_received_bits.load(Ordering::Relaxed));
    assert!((bw_sent - 0.1).abs() < 1e-10);
    assert!((bw_recv - 0.4).abs() < 1e-10);
}

#[test]
fn test_registry_records_stream_session() {
    let registry = ChargebackRegistry::new();
    registry.record_stream(
        "alice",
        "stream-proxy",
        "TCP Edge",
        0.0005,
        500_000,
        750_000,
        0.0000001,
        0.0000002,
    );

    let key = make_key("alice", "stream-proxy", 0);
    let entry = registry.entries.get(&key).unwrap();
    assert_eq!(entry.protocol_family, ProtocolFamily::Stream);
    assert_eq!(entry.status_code, 0);
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 1);
    let connection_charge = f64::from_bits(entry.charge_total_bits.load(Ordering::Relaxed));
    assert!((connection_charge - 0.0005).abs() < 1e-12);
    assert_eq!(entry.bytes_sent_total.load(Ordering::Relaxed), 500_000);
    assert_eq!(entry.bytes_received_total.load(Ordering::Relaxed), 750_000);
}

#[test]
fn test_registry_does_not_charge_bandwidth_when_price_zero() {
    // Bytes flow but no bandwidth pricing configured -> bytes accumulate,
    // bandwidth charges stay at zero.
    let registry = ChargebackRegistry::new();
    registry.record_http("alice", "proxy", "API", 200, 0.0, 1_000, 2_000, 0.0, 0.0);
    let entry = registry
        .entries
        .get(&make_key("alice", "proxy", 200))
        .unwrap();
    assert_eq!(entry.bytes_sent_total.load(Ordering::Relaxed), 1_000);
    assert_eq!(entry.bytes_received_total.load(Ordering::Relaxed), 2_000);
    assert_eq!(
        f64::from_bits(entry.bandwidth_charge_sent_bits.load(Ordering::Relaxed)),
        0.0
    );
    assert_eq!(
        f64::from_bits(entry.bandwidth_charge_received_bits.load(Ordering::Relaxed)),
        0.0
    );
}

// --- Prometheus render tests ---

#[test]
fn test_prometheus_render_empty() {
    let registry = ChargebackRegistry::new();
    let output = registry.render_prometheus_uncached();
    assert!(output.contains("ferrum_api_chargeable_calls_total"));
    assert!(output.contains("ferrum_api_charges_total"));
    assert!(output.contains("ferrum_api_stream_connections_total"));
    assert!(output.contains("ferrum_api_bytes_sent_total"));
    assert!(output.contains("ferrum_api_bytes_received_total"));
    assert!(output.contains("ferrum_api_bandwidth_charges_total"));
}

#[test]
fn test_prometheus_render_with_data() {
    let registry = ChargebackRegistry::new();
    registry.configure("USD", 5, 3600, 500, "ferrum");
    registry.record_http(
        "alice",
        "proxy-1",
        "Payments API",
        200,
        0.00001,
        0,
        0,
        0.0,
        0.0,
    );
    registry.record_http(
        "alice",
        "proxy-1",
        "Payments API",
        200,
        0.00001,
        0,
        0,
        0.0,
        0.0,
    );

    let output = registry.render_prometheus_uncached();
    assert!(output.contains("consumer=\"alice\""));
    assert!(output.contains("proxy_id=\"proxy-1\""));
    assert!(output.contains("proxy_name=\"Payments API\""));
    assert!(output.contains("status_code=\"200\""));
    // Should have 2 calls on the chargeable_calls_total line
    assert!(output.contains("ferrum_api_chargeable_calls_total{") && output.contains("} 2\n"));
    // Currency label on per-call charges
    assert!(output.contains("currency=\"USD\""));
}

#[test]
fn test_prometheus_render_emits_stream_metrics() {
    let registry = ChargebackRegistry::new();
    registry.configure("USD", 5, 3600, 500, "ferrum");
    registry.record_stream(
        "bob", "tcp-edge", "TCP Edge", 0.0, 1_024, 2_048, 0.000001, 0.000002,
    );

    let output = registry.render_prometheus_uncached();
    assert!(output.contains("ferrum_api_stream_connections_total{consumer=\"bob\""));
    assert!(output.contains("protocol_family=\"stream\""));
    // Stream entry must NOT emit ferrum_api_chargeable_calls_total rows (those are HTTP-only).
    assert!(!output.contains("ferrum_api_chargeable_calls_total{consumer=\"bob\""));
}

#[test]
fn test_prometheus_render_bandwidth_aggregates_across_status_codes() {
    let registry = ChargebackRegistry::new();
    registry.configure("USD", 5, 3600, 500, "ferrum");
    registry.record_http(
        "charlie", "proxy-x", "API", 200, 0.0, 1_000, 10_000, 0.0000001, 0.0000002,
    );
    registry.record_http(
        "charlie", "proxy-x", "API", 500, 0.0, 500, 5_000, 0.0000001, 0.0000002,
    );

    let output = registry.render_prometheus_uncached();
    // One bytes_sent line per (consumer, proxy, family) — aggregated to 1500.
    let sent_count = output
        .lines()
        .filter(|l| {
            l.starts_with("ferrum_api_bytes_sent_total{") && l.contains("consumer=\"charlie\"")
        })
        .count();
    assert_eq!(sent_count, 1, "expected one aggregated bytes_sent row");
    assert!(output.contains("ferrum_api_bytes_sent_total{") && output.contains(" 1500\n"));
    assert!(output.contains("ferrum_api_bytes_received_total{") && output.contains(" 15000\n"));
}

// --- JSON render tests ---

#[test]
fn test_json_render_empty() {
    let registry = ChargebackRegistry::new();
    let output = registry.render_json_uncached();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(parsed["consumers"].as_object().unwrap().is_empty());
    assert_eq!(parsed["currency"], "USD");
}

#[test]
fn test_json_render_with_data() {
    let registry = ChargebackRegistry::new();
    registry.configure("EUR", 5, 3600, 500, "ferrum");

    for _ in 0..100 {
        registry.record_http("bob", "proxy-2", "Orders API", 200, 0.00001, 0, 0, 0.0, 0.0);
    }
    registry.record_http("bob", "proxy-2", "Orders API", 201, 0.00002, 0, 0, 0.0, 0.0);

    let output = registry.render_json_uncached();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(parsed["currency"], "EUR");

    let bob = &parsed["consumers"]["bob"];
    assert_eq!(bob["total_calls"], 101);

    let proxy = &bob["proxies"]["proxy-2"];
    assert_eq!(proxy["proxy_name"], "Orders API");
    assert_eq!(proxy["total_calls"], 101);
    assert_eq!(proxy["protocol_family"], "http");

    let status_200 = &proxy["by_status"]["200"];
    assert_eq!(status_200["calls"], 100);
}

#[test]
fn test_json_render_includes_bandwidth() {
    let registry = ChargebackRegistry::new();
    registry.configure("USD", 5, 3600, 500, "ferrum");
    registry.record_http(
        "alice", "proxy-1", "API", 200, 0.001, 1_000, 4_000, 0.0000001, 0.0000002,
    );

    let output = registry.render_json_uncached();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    let bandwidth = &parsed["consumers"]["alice"]["proxies"]["proxy-1"]["bandwidth"];
    assert_eq!(bandwidth["bytes_sent"], 1_000);
    assert_eq!(bandwidth["bytes_received"], 4_000);
}

#[test]
fn test_json_render_includes_stream_section() {
    let registry = ChargebackRegistry::new();
    registry.configure("USD", 5, 3600, 500, "ferrum");
    registry.record_stream(
        "alice", "tcp-1", "TCP API", 0.0005, 2_048, 8_192, 0.0000001, 0.0000002,
    );

    let output = registry.render_json_uncached();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    let proxy = &parsed["consumers"]["alice"]["proxies"]["tcp-1"];
    assert_eq!(proxy["protocol_family"], "stream");
    assert_eq!(proxy["stream"]["connections"], 1);
    let connection_charges = proxy["stream"]["connection_charges"].as_f64().unwrap();
    assert!((connection_charges - 0.0005).abs() < 1e-12);
}

// --- Plugin log hook tests ---

#[tokio::test]
async fn test_log_charges_identified_consumer() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": 0.001
        }]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    let summary = make_summary("proxy-1", "Test API", Some("alice"), 200);

    plugin.log(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key("alice", "proxy-1", 200);
    assert!(registry.entries.contains_key(&key));
}

#[tokio::test]
async fn test_log_skips_anonymous_traffic() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": 0.001
        }]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    // No consumer
    let summary = make_summary("proxy-1", "Test API", None, 200);
    plugin.log(&summary).await;

    // Empty consumer
    let summary2 = make_summary("proxy-1", "Test API", Some(""), 200);
    plugin.log(&summary2).await;

    // No crash, no charge recorded for anonymous traffic
}

#[tokio::test]
async fn test_log_skips_uncharged_status_codes() {
    let config = json!({
        "pricing_tiers": [{
            "status_codes": [200],
            "price_per_call": 0.001
        }]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    // 404 is not in the pricing tiers
    let summary = make_summary("proxy-uncharged", "Test API", Some("charlie"), 404);
    plugin.log(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key("charlie", "proxy-uncharged", 404);
    assert!(!registry.entries.contains_key(&key));
}

#[tokio::test]
async fn test_log_records_bandwidth_even_when_status_is_uncharged() {
    // No status tier configured for this code, but bandwidth pricing applies →
    // we still want bandwidth bytes recorded so operators see usage data.
    let config = json!({
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.001 }],
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.0000001,
            "price_per_byte_received": 0.0000002
        }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    let summary = make_summary_with_bytes("proxy-bw", "API", Some("derek"), 404, 1_024, 4_096);
    plugin.log(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key("derek", "proxy-bw", 404);
    let entry = registry
        .entries
        .get(&key)
        .expect("bandwidth entry recorded");
    // 404 has no per-call price, so charge_total_bits stays at zero.
    let call_charge = f64::from_bits(entry.charge_total_bits.load(Ordering::Relaxed));
    assert!(call_charge.abs() < 1e-15);
    assert_eq!(entry.bytes_sent_total.load(Ordering::Relaxed), 1_024);
    assert_eq!(entry.bytes_received_total.load(Ordering::Relaxed), 4_096);
}

#[tokio::test]
async fn test_on_stream_disconnect_records_bandwidth() {
    let config = json!({
        "bandwidth_pricing": {
            "price_per_byte_sent": 0.0000001,
            "price_per_byte_received": 0.0000002
        },
        "stream_connection_pricing": { "price_per_connection": 0.001 }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    let summary = make_stream_summary(
        "tcp-edge-stream-test",
        "TCP Edge",
        Some("emma"),
        "tcp",
        10_000,
        20_000,
    );
    plugin.on_stream_disconnect(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key("emma", "tcp-edge-stream-test", 0);
    let entry = registry.entries.get(&key).expect("stream entry recorded");
    assert_eq!(entry.protocol_family, ProtocolFamily::Stream);
    assert_eq!(entry.call_count.load(Ordering::Relaxed), 1);
    let connection_charge = f64::from_bits(entry.charge_total_bits.load(Ordering::Relaxed));
    assert!((connection_charge - 0.001).abs() < 1e-12);
    assert_eq!(entry.bytes_sent_total.load(Ordering::Relaxed), 10_000);
    assert_eq!(entry.bytes_received_total.load(Ordering::Relaxed), 20_000);
}

#[tokio::test]
async fn test_on_stream_disconnect_skips_anonymous() {
    let config = json!({
        "stream_connection_pricing": { "price_per_connection": 0.001 }
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    let summary = make_stream_summary("anon-stream-test", "TCP API", None, "tcp", 10_000, 20_000);
    plugin.on_stream_disconnect(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    assert!(
        !registry
            .entries
            .iter()
            .any(|e| &*e.value().proxy_id == "anon-stream-test")
    );
}

#[tokio::test]
async fn test_on_stream_disconnect_skips_when_only_per_call_pricing_set() {
    // Only HTTP per-call pricing configured. Stream disconnects must not
    // create stub entries — otherwise every TCP/UDP session would show up in
    // /charges output with zero charges, polluting billing pipelines.
    let config = json!({
        "pricing_tiers": [{ "status_codes": [200], "price_per_call": 0.001 }]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();

    let summary = make_stream_summary(
        "http-only-stream-test",
        "TCP API",
        Some("frank"),
        "tcp",
        10_000,
        20_000,
    );
    plugin.on_stream_disconnect(&summary).await;

    let registry = ferrum_edge::plugins::api_chargeback::global_registry();
    let key = make_key("frank", "http-only-stream-test", 0);
    assert!(!registry.entries.contains_key(&key));
}

#[test]
fn test_multiple_pricing_tiers() {
    let config = json!({
        "pricing_tiers": [
            { "status_codes": [200, 201], "price_per_call": 0.00001 },
            { "status_codes": [301, 302], "price_per_call": 0.000005 }
        ]
    });
    let plugin = ApiChargeback::new(&config, "ferrum").unwrap();
    assert_eq!(plugin.name(), "api_chargeback");
}

#[test]
fn test_prometheus_render_namespace_present_for_default() {
    let registry = ChargebackRegistry::new();
    registry.configure("USD", 5, 3600, 500, "ferrum");
    registry.record_http("alice", "proxy-1", "API", 200, 0.001, 0, 0, 0.0, 0.0);

    let output = registry.render_prometheus_uncached();
    assert!(output.contains(r#"namespace="ferrum""#));
    assert!(output.contains("consumer=\"alice\""));
}

#[test]
fn test_prometheus_render_namespace_present_for_non_default() {
    let registry = ChargebackRegistry::new();
    registry.configure("USD", 5, 3600, 500, "staging");
    registry.record_http("bob", "proxy-2", "API", 200, 0.001, 0, 0, 0.0, 0.0);

    let output = registry.render_prometheus_uncached();
    assert!(output.contains(r#"namespace="staging""#));
    assert!(output.contains("consumer=\"bob\""));
}
