//! Tests for stdout_logging plugin

use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, StreamTransactionSummary, stdout_logging::StdoutLogging,
};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{create_test_context, create_test_transaction_summary};

#[tokio::test]
async fn test_stdout_logging_plugin_creation() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config).unwrap();
    assert_eq!(plugin.name(), "stdout_logging");
    assert_eq!(plugin.priority(), 9000);
    assert_eq!(
        plugin.supported_protocols(),
        &[
            ProxyProtocol::Http,
            ProxyProtocol::Grpc,
            ProxyProtocol::WebSocket,
            ProxyProtocol::Tcp,
            ProxyProtocol::Udp,
        ]
    );
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_stdout_logging_plugin_lifecycle() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config).unwrap();
    let mut ctx = create_test_context();

    // Test all lifecycle phases
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_stdout_logging_plugin_logging() {
    let config = json!({});
    let plugin = StdoutLogging::new(&config).unwrap();

    let summary = create_test_transaction_summary();

    // Should not panic when logging
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_stdout_logging_plugin_with_config() {
    let config = json!({
        "log_level": "info",
        "include_metadata": true
    });
    let plugin = StdoutLogging::new(&config).unwrap();
    assert_eq!(plugin.name(), "stdout_logging");

    let mut ctx = create_test_context();
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[test]
fn test_stdout_logging_accepts_null_config_as_defaults() {
    let plugin =
        StdoutLogging::new(&serde_json::Value::Null).expect("null config should use defaults");
    assert_eq!(plugin.name(), "stdout_logging");
    assert_eq!(plugin.priority(), 9000);
}

#[test]
fn test_stdout_logging_rejects_non_object_config() {
    let err = StdoutLogging::new(&json!("bad")).err().unwrap();
    assert!(err.contains("config must be an object"), "got: {err}");
}

#[tokio::test]
async fn test_stdout_logging_stream_disconnect() {
    let plugin = StdoutLogging::new(&json!({})).unwrap();
    let summary = StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy-1".to_string(),
        proxy_name: Some("TCP Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 8080,
        duration_ms: 15.0,
        bytes_sent: 128,
        bytes_received: 256,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    };

    plugin.on_stream_disconnect(&summary).await;
}
