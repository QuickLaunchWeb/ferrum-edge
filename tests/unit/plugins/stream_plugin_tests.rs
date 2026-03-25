//! Tests for plugin protocol support declarations.
//!
//! Verifies that each plugin correctly declares which proxy protocols
//! it supports via the `supported_protocols()` trait method.

use ferrum_gateway::plugins::{
    ALL_PROTOCOLS, HTTP_FAMILY_PROTOCOLS, HTTP_GRPC_PROTOCOLS, HTTP_ONLY_PROTOCOLS, Plugin,
    ProxyProtocol, create_plugin,
};
use serde_json::json;
use std::sync::Arc;

/// Helper to create a plugin by name with minimal config.
fn make_plugin(name: &str, config: serde_json::Value) -> Option<Arc<dyn Plugin>> {
    create_plugin(name, &config).ok().flatten()
}

#[tokio::test]
async fn test_all_protocol_plugins() {
    // Plugins that support ALL protocols (protocol-agnostic)
    let plugins = vec![
        ("ip_restriction", json!({"allow": ["10.0.0.0/8"]})),
        ("rate_limiting", json!({"per_second": 100})),
        ("stdout_logging", json!({})),
        ("prometheus_metrics", json!({})),
        ("correlation_id", json!({})),
        (
            "otel_tracing",
            json!({"endpoint": "http://example.com/traces"}),
        ),
        (
            "http_logging",
            json!({"endpoint_url": "http://example.com/logs"}),
        ),
        ("transaction_debugger", json!({})),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert_eq!(
            protocols, ALL_PROTOCOLS,
            "Plugin {} should support all protocols, got {:?}",
            name, protocols
        );
    }
}

#[test]
fn test_http_family_plugins() {
    // Plugins that support HTTP, gRPC, and WebSocket
    let plugins = vec![
        ("key_auth", json!({})),
        ("basic_auth", json!({})),
        ("access_control", json!({"allowed_consumers": ["admin"]})),
        ("bot_detection", json!({})),
        ("request_termination", json!({"status_code": 503})),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert_eq!(
            protocols, HTTP_FAMILY_PROTOCOLS,
            "Plugin {} should support HTTP family protocols, got {:?}",
            name, protocols
        );
        // Verify it does NOT support TCP/UDP
        assert!(
            !protocols.contains(&ProxyProtocol::Tcp),
            "Plugin {} should not support TCP",
            name
        );
        assert!(
            !protocols.contains(&ProxyProtocol::Udp),
            "Plugin {} should not support UDP",
            name
        );
    }
}

#[test]
fn test_http_grpc_plugins() {
    // Plugins that support HTTP and gRPC only (modify headers/body)
    let plugins = vec![
        ("request_transformer", json!({})),
        ("response_transformer", json!({})),
        ("body_validator", json!({"schema": {}})),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert_eq!(
            protocols, HTTP_GRPC_PROTOCOLS,
            "Plugin {} should support HTTP+gRPC only, got {:?}",
            name, protocols
        );
        assert!(
            !protocols.contains(&ProxyProtocol::WebSocket),
            "Plugin {} should not support WebSocket",
            name
        );
    }
}

#[test]
fn test_http_only_plugins() {
    // Plugins that only support HTTP
    let plugins = vec![("cors", json!({"origins": ["*"]}))];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert_eq!(
            protocols, HTTP_ONLY_PROTOCOLS,
            "Plugin {} should support HTTP only, got {:?}",
            name, protocols
        );
    }
}

#[test]
fn test_stream_compatible_plugins_support_tcp_udp() {
    // Verify that stream-compatible plugins support both TCP and UDP
    let stream_plugins = vec![
        ("ip_restriction", json!({"allow": ["10.0.0.0/8"]})),
        ("rate_limiting", json!({"per_second": 100})),
        ("stdout_logging", json!({})),
        ("prometheus_metrics", json!({})),
        ("correlation_id", json!({})),
    ];

    for (name, config) in stream_plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert!(
            protocols.contains(&ProxyProtocol::Tcp),
            "Plugin {} should support TCP",
            name
        );
        assert!(
            protocols.contains(&ProxyProtocol::Udp),
            "Plugin {} should support UDP",
            name
        );
    }
}

#[tokio::test]
async fn test_ip_restriction_stream_connect_allowed() {
    use ferrum_gateway::config::types::BackendProtocol;
    use ferrum_gateway::plugins::{PluginResult, StreamConnectionContext};
    use std::collections::HashMap;

    let plugin = make_plugin(
        "ip_restriction",
        json!({"allow": ["10.0.0.0/8"], "mode": "allow_first"}),
    )
    .unwrap();

    let ctx = StreamConnectionContext {
        client_ip: "10.1.2.3".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: Some("Test Proxy".to_string()),
        listen_port: 5432,
        backend_protocol: BackendProtocol::Tcp,
        metadata: HashMap::new(),
    };

    let result = plugin.on_stream_connect(&ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_ip_restriction_stream_connect_denied() {
    use ferrum_gateway::config::types::BackendProtocol;
    use ferrum_gateway::plugins::{PluginResult, StreamConnectionContext};
    use std::collections::HashMap;

    let plugin = make_plugin(
        "ip_restriction",
        json!({"allow": ["10.0.0.0/8"], "mode": "allow_first"}),
    )
    .unwrap();

    let ctx = StreamConnectionContext {
        client_ip: "192.168.1.1".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: Some("Test Proxy".to_string()),
        listen_port: 5432,
        backend_protocol: BackendProtocol::Tcp,
        metadata: HashMap::new(),
    };

    let result = plugin.on_stream_connect(&ctx).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}
