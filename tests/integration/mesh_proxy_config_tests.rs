//! Integration tests for Istio `ProxyConfig` CRD translation.
//!
//! These exercise the end-to-end slice → injected `workload_metrics` plugin
//! flow: a `MeshProxyConfig` with `tracing_sampling=N` must surface as
//! `sampling_percentage: N` in the injected `__mesh_workload_metrics` plugin
//! config when `prepare_gateway_config_for_mesh` runs.

use chrono::Utc;
use std::collections::HashMap;
use std::net::SocketAddr;

use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::modes::mesh::config::{MeshConfig, MeshProxyConfig};
use ferrum_edge::modes::mesh::{
    MESH_WORKLOAD_METRICS_PLUGIN_ID, MeshConfigProtocol, MeshRuntimeConfig, MeshTopology,
    prepare_gateway_config_for_mesh,
};

fn test_addr(s: &str) -> SocketAddr {
    s.parse().expect("valid socket address")
}

fn test_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: test_addr("127.0.0.1:15006"),
        outbound_listen_addr: test_addr("127.0.0.1:15001"),
        hbone_listen_addr: test_addr("127.0.0.1:15008"),
        east_west_listen_port: 15443,
        egress_listen_addr: test_addr("0.0.0.0:15090"),
        workload_spiffe_id: None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        // Workload labels — must match the ProxyConfig selector below to
        // trigger workload-scoped resolution.
        workload_labels: HashMap::from([("app".to_string(), "api".to_string())]),
        dns_enabled: false,
        dns_listen_addr: test_addr("127.0.0.1:15053"),
        dns_upstream_addr: test_addr("127.0.0.53:53"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: CaptureMode::Explicit,
    }
}

#[test]
fn proxy_config_tracing_sampling_flows_into_workload_metrics_plugin() {
    // A ProxyConfig with tracing.sampling=42 must surface as
    // sampling_percentage: 42 in the injected workload_metrics plugin.
    let mesh = MeshConfig {
        proxy_configs: vec![MeshProxyConfig {
            name: "api-defaults".to_string(),
            namespace: "default".to_string(),
            selector_labels: HashMap::from([("app".to_string(), "api".to_string())]),
            concurrency: Some(4),
            image: Some("distroless".to_string()),
            environment: HashMap::from([("GOMAXPROCS".to_string(), "4".to_string())]),
            tracing_sampling: Some(42.0),
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let runtime = test_runtime();

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let metrics_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics plugin injected");

    let sampling = metrics_plugin
        .config
        .get("sampling_percentage")
        .and_then(|v| v.as_f64())
        .expect("sampling_percentage populated from ProxyConfig");
    assert_eq!(sampling, 42.0);
}

#[test]
fn proxy_config_does_not_set_sampling_when_unset() {
    // A ProxyConfig with no tracing.sampling must not populate
    // sampling_percentage — the workload_metrics plugin defaults to 100.0
    // when unset.
    let mesh = MeshConfig {
        proxy_configs: vec![MeshProxyConfig {
            name: "api-defaults".to_string(),
            namespace: "default".to_string(),
            selector_labels: HashMap::from([("app".to_string(), "api".to_string())]),
            concurrency: Some(4),
            image: None,
            environment: HashMap::new(),
            tracing_sampling: None,
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let runtime = test_runtime();

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let metrics_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics plugin injected");

    assert!(
        metrics_plugin.config.get("sampling_percentage").is_none(),
        "no sampling_percentage should be set when ProxyConfig.tracing_sampling is None"
    );
}

#[test]
fn proxy_config_non_matching_selector_does_not_apply() {
    // A ProxyConfig whose selector does not match the workload's labels
    // should be filtered out at slice construction time and have no
    // impact on the injected plugin.
    let mesh = MeshConfig {
        proxy_configs: vec![MeshProxyConfig {
            name: "worker-defaults".to_string(),
            namespace: "default".to_string(),
            // Workload has `app=api` (see `test_runtime`), but this selector
            // requires `app=worker`.
            selector_labels: HashMap::from([("app".to_string(), "worker".to_string())]),
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling: Some(75.0),
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let runtime = test_runtime();

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let metrics_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics plugin injected");

    assert!(
        metrics_plugin.config.get("sampling_percentage").is_none(),
        "non-matching ProxyConfig must not contribute sampling"
    );
}
