use ferrum_edge::config::mesh::{
    MeshConfig, MeshPolicy, MeshRule, MtlsMode, PeerAuthentication, PolicyAction, PolicyScope,
    PrincipalMatch,
};
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::config::{EnvConfig, MeshConfigSource, MeshTopology};
use ferrum_edge::modes::mesh::hbone::{
    HBONE_DEFAULT_PORT, extract_source_identity_from_baggage, is_hbone_connect,
};
use ferrum_edge::modes::mesh::runtime::{
    MESH_ACCESS_LOG_PLUGIN_ID, MESH_AUTHZ_PLUGIN_ID, MESH_SPIFFE_IDENTITY_PLUGIN_ID,
    MESH_WORKLOAD_METRICS_PLUGIN_ID, MeshListenerKind, MeshRuntimeConfig, MeshTrafficDirection,
    prepare_gateway_config_for_mesh,
};
use std::time::Duration;

#[test]
fn hbone_baggage_extracts_percent_encoded_source_identity() {
    let id = extract_source_identity_from_baggage(
        "trace=abc,source.principal=spiffe%3A%2F%2Fcluster.local%2Fns%2Fdefault%2Fsa%2Fclient",
    )
    .unwrap()
    .unwrap();

    assert_eq!(id.as_str(), "spiffe://cluster.local/ns/default/sa/client");
    assert!(is_hbone_connect("connect"));
}

#[test]
fn mesh_runtime_listener_plan_uses_istio_hbone_port_by_default() {
    let env = EnvConfig {
        mode: ferrum_edge::config::OperatingMode::Mesh,
        file_config_path: Some("/tmp/ferrum.yaml".to_string()),
        ..EnvConfig::default()
    };
    let runtime = MeshRuntimeConfig::from_env(&env);
    let plan = runtime.listener_plan();

    assert_eq!(runtime.topology, MeshTopology::Sidecar);
    assert_eq!(runtime.config_source, MeshConfigSource::File);
    assert!(plan.iter().any(|listener| {
        listener.direction == MeshTrafficDirection::Outbound
            && listener.kind == MeshListenerKind::PlaintextCapture
            && listener.addr.port() == 15001
    }));
    assert!(plan.iter().any(|listener| {
        listener.direction == MeshTrafficDirection::Inbound
            && listener.kind == MeshListenerKind::MtlsTermination
            && listener.addr.port() == 15006
    }));
    assert!(plan.iter().any(|listener| {
        listener.direction == MeshTrafficDirection::Hbone
            && listener.kind == MeshListenerKind::HboneTunnel
            && listener.addr.port() == HBONE_DEFAULT_PORT
    }));
}

#[test]
fn mesh_runtime_prepares_global_mesh_plugins() {
    let env = EnvConfig {
        mode: ferrum_edge::config::OperatingMode::Mesh,
        file_config_path: Some("/tmp/ferrum.yaml".to_string()),
        namespace: "payments".to_string(),
        ..EnvConfig::default()
    };
    let runtime = MeshRuntimeConfig::from_env(&env);
    let policy = MeshPolicy {
        name: "allow-clients".to_string(),
        namespace: "payments".to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/*/sa/client".to_string()),
                namespace_pattern: None,
                trust_domain: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            action: PolicyAction::Allow,
        }],
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            mesh_policies: vec![policy],
            peer_authentications: vec![PeerAuthentication {
                name: "default-strict".to_string(),
                namespace: "payments".to_string(),
                selector: None,
                mtls_mode: MtlsMode::Strict,
                port_overrides: Default::default(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };

    let prepared = prepare_gateway_config_for_mesh(config, &runtime).unwrap();
    let by_id = |id: &str| {
        prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == id)
            .expect("mesh plugin injected")
    };

    assert_eq!(
        by_id(MESH_SPIFFE_IDENTITY_PLUGIN_ID).plugin_name,
        "spiffe_identity"
    );
    assert_eq!(by_id(MESH_AUTHZ_PLUGIN_ID).plugin_name, "mesh_authz");
    assert_eq!(
        by_id(MESH_WORKLOAD_METRICS_PLUGIN_ID).plugin_name,
        "workload_metrics"
    );
    assert_eq!(by_id(MESH_ACCESS_LOG_PLUGIN_ID).plugin_name, "access_log");
    assert!(
        prepared.plugin_configs.iter().all(|plugin| {
            plugin.scope == PluginScope::Global && plugin.namespace == "payments"
        })
    );

    let mesh_authz_policies = by_id(MESH_AUTHZ_PLUGIN_ID)
        .config
        .get("policies")
        .and_then(|policies| policies.as_array())
        .expect("mesh_authz policies array");
    assert_eq!(mesh_authz_policies.len(), 1);
    let peer_authentications = by_id(MESH_AUTHZ_PLUGIN_ID)
        .config
        .get("peer_authentications")
        .and_then(|peer_authentications| peer_authentications.as_array())
        .expect("mesh_authz peer_authentications array");
    assert_eq!(peer_authentications.len(), 1);
}

#[test]
fn mesh_runtime_preserves_operator_global_mesh_plugin_override() {
    let env = EnvConfig {
        mode: ferrum_edge::config::OperatingMode::Mesh,
        file_config_path: Some("/tmp/ferrum.yaml".to_string()),
        ..EnvConfig::default()
    };
    let runtime = MeshRuntimeConfig::from_env(&env);
    let existing = PluginConfig {
        id: "operator-mesh-authz".to_string(),
        plugin_name: "mesh_authz".to_string(),
        namespace: "ferrum".to_string(),
        config: serde_json::json!({ "policies": [] }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: Some(2005),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let config = GatewayConfig {
        plugin_configs: vec![existing],
        ..GatewayConfig::default()
    };

    let prepared = prepare_gateway_config_for_mesh(config, &runtime).unwrap();
    let mesh_authz: Vec<_> = prepared
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.plugin_name == "mesh_authz")
        .collect();

    assert_eq!(mesh_authz.len(), 1);
    assert_eq!(mesh_authz[0].id, "operator-mesh-authz");
    assert!(prepared.plugin_configs.iter().any(|plugin| {
        plugin.id == MESH_SPIFFE_IDENTITY_PLUGIN_ID && plugin.plugin_name == "spiffe_identity"
    }));
}

#[tokio::test]
async fn mesh_runtime_file_mode_starts_and_shuts_down_empty_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrum.yaml");
    std::fs::write(
        &config_path,
        r#"
version: "1"
proxies: []
consumers: []
plugin_configs: []
upstreams: []
"#,
    )
    .unwrap();

    let env = EnvConfig {
        mode: ferrum_edge::config::OperatingMode::Mesh,
        file_config_path: Some(config_path.to_string_lossy().into_owned()),
        mesh_bind_address: "127.0.0.1".to_string(),
        mesh_inbound_port: 0,
        mesh_outbound_port: 0,
        mesh_hbone_enabled: false,
        pool_warmup_enabled: false,
        accept_threads: 1,
        ..EnvConfig::default()
    };
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let shutdown = shutdown_tx.clone();
    let task = tokio::spawn(async move { ferrum_edge::modes::mesh::run(env, shutdown).await });

    tokio::time::sleep(Duration::from_millis(250)).await;
    let _ = shutdown_tx.send(true);

    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("mesh runtime shut down before timeout")
        .expect("mesh runtime task joined");
    assert!(result.is_ok(), "mesh runtime returned error: {result:?}");
}
