use ferrum_edge::config::{EnvConfig, MeshConfigSource, MeshTopology};
use ferrum_edge::modes::mesh::hbone::{
    HBONE_DEFAULT_PORT, extract_source_identity_from_baggage, is_hbone_connect,
};
use ferrum_edge::modes::mesh::runtime::{
    MeshListenerKind, MeshRuntimeConfig, MeshTrafficDirection,
};

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
