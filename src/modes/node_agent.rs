//! Node agent mode — per-node eBPF capture manager for ambient mesh.
//!
//! `FERRUM_MODE=node_agent` runs as a DaemonSet companion alongside the
//! ambient mesh proxy. It attaches BPF programs to enrolled pods' cgroups
//! and veth interfaces to transparently redirect traffic to the co-located
//! Ferrum proxy.
//!
//! The node agent does NOT run proxy listeners. Traffic capture is its sole
//! responsibility.

use std::collections::HashSet;

use dashmap::DashMap;
use tracing::{error, info, warn};

use crate::capture::CaptureConfig;
use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::ebpf::kernel_probe::{self, KernelProbeResult};
use crate::ebpf::pod_watcher;
use crate::ebpf::{EbpfBackend, FallbackMode, PodAttachmentState};

const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
const DEFAULT_BPF_FS_PATH: &str = "/sys/fs/bpf";
const DEFAULT_FALLBACK_MODE: &str = "iptables";

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct NodeAgentConfig {
    pub node_name: String,
    pub capture_config: CaptureConfig,
    pub cgroup_root: String,
    pub bpf_fs_path: String,
    pub fallback_mode: FallbackMode,
    pub excluded_namespaces: HashSet<String>,
}

impl NodeAgentConfig {
    pub fn from_env_config(_env_config: &EnvConfig) -> Result<Self, String> {
        let node_name = resolve_ferrum_var("FERRUM_NODE_AGENT_NODE_NAME").ok_or(
            "FERRUM_NODE_AGENT_NODE_NAME is required in node_agent mode \
             (set via Kubernetes downward API: spec.nodeName)"
                .to_string(),
        )?;
        if node_name.trim().is_empty() {
            return Err("FERRUM_NODE_AGENT_NODE_NAME must not be empty".to_string());
        }

        let capture_config = CaptureConfig::from_env()?;
        let cgroup_root = resolve_ferrum_var("FERRUM_NODE_AGENT_CGROUP_ROOT")
            .unwrap_or_else(|| DEFAULT_CGROUP_ROOT.to_string());
        let bpf_fs_path = resolve_ferrum_var("FERRUM_NODE_AGENT_BPF_FS_PATH")
            .unwrap_or_else(|| DEFAULT_BPF_FS_PATH.to_string());
        let fallback_mode = FallbackMode::parse(
            &resolve_ferrum_var("FERRUM_NODE_AGENT_FALLBACK_MODE")
                .unwrap_or_else(|| DEFAULT_FALLBACK_MODE.to_string()),
        )?;

        let extra_excluded: Vec<String> =
            resolve_ferrum_var("FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES")
                .map(|raw| {
                    raw.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
        let excluded_namespaces = pod_watcher::build_excluded_namespaces(&extra_excluded);

        Ok(Self {
            node_name,
            capture_config,
            cgroup_root,
            bpf_fs_path,
            fallback_mode,
            excluded_namespaces,
        })
    }
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let config = NodeAgentConfig::from_env_config(&env_config).map_err(anyhow::Error::msg)?;

    info!(
        node_name = %config.node_name,
        capture_mode = ?config.capture_config.mode,
        cgroup_root = %config.cgroup_root,
        bpf_fs_path = %config.bpf_fs_path,
        fallback_mode = ?config.fallback_mode,
        "Starting node agent"
    );

    let probe = kernel_probe::probe_kernel(&config.cgroup_root, &config.bpf_fs_path);
    info!(
        kernel_release = %probe.kernel_release,
        meets_version = probe.meets_version_requirement,
        cgroup_v2 = probe.cgroup_v2_available,
        bpf_fs = probe.bpf_fs_available,
        "Kernel probe complete"
    );

    if !probe.supports_ebpf() {
        handle_fallback(&config, &probe)?;
        wait_for_shutdown(&shutdown_tx).await;
        info!("Node agent fallback mode shutting down");
        return Ok(());
    }

    run_with_backend(create_backend(), &config, &shutdown_tx).await
}

fn create_backend() -> Box<dyn EbpfBackend> {
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        Box::new(crate::ebpf::AyaEbpfBackend::new())
    }
    #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
    {
        info!("ebpf feature not enabled, using mock backend");
        Box::new(crate::ebpf::MockEbpfBackend::default())
    }
}

async fn run_with_backend(
    mut backend: Box<dyn EbpfBackend>,
    config: &NodeAgentConfig,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    initialize_backend(backend.as_mut(), config)?;

    let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();

    info!(
        "Node agent initialized, waiting for pod events on node {}",
        config.node_name
    );

    wait_for_shutdown(&shutdown_tx).await;

    info!("Node agent shutting down, detaching BPF programs");
    cleanup_all_pods(backend.as_mut(), &pod_states);

    Ok(())
}

async fn wait_for_shutdown(shutdown_tx: &tokio::sync::watch::Sender<bool>) {
    let mut shutdown_rx = shutdown_tx.subscribe();
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

fn handle_fallback(
    config: &NodeAgentConfig,
    probe: &KernelProbeResult,
) -> Result<(), anyhow::Error> {
    match config.fallback_mode {
        FallbackMode::Iptables => {
            warn!(
                kernel_release = %probe.kernel_release,
                meets_version = probe.meets_version_requirement,
                cgroup_v2 = probe.cgroup_v2_available,
                bpf_fs = probe.bpf_fs_available,
                "Kernel does not support eBPF capture, falling back to iptables mode"
            );
            info!("Node agent running in iptables fallback mode");
            Ok(())
        }
        FallbackMode::Fail => {
            error!(
                kernel_release = %probe.kernel_release,
                meets_version = probe.meets_version_requirement,
                cgroup_v2 = probe.cgroup_v2_available,
                bpf_fs = probe.bpf_fs_available,
                "Kernel does not support eBPF capture and fallback_mode=fail"
            );
            anyhow::bail!(
                "eBPF capture requires kernel >= 5.7 with cgroup v2 and bpffs. \
                 Detected: kernel={}, cgroup_v2={}, bpf_fs={}. \
                 Set FERRUM_NODE_AGENT_FALLBACK_MODE=iptables to use iptables instead.",
                probe.kernel_release,
                probe.cgroup_v2_available,
                probe.bpf_fs_available,
            );
        }
    }
}

fn initialize_backend(
    backend: &mut dyn EbpfBackend,
    config: &NodeAgentConfig,
) -> Result<(), anyhow::Error> {
    backend.load_programs().map_err(anyhow::Error::msg)?;

    if let Some(uid) = config.capture_config.proxy_uid {
        backend.update_bypass_uid(uid).map_err(anyhow::Error::msg)?;
    }

    for cidr in &config.capture_config.include_cidrs {
        backend
            .update_cidr_include(cidr)
            .map_err(anyhow::Error::msg)?;
    }
    for cidr in &config.capture_config.exclude_cidrs {
        backend
            .update_cidr_exclude(cidr)
            .map_err(anyhow::Error::msg)?;
    }
    for port in &config.capture_config.exclude_ports {
        backend
            .update_port_exclude(*port)
            .map_err(anyhow::Error::msg)?;
    }

    info!("BPF programs loaded and maps initialized");
    Ok(())
}

fn cleanup_all_pods(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
) {
    for entry in pod_states.iter() {
        let state = entry.value();
        if state.attached
            && let Err(e) = backend.detach_pod(&state.pod_uid)
        {
            warn!(pod_uid = %state.pod_uid, error = %e, "Failed to detach BPF programs during shutdown");
        }
    }
    if let Err(e) = backend.cleanup_all() {
        warn!(error = %e, "Failed to cleanup BPF state during shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::CaptureMode;
    use crate::ebpf::MockEbpfBackend;

    #[test]
    fn initialize_backend_populates_maps() {
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig {
                mode: CaptureMode::Ebpf,
                proxy_uid: Some(1337),
                inbound_port: 15006,
                outbound_port: 15001,
                include_cidrs: vec!["10.0.0.0/8".to_string()],
                exclude_cidrs: vec!["10.0.0.1/32".to_string()],
                exclude_ports: vec![15020],
            },
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
        };

        let mut backend = MockEbpfBackend::default();
        initialize_backend(&mut backend, &config).unwrap();

        assert!(backend.programs_loaded);
        assert_eq!(backend.bypass_uids, vec![1337]);
        assert_eq!(backend.cidr_includes, vec!["10.0.0.0/8"]);
        assert_eq!(backend.cidr_excludes, vec!["10.0.0.1/32"]);
        assert_eq!(backend.port_excludes, vec![15020]);
    }

    #[test]
    fn cleanup_all_pods_detaches_attached() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        pod_states.insert(
            "pod-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-1".to_string(),
                pod_name: "test-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                cgroup_path: None,
                veth_iface: None,
                attached: true,
            },
        );
        pod_states.insert(
            "pod-2".to_string(),
            PodAttachmentState {
                pod_uid: "pod-2".to_string(),
                pod_name: "skipped-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                cgroup_path: None,
                veth_iface: None,
                attached: false,
            },
        );

        cleanup_all_pods(&mut backend, &pod_states);

        assert_eq!(backend.detached_pods.len(), 1);
        assert_eq!(backend.detached_pods[0], "pod-1");
        assert!(backend.cleaned_up);
    }

    #[test]
    fn handle_fallback_iptables_succeeds() {
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
        };
        let probe = kernel_probe::KernelProbeResult {
            kernel_release: "4.19.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: false,
            bpf_fs_available: false,
        };

        assert!(handle_fallback(&config, &probe).is_ok());
    }

    #[test]
    fn handle_fallback_fail_returns_error() {
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
        };
        let probe = kernel_probe::KernelProbeResult {
            kernel_release: "4.19.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: false,
            bpf_fs_available: false,
        };

        assert!(handle_fallback(&config, &probe).is_err());
    }

    #[tokio::test]
    async fn wait_for_shutdown_blocks_until_signal() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let wait = wait_for_shutdown(&shutdown_tx);
        tokio::pin!(wait);

        tokio::select! {
            _ = &mut wait => panic!("wait_for_shutdown returned before shutdown was signalled"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(25)) => {}
        }

        shutdown_tx
            .send(true)
            .expect("shutdown receiver should be live");
        tokio::time::timeout(std::time::Duration::from_secs(1), wait)
            .await
            .expect("shutdown wait should resolve after signal");
    }
}
