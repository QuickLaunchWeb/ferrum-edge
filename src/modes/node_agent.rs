//! Node agent mode — per-node eBPF capture manager for ambient mesh.
//!
//! `FERRUM_MODE=node_agent` runs as a DaemonSet companion alongside the
//! ambient mesh proxy. It attaches BPF programs to enrolled pods' cgroups
//! and veth interfaces to transparently redirect traffic to the co-located
//! Ferrum proxy.
//!
//! The node agent does NOT run proxy listeners. Traffic capture is its sole
//! responsibility.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use tracing::{debug, error, info, warn};

use crate::capture::{CaptureConfig, IptablesPlan};
use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::ebpf::cgroup;
use crate::ebpf::kernel_probe::{self, KernelProbeResult};
use crate::ebpf::pod_watcher::{self, EnrollmentDecision};
use crate::ebpf::veth;
use crate::ebpf::{EbpfBackend, FallbackMode, MockEbpfBackend, PodAttachmentState, PodInfo};

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
        return handle_fallback(&config, &probe, &shutdown_tx).await;
    }

    run_with_backend(create_backend(), &config, &shutdown_tx).await
}

fn create_backend() -> Box<dyn EbpfBackend> {
    #[cfg(feature = "ebpf")]
    {
        Box::new(crate::ebpf::AyaEbpfBackend::new())
    }
    #[cfg(not(feature = "ebpf"))]
    {
        info!("ebpf feature not enabled, using mock backend");
        Box::new(MockEbpfBackend::default())
    }
}

/// Metrics tracked by the node agent.
pub struct NodeAgentMetrics {
    pub pods_enrolled: AtomicU64,
    pub pods_unenrolled: AtomicU64,
    pub attach_errors: AtomicU64,
}

impl Default for NodeAgentMetrics {
    fn default() -> Self {
        Self {
            pods_enrolled: AtomicU64::new(0),
            pods_unenrolled: AtomicU64::new(0),
            attach_errors: AtomicU64::new(0),
        }
    }
}

async fn run_with_backend(
    mut backend: Box<dyn EbpfBackend>,
    config: &NodeAgentConfig,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    initialize_backend(backend.as_mut(), config)?;

    let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
    let metrics = NodeAgentMetrics::default();

    info!(
        "Node agent initialized, waiting for pod events on node {}",
        config.node_name
    );

    let mut shutdown_rx = shutdown_tx.subscribe();
    shutdown_rx.changed().await.ok();

    info!(
        pods_enrolled = metrics.pods_enrolled.load(Ordering::Relaxed),
        pods_unenrolled = metrics.pods_unenrolled.load(Ordering::Relaxed),
        attach_errors = metrics.attach_errors.load(Ordering::Relaxed),
        attached_pods = pod_states.len(),
        "Node agent shutting down, detaching BPF programs"
    );
    cleanup_all_pods(backend.as_mut(), &pod_states);

    Ok(())
}

#[allow(dead_code)]
/// Describes a pod event for enrollment processing.
pub struct PodEvent<'a> {
    pub pod_uid: &'a str,
    pub pod_name: &'a str,
    pub namespace: &'a str,
    pub labels: &'a HashMap<String, String>,
    pub annotations: &'a HashMap<String, String>,
    pub pod_ip_str: Option<&'a str>,
    pub pod_pid: Option<u32>,
}

#[allow(dead_code)]
pub fn handle_pod_added(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    event: &PodEvent<'_>,
) {
    let (pod_uid, pod_name, namespace) = (event.pod_uid, event.pod_name, event.namespace);
    let decision = pod_watcher::evaluate_enrollment(
        event.labels,
        event.annotations,
        namespace,
        &config.excluded_namespaces,
    );
    if decision != EnrollmentDecision::Enroll {
        debug!(
            pod_uid,
            pod_name, namespace, "Pod does not meet enrollment criteria"
        );
        return;
    }

    if pod_states.contains_key(pod_uid) {
        debug!(pod_uid, pod_name, "Pod already enrolled, skipping");
        return;
    }

    let pod_ip = event.pod_ip_str.and_then(pod_watcher::parse_pod_ip);
    let cgroup_path = cgroup::resolve_pod_cgroup_path(&config.cgroup_root, pod_uid)
        .map(|p| p.to_string_lossy().to_string());
    let veth_iface = veth::discover_veth_for_pod(event.pod_pid);

    let mut state = PodAttachmentState {
        pod_uid: pod_uid.to_string(),
        pod_name: pod_name.to_string(),
        namespace: namespace.to_string(),
        pod_ip,
        cgroup_path: cgroup_path.clone(),
        veth_iface: veth_iface.clone(),
        attached: false,
    };

    if let Some(ref cgroup) = cgroup_path {
        let programs = [
            "ferrum_connect4",
            "ferrum_connect6",
            "ferrum_getpeername4",
            "ferrum_getpeername6",
        ];
        let mut attach_ok = true;
        for prog in &programs {
            if let Err(e) = backend.attach_cgroup(pod_uid, cgroup, prog) {
                warn!(pod_uid, program = prog, error = %e, "Failed to attach cgroup program");
                metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
                attach_ok = false;
                break;
            }
        }
        if attach_ok {
            if let Some(ref iface) = veth_iface
                && let Err(e) = backend.attach_tc(pod_uid, iface, "ferrum_tc_inbound")
            {
                warn!(pod_uid, iface, error = %e, "Failed to attach tc program");
                metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(ip) = pod_ip {
                let info = PodInfo {
                    proxy_port: config.capture_config.outbound_port,
                    cgroup_id: 0,
                };
                let _ = backend.update_pod_ip(ip, &info);
            }
            state.attached = true;
            metrics.pods_enrolled.fetch_add(1, Ordering::Relaxed);
            info!(
                pod_uid,
                pod_name,
                namespace,
                ?pod_ip,
                "Pod enrolled for eBPF capture"
            );
        }
    } else {
        warn!(
            pod_uid,
            pod_name, "Could not resolve cgroup path, skipping attachment"
        );
        metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    pod_states.insert(pod_uid.to_string(), state);
}

#[allow(dead_code)]
pub fn handle_pod_removed(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
) {
    let removed = pod_states.remove(pod_uid);
    let Some((_, state)) = removed else {
        return;
    };

    if state.attached {
        if let Err(e) = backend.detach_pod(pod_uid) {
            warn!(pod_uid, error = %e, "Failed to detach BPF programs");
        }
        if let Some(ip) = state.pod_ip
            && let Err(e) = backend.remove_pod_ip(ip)
        {
            warn!(pod_uid, %ip, error = %e, "Failed to remove pod IP from map");
        }
        metrics.pods_unenrolled.fetch_add(1, Ordering::Relaxed);
        info!(pod_uid, pod_name = %state.pod_name, "Pod unenrolled from eBPF capture");
    }
}

async fn handle_fallback(
    config: &NodeAgentConfig,
    probe: &KernelProbeResult,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
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

            let plan = IptablesPlan::for_config(&config.capture_config);
            execute_iptables_commands(&plan.commands, "setup").await;

            info!("Iptables fallback rules applied, awaiting shutdown signal");

            let mut shutdown_rx = shutdown_tx.subscribe();
            shutdown_rx.changed().await.ok();

            info!("Shutdown signal received, cleaning up iptables rules");
            let cleanup = IptablesPlan::cleanup_commands();
            execute_iptables_commands(&cleanup, "cleanup").await;

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

/// Execute a list of shell commands (iptables setup or cleanup) sequentially.
///
/// Each command is run via `sh -c` so that shell operators (`||`, `2>/dev/null`)
/// are interpreted correctly. Failures are logged but do not abort the remaining
/// commands — iptables rules are idempotent, so partial application is safe and
/// a subsequent retry will converge.
async fn execute_iptables_commands(commands: &[String], phase: &str) {
    for cmd in commands {
        debug!(command = %cmd, phase, "Executing iptables command");
        match tokio::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .await
        {
            Ok(output) => {
                if output.status.success() {
                    debug!(command = %cmd, phase, "iptables command succeeded");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!(
                        command = %cmd,
                        phase,
                        exit_code = output.status.code(),
                        stderr = %stderr.trim(),
                        "iptables command failed"
                    );
                }
            }
            Err(e) => {
                error!(
                    command = %cmd,
                    phase,
                    error = %e,
                    "Failed to spawn iptables command"
                );
            }
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

    #[tokio::test]
    async fn handle_fallback_iptables_succeeds() {
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
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        // Send shutdown from a spawned task after a brief delay so
        // handle_fallback's internal subscriber is registered before the
        // send arrives. The iptables commands all fail fast on non-Linux
        // (no iptables binary) so the subscribe point is reached quickly.
        let tx_clone = shutdown_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            tx_clone.send(true).ok();
        });

        // handle_fallback will attempt to run iptables commands which will
        // fail on non-Linux (or without privileges), but the function logs
        // errors and continues — it should still return Ok.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            handle_fallback(&config, &probe, &shutdown_tx),
        )
        .await
        .expect("handle_fallback should complete within timeout");
        assert!(result.is_ok());
    }

    #[test]
    fn handle_pod_added_skips_when_cgroup_not_found() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_pid: None,
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-1"));
        assert_eq!(metrics.attach_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_added_enrolls_with_real_cgroup() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();

        let temp_dir = std::env::temp_dir().join("ferrum_test_cgroup_enroll");
        let pod_cgroup = temp_dir.join("kubepods/podtest-uid-1");
        std::fs::create_dir_all(&pod_cgroup).unwrap();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: temp_dir.to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "test-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_pid: None,
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(pod_states.contains_key("test-uid-1"));
        let state = pod_states.get("test-uid-1").unwrap();
        assert!(state.attached);
        assert_eq!(metrics.pods_enrolled.load(Ordering::Relaxed), 1);

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn handle_pod_added_skips_non_matching() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
        };
        let event = PodEvent {
            pod_uid: "pod-uid-2",
            pod_name: "no-mesh-pod",
            namespace: "default",
            labels: &HashMap::new(),
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_pid: None,
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-2"));
        assert_eq!(metrics.pods_enrolled.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handle_pod_added_skips_excluded_namespace() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let excluded = pod_watcher::build_excluded_namespaces(&[]);
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: excluded,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-3",
            pod_name: "system-pod",
            namespace: "kube-system",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_pid: None,
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-3"));
    }

    #[test]
    fn handle_pod_removed_cleans_up_attached() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 5);

        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "test-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                cgroup_path: Some("/sys/fs/cgroup/kubepods/poduid1".to_string()),
                veth_iface: Some("veth123".to_string()),
                attached: true,
            },
        );
        backend
            .update_pod_ip(
                ip,
                &PodInfo {
                    proxy_port: 15001,
                    cgroup_id: 0,
                },
            )
            .unwrap();

        handle_pod_removed(&mut backend, &pod_states, &metrics, "pod-uid-1");

        assert!(!pod_states.contains_key("pod-uid-1"));
        assert_eq!(backend.detached_pods, vec!["pod-uid-1"]);
        assert!(!backend.pod_ips.contains_key(&ip));
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_removed_noop_for_unknown() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();

        handle_pod_removed(&mut backend, &pod_states, &metrics, "nonexistent");

        assert!(backend.detached_pods.is_empty());
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handle_pod_added_skips_duplicate() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);

        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                cgroup_path: None,
                veth_iface: None,
                attached: true,
            },
        );

        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "duplicate",
            namespace: "default",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_pid: None,
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert_eq!(pod_states.get("pod-uid-1").unwrap().pod_name, "existing");
    }

    #[tokio::test]
    async fn handle_fallback_fail_returns_error() {
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
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        assert!(
            handle_fallback(&config, &probe, &shutdown_tx)
                .await
                .is_err()
        );
    }
}
