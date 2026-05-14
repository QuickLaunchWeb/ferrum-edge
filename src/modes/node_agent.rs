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
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::api::Api;
use kube::runtime::watcher::{self as kube_watcher, Event};
use tracing::{debug, error, info, warn};

use crate::capture::{CaptureConfig, IptablesPlan};
use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::ebpf::cgroup;
use crate::ebpf::kernel_probe::{self, KernelProbeResult};
use crate::ebpf::pod_watcher::{self, EnrollmentDecision};
use crate::ebpf::veth;
use crate::ebpf::{EbpfBackend, FallbackMode, PodAttachmentState, PodInfo};

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

    let mut shutdown_rx = shutdown_tx.subscribe();
    let client = build_node_agent_kube_client().await?;
    let pods: Api<Pod> = Api::all(client);
    let watcher_config =
        kube_watcher::Config::default().fields(&format!("spec.nodeName={}", config.node_name));
    let mut pod_stream = Box::pin(kube_watcher::watcher(pods, watcher_config));
    let mut init_seen: Option<HashSet<String>> = None;

    info!(
        "Node agent initialized, watching pod events on node {}",
        config.node_name
    );

    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            event = pod_stream.next() => {
                match event {
                    Some(Ok(Event::Apply(pod))) => {
                        handle_kube_pod_applied(
                            backend.as_mut(),
                            &pod_states,
                            config,
                            &metrics,
                            &pod,
                        );
                    }
                    Some(Ok(Event::Delete(pod))) => {
                        if let Some(uid) = pod_uid(&pod) {
                            handle_pod_removed(backend.as_mut(), &pod_states, &metrics, &uid);
                        }
                    }
                    Some(Ok(Event::Init)) => {
                        init_seen = Some(HashSet::new());
                    }
                    Some(Ok(Event::InitApply(pod))) => {
                        if let Some(uid) = handle_kube_pod_applied(
                            backend.as_mut(),
                            &pod_states,
                            config,
                            &metrics,
                            &pod,
                        ) && let Some(seen) = &mut init_seen {
                            seen.insert(uid);
                        }
                    }
                    Some(Ok(Event::InitDone)) => {
                        if let Some(seen) = init_seen.take() {
                            let stale_uids: Vec<String> = pod_states
                                .iter()
                                .filter(|entry| !seen.contains(entry.key().as_str()))
                                .map(|entry| entry.key().clone())
                                .collect();
                            for uid in stale_uids {
                                handle_pod_removed(backend.as_mut(), &pod_states, &metrics, &uid);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        warn!(error = %e, "Pod watcher error; kube-rs will retry");
                        metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {
                        warn!("Pod watcher ended unexpectedly");
                        break;
                    }
                }
            }
        }
    }

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

async fn build_node_agent_kube_client() -> Result<kube::Client, anyhow::Error> {
    let config = match kube::Config::incluster() {
        Ok(config) => config,
        Err(in_cluster_err) => match kube::Config::infer().await {
            Ok(config) => config,
            Err(infer_err) => {
                anyhow::bail!(
                    "Failed to build Kubernetes client for node_agent mode: \
                     incluster={in_cluster_err}; inferred={infer_err}"
                );
            }
        },
    };
    Ok(kube::Client::try_from(config)?)
}

fn pod_uid(pod: &Pod) -> Option<String> {
    pod.metadata.uid.clone()
}

fn handle_kube_pod_applied(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    pod: &Pod,
) -> Option<String> {
    let pod_uid = pod_uid(pod)?;
    let pod_name = pod.metadata.name.clone().unwrap_or_else(|| pod_uid.clone());
    let namespace = pod
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let labels: HashMap<String, String> = pod
        .metadata
        .labels
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let annotations: HashMap<String, String> = pod
        .metadata
        .annotations
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let pod_ip = pod
        .status
        .as_ref()
        .and_then(|status| status.pod_ip.as_deref());
    let event = PodEvent {
        pod_uid: &pod_uid,
        pod_name: &pod_name,
        namespace: &namespace,
        labels: &labels,
        annotations: &annotations,
        pod_ip_str: pod_ip,
        pod_pid: None,
    };
    handle_pod_added(backend, pod_states, config, metrics, &event);
    Some(pod_uid)
}

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
        if pod_states.contains_key(pod_uid) {
            handle_pod_removed(backend, pod_states, metrics, pod_uid);
        }
        debug!(
            pod_uid,
            pod_name, namespace, "Pod does not meet enrollment criteria"
        );
        return;
    }

    let pod_ip = event.pod_ip_str.and_then(pod_watcher::parse_pod_ip);
    if let Some(mut state) = pod_states.get_mut(pod_uid) {
        reconcile_existing_pod_ip(backend, config, metrics, pod_uid, pod_ip, &mut state);
        debug!(pod_uid, pod_name, "Pod already enrolled, reconciled state");
        return;
    }

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
                if let Err(e) = backend.update_pod_ip(ip, &info) {
                    warn!(pod_uid, %ip, error = %e, "Failed to update pod IP map");
                    metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
                    if let Err(detach_err) = backend.detach_pod(pod_uid) {
                        warn!(pod_uid, error = %detach_err, "Failed to clean up partially attached pod");
                    }
                    return;
                }
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
        } else if let Err(e) = backend.detach_pod(pod_uid) {
            warn!(pod_uid, error = %e, "Failed to clean up partially attached pod");
        }
    } else {
        warn!(
            pod_uid,
            pod_name, "Could not resolve cgroup path, skipping attachment"
        );
        metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if state.attached {
        pod_states.insert(pod_uid.to_string(), state);
    }
}

fn reconcile_existing_pod_ip(
    backend: &mut dyn EbpfBackend,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    pod_ip: Option<std::net::Ipv4Addr>,
    state: &mut PodAttachmentState,
) {
    let Some(new_ip) = pod_ip else {
        return;
    };
    if state.pod_ip == Some(new_ip) {
        return;
    }

    let info = PodInfo {
        proxy_port: config.capture_config.outbound_port,
        cgroup_id: 0,
    };
    if let Err(e) = backend.update_pod_ip(new_ip, &info) {
        warn!(pod_uid, %new_ip, error = %e, "Failed to update pod IP map for existing pod");
        metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if let Some(old_ip) = state.pod_ip
        && let Err(e) = backend.remove_pod_ip(old_ip)
    {
        warn!(pod_uid, %old_ip, error = %e, "Failed to remove stale pod IP from map");
        metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
    }
    state.pod_ip = Some(new_ip);
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
    handle_fallback_with(config, probe, shutdown_tx, |cmds, phase| async move {
        execute_iptables_commands(&cmds, phase).await
    })
    .await
}

/// Test seam for [`handle_fallback`]. The production path passes
/// `execute_iptables_commands` (real `sh -c`); the unit test passes a no-op
/// closure so it can assert the control flow (setup → wait → cleanup) without
/// spawning ~11 subprocesses, which (a) is wall-clock expensive on a loaded
/// CI box and (b) drags real-time scheduling into a test that should be
/// purely deterministic.
async fn handle_fallback_with<F, Fut>(
    config: &NodeAgentConfig,
    probe: &KernelProbeResult,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    mut execute: F,
) -> Result<(), anyhow::Error>
where
    F: FnMut(Vec<String>, &'static str) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
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
            execute(plan.commands, "setup").await;

            info!("Iptables fallback rules applied, awaiting shutdown signal");

            wait_for_shutdown(shutdown_tx).await;

            info!("Shutdown signal received, cleaning up iptables rules");
            let cleanup = IptablesPlan::cleanup_commands();
            execute(cleanup, "cleanup").await;

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
///
/// Only invoked from `handle_fallback`, which is reached only on `node_agent`
/// mode after kernel-probe failure. The commands are formed from
/// `IptablesPlan::for_config` / `cleanup_commands`, both of which use
/// hardcoded chain names and operator inputs validated upstream
/// (`validate_cidr_list`, `parse_port_list`, `parse_proxy_uid`).
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
                include_outbound_ports: Vec::new(),
                exclude_cidrs: vec!["10.0.0.1/32".to_string()],
                exclude_ports: vec![15020],
                exclude_inbound_ports: Vec::new(),
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

    // Verifies handle_fallback's control flow (setup → wait → cleanup → Ok)
    // without spawning real subprocesses. The earlier shape — invoking
    // `handle_fallback` directly on non-Linux so each `sh -c iptables …`
    // would fail fast — coupled a real-time sleep+signal race to ~11
    // fork/exec calls. Under CI contention either the subprocess storm or
    // the wall-clock race could push the test past its outer timeout.
    //
    // This version uses `handle_fallback_with` to inject a no-op runner and
    // pre-signals shutdown so `wait_for_shutdown`'s `borrow()` returns
    // immediately. End-to-end: no I/O, no real-time dependency, no flake.
    // The standalone `wait_for_shutdown_blocks_until_signal` test still
    // exercises the blocking path, and `IptablesPlan` has its own coverage
    // for command generation, so nothing of value is lost by mocking the
    // executor here.
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
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        shutdown_tx
            .send(true)
            .expect("watch channel should be open");

        let phases = std::sync::Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
        let phases_for_runner = std::sync::Arc::clone(&phases);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handle_fallback_with(&config, &probe, &shutdown_tx, move |_, phase| {
                let phases = std::sync::Arc::clone(&phases_for_runner);
                async move {
                    phases.lock().expect("phases mutex").push(phase);
                }
            }),
        )
        .await
        .expect("handle_fallback should complete within timeout");
        assert!(result.is_ok());
        assert_eq!(
            *phases.lock().expect("phases mutex"),
            vec!["setup", "cleanup"]
        );
    }

    #[test]
    fn handle_pod_added_enrolls_matching_pod() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
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

        assert!(pod_states.contains_key("pod-uid-1"));
        assert_eq!(backend.cgroup_attachments.len(), 4);
        assert!(
            backend
                .pod_ips
                .contains_key(&std::net::Ipv4Addr::new(10, 0, 0, 5))
        );
        assert_eq!(metrics.pods_enrolled.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_added_missing_cgroup_does_not_poison_state() {
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
    fn handle_pod_added_unenrolls_existing_pod_when_labels_no_longer_match() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        pod_states.insert(
            "pod-uid-2".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-2".to_string(),
                pod_name: "mesh-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                cgroup_path: Some("/sys/fs/cgroup/kubepods/poduid2".to_string()),
                veth_iface: None,
                attached: true,
            },
        );
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
            pod_name: "mesh-pod",
            namespace: "default",
            labels: &HashMap::new(),
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_pid: None,
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-2"));
        assert_eq!(backend.detached_pods, vec!["pod-uid-2"]);
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 1);
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

    #[test]
    fn handle_pod_added_updates_existing_pod_ip() {
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
            pod_name: "existing",
            namespace: "default",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.8"),
            pod_pid: None,
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        assert_eq!(pod_states.get("pod-uid-1").unwrap().pod_ip, Some(ip));
        assert!(backend.pod_ips.contains_key(&ip));
        assert_eq!(metrics.attach_errors.load(Ordering::Relaxed), 0);
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
