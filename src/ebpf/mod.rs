#![allow(dead_code)]
//! Userspace eBPF manager for the node-agent capture mode.
//!
//! This module owns the trait surface, shared types, and mock backend for
//! managing BPF program attachment to pod cgroups and veth interfaces.
//! The real aya-based loader lives behind
//! `#[cfg(all(feature = "ebpf", target_os = "linux"))]`; default and non-Linux
//! builds use `MockEbpfBackend` for lifecycle tests without kernel interaction.

pub mod bpf_metrics;
pub mod cgroup;
pub mod event_consumer;
pub mod kernel_probe;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub mod loader;
pub mod maps;
pub mod pod_watcher;
pub mod veth;

#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub use loader::AyaEbpfBackend;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};

use ferrum_ebpf_common::{BpfCaptureConfig, INBOUND_HBONE_PORT, OUTBOUND_CAPTURE_PORT};

pub const DEFAULT_NODE_AGENT_SOCKET_PATH: &str = "/run/ferrum/node-agent.sock";
pub const BPF_MAP_ORIG_DST4: &str = "FERRUM_ORIG_DST4";
pub const BPF_MAP_ORIG_DST6: &str = "FERRUM_ORIG_DST6";
pub const BPF_MAP_POD_IPS: &str = "FERRUM_POD_IPS";
pub const BPF_MAP_BYPASS_UIDS: &str = "FERRUM_BYPASS_UIDS";
pub const BPF_MAP_CIDR_EXCLUDE4: &str = "FERRUM_CIDR_EXCLUDE4";
pub const BPF_MAP_CIDR_EXCLUDE6: &str = "FERRUM_CIDR_EXCLUDE6";
pub const BPF_MAP_CIDR_INCLUDE4: &str = "FERRUM_CIDR_INCLUDE4";
pub const BPF_MAP_CIDR_INCLUDE6: &str = "FERRUM_CIDR_INCLUDE6";
pub const BPF_MAP_PORT_EXCLUDE: &str = "FERRUM_PORT_EXCLUDE";
pub const BPF_MAP_CAPTURE_CONFIG: &str = "FERRUM_CAPTURE_CONFIG";

/// Node-agent proxy topology for the capture contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAgentProxyMode {
    LocalPod,
    NodeWaypoint,
}

impl NodeAgentProxyMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "local_pod" => Ok(Self::LocalPod),
            "node_waypoint" => Ok(Self::NodeWaypoint),
            other => Err(format!(
                "Invalid FERRUM_NODE_AGENT_PROXY_MODE '{other}'. Expected: local_pod or node_waypoint"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalPod => "local_pod",
            Self::NodeWaypoint => "node_waypoint",
        }
    }
}

impl std::fmt::Display for NodeAgentProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// BPF map names that form the node-agent/proxy capture ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureBpfMaps {
    pub orig_dst4: &'static str,
    pub orig_dst6: &'static str,
    pub pod_ips: &'static str,
    pub bypass_uids: &'static str,
    pub cidr_exclude4: &'static str,
    pub cidr_exclude6: &'static str,
    pub cidr_include4: &'static str,
    pub cidr_include6: &'static str,
    pub port_exclude: &'static str,
    pub capture_config: &'static str,
}

impl Default for CaptureBpfMaps {
    fn default() -> Self {
        Self {
            orig_dst4: BPF_MAP_ORIG_DST4,
            orig_dst6: BPF_MAP_ORIG_DST6,
            pod_ips: BPF_MAP_POD_IPS,
            bypass_uids: BPF_MAP_BYPASS_UIDS,
            cidr_exclude4: BPF_MAP_CIDR_EXCLUDE4,
            cidr_exclude6: BPF_MAP_CIDR_EXCLUDE6,
            cidr_include4: BPF_MAP_CIDR_INCLUDE4,
            cidr_include6: BPF_MAP_CIDR_INCLUDE6,
            port_exclude: BPF_MAP_PORT_EXCLUDE,
            capture_config: BPF_MAP_CAPTURE_CONFIG,
        }
    }
}

/// Formal node-agent/proxy capture surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureContract {
    pub proxy_mode: NodeAgentProxyMode,
    pub outbound_capture_port: u16,
    pub hbone_redirect_port: u16,
    pub unix_socket_path: String,
    pub bpf_maps: CaptureBpfMaps,
}

impl CaptureContract {
    pub fn new(
        proxy_mode: NodeAgentProxyMode,
        outbound_capture_port: u16,
        hbone_redirect_port: u16,
        unix_socket_path: impl Into<String>,
    ) -> Result<Self, String> {
        if outbound_capture_port == 0 {
            return Err("CaptureContract outbound_capture_port must be non-zero".to_string());
        }
        if hbone_redirect_port == 0 {
            return Err("CaptureContract hbone_redirect_port must be non-zero".to_string());
        }
        if outbound_capture_port == hbone_redirect_port {
            return Err(
                "CaptureContract outbound_capture_port and hbone_redirect_port must differ"
                    .to_string(),
            );
        }
        let unix_socket_path = unix_socket_path.into();
        if unix_socket_path.trim().is_empty() {
            return Err("CaptureContract unix_socket_path must not be empty".to_string());
        }

        Ok(Self {
            proxy_mode,
            outbound_capture_port,
            hbone_redirect_port,
            unix_socket_path,
            bpf_maps: CaptureBpfMaps::default(),
        })
    }

    pub fn local_pod_defaults() -> Self {
        Self {
            proxy_mode: NodeAgentProxyMode::LocalPod,
            outbound_capture_port: OUTBOUND_CAPTURE_PORT,
            hbone_redirect_port: INBOUND_HBONE_PORT,
            unix_socket_path: DEFAULT_NODE_AGENT_SOCKET_PATH.to_string(),
            bpf_maps: CaptureBpfMaps::default(),
        }
    }

    pub fn bpf_capture_config(&self) -> BpfCaptureConfig {
        BpfCaptureConfig::new(self.outbound_capture_port, self.hbone_redirect_port)
    }
}

/// Metrics tracked by the node agent.
pub struct NodeAgentMetrics {
    pub pods_enrolled: AtomicU64,
    pub pods_unenrolled: AtomicU64,
    pub attach_errors: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeAgentMetricsSnapshot {
    pub pods_enrolled: u64,
    pub pods_unenrolled: u64,
    pub attach_errors: u64,
}

impl NodeAgentMetrics {
    pub fn snapshot(&self) -> NodeAgentMetricsSnapshot {
        NodeAgentMetricsSnapshot {
            pods_enrolled: self.pods_enrolled.load(Ordering::Relaxed),
            pods_unenrolled: self.pods_unenrolled.load(Ordering::Relaxed),
            attach_errors: self.attach_errors.load(Ordering::Relaxed),
        }
    }
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

/// Metadata tracked per enrolled pod IP in the BPF `FERRUM_POD_IPS` map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodInfo {
    pub proxy_port: u16,
    /// Reserved for future cgroup-aware BPF policy; current node-agent
    /// enrollment writes `0` because IP-to-proxy-port capture is sufficient.
    pub cgroup_id: u64,
}

/// State tracked per attached pod for graceful cleanup on removal.
#[derive(Debug, Clone)]
pub struct PodAttachmentState {
    pub pod_uid: String,
    pub pod_name: String,
    pub namespace: String,
    pub pod_ip: Option<Ipv4Addr>,
    pub cgroup_path: Option<String>,
    pub veth_iface: Option<String>,
    pub attached: bool,
}

/// Fallback behavior when the kernel does not support eBPF capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackMode {
    Iptables,
    Fail,
}

impl FallbackMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "iptables" => Ok(Self::Iptables),
            "fail" => Ok(Self::Fail),
            other => Err(format!(
                "Invalid FERRUM_NODE_AGENT_FALLBACK_MODE '{other}'. Expected: iptables, fail"
            )),
        }
    }
}

/// Abstraction over BPF program management for testability.
///
/// `AyaEbpfBackend` uses `aya` to load and attach programs on Linux when the
/// `ebpf` feature is enabled; `MockEbpfBackend` is the in-memory test
/// substitute.
pub trait EbpfBackend: Send + Sync {
    fn load_programs(&mut self) -> Result<(), String>;
    fn update_capture_config(&mut self, config: &BpfCaptureConfig) -> Result<(), String>;
    fn attach_cgroup(
        &mut self,
        pod_uid: &str,
        cgroup_path: &str,
        program: &str,
    ) -> Result<(), String>;
    fn attach_tc(&mut self, pod_uid: &str, iface: &str, program: &str) -> Result<(), String>;
    fn detach_pod(&mut self, pod_uid: &str) -> Result<(), String>;
    fn update_pod_ip(&mut self, ip: Ipv4Addr, info: &PodInfo) -> Result<(), String>;
    fn remove_pod_ip(&mut self, ip: Ipv4Addr) -> Result<(), String>;
    fn update_bypass_uid(&mut self, uid: u32) -> Result<(), String>;
    fn update_cidr_exclude(&mut self, cidr: &str) -> Result<(), String>;
    fn update_cidr_include(&mut self, cidr: &str) -> Result<(), String>;
    fn update_port_exclude(&mut self, port: u16) -> Result<(), String>;
    fn cleanup_all(&mut self) -> Result<(), String>;
}

/// In-memory mock backend for Phase 1 and integration tests.
#[derive(Debug, Default)]
pub struct MockEbpfBackend {
    pub programs_loaded: bool,
    pub cgroup_attachments: Vec<(String, String)>,
    pub tc_attachments: Vec<(String, String)>,
    pub pod_ips: HashMap<Ipv4Addr, PodInfo>,
    pub bypass_uids: Vec<u32>,
    pub cidr_excludes: Vec<String>,
    pub cidr_includes: Vec<String>,
    pub port_excludes: Vec<u16>,
    pub capture_config: Option<BpfCaptureConfig>,
    pub detached_pods: Vec<String>,
    pub cleaned_up: bool,
    pub fail_update_capture_config: bool,
}

impl EbpfBackend for MockEbpfBackend {
    fn load_programs(&mut self) -> Result<(), String> {
        self.programs_loaded = true;
        Ok(())
    }

    fn update_capture_config(&mut self, config: &BpfCaptureConfig) -> Result<(), String> {
        if self.fail_update_capture_config {
            return Err("capture config update failed".to_string());
        }
        self.capture_config = Some(*config);
        Ok(())
    }

    fn attach_cgroup(
        &mut self,
        _pod_uid: &str,
        cgroup_path: &str,
        program: &str,
    ) -> Result<(), String> {
        self.cgroup_attachments
            .push((cgroup_path.to_string(), program.to_string()));
        Ok(())
    }

    fn attach_tc(&mut self, _pod_uid: &str, iface: &str, program: &str) -> Result<(), String> {
        self.tc_attachments
            .push((iface.to_string(), program.to_string()));
        Ok(())
    }

    fn detach_pod(&mut self, pod_uid: &str) -> Result<(), String> {
        self.detached_pods.push(pod_uid.to_string());
        Ok(())
    }

    fn update_pod_ip(&mut self, ip: Ipv4Addr, info: &PodInfo) -> Result<(), String> {
        self.pod_ips.insert(ip, info.clone());
        Ok(())
    }

    fn remove_pod_ip(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        self.pod_ips.remove(&ip);
        Ok(())
    }

    fn update_bypass_uid(&mut self, uid: u32) -> Result<(), String> {
        self.bypass_uids.push(uid);
        Ok(())
    }

    fn update_cidr_exclude(&mut self, cidr: &str) -> Result<(), String> {
        self.cidr_excludes.push(cidr.to_string());
        Ok(())
    }

    fn update_cidr_include(&mut self, cidr: &str) -> Result<(), String> {
        self.cidr_includes.push(cidr.to_string());
        Ok(())
    }

    fn update_port_exclude(&mut self, port: u16) -> Result<(), String> {
        self.port_excludes.push(port);
        Ok(())
    }

    fn cleanup_all(&mut self) -> Result<(), String> {
        self.cgroup_attachments.clear();
        self.tc_attachments.clear();
        self.pod_ips.clear();
        self.cleaned_up = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_mode_parse_valid() {
        assert_eq!(
            FallbackMode::parse("iptables").unwrap(),
            FallbackMode::Iptables
        );
        assert_eq!(FallbackMode::parse("fail").unwrap(), FallbackMode::Fail);
        assert_eq!(
            FallbackMode::parse("IPTABLES").unwrap(),
            FallbackMode::Iptables
        );
    }

    #[test]
    fn fallback_mode_parse_invalid() {
        assert!(FallbackMode::parse("other").is_err());
    }

    #[test]
    fn node_agent_proxy_mode_parse_valid() {
        assert_eq!(
            NodeAgentProxyMode::parse("local_pod").unwrap(),
            NodeAgentProxyMode::LocalPod
        );
        assert_eq!(
            NodeAgentProxyMode::parse("node_waypoint").unwrap(),
            NodeAgentProxyMode::NodeWaypoint
        );
        assert_eq!(
            NodeAgentProxyMode::parse("LOCAL_POD").unwrap(),
            NodeAgentProxyMode::LocalPod
        );
    }

    #[test]
    fn capture_contract_projects_bpf_config() {
        let contract = CaptureContract::new(
            NodeAgentProxyMode::NodeWaypoint,
            16001,
            16008,
            "/tmp/ferrum.sock",
        )
        .unwrap();

        assert_eq!(contract.proxy_mode, NodeAgentProxyMode::NodeWaypoint);
        assert_eq!(contract.bpf_maps.capture_config, BPF_MAP_CAPTURE_CONFIG);
        assert_eq!(
            contract.bpf_capture_config(),
            BpfCaptureConfig::new(16001, 16008)
        );
    }

    #[test]
    fn capture_contract_rejects_invalid_surface() {
        assert!(
            CaptureContract::new(NodeAgentProxyMode::LocalPod, 0, 15008, "/tmp/ferrum.sock")
                .is_err()
        );
        assert!(
            CaptureContract::new(NodeAgentProxyMode::LocalPod, 15001, 0, "/tmp/ferrum.sock")
                .is_err()
        );
        assert!(
            CaptureContract::new(
                NodeAgentProxyMode::LocalPod,
                15001,
                15001,
                "/tmp/ferrum.sock"
            )
            .is_err()
        );
        assert!(CaptureContract::new(NodeAgentProxyMode::LocalPod, 15001, 15008, "").is_err());
    }

    #[test]
    fn mock_backend_load_and_attach() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        assert!(backend.programs_loaded);

        backend
            .update_capture_config(&BpfCaptureConfig::new(16001, 16008))
            .unwrap();
        assert_eq!(
            backend.capture_config,
            Some(BpfCaptureConfig::new(16001, 16008))
        );

        backend
            .attach_cgroup(
                "pod-abc",
                "/sys/fs/cgroup/kubepods/pod-abc",
                "ferrum_connect4",
            )
            .unwrap();
        backend
            .attach_tc("pod-abc", "eth0", "ferrum_tc_inbound")
            .unwrap();

        assert_eq!(backend.cgroup_attachments.len(), 1);
        assert_eq!(backend.tc_attachments.len(), 1);
    }

    #[test]
    fn mock_backend_pod_ip_lifecycle() {
        let mut backend = MockEbpfBackend::default();
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let info = PodInfo {
            proxy_port: 15001,
            cgroup_id: 42,
        };

        backend.update_pod_ip(ip, &info).unwrap();
        assert_eq!(backend.pod_ips.get(&ip), Some(&info));

        backend.remove_pod_ip(ip).unwrap();
        assert!(!backend.pod_ips.contains_key(&ip));
    }

    #[test]
    fn mock_backend_cleanup() {
        let mut backend = MockEbpfBackend::default();
        backend
            .attach_cgroup(
                "pod-abc",
                "/sys/fs/cgroup/kubepods/pod-abc",
                "ferrum_connect4",
            )
            .unwrap();
        backend
            .update_pod_ip(
                Ipv4Addr::new(10, 0, 0, 1),
                &PodInfo {
                    proxy_port: 15001,
                    cgroup_id: 1,
                },
            )
            .unwrap();

        backend.cleanup_all().unwrap();
        assert!(backend.cleaned_up);
        assert!(backend.cgroup_attachments.is_empty());
        assert!(backend.pod_ips.is_empty());
    }
}
