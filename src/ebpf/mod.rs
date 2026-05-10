#![allow(dead_code)]
//! Userspace eBPF manager for the node-agent capture mode.
//!
//! This module owns the trait surface, shared types, and mock backend for
//! managing BPF program attachment to pod cgroups and veth interfaces.
//! The real aya-based loader will land behind `#[cfg(feature = "ebpf")]` in a
//! future phase; Phase 1 uses `MockEbpfBackend` for the full lifecycle without
//! kernel interaction.

pub mod cgroup;
pub mod kernel_probe;
#[cfg(feature = "ebpf")]
pub mod loader;
pub mod maps;
pub mod pod_watcher;
pub mod veth;

#[cfg(feature = "ebpf")]
pub use loader::AyaEbpfBackend;

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Metadata tracked per enrolled pod IP in the BPF `FERRUM_POD_IPS` map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodInfo {
    pub proxy_port: u16,
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
/// The real implementation will use `aya` to load and attach programs;
/// `MockEbpfBackend` provides an in-memory substitute for Phase 1 and tests.
pub trait EbpfBackend: Send + Sync {
    fn load_programs(&mut self) -> Result<(), String>;
    fn attach_cgroup(&mut self, cgroup_path: &str, program: &str) -> Result<(), String>;
    fn attach_tc(&mut self, iface: &str, program: &str) -> Result<(), String>;
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
    pub detached_pods: Vec<String>,
    pub cleaned_up: bool,
}

impl EbpfBackend for MockEbpfBackend {
    fn load_programs(&mut self) -> Result<(), String> {
        self.programs_loaded = true;
        Ok(())
    }

    fn attach_cgroup(&mut self, cgroup_path: &str, program: &str) -> Result<(), String> {
        self.cgroup_attachments
            .push((cgroup_path.to_string(), program.to_string()));
        Ok(())
    }

    fn attach_tc(&mut self, iface: &str, program: &str) -> Result<(), String> {
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
    fn mock_backend_load_and_attach() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        assert!(backend.programs_loaded);

        backend
            .attach_cgroup("/sys/fs/cgroup/kubepods/pod-abc", "ferrum_connect4")
            .unwrap();
        backend.attach_tc("eth0", "ferrum_tc_inbound").unwrap();

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
            .attach_cgroup("/sys/fs/cgroup/kubepods/pod-abc", "ferrum_connect4")
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
