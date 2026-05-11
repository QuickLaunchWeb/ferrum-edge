//! aya-based eBPF program loader and attachment manager.
//!
//! `AyaEbpfBackend` implements `EbpfBackend` using the `aya` crate to load
//! BPF ELF bytes, attach programs to pod cgroups and veth interfaces, and
//! manage BPF map contents. Available only on Linux with `--features ebpf`.

#![allow(dead_code)]

#[cfg(feature = "ebpf")]
use std::collections::HashMap;
#[cfg(feature = "ebpf")]
use std::fs::File;
#[cfg(feature = "ebpf")]
use std::net::Ipv4Addr;
#[cfg(feature = "ebpf")]
use std::os::fd::AsFd;

#[cfg(feature = "ebpf")]
use aya::Ebpf;
#[cfg(feature = "ebpf")]
use aya::programs::{CgroupSockAddr, SchedClassifier, TcAttachType};
#[cfg(feature = "ebpf")]
use tracing::{debug, info, warn};

#[cfg(feature = "ebpf")]
use super::maps::BpfMaps;
#[cfg(feature = "ebpf")]
use super::{EbpfBackend, PodInfo};

#[cfg(feature = "ebpf")]
const BPF_ELF_BYTES: &[u8] =
    include_bytes!("../../ebpf/target/bpfel-unknown-none/release/ferrum-ebpf");

#[cfg(feature = "ebpf")]
const CGROUP_PROGRAMS: &[&str] = &[
    "ferrum_connect4",
    "ferrum_connect6",
    "ferrum_getpeername4",
    "ferrum_getpeername6",
];

#[cfg(feature = "ebpf")]
const TC_PROGRAM: &str = "ferrum_tc_inbound";

/// Tracks per-pod attachment state for cleanup, keyed by pod_uid.
#[cfg(feature = "ebpf")]
struct PodLinks {
    cgroup_link_ids: Vec<aya::programs::CgroupSockAddrLinkId>,
    tc_link_ids: Vec<aya::programs::SchedClassifierLinkId>,
}

/// Real aya-backed eBPF loader. Only available on Linux with `--features ebpf`.
#[cfg(feature = "ebpf")]
pub struct AyaEbpfBackend {
    bpf: Option<Ebpf>,
    maps: Option<BpfMaps>,
    /// Keyed by pod_uid so `detach_pod(pod_uid)` finds the right links.
    pod_links: HashMap<String, PodLinks>,
}

#[cfg(feature = "ebpf")]
impl AyaEbpfBackend {
    pub fn new() -> Self {
        Self {
            bpf: None,
            maps: None,
            pod_links: HashMap::new(),
        }
    }

    fn bpf(&self) -> Result<&Ebpf, String> {
        self.bpf
            .as_ref()
            .ok_or_else(|| "BPF programs not loaded".to_string())
    }

    fn bpf_mut(&mut self) -> Result<&mut Ebpf, String> {
        self.bpf
            .as_mut()
            .ok_or_else(|| "BPF programs not loaded".to_string())
    }
}

#[cfg(feature = "ebpf")]
impl EbpfBackend for AyaEbpfBackend {
    fn load_programs(&mut self) -> Result<(), String> {
        let mut bpf =
            Ebpf::load(BPF_ELF_BYTES).map_err(|e| format!("Failed to load BPF ELF: {e}"))?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            warn!("Failed to initialize eBPF logger (non-fatal): {e}");
        }

        for name in CGROUP_PROGRAMS {
            let prog: &mut CgroupSockAddr = bpf
                .program_mut(name)
                .ok_or_else(|| format!("BPF program '{name}' not found in ELF"))?
                .try_into()
                .map_err(|e| format!("'{name}' is not a CgroupSockAddr program: {e}"))?;
            prog.load()
                .map_err(|e| format!("Failed to load BPF program '{name}': {e}"))?;
            debug!(program = name, "BPF cgroup program loaded");
        }

        let tc: &mut SchedClassifier = bpf
            .program_mut(TC_PROGRAM)
            .ok_or_else(|| format!("BPF program '{TC_PROGRAM}' not found in ELF"))?
            .try_into()
            .map_err(|e| format!("'{TC_PROGRAM}' is not a SchedClassifier: {e}"))?;
        tc.load()
            .map_err(|e| format!("Failed to load BPF program '{TC_PROGRAM}': {e}"))?;
        debug!(program = TC_PROGRAM, "BPF tc program loaded");

        self.maps = Some(BpfMaps::from_ebpf(&bpf)?);
        self.bpf = Some(bpf);

        info!("All BPF programs loaded successfully");
        Ok(())
    }

    fn attach_cgroup(
        &mut self,
        pod_uid: &str,
        cgroup_path: &str,
        program: &str,
    ) -> Result<(), String> {
        let cgroup_fd = File::open(cgroup_path)
            .map_err(|e| format!("Failed to open cgroup '{cgroup_path}': {e}"))?;

        let bpf = self.bpf_mut()?;
        let prog: &mut CgroupSockAddr = bpf
            .program_mut(program)
            .ok_or_else(|| format!("BPF program '{program}' not found"))?
            .try_into()
            .map_err(|e| format!("'{program}' type mismatch: {e}"))?;

        let link_id = prog
            .attach(cgroup_fd.as_fd())
            .map_err(|e| format!("Failed to attach '{program}' to '{cgroup_path}': {e}"))?;

        let links = self
            .pod_links
            .entry(pod_uid.to_string())
            .or_insert_with(|| PodLinks {
                cgroup_link_ids: Vec::new(),
                tc_link_ids: Vec::new(),
            });
        links.cgroup_link_ids.push(link_id);

        debug!(program, cgroup_path, pod_uid, "BPF cgroup program attached");
        Ok(())
    }

    fn attach_tc(&mut self, pod_uid: &str, iface: &str, program: &str) -> Result<(), String> {
        let bpf = self.bpf_mut()?;
        let prog: &mut SchedClassifier = bpf
            .program_mut(program)
            .ok_or_else(|| format!("BPF program '{program}' not found"))?
            .try_into()
            .map_err(|e| format!("'{program}' type mismatch: {e}"))?;

        let link_id = prog
            .attach(iface, TcAttachType::Ingress)
            .map_err(|e| format!("Failed to attach '{program}' to '{iface}': {e}"))?;

        let links = self
            .pod_links
            .entry(pod_uid.to_string())
            .or_insert_with(|| PodLinks {
                cgroup_link_ids: Vec::new(),
                tc_link_ids: Vec::new(),
            });
        links.tc_link_ids.push(link_id);

        debug!(program, iface, pod_uid, "BPF tc program attached");
        Ok(())
    }

    fn detach_pod(&mut self, pod_uid: &str) -> Result<(), String> {
        self.pod_links.remove(pod_uid);
        debug!(pod_uid, "BPF programs detached for pod");
        Ok(())
    }

    fn update_pod_ip(&mut self, ip: Ipv4Addr, info: &PodInfo) -> Result<(), String> {
        let maps = self.maps.as_ref().ok_or("BPF maps not initialized")?;
        maps.insert_pod_ip(ip, info)
    }

    fn remove_pod_ip(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        let maps = self.maps.as_ref().ok_or("BPF maps not initialized")?;
        maps.remove_pod_ip(ip)
    }

    fn update_bypass_uid(&mut self, uid: u32) -> Result<(), String> {
        let maps = self.maps.as_ref().ok_or("BPF maps not initialized")?;
        maps.insert_bypass_uid(uid)
    }

    fn update_cidr_exclude(&mut self, cidr: &str) -> Result<(), String> {
        let maps = self.maps.as_ref().ok_or("BPF maps not initialized")?;
        maps.insert_cidr_exclude(cidr)
    }

    fn update_cidr_include(&mut self, cidr: &str) -> Result<(), String> {
        let maps = self.maps.as_ref().ok_or("BPF maps not initialized")?;
        maps.insert_cidr_include(cidr)
    }

    fn update_port_exclude(&mut self, port: u16) -> Result<(), String> {
        let maps = self.maps.as_ref().ok_or("BPF maps not initialized")?;
        maps.insert_port_exclude(port)
    }

    fn cleanup_all(&mut self) -> Result<(), String> {
        self.pod_links.clear();
        self.maps = None;
        self.bpf = None;
        info!("BPF programs and maps cleaned up");
        Ok(())
    }
}
