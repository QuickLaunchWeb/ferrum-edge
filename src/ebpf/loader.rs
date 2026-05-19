//! aya-based eBPF program loader and attachment manager.
//!
//! `AyaEbpfBackend` implements `EbpfBackend` using the `aya` crate to load
//! BPF ELF bytes, attach programs to pod cgroups and veth interfaces, and
//! manage BPF map contents. Available only on Linux with `--features ebpf`.

#![allow(dead_code)]

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::collections::HashMap;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::fs::{self, File};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::net::Ipv4Addr;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::os::fd::AsFd;

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::programs::{CgroupSockAddr, SchedClassifier, SockOps, SockOpsLinkId, TcAttachType};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::{Ebpf, EbpfLoader};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use tracing::{debug, info, warn};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use super::maps::BpfMaps;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use super::{
    BPF_MAP_SOCK_OPS_EVENTS, BPF_MAP_SOCK_OPS_STATS, BPF_PROGRAM_SOCK_OPS,
    BPF_SOCK_OPS_EVENTS_PIN_PATH, BPF_SOCK_OPS_STATS_PIN_PATH, EbpfBackend, IncludePortsPolicy,
    PodInfo,
};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use ferrum_ebpf_common::{BpfCaptureConfig, SOCK_OPS_RINGBUF_DEFAULT_BYTES};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
const DEFAULT_BPF_ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/ebpf/target/bpfel-unknown-none/release/ferrum-ebpf"
);

#[cfg(all(feature = "ebpf", target_os = "linux"))]
const CGROUP_PROGRAMS: &[&str] = &[
    "ferrum_connect4",
    "ferrum_connect6",
    "ferrum_getpeername4",
    "ferrum_getpeername6",
];

#[cfg(all(feature = "ebpf", target_os = "linux"))]
const TC_PROGRAM: &str = "ferrum_tc_inbound";

/// Tracks per-pod attachment state for cleanup.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
struct PodLinks {
    cgroup_link_ids: Vec<aya::programs::CgroupSockAddrLinkId>,
    tc_link_ids: Vec<aya::programs::SchedClassifierLinkId>,
}

/// Real aya-backed eBPF loader. Only available on Linux with `--features ebpf`.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub struct AyaEbpfBackend {
    bpf: Option<Ebpf>,
    maps: Option<BpfMaps>,
    pod_links: HashMap<String, PodLinks>,
    /// Link id for the global SOCK_OPS attach. Set on first successful
    /// `attach_sock_ops`; cleared by `cleanup_all` (the link is detached
    /// implicitly when `Ebpf` is dropped, but holding the id lets future
    /// callers detach explicitly if needed).
    sock_ops_link_id: Option<SockOpsLinkId>,
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
impl AyaEbpfBackend {
    pub fn new() -> Self {
        Self {
            bpf: None,
            maps: None,
            pod_links: HashMap::new(),
            sock_ops_link_id: None,
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

#[cfg(all(feature = "ebpf", target_os = "linux"))]
impl EbpfBackend for AyaEbpfBackend {
    fn load_programs(&mut self) -> Result<(), String> {
        let bpf_elf_path =
            crate::config::conf_file::resolve_ferrum_var("FERRUM_NODE_AGENT_BPF_ELF_PATH")
                .unwrap_or_else(|| DEFAULT_BPF_ELF_PATH.to_string());
        let bpf_elf = fs::read(&bpf_elf_path)
            .map_err(|e| format!("Failed to read BPF ELF '{bpf_elf_path}': {e}"))?;

        // Size the SOCK_OPS event ringbuf from operator config. The kernel
        // baked a 4 MiB default into the ELF; `set_max_entries` rewrites
        // the descriptor at load time so the actual kernel object honors
        // FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES without rebuilding the ELF.
        let ringbuf_bytes = resolve_sock_ops_ringbuf_bytes();
        let mut bpf = EbpfLoader::new()
            .set_max_entries(BPF_MAP_SOCK_OPS_EVENTS, ringbuf_bytes)
            .load(&bpf_elf)
            .map_err(|e| format!("Failed to load BPF ELF: {e}"))?;

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

        // Load the SOCK_OPS observability program. Best-effort: failing
        // to load this program does NOT break capture — it only loses
        // TCP-layer telemetry. The attach + pin happens in
        // `attach_sock_ops`, which the node-agent calls once at startup.
        if let Some(prog_ref) = bpf.program_mut(BPF_PROGRAM_SOCK_OPS) {
            match TryInto::<&mut SockOps>::try_into(prog_ref) {
                Ok(prog) => {
                    if let Err(e) = prog.load() {
                        warn!(
                            program = BPF_PROGRAM_SOCK_OPS,
                            error = %e,
                            "Failed to load SOCK_OPS program (TCP-layer observability disabled)"
                        );
                    } else {
                        debug!(
                            program = BPF_PROGRAM_SOCK_OPS,
                            ringbuf_bytes, "BPF sock_ops program loaded"
                        );
                    }
                }
                Err(e) => warn!(
                    program = BPF_PROGRAM_SOCK_OPS,
                    error = %e,
                    "SOCK_OPS program type mismatch (TCP-layer observability disabled)"
                ),
            }
        } else {
            warn!(
                program = BPF_PROGRAM_SOCK_OPS,
                "SOCK_OPS program not present in ELF (TCP-layer observability disabled)"
            );
        }

        self.maps = Some(BpfMaps::from_ebpf(&bpf)?);
        self.bpf = Some(bpf);

        info!("All BPF programs loaded successfully");
        Ok(())
    }

    fn update_capture_config(&mut self, config: &BpfCaptureConfig) -> Result<(), String> {
        let maps = self.maps.as_ref().ok_or("BPF maps not initialized")?;
        maps.update_capture_config(config)
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

        debug!(program, cgroup_path, "BPF cgroup program attached");
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

        debug!(program, iface, "BPF tc program attached");
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

    fn update_pod_include_ports(
        &mut self,
        cgroup_id: u64,
        policy: &IncludePortsPolicy,
    ) -> Result<(), String> {
        let maps = self.maps.as_ref().ok_or("BPF maps not initialized")?;
        maps.insert_include_ports(cgroup_id, policy)
    }

    fn remove_pod_include_ports(&mut self, cgroup_id: u64) -> Result<(), String> {
        let maps = self.maps.as_ref().ok_or("BPF maps not initialized")?;
        maps.remove_include_ports(cgroup_id)
    }

    fn attach_sock_ops(&mut self, cgroup_root: &str) -> Result<(), String> {
        if self.sock_ops_link_id.is_some() {
            // Already attached — idempotent, no-op.
            return Ok(());
        }

        let cgroup_fd = File::open(cgroup_root)
            .map_err(|e| format!("Failed to open cgroup root '{cgroup_root}': {e}"))?;

        let bpf = self.bpf_mut()?;

        // Look up the program before we try to attach. The program may
        // not be present (load failed best-effort above) — that's
        // surfaced as a clean error instead of an unwrap panic.
        let Some(prog_ref) = bpf.program_mut(BPF_PROGRAM_SOCK_OPS) else {
            return Err(format!(
                "SOCK_OPS program '{BPF_PROGRAM_SOCK_OPS}' not loaded; cannot attach"
            ));
        };
        let prog: &mut SockOps = prog_ref
            .try_into()
            .map_err(|e| format!("'{BPF_PROGRAM_SOCK_OPS}' is not a SockOps program: {e}"))?;

        let link_id = prog
            .attach(cgroup_fd.as_fd())
            .map_err(|e| format!("Failed to attach SOCK_OPS to '{cgroup_root}': {e}"))?;

        // Pin BEFORE storing link_id so a pinning failure can detach the
        // program atomically. Without this, a pinning failure (bpffs not
        // mounted, ENOSPC, permission denied on /sys/fs/bpf/ferrum/) leaves
        // the SOCK_OPS program attached and burning kernel CPU on every TCP
        // socket op cluster-wide, while writing into a ringbuf no userspace
        // process can ever drain. Better to fail closed.
        if let Err(e) = pin_sock_ops_maps(bpf) {
            warn!(
                error = %e,
                "Failed to pin SOCK_OPS maps; detaching program to avoid leaking an unreachable ringbuf"
            );
            // Re-fetch prog_mut because the previous binding's borrow ended
            // when pin_sock_ops_maps returned (it took &mut Ebpf).
            if let Some(prog_ref) = bpf.program_mut(BPF_PROGRAM_SOCK_OPS) {
                if let Ok(prog) = TryInto::<&mut SockOps>::try_into(prog_ref) {
                    if let Err(detach_err) = prog.detach(link_id) {
                        warn!(
                            error = %detach_err,
                            "Best-effort detach of SOCK_OPS after pin failure also failed"
                        );
                    }
                }
            }
            return Err(e);
        }
        // Only record the link_id once pinning has succeeded — keeps the
        // recorded lifecycle state consistent with what's actually live.
        self.sock_ops_link_id = Some(link_id);

        info!(
            cgroup_root,
            pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
            "SOCK_OPS program attached and event ringbuf pinned"
        );
        Ok(())
    }

    fn cleanup_all(&mut self) -> Result<(), String> {
        self.pod_links.clear();
        self.sock_ops_link_id = None;
        self.maps = None;
        self.bpf = None;
        // Best-effort: unpin the SOCK_OPS maps so a stale pin doesn't
        // mislead a future mesh-proxy start. Missing pin is fine.
        let _ = fs::remove_file(BPF_SOCK_OPS_EVENTS_PIN_PATH);
        let _ = fs::remove_file(BPF_SOCK_OPS_STATS_PIN_PATH);
        info!("BPF programs and maps cleaned up");
        Ok(())
    }
}

/// Resolve `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` with the kernel-default
/// fallback. Invalid (non-numeric / zero / non-power-of-two) values are
/// rejected with a `warn!` and silently fall back to the default so the
/// gateway never refuses to start over an observability tuning knob.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn resolve_sock_ops_ringbuf_bytes() -> u32 {
    let Some(raw) =
        crate::config::conf_file::resolve_ferrum_var("FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES")
    else {
        return SOCK_OPS_RINGBUF_DEFAULT_BYTES;
    };
    // 256 MiB is a generous ceiling for a per-node TCP-event ringbuf.
    // Stops operator typos (e.g., 2147483648 instead of 4194304) from
    // claiming a gigabyte of locked kernel memory on every mesh-proxy
    // node. Plenty of headroom for high-traffic node-waypoints.
    const MAX_BYTES: u32 = 256 * 1024 * 1024;
    match raw.trim().parse::<u32>() {
        Ok(n) if n >= 4096 && n <= MAX_BYTES && n.is_power_of_two() => n,
        Ok(n) if n > MAX_BYTES => {
            warn!(
                value = n,
                max_bytes = MAX_BYTES,
                "FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES exceeds maximum supported size; using default {}",
                SOCK_OPS_RINGBUF_DEFAULT_BYTES
            );
            SOCK_OPS_RINGBUF_DEFAULT_BYTES
        }
        Ok(n) => {
            warn!(
                value = n,
                "FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES must be a power of two between 4096 and {}; using default {}",
                MAX_BYTES,
                SOCK_OPS_RINGBUF_DEFAULT_BYTES
            );
            SOCK_OPS_RINGBUF_DEFAULT_BYTES
        }
        Err(e) => {
            warn!(
                raw = %raw,
                error = %e,
                "FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES is not a valid u32; using default {}",
                SOCK_OPS_RINGBUF_DEFAULT_BYTES
            );
            SOCK_OPS_RINGBUF_DEFAULT_BYTES
        }
    }
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn pin_sock_ops_maps(bpf: &mut Ebpf) -> Result<(), String> {
    // Ensure the parent dir exists. /sys/fs/bpf must already be mounted
    // (bpffs); we only need to create the /ferrum subdirectory.
    if let Some(parent) = std::path::Path::new(BPF_SOCK_OPS_EVENTS_PIN_PATH).parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        return Err(format!(
            "Failed to create pin parent dir '{}': {e}",
            parent.display()
        ));
    }
    pin_map_at(bpf, BPF_MAP_SOCK_OPS_EVENTS, BPF_SOCK_OPS_EVENTS_PIN_PATH)?;
    pin_map_at(bpf, BPF_MAP_SOCK_OPS_STATS, BPF_SOCK_OPS_STATS_PIN_PATH)?;
    Ok(())
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn pin_map_at(bpf: &mut Ebpf, map_name: &str, pin_path: &str) -> Result<(), String> {
    // If a stale pin exists (e.g. previous run did not clean up), remove
    // it so the new map gets pinned fresh. Best-effort: missing path is
    // fine, only surface real errors.
    if std::path::Path::new(pin_path).exists()
        && let Err(e) = fs::remove_file(pin_path)
    {
        return Err(format!("Failed to remove stale pin '{pin_path}': {e}"));
    }
    let map = bpf
        .map_mut(map_name)
        .ok_or_else(|| format!("BPF map '{map_name}' not found"))?;
    map.pin(pin_path)
        .map_err(|e| format!("Failed to pin '{map_name}' at '{pin_path}': {e}"))
}
