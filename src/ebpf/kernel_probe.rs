#![allow(dead_code)]
//! Runtime kernel detection for eBPF capability probing.
//!
//! The node agent checks kernel version and cgroup v2 availability before
//! attempting BPF program loading. On kernels < 5.7 (or when cgroup v2 is
//! unavailable) the agent falls back to iptables or exits, depending on
//! `FERRUM_NODE_AGENT_FALLBACK_MODE`.

use std::path::Path;

/// Minimum kernel version required for cgroup-based eBPF capture.
pub const MIN_KERNEL_MAJOR: u32 = 5;
pub const MIN_KERNEL_MINOR: u32 = 7;

/// Kernel capability probe result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelProbeResult {
    pub kernel_release: String,
    pub meets_version_requirement: bool,
    pub cgroup_v2_available: bool,
    pub bpf_fs_available: bool,
}

impl KernelProbeResult {
    pub fn supports_ebpf(&self) -> bool {
        self.meets_version_requirement && self.cgroup_v2_available && self.bpf_fs_available
    }
}

/// Probe the running kernel for eBPF capture prerequisites.
pub fn probe_kernel(cgroup_root: &str, bpf_fs_path: &str) -> KernelProbeResult {
    let kernel_release = read_kernel_release();
    let meets_version_requirement = check_kernel_version(&kernel_release);
    let cgroup_v2_available = check_cgroup_v2(cgroup_root);
    let bpf_fs_available = check_bpf_fs(bpf_fs_path);

    KernelProbeResult {
        kernel_release,
        meets_version_requirement,
        cgroup_v2_available,
        bpf_fs_available,
    }
}

fn read_kernel_release() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        "non-linux".to_string()
    }
}

fn check_kernel_version(release: &str) -> bool {
    !crate::capture::should_fallback_to_iptables(release)
}

fn check_cgroup_v2(cgroup_root: &str) -> bool {
    let cgroup_type_path = Path::new(cgroup_root).join("cgroup.type");
    let cgroup_procs_path = Path::new(cgroup_root).join("cgroup.procs");
    cgroup_type_path.exists() || cgroup_procs_path.exists()
}

fn check_bpf_fs(bpf_fs_path: &str) -> bool {
    Path::new(bpf_fs_path).is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_version_check_uses_capture_module() {
        assert!(!check_kernel_version("4.19.0"));
        assert!(!check_kernel_version("5.4.0"));
        assert!(check_kernel_version("5.7.0"));
        assert!(check_kernel_version("5.15.0"));
        assert!(check_kernel_version("6.6.12"));
    }

    #[test]
    fn kernel_version_check_unparseable() {
        assert!(!check_kernel_version("unknown"));
        assert!(!check_kernel_version(""));
    }

    #[test]
    fn probe_result_supports_ebpf_all_true() {
        let result = KernelProbeResult {
            kernel_release: "6.1.0".to_string(),
            meets_version_requirement: true,
            cgroup_v2_available: true,
            bpf_fs_available: true,
        };
        assert!(result.supports_ebpf());
    }

    #[test]
    fn probe_result_missing_cgroup_v2() {
        let result = KernelProbeResult {
            kernel_release: "6.1.0".to_string(),
            meets_version_requirement: true,
            cgroup_v2_available: false,
            bpf_fs_available: true,
        };
        assert!(!result.supports_ebpf());
    }

    #[test]
    fn probe_result_old_kernel() {
        let result = KernelProbeResult {
            kernel_release: "4.19.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: true,
            bpf_fs_available: true,
        };
        assert!(!result.supports_ebpf());
    }

    #[test]
    fn check_cgroup_v2_nonexistent_path() {
        assert!(!check_cgroup_v2("/nonexistent/cgroup/path"));
    }

    #[test]
    fn check_bpf_fs_nonexistent_path() {
        assert!(!check_bpf_fs("/nonexistent/bpf/path"));
    }
}
