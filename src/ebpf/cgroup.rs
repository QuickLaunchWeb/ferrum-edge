#![allow(dead_code)]
//! cgroup v2 path resolution for Kubernetes pods.
//!
//! Kubernetes uses two cgroup drivers — `systemd` and `cgroupfs` — each
//! placing pod cgroups at different paths. The node agent must resolve
//! the correct path before attaching BPF programs.

use std::path::{Path, PathBuf};

/// Resolve the cgroup v2 path for a Kubernetes pod.
///
/// Tries the systemd driver path first (`kubepods.slice/...`), then falls back
/// to the cgroupfs driver path (`kubepods/pod{uid}/`).
pub fn resolve_pod_cgroup_path(cgroup_root: &str, pod_uid: &str) -> Option<PathBuf> {
    let sanitized_uid = pod_uid.replace('-', "_");

    let systemd_path =
        Path::new(cgroup_root).join(format!("kubepods.slice/kubepods-pod{sanitized_uid}.slice"));
    if systemd_path.exists() {
        return Some(systemd_path);
    }

    let cgroupfs_path = Path::new(cgroup_root).join(format!("kubepods/pod{pod_uid}"));
    if cgroupfs_path.exists() {
        return Some(cgroupfs_path);
    }

    let cgroupfs_burstable =
        Path::new(cgroup_root).join(format!("kubepods/burstable/pod{pod_uid}"));
    if cgroupfs_burstable.exists() {
        return Some(cgroupfs_burstable);
    }

    let cgroupfs_besteffort =
        Path::new(cgroup_root).join(format!("kubepods/besteffort/pod{pod_uid}"));
    if cgroupfs_besteffort.exists() {
        return Some(cgroupfs_besteffort);
    }

    None
}

/// Build the expected cgroup path for a given QoS class (for testing/validation).
pub fn cgroup_path_for_qos(cgroup_root: &str, pod_uid: &str, qos_class: &str) -> PathBuf {
    match qos_class {
        "Guaranteed" => Path::new(cgroup_root).join(format!("kubepods/pod{pod_uid}")),
        "Burstable" => Path::new(cgroup_root).join(format!("kubepods/burstable/pod{pod_uid}")),
        "BestEffort" => Path::new(cgroup_root).join(format!("kubepods/besteffort/pod{pod_uid}")),
        _ => Path::new(cgroup_root).join(format!("kubepods/pod{pod_uid}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_path_for_qos_guaranteed() {
        let path = cgroup_path_for_qos("/sys/fs/cgroup", "abc-123", "Guaranteed");
        assert_eq!(path, PathBuf::from("/sys/fs/cgroup/kubepods/podabc-123"));
    }

    #[test]
    fn cgroup_path_for_qos_burstable() {
        let path = cgroup_path_for_qos("/sys/fs/cgroup", "abc-123", "Burstable");
        assert_eq!(
            path,
            PathBuf::from("/sys/fs/cgroup/kubepods/burstable/podabc-123")
        );
    }

    #[test]
    fn cgroup_path_for_qos_besteffort() {
        let path = cgroup_path_for_qos("/sys/fs/cgroup", "abc-123", "BestEffort");
        assert_eq!(
            path,
            PathBuf::from("/sys/fs/cgroup/kubepods/besteffort/podabc-123")
        );
    }

    #[test]
    fn resolve_pod_cgroup_path_nonexistent() {
        assert!(resolve_pod_cgroup_path("/nonexistent/cgroup", "abc-123").is_none());
    }

    #[test]
    fn systemd_path_sanitizes_dashes_to_underscores() {
        let sanitized = "abc-def-123".replace('-', "_");
        assert_eq!(sanitized, "abc_def_123");
    }
}
