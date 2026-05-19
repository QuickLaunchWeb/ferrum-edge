#![allow(dead_code)]
//! Host-side veth interface discovery for pod network namespaces.
//!
//! When a pod is enrolled for eBPF capture, the node agent attaches a tc/ingress
//! program to the host-side veth peer to redirect inbound packets. This module
//! resolves the veth interface name from the pod's network namespace.

#[cfg(target_os = "linux")]
use std::path::Path;

/// Discover the host-side veth interface for a pod by reading the pod-side
/// interface's peer ifindex from the pod's sysfs view, then resolving that
/// ifindex in the host network namespace.
///
/// When the Kubernetes watch path does not have an explicit process id, the
/// cgroup path is used to find a live process in the pod cgroup tree.
/// Returns `None` if the interface cannot be determined (non-Linux or missing
/// procfs/sysfs entries).
pub fn discover_veth_for_pod(pod_pid: Option<u32>, cgroup_path: Option<&str>) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if let Some(pid) = pod_pid
            && let Some(iface) = discover_veth_linux(pid)
        {
            return Some(iface);
        }

        cgroup_path.and_then(discover_veth_from_cgroup)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pod_pid;
        let _ = cgroup_path;
        None
    }
}

#[cfg(target_os = "linux")]
fn discover_veth_linux(pid: u32) -> Option<String> {
    let ifindex = read_pod_peer_ifindex(pid)?;
    resolve_iface_by_index(ifindex)
}

#[cfg(target_os = "linux")]
fn discover_veth_from_cgroup(cgroup_path: &str) -> Option<String> {
    let mut dirs = vec![Path::new(cgroup_path).to_path_buf()];
    let mut scanned_dirs = 0usize;

    while let Some(dir) = dirs.pop() {
        scanned_dirs += 1;
        if scanned_dirs > 1024 {
            break;
        }

        if let Ok(procs) = std::fs::read_to_string(dir.join("cgroup.procs")) {
            for pid in procs.split_whitespace().filter_map(|raw| raw.parse().ok()) {
                if let Some(iface) = discover_veth_linux(pid) {
                    return Some(iface);
                }
            }
        }

        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                dirs.push(entry.path());
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn read_pod_peer_ifindex(pid: u32) -> Option<u32> {
    let net_class = format!("/proc/{pid}/root/sys/class/net");
    read_pod_peer_ifindex_from_net_class(Path::new(&net_class))
}

/// Read the host peer interface index from the pod's network namespace sysfs.
///
/// `/proc/{pid}/net/*` exposes the pod-side interface index, not the host-side
/// veth peer. The pod-side sysfs `iflink` value points at the peer ifindex, so
/// resolve that value against host `/sys/class/net/*/ifindex`.
#[cfg(target_os = "linux")]
fn read_pod_peer_ifindex_from_net_class(net_class: &Path) -> Option<u32> {
    if let Some(peer) = read_peer_ifindex_for_iface(&net_class.join("eth0")) {
        return Some(peer);
    }

    for (_, iface_path) in sorted_non_primary_interfaces(net_class)? {
        if let Some(peer) = read_peer_ifindex_for_iface(&iface_path) {
            return Some(peer);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_peer_ifindex_for_iface(iface_path: &Path) -> Option<u32> {
    if !iface_path.exists() {
        return None;
    }
    let iflink = read_u32_from_file(&iface_path.join("iflink"))?;
    let ifindex = read_u32_from_file(&iface_path.join("ifindex"));
    if ifindex == Some(iflink) {
        return None;
    }
    Some(iflink)
}

#[cfg(target_os = "linux")]
fn sorted_non_primary_interfaces(net_class: &Path) -> Option<Vec<(String, std::path::PathBuf)>> {
    let mut entries = std::fs::read_dir(net_class)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let iface_name = entry.file_name().to_string_lossy().to_string();
            (iface_name != "lo" && iface_name != "eth0").then_some((iface_name, entry.path()))
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Some(entries)
}

#[cfg(target_os = "linux")]
fn read_u32_from_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Resolve a network interface name by its ifindex from sysfs.
#[cfg(target_os = "linux")]
fn resolve_iface_by_index(ifindex: u32) -> Option<String> {
    resolve_iface_by_index_in_sysfs(Path::new("/sys/class/net"), ifindex)
}

#[cfg(target_os = "linux")]
fn resolve_iface_by_index_in_sysfs(sysfs_net: &Path, ifindex: u32) -> Option<String> {
    let entries = std::fs::read_dir(sysfs_net).ok()?;
    for entry in entries.flatten() {
        let iface_name = entry.file_name().to_string_lossy().to_string();
        if read_u32_from_file(&entry.path().join("ifindex")) == Some(ifindex) {
            return Some(iface_name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use tempfile::tempdir;

    #[cfg(target_os = "linux")]
    fn write(path: &Path, value: &str) {
        std::fs::write(path, value).unwrap();
    }

    #[test]
    fn discover_veth_no_pid_returns_none() {
        assert!(discover_veth_for_pod(None, None).is_none());
    }

    #[test]
    fn discover_veth_nonexistent_pid() {
        assert!(discover_veth_for_pod(Some(999_999_999), None).is_none());
    }

    #[test]
    fn discover_veth_nonexistent_cgroup_returns_none() {
        assert!(discover_veth_for_pod(None, Some("/definitely/not/a/cgroup")).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_pod_peer_ifindex_uses_iflink_not_pod_ifindex() {
        let dir = tempdir().unwrap();
        let net = dir.path();
        std::fs::create_dir(net.join("lo")).unwrap();
        write(&net.join("lo/ifindex"), "1\n");
        write(&net.join("lo/iflink"), "1\n");

        std::fs::create_dir(net.join("eth0")).unwrap();
        write(&net.join("eth0/ifindex"), "7\n");
        write(&net.join("eth0/iflink"), "42\n");

        assert_eq!(read_pod_peer_ifindex_from_net_class(net), Some(42));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_pod_peer_ifindex_skips_non_veth_like_self_links() {
        let dir = tempdir().unwrap();
        let net = dir.path();
        std::fs::create_dir(net.join("eth0")).unwrap();
        write(&net.join("eth0/ifindex"), "7\n");
        write(&net.join("eth0/iflink"), "7\n");

        assert_eq!(read_pod_peer_ifindex_from_net_class(net), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_pod_peer_ifindex_prefers_eth0_over_secondary_interfaces() {
        let dir = tempdir().unwrap();
        let net = dir.path();
        std::fs::create_dir(net.join("net1")).unwrap();
        write(&net.join("net1/ifindex"), "11\n");
        write(&net.join("net1/iflink"), "99\n");

        std::fs::create_dir(net.join("eth0")).unwrap();
        write(&net.join("eth0/ifindex"), "7\n");
        write(&net.join("eth0/iflink"), "42\n");

        assert_eq!(read_pod_peer_ifindex_from_net_class(net), Some(42));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_iface_by_index_uses_host_ifindex() {
        let dir = tempdir().unwrap();
        let net = dir.path();
        std::fs::create_dir(net.join("vethabc")).unwrap();
        write(&net.join("vethabc/ifindex"), "42\n");
        std::fs::create_dir(net.join("cni0")).unwrap();
        write(&net.join("cni0/ifindex"), "9\n");

        assert_eq!(
            resolve_iface_by_index_in_sysfs(net, 42).as_deref(),
            Some("vethabc")
        );
    }
}
