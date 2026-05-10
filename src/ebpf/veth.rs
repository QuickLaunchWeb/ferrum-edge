#![allow(dead_code)]
//! Host-side veth interface discovery for pod network namespaces.
//!
//! When a pod is enrolled for eBPF capture, the node agent attaches a tc/ingress
//! program to the host-side veth peer to redirect inbound packets. This module
//! resolves the veth interface name from the pod's network namespace.

/// Discover the host-side veth interface for a pod by reading its network
/// namespace link index from `/proc/{pid}/net/` or sysfs.
///
/// Returns `None` if the interface cannot be determined (non-Linux or
/// missing procfs/sysfs entries).
pub fn discover_veth_for_pod(pod_pid: Option<u32>) -> Option<String> {
    let pid = pod_pid?;

    #[cfg(target_os = "linux")]
    {
        discover_veth_linux(pid)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "linux")]
fn discover_veth_linux(pid: u32) -> Option<String> {
    let ifindex = read_pod_peer_ifindex(pid)?;
    resolve_iface_by_index(ifindex)
}

/// Read the peer interface index from the pod's network namespace.
///
/// Parses `/proc/{pid}/net/dev` is not sufficient (it shows the pod-side names).
/// Instead we look at `/sys/class/net/` on the host for a veth whose ifindex
/// matches the peer.
#[cfg(target_os = "linux")]
fn read_pod_peer_ifindex(pid: u32) -> Option<u32> {
    let net_path = format!("/proc/{pid}/net/if_inet6");
    let content = std::fs::read_to_string(&net_path).ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 6 && fields[5] != "lo" {
            return fields[1].parse::<u32>().ok();
        }
    }
    None
}

/// Resolve a network interface name by its ifindex from sysfs.
#[cfg(target_os = "linux")]
fn resolve_iface_by_index(ifindex: u32) -> Option<String> {
    let sysfs_net = Path::new("/sys/class/net");
    let entries = std::fs::read_dir(sysfs_net).ok()?;
    for entry in entries.flatten() {
        let iface_name = entry.file_name().to_string_lossy().to_string();
        let index_path = entry.path().join("ifindex");
        if let Ok(index_str) = std::fs::read_to_string(&index_path) {
            if let Ok(idx) = index_str.trim().parse::<u32>() {
                if idx == ifindex {
                    return Some(iface_name);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_veth_no_pid_returns_none() {
        assert!(discover_veth_for_pod(None).is_none());
    }

    #[test]
    fn discover_veth_nonexistent_pid() {
        assert!(discover_veth_for_pod(Some(999_999_999)).is_none());
    }
}
