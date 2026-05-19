#![allow(dead_code)]
//! Host-side veth interface discovery for pod network namespaces.
//!
//! When a pod is enrolled for eBPF capture, the node agent attaches a tc/ingress
//! program to the host-side veth peer to redirect inbound packets. This module
//! resolves the veth interface name from the pod's network namespace.

#[cfg(target_os = "linux")]
use std::path::Path;

/// Discover the host-side veth interface for a pod by reading its network
/// namespace link index from `/proc/{pid}/net/` or sysfs.
///
/// Returns `None` if the interface cannot be determined (non-Linux or
/// missing procfs/sysfs entries).
pub fn discover_veth_for_pod(pod_pid: Option<u32>) -> Option<String> {
    #[cfg(test)]
    {
        if let Some(name) = tests::test_override() {
            return Some(name);
        }
    }

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
        if let Ok(index_str) = std::fs::read_to_string(&index_path)
            && let Ok(idx) = index_str.trim().parse::<u32>()
            && idx == ifindex
        {
            return Some(iface_name);
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        /// Test-only override consulted by `discover_veth_for_pod` before
        /// it tries procfs/sysfs. Set via [`TestOverrideGuard`] in tests
        /// that exercise `handle_pod_added` (or any other production code
        /// that calls `discover_veth_for_pod`) on a host that does not
        /// have the pod's network namespace materialised (which is every
        /// machine running `cargo test`). The guard restores the previous
        /// value on drop so concurrent tests stay isolated.
        static TEST_VETH_OVERRIDE: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    /// Read the current thread-local override (if any) without taking
    /// ownership. Called from the production path under `#[cfg(test)]`.
    pub(crate) fn test_override() -> Option<String> {
        TEST_VETH_OVERRIDE.with(|cell| cell.borrow().clone())
    }

    /// Drop guard that scopes a test-only veth override to a single test.
    /// Pin one of these on the stack before calling into production code
    /// that may invoke `discover_veth_for_pod`; previous value is restored
    /// when the guard drops, so nested overrides still work correctly.
    pub struct TestOverrideGuard {
        previous: Option<String>,
    }

    impl TestOverrideGuard {
        pub fn new(name: &str) -> Self {
            let previous = TEST_VETH_OVERRIDE.with(|cell| {
                let prev = cell.borrow().clone();
                *cell.borrow_mut() = Some(name.to_string());
                prev
            });
            Self { previous }
        }
    }

    impl Drop for TestOverrideGuard {
        fn drop(&mut self) {
            let previous = self.previous.take();
            TEST_VETH_OVERRIDE.with(|cell| {
                *cell.borrow_mut() = previous;
            });
        }
    }

    #[test]
    fn discover_veth_no_pid_returns_none() {
        assert!(discover_veth_for_pod(None).is_none());
    }

    #[test]
    fn discover_veth_nonexistent_pid() {
        assert!(discover_veth_for_pod(Some(999_999_999)).is_none());
    }

    #[test]
    fn discover_veth_test_override_takes_precedence() {
        let _guard = TestOverrideGuard::new("vethTEST");
        assert_eq!(discover_veth_for_pod(None).as_deref(), Some("vethTEST"));
        assert_eq!(
            discover_veth_for_pod(Some(999_999_999)).as_deref(),
            Some("vethTEST")
        );
    }
}
