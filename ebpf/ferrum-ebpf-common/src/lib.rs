//! Shared types between Ferrum eBPF programs and userspace loader.
//!
//! All types are `#[repr(C)]` for BPF map compatibility and `Copy` since BPF
//! maps operate on raw bytes. Fields use fixed-width integers aligned to 4-byte
//! boundaries (BPF verifier requirement).

#![no_std]

/// Key for the `FERRUM_ORIG_DST4` / `FERRUM_ORIG_DST6` maps.
///
/// Uses `bpf_get_socket_cookie()` rather than a connection tuple because the
/// local port is not assigned at `connect()` time — the kernel picks it during
/// the syscall after the BPF hook runs. The proxy retrieves the cookie via
/// `getsockopt(SO_COOKIE)` to look up the original destination.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrigDstKey {
    pub cookie: u64,
}

/// Original IPv4 destination stored before connect rewrite.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrigDst4 {
    pub addr: u32,
    pub port: u32,
    /// Kubernetes pod UID encoded as raw UUID bytes. Zero means "unknown" and
    /// must be treated as fail-closed by node-waypoint identity resolution.
    pub pod_uid: [u8; 16],
    /// Stable first-eight-bytes SHA-256 hash of the workload SPIFFE ID.
    /// Zero means the node-agent did not attach a hash for this socket.
    pub workload_spiffe_hash: u64,
}

/// Original IPv6 destination stored before connect rewrite.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrigDst6 {
    pub addr: [u32; 4],
    pub port: u32,
    pub _pad: u32,
    /// Kubernetes pod UID encoded as raw UUID bytes. Zero means "unknown" and
    /// must be treated as fail-closed by node-waypoint identity resolution.
    pub pod_uid: [u8; 16],
    /// Stable first-eight-bytes SHA-256 hash of the workload SPIFFE ID.
    /// Zero means the node-agent did not attach a hash for this socket.
    pub workload_spiffe_hash: u64,
}

/// Pod metadata in the `FERRUM_POD_IPS` map, keyed by IPv4 address (`u32`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PodInfo {
    pub proxy_port: u32,
    pub _pad: u32,
}

/// Node-agent supplied capture settings in the `FERRUM_CAPTURE_CONFIG` map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BpfCaptureConfig {
    pub outbound_capture_port: u32,
    pub hbone_redirect_port: u32,
}

/// IPv4 address payload for `FERRUM_CIDR_INCLUDE` / `FERRUM_CIDR_EXCLUDE`.
///
/// Aya's LPM trie wrapper stores the leading `prefix_len` separately in
/// `aya_ebpf::maps::lpm_trie::Key`, so this shared payload intentionally holds
/// only address bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidrKey4 {
    pub addr: u32,
}

/// IPv6 address payload for LPM trie keys.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidrKey6 {
    pub addr: [u32; 4],
}

/// Outbound capture port. Connect hooks rewrite destinations here.
pub const OUTBOUND_CAPTURE_PORT: u16 = 15001;

/// Inbound HBONE port. TC ingress redirects inbound packets here.
pub const INBOUND_HBONE_PORT: u16 = 15008;

/// Singleton key for `FERRUM_CAPTURE_CONFIG`.
pub const FERRUM_CAPTURE_CONFIG_KEY: u32 = 0;

/// IPv4 loopback (127.0.0.1) stored as the `u32` the kernel's `user_ip4`
/// field expects (network byte order in memory).
pub const IPV4_LOOPBACK_NBO: u32 = u32::from_ne_bytes([127, 0, 0, 1]);

/// IPv6 loopback `[::1]` stored as the kernel's `user_ip6` expects (NBO).
pub const IPV6_LOOPBACK_NBO: [u32; 4] = [0, 0, 0, u32::from_ne_bytes([0, 0, 0, 1])];

impl CidrKey4 {
    /// Build an LPM key payload from a network-byte-order IPv4 address.
    pub const fn new(addr_nbo: u32) -> Self {
        Self { addr: addr_nbo }
    }

    /// Full /32 match for a single IPv4 address.
    pub const fn host(addr_nbo: u32) -> Self {
        Self::new(addr_nbo)
    }
}

impl CidrKey6 {
    pub const fn new(addr_nbo: [u32; 4]) -> Self {
        Self { addr: addr_nbo }
    }

    pub const fn host(addr_nbo: [u32; 4]) -> Self {
        Self::new(addr_nbo)
    }
}

impl BpfCaptureConfig {
    pub const fn new(outbound_capture_port: u16, hbone_redirect_port: u16) -> Self {
        Self {
            outbound_capture_port: outbound_capture_port as u32,
            hbone_redirect_port: hbone_redirect_port as u32,
        }
    }

    pub const fn default_ports() -> Self {
        Self::new(OUTBOUND_CAPTURE_PORT, INBOUND_HBONE_PORT)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::mem;

    #[test]
    fn type_sizes_are_bpf_aligned() {
        assert_eq!(mem::size_of::<OrigDstKey>(), 8);
        assert_eq!(mem::size_of::<OrigDst4>(), 32);
        assert_eq!(mem::size_of::<OrigDst6>(), 48);
        assert_eq!(mem::size_of::<PodInfo>(), 8);
        assert_eq!(mem::size_of::<BpfCaptureConfig>(), 8);
        assert_eq!(mem::size_of::<CidrKey4>(), 4);
        assert_eq!(mem::size_of::<CidrKey6>(), 16);
    }

    #[test]
    fn types_are_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<OrigDstKey>();
        assert_copy::<OrigDst4>();
        assert_copy::<OrigDst6>();
        assert_copy::<PodInfo>();
        assert_copy::<BpfCaptureConfig>();
        assert_copy::<CidrKey4>();
        assert_copy::<CidrKey6>();
    }

    #[test]
    fn cidr_key4_host() {
        let key = CidrKey4::host(0x0a000001);
        assert_eq!(key.addr, 0x0a000001);
    }

    #[test]
    fn cidr_key4_subnet() {
        let key = CidrKey4::new(0x0a000000);
        assert_eq!(key.addr, 0x0a000000);
    }

    #[test]
    fn cidr_key6_host() {
        let key = CidrKey6::host([0, 0, 0, u32::from_be(1)]);
        assert_eq!(key.addr, [0, 0, 0, u32::from_be(1)]);
    }

    #[test]
    fn ipv4_loopback_constant() {
        let bytes = IPV4_LOOPBACK_NBO.to_ne_bytes();
        assert_eq!(bytes, [127, 0, 0, 1]);
    }

    #[test]
    fn ipv6_loopback_constant() {
        assert_eq!(IPV6_LOOPBACK_NBO[0], 0);
        assert_eq!(IPV6_LOOPBACK_NBO[1], 0);
        assert_eq!(IPV6_LOOPBACK_NBO[2], 0);
        let last = IPV6_LOOPBACK_NBO[3].to_ne_bytes();
        assert_eq!(last, [0, 0, 0, 1]);
    }

    #[test]
    fn capture_config_defaults_match_public_ports() {
        let config = BpfCaptureConfig::default_ports();
        assert_eq!(config.outbound_capture_port, OUTBOUND_CAPTURE_PORT as u32);
        assert_eq!(config.hbone_redirect_port, INBOUND_HBONE_PORT as u32);
        assert_eq!(FERRUM_CAPTURE_CONFIG_KEY, 0);
    }
}
