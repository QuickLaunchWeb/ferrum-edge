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

/// Maximum number of explicit `includeOutboundPorts` ports the per-cgroup
/// BPF gate supports. Sized to cover normal pod annotations (typically 1-5
/// ports). Pods exceeding this cap fall through to capture-all behavior so
/// the gate degrades gracefully instead of silently dropping ports — the
/// userspace loader emits a `warn!` when truncation happens.
pub const INCLUDE_PORTS_MAX: usize = 16;

/// Per-cgroup outbound `includeOutboundPorts` policy in the
/// `FERRUM_INCLUDE_PORTS` map, keyed by cgroup id (`bpf_get_current_cgroup_id`).
///
/// Semantics:
/// - No entry for a cgroup → no narrowing, capture every TCP port (preserves
///   pre-existing un-annotated pod behavior).
/// - Entry with `all_ports == 1` → matches the `*` wildcard annotation;
///   capture every port. `port_count` is ignored in this case.
/// - Entry with `all_ports == 0` and `port_count > 0` → capture only those
///   ports; everything else returns from the connect hook without rewrite.
/// - Entry with `all_ports == 0` and `port_count == 0` → fail-open, behaves
///   like "no entry" (the userspace side should not write this shape; the
///   BPF program tolerates it defensively).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncludePortsPolicy {
    /// Non-zero means "capture all outbound ports" (the `*` wildcard).
    /// `u32` to keep the struct 4-byte aligned for the BPF verifier.
    pub all_ports: u32,
    /// Number of valid entries in `ports`. Always `<= INCLUDE_PORTS_MAX`.
    pub port_count: u32,
    /// Sorted ascending. Trailing entries beyond `port_count` are ignored
    /// and may be uninitialized in flight.
    pub ports: [u16; INCLUDE_PORTS_MAX],
}

impl IncludePortsPolicy {
    /// Construct a `*`-style "capture all ports" policy.
    pub const fn all() -> Self {
        Self {
            all_ports: 1,
            port_count: 0,
            ports: [0u16; INCLUDE_PORTS_MAX],
        }
    }

    /// Construct an explicit-ports policy. Caller must have already sorted
    /// and deduped `ports`; truncates at `INCLUDE_PORTS_MAX` (the userspace
    /// side warns when this happens).
    pub fn explicit(ports: &[u16]) -> Self {
        let mut storage = [0u16; INCLUDE_PORTS_MAX];
        let count = ports.len().min(INCLUDE_PORTS_MAX);
        for (slot, value) in storage.iter_mut().zip(ports.iter().take(count)) {
            *slot = *value;
        }
        Self {
            all_ports: 0,
            port_count: count as u32,
            ports: storage,
        }
    }

    /// `true` when this entry encodes the `*` wildcard.
    pub const fn is_all_ports(&self) -> bool {
        self.all_ports != 0
    }
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

/// Single SOCK_OPS event record published by the kernel-side
/// `BPF_PROG_TYPE_SOCK_OPS` program over the ringbuf and consumed by the
/// userspace `SockOpsConsumer`. Fixed-width fields for stable BPF wire
/// shape; the userspace decoder maps this into the `SockOpsEvent` enum.
///
/// `event_type` selects which variant the record carries; meaning of the
/// remaining fields depends on the variant — see the `SOCK_OPS_EVENT_*`
/// constants. `_pad` keeps the struct 8-byte aligned for the BPF verifier.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockOpsRecord {
    /// One of the `SOCK_OPS_EVENT_*` constants.
    pub event_type: u32,
    /// Direction when meaningful (`SOCK_OPS_DIRECTION_*`); zero otherwise.
    pub direction: u32,
    /// Drop reason when `event_type == SOCK_OPS_EVENT_DROP_REASON`
    /// (`SOCK_OPS_DROP_*`); zero otherwise.
    pub drop_reason: u32,
    pub _pad: u32,
    /// Payload value for latency / RTT variants in microseconds. Zero for
    /// pure event types (connect, accept_established, rst, fin).
    pub value: u64,
}

// `SockOpsRecord::event_type` discriminants. Matches the
// `SockOpsEvent` enum on the userspace side.
pub const SOCK_OPS_EVENT_CONNECT: u32 = 1;
pub const SOCK_OPS_EVENT_ACCEPT_ESTABLISHED: u32 = 2;
pub const SOCK_OPS_EVENT_RST: u32 = 3;
pub const SOCK_OPS_EVENT_FIN: u32 = 4;
pub const SOCK_OPS_EVENT_RTT_SAMPLE: u32 = 5;
pub const SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY: u32 = 6;
pub const SOCK_OPS_EVENT_ACCEPT_TO_FIRST_BYTE_LATENCY: u32 = 7;
pub const SOCK_OPS_EVENT_DROP_REASON: u32 = 8;

// `SockOpsRecord::direction` values. Zero is "unused".
pub const SOCK_OPS_DIRECTION_SENT: u32 = 1;
pub const SOCK_OPS_DIRECTION_RECEIVED: u32 = 2;

// `SockOpsRecord::drop_reason` values. Zero is "unused".
pub const SOCK_OPS_DROP_BYPASS_UID_HIT: u32 = 1;
pub const SOCK_OPS_DROP_EXCLUDE_CIDR_HIT: u32 = 2;
pub const SOCK_OPS_DROP_NOT_IN_INCLUDE_CIDR: u32 = 3;
pub const SOCK_OPS_DROP_EXCLUDE_PORT_HIT: u32 = 4;

/// Default ringbuf byte size (4 MiB) used when
/// `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` is unset. Must be a power of two.
pub const SOCK_OPS_RINGBUF_DEFAULT_BYTES: u32 = 4 * 1024 * 1024;

/// `FERRUM_SOCK_OPS_STATS` index for "events dropped because the ringbuf
/// could not be reserved". Userspace polls this counter periodically; when
/// it advances between polls, [`SockOpsConsumer::record_overrun`] fires.
pub const SOCK_OPS_STATS_EVENTS_DROPPED: u32 = 0;
/// Length of `FERRUM_SOCK_OPS_STATS` array map.
pub const SOCK_OPS_STATS_LEN: u32 = 1;

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
        // IncludePortsPolicy: two u32 (8) + [u16; INCLUDE_PORTS_MAX] (32) = 40 bytes, 4-byte aligned.
        assert_eq!(
            mem::size_of::<IncludePortsPolicy>(),
            8 + 2 * INCLUDE_PORTS_MAX
        );
        assert_eq!(mem::align_of::<IncludePortsPolicy>(), 4);
        // SockOpsRecord: four u32 (16) + one u64 (8) = 24 bytes, 8-byte aligned.
        assert_eq!(mem::size_of::<SockOpsRecord>(), 24);
        assert_eq!(mem::align_of::<SockOpsRecord>(), 8);
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
        assert_copy::<IncludePortsPolicy>();
        assert_copy::<SockOpsRecord>();
    }

    #[test]
    fn include_ports_policy_all_sentinel() {
        let policy = IncludePortsPolicy::all();
        assert!(policy.is_all_ports());
        assert_eq!(policy.port_count, 0);
    }

    #[test]
    fn include_ports_policy_explicit_within_cap() {
        let policy = IncludePortsPolicy::explicit(&[80, 443, 5432]);
        assert!(!policy.is_all_ports());
        assert_eq!(policy.port_count, 3);
        assert_eq!(&policy.ports[..3], &[80, 443, 5432]);
        // Trailing slots remain zero so the kernel sees a well-defined struct.
        assert!(policy.ports[3..].iter().all(|&p| p == 0));
    }

    #[test]
    fn include_ports_policy_truncates_at_cap() {
        let mut ports = [0u16; INCLUDE_PORTS_MAX + 4];
        for (i, slot) in ports.iter_mut().enumerate() {
            *slot = (i as u16) + 1;
        }
        let policy = IncludePortsPolicy::explicit(&ports);
        assert_eq!(policy.port_count as usize, INCLUDE_PORTS_MAX);
        // First INCLUDE_PORTS_MAX entries preserved, rest dropped.
        for i in 0..INCLUDE_PORTS_MAX {
            assert_eq!(policy.ports[i], ports[i]);
        }
    }

    #[test]
    fn include_ports_policy_empty_is_fail_open_shape() {
        let policy = IncludePortsPolicy::explicit(&[]);
        assert!(!policy.is_all_ports());
        assert_eq!(policy.port_count, 0);
        assert!(policy.ports.iter().all(|&p| p == 0));
    }

    #[test]
    fn sock_ops_default_ringbuf_size_is_power_of_two() {
        assert!(SOCK_OPS_RINGBUF_DEFAULT_BYTES.is_power_of_two());
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
