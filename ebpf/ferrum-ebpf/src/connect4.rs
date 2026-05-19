//! cgroup/connect4 — outbound IPv4 traffic capture.
//!
//! Intercepts `connect()` syscalls for IPv4 TCP from enrolled pods:
//! 1. Skip if calling UID is in the bypass set (proxy UID 1337)
//! 2. Skip if destination port is excluded
//! 3. Skip if destination IP matches an exclude CIDR
//! 4. Skip if include CIDRs are configured and destination doesn't match
//! 5. Skip if pod has `includeOutboundPorts` and dest port is NOT in the list
//! 6. Store original destination in `FERRUM_ORIG_DST4` keyed by socket cookie
//! 7. Rewrite destination to 127.0.0.1:15001 (outbound capture port)

use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::programs::SockAddrContext;
use aya_ebpf::EbpfContext;

use crate::maps::{
    FERRUM_BYPASS_UIDS, FERRUM_CAPTURE_CONFIG, FERRUM_CIDR_EXCLUDE4, FERRUM_CIDR_INCLUDE4,
    FERRUM_INCLUDE_PORTS, FERRUM_ORIG_DST4, FERRUM_PORT_EXCLUDE,
};
use ferrum_ebpf_common::{
    CidrKey4, IncludePortsPolicy, OrigDst4, OrigDstKey, FERRUM_CAPTURE_CONFIG_KEY,
    IPV4_LOOPBACK_NBO, OUTBOUND_CAPTURE_PORT,
};

#[cgroup_sock_addr(connect4)]
pub fn ferrum_connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_connect4(ctx: &SockAddrContext) -> Result<i32, i64> {
    let sock_addr = unsafe { &*ctx.sock_addr };

    let uid = (aya_ebpf::helpers::bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    if unsafe { FERRUM_BYPASS_UIDS.get(&uid) }.is_some() {
        return Ok(1);
    }

    let dst_ip = sock_addr.user_ip4;
    let dst_port = (sock_addr.user_port >> 16) as u16;

    if unsafe { FERRUM_PORT_EXCLUDE.get(&dst_port) }.is_some() {
        return Ok(1);
    }

    let exclude_key = LpmKey::new(32, CidrKey4::host(dst_ip));
    if FERRUM_CIDR_EXCLUDE4.get(&exclude_key).is_some() {
        return Ok(1);
    }

    let include_key = LpmKey::new(32, CidrKey4::host(dst_ip));
    if FERRUM_CIDR_INCLUDE4.get(&include_key).is_none() {
        return Ok(1);
    }

    if !include_port_allowed(dst_port) {
        return Ok(1);
    }

    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    let key = OrigDstKey { cookie };
    let orig = OrigDst4 {
        addr: dst_ip,
        port: dst_port as u32,
        pod_uid: [0; 16],
        workload_spiffe_hash: 0,
    };
    let _ = FERRUM_ORIG_DST4.insert(&key, &orig, 0);

    let sock_addr = unsafe { &mut *ctx.sock_addr };
    sock_addr.user_ip4 = IPV4_LOOPBACK_NBO;
    sock_addr.user_port = outbound_capture_port() << 16;

    Ok(1)
}

#[inline(always)]
fn outbound_capture_port() -> u32 {
    let key = FERRUM_CAPTURE_CONFIG_KEY;
    match unsafe { FERRUM_CAPTURE_CONFIG.get(&key) } {
        Some(config) if config.outbound_capture_port != 0 => config.outbound_capture_port & 0xffff,
        _ => OUTBOUND_CAPTURE_PORT as u32,
    }
}

/// Honor `traffic.sidecar.istio.io/includeOutboundPorts`. Returns `true`
/// when the connect should proceed to rewrite (either the pod has no
/// include-port narrowing, the policy is the `*` wildcard, or the dest
/// port is in the explicit allow-list). Lookup is keyed by the calling
/// task's cgroup id, so each annotated pod gets its own per-cgroup
/// policy.
#[inline(always)]
fn include_port_allowed(dst_port: u16) -> bool {
    let cgroup_id = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    let Some(policy) = (unsafe { FERRUM_INCLUDE_PORTS.get(&cgroup_id) }) else {
        // No per-cgroup policy means the pod is unannotated — preserve
        // the prior "capture everything that survived the earlier
        // checks" behavior.
        return true;
    };
    policy_admits_port(policy, dst_port)
}

#[inline(always)]
fn policy_admits_port(policy: &IncludePortsPolicy, dst_port: u16) -> bool {
    if policy.all_ports != 0 {
        return true;
    }
    let count = policy.port_count as usize;
    // Defensive fail-open: an entry without explicit ports and without the
    // wildcard flag is treated as "no narrowing". Userspace never writes
    // this shape but kernel-space should not silently drop traffic if the
    // map is ever populated unexpectedly.
    if count == 0 {
        return true;
    }
    let mut i = 0;
    while i < count && i < policy.ports.len() {
        if policy.ports[i] == dst_port {
            return true;
        }
        i += 1;
    }
    false
}
