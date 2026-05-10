//! cgroup/connect6 — outbound IPv6 traffic capture.
//!
//! Same logic as connect4 but for IPv6. Rewrites destination to [::1]:15001.

use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::programs::SockAddrContext;

use crate::maps::{
    FERRUM_BYPASS_UIDS, FERRUM_CIDR_EXCLUDE6, FERRUM_CIDR_INCLUDE6, FERRUM_ORIG_DST6,
    FERRUM_PORT_EXCLUDE,
};
use ferrum_ebpf_common::{
    CidrKey6, OrigDst6, OrigDstKey, IPV6_LOOPBACK_NBO, OUTBOUND_CAPTURE_PORT,
};

#[cgroup_sock_addr(connect6)]
pub fn ferrum_connect6(ctx: SockAddrContext) -> i32 {
    match try_connect6(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_connect6(ctx: &SockAddrContext) -> Result<i32, i64> {
    let sock_addr = unsafe { &*ctx.sock_addr };

    let uid = (unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() } & 0xFFFFFFFF) as u32;
    if unsafe { FERRUM_BYPASS_UIDS.get(&uid) }.is_some() {
        return Ok(1);
    }

    let dst_ip = sock_addr.user_ip6;
    let dst_port = (sock_addr.user_port >> 16) as u16;

    if unsafe { FERRUM_PORT_EXCLUDE.get(&dst_port) }.is_some() {
        return Ok(1);
    }

    let exclude_key = CidrKey6::host(dst_ip);
    if unsafe { FERRUM_CIDR_EXCLUDE6.get(&exclude_key) }.is_some() {
        return Ok(1);
    }

    let include_key = CidrKey6::host(dst_ip);
    if unsafe { FERRUM_CIDR_INCLUDE6.get(&include_key) }.is_none() {
        return Ok(1);
    }

    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    let key = OrigDstKey { cookie };
    let orig = OrigDst6 {
        addr: dst_ip,
        port: dst_port as u32,
        _pad: 0,
    };
    let _ = unsafe { FERRUM_ORIG_DST6.insert(&key, &orig, 0) };

    let sock_addr = unsafe { &mut *ctx.sock_addr };
    sock_addr.user_ip6 = IPV6_LOOPBACK_NBO;
    sock_addr.user_port = (OUTBOUND_CAPTURE_PORT as u32) << 16;

    Ok(1)
}
