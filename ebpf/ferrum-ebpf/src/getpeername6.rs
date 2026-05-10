//! cgroup/getpeername6 — return original IPv6 destination.
//!
//! Same as getpeername4 but for IPv6 sockets.

use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::programs::SockAddrContext;

use crate::maps::FERRUM_ORIG_DST6;
use ferrum_ebpf_common::OrigDstKey;

#[cgroup_sock_addr(getpeername6)]
pub fn ferrum_getpeername6(ctx: SockAddrContext) -> i32 {
    match try_getpeername6(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_getpeername6(ctx: &SockAddrContext) -> Result<i32, i64> {
    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    let key = OrigDstKey { cookie };

    if let Some(orig) = unsafe { FERRUM_ORIG_DST6.get(&key) } {
        let sock_addr = unsafe { &mut *ctx.sock_addr };
        sock_addr.user_ip6 = orig.addr;
        sock_addr.user_port = (orig.port as u32) << 16;
    }

    Ok(1)
}
