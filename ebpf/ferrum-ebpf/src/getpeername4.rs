//! cgroup/getpeername4 — return original IPv4 destination.
//!
//! When a process calls `getpeername()`, this hook looks up the socket cookie
//! in `FERRUM_ORIG_DST4` and replaces the returned address (which would be
//! 127.0.0.1:15001) with the original destination. This lets the proxy
//! discover the real target without `SO_ORIGINAL_DST`.

use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::programs::SockAddrContext;

use crate::maps::FERRUM_ORIG_DST4;
use ferrum_ebpf_common::OrigDstKey;

#[cgroup_sock_addr(getpeername4)]
pub fn ferrum_getpeername4(ctx: SockAddrContext) -> i32 {
    match try_getpeername4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_getpeername4(ctx: &SockAddrContext) -> Result<i32, i64> {
    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    let key = OrigDstKey { cookie };

    if let Some(orig) = unsafe { FERRUM_ORIG_DST4.get(&key) } {
        let sock_addr = unsafe { &mut *ctx.sock_addr };
        sock_addr.user_ip4 = orig.addr;
        sock_addr.user_port = (orig.port as u32) << 16;
    }

    Ok(1)
}
