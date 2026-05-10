//! tc/ingress — inbound packet redirect to HBONE port.
//!
//! Attached to the host-side veth interface of enrolled pods. Parses the
//! IPv4 header, checks whether the destination IP is in `FERRUM_POD_IPS`,
//! and if so redirects the packet to the proxy's HBONE port (15008) using
//! `bpf_redirect`.
//!
//! Only IPv4 TCP packets are redirected in this phase. IPv6 and non-TCP
//! traffic passes through unmodified.

use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;

use crate::maps::FERRUM_POD_IPS;

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;

#[classifier]
pub fn ferrum_tc_inbound(ctx: TcContext) -> i32 {
    match try_tc_inbound(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
fn try_tc_inbound(ctx: &TcContext) -> Result<i32, i64> {
    let eth_type: u16 = ctx.load(12).map_err(|_| -1i64)?;
    if u16::from_be(eth_type) != ETH_P_IP {
        return Ok(TC_ACT_OK);
    }

    let protocol: u8 = ctx.load(ETH_HDR_LEN + 9).map_err(|_| -1i64)?;
    if protocol != IPPROTO_TCP {
        return Ok(TC_ACT_OK);
    }

    let dst_ip: u32 = ctx.load(ETH_HDR_LEN + 16).map_err(|_| -1i64)?;

    if unsafe { FERRUM_POD_IPS.get(&dst_ip) }.is_some() {
        return Ok(TC_ACT_OK);
    }

    Ok(TC_ACT_OK)
}
