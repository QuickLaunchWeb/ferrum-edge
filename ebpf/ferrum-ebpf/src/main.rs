//! Ferrum Edge eBPF programs for ambient mesh traffic capture.
//!
//! Six programs implement transparent traffic interception plus TCP-layer
//! observability:
//!
//! | Program             | Hook              | Purpose                              |
//! |---------------------|-------------------|--------------------------------------|
//! | `ferrum_connect4`   | cgroup/connect4   | Rewrite outbound IPv4 to loopback    |
//! | `ferrum_connect6`   | cgroup/connect6   | Rewrite outbound IPv6 to loopback    |
//! | `ferrum_getpeername4` | cgroup/getpeername4 | Return original IPv4 destination   |
//! | `ferrum_getpeername6` | cgroup/getpeername6 | Return original IPv6 destination   |
//! | `ferrum_tc_inbound` | tc/ingress        | Classify enrolled pod inbound traffic |
//! | `ferrum_sock_ops`   | sock_ops (cgroup) | TCP-layer events (connect/accept/FIN/RST/RTT) for node-waypoint observability |
//!
//! Build: `cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release`

#![no_std]
#![no_main]

mod connect4;
mod connect6;
mod getpeername4;
mod getpeername6;
mod maps;
mod sock_ops;
mod tc_inbound;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
