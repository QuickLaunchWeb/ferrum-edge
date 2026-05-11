//! Ferrum Edge eBPF programs for ambient mesh traffic capture.
//!
//! Five programs implement transparent traffic interception:
//!
//! | Program             | Hook              | Purpose                              |
//! |---------------------|-------------------|--------------------------------------|
//! | `ferrum_connect4`   | cgroup/connect4   | Rewrite outbound IPv4 to loopback    |
//! | `ferrum_connect6`   | cgroup/connect6   | Rewrite outbound IPv6 to loopback    |
//! | `ferrum_getpeername4` | cgroup/getpeername4 | Return original IPv4 destination   |
//! | `ferrum_getpeername6` | cgroup/getpeername6 | Return original IPv6 destination   |
//! | `ferrum_tc_inbound` | tc/ingress        | Classify enrolled pod inbound traffic |
//!
//! Build: `cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release`

#![no_std]
#![no_main]

mod connect4;
mod connect6;
mod getpeername4;
mod getpeername6;
mod maps;
mod tc_inbound;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
