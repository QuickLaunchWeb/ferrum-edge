//! Shared helpers for the mesh DNS proxy E2E perf harness.

pub mod dns_wire;
pub mod metrics;
pub mod slice;

pub mod proto {
    tonic::include_proto!("ferrum");
}

/// Synthetic mesh slice version stamp the stub publishes.
pub const STUB_SLICE_VERSION: &str = "perf-stub-v1";
