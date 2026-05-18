//! Shared helpers for the mesh DNS proxy E2E perf harness.

pub mod dns_wire;
pub mod metrics;
pub mod slice;

pub mod proto {
    tonic::include_proto!("ferrum");
}

/// Default mesh DNS proxy listener (must match
/// `src/modes/mesh/mod.rs::DEFAULT_DNS_LISTEN_ADDR`). The harness assumes
/// the gateway is reachable on this address.
pub const DEFAULT_GATEWAY_DNS_ADDR: &str = "127.0.0.1:15053";

/// Synthetic mesh slice version stamp the stub publishes.
pub const STUB_SLICE_VERSION: &str = "perf-stub-v1";

/// The CP/DP JWT issuer the stub claims. Must match
/// `crate::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER` in the gateway.
pub const STUB_JWT_ISSUER: &str = "ferrum-edge-cp-dp";
