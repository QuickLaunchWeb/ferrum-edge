//! Typed clients for driving [`super::harness::GatewayHarness`]-powered tests.
//!
//! Phase 1 ships HTTP/1.1. Phase 3 adds H3. Phase 4 adds UDP and DTLS.
//! H2/gRPC/WebSocket clients arrive in later phases (or are added by the
//! Phase 2 agent's PR alongside this one).

pub mod dtls;
pub mod http1;
pub mod http3;
pub mod udp;

pub use dtls::DtlsClient;
pub use http1::{ClientResponse, Http1Client};
pub use http3::{Http3Client, Http3Response};
pub use udp::UdpClient;
