//! Scripted backends used by [`super::harness::GatewayHarness`] tests.
//!
//! Each submodule provides a server that accepts a deterministic script of
//! wire-level steps, so tests can reproduce specific failure modes
//! (connection refused, TLS cert expired, body truncated mid-stream, H2
//! stream reset mid-response, gRPC trailers missing, etc.) without reaching
//! for `std::process::Command` or brittle timing.
//!
//! - [`tcp`] — raw TCP
//! - [`tls`] — TLS-terminating wrapper around TCP (includes ALPN scripting)
//! - [`http1`] — HTTP/1.1-aware wrapper around TCP (parses requests, knows
//!   how to split responses)
//! - [`http2`] — HTTP/2 (h2 crate server) for frame-level scripting: GOAWAY,
//!   RST_STREAM, flow-control stalls, etc.
//! - [`grpc`] — gRPC framing on top of [`http2`]: length-prefixed messages,
//!   `grpc-status` trailers, missing-trailer fallbacks.

pub mod grpc;
pub mod http1;
pub mod http2;
pub mod tcp;
pub mod tls;

pub use grpc::{GrpcStep, MatchRpc, ScriptedGrpcBackend, ScriptedGrpcBackendBuilder};
pub use http1::{HttpStep, Request as Http1Request, RequestMatcher, ScriptedHttp1Backend};
pub use http2::{
    ConnectionSettings, H2Step, MatchHeaders, ReceivedStream, ScriptedH2Backend,
    ScriptedH2BackendBuilder,
};
pub use tcp::{ExecutionMode, ScriptedTcpBackend, TcpStep};
pub use tls::{ScriptedTlsBackend, TlsConfig};
