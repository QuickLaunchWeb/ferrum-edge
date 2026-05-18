//! Shared helpers for the HBONE E2E harness.
//!
//! Three binaries live next to this lib:
//! - `hbone_backend`  — plaintext HTTP/1.1 echo backend.
//! - `hbone_sidecar`  — stub ambient sidecar (terminates HBONE H2 CONNECT + mTLS,
//!   relays the inner stream to the plaintext backend).
//! - `hbone_loadgen`  — load generator + cert generator subcommand.

pub mod certs;
pub mod metrics;
pub mod tls;
