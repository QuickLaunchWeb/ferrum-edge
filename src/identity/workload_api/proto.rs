//! Generated SPIFFE Workload API stubs.
//!
//! `tonic_prost_build` (invoked from `build.rs`) compiles `proto/workload_api.proto`
//! and emits a module under `OUT_DIR`. We re-include it here so the rest of
//! the crate uses a stable path: `crate::identity::workload_api::proto::*`.

#![allow(
    missing_docs,
    clippy::large_enum_variant,
    clippy::derive_partial_eq_without_eq
)]

tonic::include_proto!("spiffe.workload");
