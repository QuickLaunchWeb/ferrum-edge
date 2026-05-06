//! xDS and native mesh-config distribution (Layer 3).
//!
//! Phase B keeps this path strictly additive: the ADS service is only mounted
//! when `FERRUM_XDS_ENABLED=true`, and all xDS/native streams translate from
//! the canonical Layer 2 mesh model instead of reading any config source
//! directly.

// Phase B exposes xDS pieces before every runtime path consumes them. Keep the
// allowance scoped to dead code only; unused imports should still be caught.
#![allow(dead_code)]

pub mod conformance;
pub mod nonce;
pub mod server;
pub mod slice;
pub mod snapshot;
pub mod translator;

pub mod proto {
    // Not google.protobuf.Any/Status: these are the minimal wire-compatible
    // xDS shims Ferrum needs for Phase B.
    tonic::include_proto!("envoy.service.discovery.v3");
}

// Public re-exports are used by library consumers/tests even when the binary
// target only reaches xDS through narrower module paths.
#[allow(unused_imports)]
pub use nonce::{AckOutcome, XdsNonceTracker};
pub use server::XdsAdsServer;
pub use slice::{MeshSlice, MeshSliceRequest};
#[allow(unused_imports)]
pub use snapshot::{XdsResource, XdsSnapshot, XdsSnapshotCache};
#[allow(unused_imports)]
pub use translator::{
    CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, SDS_TYPE_URL, XDS_TYPE_URLS,
    translate_mesh_slice_to_snapshot,
};
