//! xDS and native mesh-config distribution (Layer 3).
//!
//! Phase B keeps this path strictly additive: the ADS service is only mounted
//! when `FERRUM_XDS_ENABLED=true`, and all xDS/native streams translate from
//! the canonical Layer 2 mesh model instead of reading any config source
//! directly.

#![allow(dead_code, unused_imports)]

pub mod conformance;
pub mod nonce;
pub mod server;
pub mod slice;
pub mod snapshot;
pub mod translator;

pub mod proto {
    tonic::include_proto!("envoy.service.discovery.v3");
}

pub use nonce::{AckOutcome, XdsNonceTracker};
pub use server::XdsAdsServer;
pub use slice::{MeshSlice, MeshSliceRequest};
pub use snapshot::{XdsResource, XdsSnapshot, XdsSnapshotCache};
pub use translator::{
    CDS_TYPE_URL, EDS_TYPE_URL, LDS_TYPE_URL, RDS_TYPE_URL, SDS_TYPE_URL, XDS_TYPE_URLS,
    translate_mesh_slice_to_snapshot,
};
