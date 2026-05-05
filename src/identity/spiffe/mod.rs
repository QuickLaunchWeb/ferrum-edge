//! SPIFFE primitives: trust domains, SPIFFE IDs, and X.509 URI-SAN encoding.
//!
//! These types are independent of the gRPC Workload API client/server and the
//! certificate authority — they are the shared vocabulary that every other
//! mesh layer references.

pub mod id;
pub mod trust_domain;
pub mod uri_san;

#[allow(unused_imports)]
pub use id::{MAX_SPIFFE_ID_LEN, SpiffeId, SpiffeIdError};
#[allow(unused_imports)]
pub use trust_domain::{MAX_TRUST_DOMAIN_LEN, TrustDomain, TrustDomainError};
#[allow(unused_imports)]
pub use uri_san::{
    UriSanError, extract_spiffe_id_from_cert, extract_spiffe_id_from_parsed, spiffe_id_to_san,
    try_extract_spiffe_id, try_extract_spiffe_id_from_parsed,
};
