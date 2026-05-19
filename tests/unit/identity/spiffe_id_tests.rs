//! SPIFFE-ID parser, trust-domain validator, and SPIFFE-URI hashing tests.

use ferrum_edge::identity::spiffe::{
    MAX_SPIFFE_ID_LEN, MAX_TRUST_DOMAIN_LEN, SpiffeId, SpiffeIdError, TrustDomain, TrustDomainError,
};
use std::collections::HashSet;
use std::str::FromStr;

// ── Trust domain ──────────────────────────────────────────────────────────

#[test]
fn trust_domain_accepts_simple_name() {
    let td = TrustDomain::new("prod.example.com").expect("valid");
    assert_eq!(td.as_str(), "prod.example.com");
    assert_eq!(td.as_uri(), "spiffe://prod.example.com");
}

#[test]
fn trust_domain_rejects_empty() {
    assert!(matches!(TrustDomain::new(""), Err(TrustDomainError::Empty)));
}

#[test]
fn trust_domain_rejects_uppercase() {
    assert!(matches!(
        TrustDomain::new("Prod.example.com"),
        Err(TrustDomainError::NotLowercase(_))
    ));
}

#[test]
fn trust_domain_rejects_path_component() {
    assert!(matches!(
        TrustDomain::new("prod.example.com/extra"),
        Err(TrustDomainError::HasPath(_))
    ));
}

#[test]
fn trust_domain_rejects_invalid_char() {
    assert!(matches!(
        TrustDomain::new("prod.example.com!"),
        Err(TrustDomainError::InvalidChar(_, '!'))
    ));
}

#[test]
fn trust_domain_rejects_leading_dot() {
    assert!(matches!(
        TrustDomain::new(".example.com"),
        Err(TrustDomainError::BadBoundary(_))
    ));
}

#[test]
fn trust_domain_rejects_too_long() {
    let raw = "a".repeat(MAX_TRUST_DOMAIN_LEN + 1);
    assert!(matches!(
        TrustDomain::new(raw),
        Err(TrustDomainError::TooLong(_, _, _))
    ));
}

#[test]
fn trust_domain_round_trips_via_serde() {
    let td = TrustDomain::new("prod.example.com").unwrap();
    let s = serde_json::to_string(&td).unwrap();
    let back: TrustDomain = serde_json::from_str(&s).unwrap();
    assert_eq!(back, td);
}

#[test]
fn trust_domain_serde_rejects_malformed() {
    let bad = "\"PROD.example.com\"";
    assert!(serde_json::from_str::<TrustDomain>(bad).is_err());
}

// ── SPIFFE ID parsing ─────────────────────────────────────────────────────

#[test]
fn spiffe_id_parses_simple() {
    let id = SpiffeId::new("spiffe://prod.example.com/ns/foo/sa/bar").unwrap();
    assert_eq!(id.as_str(), "spiffe://prod.example.com/ns/foo/sa/bar");
    assert_eq!(id.trust_domain().as_str(), "prod.example.com");
    assert_eq!(id.path(), "ns/foo/sa/bar");
    assert_eq!(
        id.path_segments().collect::<Vec<_>>(),
        vec!["ns", "foo", "sa", "bar"]
    );
}

#[test]
fn spiffe_id_root_no_path_ok() {
    let id = SpiffeId::new("spiffe://prod.example.com").unwrap();
    assert_eq!(id.path(), "");
    assert_eq!(id.path_segments().count(), 0);
}

#[test]
fn service_account_returns_segment_after_first_sa() {
    let id = SpiffeId::new("spiffe://cluster.local/ns/default/sa/ztunnel").unwrap();
    assert_eq!(id.service_account(), Some("ztunnel"));
}

#[test]
fn service_account_none_when_path_lacks_sa_segment() {
    let id = SpiffeId::new("spiffe://cluster.local/ns/default").unwrap();
    assert_eq!(id.service_account(), None);
}

#[test]
fn service_account_none_when_sa_is_trailing() {
    let id = SpiffeId::new("spiffe://cluster.local/ns/default/sa").unwrap();
    assert_eq!(id.service_account(), None);
}

#[test]
fn service_account_uses_first_sa_segment() {
    // A second `sa` later in the path must not override the first match.
    let id = SpiffeId::new("spiffe://cluster.local/sa/foo/sa/bar").unwrap();
    assert_eq!(id.service_account(), Some("foo"));
}

#[test]
fn service_account_none_for_root_spiffe_id() {
    let id = SpiffeId::new("spiffe://cluster.local").unwrap();
    assert_eq!(id.service_account(), None);
}

#[test]
fn namespace_returns_segment_after_first_ns() {
    let id = SpiffeId::new("spiffe://cluster.local/ns/default/sa/ztunnel").unwrap();
    assert_eq!(id.namespace(), Some("default"));
}

#[test]
fn namespace_returns_segment_after_first_ns_for_non_canonical_path() {
    // Only `ns/<namespace>` is required; a SPIFFE ID without `sa/...` still
    // resolves the namespace. Mirrors the Istio convention `spiffe://td/ns/<ns>`
    // for workload group identities.
    let id = SpiffeId::new("spiffe://cluster.local/ns/prod").unwrap();
    assert_eq!(id.namespace(), Some("prod"));
}

#[test]
fn namespace_none_when_path_lacks_ns_segment() {
    let id = SpiffeId::new("spiffe://cluster.local/sa/client").unwrap();
    assert_eq!(id.namespace(), None);
}

#[test]
fn namespace_none_when_ns_is_trailing() {
    let id = SpiffeId::new("spiffe://cluster.local/ns").unwrap();
    assert_eq!(id.namespace(), None);
}

#[test]
fn namespace_uses_first_ns_segment() {
    // A second `ns/...` later in the path must not override the first match.
    // Istio places `ns/<namespace>` at a single canonical position; honoring
    // any later `ns/` segment would weaken authorization built on top of this
    // helper (e.g., `sourceNamespace` predicates).
    let id = SpiffeId::new("spiffe://cluster.local/ns/prod/ns/staging/sa/foo").unwrap();
    assert_eq!(id.namespace(), Some("prod"));
}

#[test]
fn namespace_none_for_root_spiffe_id() {
    let id = SpiffeId::new("spiffe://cluster.local").unwrap();
    assert_eq!(id.namespace(), None);
}

#[test]
fn spiffe_id_rejects_wrong_scheme() {
    assert!(matches!(
        SpiffeId::new("https://prod.example.com/foo"),
        Err(SpiffeIdError::InvalidScheme(_))
    ));
    assert!(matches!(
        SpiffeId::new("SPIFFE://prod.example.com/foo"),
        Err(SpiffeIdError::InvalidScheme(_))
    ));
}

#[test]
fn spiffe_id_rejects_missing_trust_domain() {
    assert!(matches!(
        SpiffeId::new("spiffe:///path"),
        Err(SpiffeIdError::InvalidTrustDomain(_, _))
    ));
}

#[test]
fn spiffe_id_rejects_trailing_slash() {
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/foo/"),
        Err(SpiffeIdError::TrailingSlash(_))
    ));
}

#[test]
fn spiffe_id_rejects_query() {
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/foo?bar=1"),
        Err(SpiffeIdError::HasQuery(_))
    ));
}

#[test]
fn spiffe_id_rejects_fragment() {
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/foo#frag"),
        Err(SpiffeIdError::HasFragment(_))
    ));
}

#[test]
fn spiffe_id_rejects_empty_path_segment() {
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/foo//bar"),
        Err(SpiffeIdError::EmptyPathSegment { .. })
    ));
}

#[test]
fn spiffe_id_rejects_invalid_path_char() {
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/foo bar"),
        Err(SpiffeIdError::InvalidPathChar { .. })
    ));
}

#[test]
fn spiffe_id_rejects_idn_path() {
    // Non-ASCII in path is rejected.
    assert!(matches!(
        SpiffeId::new("spiffe://prod.example.com/π"),
        Err(SpiffeIdError::InvalidPathChar { .. })
    ));
}

#[test]
fn spiffe_id_rejects_too_long() {
    let body = "a".repeat(MAX_SPIFFE_ID_LEN + 1);
    let raw = format!("spiffe://prod.example.com/{body}");
    assert!(matches!(
        SpiffeId::new(raw),
        Err(SpiffeIdError::TooLong(_, _, _))
    ));
}

#[test]
fn spiffe_id_from_str_parses() {
    let id = SpiffeId::from_str("spiffe://td/ns/a/sa/b").unwrap();
    assert_eq!(id.trust_domain().as_str(), "td");
}

#[test]
fn spiffe_id_serde_round_trip() {
    let id = SpiffeId::new("spiffe://prod.example.com/ns/foo/sa/bar").unwrap();
    let s = serde_json::to_string(&id).unwrap();
    let back: SpiffeId = serde_json::from_str(&s).unwrap();
    assert_eq!(back, id);
}

#[test]
fn spiffe_id_hash_eq() {
    let a = SpiffeId::new("spiffe://td/ns/foo").unwrap();
    let b = SpiffeId::new("spiffe://td/ns/foo").unwrap();
    let mut set: HashSet<SpiffeId> = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
}

#[test]
fn spiffe_id_from_parts() {
    let td = TrustDomain::new("td").unwrap();
    let id = SpiffeId::from_parts(&td, "ns/foo/sa/bar").unwrap();
    assert_eq!(id.as_str(), "spiffe://td/ns/foo/sa/bar");

    // Leading slash is normalised away.
    let id2 = SpiffeId::from_parts(&td, "/ns/foo").unwrap();
    assert_eq!(id2.as_str(), "spiffe://td/ns/foo");

    // Empty path becomes the root.
    let id3 = SpiffeId::from_parts(&td, "").unwrap();
    assert_eq!(id3.as_str(), "spiffe://td");
}
