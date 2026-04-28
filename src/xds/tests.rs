//! Inline xDS tests reach into private helpers; the public-API tests
//! live in `tests/unit/xds/`. Keep this module thin — most coverage
//! belongs in the external test crate.

#![allow(unused_imports)]

use super::*;

#[test]
fn type_url_round_trip() {
    for ty in ResourceType::all() {
        let url = ty.type_url();
        assert_eq!(ResourceType::from_type_url(url), Some(ty));
    }
}

#[test]
fn unknown_type_url_returns_none() {
    assert!(ResourceType::from_type_url("type.googleapis.com/foo").is_none());
}
