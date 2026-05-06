//! Istio-flavored HBONE request metadata helpers.
//!
//! HBONE is HTTP/2 CONNECT over mTLS. Ferrum keeps this parsing boundary small
//! and explicit so future ambient transports can plug in beside it.
#![allow(dead_code)]

use std::collections::BTreeMap;

use http::{HeaderMap, Method, Version};

use crate::identity::SpiffeId;

/// Istio convention for HBONE-capable listeners.
pub const ISTIO_HBONE_PORT: u16 = 15008;
pub const BAGGAGE_HEADER: &str = "baggage";
pub const HBONE_PROTOCOL: &str = "hbone";

/// Per-stream identity metadata carried by ambient HBONE requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HboneIdentity {
    pub source_principal: Option<SpiffeId>,
    pub destination_principal: Option<SpiffeId>,
    pub baggage: BTreeMap<String, String>,
}

impl HboneIdentity {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let baggage = parse_baggage(headers);
        Self::from_baggage(baggage)
    }

    pub fn from_baggage_header(raw: &str) -> Self {
        Self::from_baggage(parse_baggage_header(raw))
    }

    fn from_baggage(baggage: BTreeMap<String, String>) -> Self {
        let source_principal = first_baggage_value(
            &baggage,
            &[
                "source.principal",
                "source_principal",
                "source.identity",
                "source_identity",
                "src.identity",
                "src_identity",
            ],
        )
        .and_then(parse_spiffe);
        let destination_principal = first_baggage_value(
            &baggage,
            &[
                "destination.principal",
                "destination_principal",
                "destination.identity",
                "destination_identity",
                "dst.identity",
                "dst_identity",
            ],
        )
        .and_then(parse_spiffe);

        Self {
            source_principal,
            destination_principal,
            baggage,
        }
    }
}

/// Detect an HBONE CONNECT stream from request parts.
///
/// Ferrum accepts plain HTTP/2 CONNECT as HBONE because Istio describes HBONE
/// as HTTP/2 CONNECT plus mTLS, while still recognizing explicit marker
/// headers used by early clients and tests.
pub fn is_hbone_connect(method: &Method, version: Version, headers: &HeaderMap) -> bool {
    if method != Method::CONNECT || version != Version::HTTP_2 {
        return false;
    }
    let protocol = headers
        .get("x-ferrum-mesh-protocol")
        .or_else(|| headers.get("x-istio-protocol"))
        .and_then(|value| value.to_str().ok());
    protocol.is_none_or(|value| value.eq_ignore_ascii_case(HBONE_PROTOCOL))
}

pub fn parse_baggage(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut baggage = BTreeMap::new();
    let Some(raw) = headers
        .get(BAGGAGE_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return baggage;
    };
    parse_baggage_header_into(raw, &mut baggage);
    baggage
}

pub fn parse_baggage_header(raw: &str) -> BTreeMap<String, String> {
    let mut baggage = BTreeMap::new();
    parse_baggage_header_into(raw, &mut baggage);
    baggage
}

fn parse_baggage_header_into(raw: &str, baggage: &mut BTreeMap<String, String>) {
    for member in raw.split(',') {
        let Some((key, value_and_params)) = member.trim().split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value_and_params
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"');
        if value.is_empty() {
            continue;
        }
        baggage.insert(key.to_string(), value.to_string());
    }
}

fn first_baggage_value<'a>(
    baggage: &'a BTreeMap<String, String>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| baggage.get(*key).map(String::as_str))
}

fn parse_spiffe(value: &str) -> Option<SpiffeId> {
    SpiffeId::new(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_http2_connect_as_hbone() {
        let headers = HeaderMap::new();
        assert!(is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_2,
            &headers
        ));
        assert!(!is_hbone_connect(&Method::GET, Version::HTTP_2, &headers));
        assert!(!is_hbone_connect(
            &Method::CONNECT,
            Version::HTTP_11,
            &headers
        ));
    }

    #[test]
    fn parses_source_and_destination_identity_from_baggage() {
        let mut headers = HeaderMap::new();
        headers.insert(
            BAGGAGE_HEADER,
            "source.principal=spiffe://cluster.local/ns/default/sa/client, \
             destination.principal=spiffe://cluster.local/ns/default/sa/server;meta=ignored"
                .parse()
                .expect("valid baggage header"),
        );

        let identity = HboneIdentity::from_headers(&headers);
        assert_eq!(
            identity.source_principal.as_ref().map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/client".to_string())
        );
        assert_eq!(
            identity
                .destination_principal
                .as_ref()
                .map(ToString::to_string),
            Some("spiffe://cluster.local/ns/default/sa/server".to_string())
        );
    }
}
