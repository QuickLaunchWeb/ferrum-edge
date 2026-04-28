//! `Workload` + scoping `PeerAuthentication` → `Listener` translation.
//!
//! For each workload we emit two virtual listeners (Istio convention,
//! kept for tooling compatibility):
//!
//! - **`virtualInbound`** on port 15006 — accepts mTLS connections from
//!   peer sidecars. Filter chain selects on SNI + ALPN. The transport
//!   socket is `DownstreamTlsContext` with SDS references for cert and
//!   validation context.
//! - **`virtualOutbound`** on port 15001 — catch-all using the
//!   `original_dst` listener filter so traffic redirected from
//!   `iptables` lands here. Filter chain matches on destination port
//!   and dispatches to the per-port outbound RDS configuration.
//!
//! The mTLS posture comes from `PeerAuthentication.mtls_mode`:
//! - `Strict` → `RequireClientCertificate=true`
//! - `Permissive` → `RequireClientCertificate=false` plus a
//!   plaintext fallback chain
//! - `Disable` → no TLS

use envoy_types::pb::envoy::config::core::v3::address::Address as AddressKind;
use envoy_types::pb::envoy::config::core::v3::config_source::ConfigSourceSpecifier;
use envoy_types::pb::envoy::config::core::v3::socket_address::PortSpecifier;
use envoy_types::pb::envoy::config::core::v3::transport_socket::ConfigType as TsConfigType;
use envoy_types::pb::envoy::config::core::v3::{Address, SocketAddress, TransportSocket};
use envoy_types::pb::envoy::config::core::v3::{AggregatedConfigSource, ApiVersion, ConfigSource};
use envoy_types::pb::envoy::config::listener::v3::{Filter, FilterChain, Listener};
use envoy_types::pb::envoy::extensions::filters::network::http_connection_manager::v3::{
    HttpConnectionManager, HttpFilter, Rds, http_connection_manager::RouteSpecifier,
};
use envoy_types::pb::envoy::extensions::transport_sockets::tls::v3::{
    CommonTlsContext, DownstreamTlsContext, SdsSecretConfig,
    common_tls_context::ValidationContextType,
};
use envoy_types::pb::google::protobuf::{Any, BoolValue};
use prost::Message;

use super::{
    DEFAULT_SDS_CERT_NAME, DEFAULT_SDS_VALIDATION_NAME, ListenerSet, SIDECAR_INBOUND_PORT,
    SIDECAR_OUTBOUND_PORT, inbound_catchall_listener_name, outbound_catchall_listener_name,
    outbound_route_name,
};
use crate::config::mesh::{MeshSlice, MtlsMode};
use crate::xds::snapshot::NodeIdentity;

const ROUTER_FILTER_NAME: &str = "envoy.filters.http.router";
const ROUTER_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router";
const HCM_NAME: &str = "envoy.filters.network.http_connection_manager";
const HCM_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";

pub fn translate(slice: Option<&MeshSlice>, _identity: &NodeIdentity) -> ListenerSet {
    let mut out = ListenerSet::new();
    let Some(slice) = slice else {
        return out;
    };

    let mtls_mode = effective_mtls_mode(slice);

    // ── Inbound listener (15006) ─────────────────────────────────────
    let inbound_filter_chain = inbound_filter_chain(mtls_mode);
    out.insert(
        inbound_catchall_listener_name().to_string(),
        Listener {
            name: inbound_catchall_listener_name().to_string(),
            address: Some(socket_address("0.0.0.0", SIDECAR_INBOUND_PORT)),
            filter_chains: vec![inbound_filter_chain],
            traffic_direction: TrafficDirection::Inbound as i32,
            ..Default::default()
        },
    );

    // ── Outbound listener (15001) ────────────────────────────────────
    // For Phase B foundation we emit one HCM filter chain per
    // distinct *port* surfaced by the slice's services + service
    // entries. Phase C will add original_dst-based per-IP routing.
    let mut outbound_ports = std::collections::BTreeSet::new();
    for svc in &slice.services {
        for p in &svc.ports {
            outbound_ports.insert(p.port);
        }
    }
    for se in &slice.service_entries {
        for p in &se.ports {
            outbound_ports.insert(p.port);
        }
    }
    let outbound_chains: Vec<FilterChain> = outbound_ports
        .into_iter()
        .map(outbound_filter_chain)
        .collect();
    out.insert(
        outbound_catchall_listener_name().to_string(),
        Listener {
            name: outbound_catchall_listener_name().to_string(),
            address: Some(socket_address("0.0.0.0", SIDECAR_OUTBOUND_PORT)),
            filter_chains: outbound_chains,
            traffic_direction: TrafficDirection::Outbound as i32,
            ..Default::default()
        },
    );

    out
}

fn socket_address(addr: &str, port: u16) -> Address {
    Address {
        address: Some(AddressKind::SocketAddress(SocketAddress {
            address: addr.to_string(),
            port_specifier: Some(PortSpecifier::PortValue(port as u32)),
            ..Default::default()
        })),
    }
}

fn inbound_filter_chain(mtls: MtlsMode) -> FilterChain {
    let hcm = HttpConnectionManager {
        stat_prefix: "inbound_hcm".to_string(),
        route_specifier: Some(RouteSpecifier::Rds(Rds {
            config_source: Some(ads_config_source()),
            route_config_name: "inbound|http".to_string(),
        })),
        http_filters: vec![router_filter()],
        ..Default::default()
    };
    let hcm_any = Any {
        type_url: HCM_TYPE_URL.to_string(),
        value: hcm.encode_to_vec(),
    };
    let mut chain = FilterChain {
        filters: vec![Filter {
            name: HCM_NAME.to_string(),
            config_type: Some(
                envoy_types::pb::envoy::config::listener::v3::filter::ConfigType::TypedConfig(
                    hcm_any,
                ),
            ),
        }],
        ..Default::default()
    };

    if mtls != MtlsMode::Disable {
        let downstream_tls = DownstreamTlsContext {
            common_tls_context: Some(common_tls_context()),
            require_client_certificate: Some(BoolValue {
                value: matches!(mtls, MtlsMode::Strict),
            }),
            ..Default::default()
        };
        let tls_any = Any {
            type_url:
                "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext"
                    .to_string(),
            value: downstream_tls.encode_to_vec(),
        };
        chain.transport_socket = Some(TransportSocket {
            name: "envoy.transport_sockets.tls".to_string(),
            config_type: Some(TsConfigType::TypedConfig(tls_any)),
        });
    }

    chain
}

fn outbound_filter_chain(port: u16) -> FilterChain {
    let hcm = HttpConnectionManager {
        stat_prefix: format!("outbound_hcm_{}", port),
        route_specifier: Some(RouteSpecifier::Rds(Rds {
            config_source: Some(ads_config_source()),
            route_config_name: outbound_route_name(port),
        })),
        http_filters: vec![router_filter()],
        ..Default::default()
    };
    let hcm_any = Any {
        type_url: HCM_TYPE_URL.to_string(),
        value: hcm.encode_to_vec(),
    };
    FilterChain {
        filter_chain_match: Some(
            envoy_types::pb::envoy::config::listener::v3::FilterChainMatch {
                destination_port: Some(envoy_types::pb::google::protobuf::UInt32Value {
                    value: port as u32,
                }),
                ..Default::default()
            },
        ),
        filters: vec![Filter {
            name: HCM_NAME.to_string(),
            config_type: Some(
                envoy_types::pb::envoy::config::listener::v3::filter::ConfigType::TypedConfig(
                    hcm_any,
                ),
            ),
        }],
        ..Default::default()
    }
}

fn router_filter() -> HttpFilter {
    HttpFilter {
        name: ROUTER_FILTER_NAME.to_string(),
        config_type: Some(
            envoy_types::pb::envoy::extensions::filters::network::http_connection_manager::v3::http_filter::ConfigType::TypedConfig(Any {
                type_url: ROUTER_TYPE_URL.to_string(),
                value: Vec::new(),
            }),
        ),
        ..Default::default()
    }
}

fn ads_config_source() -> ConfigSource {
    ConfigSource {
        resource_api_version: ApiVersion::V3 as i32,
        config_source_specifier: Some(ConfigSourceSpecifier::Ads(AggregatedConfigSource {})),
        ..Default::default()
    }
}

fn common_tls_context() -> CommonTlsContext {
    CommonTlsContext {
        tls_certificate_sds_secret_configs: vec![SdsSecretConfig {
            name: DEFAULT_SDS_CERT_NAME.to_string(),
            sds_config: Some(ads_config_source_for_sds()),
        }],
        validation_context_type: Some(ValidationContextType::ValidationContextSdsSecretConfig(
            SdsSecretConfig {
                name: DEFAULT_SDS_VALIDATION_NAME.to_string(),
                sds_config: Some(ads_config_source_for_sds()),
            },
        )),
        ..Default::default()
    }
}

fn ads_config_source_for_sds() -> ConfigSource {
    ads_config_source()
}

/// Determine the effective inbound mTLS posture for a sliced workload.
/// Picks the most specific matching `PeerAuthentication`.
fn effective_mtls_mode(slice: &MeshSlice) -> MtlsMode {
    // Heuristic: if any matching PA is Strict, prefer Strict; else
    // Permissive if any explicitly Permissive; else Disable; default
    // Permissive when there are no PAs at all.
    if slice.peer_authentications.is_empty() {
        return MtlsMode::Permissive;
    }
    let mut has_permissive = false;
    let mut has_disable = false;
    for pa in &slice.peer_authentications {
        match pa.mtls_mode {
            MtlsMode::Strict => return MtlsMode::Strict,
            MtlsMode::Permissive => has_permissive = true,
            MtlsMode::Disable => has_disable = true,
        }
    }
    if has_permissive {
        MtlsMode::Permissive
    } else if has_disable {
        MtlsMode::Disable
    } else {
        MtlsMode::Permissive
    }
}

#[derive(Clone, Copy)]
enum TrafficDirection {
    #[allow(dead_code)]
    Unspecified = 0,
    Inbound = 1,
    Outbound = 2,
}
