//! Mesh runtime mode scaffolding.
//!
//! `FERRUM_MODE=mesh` data-plane mode.
//!
//! This module owns the mesh-specific runtime knobs and the config-consumer
//! boundary. It deliberately keeps the generic proxy/plugin chain unchanged so
//! existing plugins work in mesh context.

pub mod config;
pub mod config_consumer;
pub mod dns_proxy;
pub mod hbone;
pub mod policy;
pub mod runtime;
pub mod slice;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::config::types::{
    BackendScheme, BackendTlsConfig, GatewayConfig, HealthCheckConfig, LoadBalancerAlgorithm,
    MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES, MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH,
    PassiveHealthCheck, PluginAssociation, PluginConfig, PluginScope, Proxy, ResponseBodyMode,
    SubsetDefinition, SubsetTrafficPolicy, Upstream, UpstreamPortOverride, UpstreamTarget,
};
use crate::dns::{DnsCache, DnsConfig};
use crate::grpc::dp_client::{GrpcJwtSecret, build_dp_grpc_tls_config};
use crate::modes::mesh::config::{
    AppProtocol, EastWestGateway, MeshConfig, MeshDestinationRule, MeshJwtRule, MeshLoadBalancer,
    MeshRequestAuthentication, MeshSimpleLb, MeshTelemetryConfig, MeshTrafficPolicy,
    MeshTrafficPolicyTls, MtlsMode, PolicyScope, Resolution, ServiceEntry, ServiceEntryLocation,
    service_entry_exported_to_namespace,
};
use crate::modes::mesh::config_consumer::native_client::NativeMeshClientConfig;
use crate::modes::mesh::config_consumer::xds_client::XdsClientConfig;
use crate::modes::mesh::dns_proxy::MeshDnsProxy;
use crate::modes::mesh::runtime::MeshRuntimeState;
use crate::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use crate::proxy::{self, ProxyState};
use crate::startup::wait_for_start_signals;
use crate::tls::{self, TlsPolicy};

const DEFAULT_INBOUND_LISTEN_ADDR: &str = "0.0.0.0:15006";
const DEFAULT_OUTBOUND_LISTEN_ADDR: &str = "127.0.0.1:15001";
const DEFAULT_HBONE_LISTEN_ADDR: &str = "0.0.0.0:15008";
const DEFAULT_EAST_WEST_LISTEN_PORT: u16 = 15443;
const DEFAULT_DNS_LISTEN_ADDR: &str = "127.0.0.1:15053";
const DEFAULT_DNS_UPSTREAM_ADDR: &str = "127.0.0.53:53";
const DEFAULT_DNS_TTL_SECONDS: u32 = 60;
const DEFAULT_DNS_ENABLED: bool = false;
const DEFAULT_DNS_MAX_CONCURRENT_QUERIES: usize = 1024;
const DEFAULT_EGRESS_LISTEN_ADDR: &str = "0.0.0.0:15090";

pub const MESH_SPIFFE_IDENTITY_PLUGIN_ID: &str = "__mesh_spiffe_identity";
pub const MESH_AUTHZ_PLUGIN_ID: &str = "__mesh_authz";
pub const MESH_WORKLOAD_METRICS_PLUGIN_ID: &str = "__mesh_workload_metrics";
pub const MESH_REQUEST_AUTH_PLUGIN_ID: &str = "__mesh_request_auth";
pub const MESH_ACCESS_LOG_PLUGIN_ID: &str = "__mesh_access_log";
pub const MESH_OUTBOUND_REGISTRY_PLUGIN_ID: &str = "__mesh_outbound_registry";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTrafficDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshListenerKind {
    PlaintextCapture,
    MtlsTermination,
    HboneTermination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshListener {
    pub direction: MeshTrafficDirection,
    pub kind: MeshListenerKind,
    pub addr: SocketAddr,
}

/// Mesh data-plane topology. Sidecar and ambient share the same runtime path;
/// ambient selects HBONE termination instead of sidecar inbound mTLS,
/// east-west gateway delegates SNI passthrough to the stream listener manager,
/// and egress gateway materializes HTTP-family proxies from external
/// `ServiceEntry` resources for controlled mesh-to-external routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTopology {
    Sidecar,
    Ambient,
    EastWestGateway,
    EgressGateway,
}

impl MeshTopology {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sidecar" => Ok(Self::Sidecar),
            "ambient" => Ok(Self::Ambient),
            "east_west_gateway" | "east-west-gateway" => Ok(Self::EastWestGateway),
            "egress_gateway" | "egress-gateway" => Ok(Self::EgressGateway),
            other => Err(format!(
                "Invalid FERRUM_MESH_TOPOLOGY '{other}'. Expected: sidecar, ambient, east_west_gateway, or egress_gateway"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Sidecar => "sidecar",
            Self::Ambient => "ambient",
            Self::EastWestGateway => "east_west_gateway",
            Self::EgressGateway => "egress_gateway",
        }
    }
}

/// Control-protocol source for mesh runtime config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConfigProtocol {
    Native,
    Xds,
}

impl MeshConfigProtocol {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "native" => Ok(Self::Native),
            "xds" => Ok(Self::Xds),
            other => Err(format!(
                "Invalid FERRUM_MESH_CONFIG_PROTOCOL '{other}'. Expected: native or xds"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Xds => "xds",
        }
    }
}

/// Parsed mesh runtime settings kept separate from `EnvConfig` so mesh mode
/// stays strictly additive and non-mesh deployments do not carry new fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRuntimeConfig {
    pub node_id: String,
    pub namespace: String,
    pub cp_urls: Vec<String>,
    pub config_protocol: MeshConfigProtocol,
    pub topology: MeshTopology,
    pub inbound_listen_addr: SocketAddr,
    pub outbound_listen_addr: SocketAddr,
    pub hbone_listen_addr: SocketAddr,
    pub east_west_listen_port: u16,
    /// Address the egress gateway listens on for mesh-internal mTLS traffic
    /// from sidecars. Only used when `topology == EgressGateway`. Parsed from
    /// `FERRUM_MESH_EGRESS_LISTEN_ADDR`, default `0.0.0.0:15090`.
    pub egress_listen_addr: SocketAddr,
    pub workload_spiffe_id: Option<String>,
    /// xDS node cluster identity sent in DiscoveryRequest.node.cluster.
    /// Defaults to the Ferrum namespace when `FERRUM_MESH_XDS_NODE_CLUSTER`
    /// is unset.
    pub xds_node_cluster: String,
    /// Client-side ADS request channel capacity.
    pub xds_stream_channel_capacity: usize,
    /// How often a mesh xDS client retries the primary CP while connected to a
    /// fallback CP. `0` disables the timer.
    pub xds_primary_retry_secs: u64,
    /// Mesh xDS client connect timeout in seconds. `0` disables tonic's
    /// explicit connect timeout.
    pub xds_connect_timeout_seconds: u64,
    /// Operator-configured trust-domain aliases — additional SPIFFE trust
    /// domains accepted as equivalent to the peer cert's trust domain when
    /// validating HBONE baggage `source.principal`. Default empty: strict
    /// same-trust-domain match. Mirror of Istio
    /// `MeshConfig.trustDomainAliases`.
    pub trust_domain_aliases: Vec<crate::identity::TrustDomain>,
    /// Workload labels for this mesh data plane. Used by `mesh_authz`'s
    /// PolicyScope filter (and by `MeshSlice::from_gateway_config`'s
    /// WorkloadSelector matching) to decide which policies apply to this
    /// proxy's workload. Sourced from `FERRUM_MESH_WORKLOAD_LABELS`
    /// (`key1=val1,key2=val2`); empty when unset. The Kubernetes injector
    /// (Phase D) can populate this from pod labels via the downward API.
    pub workload_labels: std::collections::HashMap<String, String>,
    /// Workload X.509-SVID certificate chain used for mesh-originated backend
    /// mTLS when DestinationRule `ISTIO_MUTUAL` is projected onto an upstream.
    /// Sourced from `FERRUM_GATEWAY_SVID_CERT_PATH`.
    pub workload_svid_cert_path: Option<String>,
    /// Workload X.509-SVID private key used with `workload_svid_cert_path`.
    /// Sourced from `FERRUM_GATEWAY_SVID_KEY_PATH`.
    pub workload_svid_key_path: Option<String>,
    /// Trust bundle for backend server SVID verification when DestinationRule
    /// `ISTIO_MUTUAL` is projected onto an upstream.
    /// Sourced from `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH`.
    pub workload_svid_trust_bundle_path: Option<String>,
    /// Whether the transparent DNS proxy is enabled. Opt-in because it
    /// requires iptables/eBPF redirect to be useful.
    /// Sourced from `FERRUM_MESH_DNS_PROXY_ENABLED` (default false).
    pub dns_enabled: bool,
    /// Listen address for the mesh DNS proxy.
    /// Sourced from `FERRUM_MESH_DNS_LISTEN_ADDR` (default `127.0.0.1:15053`).
    pub dns_listen_addr: SocketAddr,
    /// Upstream DNS resolver for non-mesh queries.
    /// Sourced from `FERRUM_MESH_DNS_UPSTREAM_ADDR` (default `127.0.0.53:53`).
    pub dns_upstream_addr: SocketAddr,
    /// TTL (seconds) for DNS responses served from the mesh resolution table.
    /// Sourced from `FERRUM_MESH_DNS_TTL_SECONDS` (default 60).
    pub dns_ttl_seconds: u32,
    /// Maximum concurrent mesh DNS queries / upstream forwards.
    /// Sourced from `FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES` (default 1024).
    pub dns_max_concurrent_queries: usize,
    /// Maximum per-slice cached mesh DNS response templates.
    /// Sourced from `FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES` (default 4096).
    pub dns_response_cache_max_entries: usize,
    /// Kubernetes cluster DNS domain used for synthetic mesh service names.
    /// Sourced from `FERRUM_MESH_CLUSTER_DOMAIN` (default `cluster.local`).
    pub cluster_domain: String,
    /// Traffic capture mode for observability/logging. Does not change proxy
    /// behavior — listeners are topology-driven. Sourced from
    /// `FERRUM_MESH_CAPTURE_MODE` (default `explicit`).
    pub capture_mode: crate::capture::CaptureMode,
    /// Operator-set outbound traffic policy. Sourced from
    /// `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY`. When `RegistryOnly`, the
    /// slice-apply path injects the `mesh_outbound_registry` plugin with a
    /// registry built from the slice's known destinations.
    pub outbound_traffic_policy: crate::modes::mesh::config::OutboundTrafficPolicy,
    /// HTTP status returned by the auto-injected outbound registry plugin for
    /// unknown destinations. Sourced from
    /// `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` (default 502).
    pub outbound_registry_reject_status: u16,
    /// When `true`, the slice builder applies Istio `Sidecar` egress scope
    /// narrowing. Sourced from `FERRUM_MESH_SIDECAR_ENFORCED` (default
    /// `false`). When disabled, `Sidecar` resources are parsed and persisted
    /// in `MeshConfig` but the slice projection ignores them — behavior is
    /// identical to today, preserving safe-rollout semantics.
    pub sidecar_enforced: bool,
}

impl MeshRuntimeConfig {
    pub fn from_env_config(env_config: &EnvConfig) -> Result<Self, String> {
        let cp_urls = env_config.resolved_dp_cp_grpc_urls();
        if cp_urls.is_empty() {
            return Err("FERRUM_DP_CP_GRPC_URLS is required in mesh mode".into());
        }

        let node_id = resolve_ferrum_var("FERRUM_MESH_NODE_ID")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "ferrum-mesh-node".to_string());
        let config_protocol = MeshConfigProtocol::parse(&env_config.mesh_config_protocol)?;
        let topology = MeshTopology::parse(
            &resolve_ferrum_var("FERRUM_MESH_TOPOLOGY").unwrap_or_else(|| "sidecar".to_string()),
        )?;
        let inbound_listen_addr = parse_socket_addr(
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_INBOUND_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_INBOUND_LISTEN_ADDR),
        )?;
        let outbound_listen_addr = parse_socket_addr(
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_OUTBOUND_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_OUTBOUND_LISTEN_ADDR),
        )?;
        let hbone_listen_addr = parse_socket_addr(
            "FERRUM_MESH_HBONE_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_HBONE_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_HBONE_LISTEN_ADDR),
        )?;
        let east_west_port_raw = resolve_ferrum_var("FERRUM_MESH_EAST_WEST_LISTEN_PORT")
            .unwrap_or_else(|| DEFAULT_EAST_WEST_LISTEN_PORT.to_string());
        let east_west_listen_port =
            parse_port("FERRUM_MESH_EAST_WEST_LISTEN_PORT", &east_west_port_raw)?;
        let egress_listen_addr = parse_socket_addr(
            "FERRUM_MESH_EGRESS_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_EGRESS_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_EGRESS_LISTEN_ADDR),
        )?;
        let workload_spiffe_id = resolve_ferrum_var("FERRUM_MESH_WORKLOAD_SPIFFE_ID")
            .filter(|value| !value.trim().is_empty());
        let workload_svid_cert_path = env_config.gateway_svid_cert_path.clone();
        let workload_svid_key_path = env_config.gateway_svid_key_path.clone();
        let workload_svid_trust_bundle_path = env_config.gateway_svid_trust_bundle_path.clone();
        let xds_node_cluster = resolve_ferrum_var("FERRUM_MESH_XDS_NODE_CLUSTER")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| env_config.namespace.clone());
        let xds_connect_timeout_raw = resolve_ferrum_var("FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "10".to_string());
        let xds_connect_timeout_seconds = parse_duration_seconds(
            "FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS",
            &xds_connect_timeout_raw,
        )?;
        let workload_labels =
            parse_workload_labels(resolve_ferrum_var("FERRUM_MESH_WORKLOAD_LABELS").as_deref())?;

        let trust_domain_aliases = env_config
            .mesh_trust_domain_aliases
            .iter()
            .map(|raw| crate::identity::TrustDomain::new(raw.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("FERRUM_MESH_TRUST_DOMAIN_ALIASES: {e}"))?;

        let dns_enabled = resolve_ferrum_var("FERRUM_MESH_DNS_PROXY_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(DEFAULT_DNS_ENABLED);
        let dns_listen_addr = parse_socket_addr(
            "FERRUM_MESH_DNS_LISTEN_ADDR",
            resolve_ferrum_var("FERRUM_MESH_DNS_LISTEN_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_DNS_LISTEN_ADDR),
        )?;
        let dns_upstream_addr = parse_socket_addr(
            "FERRUM_MESH_DNS_UPSTREAM_ADDR",
            resolve_ferrum_var("FERRUM_MESH_DNS_UPSTREAM_ADDR")
                .as_deref()
                .unwrap_or(DEFAULT_DNS_UPSTREAM_ADDR),
        )?;
        let dns_ttl_seconds = resolve_ferrum_var("FERRUM_MESH_DNS_TTL_SECONDS")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(DEFAULT_DNS_TTL_SECONDS);
        let dns_max_concurrent_queries =
            resolve_ferrum_var("FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(DEFAULT_DNS_MAX_CONCURRENT_QUERIES);
        let dns_response_cache_max_entries =
            resolve_ferrum_var("FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES);
        let cluster_domain = resolve_ferrum_var("FERRUM_MESH_CLUSTER_DOMAIN")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| dns_proxy::DEFAULT_CLUSTER_DOMAIN.to_string());
        let capture_mode = crate::capture::CaptureMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_MODE")
                .unwrap_or_else(|| "explicit".to_string()),
        )?;
        let outbound_traffic_policy = match env_config
            .mesh_outbound_traffic_policy
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "allow_any" => crate::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
            "registry_only" => crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly,
            other => {
                return Err(format!(
                    "Invalid FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY '{other}'. Expected: \
                     allow_any or registry_only"
                ));
            }
        };
        let outbound_registry_reject_status = env_config.mesh_outbound_registry_reject_status;
        if !(400..=599).contains(&outbound_registry_reject_status) {
            return Err(format!(
                "Invalid FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS \
                 '{outbound_registry_reject_status}'. Expected: 400..=599"
            ));
        }

        Ok(Self {
            node_id,
            namespace: env_config.namespace.clone(),
            cp_urls,
            config_protocol,
            topology,
            inbound_listen_addr,
            outbound_listen_addr,
            hbone_listen_addr,
            east_west_listen_port,
            egress_listen_addr,
            workload_spiffe_id,
            xds_node_cluster,
            xds_stream_channel_capacity: env_config.xds_stream_channel_capacity,
            xds_primary_retry_secs: env_config.dp_cp_failover_primary_retry_secs,
            xds_connect_timeout_seconds,
            trust_domain_aliases,
            workload_labels,
            workload_svid_cert_path,
            workload_svid_key_path,
            workload_svid_trust_bundle_path,
            dns_enabled,
            dns_listen_addr,
            dns_upstream_addr,
            dns_ttl_seconds,
            dns_max_concurrent_queries,
            dns_response_cache_max_entries,
            cluster_domain,
            capture_mode,
            outbound_traffic_policy,
            outbound_registry_reject_status,
            sidecar_enforced: env_config.mesh_sidecar_enforced,
        })
    }

    fn native_client_config(&self) -> NativeMeshClientConfig {
        NativeMeshClientConfig {
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            labels: self.workload_labels.clone(),
        }
    }

    fn xds_client_config(&self) -> XdsClientConfig {
        XdsClientConfig {
            cp_urls: self.cp_urls.clone(),
            node_id: self.node_id.clone(),
            cluster: self.xds_node_cluster.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            stream_channel_capacity: self.xds_stream_channel_capacity,
            primary_retry_secs: self.xds_primary_retry_secs,
            connect_timeout_seconds: self.xds_connect_timeout_seconds,
            labels: self
                .workload_labels
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }
    }

    pub fn listener_plan(&self) -> Vec<MeshListener> {
        match self.topology {
            MeshTopology::Sidecar => vec![
                MeshListener {
                    direction: MeshTrafficDirection::Outbound,
                    kind: MeshListenerKind::PlaintextCapture,
                    addr: self.outbound_listen_addr,
                },
                MeshListener {
                    direction: MeshTrafficDirection::Inbound,
                    kind: MeshListenerKind::MtlsTermination,
                    addr: self.inbound_listen_addr,
                },
            ],
            MeshTopology::Ambient => vec![
                MeshListener {
                    direction: MeshTrafficDirection::Outbound,
                    kind: MeshListenerKind::PlaintextCapture,
                    addr: self.outbound_listen_addr,
                },
                MeshListener {
                    direction: MeshTrafficDirection::Inbound,
                    kind: MeshListenerKind::HboneTermination,
                    addr: self.hbone_listen_addr,
                },
            ],
            MeshTopology::EastWestGateway => Vec::new(),
            MeshTopology::EgressGateway => vec![MeshListener {
                direction: MeshTrafficDirection::Inbound,
                kind: MeshListenerKind::MtlsTermination,
                addr: self.egress_listen_addr,
            }],
        }
    }

    #[allow(dead_code)] // Used by tests and future xDS bootstrap wiring.
    pub fn mesh_slice_request(&self) -> MeshSliceRequest {
        MeshSliceRequest {
            node_id: self.node_id.clone(),
            namespace: self.namespace.clone(),
            workload_spiffe_id: self.workload_spiffe_id.clone(),
            labels: self
                .workload_labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            cluster_domain: self.cluster_domain.clone(),
            enforce_sidecar_egress: self.sidecar_enforced,
        }
    }
}

/// Prepare a gateway snapshot for mesh-mode serving.
///
/// Mesh mode is the only caller. The mutation is cold-path: it runs before
/// `ProxyState` builds router/plugin caches, so non-mesh modes and ordinary
/// requests never pay for mesh plugin injection.
#[allow(dead_code)] // Used by tests and future xDS bootstrap wiring.
pub fn prepare_gateway_config_for_mesh(
    mut config: GatewayConfig,
    runtime: &MeshRuntimeConfig,
) -> Result<GatewayConfig, anyhow::Error> {
    config.normalize_fields();
    config.normalize_mesh_fields();
    let mesh_slice = MeshSlice::from_gateway_config(&config, runtime.mesh_slice_request());
    prepare_normalized_gateway_config_for_mesh(config, runtime, &mesh_slice)
}

fn prepare_gateway_config_for_native_slice(
    mut config: GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) -> Result<GatewayConfig, anyhow::Error> {
    config.normalize_fields();
    config.normalize_mesh_fields();
    prepare_normalized_gateway_config_for_mesh(config, runtime, mesh_slice)
}

fn prepare_normalized_gateway_config_for_mesh(
    mut config: GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) -> Result<GatewayConfig, anyhow::Error> {
    let mesh_errors = config.validate_mesh_fields();
    if !mesh_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "Mesh configuration validation failed: {}",
            mesh_errors.join("; ")
        ));
    }

    inject_mesh_global_plugins(&mut config, runtime, mesh_slice);
    materialize_east_west_gateway_proxies(&mut config, runtime, mesh_slice);
    materialize_egress_gateway_proxies(&mut config, runtime, mesh_slice);
    apply_destination_rules(&mut config, runtime, mesh_slice);
    config.normalize_fields();
    config.resolve_upstream_tls();
    Ok(config)
}

fn gateway_config_from_mesh_slice(
    slice: &MeshSlice,
    runtime: &MeshRuntimeConfig,
) -> Result<GatewayConfig, anyhow::Error> {
    let loaded_at = chrono::DateTime::parse_from_rfc3339(&slice.version)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: slice.workloads.clone(),
            services: slice.services.clone(),
            mesh_policies: slice.mesh_policies.clone(),
            peer_authentications: slice.peer_authentications.clone(),
            service_entries: slice.service_entries.clone(),
            request_authentications: slice.request_authentications.clone(),
            telemetry_resources: slice.telemetry_resources.clone(),
            destination_rules: slice.destination_rules.clone(),
            proxy_configs: slice.proxy_configs.clone(),
            // Slice-narrowing is applied CP-side at `MeshSlice::from_gateway_config`.
            // DPs receive the already-narrowed set of services / service-entries /
            // destination-rules; `MeshSidecar` resources are not echoed back.
            sidecars: Vec::new(),
            trust_bundles: slice.trust_bundles.clone(),
            multi_cluster: slice.multi_cluster.clone(),
            outbound_traffic_policy: slice.outbound_traffic_policy,
        })),
        loaded_at,
        ..GatewayConfig::default()
    };
    prepare_gateway_config_for_native_slice(config, runtime, slice)
}

async fn wait_for_initial_mesh_config(
    mesh_state: &MeshRuntimeState,
    runtime: &MeshRuntimeConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(GatewayConfig, Arc<MeshSlice>), anyhow::Error> {
    let mut updates = mesh_state.subscribe();
    loop {
        let snapshot = mesh_state.snapshot();
        if let Some(slice) = snapshot.as_ref().as_ref() {
            match gateway_config_from_mesh_slice(slice, runtime) {
                Ok(config) => return Ok((config, Arc::new(slice.clone()))),
                Err(e) => {
                    warn!(
                        mesh_slice_version = %slice.version,
                        error = %e,
                        "Ignoring invalid initial mesh slice"
                    );
                }
            }
        }

        tokio::select! {
            changed = updates.changed() => {
                if changed.is_err() {
                    return Err(anyhow::anyhow!(
                        "mesh slice update channel closed before a valid initial slice arrived"
                    ));
                }
            }
            _ = wait_for_mesh_shutdown(&mut shutdown_rx) => {
                return Err(anyhow::anyhow!("shutdown requested"));
            }
        }
    }
}

async fn wait_for_mesh_shutdown(shutdown_rx: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

fn materialize_east_west_gateway_proxies(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    if runtime.topology != MeshTopology::EastWestGateway {
        return;
    }

    // Materialize proxies from explicit EastWestGateway config entries (remote
    // gateway backends).
    if let Some(mesh) = config.mesh.as_ref()
        && let Some(multi_cluster) = mesh.multi_cluster.as_ref()
    {
        for gateway in &multi_cluster.east_west_gateways {
            if gateway.namespace != runtime.namespace {
                continue;
            }

            let proxy = east_west_gateway_proxy(gateway, runtime.east_west_listen_port);

            if let Some(existing) = config
                .proxies
                .iter_mut()
                .find(|candidate| candidate.id == proxy.id)
            {
                *existing = proxy;
            } else {
                config.proxies.push(proxy);
            }
        }
    }

    // Materialize SNI-routed TCP passthrough proxies for each local mesh
    // service so that inbound cross-cluster traffic on the east-west listen
    // port reaches the correct workload. Each service gets one proxy (SNI host
    // = service FQDN) and one upstream (targets = workload addresses).
    let (proxies, upstreams) = build_east_west_service_proxies_and_upstreams(
        mesh_slice,
        runtime.east_west_listen_port,
        &runtime.namespace,
        &runtime.cluster_domain,
    );

    if !proxies.is_empty() {
        info!(
            east_west_service_proxies = proxies.len(),
            east_west_service_upstreams = upstreams.len(),
            "Materializing east-west gateway proxies for local mesh services"
        );
    }

    for upstream in upstreams {
        if let Some(existing) = config
            .upstreams
            .iter_mut()
            .find(|candidate| candidate.id == upstream.id)
        {
            *existing = upstream;
        } else {
            config.upstreams.push(upstream);
        }
    }

    for proxy in proxies {
        if let Some(existing) = config
            .proxies
            .iter_mut()
            .find(|candidate| candidate.id == proxy.id)
        {
            *existing = proxy;
        } else {
            config.proxies.push(proxy);
        }
    }
}

fn east_west_gateway_proxy(gateway: &EastWestGateway, listen_port: u16) -> Proxy {
    let now = chrono::Utc::now();
    Proxy {
        id: mesh_east_west_proxy_id(&gateway.namespace, &gateway.name),
        name: Some(format!("mesh east-west {}", gateway.name)),
        namespace: gateway.namespace.clone(),
        hosts: gateway.sni_hosts.clone(),
        listen_path: None,
        backend_scheme: Some(BackendScheme::Tcp),
        dispatch_kind: Default::default(),
        backend_host: gateway.host.clone(),
        backend_port: gateway.port,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
        backend_connect_timeout_ms: 30_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: Some(listen_port),
        frontend_tls: false,
        passthrough: true,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

fn mesh_east_west_proxy_id(namespace: &str, name: &str) -> String {
    format!("__mesh-east-west-{namespace}-{name}").replace(['/', '.'], "-")
}

// ── East-west service proxy materialization ──────────────────────────────

/// Build TCP passthrough proxies and upstreams for local mesh services so that
/// inbound cross-cluster traffic on the east-west listen port is SNI-routed to
/// the correct local workload.
///
/// For each service in the mesh slice:
///   - SNI hostname = `{name}.{namespace}.svc.{cluster_domain}`
///   - One upstream with targets from workload addresses
///   - One TCP passthrough proxy on the east-west listen port
fn build_east_west_service_proxies_and_upstreams(
    mesh_slice: &MeshSlice,
    listen_port: u16,
    namespace: &str,
    cluster_domain: &str,
) -> (Vec<Proxy>, Vec<Upstream>) {
    let mut proxies = Vec::new();
    let mut upstreams = Vec::new();
    let now = chrono::Utc::now();

    for service in &mesh_slice.services {
        // Build upstream targets from workloads that belong to this service.
        let targets = build_east_west_service_targets(
            service,
            &mesh_slice.workloads,
            mesh_slice
                .multi_cluster
                .as_ref()
                .and_then(|multi_cluster| multi_cluster.local_cluster.as_deref()),
        );
        if targets.is_empty() {
            debug!(
                service = %service.name,
                namespace = %service.namespace,
                "Skipping east-west service with no reachable workload targets"
            );
            continue;
        }

        let sni_hostname = format!(
            "{}.{}.svc.{}",
            service.name, service.namespace, cluster_domain
        );
        let upstream_id = mesh_east_west_service_upstream_id(&service.namespace, &service.name);

        let upstream = Upstream {
            id: upstream_id.clone(),
            name: Some(upstream_id.clone()),
            namespace: namespace.to_string(),
            targets,
            algorithm: LoadBalancerAlgorithm::RoundRobin,
            hash_on: None,
            hash_on_cookie_config: None,
            health_checks: Some(HealthCheckConfig {
                active: None,
                passive: Some(PassiveHealthCheck::default()),
            }),
            service_discovery: None,
            subsets: None,
            port_overrides: HashMap::new(),
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        };
        upstreams.push(upstream);

        let proxy_id = mesh_east_west_service_proxy_id(&service.namespace, &service.name);
        let proxy = east_west_service_proxy(
            &proxy_id,
            &sni_hostname,
            namespace,
            &upstream_id,
            listen_port,
            now,
        );
        proxies.push(proxy);
    }

    (proxies, upstreams)
}

/// Build upstream targets from workloads that belong to the given service.
///
/// Matches workloads by SPIFFE ID against the service's `WorkloadRef` list.
/// Each workload address + first port produces one `UpstreamTarget`. When a
/// workload has no addresses, it is skipped (pod IP not yet assigned).
fn build_east_west_service_targets(
    service: &crate::modes::mesh::config::MeshService,
    workloads: &[crate::modes::mesh::config::Workload],
    local_cluster: Option<&str>,
) -> Vec<UpstreamTarget> {
    let mut targets = Vec::new();

    for workload_ref in &service.workloads {
        let Some(workload) = workloads
            .iter()
            .find(|w| w.spiffe_id == workload_ref.spiffe_id)
        else {
            continue;
        };
        if local_cluster.is_some_and(|local_cluster| {
            workload
                .cluster
                .as_deref()
                .is_some_and(|cluster| cluster != local_cluster)
        }) {
            continue;
        }

        // Use the first service port as the target port. If the service has no
        // ports, fall back to the workload's first port.
        let target_port = service
            .ports
            .first()
            .map(|p| p.port)
            .or_else(|| workload.ports.first().map(|p| p.port))
            .unwrap_or(80);

        for address in &workload.addresses {
            targets.push(UpstreamTarget {
                host: address.clone(),
                port: target_port,
                weight: 1,
                tags: workload.selector.labels.clone(),
                path: None,
            });
        }
    }

    targets
}

/// Construct a TCP passthrough proxy for east-west service routing.
fn east_west_service_proxy(
    id: &str,
    sni_hostname: &str,
    namespace: &str,
    upstream_id: &str,
    listen_port: u16,
    now: chrono::DateTime<chrono::Utc>,
) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("mesh east-west svc {sni_hostname}")),
        namespace: namespace.to_string(),
        hosts: vec![sni_hostname.to_string()],
        listen_path: None,
        backend_scheme: Some(BackendScheme::Tcp),
        dispatch_kind: Default::default(),
        backend_host: String::new(),
        backend_port: 0,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
        backend_connect_timeout_ms: 30_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: false,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: Some(upstream_id.to_string()),
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: Some(listen_port),
        frontend_tls: false,
        passthrough: true,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

fn mesh_east_west_service_proxy_id(namespace: &str, name: &str) -> String {
    format!("__mesh-ew-svc-{namespace}-{name}").replace(['/', '.'], "-")
}

fn mesh_east_west_service_upstream_id(namespace: &str, name: &str) -> String {
    format!("__mesh-ew-upstream-{namespace}-{name}").replace(['/', '.'], "-")
}

// ── DestinationRule application ────────────────────────────────────────

/// Apply DestinationRule traffic policies onto matching upstreams.
///
/// For each DestinationRule, we find upstreams whose targets match the DR
/// host and apply:
/// - `connectionPool.tcp.connectTimeout` onto proxies referencing the upstream
/// - `outlierDetection` onto the upstream's passive health check
/// - `loadBalancer` onto the upstream's algorithm
/// - `subsets` as `SubsetDefinition` entries on the upstream
///
/// Multiple DRs targeting the same upstream are applied in a deterministic
/// order — sorted by `(namespace, name)` — so the last-writer-wins outcome
/// is reproducible across CP restarts and DP subscribers.
fn apply_destination_rules(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    let mut touched_upstream_ids = std::collections::HashSet::new();
    let mut sorted_destination_rules: Vec<&MeshDestinationRule> =
        mesh_slice.destination_rules.iter().collect();
    sorted_destination_rules.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

    for dr in sorted_destination_rules {
        let matching_upstream_indices: Vec<usize> = config
            .upstreams
            .iter()
            .enumerate()
            .filter_map(|(idx, upstream)| {
                destination_rule_matches_upstream(dr, upstream).then_some(idx)
            })
            .collect();

        if matching_upstream_indices.is_empty() {
            debug!(
                host = %dr.host,
                rule = %dr.name,
                "DestinationRule has no matching upstream; skipping"
            );
            continue;
        };

        let connect_timeout_ms = dr
            .traffic_policy
            .as_ref()
            .and_then(|tp| tp.connect_timeout_ms);

        for idx in matching_upstream_indices {
            let upstream = &mut config.upstreams[idx];
            let before_upstream_projection = serde_json::to_value(&*upstream).ok();

            if let Some(ref policy) = dr.traffic_policy {
                apply_traffic_policy_to_upstream(upstream, policy, runtime);
            }

            // Build a set of ports actually exposed by this upstream's
            // targets. Used to filter phantom DR entries whose port is not
            // served by any backend — misconfigured DRs (typo in port
            // number) would otherwise silently bloat
            // `Upstream.port_overrides`. Upstreams using service discovery
            // resolve target ports at runtime, so we keep all entries when
            // service_discovery is configured.
            let upstream_target_ports: std::collections::HashSet<u16> =
                upstream.targets.iter().map(|t| t.port).collect();
            let has_service_discovery = upstream.service_discovery.is_some();

            // Second pass: per-port traffic policy overrides land on the
            // upstream's `port_overrides` slot. Pool-level dispatch already
            // keys per destination port, so per-port policy naturally scopes
            // to that port's pool entry. The top-level policy is still applied
            // first so per-port acts as an additive override of the same
            // fields.
            for (port, port_policy) in &dr.port_level_settings {
                if !has_service_discovery && !upstream_target_ports.contains(port) {
                    warn!(
                        rule = %dr.name,
                        upstream = %upstream.id,
                        port = port,
                        "DestinationRule portLevelSettings entry references a port not used by any target; skipping"
                    );
                    continue;
                }

                // The K8s translator emits warnings for
                // `portLevelSettings[].loadBalancer` / `outlierDetection` at
                // translate time (src/config_sources/k8s/istio.rs), but
                // native MeshSubscribe / xDS slices bypass that path. Surface
                // the same gap here so operators see the unenforced fields
                // regardless of how the slice arrives at the data plane.
                if port_policy.load_balancer.is_some() {
                    warn!(
                        rule = %dr.name,
                        upstream = %upstream.id,
                        port = port,
                        "DestinationRule portLevelSettings.loadBalancer is parsed but not enforced per-port today (gateway keeps a single load balancer per upstream); only connectTimeout is applied"
                    );
                }
                if port_policy.outlier_detection.is_some() {
                    warn!(
                        rule = %dr.name,
                        upstream = %upstream.id,
                        port = port,
                        "DestinationRule portLevelSettings.outlierDetection is parsed but not enforced per-port today (gateway keeps a single passive health check per upstream); only connectTimeout is applied"
                    );
                }

                let override_slot = upstream.port_overrides.entry(*port).or_default();
                apply_traffic_policy_to_port_override(override_slot, port_policy);
            }

            if !dr.subsets.is_empty() {
                if upstream.subsets.is_some() {
                    debug!(
                        rule = %dr.name,
                        upstream = %upstream.id,
                        "DestinationRule subsets overwriting existing upstream.subsets"
                    );
                }
                let subset_defs: Vec<SubsetDefinition> = dr
                    .subsets
                    .iter()
                    .map(|subset| SubsetDefinition {
                        name: subset.name.clone(),
                        labels: subset.labels.clone(),
                        traffic_policy: subset.traffic_policy.as_ref().map(|sp| {
                            SubsetTrafficPolicy {
                                load_balancer_algorithm: mesh_lb_to_ferrum(&sp.load_balancer),
                            }
                        }),
                    })
                    .collect();
                upstream.subsets = Some(subset_defs);
            }

            if let Some(timeout_ms) = connect_timeout_ms {
                let upstream_id = upstream.id.clone();
                for proxy in &mut config.proxies {
                    if proxy.upstream_id.as_deref() == Some(upstream_id.as_str())
                        && proxy.backend_connect_timeout_ms != timeout_ms
                    {
                        let now = chrono::Utc::now();
                        debug!(
                            proxy = %proxy.id,
                            upstream = %upstream_id,
                            previous_ms = proxy.backend_connect_timeout_ms,
                            new_ms = timeout_ms,
                            rule = %dr.name,
                            "DestinationRule overriding proxy backend_connect_timeout_ms"
                        );
                        proxy.backend_connect_timeout_ms = timeout_ms;
                        proxy.updated_at = now;
                    }
                }
            }

            let upstream_changed = serde_json::to_value(&*upstream)
                .map(|after| before_upstream_projection.as_ref() != Some(&after))
                .unwrap_or(true);
            if upstream_changed {
                upstream.updated_at = chrono::Utc::now();
                touched_upstream_ids.insert(upstream.id.clone());
            }
        }
    }

    if !touched_upstream_ids.is_empty() {
        let now = chrono::Utc::now();
        for proxy in &mut config.proxies {
            if proxy
                .upstream_id
                .as_deref()
                .is_some_and(|upstream_id| touched_upstream_ids.contains(upstream_id))
            {
                proxy.updated_at = now;
            }
        }
    }
}

/// Project a `MeshTrafficPolicy` onto a per-port `UpstreamPortOverride` slot.
///
/// Only `connect_timeout_ms` is wired into the dispatch hot path today
/// (`Upstream::effective_connect_timeout_ms`). Per-port LB algorithm and
/// hash-key are intentionally NOT applied — the gateway keeps a single
/// `LoadBalancer` per upstream and switching algorithm/ring per destination
/// port would require per-port balancer instances (different counters /
/// hash rings). The translator emits a warning when operators set these on
/// `portLevelSettings[].loadBalancer` so they know the gap.
///
/// Per-port `outlierDetection` is also not split out — it produces a single
/// `PassiveHealthCheck` on the upstream via the top-level policy.
fn apply_traffic_policy_to_port_override(
    slot: &mut UpstreamPortOverride,
    policy: &MeshTrafficPolicy,
) {
    if let Some(timeout_ms) = policy.connect_timeout_ms {
        slot.connect_timeout_ms = Some(timeout_ms);
    }
}

fn destination_rule_matches_upstream(dr: &MeshDestinationRule, upstream: &Upstream) -> bool {
    upstream
        .targets
        .iter()
        .any(|target| destination_rule_host_matches(&dr.host, &dr.namespace, &target.host))
        || upstream
            .name
            .as_deref()
            .is_some_and(|name| destination_rule_host_matches(&dr.host, &dr.namespace, name))
        || destination_rule_host_matches(&dr.host, &dr.namespace, &upstream.id)
}

fn destination_rule_host_matches(rule_host: &str, namespace: &str, candidate: &str) -> bool {
    let rule_host = rule_host.trim_end_matches('.').to_ascii_lowercase();
    let candidate = candidate.trim_end_matches('.').to_ascii_lowercase();
    if candidate == rule_host {
        return true;
    }

    if !rule_host.contains('.') {
        let namespaced = format!("{rule_host}.{namespace}");
        return candidate == namespaced || candidate.starts_with(&format!("{namespaced}.svc."));
    }

    let dot_count = rule_host.bytes().filter(|byte| *byte == b'.').count();
    if dot_count == 1 {
        return candidate.starts_with(&format!("{rule_host}.svc."));
    }
    if rule_host.ends_with(".svc") {
        return candidate.starts_with(&format!("{rule_host}."));
    }

    false
}

/// Apply a `MeshTrafficPolicy` onto a Ferrum `Upstream`.
///
/// When `policy.tls` is `None` the upstream's `backend_tls_*` fields are
/// left untouched and the workload's PeerAuthentication-derived mTLS
/// posture continues to apply. When `policy.tls` is `Some(...)` the DR's
/// TLS settings override the PeerAuthentication defaults via
/// `apply_traffic_policy_tls_to_upstream`.
fn apply_traffic_policy_to_upstream(
    upstream: &mut Upstream,
    policy: &MeshTrafficPolicy,
    runtime: &MeshRuntimeConfig,
) {
    if let Some(lb) = &policy.load_balancer {
        if let Some(algorithm) = mesh_lb_to_ferrum(&policy.load_balancer) {
            upstream.algorithm = algorithm;
        }
        if let MeshLoadBalancer::ConsistentHash(ch) = lb {
            if let Some(header) = &ch.http_header_name {
                upstream.hash_on = Some(format!("header:{header}"));
            } else if let Some(cookie) = &ch.http_cookie_name {
                upstream.hash_on = Some(format!("cookie:{cookie}"));
            } else if ch.use_source_ip {
                upstream.hash_on = Some("ip".to_string());
            }
        }
    }

    // Outlier detection -> passive health check.
    if let Some(ref od) = policy.outlier_detection {
        let passive = upstream
            .health_checks
            .get_or_insert_with(HealthCheckConfig::default)
            .passive
            .get_or_insert_with(PassiveHealthCheck::default);

        if let Some(consecutive) = od.consecutive_errors {
            passive.unhealthy_threshold = consecutive;
        }
        if let Some(interval) = od.interval_seconds {
            passive.unhealthy_window_seconds = interval;
        }
        if let Some(ejection) = od.base_ejection_seconds {
            passive.healthy_after_seconds = ejection;
        }
        if let Some(max_pct) = od.max_ejection_percent {
            passive.max_ejection_percent = Some(max_pct);
        }
    }

    // Backend TLS posture override from DestinationRule.trafficPolicy.tls.
    if let Some(ref tls) = policy.tls {
        apply_traffic_policy_tls_to_upstream(upstream, tls, runtime);
    }
}

/// Project `MeshTrafficPolicyTls` onto an `Upstream`'s `backend_tls_*`
/// fields. The DR wins over the PeerAuthentication-derived default for
/// every field it sets.
///
/// Mapping:
/// - `Disable`: clear all client TLS material; mark server-cert verify off
///   (no TLS handshake actually originates — `backend_scheme` controls that
///   on the proxy side and is not changed here; this only neutralizes the
///   upstream's TLS config so a backend that does happen to negotiate TLS
///   downstream does not pin client material).
/// - `Simple`: enable server-cert verification; populate CA from
///   `ca_certificates`; clear any stale client cert/key.
/// - `Mutual`: enable server-cert verification; populate CA, client cert,
///   and private key from the DR.
/// - `IstioMutual`: enable server-cert verification; project the workload's
///   X.509-SVID cert/key paths and trust bundle from the mesh runtime onto the
///   upstream.
///
/// `insecure_skip_verify=true` always wins: it forces
/// `backend_tls_verify_server_cert=false` regardless of mode.
///
/// SNI (`tls.sni`) and `subject_alt_names` project onto upstream fields here.
/// SAN lists are bounded here too because mesh-projected upstreams skip admin
/// admission. Later backend dispatch/verifier work consumes the resolved cache.
fn apply_traffic_policy_tls_to_upstream(
    upstream: &mut Upstream,
    tls: &MeshTrafficPolicyTls,
    runtime: &MeshRuntimeConfig,
) {
    match tls.mode {
        MtlsMode::Disable => {
            upstream.backend_tls_client_cert_path = None;
            upstream.backend_tls_client_key_path = None;
            upstream.backend_tls_server_ca_cert_path = None;
            upstream.backend_tls_sni = None;
            upstream.backend_tls_san_allow_list.clear();
            // When mTLS is explicitly disabled, leave `verify_server_cert`
            // at its current value (TLS may still originate when the
            // proxy's `backend_scheme` is `https`) unless the operator
            // also asked for skip_verify.
        }
        MtlsMode::Simple => {
            upstream.backend_tls_client_cert_path = None;
            upstream.backend_tls_client_key_path = None;
            upstream.backend_tls_server_ca_cert_path = tls.ca_certificates.clone();
        }
        MtlsMode::Mutual => {
            upstream.backend_tls_client_cert_path = tls.client_certificate.clone();
            upstream.backend_tls_client_key_path = tls.private_key.clone();
            upstream.backend_tls_server_ca_cert_path = tls.ca_certificates.clone();
        }
        MtlsMode::IstioMutual => {
            upstream.backend_tls_server_ca_cert_path =
                runtime.workload_svid_trust_bundle_path.clone();
            if runtime.workload_svid_trust_bundle_path.is_none() {
                warn!(
                    upstream = %upstream.id,
                    "DestinationRule ISTIO_MUTUAL requested but workload SVID trust bundle path is not configured; clearing any stale upstream CA and falling back to global/default trust"
                );
            }
            match (
                runtime.workload_svid_cert_path.clone(),
                runtime.workload_svid_key_path.clone(),
            ) {
                (Some(cert_path), Some(key_path)) => {
                    upstream.backend_tls_client_cert_path = Some(cert_path);
                    upstream.backend_tls_client_key_path = Some(key_path);
                }
                _ => {
                    warn!(
                        upstream = %upstream.id,
                        "DestinationRule ISTIO_MUTUAL requested but workload SVID cert/key paths are not both configured; preserving existing backend client certificate settings"
                    );
                }
            }
        }
        // PeerAuthentication-side modes are rejected at translate time;
        // an in-memory slice that still carries one is a programming
        // error. Treat as a no-op rather than panic on the cold path.
        MtlsMode::Strict | MtlsMode::Permissive => {
            warn!(
                upstream = %upstream.id,
                mode = ?tls.mode,
                "DestinationRule trafficPolicy.tls.mode is a server-side mode and cannot apply to client-side backend TLS; ignoring"
            );
            return;
        }
    }

    // `verify_server_cert` precedence: explicit `insecureSkipVerify=true`
    // forces false; otherwise SIMPLE/MUTUAL/ISTIO_MUTUAL require verify=true
    // and DISABLE leaves the existing value alone.
    if tls.insecure_skip_verify {
        upstream.backend_tls_verify_server_cert = false;
    } else if matches!(
        tls.mode,
        MtlsMode::Simple | MtlsMode::Mutual | MtlsMode::IstioMutual
    ) {
        upstream.backend_tls_verify_server_cert = true;
    }

    if tls.mode != MtlsMode::Disable {
        upstream.backend_tls_sni = bounded_backend_tls_sni(&upstream.id, tls.sni.as_deref());
        upstream.backend_tls_san_allow_list =
            bounded_backend_tls_san_allow_list(&upstream.id, &tls.subject_alt_names);
    }
}

fn bounded_backend_tls_sni(upstream_id: &str, sni: Option<&str>) -> Option<String> {
    let sni = sni?;
    match crate::config::types::validate_backend_tls_sni(sni) {
        Ok(()) => Some(sni.to_ascii_lowercase()),
        Err(error) => {
            warn!(
                upstream = %upstream_id,
                error = %error,
                "DestinationRule trafficPolicy.tls.sni is invalid for backend TLS; dropping SNI override"
            );
            None
        }
    }
}

fn bounded_backend_tls_san_allow_list(upstream_id: &str, sans: &[String]) -> Vec<String> {
    let mut bounded = Vec::with_capacity(sans.len().min(MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES));
    if sans.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES {
        warn!(
            upstream = %upstream_id,
            count = sans.len(),
            max = MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES,
            "DestinationRule subjectAltNames exceeds backend TLS SAN allow-list limit; dropping extra entries"
        );
    }

    for san in sans.iter().take(MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES) {
        if san.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH {
            warn!(
                upstream = %upstream_id,
                len = san.len(),
                max = MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH,
                "DestinationRule subjectAltNames entry exceeds backend TLS SAN allow-list entry limit; dropping entry"
            );
            continue;
        }
        if let Err(error) = crate::config::types::validate_backend_tls_san_allow_list_entry(san) {
            warn!(
                upstream = %upstream_id,
                error = %error,
                "DestinationRule subjectAltNames entry is invalid for backend TLS SAN allow-list; dropping entry"
            );
            continue;
        }
        let mut san = san.clone();
        crate::config::types::normalize_backend_tls_san_allow_list_entry(&mut san);
        bounded.push(san);
    }

    bounded
}

/// Convert a mesh LB config to a Ferrum `LoadBalancerAlgorithm`.
fn mesh_lb_to_ferrum(lb: &Option<MeshLoadBalancer>) -> Option<LoadBalancerAlgorithm> {
    match lb {
        Some(MeshLoadBalancer::Simple(simple)) => match simple {
            MeshSimpleLb::RoundRobin => Some(LoadBalancerAlgorithm::RoundRobin),
            MeshSimpleLb::LeastRequest => Some(LoadBalancerAlgorithm::LeastConnections),
            MeshSimpleLb::Random => Some(LoadBalancerAlgorithm::Random),
            // Istio PASSTHROUGH means direct-to-original-IP; Ferrum always routes via upstreams so RoundRobin is the closest approximation.
            MeshSimpleLb::Passthrough => Some(LoadBalancerAlgorithm::RoundRobin),
        },
        Some(MeshLoadBalancer::ConsistentHash(_)) => Some(LoadBalancerAlgorithm::ConsistentHashing),
        None => None,
    }
}

// ── Egress gateway proxy materialization ─────────────────────────────────

/// Materialize HTTP-family proxies and upstreams from external `ServiceEntry`
/// resources when the topology is `EgressGateway`.
///
/// Each external `ServiceEntry` port produces one `Upstream` (targets from
/// endpoints or DNS hosts) and one `Proxy` per host (host-only routing, no
/// `listen_path`). The resulting proxies accept mesh-internal mTLS from
/// sidecars and forward to external backends with optional re-encryption.
fn materialize_egress_gateway_proxies(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    if runtime.topology != MeshTopology::EgressGateway {
        return;
    }

    let service_entries = &mesh_slice.service_entries;
    if service_entries.is_empty() {
        debug!("egress gateway has no service entries to materialize");
        return;
    }

    let (proxies, upstreams) =
        build_egress_proxies_and_upstreams(service_entries, &runtime.namespace);

    if proxies.is_empty() {
        debug!("no external service entries produced egress proxies");
        return;
    }

    info!(
        egress_proxies = proxies.len(),
        egress_upstreams = upstreams.len(),
        "Materializing egress gateway proxies from external ServiceEntries"
    );

    // Merge upstreams: replace existing by ID or append.
    for upstream in upstreams {
        if let Some(existing) = config
            .upstreams
            .iter_mut()
            .find(|candidate| candidate.id == upstream.id)
        {
            *existing = upstream;
        } else {
            config.upstreams.push(upstream);
        }
    }

    // Merge proxies: replace existing by ID or append.
    for proxy in proxies {
        if let Some(existing) = config
            .proxies
            .iter_mut()
            .find(|candidate| candidate.id == proxy.id)
        {
            *existing = proxy;
        } else {
            config.proxies.push(proxy);
        }
    }
}

/// Build proxy + upstream pairs from external `ServiceEntry` resources.
///
/// Only entries with `location == MeshExternal` are materialized. For each
/// qualifying entry, one upstream per port is created (keyed by host + port
/// number). DNS-resolution entries use the ServiceEntry hosts as backend
/// targets; static-resolution entries use the endpoint addresses.
fn build_egress_proxies_and_upstreams(
    service_entries: &[ServiceEntry],
    namespace: &str,
) -> (Vec<Proxy>, Vec<Upstream>) {
    let mut proxies = Vec::new();
    let mut upstreams = Vec::new();
    let mut materialized_hosts = std::collections::HashSet::new();
    let now = chrono::Utc::now();

    for entry in service_entries {
        if !service_entry_exported_to_namespace(entry, namespace) {
            continue;
        }

        if entry.location != ServiceEntryLocation::MeshExternal {
            continue;
        }

        if entry.hosts.is_empty() {
            continue;
        }

        for port_spec in &entry.ports {
            let Some(backend_scheme) = egress_backend_scheme(port_spec.protocol) else {
                warn!(
                    service_entry = %entry.name,
                    namespace = %entry.namespace,
                    port = port_spec.port,
                    protocol = ?port_spec.protocol,
                    "Skipping non-HTTP ServiceEntry port for egress gateway materialization"
                );
                continue;
            };

            let proxy_hosts: Vec<&String> = entry
                .hosts
                .iter()
                .filter(|host| !materialized_hosts.contains(*host))
                .collect();
            if proxy_hosts.is_empty() {
                warn!(
                    service_entry = %entry.name,
                    namespace = %entry.namespace,
                    port = port_spec.port,
                    "Skipping egress ServiceEntry port because its hosts were already materialized"
                );
                continue;
            }

            // One proxy per host per port.
            for host in proxy_hosts {
                let targets =
                    build_egress_upstream_targets(entry, host, port_spec.port, &port_spec.name);

                if targets.is_empty() {
                    debug!(
                        service_entry = %entry.name,
                        host = %host,
                        port = port_spec.port,
                        "Skipping egress host with no resolvable targets"
                    );
                    continue;
                }

                materialized_hosts.insert(host.clone());

                let upstream_id =
                    mesh_egress_upstream_id(&entry.namespace, &entry.name, host, port_spec.port);

                let upstream = Upstream {
                    id: upstream_id.clone(),
                    name: Some(upstream_id.clone()),
                    namespace: namespace.to_string(),
                    targets,
                    algorithm: LoadBalancerAlgorithm::RoundRobin,
                    hash_on: None,
                    hash_on_cookie_config: None,
                    health_checks: egress_health_checks(),
                    service_discovery: None,
                    subsets: None,
                    port_overrides: HashMap::new(),
                    backend_tls_client_cert_path: None,
                    backend_tls_client_key_path: None,
                    backend_tls_verify_server_cert: true,
                    backend_tls_server_ca_cert_path: None,
                    backend_tls_sni: None,
                    backend_tls_san_allow_list: Vec::new(),
                    api_spec_id: None,
                    created_at: now,
                    updated_at: now,
                };
                upstreams.push(upstream);

                let proxy_id =
                    mesh_egress_proxy_id(&entry.namespace, &entry.name, host, port_spec.port);
                let proxy = egress_gateway_proxy(
                    &proxy_id,
                    host,
                    namespace,
                    Some(backend_scheme),
                    &upstream_id,
                    now,
                );
                proxies.push(proxy);
            }
        }
    }

    (proxies, upstreams)
}

fn egress_health_checks() -> Option<HealthCheckConfig> {
    Some(HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck::default()),
    })
}

/// Build upstream targets from a `ServiceEntry`. When the entry uses static
/// resolution with explicit endpoints, those addresses become targets. When
/// endpoints are empty (DNS or None resolution), each host becomes a target.
fn build_egress_upstream_targets(
    entry: &ServiceEntry,
    host: &str,
    port_number: u16,
    port_name: &Option<String>,
) -> Vec<UpstreamTarget> {
    if entry.resolution == Resolution::Static && !entry.endpoints.is_empty() {
        entry
            .endpoints
            .iter()
            .filter_map(|ep| {
                // Named endpoint ports must be present on each endpoint. Falling
                // back to the ServiceEntry port would route to an unrelated
                // service when endpoint port maps are partial.
                let target_port = match port_name.as_ref() {
                    Some(name) => ep.ports.get(name).copied(),
                    None => Some(port_number),
                }?;

                Some(UpstreamTarget {
                    host: ep.address.clone(),
                    port: target_port,
                    weight: 1,
                    tags: ep.labels.clone(),
                    path: None,
                })
            })
            .collect()
    } else {
        // DNS or None resolution: keep each host's proxy pinned to that host so
        // SNI/Host expectations cannot be crossed by load balancing.
        vec![UpstreamTarget {
            host: host.to_string(),
            port: port_number,
            weight: 1,
            tags: std::collections::HashMap::new(),
            path: None,
        }]
    }
}

/// Determine the backend scheme from the ServiceEntry port protocol.
fn egress_backend_scheme(protocol: AppProtocol) -> Option<BackendScheme> {
    match protocol {
        AppProtocol::Tls | AppProtocol::Http2 | AppProtocol::Grpc => Some(BackendScheme::Https),
        AppProtocol::Http | AppProtocol::Unknown => Some(BackendScheme::Http),
        AppProtocol::Tcp
        | AppProtocol::Mongo
        | AppProtocol::Redis
        | AppProtocol::Mysql
        | AppProtocol::Postgres => None,
    }
}

/// Construct a single egress gateway proxy. Mirrors `east_west_gateway_proxy`
/// in struct construction style but uses HTTP-family settings (host-only
/// routing, no passthrough; the mesh listener owns frontend mTLS termination.
fn egress_gateway_proxy(
    id: &str,
    host: &str,
    namespace: &str,
    backend_scheme: Option<BackendScheme>,
    upstream_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: Some(format!("mesh egress {host}")),
        namespace: namespace.to_string(),
        hosts: vec![host.to_string()],
        listen_path: None,
        backend_scheme,
        dispatch_kind: Default::default(),
        backend_host: String::new(),
        backend_port: 0,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: true,
        backend_connect_timeout_ms: 30_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default(),
        dispatch_port_overrides: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: Vec::<PluginAssociation>::new(),
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        pool_max_requests_per_connection: None,
        upstream_id: Some(upstream_id.to_string()),
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::Stream,
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

fn mesh_egress_proxy_id(namespace: &str, name: &str, host: &str, port: u16) -> String {
    format!(
        "mesh-egress-{}-{}-{}-{port}",
        sanitize_egress_id_part(namespace),
        sanitize_egress_id_part(name),
        sanitize_egress_host_id_part(host)
    )
}

fn mesh_egress_upstream_id(namespace: &str, name: &str, host: &str, port: u16) -> String {
    format!(
        "mesh-egress-up-{}-{}-{}-{port}",
        sanitize_egress_id_part(namespace),
        sanitize_egress_id_part(name),
        sanitize_egress_host_id_part(host)
    )
}

fn sanitize_egress_id_part(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '*' {
            if !sanitized.is_empty() && !sanitized.ends_with('-') {
                sanitized.push('-');
            }
            sanitized.push_str("wildcard");
        } else if ch.is_ascii_alphanumeric() || ch == '_' {
            sanitized.push(ch);
        } else if !sanitized.ends_with('-') {
            sanitized.push('-');
        }
    }
    let sanitized = sanitized.trim_matches('-');
    if sanitized.is_empty() {
        "any".to_string()
    } else {
        sanitized.to_string()
    }
}

fn sanitize_egress_host_id_part(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '*' => push_egress_id_token(&mut sanitized, "wildcard"),
            '.' => push_egress_id_token(&mut sanitized, "dot"),
            '-' => push_egress_id_token(&mut sanitized, "dash"),
            '/' => push_egress_id_token(&mut sanitized, "slash"),
            ch if ch.is_ascii_alphanumeric() || ch == '_' => sanitized.push(ch),
            ch => {
                let token = format!("x{:x}", ch as u32);
                push_egress_id_token(&mut sanitized, &token);
            }
        }
    }
    let sanitized = sanitized.trim_matches('-');
    if sanitized.is_empty() {
        "any".to_string()
    } else {
        sanitized.to_string()
    }
}

fn push_egress_id_token(sanitized: &mut String, token: &str) {
    if !sanitized.is_empty() && !sanitized.ends_with('-') {
        sanitized.push('-');
    }
    sanitized.push_str(token);
    sanitized.push('-');
}

fn inject_mesh_global_plugins(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    ensure_global_plugin(
        config,
        MESH_SPIFFE_IDENTITY_PLUGIN_ID,
        "spiffe_identity",
        serde_json::json!({}),
        &runtime.namespace,
    );
    let trust_domain_aliases: Vec<String> = runtime
        .trust_domain_aliases
        .iter()
        .map(|td| td.as_str().to_string())
        .collect();
    ensure_global_plugin(
        config,
        MESH_AUTHZ_PLUGIN_ID,
        "mesh_authz",
        serde_json::json!({
            "mesh_slice": mesh_slice,
            "trust_domain_aliases": trust_domain_aliases,
        }),
        &runtime.namespace,
    );

    // Outbound registry: inject the `mesh_outbound_registry` plugin when
    // either the slice (CRD path) OR the runtime env var declares
    // REGISTRY_ONLY. Both default to AllowAny (no plugin) so non-mesh
    // and permissive deployments pay zero per-request cost.
    let effective_outbound_policy = mesh_slice
        .outbound_traffic_policy
        .unwrap_or(runtime.outbound_traffic_policy);
    if matches!(
        effective_outbound_policy,
        crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly
    ) {
        let registry = mesh_slice.build_known_destinations(&runtime.cluster_domain);
        let outbound_listen_ports = mesh_outbound_registry_listen_ports(runtime);
        if outbound_listen_ports.is_empty() {
            config
                .plugin_configs
                .retain(|p| p.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID);
        } else {
            let plugin_config = serde_json::json!({
                "registry": registry,
                "outbound_listen_ports": outbound_listen_ports,
                "reject_status": runtime.outbound_registry_reject_status,
            });
            ensure_global_plugin(
                config,
                MESH_OUTBOUND_REGISTRY_PLUGIN_ID,
                "mesh_outbound_registry",
                plugin_config,
                &runtime.namespace,
            );
        }
    } else {
        // Remove any stale instance (e.g., operator flipped policy back).
        config
            .plugin_configs
            .retain(|p| p.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID);
    }

    // Merge applicable Telemetry resources (most specific scope wins per section).
    let merged_telemetry = merge_applicable_telemetry(mesh_slice);

    let mut workload_metrics_config = serde_json::json!({
        "node_id": runtime.node_id.clone(),
        "topology": runtime.topology.as_str(),
        "namespace": mesh_slice.namespace.clone(),
        "workload_spiffe_id": mesh_slice.workload_spiffe_id.clone(),
        "labels": mesh_slice.labels.clone(),
        "trust_domain_aliases": trust_domain_aliases,
    });
    // Apply ProxyConfig sampling as a baseline. The more granular Telemetry
    // resource below may override on the `sampling_percentage` key.
    if let Some(proxy_cfg) = mesh_slice.resolved_proxy_config()
        && let Some(sampling) = proxy_cfg.tracing_sampling
    {
        workload_metrics_config["sampling_percentage"] = serde_json::json!(sampling);
    }
    // Apply tracing config from Telemetry CRD
    if let Some(tracing) = &merged_telemetry.tracing {
        if let Some(sampling_percentage) = tracing.sampling_percentage {
            workload_metrics_config["sampling_percentage"] = serde_json::json!(sampling_percentage);
        }
        if !tracing.custom_tags.is_empty() {
            workload_metrics_config["custom_tags"] = serde_json::json!(tracing.custom_tags);
        }
        if !tracing.custom_header_tags.is_empty() {
            workload_metrics_config["custom_header_tags"] =
                serde_json::json!(tracing.custom_header_tags);
        }
        if let Some(provider) = &tracing.provider {
            workload_metrics_config["tracing_provider"] = serde_json::json!(provider);
        }
    }
    if let Some(metrics) = &merged_telemetry.metrics {
        workload_metrics_config["metrics"] = serde_json::json!(metrics);
    }
    ensure_global_plugin(
        config,
        MESH_WORKLOAD_METRICS_PLUGIN_ID,
        "workload_metrics",
        workload_metrics_config,
        &runtime.namespace,
    );
    inject_mesh_request_auth_plugin(config, runtime, mesh_slice);

    // Build access log config with optional filter from Telemetry CRD
    let access_log_config = if let Some(al) = &merged_telemetry.access_logging {
        if !al.enabled {
            // Access logging disabled — don't inject the plugin
            config
                .plugin_configs
                .retain(|p| p.id != MESH_ACCESS_LOG_PLUGIN_ID);
            return;
        }
        match &al.filter {
            Some(filter) => serde_json::json!({ "filter": filter }),
            None => serde_json::json!({}),
        }
    } else {
        serde_json::json!({})
    };
    ensure_global_plugin(
        config,
        MESH_ACCESS_LOG_PLUGIN_ID,
        "access_log",
        access_log_config,
        &runtime.namespace,
    );
}

fn mesh_outbound_registry_listen_ports(runtime: &MeshRuntimeConfig) -> Vec<u16> {
    let mut ports: Vec<u16> = runtime
        .listener_plan()
        .into_iter()
        .filter(|listener| listener.direction == MeshTrafficDirection::Outbound)
        .filter_map(|listener| {
            let port = listener.addr.port();
            (port != 0).then_some(port)
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Merge applicable `MeshTelemetryResource` entries by scope specificity.
///
/// More specific scopes (WorkloadSelector > Namespace > MeshWide) override
/// less specific ones per config section (tracing, metrics, access_logging
/// independently). Within the same scope level, later resources win.
fn merge_applicable_telemetry(mesh_slice: &MeshSlice) -> MeshTelemetryConfig {
    use crate::modes::mesh::config::scope_applies_to_workload;

    let mut applicable: Vec<(u8, &str, &str, &MeshTelemetryConfig)> = mesh_slice
        .telemetry_resources
        .iter()
        .filter(|t| scope_applies_to_workload(&t.scope, &mesh_slice.namespace, &mesh_slice.labels))
        .map(|t| {
            let specificity = match &t.scope {
                PolicyScope::MeshWide => 0,
                PolicyScope::Namespace { .. } => 1,
                PolicyScope::WorkloadSelector { .. } => 2,
            };
            (
                specificity,
                t.namespace.as_str(),
                t.name.as_str(),
                &t.config,
            )
        })
        .collect();

    // Sort by specificity ascending so more-specific overwrites less-specific.
    // Namespace/name tie-breaks make same-specificity merges deterministic
    // across informer delivery orders.
    applicable.sort_by(|left, right| (left.0, left.1, left.2).cmp(&(right.0, right.1, right.2)));

    let mut merged = MeshTelemetryConfig::default();
    for (_, _, _, config) in &applicable {
        if let Some(tracing) = &config.tracing {
            merge_tracing_config(&mut merged.tracing, tracing);
        }
        if config.metrics.is_some() {
            merged.metrics.clone_from(&config.metrics);
        }
        if config.access_logging.is_some() {
            merged.access_logging.clone_from(&config.access_logging);
        }
    }
    merged
}

fn merge_tracing_config(
    merged: &mut Option<crate::modes::mesh::config::MeshTracingConfig>,
    next: &crate::modes::mesh::config::MeshTracingConfig,
) {
    let current = merged.get_or_insert_with(|| crate::modes::mesh::config::MeshTracingConfig {
        sampling_percentage: None,
        custom_tags: HashMap::new(),
        custom_header_tags: HashMap::new(),
        provider: None,
    });

    if next.sampling_percentage.is_some() {
        current.sampling_percentage = next.sampling_percentage;
    }
    if !next.custom_tags.is_empty() {
        current.custom_tags.clone_from(&next.custom_tags);
    }
    if !next.custom_header_tags.is_empty() {
        current
            .custom_header_tags
            .clone_from(&next.custom_header_tags);
    }
    if next.provider.is_some() {
        current.provider.clone_from(&next.provider);
    }
}

/// Inject a `jwks_auth` global plugin when the mesh slice carries applicable
/// `MeshRequestAuthentication` resources with JWT rules.
///
/// Istio semantics: RequestAuthentication is **permissive** — it declares
/// which JWTs are *valid*, not which are *required*. A request with no JWT
/// passes through. An invalid JWT is rejected. Enforcement (requiring a
/// JWT) comes from AuthorizationPolicy. So the plugin is configured with
/// `anonymous_on_missing_token: true`.
fn inject_mesh_request_auth_plugin(
    config: &mut GatewayConfig,
    runtime: &MeshRuntimeConfig,
    mesh_slice: &MeshSlice,
) {
    use crate::modes::mesh::config::scope_applies_to_workload;

    let applicable: Vec<&MeshRequestAuthentication> = mesh_slice
        .request_authentications
        .iter()
        .filter(|ra| {
            scope_applies_to_workload(&ra.scope, &mesh_slice.namespace, &mesh_slice.labels)
        })
        .collect();

    if applicable.is_empty() {
        // No applicable RequestAuthentication — remove any previously injected
        // mesh request auth plugin so it doesn't persist across config updates.
        config
            .plugin_configs
            .retain(|plugin| plugin.id != MESH_REQUEST_AUTH_PLUGIN_ID);
        return;
    }

    let mut providers = Vec::new();
    for ra in &applicable {
        for rule in &ra.jwt_rules {
            if let Some(provider) = build_jwks_provider_config(rule) {
                providers.push(provider);
            }
        }
    }

    if providers.is_empty() {
        config
            .plugin_configs
            .retain(|plugin| plugin.id != MESH_REQUEST_AUTH_PLUGIN_ID);
        return;
    }

    // jwks_auth already passes through requests with no token
    // (ExtractedCredential::Missing -> PluginResult::Continue), which matches
    // Istio's permissive RequestAuthentication semantics. No extra flag needed.
    //
    // Istio JWTs may omit the `exp` claim, so we disable the default
    // `require_exp=true` that the non-mesh jwks_auth plugin enforces.
    let jwks_config = serde_json::json!({
        "providers": providers,
        "require_exp": false,
    });

    ensure_global_plugin(
        config,
        MESH_REQUEST_AUTH_PLUGIN_ID,
        "jwks_auth",
        jwks_config,
        &runtime.namespace,
    );
}

/// Build a single `jwks_auth` provider configuration from a [`MeshJwtRule`].
fn build_jwks_provider_config(rule: &MeshJwtRule) -> Option<serde_json::Value> {
    let uri = rule.jwks_uri.as_ref()?;

    let mut provider = serde_json::json!({
        "issuer": rule.issuer,
        "jwks_uri": uri,
        "forward_original_token": rule.forward_original_token,
    });

    if !rule.audiences.is_empty() {
        provider["audience"] = serde_json::json!(rule.audiences[0]);
    }

    Some(provider)
}

fn ensure_global_plugin(
    config: &mut GatewayConfig,
    id: &str,
    plugin_name: &str,
    plugin_config: serde_json::Value,
    namespace: &str,
) {
    let now = chrono::Utc::now();
    let mesh_plugin = PluginConfig {
        id: id.to_string(),
        plugin_name: plugin_name.to_string(),
        namespace: namespace.to_string(),
        config: plugin_config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };

    if let Some(existing) = config
        .plugin_configs
        .iter_mut()
        .find(|plugin| plugin.id == id)
    {
        *existing = mesh_plugin;
    } else if config
        .plugin_configs
        .iter()
        .any(|plugin| plugin.scope == PluginScope::Global && plugin.plugin_name == plugin_name)
    {
        // A user-managed global plugin of the same type is an explicit
        // operator override. Reserved mesh-managed IDs still update above.
    } else {
        config.plugin_configs.push(mesh_plugin);
    }
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let runtime = MeshRuntimeConfig::from_env_config(&env_config)
        .map_err(|e| anyhow::anyhow!(e))
        .context("invalid mesh runtime configuration")?;
    ensure_runtime_config_protocol_supported(&runtime)?;

    info!(
        node_id = %runtime.node_id,
        namespace = %runtime.namespace,
        topology = runtime.topology.as_str(),
        config_protocol = runtime.config_protocol.as_str(),
        inbound = %runtime.inbound_listen_addr,
        outbound = %runtime.outbound_listen_addr,
        hbone = %runtime.hbone_listen_addr,
        east_west_listen_port = runtime.east_west_listen_port,
        egress = %runtime.egress_listen_addr,
        cp_urls = runtime.cp_urls.len(),
        "Mesh mode starting"
    );

    let mesh_state = MeshRuntimeState::new();

    let jwt_secret = GrpcJwtSecret::with_issuer(
        env_config.cp_dp_grpc_jwt_secret.clone().ok_or_else(|| {
            anyhow::anyhow!("FERRUM_CP_DP_GRPC_JWT_SECRET is required in mesh mode")
        })?,
        env_config.cp_dp_grpc_jwt_issuer.clone(),
    );
    let grpc_tls = build_dp_grpc_tls_config(&env_config, &runtime.cp_urls, "Mesh")?;
    let mut background_handles = Vec::new();

    match runtime.config_protocol {
        MeshConfigProtocol::Native => {
            let client_config = runtime.native_client_config();
            let request = client_config.subscribe_request(crate::FERRUM_VERSION);
            let cp_urls = runtime.cp_urls.clone();
            let state = mesh_state.clone();
            let shutdown_rx = shutdown_tx.subscribe();
            let handle = tokio::spawn(
                config_consumer::native_client::start_native_mesh_client_with_shutdown(
                    cp_urls,
                    jwt_secret.clone(),
                    client_config,
                    state,
                    shutdown_rx,
                    grpc_tls.clone(),
                ),
            );
            background_handles.push(handle);
            info!(
                node_id = %request.node_id,
                namespace = %request.namespace,
                cp_urls = runtime.cp_urls.len(),
                has_first_slice = mesh_state.has_first_slice(),
                "Mesh mode initialized native MeshSubscribe consumer"
            );
        }
        MeshConfigProtocol::Xds => {
            let xds_config = runtime.xds_client_config();
            let state = mesh_state.clone();
            let shutdown_rx = shutdown_tx.subscribe();
            let handle = tokio::spawn(config_consumer::xds_client::start_xds_client_with_shutdown(
                jwt_secret.clone(),
                xds_config,
                state,
                shutdown_rx,
                grpc_tls.clone(),
            ));
            background_handles.push(handle);
            info!(
                node_id = %runtime.node_id,
                namespace = %runtime.namespace,
                cp_urls = runtime.cp_urls.len(),
                has_first_slice = mesh_state.has_first_slice(),
                "Mesh mode initialized xDS ADS consumer"
            );
        }
    }
    let (bootstrap_config, initial_applied_mesh_slice) =
        wait_for_initial_mesh_config(&mesh_state, &runtime, shutdown_tx.subscribe())
            .await
            .context("mesh runtime stopped before receiving a valid initial mesh slice")?;
    info!(
        mesh_global_plugins = bootstrap_config.plugin_configs.len(),
        mesh_slice_version = %initial_applied_mesh_slice.version,
        "Mesh global plugin chain prepared from initial mesh slice"
    );

    serve_mesh_runtime(
        env_config,
        runtime,
        bootstrap_config,
        shutdown_tx,
        mesh_state,
        Some(initial_applied_mesh_slice),
        background_handles,
    )
    .await
}

fn ensure_runtime_config_protocol_supported(
    runtime: &MeshRuntimeConfig,
) -> Result<(), anyhow::Error> {
    match runtime.config_protocol {
        MeshConfigProtocol::Native | MeshConfigProtocol::Xds => Ok(()),
    }
}

async fn serve_mesh_runtime(
    env_config: EnvConfig,
    runtime: MeshRuntimeConfig,
    config: GatewayConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    mesh_state: MeshRuntimeState,
    initial_applied_mesh_slice: Option<Arc<MeshSlice>>,
    mut mesh_background_handles: Vec<JoinHandle<()>>,
) -> Result<(), anyhow::Error> {
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: env_config.dns_overrides.clone(),
        resolver_addresses: env_config.dns_resolver_address.clone(),
        hosts_file_path: env_config.dns_resolver_hosts_file.clone(),
        dns_order: env_config.dns_order.clone(),
        ttl_override_seconds: env_config.dns_ttl_override,
        min_ttl_seconds: env_config.dns_min_ttl,
        stale_ttl_seconds: env_config.dns_stale_ttl,
        error_ttl_seconds: env_config.dns_error_ttl,
        max_cache_size: env_config.dns_cache_max_size,
        warmup_concurrency: env_config.dns_warmup_concurrency,
        slow_threshold_ms: env_config.dns_slow_threshold_ms,
        refresh_threshold_percent: env_config.dns_refresh_threshold_percent,
        failed_retry_interval_seconds: env_config.dns_failed_retry_interval,
        try_tcp_on_error: env_config.dns_try_tcp_on_error,
        num_concurrent_reqs: env_config.dns_num_concurrent_reqs,
        max_active_requests: env_config.dns_max_active_requests,
        max_concurrent_refreshes: env_config.dns_max_concurrent_refreshes,
        backend_allow_ips: env_config.backend_allow_ips.clone(),
        shard_amount: env_config.pool_shard_amount,
    });

    let mut hostnames: Vec<_> = config
        .proxies
        .iter()
        .map(|proxy| {
            (
                proxy.backend_host.clone(),
                proxy.dns_override.clone(),
                proxy.dns_cache_ttl_seconds,
            )
        })
        .collect();
    for upstream in &config.upstreams {
        for target in &upstream.targets {
            hostnames.push((target.host.clone(), None, None));
        }
    }

    let tls_policy = TlsPolicy::from_env_config(&env_config)?;
    let crls = tls::load_crls(env_config.tls_crl_file_path.as_deref())?;
    let (proxy_state, health_check_handles) = ProxyState::new(
        config,
        dns_cache.clone(),
        env_config.clone(),
        Some(tls_policy.clone()),
        Some(shutdown_tx.subscribe()),
    )?;
    proxy_state
        .stream_listener_manager
        .set_global_shutdown_rx(shutdown_tx.subscribe());

    for host in proxy_state.plugin_cache.collect_warmup_hostnames() {
        hostnames.push((host, None, None));
    }
    dns_cache.warmup(hostnames).await;

    if env_config.pool_warmup_enabled {
        proxy_state.warmup_connection_pools().await;
    }
    proxy_state.start_backend_capability_refresh_task(
        !env_config.pool_warmup_enabled,
        Some(shutdown_tx.subscribe()),
    );
    proxy_state.start_service_discovery(Some(shutdown_tx.subscribe()));

    let dns_handle =
        dns_cache.start_background_refresh_with_shutdown(Some(shutdown_tx.subscribe()));
    let dns_retry_handle = dns_cache.start_failed_retry_task(Some(shutdown_tx.subscribe()));
    let per_ip_cleanup_handle =
        proxy_state.start_per_ip_cleanup_task(Some(shutdown_tx.subscribe()));
    let overload_handle = crate::overload::start_monitor(
        proxy_state.overload.clone(),
        env_config.overload_config(),
        env_config.max_connections,
        env_config.max_requests,
        shutdown_tx.subscribe(),
    );
    let metrics_handle = crate::metrics::start_metrics_monitor(
        proxy_state.request_count.clone(),
        proxy_state.status_counts.clone(),
        proxy_state.windowed_metrics.clone(),
        env_config.status_metrics_window_seconds,
        shutdown_tx.subscribe(),
    );
    // Start mesh DNS proxy if enabled
    let dns_proxy_handle = if runtime.dns_enabled {
        let dns_proxy = Arc::new(MeshDnsProxy::new(
            runtime.dns_listen_addr,
            runtime.dns_upstream_addr,
            runtime.dns_ttl_seconds,
            runtime.dns_max_concurrent_queries,
            runtime.dns_response_cache_max_entries,
            runtime.cluster_domain.clone(),
        ));
        // Build initial resolution table from the applied slice
        if let Some(ref slice) = initial_applied_mesh_slice {
            dns_proxy.update_from_slice(slice);
        }
        let dns_sockets = dns_proxy.bind().await.with_context(|| {
            format!(
                "failed to bind mesh DNS proxy at {}",
                runtime.dns_listen_addr
            )
        })?;
        let dns_shutdown = shutdown_tx.subscribe();
        let dns_runner = dns_proxy.clone();
        mesh_background_handles.push(tokio::spawn(async move {
            dns_runner.run_bound(dns_sockets, dns_shutdown).await;
        }));
        info!(
            addr = %runtime.dns_listen_addr,
            upstream = %runtime.dns_upstream_addr,
            ttl = runtime.dns_ttl_seconds,
            max_concurrent_queries = runtime.dns_max_concurrent_queries,
            response_cache_max_entries = runtime.dns_response_cache_max_entries,
            cluster_domain = %runtime.cluster_domain,
            "Mesh DNS proxy started"
        );
        Some(dns_proxy)
    } else {
        None
    };

    // Resolve mTLS mode from the initial mesh slice. This is evaluated once at
    // startup — PeerAuthentication changes pushed via CP/xDS update the slice
    // but do NOT live-rotate the inbound TLS ServerConfig (consistent with the
    // project's static-TLS-material model). A restart is required.
    let inbound_mtls_mode =
        resolve_inbound_mtls_mode(initial_applied_mesh_slice.as_deref(), &runtime);
    validate_inbound_mtls_mode_for_topology(&runtime, inbound_mtls_mode)?;

    let mesh_apply_handle = start_mesh_slice_apply_task(
        mesh_state,
        proxy_state.clone(),
        runtime.clone(),
        initial_applied_mesh_slice,
        shutdown_tx.subscribe(),
        dns_proxy_handle,
    );

    validate_egress_gateway_mtls_config(&runtime, &env_config)?;
    let frontend_tls = load_mesh_frontend_tls(&env_config, &tls_policy, &crls, inbound_mtls_mode)?;
    if let Some(ref tls_config) = frontend_tls {
        proxy_state
            .stream_listener_manager
            .set_frontend_tls_config(Some(tls_config.clone()))
            .await;
    }

    info!(
        listeners = runtime.listener_plan().len(),
        ?inbound_mtls_mode,
        "Mesh listener plan prepared"
    );
    let mut listener_handles = Vec::new();
    let mut startup_signals = Vec::new();
    for listener in runtime.listener_plan() {
        let tls_config =
            listener_tls_config_for_mtls_mode(&listener, frontend_tls.clone(), inbound_mtls_mode);
        if tls_config.is_none()
            && matches!(
                listener.kind,
                MeshListenerKind::MtlsTermination | MeshListenerKind::HboneTermination
            )
            && inbound_mtls_mode != config::MtlsMode::Disable
        {
            warn!(
                direction = ?listener.direction,
                addr = %listener.addr,
                "Mesh TLS listener is running without frontend TLS because no mesh/frontend certificate is configured"
            );
        }

        let label = format!("{:?} mesh listener", listener.direction);
        let state = proxy_state.clone();
        let shutdown = shutdown_tx.subscribe();
        let addr = listener.addr;
        let direction = listener.direction;
        let kind = listener.kind;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            info!(
                direction = ?direction,
                kind = ?kind,
                addr = %addr,
                "Starting mesh listener"
            );
            if let Err(e) = proxy::start_proxy_listener_with_tls_and_signal(
                addr,
                state,
                shutdown,
                tls_config,
                Some(started_tx),
            )
            .await
            {
                error!(
                    direction = ?direction,
                    kind = ?kind,
                    addr = %addr,
                    "Mesh listener error: {}",
                    e
                );
            }
        });
        listener_handles.push(handle);
        startup_signals.push((label, started_rx));
    }

    let startup_result: Result<(), anyhow::Error> = async {
        proxy_state.initial_reconcile_stream_listeners().await?;
        wait_for_start_signals(startup_signals, Duration::from_secs(10)).await?;
        proxy_state
            .stream_listener_manager
            .wait_until_started(Duration::from_secs(10))
            .await?;
        info!("Mesh runtime startup complete");
        Ok(())
    }
    .await;
    if let Err(e) = startup_result {
        warn!(
            "Mesh runtime startup failed after spawning tasks: {}; draining before returning",
            e
        );
        let _ = shutdown_tx.send(true);
        let _ =
            await_mesh_listener_handles(listener_handles, shutdown_tx.clone(), "startup failure")
                .await;
        shutdown_and_join_mesh(
            proxy_state,
            MeshBackgroundTasks {
                handles: vec![
                    dns_handle,
                    overload_handle,
                    metrics_handle,
                    mesh_apply_handle,
                ],
                dns_retry_handle,
                per_ip_cleanup_handle,
                health_check_handles,
                mesh_background_handles,
            },
            env_config.shutdown_drain_seconds,
        )
        .await;
        return Err(e);
    }

    let listener_result =
        await_mesh_listener_handles(listener_handles, shutdown_tx.clone(), "shutdown").await;

    shutdown_and_join_mesh(
        proxy_state,
        MeshBackgroundTasks {
            handles: vec![
                dns_handle,
                overload_handle,
                metrics_handle,
                mesh_apply_handle,
            ],
            dns_retry_handle,
            per_ip_cleanup_handle,
            health_check_handles,
            mesh_background_handles,
        },
        env_config.shutdown_drain_seconds,
    )
    .await;
    info!("Mesh runtime mode shutting down");
    listener_result?;
    Ok(())
}

/// Resolve the effective mTLS mode for the inbound TLS-terminating listener
/// from the initial mesh slice. Falls back to `Permissive` when no slice or no
/// PeerAuthentication policies are available.
///
/// Port selection follows the topology's TLS-terminating listener (see
/// `listener_plan()`), so PeerAuthentication `port_overrides` keyed on the
/// actual listener port are honoured for every topology, not just Sidecar.
fn resolve_inbound_mtls_mode(
    initial_slice: Option<&MeshSlice>,
    runtime: &MeshRuntimeConfig,
) -> config::MtlsMode {
    let Some(slice) = initial_slice else {
        return config::MtlsMode::Permissive;
    };
    slice.resolve_effective_mtls_mode(inbound_mtls_resolution_port(runtime))
}

/// Pick the port used to resolve PeerAuthentication `port_overrides` for the
/// inbound TLS-terminating listener of the current topology.
fn inbound_mtls_resolution_port(runtime: &MeshRuntimeConfig) -> u16 {
    match runtime.topology {
        MeshTopology::Sidecar => runtime.inbound_listen_addr.port(),
        MeshTopology::Ambient => runtime.hbone_listen_addr.port(),
        MeshTopology::EgressGateway => runtime.egress_listen_addr.port(),
        // East-west gateways do SNI passthrough — no TLS termination, no port
        // override surface. Use inbound for stability; the resolved mode is
        // not consumed by any TLS listener in this topology.
        MeshTopology::EastWestGateway => runtime.inbound_listen_addr.port(),
    }
}

/// Reject `MtlsMode::Disable` on topologies whose inbound listener is
/// fundamentally mTLS-only:
///
/// - **Ambient**: HBONE is HTTP/2 CONNECT over mTLS — running it plaintext
///   is not a valid HBONE listener.
/// - **EgressGateway**: the egress listener must verify sidecar client
///   certificates (already enforced for env-derived TLS materials by
///   `validate_egress_gateway_mtls_config`; this check covers the
///   policy-derived path).
///
/// Sidecar and EastWestGateway accept any resolved mode (EastWestGateway
/// has no TLS termination so it is structurally a no-op).
fn validate_inbound_mtls_mode_for_topology(
    runtime: &MeshRuntimeConfig,
    mtls_mode: config::MtlsMode,
) -> Result<(), anyhow::Error> {
    if mtls_mode != config::MtlsMode::Disable {
        return Ok(());
    }
    match runtime.topology {
        MeshTopology::Ambient => Err(anyhow::anyhow!(
            "Mesh PeerAuthentication resolved to DISABLE on Ambient topology, but HBONE \
             (HTTP/2 CONNECT over mTLS) requires mTLS. Use PERMISSIVE or STRICT for this \
             workload, or move it to Sidecar topology if plaintext-only is intended."
        )),
        MeshTopology::EgressGateway => Err(anyhow::anyhow!(
            "Mesh PeerAuthentication resolved to DISABLE on EgressGateway topology, but the \
             egress mTLS listener must verify sidecar client certificates. Use PERMISSIVE or \
             STRICT for this workload."
        )),
        MeshTopology::Sidecar | MeshTopology::EastWestGateway => Ok(()),
    }
}

/// Build the mesh frontend TLS configuration respecting the resolved mTLS mode.
///
/// - `Strict` / `Permissive`: Load TLS with the appropriate client-auth mode.
/// - `Disable`: Return `None` (plaintext listener).
fn load_mesh_frontend_tls(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &[rustls::pki_types::CertificateRevocationListDer<'static>],
    mtls_mode: config::MtlsMode,
) -> Result<Option<Arc<rustls::ServerConfig>>, anyhow::Error> {
    if mtls_mode == config::MtlsMode::Disable {
        info!(
            "Mesh PeerAuthentication mTLS mode is DISABLE; inbound listener will accept plaintext only"
        );
        return Ok(None);
    }

    let (Some(cert_path), Some(key_path)) = (
        env_config.frontend_tls_cert_path.as_ref(),
        env_config.frontend_tls_key_path.as_ref(),
    ) else {
        if mtls_mode == config::MtlsMode::Strict {
            return Err(anyhow::anyhow!(
                "Mesh PeerAuthentication STRICT requires FERRUM_FRONTEND_TLS_CERT_PATH and FERRUM_FRONTEND_TLS_KEY_PATH"
            ));
        }
        return Ok(None);
    };

    let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.as_deref();
    let client_auth = match mtls_mode {
        config::MtlsMode::Strict => tls::MeshClientAuth::Required,
        config::MtlsMode::Permissive if client_ca_bundle_path.is_some() => {
            tls::MeshClientAuth::Optional
        }
        config::MtlsMode::Permissive => {
            warn!(
                "Mesh PeerAuthentication mTLS mode is PERMISSIVE but no \
                 FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH is configured; \
                 client certificates will not be requested or verified"
            );
            tls::MeshClientAuth::None
        }
        config::MtlsMode::Disable => unreachable!("handled above"),
        // `Simple` / `Mutual` / `IstioMutual` are client-side modes from
        // `DestinationRule.trafficPolicy.tls` and never reach this
        // server-side PeerAuthentication resolver. Treat as a programming
        // error: warn and fall back to no client auth so we don't crash a
        // running data plane.
        config::MtlsMode::Simple | config::MtlsMode::Mutual | config::MtlsMode::IstioMutual => {
            warn!(
                mode = ?mtls_mode,
                "Mesh PeerAuthentication received a client-side DR.tls mode; \
                 falling back to no client auth (this is a programming error \
                 in the K8s translator if observed)"
            );
            tls::MeshClientAuth::None
        }
    };

    let mut tls_config = tls::load_mesh_tls_config(
        cert_path,
        key_path,
        client_ca_bundle_path,
        client_auth,
        tls_policy,
        env_config.tls_cert_expiry_warning_days,
        crls,
    )
    .map_err(|e| anyhow::anyhow!("Invalid mesh frontend TLS configuration: {}", e))?;
    tls::enable_early_data(&mut tls_config, tls_policy);
    if env_config.ktls_enabled.could_be_enabled() {
        tls::enable_secret_extraction_for_ktls(&mut tls_config);
    }
    Ok(Some(tls_config))
}

fn validate_egress_gateway_mtls_config(
    runtime: &MeshRuntimeConfig,
    env_config: &EnvConfig,
) -> Result<(), anyhow::Error> {
    if runtime.topology != MeshTopology::EgressGateway {
        return Ok(());
    }

    if env_config.frontend_tls_cert_path.is_none() || env_config.frontend_tls_key_path.is_none() {
        return Err(anyhow::anyhow!(
            "FERRUM_MESH_TOPOLOGY=egress_gateway requires FERRUM_FRONTEND_TLS_CERT_PATH and FERRUM_FRONTEND_TLS_KEY_PATH for the egress mTLS listener"
        ));
    }

    if env_config.tls_no_verify {
        return Err(anyhow::anyhow!(
            "FERRUM_MESH_TOPOLOGY=egress_gateway cannot be used with FERRUM_TLS_NO_VERIFY=true because the egress mTLS listener must verify sidecar client certificates"
        ));
    }

    if env_config.frontend_tls_client_ca_bundle_path.is_none() {
        return Err(anyhow::anyhow!(
            "FERRUM_MESH_TOPOLOGY=egress_gateway requires FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH so sidecar client certificates are verified"
        ));
    }

    Ok(())
}

fn listener_tls_config(
    listener: &MeshListener,
    frontend_tls: Option<Arc<rustls::ServerConfig>>,
) -> Option<Arc<rustls::ServerConfig>> {
    match listener.kind {
        MeshListenerKind::PlaintextCapture => None,
        MeshListenerKind::MtlsTermination | MeshListenerKind::HboneTermination => frontend_tls,
    }
}

/// Resolve the per-listener TLS config, respecting PeerAuthentication mTLS mode.
///
/// - `Disable` mode: all listeners run plaintext (no TLS config).
/// - `Strict` / `Permissive`: mTLS/HBONE listeners get the frontend TLS config;
///   plaintext-capture listeners stay plaintext.
fn listener_tls_config_for_mtls_mode(
    listener: &MeshListener,
    frontend_tls: Option<Arc<rustls::ServerConfig>>,
    mtls_mode: config::MtlsMode,
) -> Option<Arc<rustls::ServerConfig>> {
    if mtls_mode == config::MtlsMode::Disable {
        return None;
    }
    listener_tls_config(listener, frontend_tls)
}

fn start_mesh_slice_apply_task(
    mesh_state: MeshRuntimeState,
    proxy_state: ProxyState,
    runtime: MeshRuntimeConfig,
    initial_applied_mesh_slice: Option<Arc<MeshSlice>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    dns_proxy: Option<Arc<MeshDnsProxy>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut updates = mesh_state.subscribe();
        let mut last_applied_slice = initial_applied_mesh_slice;
        loop {
            if *shutdown_rx.borrow() {
                return;
            }

            let snapshot = mesh_state.snapshot();
            if let Some(slice) = snapshot.as_ref().as_ref() {
                if mesh_slice_matches_last_applied(last_applied_slice.as_deref(), slice) {
                    debug!(
                        mesh_slice_version = %slice.version,
                        "Skipping no-op mesh slice update"
                    );
                } else {
                    match gateway_config_from_mesh_slice(slice, &runtime) {
                        Ok(config) => {
                            let previous_loaded_at = proxy_state.config.load_full().loaded_at;
                            let candidate_loaded_at = config.loaded_at;
                            let applied = proxy_state.update_config(config);
                            let current_loaded_at = proxy_state.config.load_full().loaded_at;
                            let accepted = mesh_proxy_update_was_accepted(
                                applied,
                                previous_loaded_at,
                                current_loaded_at,
                                candidate_loaded_at,
                            );
                            record_mesh_slice_apply_result(
                                &mut last_applied_slice,
                                slice,
                                accepted,
                            );
                            if accepted && let Some(ref dns_proxy) = dns_proxy {
                                dns_proxy.update_from_slice(slice);
                            }
                            if applied {
                                info!(
                                    mesh_slice_version = %slice.version,
                                    "Applied mesh slice to proxy runtime"
                                );
                            } else if accepted {
                                debug!(
                                    mesh_slice_version = %slice.version,
                                    "Accepted mesh slice with no proxy runtime delta"
                                );
                            } else {
                                warn!(
                                    mesh_slice_version = %slice.version,
                                    "Rejected mesh slice proxy config; leaving last applied slice and DNS table unchanged"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                mesh_slice_version = %slice.version,
                                error = %e,
                                "Ignoring invalid mesh slice update"
                            );
                        }
                    }
                }
            }

            tokio::select! {
                changed = updates.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = wait_for_mesh_shutdown(&mut shutdown_rx) => return,
            }
        }
    })
}

fn mesh_slice_matches_last_applied(
    last_applied_slice: Option<&MeshSlice>,
    slice: &MeshSlice,
) -> bool {
    last_applied_slice.is_some_and(|applied| applied.content_eq(slice))
}

fn record_mesh_slice_apply_result(
    last_applied_slice: &mut Option<Arc<MeshSlice>>,
    slice: &MeshSlice,
    applied: bool,
) {
    if applied {
        *last_applied_slice = Some(Arc::new(slice.clone()));
    }
}

fn mesh_proxy_update_was_accepted(
    applied: bool,
    previous_loaded_at: chrono::DateTime<chrono::Utc>,
    current_loaded_at: chrono::DateTime<chrono::Utc>,
    candidate_loaded_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    applied || (current_loaded_at == candidate_loaded_at && current_loaded_at != previous_loaded_at)
}

struct MeshBackgroundTasks {
    handles: Vec<JoinHandle<()>>,
    dns_retry_handle: Option<JoinHandle<()>>,
    per_ip_cleanup_handle: Option<JoinHandle<()>>,
    health_check_handles: Vec<JoinHandle<()>>,
    mesh_background_handles: Vec<JoinHandle<()>>,
}

async fn await_mesh_listener_handles(
    listener_handles: Vec<JoinHandle<()>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    reason: &str,
) -> Result<(), tokio::task::JoinError> {
    if listener_handles.is_empty() {
        let mut wait_shutdown = shutdown_tx.subscribe();
        while !*wait_shutdown.borrow() {
            if wait_shutdown.changed().await.is_err() {
                break;
            }
        }
        info!(
            reason,
            "Mesh runtime observed shutdown with no active listeners"
        );
        Ok(())
    } else {
        let shutdown_on_panic = move || {
            let _ = shutdown_tx.send(true);
        };
        crate::modes::file::await_listener_handles(listener_handles, shutdown_on_panic).await
    }
}

async fn shutdown_and_join_mesh(
    proxy_state: ProxyState,
    mut tasks: MeshBackgroundTasks,
    drain_seconds: u64,
) {
    proxy_state.stream_listener_manager.shutdown_all().await;
    crate::overload::begin_drain(&proxy_state.overload);
    if drain_seconds > 0 {
        crate::overload::wait_for_drain(&proxy_state.overload, Duration::from_secs(drain_seconds))
            .await;
    }

    if let Some(handle) = tasks.dns_retry_handle {
        tasks.handles.push(handle);
    }
    if let Some(handle) = tasks.per_ip_cleanup_handle {
        tasks.handles.push(handle);
    }
    tasks
        .health_check_handles
        .extend(proxy_state.health_checker.take_active_check_handles());
    tasks.handles.extend(tasks.health_check_handles);
    tasks.handles.extend(tasks.mesh_background_handles);

    crate::modes::file::join_background_handles(tasks.handles, Duration::from_secs(5)).await;
}

fn parse_socket_addr(key: &str, raw: &str) -> Result<SocketAddr, String> {
    raw.parse::<SocketAddr>()
        .map_err(|e| format!("{key} must be a socket address (got '{raw}'): {e}"))
}

/// Parse `FERRUM_MESH_WORKLOAD_LABELS` (`k1=v1,k2=v2`). Empty / `None` returns
/// an empty map. Whitespace around keys/values is trimmed; empty entries are
/// skipped (so a trailing `,` is harmless). Duplicate keys are rejected so the
/// operator catches a typo immediately.
fn parse_workload_labels(
    raw: Option<&str>,
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut labels = std::collections::HashMap::new();
    let Some(raw) = raw else {
        return Ok(labels);
    };
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            format!("FERRUM_MESH_WORKLOAD_LABELS entry '{entry}' must be in 'key=value' form")
        })?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            return Err(format!(
                "FERRUM_MESH_WORKLOAD_LABELS entry '{entry}' has an empty key"
            ));
        }
        if labels.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!(
                "FERRUM_MESH_WORKLOAD_LABELS contains duplicate key '{key}'"
            ));
        }
    }
    Ok(labels)
}

fn parse_port(key: &str, raw: &str) -> Result<u16, String> {
    let port = raw
        .parse::<u16>()
        .map_err(|e| format!("{key} must be a TCP port (got '{raw}'): {e}"))?;
    if port == 0 {
        Err(format!("{key} must be between 1 and 65535 (got 0)"))
    } else {
        Ok(port)
    }
}

fn parse_duration_seconds(key: &str, raw: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|e| format!("{key} must be a duration in seconds (got '{raw}'): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EnvConfig;
    use crate::config::types::PluginScope;
    use crate::dns::{DnsCache, DnsConfig};
    use crate::identity::{SpiffeId, TrustDomain};
    use crate::modes::mesh::config::{
        AccessLogFilter, AppProtocol, EastWestGateway, MeshAccessLoggingConfig, MeshConfig,
        MeshEndpoint, MeshJwtRule, MeshPolicy, MeshRequestAuthentication, MeshRule, MeshService,
        MeshTelemetryResource, MeshTracingConfig, MultiClusterConfig, PolicyAction, PolicyScope,
        PrincipalMatch, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
        TracingProvider, Workload, WorkloadPort, WorkloadSelector,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_mesh_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let keys = [
            "FERRUM_MODE",
            "FERRUM_NAMESPACE",
            "FERRUM_DP_CP_GRPC_URLS",
            "FERRUM_CP_DP_GRPC_JWT_SECRET",
            "FERRUM_MESH_NODE_ID",
            "FERRUM_MESH_CONFIG_PROTOCOL",
            "FERRUM_MESH_XDS_NODE_CLUSTER",
            "FERRUM_MESH_TOPOLOGY",
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            "FERRUM_MESH_HBONE_LISTEN_ADDR",
            "FERRUM_MESH_EAST_WEST_LISTEN_PORT",
            "FERRUM_MESH_EGRESS_LISTEN_ADDR",
            "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
            "FERRUM_MESH_WORKLOAD_LABELS",
            "FERRUM_MESH_TRUST_DOMAIN_ALIASES",
            "FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS",
            "FERRUM_MESH_DNS_PROXY_ENABLED",
            "FERRUM_MESH_DNS_LISTEN_ADDR",
            "FERRUM_MESH_DNS_UPSTREAM_ADDR",
            "FERRUM_MESH_DNS_TTL_SECONDS",
            "FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES",
            "FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES",
            "FERRUM_MESH_CLUSTER_DOMAIN",
            "FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY",
            "FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS",
            "FERRUM_XDS_STREAM_CHANNEL_CAPACITY",
            "FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS",
            "FERRUM_POOL_WARMUP_ENABLED",
            "FERRUM_SHUTDOWN_DRAIN_SECONDS",
        ];

        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
        for (key, value) in vars {
            unsafe { std::env::set_var(key, value) };
        }

        f();

        for key in keys {
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn mesh_runtime_config_defaults_to_sidecar_native_ports() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.node_id, "node-a");
                assert_eq!(runtime.namespace, "ferrum");
                assert_eq!(runtime.cp_urls, vec!["http://cp:50051"]);
                assert_eq!(runtime.config_protocol, MeshConfigProtocol::Native);
                assert_eq!(runtime.topology, MeshTopology::Sidecar);
                assert_eq!(
                    runtime.inbound_listen_addr,
                    DEFAULT_INBOUND_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.outbound_listen_addr,
                    DEFAULT_OUTBOUND_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.hbone_listen_addr,
                    DEFAULT_HBONE_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
                );
                assert_eq!(runtime.east_west_listen_port, DEFAULT_EAST_WEST_LISTEN_PORT);
                assert_eq!(
                    runtime.dns_max_concurrent_queries,
                    DEFAULT_DNS_MAX_CONCURRENT_QUERIES
                );
                assert_eq!(
                    runtime.dns_response_cache_max_entries,
                    dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES
                );
                assert_eq!(runtime.cluster_domain, dns_proxy::DEFAULT_CLUSTER_DOMAIN);
                assert_eq!(runtime.outbound_registry_reject_status, 502);
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_native_ambient_overrides() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                (
                    "FERRUM_DP_CP_GRPC_URLS",
                    "https://cp1:50051,https://cp2:50051",
                ),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-b"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "native"),
                ("FERRUM_MESH_TOPOLOGY", "ambient"),
                ("FERRUM_MESH_INBOUND_LISTEN_ADDR", "127.0.0.1:16006"),
                ("FERRUM_MESH_OUTBOUND_LISTEN_ADDR", "127.0.0.1:16001"),
                ("FERRUM_MESH_HBONE_LISTEN_ADDR", "127.0.0.1:16008"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "16443"),
                ("FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES", "2048"),
                ("FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES", "8192"),
                ("FERRUM_MESH_CLUSTER_DOMAIN", "corp.local"),
                (
                    "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                    "spiffe://cluster.local/ns/default/sa/api",
                ),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.config_protocol, MeshConfigProtocol::Native);
                assert_eq!(runtime.topology, MeshTopology::Ambient);
                assert_eq!(runtime.cp_urls.len(), 2);
                assert_eq!(
                    runtime.workload_spiffe_id.as_deref(),
                    Some("spiffe://cluster.local/ns/default/sa/api")
                );
                assert_eq!(
                    runtime.inbound_listen_addr,
                    "127.0.0.1:16006".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.outbound_listen_addr,
                    "127.0.0.1:16001".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(
                    runtime.hbone_listen_addr,
                    "127.0.0.1:16008".parse::<SocketAddr>().unwrap()
                );
                assert_eq!(runtime.east_west_listen_port, 16443);
                assert_eq!(runtime.dns_max_concurrent_queries, 2048);
                assert_eq!(runtime.dns_response_cache_max_entries, 8192);
                assert_eq!(runtime.cluster_domain, "corp.local");
            },
        );
    }

    #[test]
    fn mesh_runtime_accepts_xds_protocol() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-x"),
                ("FERRUM_MESH_CONFIG_PROTOCOL", "xds"),
                ("FERRUM_MESH_XDS_NODE_CLUSTER", "cluster-a"),
                ("FERRUM_XDS_STREAM_CHANNEL_CAPACITY", "64"),
                ("FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS", "17"),
                ("FERRUM_MESH_WORKLOAD_LABELS", "app=api,version=v1"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config accepts xDS");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let xds_config = runtime.xds_client_config();

                assert_eq!(runtime.config_protocol, MeshConfigProtocol::Xds);
                assert!(ensure_runtime_config_protocol_supported(&runtime).is_ok());
                assert_eq!(xds_config.cp_urls, vec!["http://cp:50051"]);
                assert_eq!(xds_config.node_id, "node-x");
                assert_eq!(xds_config.cluster, "cluster-a");
                assert_eq!(xds_config.stream_channel_capacity, 64);
                assert_eq!(xds_config.primary_retry_secs, 300);
                assert_eq!(xds_config.connect_timeout_seconds, 17);
                assert_eq!(
                    xds_config.labels.get("app").map(String::as_str),
                    Some("api")
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_east_west_gateway_topology() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "15444"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.topology, MeshTopology::EastWestGateway);
                assert_eq!(runtime.east_west_listen_port, 15444);
                assert!(runtime.listener_plan().is_empty());
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_workload_labels() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_WORKLOAD_LABELS", " app = api , version=v1 , ,"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.workload_labels.len(), 2);
                assert_eq!(
                    runtime.workload_labels.get("app").map(String::as_str),
                    Some("api")
                );
                assert_eq!(
                    runtime.workload_labels.get("version").map(String::as_str),
                    Some("v1")
                );
                let request = runtime.mesh_slice_request();
                assert_eq!(request.labels.get("app").map(String::as_str), Some("api"));
                assert_eq!(
                    request.labels.get("version").map(String::as_str),
                    Some("v1")
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_trust_domain_aliases_and_egress_strip_keys() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                (
                    "FERRUM_MESH_TRUST_DOMAIN_ALIASES",
                    " partner.local , legacy.cluster.local ,",
                ),
                (
                    "FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS",
                    " source. , mesh. ,",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                let aliases: Vec<_> = runtime
                    .trust_domain_aliases
                    .iter()
                    .map(|alias| alias.as_str())
                    .collect();
                assert_eq!(aliases, vec!["partner.local", "legacy.cluster.local"]);
                assert_eq!(
                    env.mesh_egress_strip_baggage_keys,
                    vec!["source.".to_string(), "mesh.".to_string()]
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_invalid_trust_domain_alias() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TRUST_DOMAIN_ALIASES", "Bad.Trust"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_TRUST_DOMAIN_ALIASES"));
                assert!(err.contains("Bad.Trust"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_workload_label_without_equals() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_WORKLOAD_LABELS", "appapi"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_WORKLOAD_LABELS"));
                assert!(err.contains("key=value"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_duplicate_workload_label_key() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_WORKLOAD_LABELS", "app=api,app=worker"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("duplicate key"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_bad_topology() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "east-west"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_TOPOLOGY"));
            },
        );
    }

    #[test]
    fn mesh_runtime_config_parses_outbound_registry_reject_status() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS", "403"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.outbound_registry_reject_status, 403);
            },
        );
    }

    #[test]
    fn mesh_runtime_config_rejects_invalid_outbound_registry_reject_status() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS", "399"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let err = MeshRuntimeConfig::from_env_config(&env).unwrap_err();
                assert!(err.contains("FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS"));
            },
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_starts_listeners_and_shuts_down() {
        let env = EnvConfig {
            mode: crate::config::OperatingMode::Mesh,
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            accept_threads: 1,
            ..EnvConfig::default()
        };
        let runtime = MeshRuntimeConfig {
            node_id: "node-a".to_string(),
            namespace: "ferrum".to_string(),
            cp_urls: vec!["http://127.0.0.1:1".to_string()],
            config_protocol: MeshConfigProtocol::Native,
            topology: MeshTopology::Sidecar,
            inbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            outbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            hbone_listen_addr: "127.0.0.1:0".parse().unwrap(),
            east_west_listen_port: DEFAULT_EAST_WEST_LISTEN_PORT,
            egress_listen_addr: DEFAULT_EGRESS_LISTEN_ADDR.parse().unwrap(),
            workload_spiffe_id: None,
            xds_node_cluster: "ferrum".to_string(),
            xds_stream_channel_capacity: 32,
            xds_primary_retry_secs: 300,
            xds_connect_timeout_seconds: 10,
            trust_domain_aliases: Vec::new(),
            workload_labels: HashMap::new(),
            workload_svid_cert_path: None,
            workload_svid_key_path: None,
            workload_svid_trust_bundle_path: None,
            dns_enabled: false,
            dns_listen_addr: DEFAULT_DNS_LISTEN_ADDR.parse().unwrap(),
            dns_upstream_addr: DEFAULT_DNS_UPSTREAM_ADDR.parse().unwrap(),
            dns_ttl_seconds: DEFAULT_DNS_TTL_SECONDS,
            dns_max_concurrent_queries: DEFAULT_DNS_MAX_CONCURRENT_QUERIES,
            dns_response_cache_max_entries: dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES,
            cluster_domain: dns_proxy::DEFAULT_CLUSTER_DOMAIN.to_string(),
            capture_mode: crate::capture::CaptureMode::Explicit,
            outbound_traffic_policy: crate::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
            outbound_registry_reject_status: 502,
            sidecar_enforced: false,
        };
        let config = prepare_gateway_config_for_mesh(GatewayConfig::default(), &runtime).unwrap();
        let mesh_state = MeshRuntimeState::new();
        mesh_state.install_slice(MeshSlice {
            version: chrono::Utc::now().to_rfc3339(),
            ..MeshSlice::default()
        });
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let task_shutdown = shutdown_tx.clone();
        let task = tokio::spawn(async move {
            serve_mesh_runtime(
                env,
                runtime,
                config,
                task_shutdown,
                mesh_state,
                None,
                Vec::new(),
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !task.is_finished(),
            "mesh runtime should keep serving until shutdown"
        );
        let _ = shutdown_tx.send(true);

        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("mesh runtime shut down before timeout")
            .expect("mesh runtime task joined");
        assert!(result.is_ok(), "mesh runtime returned error: {result:?}");
    }

    fn workload(name: &str, app: &str) -> Workload {
        let trust_domain = TrustDomain::new("cluster.local").unwrap();
        Workload {
            spiffe_id: SpiffeId::new(format!("spiffe://cluster.local/ns/default/sa/{name}"))
                .unwrap(),
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), app.to_string())]),
                namespace: Some("default".to_string()),
            },
            service_name: name.to_string(),
            addresses: Vec::new(),
            ports: vec![WorkloadPort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            trust_domain,
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
        }
    }

    fn test_mesh_runtime_config() -> MeshRuntimeConfig {
        MeshRuntimeConfig {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            cp_urls: vec!["http://127.0.0.1:1".to_string()],
            config_protocol: MeshConfigProtocol::Native,
            topology: MeshTopology::Sidecar,
            inbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            outbound_listen_addr: "127.0.0.1:0".parse().unwrap(),
            hbone_listen_addr: "127.0.0.1:0".parse().unwrap(),
            east_west_listen_port: DEFAULT_EAST_WEST_LISTEN_PORT,
            egress_listen_addr: DEFAULT_EGRESS_LISTEN_ADDR.parse().unwrap(),
            workload_spiffe_id: None,
            xds_node_cluster: "default".to_string(),
            xds_stream_channel_capacity: 32,
            xds_primary_retry_secs: 300,
            xds_connect_timeout_seconds: 10,
            trust_domain_aliases: Vec::new(),
            workload_labels: HashMap::new(),
            workload_svid_cert_path: None,
            workload_svid_key_path: None,
            workload_svid_trust_bundle_path: None,
            dns_enabled: false,
            dns_listen_addr: DEFAULT_DNS_LISTEN_ADDR.parse().unwrap(),
            dns_upstream_addr: DEFAULT_DNS_UPSTREAM_ADDR.parse().unwrap(),
            dns_ttl_seconds: DEFAULT_DNS_TTL_SECONDS,
            dns_max_concurrent_queries: DEFAULT_DNS_MAX_CONCURRENT_QUERIES,
            dns_response_cache_max_entries: dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES,
            cluster_domain: dns_proxy::DEFAULT_CLUSTER_DOMAIN.to_string(),
            capture_mode: crate::capture::CaptureMode::Explicit,
            outbound_traffic_policy: crate::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
            outbound_registry_reject_status: 502,
            sidecar_enforced: false,
        }
    }

    fn make_test_proxy_state(initial_config: GatewayConfig) -> ProxyState {
        ProxyState::new(
            initial_config,
            DnsCache::new(DnsConfig::default()),
            EnvConfig {
                pool_warmup_enabled: false,
                shutdown_drain_seconds: 0,
                ..EnvConfig::default()
            },
            None,
            None,
        )
        .expect("ProxyState construction should succeed in tests")
        .0
    }

    fn destination_rule_test_upstream(id: &str, host: &str) -> Upstream {
        let now = chrono::Utc::now();
        Upstream {
            id: id.to_string(),
            namespace: "default".to_string(),
            name: Some(id.to_string()),
            targets: vec![UpstreamTarget {
                host: host.to_string(),
                port: 8080,
                weight: 1,
                tags: HashMap::new(),
                path: None,
            }],
            algorithm: LoadBalancerAlgorithm::RoundRobin,
            hash_on: None,
            hash_on_cookie_config: None,
            health_checks: None,
            service_discovery: None,
            subsets: None,
            port_overrides: HashMap::new(),
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            backend_tls_sni: None,
            backend_tls_san_allow_list: Vec::new(),
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn destination_rule_test_proxy(id: &str, upstream_id: &str) -> Proxy {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "hosts": [format!("{id}.example.com")],
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": upstream_id
        }))
        .expect("test proxy")
    }

    #[test]
    fn destination_rule_applies_short_host_to_all_matching_upstreams() {
        let mut config = GatewayConfig {
            proxies: vec![
                destination_rule_test_proxy("p1", "u1"),
                destination_rule_test_proxy("p2", "u2"),
            ],
            upstreams: vec![
                destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local"),
                destination_rule_test_upstream("u2", "reviews.default.svc.cluster.local"),
            ],
            ..GatewayConfig::default()
        };
        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connect_timeout_ms: Some(1234),
                    load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice);

        assert!(
            config
                .upstreams
                .iter()
                .all(|upstream| upstream.algorithm == LoadBalancerAlgorithm::Random)
        );
        assert!(
            config
                .proxies
                .iter()
                .all(|proxy| proxy.backend_connect_timeout_ms == 1234)
        );
    }

    #[test]
    fn destination_rule_apply_order_is_deterministic_by_namespace_then_name() {
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        // Insert in reverse alphabetical order; sort by (namespace, name) means
        // "default/a-first" applies first and "default/z-last" wins.
        let slice = MeshSlice {
            destination_rules: vec![
                MeshDestinationRule {
                    name: "z-last".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: Some(MeshTrafficPolicy {
                        connect_timeout_ms: Some(9999),
                        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                        ..MeshTrafficPolicy::default()
                    }),
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
                MeshDestinationRule {
                    name: "a-first".to_string(),
                    namespace: "default".to_string(),
                    host: "reviews.default.svc.cluster.local".to_string(),
                    traffic_policy: Some(MeshTrafficPolicy {
                        connect_timeout_ms: Some(1111),
                        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin)),
                        ..MeshTrafficPolicy::default()
                    }),
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                },
            ],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice);

        assert_eq!(config.upstreams[0].algorithm, LoadBalancerAlgorithm::Random);
        assert_eq!(config.proxies[0].backend_connect_timeout_ms, 9999);
    }

    // ── DestinationRule trafficPolicy.tls cold-path apply ──────────────

    #[test]
    fn dr_tls_none_preserves_existing_upstream_backend_tls() {
        // When MeshTrafficPolicy.tls is None the upstream's existing
        // backend_tls_* fields must NOT be touched — PeerAuthentication
        // defaults continue to drive the mTLS posture.
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_client_cert_path = Some("/pre/client.pem".to_string());
        upstream.backend_tls_client_key_path = Some("/pre/client.key".to_string());
        upstream.backend_tls_server_ca_cert_path = Some("/pre/ca.pem".to_string());
        upstream.backend_tls_verify_server_cert = true;

        let policy = MeshTrafficPolicy {
            connect_timeout_ms: Some(1000),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        // backend_tls_* untouched.
        assert_eq!(
            upstream.backend_tls_client_cert_path.as_deref(),
            Some("/pre/client.pem")
        );
        assert_eq!(
            upstream.backend_tls_client_key_path.as_deref(),
            Some("/pre/client.key")
        );
        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/pre/ca.pem")
        );
        assert!(upstream.backend_tls_verify_server_cert);
    }

    #[test]
    fn dr_tls_simple_projects_ca_and_clears_client_material() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_client_cert_path = Some("/stale/client.pem".to_string());
        upstream.backend_tls_client_key_path = Some("/stale/client.key".to_string());

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                sni: Some("reviews.example.com".to_string()),
                ca_certificates: Some("/etc/certs/ca.pem".to_string()),
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/etc/certs/ca.pem")
        );
        assert!(upstream.backend_tls_client_cert_path.is_none());
        assert!(upstream.backend_tls_client_key_path.is_none());
        assert!(upstream.backend_tls_verify_server_cert);
        assert_eq!(
            upstream.backend_tls_sni.as_deref(),
            Some("reviews.example.com")
        );
    }

    #[test]
    fn dr_tls_mutual_projects_full_mtls_material() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Mutual,
                ca_certificates: Some("/etc/certs/ca.pem".to_string()),
                client_certificate: Some("/etc/certs/client.pem".to_string()),
                private_key: Some("/etc/certs/client.key".to_string()),
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        assert_eq!(
            upstream.backend_tls_client_cert_path.as_deref(),
            Some("/etc/certs/client.pem")
        );
        assert_eq!(
            upstream.backend_tls_client_key_path.as_deref(),
            Some("/etc/certs/client.key")
        );
        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/etc/certs/ca.pem")
        );
        assert!(upstream.backend_tls_verify_server_cert);
    }

    #[test]
    fn dr_tls_disable_clears_upstream_backend_tls_material() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_client_cert_path = Some("/pre/client.pem".to_string());
        upstream.backend_tls_client_key_path = Some("/pre/client.key".to_string());
        upstream.backend_tls_server_ca_cert_path = Some("/pre/ca.pem".to_string());
        upstream.backend_tls_sni = Some("stale.mesh.internal".to_string());
        upstream.backend_tls_san_allow_list = vec!["stale.mesh.internal".to_string()];
        // Pre-set verify=true and confirm DISABLE without insecure_skip_verify
        // leaves it at its current value (the comment on
        // `apply_traffic_policy_tls_to_upstream` documents this invariant).
        upstream.backend_tls_verify_server_cert = true;

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Disable,
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        assert!(upstream.backend_tls_client_cert_path.is_none());
        assert!(upstream.backend_tls_client_key_path.is_none());
        assert!(upstream.backend_tls_server_ca_cert_path.is_none());
        assert!(upstream.backend_tls_sni.is_none());
        assert!(upstream.backend_tls_san_allow_list.is_empty());
        assert!(
            upstream.backend_tls_verify_server_cert,
            "DISABLE without insecure_skip_verify must preserve the existing \
             backend_tls_verify_server_cert value (was true before apply)"
        );
    }

    #[test]
    fn dr_tls_disable_with_insecure_skip_verify_flips_verify_false() {
        // Even on DISABLE the explicit `insecureSkipVerify=true` must force
        // backend_tls_verify_server_cert=false — `insecure_skip_verify` has
        // operator-intent precedence over the mode-derived defaults.
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_verify_server_cert = true;

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Disable,
                insecure_skip_verify: true,
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        assert!(!upstream.backend_tls_verify_server_cert);
    }

    #[test]
    fn dr_tls_insecure_skip_verify_forces_verify_false() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_verify_server_cert = true;

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                insecure_skip_verify: true,
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        assert!(!upstream.backend_tls_verify_server_cert);
    }

    #[test]
    fn dr_tls_istio_mutual_projects_runtime_svid_material() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_client_cert_path = Some("/stale/client.pem".to_string());
        upstream.backend_tls_client_key_path = Some("/stale/client.key".to_string());
        upstream.backend_tls_server_ca_cert_path = Some("/stale/ca.pem".to_string());
        upstream.backend_tls_verify_server_cert = false;
        let runtime = MeshRuntimeConfig {
            workload_svid_cert_path: Some("/var/run/secrets/ferrum/svid.pem".to_string()),
            workload_svid_key_path: Some("/var/run/secrets/ferrum/svid.key".to_string()),
            workload_svid_trust_bundle_path: Some(
                "/var/run/secrets/ferrum/trust-bundle.pem".to_string(),
            ),
            ..test_mesh_runtime_config()
        };

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::IstioMutual,
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &runtime);

        assert!(upstream.backend_tls_verify_server_cert);
        assert_eq!(
            upstream.backend_tls_client_cert_path.as_deref(),
            Some("/var/run/secrets/ferrum/svid.pem")
        );
        assert_eq!(
            upstream.backend_tls_client_key_path.as_deref(),
            Some("/var/run/secrets/ferrum/svid.key")
        );
        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/var/run/secrets/ferrum/trust-bundle.pem")
        );
    }

    #[test]
    fn dr_tls_istio_mutual_without_svid_preserves_existing_client_material() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_client_cert_path = Some("/existing/client.pem".to_string());
        upstream.backend_tls_client_key_path = Some("/existing/client.key".to_string());
        upstream.backend_tls_server_ca_cert_path = Some("/stale/ca.pem".to_string());
        upstream.backend_tls_verify_server_cert = false;
        let runtime = MeshRuntimeConfig {
            workload_svid_cert_path: None,
            workload_svid_key_path: None,
            workload_svid_trust_bundle_path: None,
            ..test_mesh_runtime_config()
        };

        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::IstioMutual,
                sni: Some("reviews.mesh.internal".to_string()),
                subject_alt_names: vec!["reviews.mesh.internal".to_string()],
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };
        apply_traffic_policy_to_upstream(&mut upstream, &policy, &runtime);

        assert!(upstream.backend_tls_verify_server_cert);
        assert_eq!(
            upstream.backend_tls_client_cert_path.as_deref(),
            Some("/existing/client.pem")
        );
        assert_eq!(
            upstream.backend_tls_client_key_path.as_deref(),
            Some("/existing/client.key")
        );
        assert!(
            upstream.backend_tls_server_ca_cert_path.is_none(),
            "ISTIO_MUTUAL without a configured trust bundle must not preserve a stale upstream CA"
        );
        assert_eq!(
            upstream.backend_tls_sni.as_deref(),
            Some("reviews.mesh.internal")
        );
        assert_eq!(
            upstream.backend_tls_san_allow_list,
            vec!["reviews.mesh.internal".to_string()]
        );
    }

    #[test]
    fn dr_tls_sni_and_sans_project_onto_upstream() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                sni: Some("reviews.mesh.internal".to_string()),
                subject_alt_names: vec![
                    "reviews.mesh.internal".to_string(),
                    "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
                ],
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };

        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        assert_eq!(
            upstream.backend_tls_sni.as_deref(),
            Some("reviews.mesh.internal")
        );
        assert_eq!(
            upstream.backend_tls_san_allow_list,
            vec![
                "reviews.mesh.internal".to_string(),
                "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
            ]
        );
    }

    #[test]
    fn dr_tls_drops_invalid_sni_and_sans_before_projection() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.backend_tls_sni = Some("stale.mesh.internal".to_string());
        upstream.backend_tls_san_allow_list = vec!["stale.mesh.internal".to_string()];
        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                sni: Some("bad host name".to_string()),
                subject_alt_names: vec![
                    "REVIEWS.Mesh.Internal".to_string(),
                    "10.0.0.8".to_string(),
                    "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
                    "https://not-accepted.example".to_string(),
                    String::new(),
                ],
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };

        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        assert!(upstream.backend_tls_sni.is_none());
        assert_eq!(
            upstream.backend_tls_san_allow_list,
            vec![
                "reviews.mesh.internal".to_string(),
                "10.0.0.8".to_string(),
                "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
            ]
        );
    }

    #[test]
    fn dr_tls_drops_overlong_sni_before_projection() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                sni: Some(format!("{}.mesh.internal", "a".repeat(300))),
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };

        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        assert!(upstream.backend_tls_sni.is_none());
    }

    #[test]
    fn dr_tls_san_allow_list_drops_entries_over_mesh_limit() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                subject_alt_names: (0..=MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES)
                    .map(|i| format!("san-{i}.mesh.internal"))
                    .collect(),
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };

        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        assert_eq!(
            upstream.backend_tls_san_allow_list.len(),
            MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES
        );
        assert_eq!(
            upstream
                .backend_tls_san_allow_list
                .last()
                .map(String::as_str),
            Some("san-255.mesh.internal")
        );
    }

    #[test]
    fn dr_tls_san_allow_list_drops_overlong_entries() {
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        let policy = MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                subject_alt_names: vec![
                    "reviews.mesh.internal".to_string(),
                    format!(
                        "{}.mesh.internal",
                        "a".repeat(MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH)
                    ),
                ],
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        };

        apply_traffic_policy_to_upstream(&mut upstream, &policy, &test_mesh_runtime_config());

        assert_eq!(
            upstream.backend_tls_san_allow_list,
            vec!["reviews.mesh.internal".to_string()]
        );
    }

    #[test]
    fn destination_rule_tls_projection_bumps_referencing_proxy_timestamps() {
        let stale = chrono::Utc::now() - chrono::Duration::hours(1);
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        config.proxies[0].updated_at = stale;
        config.upstreams[0].updated_at = stale;

        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    tls: Some(MeshTrafficPolicyTls {
                        mode: MtlsMode::Simple,
                        sni: Some("reviews.mesh.internal".to_string()),
                        subject_alt_names: vec!["reviews.mesh.internal".to_string()],
                        ..MeshTrafficPolicyTls::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice);

        assert!(
            config.upstreams[0].updated_at > stale,
            "DR-derived upstream TLS changes must make ConfigDelta see the upstream as modified"
        );
        assert!(
            config.proxies[0].updated_at > stale,
            "proxies referencing changed upstreams must rebuild cached route-table proxy Arcs"
        );
    }

    #[test]
    fn dr_tls_flows_end_to_end_through_apply_destination_rules() {
        // Integration-style: a DR with trafficPolicy.tls produces an
        // upstream whose backend_tls_* fields reflect the DR settings.
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };

        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-mtls".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    tls: Some(MeshTrafficPolicyTls {
                        mode: MtlsMode::Mutual,
                        ca_certificates: Some("/etc/certs/ca.pem".to_string()),
                        client_certificate: Some("/etc/certs/client.pem".to_string()),
                        private_key: Some("/etc/certs/client.key".to_string()),
                        ..MeshTrafficPolicyTls::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice);

        let upstream = &config.upstreams[0];
        assert_eq!(
            upstream.backend_tls_client_cert_path.as_deref(),
            Some("/etc/certs/client.pem")
        );
        assert_eq!(
            upstream.backend_tls_client_key_path.as_deref(),
            Some("/etc/certs/client.key")
        );
        assert_eq!(
            upstream.backend_tls_server_ca_cert_path.as_deref(),
            Some("/etc/certs/ca.pem")
        );
        assert!(upstream.backend_tls_verify_server_cert);
    }

    #[test]
    fn destination_rule_top_level_and_per_port_override_apply_independently() {
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![destination_rule_test_upstream(
                "u1",
                "reviews.default.svc.cluster.local",
            )],
            ..GatewayConfig::default()
        };
        let mut port_level = HashMap::new();
        port_level.insert(
            8080u16,
            MeshTrafficPolicy {
                connect_timeout_ms: Some(2222),
                load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                ..MeshTrafficPolicy::default()
            },
        );
        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connect_timeout_ms: Some(1111),
                    load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin)),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: port_level,
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice);

        // Top-level policy still applies to the upstream itself.
        assert_eq!(
            config.upstreams[0].algorithm,
            LoadBalancerAlgorithm::RoundRobin
        );
        assert_eq!(config.proxies[0].backend_connect_timeout_ms, 1111);

        // Per-port 8080 connect-timeout override lands on port_overrides[8080]
        // without disturbing the upstream-level fields or the proxy-default
        // connect timeout. The LB algorithm in `portLevelSettings[].loadBalancer`
        // is intentionally NOT mirrored here today — see
        // `apply_traffic_policy_to_port_override` rationale.
        let port_8080 = config.upstreams[0]
            .port_overrides
            .get(&8080)
            .expect("port 8080 override");
        assert_eq!(port_8080.connect_timeout_ms, Some(2222));

        // Proof that the override is actually consulted at dispatch time via
        // the helper the hot path uses — port 8080 wins, other ports fall
        // back to the proxy default.
        let upstream = &config.upstreams[0];
        assert_eq!(upstream.effective_connect_timeout_ms(8080, 1111), 2222);
        assert_eq!(upstream.effective_connect_timeout_ms(9090, 1111), 1111);
    }

    #[test]
    fn destination_rule_two_per_port_overrides_land_on_distinct_slots() {
        // Upstream must expose BOTH ports the DR references — the phantom-
        // port filter in `apply_destination_rules` rejects per-port settings
        // whose port is not served by any target. Add a 9090 target so the
        // second DR entry has somewhere to land.
        let mut upstream =
            destination_rule_test_upstream("u1", "reviews.default.svc.cluster.local");
        upstream.targets.push(UpstreamTarget {
            host: "reviews.default.svc.cluster.local".to_string(),
            port: 9090,
            weight: 1,
            tags: HashMap::new(),
            path: None,
        });
        let mut config = GatewayConfig {
            proxies: vec![destination_rule_test_proxy("p1", "u1")],
            upstreams: vec![upstream],
            ..GatewayConfig::default()
        };
        let mut port_level = HashMap::new();
        port_level.insert(
            8080u16,
            MeshTrafficPolicy {
                connect_timeout_ms: Some(750),
                load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)),
                ..MeshTrafficPolicy::default()
            },
        );
        port_level.insert(
            9090u16,
            MeshTrafficPolicy {
                connect_timeout_ms: Some(3000),
                load_balancer: Some(MeshLoadBalancer::ConsistentHash(
                    crate::modes::mesh::config::MeshConsistentHash {
                        http_header_name: Some("x-user".to_string()),
                        http_cookie_name: None,
                        use_source_ip: false,
                    },
                )),
                ..MeshTrafficPolicy::default()
            },
        );
        let slice = MeshSlice {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings: port_level,
                subsets: Vec::new(),
            }],
            ..MeshSlice::default()
        };

        apply_destination_rules(&mut config, &test_mesh_runtime_config(), &slice);

        let p8080 = config.upstreams[0]
            .port_overrides
            .get(&8080)
            .expect("port 8080 override");
        assert_eq!(p8080.connect_timeout_ms, Some(750));

        let p9090 = config.upstreams[0]
            .port_overrides
            .get(&9090)
            .expect("port 9090 override");
        assert_eq!(p9090.connect_timeout_ms, Some(3000));

        // Effective-timeout helper is what the dispatch hot path consults.
        // Each port's own override wins; an unrelated port falls back to the
        // proxy default (here passed in as 5000ms).
        let upstream = &config.upstreams[0];
        assert_eq!(upstream.effective_connect_timeout_ms(8080, 5000), 750);
        assert_eq!(upstream.effective_connect_timeout_ms(9090, 5000), 3000);
        assert_eq!(upstream.effective_connect_timeout_ms(7777, 5000), 5000);
    }

    #[test]
    fn telemetry_tracing_merge_preserves_inherited_sampling_for_tag_only_override() {
        let mesh_slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            workload_spiffe_id: None,
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            version: "test".to_string(),
            workloads: Vec::new(),
            services: Vec::new(),
            mesh_policies: Vec::new(),
            peer_authentications: Vec::new(),
            service_entries: Vec::new(),
            request_authentications: Vec::new(),
            telemetry_resources: vec![
                MeshTelemetryResource {
                    name: "mesh-defaults".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    config: MeshTelemetryConfig {
                        tracing: Some(MeshTracingConfig {
                            sampling_percentage: Some(100.0),
                            custom_tags: HashMap::new(),
                            custom_header_tags: HashMap::new(),
                            provider: None,
                        }),
                        ..MeshTelemetryConfig::default()
                    },
                },
                MeshTelemetryResource {
                    name: "api-tags".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    config: MeshTelemetryConfig {
                        tracing: Some(MeshTracingConfig {
                            sampling_percentage: None,
                            custom_tags: HashMap::from([("env".to_string(), "prod".to_string())]),
                            custom_header_tags: HashMap::from([(
                                "tenant".to_string(),
                                "x-tenant".to_string(),
                            )]),
                            provider: None,
                        }),
                        ..MeshTelemetryConfig::default()
                    },
                },
            ],
            destination_rules: Vec::new(),
            proxy_configs: Vec::new(),
            trust_bundles: None,
            multi_cluster: None,
            outbound_traffic_policy: None,
        };

        let merged = merge_applicable_telemetry(&mesh_slice);
        let tracing = merged.tracing.expect("tracing merged");

        assert_eq!(tracing.sampling_percentage, Some(100.0));
        assert_eq!(
            tracing.custom_tags.get("env").map(String::as_str),
            Some("prod")
        );
        assert_eq!(
            tracing.custom_header_tags.get("tenant").map(String::as_str),
            Some("x-tenant")
        );
    }

    #[test]
    fn mesh_runtime_telemetry_uses_mesh_slice_identity_for_native_slices() {
        let runtime = test_mesh_runtime_config();
        let mesh_slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            version: chrono::Utc::now().to_rfc3339(),
            telemetry_resources: vec![MeshTelemetryResource {
                name: "api-access-log".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "api".to_string())]),
                        namespace: Some("default".to_string()),
                    },
                },
                config: MeshTelemetryConfig {
                    access_logging: Some(MeshAccessLoggingConfig {
                        enabled: true,
                        filter: Some(AccessLogFilter {
                            status_code_min: Some(500),
                            status_code_max: None,
                            min_latency_ms: None,
                            errors_only: false,
                        }),
                    }),
                    ..MeshTelemetryConfig::default()
                },
            }],
            ..MeshSlice::default()
        };

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime).expect("mesh slice config");
        let access_log = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_ACCESS_LOG_PLUGIN_ID)
            .expect("access_log plugin injected");

        assert_eq!(access_log.config["filter"]["status_code_min"], 500);
    }

    #[test]
    fn inject_mesh_global_plugins_injects_outbound_registry_from_slice_policy() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_listen_addr = "127.0.0.1:15001".parse().unwrap();
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            services: vec![MeshService {
                name: "reviews".to_string(),
                namespace: "default".to_string(),
                ports: vec![ServicePort {
                    port: 8080,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            outbound_traffic_policy: Some(
                crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly,
            ),
            ..MeshSlice::default()
        };

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime).expect("mesh slice config");
        let registry_plugin = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
            .expect("outbound registry plugin injected");
        let registry = registry_plugin.config["registry"]
            .as_array()
            .expect("registry array");

        assert_eq!(registry_plugin.plugin_name, "mesh_outbound_registry");
        assert_eq!(
            registry_plugin.config["outbound_listen_ports"],
            serde_json::json!([15001])
        );
        assert_eq!(registry_plugin.config["reject_status"], 502);
        assert!(registry.iter().any(|entry| entry == "reviews"));
        assert!(registry.iter().any(|entry| entry == "reviews.default"));
        assert!(
            registry
                .iter()
                .any(|entry| entry == "reviews.default.svc.cluster.local:8080")
        );
    }

    #[test]
    fn inject_mesh_global_plugins_uses_runtime_outbound_registry_reject_status() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_listen_addr = "127.0.0.1:15001".parse().unwrap();
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        runtime.outbound_registry_reject_status = 403;
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime).expect("mesh slice config");
        let registry_plugin = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
            .expect("outbound registry plugin injected");

        assert_eq!(registry_plugin.config["reject_status"], 403);
    }

    #[test]
    fn inject_mesh_global_plugins_skips_outbound_registry_without_outbound_listener() {
        let mut runtime = test_mesh_runtime_config();
        runtime.topology = MeshTopology::EgressGateway;
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime).expect("mesh slice config");

        assert!(
            prepared
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
        );
    }

    #[test]
    fn inject_mesh_global_plugins_runtime_registry_only_applies_when_slice_policy_absent() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_listen_addr = "127.0.0.1:15001".parse().unwrap();
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            services: vec![MeshService {
                name: "ratings".to_string(),
                namespace: "default".to_string(),
                ports: Vec::new(),
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime).expect("mesh slice config");

        let plugin = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
            .expect("outbound registry plugin injected");
        let registry = plugin
            .config
            .get("registry")
            .and_then(serde_json::Value::as_array)
            .expect("registry config array");
        assert!(
            registry
                .iter()
                .any(|entry| entry.as_str() == Some("ratings.default"))
        );
        assert!(
            registry
                .iter()
                .any(|entry| entry.as_str() == Some("ratings.default:*"))
        );
    }

    #[test]
    fn inject_mesh_global_plugins_skips_outbound_registry_when_outbound_port_is_zero() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_listen_addr = "127.0.0.1:0".parse().unwrap();
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime).expect("mesh slice config");

        assert!(
            prepared
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
        );
    }

    #[test]
    fn inject_mesh_global_plugins_slice_allow_any_overrides_runtime_registry_only() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            outbound_traffic_policy: Some(
                crate::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
            ),
            ..MeshSlice::default()
        };

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime).expect("mesh slice config");

        assert!(
            prepared
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
        );
    }

    #[test]
    fn inject_mesh_global_plugins_removes_stale_outbound_registry_when_allow_any() {
        let runtime = test_mesh_runtime_config();
        let now = chrono::Utc::now();
        let mut config = GatewayConfig {
            plugin_configs: vec![crate::config::types::PluginConfig {
                id: MESH_OUTBOUND_REGISTRY_PLUGIN_ID.to_string(),
                plugin_name: "mesh_outbound_registry".to_string(),
                namespace: "default".to_string(),
                config: serde_json::json!({"registry": ["stale.default"]}),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: now,
                updated_at: now,
            }],
            ..GatewayConfig::default()
        };
        let mesh_slice = MeshSlice {
            outbound_traffic_policy: Some(
                crate::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
            ),
            ..MeshSlice::default()
        };

        inject_mesh_global_plugins(&mut config, &runtime, &mesh_slice);

        assert!(
            config
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
        );
    }

    #[test]
    fn inject_mesh_global_plugins_rebuilds_outbound_registry_on_slice_update() {
        let mut runtime = test_mesh_runtime_config();
        runtime.outbound_listen_addr = "127.0.0.1:15001".parse().unwrap();
        runtime.outbound_traffic_policy =
            crate::modes::mesh::config::OutboundTrafficPolicy::RegistryOnly;
        let now = chrono::Utc::now();
        let mut config = GatewayConfig {
            plugin_configs: vec![crate::config::types::PluginConfig {
                id: MESH_OUTBOUND_REGISTRY_PLUGIN_ID.to_string(),
                plugin_name: "mesh_outbound_registry".to_string(),
                namespace: "default".to_string(),
                config: serde_json::json!({"registry": ["stale.default"]}),
                scope: PluginScope::Global,
                proxy_id: None,
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: now,
                updated_at: now,
            }],
            ..GatewayConfig::default()
        };
        let mesh_slice = MeshSlice {
            namespace: "default".to_string(),
            services: vec![MeshService {
                name: "ratings".to_string(),
                namespace: "default".to_string(),
                ports: vec![ServicePort {
                    port: 9080,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                }],
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            outbound_traffic_policy: None,
            ..MeshSlice::default()
        };

        inject_mesh_global_plugins(&mut config, &runtime, &mesh_slice);
        let registry_plugin = config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID)
            .expect("outbound registry plugin retained");
        let registry = registry_plugin.config["registry"]
            .as_array()
            .expect("registry array");

        assert!(registry.iter().any(|entry| entry == "ratings.default"));
        assert!(!registry.iter().any(|entry| entry == "stale.default"));
    }

    #[test]
    fn inject_mesh_global_plugins_merges_zipkin_provider_into_workload_metrics() {
        let runtime = test_mesh_runtime_config();
        let mesh_slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            version: chrono::Utc::now().to_rfc3339(),
            telemetry_resources: vec![MeshTelemetryResource {
                name: "api-tracing".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "api".to_string())]),
                        namespace: Some("default".to_string()),
                    },
                },
                config: MeshTelemetryConfig {
                    tracing: Some(MeshTracingConfig {
                        sampling_percentage: Some(10.0),
                        custom_tags: HashMap::new(),
                        custom_header_tags: HashMap::new(),
                        provider: Some(TracingProvider::Zipkin {
                            url: "http://zipkin.istio-system:9411/api/v2/spans".to_string(),
                        }),
                    }),
                    ..MeshTelemetryConfig::default()
                },
            }],
            ..MeshSlice::default()
        };

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime).expect("mesh slice config");
        let workload_metrics = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
            .expect("workload_metrics plugin injected");

        let provider = workload_metrics
            .config
            .get("tracing_provider")
            .expect("tracing_provider merged into workload_metrics");
        assert_eq!(
            provider.get("kind").and_then(serde_json::Value::as_str),
            Some("zipkin")
        );
        assert_eq!(
            provider
                .pointer("/config/url")
                .and_then(serde_json::Value::as_str),
            Some("http://zipkin.istio-system:9411/api/v2/spans")
        );
        // Sampling percentage from the same Telemetry block is still applied.
        assert_eq!(
            workload_metrics.config["sampling_percentage"],
            serde_json::json!(10.0)
        );
    }

    async fn wait_for_mesh_authz_label(proxy_state: &ProxyState, key: &str, expected: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let observed = proxy_state
                    .current_config()
                    .plugin_configs
                    .iter()
                    .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
                    .and_then(|plugin| {
                        plugin
                            .config
                            .pointer(&format!("/mesh_slice/labels/{key}"))
                            .and_then(|value| value.as_str())
                            .map(str::to_string)
                    });
                if observed.as_deref() == Some(expected) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("mesh_authz label {key} did not become {expected}"));
    }

    #[test]
    fn mesh_runtime_listener_plan_uses_sidecar_ports() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let plan = runtime.listener_plan();

                assert_eq!(plan.len(), 2);
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Outbound
                        && listener.kind == MeshListenerKind::PlaintextCapture
                        && listener.addr.port() == 15001
                }));
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Inbound
                        && listener.kind == MeshListenerKind::MtlsTermination
                        && listener.addr.port() == 15006
                }));
            },
        );
    }

    #[test]
    fn mesh_runtime_listener_plan_uses_ambient_hbone_port() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "ambient"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let plan = runtime.listener_plan();

                assert_eq!(plan.len(), 2);
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Outbound
                        && listener.kind == MeshListenerKind::PlaintextCapture
                        && listener.addr.port() == 15001
                }));
                assert!(plan.iter().any(|listener| {
                    listener.direction == MeshTrafficDirection::Inbound
                        && listener.kind == MeshListenerKind::HboneTermination
                        && listener.addr.port() == 15008
                }));
            },
        );
    }

    #[test]
    fn mesh_runtime_prepares_east_west_passthrough_proxies() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "mesh-system"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "15443"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        multi_cluster: Some(MultiClusterConfig {
                            east_west_gateways: vec![EastWestGateway {
                                name: "remote-a".to_string(),
                                namespace: "mesh-system".to_string(),
                                host: "EastWest.Remote.Example".to_string(),
                                port: 443,
                                sni_hosts: vec!["API.Remote.Example".to_string()],
                                trust_domain: Some(TrustDomain::new("remote.test").unwrap()),
                                network: Some("network-a".to_string()),
                            }],
                            ..MultiClusterConfig::default()
                        }),
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let proxy = prepared
                    .proxies
                    .iter()
                    .find(|proxy| proxy.id == "__mesh-east-west-mesh-system-remote-a")
                    .expect("east-west proxy");

                assert_eq!(proxy.listen_port, Some(15443));
                assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
                assert_eq!(
                    proxy.dispatch_kind,
                    crate::config::types::DispatchKind::TcpRaw
                );
                assert!(proxy.passthrough);
                assert_eq!(proxy.backend_host, "eastwest.remote.example");
                assert_eq!(proxy.hosts, vec!["api.remote.example"]);
            },
        );
    }

    #[test]
    fn east_west_gateway_materializes_service_proxies_from_slice() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "default"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "15443"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        services: vec![MeshService {
                            name: "reviews".to_string(),
                            namespace: "default".to_string(),
                            ports: vec![ServicePort {
                                port: 9080,
                                protocol: AppProtocol::Http,
                                name: Some("http".to_string()),
                            }],
                            workloads: vec![crate::modes::mesh::config::WorkloadRef {
                                spiffe_id: SpiffeId::new(
                                    "spiffe://cluster.local/ns/default/sa/reviews",
                                )
                                .unwrap(),
                            }],
                            protocol_overrides: HashMap::new(),
                        }],
                        workloads: vec![{
                            let mut wl = workload("reviews", "reviews");
                            wl.addresses = vec!["10.0.0.5".to_string()];
                            wl
                        }],
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

                // Verify service proxy was materialized.
                let proxy = prepared
                    .proxies
                    .iter()
                    .find(|p| p.id == "__mesh-ew-svc-default-reviews")
                    .expect("east-west service proxy");

                assert_eq!(proxy.listen_port, Some(15443));
                assert_eq!(proxy.backend_scheme, Some(BackendScheme::Tcp));
                assert!(proxy.passthrough);
                assert_eq!(proxy.hosts, vec!["reviews.default.svc.cluster.local"]);
                assert_eq!(
                    proxy.upstream_id.as_deref(),
                    Some("__mesh-ew-upstream-default-reviews")
                );

                // Verify upstream was materialized.
                let upstream = prepared
                    .upstreams
                    .iter()
                    .find(|u| u.id == "__mesh-ew-upstream-default-reviews")
                    .expect("east-west service upstream");

                assert_eq!(upstream.targets.len(), 1);
                assert_eq!(upstream.targets[0].host, "10.0.0.5");
                assert_eq!(upstream.targets[0].port, 9080);
            },
        );
    }

    #[test]
    fn east_west_gateway_skips_services_without_workload_addresses() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "default"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        services: vec![MeshService {
                            name: "pending".to_string(),
                            namespace: "default".to_string(),
                            ports: vec![ServicePort {
                                port: 8080,
                                protocol: AppProtocol::Http,
                                name: None,
                            }],
                            workloads: vec![crate::modes::mesh::config::WorkloadRef {
                                spiffe_id: SpiffeId::new(
                                    "spiffe://cluster.local/ns/default/sa/pending",
                                )
                                .unwrap(),
                            }],
                            protocol_overrides: HashMap::new(),
                        }],
                        // Workload exists but has no addresses (pod IP not yet assigned).
                        workloads: vec![workload("pending", "pending")],
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

                assert!(
                    !prepared
                        .proxies
                        .iter()
                        .any(|p| p.id == "__mesh-ew-svc-default-pending"),
                    "service with no reachable targets should not produce a proxy"
                );
            },
        );
    }

    #[test]
    fn east_west_gateway_multiple_services_correct_upstream_targets() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "default"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
                ("FERRUM_MESH_EAST_WEST_LISTEN_PORT", "15443"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        services: vec![
                            MeshService {
                                name: "reviews".to_string(),
                                namespace: "default".to_string(),
                                ports: vec![ServicePort {
                                    port: 9080,
                                    protocol: AppProtocol::Http,
                                    name: None,
                                }],
                                workloads: vec![crate::modes::mesh::config::WorkloadRef {
                                    spiffe_id: SpiffeId::new(
                                        "spiffe://cluster.local/ns/default/sa/reviews",
                                    )
                                    .unwrap(),
                                }],
                                protocol_overrides: HashMap::new(),
                            },
                            MeshService {
                                name: "ratings".to_string(),
                                namespace: "default".to_string(),
                                ports: vec![ServicePort {
                                    port: 3000,
                                    protocol: AppProtocol::Http,
                                    name: None,
                                }],
                                workloads: vec![crate::modes::mesh::config::WorkloadRef {
                                    spiffe_id: SpiffeId::new(
                                        "spiffe://cluster.local/ns/default/sa/ratings",
                                    )
                                    .unwrap(),
                                }],
                                protocol_overrides: HashMap::new(),
                            },
                        ],
                        workloads: vec![
                            {
                                let mut wl = workload("reviews", "reviews");
                                wl.addresses = vec!["10.0.0.5".to_string()];
                                wl
                            },
                            {
                                let mut wl = workload("ratings", "ratings");
                                wl.addresses = vec!["10.0.0.6".to_string(), "10.0.0.7".to_string()];
                                wl
                            },
                        ],
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

                // Both services should produce proxies.
                let reviews_proxy = prepared
                    .proxies
                    .iter()
                    .find(|p| p.id == "__mesh-ew-svc-default-reviews")
                    .expect("reviews proxy");
                assert_eq!(reviews_proxy.listen_port, Some(15443));
                assert_eq!(
                    reviews_proxy.hosts,
                    vec!["reviews.default.svc.cluster.local"]
                );

                let ratings_proxy = prepared
                    .proxies
                    .iter()
                    .find(|p| p.id == "__mesh-ew-svc-default-ratings")
                    .expect("ratings proxy");
                assert_eq!(ratings_proxy.listen_port, Some(15443));
                assert_eq!(
                    ratings_proxy.hosts,
                    vec!["ratings.default.svc.cluster.local"]
                );

                // Ratings upstream should have 2 targets (two addresses).
                let ratings_upstream = prepared
                    .upstreams
                    .iter()
                    .find(|u| u.id == "__mesh-ew-upstream-default-ratings")
                    .expect("ratings upstream");
                assert_eq!(ratings_upstream.targets.len(), 2);
                assert_eq!(ratings_upstream.targets[0].host, "10.0.0.6");
                assert_eq!(ratings_upstream.targets[1].host, "10.0.0.7");
                assert_eq!(ratings_upstream.targets[0].port, 3000);
            },
        );
    }

    #[test]
    fn east_west_gateway_service_targets_ignore_remote_cluster_workloads() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_NAMESPACE", "default"),
                ("FERRUM_MESH_TOPOLOGY", "east_west_gateway"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                let mut local = workload("reviews-local", "reviews");
                local.addresses = vec!["10.0.0.5".to_string()];
                local.cluster = Some("cluster-a".to_string());
                let mut remote = workload("reviews-remote", "reviews");
                remote.addresses = vec!["172.16.0.5".to_string()];
                remote.cluster = Some("cluster-b".to_string());
                let mut clusterless = workload("reviews-clusterless", "reviews");
                clusterless.addresses = vec!["10.0.0.6".to_string()];

                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        services: vec![MeshService {
                            name: "reviews".to_string(),
                            namespace: "default".to_string(),
                            ports: vec![ServicePort {
                                port: 9080,
                                protocol: AppProtocol::Http,
                                name: None,
                            }],
                            workloads: vec![
                                crate::modes::mesh::config::WorkloadRef {
                                    spiffe_id: local.spiffe_id.clone(),
                                },
                                crate::modes::mesh::config::WorkloadRef {
                                    spiffe_id: remote.spiffe_id.clone(),
                                },
                                crate::modes::mesh::config::WorkloadRef {
                                    spiffe_id: clusterless.spiffe_id.clone(),
                                },
                            ],
                            protocol_overrides: HashMap::new(),
                        }],
                        workloads: vec![local, remote, clusterless],
                        multi_cluster: Some(MultiClusterConfig {
                            local_cluster: Some("cluster-a".to_string()),
                            ..MultiClusterConfig::default()
                        }),
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let upstream = prepared
                    .upstreams
                    .iter()
                    .find(|u| u.id == "__mesh-ew-upstream-default-reviews")
                    .expect("reviews upstream");
                let hosts: Vec<&str> = upstream
                    .targets
                    .iter()
                    .map(|target| target.host.as_str())
                    .collect();

                assert_eq!(hosts, vec!["10.0.0.5", "10.0.0.6"]);
                assert!(
                    !hosts.contains(&"172.16.0.5"),
                    "remote-cluster workloads should not become local east-west targets"
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_prepares_global_mesh_plugins_from_slice() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
                (
                    "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                    "spiffe://cluster.local/ns/default/sa/api",
                ),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let api_policy = MeshPolicy {
                    name: "api-only".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    rules: vec![MeshRule {
                        from: vec![PrincipalMatch {
                            spiffe_id_pattern: Some(
                                "spiffe://cluster.local/ns/default/sa/client".to_string(),
                            ),
                            namespace_pattern: None,
                            trust_domain: None,
                        }],
                        to: Vec::new(),
                        when: Vec::new(),
                        request_principals: Vec::new(),
                        never_matches: false,
                        action: PolicyAction::Allow,
                    }],
                };
                let worker_policy = MeshPolicy {
                    name: "worker-only".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "worker".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                    rules: Vec::new(),
                };
                let config = GatewayConfig {
                    mesh: Some(Box::new(MeshConfig {
                        workloads: vec![workload("api", "api"), workload("worker", "worker")],
                        mesh_policies: vec![api_policy, worker_policy],
                        ..MeshConfig::default()
                    })),
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let by_id = |id: &str| {
                    prepared
                        .plugin_configs
                        .iter()
                        .find(|plugin| plugin.id == id)
                        .expect("mesh plugin injected")
                };

                assert_eq!(
                    by_id(MESH_SPIFFE_IDENTITY_PLUGIN_ID).plugin_name,
                    "spiffe_identity"
                );
                assert_eq!(by_id(MESH_AUTHZ_PLUGIN_ID).plugin_name, "mesh_authz");
                assert_eq!(
                    by_id(MESH_WORKLOAD_METRICS_PLUGIN_ID).plugin_name,
                    "workload_metrics"
                );
                assert_eq!(by_id(MESH_ACCESS_LOG_PLUGIN_ID).plugin_name, "access_log");
                assert!(
                    prepared
                        .plugin_configs
                        .iter()
                        .all(|plugin| plugin.scope == PluginScope::Global)
                );

                let mesh_slice = by_id(MESH_AUTHZ_PLUGIN_ID)
                    .config
                    .get("mesh_slice")
                    .expect("mesh_authz mesh_slice");
                let policies = mesh_slice
                    .get("mesh_policies")
                    .and_then(|policies| policies.as_array())
                    .expect("mesh policies array");
                assert_eq!(policies.len(), 1);
                assert_eq!(
                    policies[0].get("name").and_then(|name| name.as_str()),
                    Some("api-only")
                );
                assert_eq!(
                    mesh_slice
                        .pointer("/labels/app")
                        .and_then(|label| label.as_str()),
                    Some("api")
                );
            },
        );
    }

    #[test]
    fn mesh_runtime_uses_native_slice_without_reslicing_policies() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_NODE_ID", "node-a"),
                ("FERRUM_NAMESPACE", "default"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let slice = MeshSlice {
                    node_id: "node-a".to_string(),
                    namespace: "default".to_string(),
                    labels: [("app".to_string(), "api".to_string())].into(),
                    version: chrono::Utc::now().to_rfc3339(),
                    mesh_policies: vec![MeshPolicy {
                        name: "api-only".to_string(),
                        namespace: "default".to_string(),
                        scope: PolicyScope::WorkloadSelector {
                            selector: WorkloadSelector {
                                labels: HashMap::from([("app".to_string(), "api".to_string())]),
                                namespace: Some("default".to_string()),
                            },
                        },
                        rules: vec![MeshRule {
                            from: vec![PrincipalMatch {
                                spiffe_id_pattern: Some(
                                    "spiffe://cluster.local/ns/default/sa/client".to_string(),
                                ),
                                namespace_pattern: None,
                                trust_domain: None,
                            }],
                            to: Vec::new(),
                            when: Vec::new(),
                            request_principals: Vec::new(),
                            never_matches: false,
                            action: PolicyAction::Allow,
                        }],
                    }],
                    ..MeshSlice::default()
                };

                let prepared =
                    gateway_config_from_mesh_slice(&slice, &runtime).expect("native slice config");
                let mesh_authz = prepared
                    .plugin_configs
                    .iter()
                    .find(|plugin| plugin.id == MESH_AUTHZ_PLUGIN_ID)
                    .expect("mesh_authz plugin");
                let plugin_slice = mesh_authz
                    .config
                    .get("mesh_slice")
                    .expect("mesh_authz mesh_slice");

                assert_eq!(
                    plugin_slice
                        .pointer("/labels/app")
                        .and_then(|label| label.as_str()),
                    Some("api")
                );
                let policies = plugin_slice
                    .get("mesh_policies")
                    .and_then(|policies| policies.as_array())
                    .expect("mesh policies array");
                assert_eq!(policies.len(), 1);
                assert_eq!(
                    policies[0].get("name").and_then(|name| name.as_str()),
                    Some("api-only")
                );
            },
        );
    }

    #[test]
    fn mesh_slice_rejection_does_not_advance_apply_dedupe_baseline() {
        let mut last_applied_slice = None;
        let rejected = MeshSlice {
            version: "bad-v1".to_string(),
            labels: [("app".to_string(), "api".to_string())].into(),
            ..MeshSlice::default()
        };
        record_mesh_slice_apply_result(&mut last_applied_slice, &rejected, false);
        assert!(last_applied_slice.is_none());
        assert!(!mesh_slice_matches_last_applied(
            last_applied_slice.as_deref(),
            &MeshSlice {
                version: "bad-v2".to_string(),
                labels: [("app".to_string(), "api".to_string())].into(),
                ..MeshSlice::default()
            }
        ));

        record_mesh_slice_apply_result(&mut last_applied_slice, &rejected, true);
        assert!(mesh_slice_matches_last_applied(
            last_applied_slice.as_deref(),
            &MeshSlice {
                version: "bad-v2".to_string(),
                labels: [("app".to_string(), "api".to_string())].into(),
                ..MeshSlice::default()
            }
        ));
    }

    #[test]
    fn mesh_proxy_update_acceptance_distinguishes_no_delta_from_rejection() {
        let previous = chrono::Utc::now();
        let candidate = previous + chrono::Duration::milliseconds(1);

        assert!(mesh_proxy_update_was_accepted(
            true, previous, previous, candidate
        ));
        assert!(mesh_proxy_update_was_accepted(
            false, previous, candidate, candidate
        ));
        assert!(!mesh_proxy_update_was_accepted(
            false, previous, previous, candidate
        ));
        assert!(!mesh_proxy_update_was_accepted(
            false, previous, previous, previous
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_apply_task_propagates_subsequent_native_slices() {
        let runtime = test_mesh_runtime_config();
        let mesh_state = MeshRuntimeState::new();
        let proxy_state = make_test_proxy_state(GatewayConfig::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let apply_task = start_mesh_slice_apply_task(
            mesh_state.clone(),
            proxy_state.clone(),
            runtime,
            None,
            shutdown_rx,
            None,
        );

        mesh_state.install_slice(MeshSlice {
            version: "slice-v1".to_string(),
            labels: [("app".to_string(), "api".to_string())].into(),
            ..MeshSlice::default()
        });
        wait_for_mesh_authz_label(&proxy_state, "app", "api").await;

        mesh_state.install_slice(MeshSlice {
            version: "slice-v2".to_string(),
            labels: [("app".to_string(), "worker".to_string())].into(),
            ..MeshSlice::default()
        });
        wait_for_mesh_authz_label(&proxy_state, "app", "worker").await;

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), apply_task)
            .await
            .expect("apply task should stop")
            .expect("apply task should join");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mesh_runtime_waits_for_valid_initial_native_slice() {
        let runtime = test_mesh_runtime_config();
        let mesh_state = MeshRuntimeState::new();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let state = mesh_state.clone();

        let wait = tokio::spawn(async move {
            wait_for_initial_mesh_config(&state, &runtime, shutdown_rx).await
        });

        mesh_state.install_slice(MeshSlice {
            version: "bad-slice".to_string(),
            services: vec![MeshService {
                name: String::new(),
                namespace: "default".to_string(),
                ports: Vec::new(),
                workloads: Vec::new(),
                protocol_overrides: HashMap::new(),
            }],
            ..MeshSlice::default()
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!wait.is_finished());

        mesh_state.install_slice(MeshSlice {
            version: "good-slice".to_string(),
            ..MeshSlice::default()
        });

        let (config, slice) = wait
            .await
            .expect("wait task joins")
            .expect("valid slice is accepted");
        assert_eq!(slice.version, "good-slice");
        assert!(!config.plugin_configs.is_empty());
    }

    #[test]
    fn mesh_runtime_preserves_operator_global_mesh_plugin_override() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let existing = PluginConfig {
                    id: "operator-mesh-authz".to_string(),
                    plugin_name: "mesh_authz".to_string(),
                    namespace: "ferrum".to_string(),
                    config: serde_json::json!({ "mesh_slice": MeshSlice::default() }),
                    scope: PluginScope::Global,
                    proxy_id: None,
                    enabled: true,
                    priority_override: Some(2005),
                    api_spec_id: None,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                let config = GatewayConfig {
                    plugin_configs: vec![existing],
                    ..GatewayConfig::default()
                };

                let prepared =
                    prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
                let mesh_authz: Vec<_> = prepared
                    .plugin_configs
                    .iter()
                    .filter(|plugin| plugin.plugin_name == "mesh_authz")
                    .collect();

                assert_eq!(mesh_authz.len(), 1);
                assert_eq!(mesh_authz[0].id, "operator-mesh-authz");
                assert!(prepared.plugin_configs.iter().any(|plugin| {
                    plugin.id == MESH_SPIFFE_IDENTITY_PLUGIN_ID
                        && plugin.plugin_name == "spiffe_identity"
                }));
            },
        );
    }

    #[test]
    fn mesh_runtime_updates_mesh_managed_global_plugin_by_id() {
        let runtime = test_mesh_runtime_config();
        let now = chrono::Utc::now();
        let existing = PluginConfig {
            id: MESH_REQUEST_AUTH_PLUGIN_ID.to_string(),
            plugin_name: "jwks_auth".to_string(),
            namespace: "default".to_string(),
            config: serde_json::json!({
                "providers": [
                    { "issuer": "https://stale.example.com", "jwks_uri": "https://stale.example.com/jwks" }
                ]
            }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![test_request_authentication(
                    "fresh",
                    PolicyScope::MeshWide,
                )],
                ..MeshConfig::default()
            })),
            plugin_configs: vec![existing],
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks_plugins: Vec<_> = prepared
            .plugin_configs
            .iter()
            .filter(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .collect();
        assert_eq!(jwks_plugins.len(), 1);
        assert_eq!(
            jwks_plugins[0].config["providers"][0]
                .get("issuer")
                .and_then(|issuer| issuer.as_str()),
            Some("https://fresh.example.com")
        );
    }

    // ── RequestAuthentication injection ──────────────────────────────────

    fn test_request_authentication(name: &str, scope: PolicyScope) -> MeshRequestAuthentication {
        MeshRequestAuthentication {
            name: name.to_string(),
            namespace: "default".to_string(),
            scope,
            jwt_rules: vec![MeshJwtRule {
                issuer: format!("https://{name}.example.com"),
                audiences: vec!["test-app".to_string()],
                jwks_uri: Some(format!("https://{name}.example.com/jwks")),
                jwks: None,
                from_headers: Vec::new(),
                from_params: Vec::new(),
                forward_original_token: false,
            }],
        }
    }

    #[test]
    fn mesh_runtime_injects_jwks_auth_for_matching_request_authentication() {
        let runtime = MeshRuntimeConfig {
            workload_labels: HashMap::from([("app".to_string(), "api".to_string())]),
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![test_request_authentication(
                    "api-jwt",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin injected");

        assert_eq!(jwks.plugin_name, "jwks_auth");
        assert_eq!(jwks.scope, PluginScope::Global);
        let providers = jwks
            .config
            .get("providers")
            .and_then(|v| v.as_array())
            .expect("providers array");
        assert_eq!(providers.len(), 1);
        assert_eq!(
            providers[0].get("issuer").and_then(|v| v.as_str()),
            Some("https://api-jwt.example.com")
        );
    }

    #[test]
    fn mesh_runtime_request_auth_uses_mesh_slice_identity_for_native_slices() {
        let runtime = test_mesh_runtime_config();
        let mesh_slice = MeshSlice {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
            version: chrono::Utc::now().to_rfc3339(),
            request_authentications: vec![test_request_authentication(
                "api-jwt",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "api".to_string())]),
                        namespace: Some("default".to_string()),
                    },
                },
            )],
            ..MeshSlice::default()
        };

        let prepared =
            gateway_config_from_mesh_slice(&mesh_slice, &runtime).expect("mesh slice config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin injected");
        let providers = jwks
            .config
            .get("providers")
            .and_then(|v| v.as_array())
            .expect("providers array");

        assert_eq!(
            providers[0].get("issuer").and_then(|v| v.as_str()),
            Some("https://api-jwt.example.com")
        );
    }

    #[test]
    fn mesh_runtime_does_not_inject_jwks_auth_for_non_matching_selector() {
        let runtime = MeshRuntimeConfig {
            workload_labels: HashMap::from([("app".to_string(), "worker".to_string())]),
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![test_request_authentication(
                    "api-only-jwt",
                    PolicyScope::WorkloadSelector {
                        selector: WorkloadSelector {
                            labels: HashMap::from([("app".to_string(), "api".to_string())]),
                            namespace: Some("default".to_string()),
                        },
                    },
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        assert!(
            !prepared
                .plugin_configs
                .iter()
                .any(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID),
            "jwks_auth should not be injected for non-matching workload"
        );
    }

    #[test]
    fn mesh_runtime_merges_multiple_request_authentications() {
        let runtime = MeshRuntimeConfig {
            workload_labels: HashMap::from([("app".to_string(), "api".to_string())]),
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![
                    test_request_authentication(
                        "google",
                        PolicyScope::Namespace {
                            namespace: "default".to_string(),
                        },
                    ),
                    test_request_authentication("okta", PolicyScope::MeshWide),
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin injected");

        let providers = jwks
            .config
            .get("providers")
            .and_then(|v| v.as_array())
            .expect("providers array");
        assert_eq!(
            providers.len(),
            2,
            "both request authentications' rules should merge into providers"
        );
    }

    #[test]
    fn mesh_runtime_does_not_inject_jwks_auth_for_empty_rules() {
        let runtime = test_mesh_runtime_config();
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![MeshRequestAuthentication {
                    name: "empty".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    jwt_rules: Vec::new(),
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        assert!(
            !prepared
                .plugin_configs
                .iter()
                .any(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID),
            "empty jwt_rules should not inject jwks_auth"
        );
    }

    #[test]
    fn mesh_runtime_request_auth_jwks_config_contains_audience() {
        let runtime = test_mesh_runtime_config();
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![MeshRequestAuthentication {
                    name: "with-aud".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    jwt_rules: vec![MeshJwtRule {
                        issuer: "https://auth.example.com".to_string(),
                        audiences: vec!["my-api".to_string()],
                        jwks_uri: Some("https://auth.example.com/jwks".to_string()),
                        jwks: None,
                        from_headers: Vec::new(),
                        from_params: Vec::new(),
                        forward_original_token: false,
                    }],
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin");

        let provider = &jwks.config["providers"][0];
        assert_eq!(
            provider.get("audience").and_then(|v| v.as_str()),
            Some("my-api"),
            "first audience should be set"
        );
        assert_eq!(
            provider.get("jwks_uri").and_then(|v| v.as_str()),
            Some("https://auth.example.com/jwks")
        );
    }

    #[test]
    fn mesh_runtime_request_auth_sets_require_exp_false() {
        let runtime = test_mesh_runtime_config();
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                request_authentications: vec![MeshRequestAuthentication {
                    name: "exp-test".to_string(),
                    namespace: "default".to_string(),
                    scope: PolicyScope::MeshWide,
                    jwt_rules: vec![MeshJwtRule {
                        issuer: "https://auth.example.com".to_string(),
                        audiences: Vec::new(),
                        jwks_uri: Some("https://auth.example.com/jwks".to_string()),
                        jwks: None,
                        from_headers: Vec::new(),
                        from_params: Vec::new(),
                        forward_original_token: false,
                    }],
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");
        let jwks = prepared
            .plugin_configs
            .iter()
            .find(|plugin| plugin.id == MESH_REQUEST_AUTH_PLUGIN_ID)
            .expect("jwks_auth plugin");

        // Istio JWTs may omit `exp`, so mesh injection must disable
        // the default require_exp=true behavior.
        assert_eq!(
            jwks.config.get("require_exp").and_then(|v| v.as_bool()),
            Some(false),
            "mesh request auth must set require_exp=false for Istio compatibility"
        );
    }

    // ── EgressGateway topology tests ─────────────────────────────────────

    #[test]
    fn mesh_topology_parses_egress_gateway_variants() {
        assert_eq!(
            MeshTopology::parse("egress_gateway").unwrap(),
            MeshTopology::EgressGateway
        );
        assert_eq!(
            MeshTopology::parse("egress-gateway").unwrap(),
            MeshTopology::EgressGateway
        );
        assert_eq!(
            MeshTopology::parse("EGRESS_GATEWAY").unwrap(),
            MeshTopology::EgressGateway
        );
        assert!(MeshTopology::parse("egress").is_err());
        assert_eq!(MeshTopology::EgressGateway.as_str(), "egress_gateway");
    }

    #[test]
    fn mesh_runtime_config_parses_egress_gateway_topology() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "egress_gateway"),
                ("FERRUM_MESH_EGRESS_LISTEN_ADDR", "0.0.0.0:15444"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");

                assert_eq!(runtime.topology, MeshTopology::EgressGateway);
                assert_eq!(
                    runtime.egress_listen_addr,
                    "0.0.0.0:15444".parse::<SocketAddr>().unwrap()
                );
            },
        );
    }

    #[test]
    fn mesh_egress_gateway_listener_plan_has_single_mtls_listener() {
        with_mesh_env(
            &[
                ("FERRUM_MODE", "mesh"),
                ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
                (
                    "FERRUM_CP_DP_GRPC_JWT_SECRET",
                    "secret-padding-for-32-char-min!!",
                ),
                ("FERRUM_MESH_TOPOLOGY", "egress_gateway"),
                ("FERRUM_MESH_EGRESS_LISTEN_ADDR", "0.0.0.0:15443"),
            ],
            || {
                let env = EnvConfig::from_env().expect("mesh env config");
                let runtime =
                    MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
                let plan = runtime.listener_plan();

                assert_eq!(plan.len(), 1);
                let listener = &plan[0];
                assert_eq!(listener.direction, MeshTrafficDirection::Inbound);
                assert_eq!(listener.kind, MeshListenerKind::MtlsTermination);
                assert_eq!(listener.addr.port(), 15443);
            },
        );
    }

    #[test]
    fn egress_gateway_requires_mtls_materials() {
        let runtime = MeshRuntimeConfig {
            topology: MeshTopology::EgressGateway,
            ..test_mesh_runtime_config()
        };
        let mut env = EnvConfig::default();

        let err = validate_egress_gateway_mtls_config(&runtime, &env).unwrap_err();
        assert!(err.to_string().contains("FERRUM_FRONTEND_TLS_CERT_PATH"));

        env.frontend_tls_cert_path = Some("/tmp/server.crt".to_string());
        env.frontend_tls_key_path = Some("/tmp/server.key".to_string());
        let err = validate_egress_gateway_mtls_config(&runtime, &env).unwrap_err();
        assert!(
            err.to_string()
                .contains("FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH")
        );

        env.frontend_tls_client_ca_bundle_path = Some("/tmp/client-ca.pem".to_string());
        validate_egress_gateway_mtls_config(&runtime, &env).expect("mTLS config is complete");

        env.tls_no_verify = true;
        let err = validate_egress_gateway_mtls_config(&runtime, &env).unwrap_err();
        assert!(err.to_string().contains("FERRUM_TLS_NO_VERIFY=true"));
    }

    #[test]
    fn strict_peer_auth_fails_closed_without_frontend_tls_materials() {
        let env = EnvConfig::default();
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");

        let err = load_mesh_frontend_tls(&env, &tls_policy, &[], config::MtlsMode::Strict)
            .expect_err("strict mTLS must require cert and key material");

        assert!(
            err.to_string()
                .contains("PeerAuthentication STRICT requires")
        );
    }

    #[test]
    fn permissive_peer_auth_allows_missing_frontend_tls_materials() {
        let env = EnvConfig::default();
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");

        let tls_config =
            load_mesh_frontend_tls(&env, &tls_policy, &[], config::MtlsMode::Permissive)
                .expect("permissive mTLS can run without frontend TLS materials");

        assert!(tls_config.is_none());
    }

    #[test]
    fn permissive_without_ca_bundle_degrades_to_no_client_auth() {
        let env = EnvConfig {
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            frontend_tls_client_ca_bundle_path: None,
            ..EnvConfig::default()
        };
        let tls_policy = TlsPolicy::from_env_config(&env).expect("tls policy");

        let tls_config =
            load_mesh_frontend_tls(&env, &tls_policy, &[], config::MtlsMode::Permissive)
                .expect("permissive without CA bundle should succeed");

        assert!(
            tls_config.is_some(),
            "TLS config should be built (no client auth, but server TLS active)"
        );
    }

    // ── Topology-aware port resolution + Disable-mode validation ────────

    fn runtime_with_topology(topology: MeshTopology) -> MeshRuntimeConfig {
        let mut runtime = test_mesh_runtime_config();
        runtime.topology = topology;
        runtime.inbound_listen_addr = "127.0.0.1:15006".parse().unwrap();
        runtime.hbone_listen_addr = "127.0.0.1:15008".parse().unwrap();
        runtime.egress_listen_addr = "127.0.0.1:15090".parse().unwrap();
        runtime
    }

    fn peer_auth_with_port_override(
        port: u16,
        mode: config::MtlsMode,
    ) -> config::PeerAuthentication {
        config::PeerAuthentication {
            name: "ns-policy".to_string(),
            namespace: "default".to_string(),
            scope: None,
            selector: None,
            mtls_mode: config::MtlsMode::Permissive,
            port_overrides: HashMap::from([(port, mode)]),
        }
    }

    fn slice_with_peer_auths(peer_auths: Vec<config::PeerAuthentication>) -> MeshSlice {
        MeshSlice {
            namespace: "default".to_string(),
            peer_authentications: peer_auths,
            ..MeshSlice::default()
        }
    }

    #[test]
    fn inbound_mtls_resolution_port_picks_topology_correct_port() {
        let sidecar = runtime_with_topology(MeshTopology::Sidecar);
        assert_eq!(inbound_mtls_resolution_port(&sidecar), 15006);

        let ambient = runtime_with_topology(MeshTopology::Ambient);
        assert_eq!(inbound_mtls_resolution_port(&ambient), 15008);

        let egress = runtime_with_topology(MeshTopology::EgressGateway);
        assert_eq!(inbound_mtls_resolution_port(&egress), 15090);

        // East-west has no TLS termination; pick a stable port for the call.
        let east_west = runtime_with_topology(MeshTopology::EastWestGateway);
        assert_eq!(inbound_mtls_resolution_port(&east_west), 15006);
    }

    #[test]
    fn resolve_inbound_mtls_mode_honours_hbone_port_override_for_ambient() {
        // Port override keyed on the HBONE port (15008). With the prior bug
        // (always looking up 15006) this would have fallen through to the
        // top-level Permissive mode.
        let slice = slice_with_peer_auths(vec![peer_auth_with_port_override(
            15008,
            config::MtlsMode::Strict,
        )]);
        let runtime = runtime_with_topology(MeshTopology::Ambient);

        assert_eq!(
            resolve_inbound_mtls_mode(Some(&slice), &runtime),
            config::MtlsMode::Strict,
        );
    }

    #[test]
    fn resolve_inbound_mtls_mode_honours_egress_port_override_for_egress_gateway() {
        let slice = slice_with_peer_auths(vec![peer_auth_with_port_override(
            15090,
            config::MtlsMode::Strict,
        )]);
        let runtime = runtime_with_topology(MeshTopology::EgressGateway);

        assert_eq!(
            resolve_inbound_mtls_mode(Some(&slice), &runtime),
            config::MtlsMode::Strict,
        );
    }

    #[test]
    fn resolve_inbound_mtls_mode_honours_inbound_port_override_for_sidecar() {
        let slice = slice_with_peer_auths(vec![peer_auth_with_port_override(
            15006,
            config::MtlsMode::Strict,
        )]);
        let runtime = runtime_with_topology(MeshTopology::Sidecar);

        assert_eq!(
            resolve_inbound_mtls_mode(Some(&slice), &runtime),
            config::MtlsMode::Strict,
        );
    }

    #[test]
    fn validate_inbound_mtls_mode_rejects_disable_on_ambient() {
        let runtime = runtime_with_topology(MeshTopology::Ambient);
        let err = validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Disable)
            .expect_err("Disable on Ambient must be rejected");

        assert!(err.to_string().contains("Ambient"));
        assert!(err.to_string().contains("HBONE"));
    }

    #[test]
    fn validate_inbound_mtls_mode_rejects_disable_on_egress_gateway() {
        let runtime = runtime_with_topology(MeshTopology::EgressGateway);
        let err = validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Disable)
            .expect_err("Disable on EgressGateway must be rejected");

        assert!(err.to_string().contains("EgressGateway"));
    }

    #[test]
    fn validate_inbound_mtls_mode_accepts_disable_on_sidecar() {
        let runtime = runtime_with_topology(MeshTopology::Sidecar);
        validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Disable)
            .expect("Disable on Sidecar is allowed (plaintext-only inbound)");
    }

    #[test]
    fn validate_inbound_mtls_mode_accepts_disable_on_east_west_gateway() {
        // East-west gateways do SNI passthrough — there is no TLS-terminating
        // listener to fail closed. The resolved mode is structurally unused.
        let runtime = runtime_with_topology(MeshTopology::EastWestGateway);
        validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Disable)
            .expect("Disable on EastWestGateway is structurally a no-op");
    }

    #[test]
    fn validate_inbound_mtls_mode_accepts_permissive_and_strict_on_all_topologies() {
        for topology in [
            MeshTopology::Sidecar,
            MeshTopology::Ambient,
            MeshTopology::EastWestGateway,
            MeshTopology::EgressGateway,
        ] {
            let runtime = runtime_with_topology(topology);
            validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Permissive)
                .unwrap_or_else(|e| panic!("Permissive on {:?} should succeed: {}", topology, e));
            validate_inbound_mtls_mode_for_topology(&runtime, config::MtlsMode::Strict)
                .unwrap_or_else(|e| panic!("Strict on {:?} should succeed: {}", topology, e));
        }
    }

    fn test_external_service_entry(
        name: &str,
        hosts: Vec<String>,
        port: u16,
        protocol: AppProtocol,
    ) -> ServiceEntry {
        ServiceEntry {
            name: name.to_string(),
            namespace: "default".to_string(),
            hosts,
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port,
                protocol,
                name: Some("http".to_string()),
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }
    }

    #[test]
    fn egress_materializes_proxies_from_external_service_entries() {
        let service_entries = vec![test_external_service_entry(
            "external-api",
            vec!["api.external.com".to_string()],
            443,
            AppProtocol::Tls,
        )];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");

        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);

        let proxy = &proxies[0];
        assert_eq!(
            proxy.id,
            "mesh-egress-default-external-api-api-dot-external-dot-com-443"
        );
        assert_eq!(proxy.hosts, vec!["api.external.com"]);
        assert!(proxy.listen_path.is_none());
        assert!(proxy.listen_port.is_none());
        assert_eq!(proxy.backend_scheme, Some(BackendScheme::Https));
        assert!(!proxy.frontend_tls);
        assert!(!proxy.passthrough);
        assert_eq!(
            proxy.upstream_id.as_deref(),
            Some("mesh-egress-up-default-external-api-api-dot-external-dot-com-443")
        );
        assert!(proxy.preserve_host_header);

        let upstream = &upstreams[0];
        assert_eq!(
            upstream.id,
            "mesh-egress-up-default-external-api-api-dot-external-dot-com-443"
        );
        assert!(
            upstream
                .health_checks
                .as_ref()
                .is_some_and(|checks| { checks.active.is_none() && checks.passive.is_some() })
        );
        assert_eq!(upstream.targets.len(), 1);
        assert_eq!(upstream.targets[0].host, "api.external.com");
        assert_eq!(upstream.targets[0].port, 443);
    }

    #[test]
    fn egress_skips_mesh_internal_service_entries() {
        let service_entries = vec![ServiceEntry {
            name: "internal-svc".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["internal.svc.cluster.local".to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshInternal,
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");

        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());
    }

    #[test]
    fn egress_skips_mesh_internal_service_entries_with_static_endpoints() {
        let service_entries = vec![ServiceEntry {
            name: "internal-static".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["internal.svc.cluster.local".to_string()],
            endpoints: vec![MeshEndpoint {
                address: "10.1.0.2".to_string(),
                ports: HashMap::from([("http".to_string(), 8080)]),
                labels: HashMap::new(),
                network: None,
            }],
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshInternal,
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");

        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());
    }

    #[test]
    fn egress_respects_namespace_and_export_to_visibility() {
        let mut service_entry = test_external_service_entry(
            "payments-api",
            vec!["payments.example.com".to_string()],
            443,
            AppProtocol::Tls,
        );
        service_entry.namespace = "payments".to_string();

        let (proxies, upstreams) =
            build_egress_proxies_and_upstreams(&[service_entry.clone()], "default");
        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());

        service_entry.export_to = vec!["*".to_string()];
        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&[service_entry], "default");
        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);
    }

    #[test]
    fn egress_skips_l4_service_entry_ports() {
        let service_entries = vec![ServiceEntry {
            name: "mysql".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["db.external.com".to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 3306,
                protocol: AppProtocol::Mysql,
                name: Some("mysql".to_string()),
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");
        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());
    }

    #[test]
    fn egress_sanitizes_wildcard_host_ids_but_preserves_route_host() {
        let service_entries = vec![test_external_service_entry(
            "wildcard-api",
            vec!["*.api.external.com".to_string()],
            443,
            AppProtocol::Tls,
        )];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");

        assert_eq!(proxies.len(), 1);
        assert_eq!(
            proxies[0].id,
            "mesh-egress-default-wildcard-api-wildcard-dot-api-dot-external-dot-com-443"
        );
        assert_eq!(proxies[0].hosts, vec!["*.api.external.com"]);
        assert_eq!(
            upstreams[0].id,
            "mesh-egress-up-default-wildcard-api-wildcard-dot-api-dot-external-dot-com-443"
        );
    }

    #[test]
    fn egress_host_id_sanitization_preserves_distinct_valid_hostnames() {
        assert_ne!(
            sanitize_egress_host_id_part("a.b.com"),
            sanitize_egress_host_id_part("a-b.com")
        );
        assert_eq!(
            sanitize_egress_host_id_part("*.api.external.com"),
            "wildcard-dot-api-dot-external-dot-com"
        );
    }

    #[test]
    fn egress_creates_one_host_only_proxy_per_host() {
        let service_entries = vec![ServiceEntry {
            name: "multi-host".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["api.example.com".to_string(), "cdn.example.com".to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![
                ServicePort {
                    port: 80,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                },
                ServicePort {
                    port: 443,
                    protocol: AppProtocol::Tls,
                    name: Some("https".to_string()),
                },
            ],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");

        // Host-only HTTP proxies cannot safely distinguish multiple ports for
        // the same host, so only the first materialized port owns each host.
        assert_eq!(proxies.len(), 2);
        assert_eq!(upstreams.len(), 2);

        assert!(
            proxies
                .iter()
                .any(|p| p.id == "mesh-egress-default-multi-host-api-dot-example-dot-com-80")
        );
        assert!(
            proxies
                .iter()
                .any(|p| p.id == "mesh-egress-default-multi-host-cdn-dot-example-dot-com-80")
        );

        let http_proxy = proxies
            .iter()
            .find(|p| p.id == "mesh-egress-default-multi-host-api-dot-example-dot-com-80")
            .unwrap();
        assert_eq!(http_proxy.backend_scheme, Some(BackendScheme::Http));
    }

    #[test]
    fn egress_uses_static_endpoints_with_named_ports_as_targets() {
        let service_entries = vec![ServiceEntry {
            name: "static-backend".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["api.external.com".to_string()],
            endpoints: vec![
                MeshEndpoint {
                    address: "10.0.0.1".to_string(),
                    ports: HashMap::from([("http".to_string(), 8080)]),
                    labels: HashMap::from([("az".to_string(), "us-east-1a".to_string())]),
                    network: None,
                },
                MeshEndpoint {
                    address: "10.0.0.2".to_string(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                },
            ],
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");

        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);

        let upstream = &upstreams[0];
        assert_eq!(upstream.targets.len(), 1);

        assert_eq!(upstream.targets[0].host, "10.0.0.1");
        assert_eq!(upstream.targets[0].port, 8080);
        assert_eq!(
            upstream.targets[0].tags.get("az").map(String::as_str),
            Some("us-east-1a")
        );
    }

    #[test]
    fn egress_dns_resolution_uses_hosts_as_targets() {
        let service_entries = vec![test_external_service_entry(
            "dns-svc",
            vec![
                "primary.external.com".to_string(),
                "secondary.external.com".to_string(),
            ],
            443,
            AppProtocol::Tls,
        )];

        let (_, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");

        assert_eq!(upstreams.len(), 2);
        let primary = upstreams
            .iter()
            .find(|upstream| upstream.id.contains("primary-dot-external-dot-com"))
            .expect("primary upstream");
        assert_eq!(primary.targets.len(), 1);
        assert_eq!(primary.targets[0].host, "primary.external.com");
        assert_eq!(primary.targets[0].port, 443);

        let secondary = upstreams
            .iter()
            .find(|upstream| upstream.id.contains("secondary-dot-external-dot-com"))
            .expect("secondary upstream");
        assert_eq!(secondary.targets.len(), 1);
        assert_eq!(secondary.targets[0].host, "secondary.external.com");
        assert_eq!(secondary.targets[0].port, 443);
    }

    #[test]
    fn egress_empty_service_entries_produces_no_proxies() {
        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&[], "default");
        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());
    }

    #[test]
    fn mesh_runtime_materializes_egress_proxies_in_prepared_config() {
        let runtime = MeshRuntimeConfig {
            topology: MeshTopology::EgressGateway,
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                service_entries: vec![test_external_service_entry(
                    "ext-api",
                    vec!["api.partner.com".to_string()],
                    443,
                    AppProtocol::Tls,
                )],
                destination_rules: vec![MeshDestinationRule {
                    name: "partner-policy".to_string(),
                    namespace: "default".to_string(),
                    host: "api.partner.com".to_string(),
                    traffic_policy: Some(MeshTrafficPolicy {
                        connect_timeout_ms: Some(1234),
                        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
                        ..MeshTrafficPolicy::default()
                    }),
                    port_level_settings: HashMap::new(),
                    subsets: Vec::new(),
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

        // Should have the egress proxy
        let egress_proxy = prepared
            .proxies
            .iter()
            .find(|proxy| proxy.id == "mesh-egress-default-ext-api-api-dot-partner-dot-com-443")
            .expect("egress proxy should be materialized");
        assert_eq!(egress_proxy.hosts, vec!["api.partner.com"]);
        assert!(!egress_proxy.frontend_tls);
        assert_eq!(egress_proxy.backend_scheme, Some(BackendScheme::Https));
        assert_eq!(egress_proxy.backend_connect_timeout_ms, 1234);

        // Should have the egress upstream
        let egress_upstream = prepared
            .upstreams
            .iter()
            .find(|upstream| {
                upstream.id == "mesh-egress-up-default-ext-api-api-dot-partner-dot-com-443"
            })
            .expect("egress upstream should be materialized");
        assert_eq!(egress_upstream.targets.len(), 1);
        assert_eq!(egress_upstream.targets[0].host, "api.partner.com");
        assert_eq!(egress_upstream.algorithm, LoadBalancerAlgorithm::Random);

        // Mesh plugins should be injected
        assert!(
            prepared
                .plugin_configs
                .iter()
                .any(|p| p.id == MESH_SPIFFE_IDENTITY_PLUGIN_ID)
        );
        assert!(
            prepared
                .plugin_configs
                .iter()
                .any(|p| p.id == MESH_AUTHZ_PLUGIN_ID)
        );
    }

    #[test]
    fn egress_does_not_materialize_when_topology_is_sidecar() {
        let runtime = test_mesh_runtime_config();
        assert_eq!(runtime.topology, MeshTopology::Sidecar);

        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                service_entries: vec![test_external_service_entry(
                    "ext-api",
                    vec!["api.partner.com".to_string()],
                    443,
                    AppProtocol::Tls,
                )],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

        // No egress proxies should be materialized for sidecar topology
        assert!(
            !prepared
                .proxies
                .iter()
                .any(|p| p.id.starts_with("mesh-egress-"))
        );
    }

    #[test]
    fn egress_backend_scheme_maps_protocols_correctly() {
        assert_eq!(
            egress_backend_scheme(AppProtocol::Tls),
            Some(BackendScheme::Https)
        );
        assert_eq!(
            egress_backend_scheme(AppProtocol::Http2),
            Some(BackendScheme::Https)
        );
        assert_eq!(
            egress_backend_scheme(AppProtocol::Grpc),
            Some(BackendScheme::Https)
        );
        assert_eq!(
            egress_backend_scheme(AppProtocol::Http),
            Some(BackendScheme::Http)
        );
        assert_eq!(
            egress_backend_scheme(AppProtocol::Unknown),
            Some(BackendScheme::Http)
        );
        assert_eq!(egress_backend_scheme(AppProtocol::Tcp), None);
    }

    #[test]
    fn egress_resolution_none_uses_hosts_as_targets() {
        let service_entries = vec![ServiceEntry {
            name: "passthrough-ext".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["cdn.example.com".to_string()],
            endpoints: Vec::new(),
            resolution: Resolution::None,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 443,
                protocol: AppProtocol::Tls,
                name: Some("https".to_string()),
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");

        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);
        assert_eq!(upstreams[0].targets.len(), 1);
        assert_eq!(upstreams[0].targets[0].host, "cdn.example.com");
        assert_eq!(upstreams[0].targets[0].port, 443);
    }

    #[test]
    fn egress_static_resolution_unnamed_port_uses_entry_port() {
        let service_entries = vec![ServiceEntry {
            name: "static-unnamed".to_string(),
            namespace: "default".to_string(),
            hosts: vec!["api.vendor.com".to_string()],
            endpoints: vec![
                MeshEndpoint {
                    address: "203.0.113.10".to_string(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                },
                MeshEndpoint {
                    address: "203.0.113.11".to_string(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                },
            ],
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 8443,
                protocol: AppProtocol::Tls,
                name: None,
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");

        assert_eq!(proxies.len(), 1);
        assert_eq!(upstreams.len(), 1);
        // Proxy stays pinned to the ServiceEntry host so SNI/Host headers are
        // not crossed by load balancing across endpoint IPs.
        assert_eq!(proxies[0].hosts, vec!["api.vendor.com"]);
        assert_eq!(upstreams[0].targets.len(), 2);
        assert_eq!(upstreams[0].targets[0].host, "203.0.113.10");
        assert_eq!(upstreams[0].targets[0].port, 8443);
        assert_eq!(upstreams[0].targets[1].host, "203.0.113.11");
        assert_eq!(upstreams[0].targets[1].port, 8443);
    }

    #[test]
    fn egress_skips_service_entries_with_empty_hosts() {
        let service_entries = vec![ServiceEntry {
            name: "no-hosts".to_string(),
            namespace: "default".to_string(),
            hosts: Vec::new(),
            endpoints: Vec::new(),
            resolution: Resolution::Dns,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 443,
                protocol: AppProtocol::Tls,
                name: Some("https".to_string()),
            }],
            export_to: Vec::new(),
            workload_selector: None,
        }];

        let (proxies, upstreams) = build_egress_proxies_and_upstreams(&service_entries, "default");
        assert!(proxies.is_empty());
        assert!(upstreams.is_empty());
    }

    #[test]
    fn egress_mixed_internal_external_only_materializes_external() {
        let runtime = MeshRuntimeConfig {
            topology: MeshTopology::EgressGateway,
            ..test_mesh_runtime_config()
        };
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                service_entries: vec![
                    // MeshExternal -- should be materialized
                    test_external_service_entry(
                        "ext-api",
                        vec!["api.partner.com".to_string()],
                        443,
                        AppProtocol::Tls,
                    ),
                    // MeshInternal -- should be skipped
                    ServiceEntry {
                        name: "internal-svc".to_string(),
                        namespace: "default".to_string(),
                        hosts: vec!["internal.svc.cluster.local".to_string()],
                        endpoints: Vec::new(),
                        resolution: Resolution::Dns,
                        location: ServiceEntryLocation::MeshInternal,
                        ports: vec![ServicePort {
                            port: 8080,
                            protocol: AppProtocol::Http,
                            name: None,
                        }],
                        export_to: Vec::new(),
                        workload_selector: None,
                    },
                    // Another MeshExternal -- should be materialized
                    test_external_service_entry(
                        "ext-metrics",
                        vec!["metrics.vendor.com".to_string()],
                        443,
                        AppProtocol::Tls,
                    ),
                ],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh config");

        let egress_proxies: Vec<_> = prepared
            .proxies
            .iter()
            .filter(|p| p.id.starts_with("mesh-egress-"))
            .collect();
        assert_eq!(egress_proxies.len(), 2);

        let egress_upstreams: Vec<_> = prepared
            .upstreams
            .iter()
            .filter(|u| u.id.starts_with("mesh-egress-up-"))
            .collect();
        assert_eq!(egress_upstreams.len(), 2);

        // Verify the external ones are present
        assert!(
            egress_proxies
                .iter()
                .any(|p| p.hosts == vec!["api.partner.com"])
        );
        assert!(
            egress_proxies
                .iter()
                .any(|p| p.hosts == vec!["metrics.vendor.com"])
        );

        // Verify the internal one is NOT present
        assert!(
            !egress_proxies
                .iter()
                .any(|p| p.hosts.contains(&"internal.svc.cluster.local".to_string()))
        );
    }
}
