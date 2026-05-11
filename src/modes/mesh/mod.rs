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
    PassiveHealthCheck, PluginAssociation, PluginConfig, PluginScope, Proxy, ResponseBodyMode,
    Upstream, UpstreamTarget,
};
use crate::dns::{DnsCache, DnsConfig};
use crate::grpc::dp_client::{GrpcJwtSecret, build_dp_grpc_tls_config};
use crate::modes::mesh::config::{
    AppProtocol, EastWestGateway, MeshConfig, MeshJwtRule, MeshRequestAuthentication,
    MeshTelemetryConfig, PolicyScope, Resolution, ServiceEntry, ServiceEntryLocation,
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
            dns_enabled,
            dns_listen_addr,
            dns_upstream_addr,
            dns_ttl_seconds,
            dns_max_concurrent_queries,
            dns_response_cache_max_entries,
            cluster_domain,
            capture_mode,
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
    config.normalize_fields();
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
            trust_bundles: slice.trust_bundles.clone(),
            multi_cluster: slice.multi_cluster.clone(),
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
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
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
                    backend_tls_client_cert_path: None,
                    backend_tls_client_key_path: None,
                    backend_tls_verify_server_cert: true,
                    backend_tls_server_ca_cert_path: None,
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

    let mesh_apply_handle = start_mesh_slice_apply_task(
        mesh_state,
        proxy_state.clone(),
        runtime.clone(),
        initial_applied_mesh_slice,
        shutdown_tx.subscribe(),
        dns_proxy_handle,
    );

    validate_egress_gateway_mtls_config(&runtime, &env_config)?;
    let frontend_tls = load_frontend_tls(&env_config, &tls_policy, &crls)?;
    if let Some(ref tls_config) = frontend_tls {
        proxy_state
            .stream_listener_manager
            .set_frontend_tls_config(Some(tls_config.clone()))
            .await;
    }

    info!(
        listeners = runtime.listener_plan().len(),
        "Mesh listener plan prepared"
    );
    let mut listener_handles = Vec::new();
    let mut startup_signals = Vec::new();
    for listener in runtime.listener_plan() {
        let tls_config = listener_tls_config(&listener, frontend_tls.clone());
        if tls_config.is_none()
            && matches!(
                listener.kind,
                MeshListenerKind::MtlsTermination | MeshListenerKind::HboneTermination
            )
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

fn load_frontend_tls(
    env_config: &EnvConfig,
    tls_policy: &TlsPolicy,
    crls: &[rustls::pki_types::CertificateRevocationListDer<'static>],
) -> Result<Option<Arc<rustls::ServerConfig>>, anyhow::Error> {
    let (Some(cert_path), Some(key_path)) = (
        env_config.frontend_tls_cert_path.as_ref(),
        env_config.frontend_tls_key_path.as_ref(),
    ) else {
        return Ok(None);
    };

    let client_ca_bundle_path = env_config.frontend_tls_client_ca_bundle_path.as_deref();
    let mut config = tls::load_tls_config_with_client_auth(
        cert_path,
        key_path,
        client_ca_bundle_path,
        env_config.tls_no_verify,
        tls_policy,
        env_config.tls_cert_expiry_warning_days,
        crls,
    )
    .map_err(|e| anyhow::anyhow!("Invalid mesh frontend TLS configuration: {}", e))?;
    tls::enable_early_data(&mut config, tls_policy);
    if env_config.ktls_enabled.could_be_enabled() {
        tls::enable_secret_extraction_for_ktls(&mut config);
    }
    Ok(Some(config))
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
        PrincipalMatch, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort, Workload,
        WorkloadPort, WorkloadSelector,
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
            dns_enabled: false,
            dns_listen_addr: DEFAULT_DNS_LISTEN_ADDR.parse().unwrap(),
            dns_upstream_addr: DEFAULT_DNS_UPSTREAM_ADDR.parse().unwrap(),
            dns_ttl_seconds: DEFAULT_DNS_TTL_SECONDS,
            dns_max_concurrent_queries: DEFAULT_DNS_MAX_CONCURRENT_QUERIES,
            dns_response_cache_max_entries: dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES,
            cluster_domain: dns_proxy::DEFAULT_CLUSTER_DOMAIN.to_string(),
            capture_mode: crate::capture::CaptureMode::Explicit,
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
            dns_enabled: false,
            dns_listen_addr: DEFAULT_DNS_LISTEN_ADDR.parse().unwrap(),
            dns_upstream_addr: DEFAULT_DNS_UPSTREAM_ADDR.parse().unwrap(),
            dns_ttl_seconds: DEFAULT_DNS_TTL_SECONDS,
            dns_max_concurrent_queries: DEFAULT_DNS_MAX_CONCURRENT_QUERIES,
            dns_response_cache_max_entries: dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES,
            cluster_domain: dns_proxy::DEFAULT_CLUSTER_DOMAIN.to_string(),
            capture_mode: crate::capture::CaptureMode::Explicit,
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
                        }),
                        ..MeshTelemetryConfig::default()
                    },
                },
            ],
            trust_bundles: None,
            multi_cluster: None,
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
