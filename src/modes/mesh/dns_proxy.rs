//! Transparent DNS proxy for mesh ServiceEntry / MeshService resolution.
//!
//! Intercepts DNS queries (typically redirected from port 53 via iptables/eBPF)
//! and resolves mesh-internal hostnames from a pre-built resolution table.
//! Non-mesh queries are forwarded transparently to the upstream system resolver.
//!
//! The resolution table is rebuilt atomically (via `ArcSwap`) whenever the
//! `MeshSlice` is updated, so there are no locks on the query hot path.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, error, info, trace, warn};

use crate::modes::mesh::slice::MeshSlice;

// ── DNS wire-format constants ────────────────────────────────────────────

const DNS_HEADER_SIZE: usize = 12;
const DNS_MAX_UDP_PACKET_SIZE: usize = 4096;
const DNS_UDP_SAFE_PACKET_SIZE: usize = 512;
const DNS_MAX_TCP_PACKET_SIZE: usize = u16::MAX as usize;
const DNS_UPSTREAM_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_CLUSTER_DOMAIN: &str = "cluster.local";

// QTYPE values
const QTYPE_A: u16 = 1;
const QTYPE_OPT: u16 = 41;
const QTYPE_AAAA: u16 = 28;

// QCLASS
const QCLASS_IN: u16 = 1;

// Response flags
const FLAGS_QR: u16 = 0x8000; // Response
const FLAGS_AA: u16 = 0x0400; // Authoritative Answer
const FLAGS_TC: u16 = 0x0200; // Truncated
const FLAGS_RD: u16 = 0x0100; // Recursion Desired
const FLAGS_RA: u16 = 0x0080; // Recursion Available

const RCODE_FORMERR: u16 = 1;
const RCODE_SERVFAIL: u16 = 2;

// ── DNS query representation ─────────────────────────────────────────────

/// Parsed DNS question extracted from an incoming query packet.
#[derive(Clone)]
struct DnsQuery {
    /// Transaction ID (echoed back in responses).
    id: u16,
    /// Original flags from the query (we copy RD etc.).
    flags: u16,
    /// Normalized hostname: lowercase, trailing dot stripped.
    name: String,
    /// Query type (1 = A, 28 = AAAA).
    qtype: u16,
    /// Query class (1 = IN).
    qclass: u16,
    /// EDNS(0) OPT pseudo-record from the query, echoed when it fits.
    opt_record: Option<Vec<u8>>,
    /// Client-advertised UDP response size from EDNS(0), clamped at response time.
    udp_payload_size: usize,
}

struct DnsRecordSet {
    ips: Vec<IpAddr>,
    authoritative: bool,
}

struct WildcardRecordSet {
    suffix: String,
    records: DnsRecordSet,
}

pub struct ResolvedDnsRecords<'a> {
    ips: &'a [IpAddr],
    authoritative: bool,
}

impl<'a> ResolvedDnsRecords<'a> {
    #[cfg(test)]
    fn contains(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.ips.len()
    }

    #[cfg(test)]
    fn iter(&self) -> std::slice::Iter<'a, IpAddr> {
        self.ips.iter()
    }
}

// ── Resolution table ─────────────────────────────────────────────────────

/// FQDN-to-IP resolution table built from mesh config.
///
/// Rebuilt atomically from `MeshSlice` on config updates. The `ArcSwap`
/// wrapper ensures the query hot path never blocks on a rebuild.
pub struct DnsResolutionTable {
    /// Exact hostname matches (lowercase, trailing dot stripped).
    exact: HashMap<String, DnsRecordSet>,
    /// Wildcard matches bucketed by final suffix label for bounded lookup.
    wildcard_suffixes: HashMap<String, Vec<WildcardRecordSet>>,
}

impl DnsResolutionTable {
    fn empty() -> Self {
        Self {
            exact: HashMap::new(),
            wildcard_suffixes: HashMap::new(),
        }
    }

    /// Build a resolution table from a mesh slice.
    ///
    /// Indexes `ServiceEntry.hosts` mapped to their endpoint IPs, plus
    /// `MeshService` short names (`{name}.{namespace}.svc.cluster.local`)
    /// mapped to workload addresses resolved through the slice.
    #[allow(dead_code)]
    pub fn from_mesh_slice(slice: &MeshSlice) -> Self {
        Self::from_mesh_slice_with_cluster_domain(slice, DEFAULT_CLUSTER_DOMAIN)
    }

    pub fn from_mesh_slice_with_cluster_domain(slice: &MeshSlice, cluster_domain: &str) -> Self {
        let cluster_domain = normalize_dns_name(cluster_domain);
        let mut exact: HashMap<String, DnsRecordSet> = HashMap::new();
        let mut wildcard_suffixes: HashMap<String, Vec<WildcardRecordSet>> = HashMap::new();

        // Index workload addresses by SPIFFE ID for MeshService resolution.
        let mut workload_ips: HashMap<&str, Vec<IpAddr>> = HashMap::new();
        for wl in &slice.workloads {
            let ips: Vec<IpAddr> = wl
                .addresses
                .iter()
                .filter_map(|addr| addr.parse::<IpAddr>().ok())
                .filter(is_routable_mesh_dns_ip)
                .collect();
            if !ips.is_empty() {
                workload_ips.insert(wl.spiffe_id.as_str(), ips);
            }
        }

        // From ServiceEntries: hosts -> endpoint IPs
        for entry in &slice.service_entries {
            let ips: Vec<IpAddr> = entry
                .endpoints
                .iter()
                .filter_map(|ep| ep.address.parse::<IpAddr>().ok())
                .filter(is_routable_mesh_dns_ip)
                .collect();
            if ips.is_empty() {
                continue;
            }

            for host in &entry.hosts {
                let normalized = normalize_dns_name(host);
                if normalized.is_empty() {
                    continue;
                }
                if let Some(suffix) = normalized.strip_prefix("*.") {
                    if !suffix.is_empty() {
                        let authoritative = is_authoritative_mesh_dns_name(suffix, &cluster_domain);
                        let last_label = suffix.rsplit('.').next().unwrap_or(suffix).to_string();
                        wildcard_suffixes
                            .entry(last_label)
                            .or_default()
                            .push(WildcardRecordSet {
                                suffix: suffix.to_string(),
                                records: DnsRecordSet {
                                    ips: ips.clone(),
                                    authoritative,
                                },
                            });
                    }
                } else {
                    let authoritative =
                        is_authoritative_mesh_dns_name(&normalized, &cluster_domain);
                    extend_record_set(&mut exact, normalized, ips.iter().copied(), authoritative);
                }
            }
        }

        // From MeshServices: construct FQDN from name + namespace and resolve
        // workload addresses through SPIFFE ID references.
        for svc in &slice.services {
            let mut svc_ips: Vec<IpAddr> = Vec::new();
            for wl_ref in &svc.workloads {
                if let Some(ips) = workload_ips.get(wl_ref.spiffe_id.as_str()) {
                    svc_ips.extend(ips.iter());
                }
            }
            if svc_ips.is_empty() {
                continue;
            }

            // Register the Kubernetes-style FQDN:
            // {name}.{namespace}.svc.{cluster_domain}
            let fqdn = normalize_dns_name(&format!(
                "{}.{}.svc.{}",
                svc.name, svc.namespace, cluster_domain
            ));
            extend_record_set(&mut exact, fqdn, svc_ips.iter().copied(), true);

            // Also register short name: {name}.{namespace}
            let short = normalize_dns_name(&format!("{}.{}", svc.name, svc.namespace));
            extend_record_set(&mut exact, short, svc_ips.iter().copied(), true);
        }

        // Deduplicate IPs within each entry
        for records in exact.values_mut() {
            records.ips.sort();
            records.ips.dedup();
        }
        for bucket in wildcard_suffixes.values_mut() {
            bucket.sort_by_key(|entry| Reverse(entry.suffix.len()));
            for entry in bucket {
                entry.records.ips.sort();
                entry.records.ips.dedup();
            }
        }

        Self {
            exact,
            wildcard_suffixes,
        }
    }

    /// Resolve a hostname against the table. Returns `None` for non-mesh names.
    #[allow(dead_code)]
    pub fn resolve(&self, name: &str) -> Option<ResolvedDnsRecords<'_>> {
        let normalized = normalize_dns_name(name);
        self.resolve_normalized(&normalized)
    }

    fn resolve_normalized(&self, normalized: &str) -> Option<ResolvedDnsRecords<'_>> {
        // Exact match first (O(1))
        if let Some(records) = self.exact.get(normalized) {
            return Some(ResolvedDnsRecords {
                ips: records.ips.as_slice(),
                authoritative: records.authoritative,
            });
        }

        let last_label = normalized.rsplit('.').next()?;
        let bucket = self.wildcard_suffixes.get(last_label)?;
        for wildcard in bucket {
            if single_label_wildcard_matches(normalized, &wildcard.suffix) {
                return Some(ResolvedDnsRecords {
                    ips: wildcard.records.ips.as_slice(),
                    authoritative: wildcard.records.authoritative,
                });
            }
        }

        None
    }

    /// Number of exact entries in the table.
    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }

    /// Number of wildcard entries in the table.
    pub fn wildcard_count(&self) -> usize {
        self.wildcard_suffixes.values().map(Vec::len).sum()
    }
}

fn extend_record_set(
    exact: &mut HashMap<String, DnsRecordSet>,
    name: String,
    ips: impl IntoIterator<Item = IpAddr>,
    authoritative: bool,
) {
    let records = exact.entry(name).or_insert_with(|| DnsRecordSet {
        ips: Vec::new(),
        authoritative,
    });
    records.authoritative |= authoritative;
    records.ips.extend(ips);
}

fn single_label_wildcard_matches(name: &str, suffix: &str) -> bool {
    if name.len() <= suffix.len() + 1 {
        return false;
    }
    if !name.ends_with(suffix) {
        return false;
    }
    let prefix_len = name.len() - suffix.len() - 1;
    name.as_bytes()[prefix_len] == b'.' && !name[..prefix_len].contains('.')
}

fn is_authoritative_mesh_dns_name(name: &str, cluster_domain: &str) -> bool {
    let svc_suffix = format!(".svc.{cluster_domain}");
    name.ends_with(&svc_suffix) || name == format!("svc.{cluster_domain}")
}

fn is_routable_mesh_dns_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            !addr.is_unspecified()
                && !addr.is_loopback()
                && !addr.is_link_local()
                && !addr.is_broadcast()
                && !addr.is_multicast()
        }
        IpAddr::V6(addr) => {
            !addr.is_unspecified()
                && !addr.is_loopback()
                && !addr.is_unicast_link_local()
                && !addr.is_multicast()
        }
    }
}

/// Normalize a DNS name: lowercase + strip trailing dot.
fn normalize_dns_name(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_string()
}

// ── DNS proxy server ─────────────────────────────────────────────────────

/// Transparent mesh DNS proxy.
///
/// Listens on a UDP port and resolves mesh-internal names from a lock-free
/// resolution table. Non-mesh queries are forwarded to the upstream resolver.
pub struct MeshDnsProxy {
    listen_addr: SocketAddr,
    resolution_table: Arc<ArcSwap<DnsResolutionTable>>,
    upstream_resolver: SocketAddr,
    ttl_seconds: u32,
    max_concurrent_queries: usize,
    cluster_domain: String,
}

impl MeshDnsProxy {
    /// Create a new DNS proxy (does not bind yet; call `run()` to start).
    pub fn new(
        listen_addr: SocketAddr,
        upstream_resolver: SocketAddr,
        ttl_seconds: u32,
        max_concurrent_queries: usize,
        cluster_domain: String,
    ) -> Self {
        Self {
            listen_addr,
            resolution_table: Arc::new(ArcSwap::new(Arc::new(DnsResolutionTable::empty()))),
            upstream_resolver,
            ttl_seconds,
            max_concurrent_queries: max_concurrent_queries.max(1),
            cluster_domain: normalize_dns_name(&cluster_domain),
        }
    }

    /// Rebuild the resolution table from a new mesh slice.
    pub fn update_from_slice(&self, slice: &MeshSlice) {
        let new_table =
            DnsResolutionTable::from_mesh_slice_with_cluster_domain(slice, &self.cluster_domain);
        let exact_count = new_table.exact_count();
        let wildcard_count = new_table.wildcard_count();
        self.resolution_table.store(Arc::new(new_table));
        debug!(
            exact_entries = exact_count,
            wildcard_entries = wildcard_count,
            "DNS resolution table rebuilt from mesh slice"
        );
    }

    /// Run the DNS proxy server loop until shutdown.
    pub async fn run(self: Arc<Self>, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
        let socket = match UdpSocket::bind(self.listen_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!(addr = %self.listen_addr, error = %e, "Failed to bind mesh DNS proxy");
                return;
            }
        };

        let tcp_listener = match TcpListener::bind(self.listen_addr).await {
            Ok(listener) => listener,
            Err(e) => {
                error!(addr = %self.listen_addr, error = %e, "Failed to bind mesh DNS TCP listener");
                return;
            }
        };

        let (forward_tx, forward_rx) = mpsc::channel(self.max_concurrent_queries.saturating_mul(2));
        let forward_shutdown = shutdown_rx.clone();
        let forward_handle = tokio::spawn(run_udp_forwarder(
            forward_rx,
            socket.clone(),
            self.upstream_resolver,
            self.max_concurrent_queries,
            forward_shutdown,
        ));

        info!(
            addr = %self.listen_addr,
            upstream = %self.upstream_resolver,
            max_concurrent_queries = self.max_concurrent_queries,
            "Mesh DNS proxy listening on UDP and TCP"
        );

        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_queries));
        let mut buf = vec![0u8; DNS_MAX_UDP_PACKET_SIZE];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                                if let Some(response) = build_dns_error_response_from_packet(
                                    &buf[..len],
                                    RCODE_SERVFAIL,
                                    DNS_UDP_SAFE_PACKET_SIZE,
                                ) {
                                    let _ = socket.send_to(&response, src).await;
                                }
                                warn!(src = %src, "DNS proxy query concurrency limit reached");
                                continue;
                            };
                            let packet = buf[..len].to_vec();
                            let socket = socket.clone();
                            let table = self.resolution_table.clone();
                            let ttl = self.ttl_seconds;
                            let forward_tx = forward_tx.clone();

                            tokio::spawn(async move {
                                let _permit = permit;
                                handle_dns_query_udp(packet, src, &socket, &table, &forward_tx, ttl).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "DNS proxy recv error");
                        }
                    }
                }
                result = tcp_listener.accept() => {
                    match result {
                        Ok((stream, src)) => {
                            let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                                warn!(src = %src, "DNS proxy TCP concurrency limit reached");
                                continue;
                            };
                            let table = self.resolution_table.clone();
                            let upstream = self.upstream_resolver;
                            let ttl = self.ttl_seconds;
                            tokio::spawn(async move {
                                let _permit = permit;
                                handle_dns_tcp_connection(stream, src, &table, upstream, ttl).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "DNS proxy TCP accept error");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Mesh DNS proxy shutting down");
                        break;
                    }
                }
            }
        }

        drop(forward_tx);
        let _ = forward_handle.await;
    }
}

// ── Query handler ────────────────────────────────────────────────────────

struct UdpForwardRequest {
    packet: Vec<u8>,
    src: SocketAddr,
    query: DnsQuery,
}

enum DnsDecision {
    Respond(Vec<u8>),
    Forward(DnsQuery),
    Drop,
}

async fn handle_dns_query_udp(
    packet: Vec<u8>,
    src: SocketAddr,
    socket: &UdpSocket,
    table: &ArcSwap<DnsResolutionTable>,
    forward_tx: &mpsc::Sender<UdpForwardRequest>,
    ttl: u32,
) {
    let max_response_size = udp_response_size(&packet);
    match evaluate_dns_query(&packet, table, ttl, max_response_size) {
        DnsDecision::Respond(response) => {
            let _ = socket.send_to(&response, src).await;
        }
        DnsDecision::Forward(query) => {
            let request = UdpForwardRequest { packet, src, query };
            if let Err(err) = forward_tx.try_send(request) {
                let request = err.into_inner();
                let response = build_dns_error_response(
                    &request.query,
                    RCODE_SERVFAIL,
                    false,
                    max_response_size,
                );
                let _ = socket.send_to(&response, src).await;
                warn!(client = %src, "DNS upstream forward queue is full");
            }
        }
        DnsDecision::Drop => {}
    }
}

async fn handle_dns_tcp_connection(
    mut stream: TcpStream,
    src: SocketAddr,
    table: &ArcSwap<DnsResolutionTable>,
    upstream: SocketAddr,
    ttl: u32,
) {
    loop {
        let mut len_buf = [0u8; 2];
        if let Err(e) = stream.read_exact(&mut len_buf).await {
            trace!(client = %src, error = %e, "DNS TCP connection closed");
            return;
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            continue;
        }
        let mut packet = vec![0u8; len];
        if let Err(e) = stream.read_exact(&mut packet).await {
            debug!(client = %src, error = %e, "Failed to read DNS TCP query");
            return;
        }

        let response = match evaluate_dns_query(&packet, table, ttl, DNS_MAX_TCP_PACKET_SIZE) {
            DnsDecision::Respond(response) => response,
            DnsDecision::Forward(_) => match forward_to_upstream_tcp(&packet, upstream).await {
                Some(response) => response,
                None => build_dns_error_response_from_packet(
                    &packet,
                    RCODE_SERVFAIL,
                    DNS_MAX_TCP_PACKET_SIZE,
                )
                .unwrap_or_default(),
            },
            DnsDecision::Drop => continue,
        };

        if response.len() > u16::MAX as usize {
            warn!(client = %src, response_bytes = response.len(), "DNS TCP response too large");
            return;
        }
        if stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .is_err()
        {
            return;
        }
        if stream.write_all(&response).await.is_err() {
            return;
        }
    }
}

fn evaluate_dns_query(
    packet: &[u8],
    table: &ArcSwap<DnsResolutionTable>,
    ttl: u32,
    max_response_size: usize,
) -> DnsDecision {
    let query = match parse_dns_query(packet) {
        Some(q) => q,
        None => {
            return build_dns_error_response_from_packet(packet, RCODE_FORMERR, max_response_size)
                .map(DnsDecision::Respond)
                .unwrap_or(DnsDecision::Drop);
        }
    };

    // Only handle A/AAAA queries for IN class.
    if query.qclass != QCLASS_IN || (query.qtype != QTYPE_A && query.qtype != QTYPE_AAAA) {
        return DnsDecision::Forward(query);
    }

    let table = table.load();
    match table.resolve_normalized(&query.name) {
        Some(records) => {
            // Filter by query type: A gets IPv4, AAAA gets IPv6
            let filtered: Vec<&IpAddr> = records
                .ips
                .iter()
                .filter(|ip| {
                    matches!(
                        (query.qtype, **ip),
                        (QTYPE_A, IpAddr::V4(_)) | (QTYPE_AAAA, IpAddr::V6(_))
                    )
                })
                .collect();

            if filtered.is_empty() {
                // Have the name but no matching record type -- return empty (not NXDOMAIN)
                let response =
                    build_dns_empty_response(&query, records.authoritative, max_response_size);
                DnsDecision::Respond(response)
            } else {
                let response = build_dns_response(
                    &query,
                    &filtered,
                    ttl,
                    records.authoritative,
                    max_response_size,
                );
                trace!(
                    name = %query.name,
                    qtype = query.qtype,
                    answers = filtered.len(),
                    authoritative = records.authoritative,
                    "DNS query resolved from mesh table"
                );
                DnsDecision::Respond(response)
            }
        }
        None => {
            // Not a mesh name -- forward to upstream
            DnsDecision::Forward(query)
        }
    }
}

async fn forward_to_upstream_tcp(packet: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(DNS_UPSTREAM_TIMEOUT_SECS),
        TcpStream::connect(upstream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!(error = %e, upstream = %upstream, "Failed to connect to upstream DNS over TCP");
            return None;
        }
        Err(_) => {
            warn!(upstream = %upstream, "Timed out connecting to upstream DNS over TCP");
            return None;
        }
    };

    if stream
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await
        .is_err()
    {
        warn!(upstream = %upstream, "Failed to write upstream DNS TCP query length");
        return None;
    }
    if stream.write_all(packet).await.is_err() {
        warn!(upstream = %upstream, "Failed to write upstream DNS TCP query");
        return None;
    }

    let mut len_buf = [0u8; 2];
    match tokio::time::timeout(
        Duration::from_secs(DNS_UPSTREAM_TIMEOUT_SECS),
        stream.read_exact(&mut len_buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            warn!(error = %e, upstream = %upstream, "Upstream DNS TCP length read failed");
            return None;
        }
        Err(_) => {
            warn!(upstream = %upstream, "Upstream DNS TCP query timed out");
            return None;
        }
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    match tokio::time::timeout(
        Duration::from_secs(DNS_UPSTREAM_TIMEOUT_SECS),
        stream.read_exact(&mut response),
    )
    .await
    {
        Ok(Ok(_)) => {
            if response.len() < 2 || response[..2] != packet[..2] {
                warn!(upstream = %upstream, "Ignoring upstream DNS TCP response with mismatched transaction ID");
                None
            } else {
                Some(response)
            }
        }
        Ok(Err(e)) => {
            warn!(error = %e, upstream = %upstream, "Upstream DNS TCP response read failed");
            None
        }
        Err(_) => {
            warn!(upstream = %upstream, "Upstream DNS TCP response timed out");
            None
        }
    }
}

struct PendingForward {
    client: SocketAddr,
    original_id: u16,
    query: DnsQuery,
    expires_at: Instant,
}

async fn run_udp_forwarder(
    mut requests: mpsc::Receiver<UdpForwardRequest>,
    client_socket: Arc<UdpSocket>,
    upstream: SocketAddr,
    max_outstanding: usize,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let bind_addr = if upstream.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let upstream_socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, upstream = %upstream, "Failed to bind shared upstream DNS socket");
            while let Some(request) = requests.recv().await {
                send_udp_servfail(&client_socket, &request.query, request.src).await;
            }
            return;
        }
    };
    if let Err(e) = upstream_socket.connect(upstream).await {
        error!(error = %e, upstream = %upstream, "Failed to connect shared upstream DNS socket");
        while let Some(request) = requests.recv().await {
            send_udp_servfail(&client_socket, &request.query, request.src).await;
        }
        return;
    }

    let mut pending: HashMap<u16, PendingForward> = HashMap::new();
    let mut next_id = 0u16;
    let mut response_buf = vec![0u8; DNS_MAX_UDP_PACKET_SIZE];
    let mut cleanup = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            maybe_request = requests.recv() => {
                let Some(request) = maybe_request else {
                    break;
                };
                if pending.len() >= max_outstanding {
                    warn!(client = %request.src, outstanding = pending.len(), "DNS upstream forward limit reached");
                    send_udp_servfail(&client_socket, &request.query, request.src).await;
                    continue;
                }

                let Some(upstream_id) = allocate_upstream_id(&mut next_id, &pending) else {
                    warn!("DNS upstream transaction ID space exhausted");
                    send_udp_servfail(&client_socket, &request.query, request.src).await;
                    continue;
                };

                let mut upstream_packet = request.packet;
                upstream_packet[..2].copy_from_slice(&upstream_id.to_be_bytes());
                match upstream_socket.send(&upstream_packet).await {
                    Ok(_) => {
                        pending.insert(upstream_id, PendingForward {
                            client: request.src,
                            original_id: request.query.id,
                            query: request.query,
                            expires_at: Instant::now() + Duration::from_secs(DNS_UPSTREAM_TIMEOUT_SECS),
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, upstream = %upstream, "Failed to send DNS query to upstream");
                        send_udp_servfail(&client_socket, &request.query, request.src).await;
                    }
                }
            }
            result = upstream_socket.recv(&mut response_buf), if !pending.is_empty() => {
                match result {
                    Ok(len) => {
                        if len < 2 {
                            warn!("Ignoring short upstream DNS response");
                            continue;
                        }
                        let upstream_id = u16::from_be_bytes([response_buf[0], response_buf[1]]);
                        let Some(pending_request) = pending.remove(&upstream_id) else {
                            warn!(upstream_id, "Ignoring upstream DNS response with unknown transaction ID");
                            continue;
                        };
                        let mut response = response_buf[..len].to_vec();
                        response[..2].copy_from_slice(&pending_request.original_id.to_be_bytes());
                        let _ = client_socket.send_to(&response, pending_request.client).await;
                        trace!(client = %pending_request.client, bytes = response.len(), "Forwarded DNS response from upstream");
                    }
                    Err(e) => {
                        warn!(error = %e, upstream = %upstream, "Upstream DNS recv error");
                    }
                }
            }
            _ = cleanup.tick() => {
                let now = Instant::now();
                let expired: Vec<u16> = pending
                    .iter()
                    .filter_map(|(id, request)| (request.expires_at <= now).then_some(*id))
                    .collect();
                for id in expired {
                    if let Some(request) = pending.remove(&id) {
                        warn!(client = %request.client, upstream = %upstream, "Upstream DNS query timed out");
                        send_udp_servfail(&client_socket, &request.query, request.client).await;
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}

fn allocate_upstream_id(next_id: &mut u16, pending: &HashMap<u16, PendingForward>) -> Option<u16> {
    for _ in 0..=u16::MAX {
        let candidate = *next_id;
        *next_id = next_id.wrapping_add(1);
        if !pending.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    None
}

async fn send_udp_servfail(socket: &UdpSocket, query: &DnsQuery, client: SocketAddr) {
    let response = build_dns_error_response(query, RCODE_SERVFAIL, false, DNS_UDP_SAFE_PACKET_SIZE);
    let _ = socket.send_to(&response, client).await;
}

fn udp_response_size(packet: &[u8]) -> usize {
    parse_dns_query(packet)
        .map(|query| {
            query
                .udp_payload_size
                .clamp(DNS_UDP_SAFE_PACKET_SIZE, DNS_MAX_UDP_PACKET_SIZE)
        })
        .unwrap_or(DNS_UDP_SAFE_PACKET_SIZE)
}

// ── DNS wire format parsing ──────────────────────────────────────────────

/// Parse an incoming DNS query packet. Returns `None` if the packet is
/// malformed or not a standard query.
fn parse_dns_query(packet: &[u8]) -> Option<DnsQuery> {
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let nscount = u16::from_be_bytes([packet[8], packet[9]]);
    let arcount = u16::from_be_bytes([packet[10], packet[11]]);

    // Must be a standard query (QR=0, OPCODE=0)
    if flags & 0xF800 != 0 {
        return None;
    }

    if ancount != 0 || nscount != 0 {
        return None;
    }

    // Must have exactly one question
    if qdcount != 1 {
        return None;
    }

    // Parse QNAME (label-encoded)
    let (name, offset) = parse_dns_name(packet, DNS_HEADER_SIZE)?;
    if name.is_empty() {
        return None;
    }

    // Need at least 4 more bytes for QTYPE + QCLASS
    if offset + 4 > packet.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let question_end = offset + 4;

    let normalized = normalize_dns_name(&name);
    if normalized.is_empty() {
        return None;
    }

    let mut additional_offset = question_end;
    let mut opt_record = None;
    let mut udp_payload_size = DNS_UDP_SAFE_PACKET_SIZE;
    for _ in 0..arcount {
        let record_start = additional_offset;
        let (_, record_name_end) = parse_dns_name(packet, additional_offset)?;
        if record_name_end + 10 > packet.len() {
            return None;
        }
        let record_type =
            u16::from_be_bytes([packet[record_name_end], packet[record_name_end + 1]]);
        let record_class =
            u16::from_be_bytes([packet[record_name_end + 2], packet[record_name_end + 3]]);
        let rdlen =
            u16::from_be_bytes([packet[record_name_end + 8], packet[record_name_end + 9]]) as usize;
        let record_end = record_name_end + 10 + rdlen;
        if record_end > packet.len() {
            return None;
        }
        if record_type == QTYPE_OPT {
            if opt_record.is_some() {
                return None;
            }
            udp_payload_size = usize::from(record_class);
            opt_record = Some(packet[record_start..record_end].to_vec());
        }
        additional_offset = record_end;
    }
    if additional_offset != packet.len() {
        return None;
    }

    Some(DnsQuery {
        id,
        flags,
        name: normalized,
        qtype,
        qclass,
        opt_record,
        udp_payload_size,
    })
}

/// Parse a DNS label-encoded name starting at `offset`. Returns the
/// decoded name and the byte position immediately after it.
///
/// Supports pointer compression (0xC0xx) for completeness but the
/// question section of standard queries does not use pointers.
fn parse_dns_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::with_capacity(64);
    let mut offset = start;
    let mut return_offset = None;
    let mut visited = vec![false; packet.len()];

    loop {
        if offset >= packet.len() {
            return None;
        }
        if visited[offset] {
            return None;
        }
        visited[offset] = true;

        let len = packet[offset] as usize;

        if len == 0 {
            // End of name
            if return_offset.is_none() {
                return_offset = Some(offset + 1);
            }
            break;
        }

        // Pointer compression
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return None;
            }
            if return_offset.is_none() {
                return_offset = Some(offset + 2);
            }
            let pointer = ((len & 0x3F) << 8) | packet[offset + 1] as usize;
            if pointer >= packet.len() {
                return None;
            }
            offset = pointer;
            continue;
        }

        // Label length must be <= 63
        if len > 63 {
            return None;
        }

        offset += 1;
        if offset + len > packet.len() {
            return None;
        }

        if !name.is_empty() {
            name.push('.');
        }
        // DNS labels are case-insensitive; we normalize in the caller
        for &byte in &packet[offset..offset + len] {
            if !is_valid_dns_label_byte(byte) {
                return None;
            }
            name.push(byte as char);
        }
        if name.len() + 1 > 255 {
            return None;
        }
        offset += len;
    }

    Some((name, return_offset.unwrap_or(offset)))
}

fn is_valid_dns_label_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// Build a DNS response with answer records.
fn build_dns_response(
    query: &DnsQuery,
    answers: &[&IpAddr],
    ttl: u32,
    authoritative: bool,
    max_response_size: usize,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(max_response_size.min(DNS_MAX_UDP_PACKET_SIZE));
    write_dns_response_header(&mut response, query, 0, authoritative, false, 0, 0);
    encode_dns_name(&query.name, &mut response).expect("parsed DNS names are encodable");
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());

    let opt_len = query.opt_record.as_ref().map_or(0, Vec::len);
    let mut answer_count = 0u16;
    let mut truncated = false;

    for ip in answers.iter().take(u16::MAX as usize) {
        let record_len = dns_answer_record_len(ip);
        if response.len() + record_len + opt_len > max_response_size {
            truncated = true;
            break;
        }
        write_dns_answer_record(&mut response, ip, ttl);
        answer_count = answer_count.saturating_add(1);
    }
    if answers.len() > usize::from(answer_count) {
        truncated = true;
    }

    let arcount = append_opt_record(query, &mut response, max_response_size);
    patch_dns_response_header(
        &mut response,
        query,
        answer_count,
        authoritative,
        truncated,
        0,
        arcount,
    );
    response
}

/// Build an empty DNS response (name exists, but no records of the requested type).
fn build_dns_empty_response(
    query: &DnsQuery,
    authoritative: bool,
    max_response_size: usize,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(max_response_size.min(DNS_UDP_SAFE_PACKET_SIZE));
    write_dns_response_header(&mut response, query, 0, authoritative, false, 0, 0);
    encode_dns_name(&query.name, &mut response).expect("parsed DNS names are encodable");
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());
    let arcount = append_opt_record(query, &mut response, max_response_size);
    patch_dns_response_header(&mut response, query, 0, authoritative, false, 0, arcount);
    response
}

fn build_dns_error_response(
    query: &DnsQuery,
    rcode: u16,
    authoritative: bool,
    max_response_size: usize,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(max_response_size.min(DNS_UDP_SAFE_PACKET_SIZE));
    write_dns_response_header(&mut response, query, 0, authoritative, false, rcode, 0);
    encode_dns_name(&query.name, &mut response).expect("parsed DNS names are encodable");
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());
    let arcount = append_opt_record(query, &mut response, max_response_size);
    patch_dns_response_header(
        &mut response,
        query,
        0,
        authoritative,
        false,
        rcode,
        arcount,
    );
    response
}

fn build_dns_error_response_from_packet(
    packet: &[u8],
    rcode: u16,
    max_response_size: usize,
) -> Option<Vec<u8>> {
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let rd_flag = flags & FLAGS_RD;
    let response_flags = FLAGS_QR | FLAGS_RA | rd_flag | (rcode & 0x000F);
    let mut response = Vec::with_capacity(max_response_size.min(DNS_UDP_SAFE_PACKET_SIZE));
    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    Some(response)
}

fn write_dns_response_header(
    response: &mut Vec<u8>,
    query: &DnsQuery,
    answer_count: u16,
    authoritative: bool,
    truncated: bool,
    rcode: u16,
    arcount: u16,
) {
    response.extend_from_slice(&query.id.to_be_bytes());
    response.extend_from_slice(
        &dns_response_flags(query, authoritative, truncated, rcode).to_be_bytes(),
    );
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    response.extend_from_slice(&answer_count.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&arcount.to_be_bytes()); // ARCOUNT
}

fn patch_dns_response_header(
    response: &mut [u8],
    query: &DnsQuery,
    answer_count: u16,
    authoritative: bool,
    truncated: bool,
    rcode: u16,
    arcount: u16,
) {
    response[2..4]
        .copy_from_slice(&dns_response_flags(query, authoritative, truncated, rcode).to_be_bytes());
    response[6..8].copy_from_slice(&answer_count.to_be_bytes());
    response[10..12].copy_from_slice(&arcount.to_be_bytes());
}

fn dns_response_flags(query: &DnsQuery, authoritative: bool, truncated: bool, rcode: u16) -> u16 {
    let rd_flag = query.flags & FLAGS_RD;
    let aa_flag = if authoritative { FLAGS_AA } else { 0 };
    let tc_flag = if truncated { FLAGS_TC } else { 0 };
    FLAGS_QR | aa_flag | tc_flag | rd_flag | FLAGS_RA | (rcode & 0x000F)
}

fn dns_answer_record_len(ip: &IpAddr) -> usize {
    12 + match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    }
}

fn write_dns_answer_record(response: &mut Vec<u8>, ip: &IpAddr, ttl: u32) {
    // NAME pointer: 0xC00C points to QNAME at byte 12
    response.extend_from_slice(&[0xC0, 0x0C]);

    match ip {
        IpAddr::V4(v4) => {
            response.extend_from_slice(&QTYPE_A.to_be_bytes()); // TYPE
            response.extend_from_slice(&QCLASS_IN.to_be_bytes()); // CLASS
            response.extend_from_slice(&ttl.to_be_bytes()); // TTL
            response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            response.extend_from_slice(&v4.octets()); // RDATA
        }
        IpAddr::V6(v6) => {
            response.extend_from_slice(&QTYPE_AAAA.to_be_bytes()); // TYPE
            response.extend_from_slice(&QCLASS_IN.to_be_bytes()); // CLASS
            response.extend_from_slice(&ttl.to_be_bytes()); // TTL
            response.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
            response.extend_from_slice(&v6.octets()); // RDATA
        }
    }
}

fn append_opt_record(query: &DnsQuery, response: &mut Vec<u8>, max_response_size: usize) -> u16 {
    let Some(opt_record) = query.opt_record.as_ref() else {
        return 0;
    };
    if response.len() + opt_record.len() > max_response_size {
        return 0;
    }
    response.extend_from_slice(opt_record);
    1
}

/// Encode a hostname into DNS label format and append to the buffer.
fn encode_dns_name(name: &str, buf: &mut Vec<u8>) -> Option<()> {
    if name.is_empty() || name.len() + 1 > 255 {
        return None;
    }
    for label in name.split('.') {
        let len = label.len();
        if len > 63
            || len == 0
            || !label
                .as_bytes()
                .iter()
                .copied()
                .all(is_valid_dns_label_byte)
        {
            return None;
        }
        buf.push(len as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // Root label terminator
    Some(())
}

// ── Unit tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TrustDomain;
    use crate::identity::spiffe::SpiffeId;
    use crate::modes::mesh::config::{AppProtocol, Workload, WorkloadPort, WorkloadSelector};
    use crate::modes::mesh::config::{
        MeshEndpoint, MeshService, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
        WorkloadRef,
    };
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── DNS wire format tests ────────────────────────────────────────────

    fn build_a_query(name: &str) -> Vec<u8> {
        build_query_packet(name, QTYPE_A)
    }

    fn build_aaaa_query(name: &str) -> Vec<u8> {
        build_query_packet(name, QTYPE_AAAA)
    }

    fn build_query_packet(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        // Header
        packet.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
        packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // QNAME
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label
        // QTYPE + QCLASS
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
        packet
    }

    fn build_query_with_opt(name: &str, qtype: u16, udp_payload_size: u16) -> Vec<u8> {
        let mut packet = build_query_packet(name, qtype);
        packet[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        packet.push(0); // Root owner name
        packet.extend_from_slice(&QTYPE_OPT.to_be_bytes());
        packet.extend_from_slice(&udp_payload_size.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes()); // TTL / extended RCODE / flags
        packet.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
        packet
    }

    #[test]
    fn parse_dns_query_valid_a_query() {
        let packet = build_a_query("example.com");
        let query = parse_dns_query(&packet).expect("should parse");
        assert_eq!(query.id, 0x1234);
        assert_eq!(query.name, "example.com");
        assert_eq!(query.qtype, QTYPE_A);
        assert_eq!(query.qclass, QCLASS_IN);
    }

    #[test]
    fn parse_dns_query_valid_aaaa_query() {
        let packet = build_aaaa_query("ipv6.example.com");
        let query = parse_dns_query(&packet).expect("should parse");
        assert_eq!(query.name, "ipv6.example.com");
        assert_eq!(query.qtype, QTYPE_AAAA);
    }

    #[test]
    fn parse_dns_query_truncated_packet() {
        let packet = vec![0u8; 5]; // Too short for header
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_query_rejects_root_name() {
        let packet = build_a_query("");
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_query_rejects_non_ascii_labels() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(1);
        packet.push(0xff);
        packet.push(0);
        packet.extend_from_slice(&QTYPE_A.to_be_bytes());
        packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_query_honors_edns_payload_size() {
        let packet = build_query_with_opt("example.com", QTYPE_A, 1232);
        let query = parse_dns_query(&packet).expect("should parse");
        assert_eq!(query.udp_payload_size, 1232);
        assert!(query.opt_record.is_some());
    }

    #[test]
    fn parse_dns_query_non_query_opcode() {
        let mut packet = build_a_query("test.com");
        // Set QR=1 (response)
        packet[2] |= 0x80;
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn parse_dns_query_non_in_class() {
        let mut packet = build_a_query("test.com");
        // Change QCLASS from 1 (IN) to 3 (CH)
        let qclass_offset = packet.len() - 2;
        packet[qclass_offset] = 0;
        packet[qclass_offset + 1] = 3;
        let query = parse_dns_query(&packet).expect("should parse");
        assert_eq!(query.qclass, 3);
    }

    #[test]
    fn parse_dns_query_truncated_after_name() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        // QNAME with no QTYPE/QCLASS
        packet.push(3);
        packet.extend_from_slice(b"foo");
        packet.push(0);
        assert!(parse_dns_query(&packet).is_none());
    }

    #[test]
    fn build_dns_response_a_record() {
        let packet = build_a_query("api.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let response = build_dns_response(&query, &[&ip], 60, true, DNS_UDP_SAFE_PACKET_SIZE);

        // Verify header
        assert_eq!(response[0..2], query.id.to_be_bytes());
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!(flags & FLAGS_QR != 0); // Is response
        assert!(flags & FLAGS_AA != 0); // Authoritative
        assert!(flags & FLAGS_RA != 0); // Recursion available is server state
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);

        // Find the answer section (after reconstructed question)
        // The answer uses a name pointer 0xC00C and then TYPE(2)+CLASS(2)+TTL(4)+RDLEN(2)+RDATA(4)
        // Verify the A record data is present at the end
        let rdata_start = response.len() - 4;
        assert_eq!(&response[rdata_start..], &[10, 0, 0, 1]);
    }

    #[test]
    fn build_dns_response_aaaa_record() {
        let packet = build_aaaa_query("ipv6.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let ip: IpAddr = "::1".parse().unwrap();
        let response = build_dns_response(&query, &[&ip], 120, true, DNS_UDP_SAFE_PACKET_SIZE);

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);

        // AAAA RDATA is 16 bytes at the end
        let rdata_start = response.len() - 16;
        let expected_ip: Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(&response[rdata_start..], &expected_ip.octets());
    }

    #[test]
    fn build_dns_response_multiple_answers() {
        let packet = build_a_query("multi.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let response =
            build_dns_response(&query, &[&ip1, &ip2], 60, true, DNS_UDP_SAFE_PACKET_SIZE);

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 2);
    }

    #[test]
    fn build_dns_response_sets_tc_when_udp_response_would_exceed_limit() {
        let packet = build_a_query("many.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let ips: Vec<IpAddr> = (1..=20)
            .map(|octet| IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)))
            .collect();
        let answer_refs: Vec<&IpAddr> = ips.iter().collect();
        let response = build_dns_response(&query, &answer_refs, 60, true, 96);
        let flags = u16::from_be_bytes([response[2], response[3]]);
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert!(flags & FLAGS_TC != 0);
        assert!(usize::from(ancount) < ips.len());
        assert!(response.len() <= 96);
    }

    #[test]
    fn build_dns_response_echoes_opt_record_when_present() {
        let packet = build_query_with_opt("edns.example.com", QTYPE_A, 1232);
        let query = parse_dns_query(&packet).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let response = build_dns_response(&query, &[&ip], 60, true, 1232);
        let arcount = u16::from_be_bytes([response[10], response[11]]);
        assert_eq!(arcount, 1);
        assert!(response.ends_with(query.opt_record.as_ref().unwrap()));
    }

    #[test]
    fn build_dns_response_omits_aa_for_external_service_entry_names() {
        let packet = build_a_query("api.external.com");
        let query = parse_dns_query(&packet).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let response = build_dns_response(&query, &[&ip], 60, false, DNS_UDP_SAFE_PACKET_SIZE);
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & FLAGS_AA, 0);
        assert!(flags & FLAGS_RA != 0);
    }

    #[test]
    fn build_dns_empty_response_correct_flags() {
        let packet = build_aaaa_query("no-aaaa.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let response = build_dns_empty_response(&query, true, DNS_UDP_SAFE_PACKET_SIZE);

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!(flags & FLAGS_QR != 0);
        assert!(flags & FLAGS_AA != 0);
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 0);
    }

    #[test]
    fn encode_and_parse_roundtrip() {
        let name = "foo.bar.baz.example.com";
        let mut encoded = Vec::new();
        // Build a minimal packet with header + encoded name
        encoded.extend_from_slice(&[0u8; DNS_HEADER_SIZE]); // dummy header
        encode_dns_name(name, &mut encoded).unwrap();
        let (parsed, _) = parse_dns_name(&encoded, DNS_HEADER_SIZE).unwrap();
        assert_eq!(parsed, name);
    }

    // ── Resolution table tests ───────────────────────────────────────────

    fn test_service_entry(hosts: Vec<&str>, endpoints: Vec<&str>) -> ServiceEntry {
        ServiceEntry {
            name: "test-se".to_string(),
            namespace: "default".to_string(),
            hosts: hosts.into_iter().map(String::from).collect(),
            endpoints: endpoints
                .into_iter()
                .map(|addr| MeshEndpoint {
                    address: addr.to_string(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                })
                .collect(),
            resolution: Resolution::Static,
            location: ServiceEntryLocation::MeshExternal,
            ports: vec![ServicePort {
                port: 443,
                protocol: AppProtocol::Http,
                name: Some("https".to_string()),
            }],
        }
    }

    fn test_workload(spiffe_id: &str, addresses: Vec<&str>) -> Workload {
        let trust_domain = TrustDomain::new("cluster.local").unwrap();
        Workload {
            spiffe_id: SpiffeId::new(spiffe_id.to_string()).unwrap(),
            selector: WorkloadSelector::default(),
            service_name: "test-svc".to_string(),
            addresses: addresses.into_iter().map(String::from).collect(),
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

    fn test_mesh_service(name: &str, namespace: &str, workload_refs: Vec<&str>) -> MeshService {
        MeshService {
            name: name.to_string(),
            namespace: namespace.to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            }],
            workloads: workload_refs
                .into_iter()
                .map(|id| WorkloadRef {
                    spiffe_id: SpiffeId::new(id.to_string()).unwrap(),
                })
                .collect(),
            protocol_overrides: HashMap::new(),
        }
    }

    #[test]
    fn resolution_table_from_service_entries() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["api.external.com", "db.external.com"],
                vec!["10.0.0.1", "10.0.0.2"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert_eq!(table.exact_count(), 2);

        let ips = table.resolve("api.external.com").unwrap();
        assert!(ips.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"10.0.0.2".parse::<IpAddr>().unwrap()));

        let ips = table.resolve("db.external.com").unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn resolution_table_from_mesh_services() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/api";
        let slice = MeshSlice {
            workloads: vec![test_workload(spiffe, vec!["10.1.0.1", "10.1.0.2"])],
            services: vec![test_mesh_service("my-api", "default", vec![spiffe])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);

        // FQDN: my-api.default.svc.cluster.local
        let ips = table.resolve("my-api.default.svc.cluster.local").unwrap();
        assert!(ips.contains(&"10.1.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"10.1.0.2".parse::<IpAddr>().unwrap()));

        // Short name: my-api.default
        let ips = table.resolve("my-api.default").unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn resolution_table_wildcard_matching() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(vec!["*.example.com"], vec!["10.0.0.1"])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert_eq!(table.wildcard_count(), 1);

        // Should match subdomains
        assert!(table.resolve("foo.example.com").is_some());
        assert!(table.resolve("bar.example.com").is_some());
        assert!(table.resolve("deep.sub.example.com").is_none());

        // Should NOT match the bare suffix itself
        assert!(table.resolve("example.com").is_none());

        // Should NOT match a non-subdomain that merely ends with the suffix
        assert!(table.resolve("fooexample.com").is_none());
    }

    #[test]
    fn resolution_table_case_insensitive() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["API.Example.COM"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);

        // Lookup with different case should match
        assert!(table.resolve("api.example.com").is_some());
        assert!(table.resolve("API.EXAMPLE.COM").is_some());
        assert!(table.resolve("Api.Example.Com").is_some());
    }

    #[test]
    fn resolution_table_trailing_dot() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["api.example.com."],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);

        // Both with and without trailing dot should resolve
        assert!(table.resolve("api.example.com").is_some());
        assert!(table.resolve("api.example.com.").is_some());
    }

    #[test]
    fn resolution_table_uses_custom_cluster_domain_for_mesh_services() {
        let spiffe = "spiffe://cluster.local/ns/default/sa/api";
        let slice = MeshSlice {
            workloads: vec![test_workload(spiffe, vec!["10.1.0.1"])],
            services: vec![test_mesh_service("my-api", "default", vec![spiffe])],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice_with_cluster_domain(&slice, "corp.local");

        assert!(table.resolve("my-api.default.svc.corp.local").is_some());
        assert!(table.resolve("my-api.default.svc.cluster.local").is_none());
    }

    #[test]
    fn resolution_table_no_match() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["known.example.com"],
                vec!["10.0.0.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert!(table.resolve("unknown.example.com").is_none());
        assert!(table.resolve("google.com").is_none());
    }

    #[test]
    fn resolution_table_skips_non_ip_and_non_routable_endpoints() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["mixed.example.com"],
                vec!["10.0.0.1", "not-an-ip", "::1", "127.0.0.1", "169.254.1.1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table.resolve("mixed.example.com").unwrap();
        assert_eq!(ips.len(), 1);
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn resolution_table_skips_entries_with_no_valid_ips() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["no-ips.example.com"],
                vec!["hostname.internal"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        assert!(table.resolve("no-ips.example.com").is_none());
    }

    #[test]
    fn resolution_table_empty_slice() {
        let table = DnsResolutionTable::from_mesh_slice(&MeshSlice::default());
        assert_eq!(table.exact_count(), 0);
        assert_eq!(table.wildcard_count(), 0);
    }

    #[test]
    fn resolution_table_deduplicates_ips() {
        let spiffe1 = "spiffe://cluster.local/ns/default/sa/api-1";
        let spiffe2 = "spiffe://cluster.local/ns/default/sa/api-2";
        let slice = MeshSlice {
            workloads: vec![
                test_workload(spiffe1, vec!["10.1.0.1"]),
                test_workload(spiffe2, vec!["10.1.0.1"]), // Same IP
            ],
            services: vec![test_mesh_service(
                "shared-ip",
                "default",
                vec![spiffe1, spiffe2],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table
            .resolve("shared-ip.default.svc.cluster.local")
            .unwrap();
        // Should be deduplicated
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn resolution_table_mixed_ipv4_ipv6() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["dual.example.com"],
                vec!["10.0.0.1", "fd00::1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table.resolve("dual.example.com").unwrap();
        assert_eq!(ips.len(), 2);

        let v4_count = ips.iter().filter(|ip| ip.is_ipv4()).count();
        let v6_count = ips.iter().filter(|ip| ip.is_ipv6()).count();
        assert_eq!(v4_count, 1);
        assert_eq!(v6_count, 1);
    }
}
