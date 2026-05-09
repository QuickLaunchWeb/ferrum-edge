//! Transparent DNS proxy for mesh ServiceEntry / MeshService resolution.
//!
//! Intercepts DNS queries (typically redirected from port 53 via iptables/eBPF)
//! and resolves mesh-internal hostnames from a pre-built resolution table.
//! Non-mesh queries are forwarded transparently to the upstream system resolver.
//!
//! The resolution table is rebuilt atomically (via `ArcSwap`) whenever the
//! `MeshSlice` is updated, so there are no locks on the query hot path.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, trace, warn};

use crate::xds::slice::MeshSlice;

// ── DNS wire-format constants ────────────────────────────────────────────

const DNS_HEADER_SIZE: usize = 12;
const DNS_MAX_PACKET_SIZE: usize = 4096;
const DNS_UPSTREAM_TIMEOUT_SECS: u64 = 5;

// QTYPE values
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

// QCLASS
const QCLASS_IN: u16 = 1;

// Response flags
const FLAGS_QR: u16 = 0x8000; // Response
const FLAGS_AA: u16 = 0x0400; // Authoritative Answer
const FLAGS_RD: u16 = 0x0100; // Recursion Desired
const FLAGS_RA: u16 = 0x0080; // Recursion Available

// ── DNS query representation ─────────────────────────────────────────────

/// Parsed DNS question extracted from an incoming query packet.
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
    /// Byte offset where the question section ends in the original packet.
    /// Used to construct the answer section with a pointer back to QNAME.
    question_end: usize,
}

// ── Resolution table ─────────────────────────────────────────────────────

/// FQDN-to-IP resolution table built from mesh config.
///
/// Rebuilt atomically from `MeshSlice` on config updates. The `ArcSwap`
/// wrapper ensures the query hot path never blocks on a rebuild.
pub struct DnsResolutionTable {
    /// Exact hostname matches (lowercase, trailing dot stripped).
    exact: HashMap<String, Vec<IpAddr>>,
    /// Wildcard matches: suffix -> IPs (e.g., "example.com" matches "*.example.com").
    wildcard_suffixes: Vec<(String, Vec<IpAddr>)>,
}

impl DnsResolutionTable {
    /// Build a resolution table from a mesh slice.
    ///
    /// Indexes `ServiceEntry.hosts` mapped to their endpoint IPs, plus
    /// `MeshService` short names (`{name}.{namespace}.svc.cluster.local`)
    /// mapped to workload addresses resolved through the slice.
    pub fn from_mesh_slice(slice: &MeshSlice) -> Self {
        let mut exact: HashMap<String, Vec<IpAddr>> = HashMap::new();
        let mut wildcard_suffixes: Vec<(String, Vec<IpAddr>)> = Vec::new();

        // Index workload addresses by SPIFFE ID for MeshService resolution.
        let mut workload_ips: HashMap<&str, Vec<IpAddr>> = HashMap::new();
        for wl in &slice.workloads {
            let ips: Vec<IpAddr> = wl
                .addresses
                .iter()
                .filter_map(|addr| addr.parse::<IpAddr>().ok())
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
                        wildcard_suffixes.push((suffix.to_string(), ips.clone()));
                    }
                } else {
                    exact.entry(normalized).or_default().extend(ips.iter());
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

            // Register the Kubernetes-style FQDN: {name}.{namespace}.svc.cluster.local
            let fqdn = format!("{}.{}.svc.cluster.local", svc.name, svc.namespace);
            exact.entry(fqdn).or_default().extend(svc_ips.iter());

            // Also register short name: {name}.{namespace}
            let short = format!("{}.{}", svc.name, svc.namespace);
            exact.entry(short).or_default().extend(svc_ips.iter());
        }

        // Deduplicate IPs within each entry
        for ips in exact.values_mut() {
            ips.sort_by(|a, b| format!("{a}").cmp(&format!("{b}")));
            ips.dedup();
        }
        for (_, ips) in &mut wildcard_suffixes {
            ips.sort_by(|a, b| format!("{a}").cmp(&format!("{b}")));
            ips.dedup();
        }

        Self {
            exact,
            wildcard_suffixes,
        }
    }

    /// Resolve a hostname against the table. Returns `None` for non-mesh names.
    pub fn resolve(&self, name: &str) -> Option<&Vec<IpAddr>> {
        let normalized = normalize_dns_name(name);

        // Exact match first (O(1))
        if let Some(ips) = self.exact.get(&normalized) {
            return Some(ips);
        }

        // Wildcard suffix match
        for (suffix, ips) in &self.wildcard_suffixes {
            if normalized.len() > suffix.len() + 1
                && normalized.ends_with(suffix.as_str())
                && normalized.as_bytes()[normalized.len() - suffix.len() - 1] == b'.'
            {
                return Some(ips);
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
        self.wildcard_suffixes.len()
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
}

impl MeshDnsProxy {
    /// Create a new DNS proxy (does not bind yet; call `run()` to start).
    pub fn new(listen_addr: SocketAddr, upstream_resolver: SocketAddr, ttl_seconds: u32) -> Self {
        Self {
            listen_addr,
            resolution_table: Arc::new(ArcSwap::new(Arc::new(DnsResolutionTable {
                exact: HashMap::new(),
                wildcard_suffixes: Vec::new(),
            }))),
            upstream_resolver,
            ttl_seconds,
        }
    }

    /// Return a clonable handle to the resolution table for updating from
    /// external MeshSlice installs.
    pub fn resolution_table_handle(&self) -> Arc<ArcSwap<DnsResolutionTable>> {
        self.resolution_table.clone()
    }

    /// Rebuild the resolution table from a new mesh slice.
    pub fn update_from_slice(&self, slice: &MeshSlice) {
        let new_table = DnsResolutionTable::from_mesh_slice(slice);
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
    pub async fn run(self, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
        let socket = match UdpSocket::bind(self.listen_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!(addr = %self.listen_addr, error = %e, "Failed to bind mesh DNS proxy");
                return;
            }
        };

        info!(addr = %self.listen_addr, "Mesh DNS proxy listening");

        let mut buf = vec![0u8; DNS_MAX_PACKET_SIZE];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            let packet = buf[..len].to_vec();
                            let socket = socket.clone();
                            let table = self.resolution_table.clone();
                            let upstream = self.upstream_resolver;
                            let ttl = self.ttl_seconds;

                            tokio::spawn(async move {
                                handle_dns_query(packet, src, &socket, &table, upstream, ttl).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "DNS proxy recv error");
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
    }
}

// ── Query handler ────────────────────────────────────────────────────────

async fn handle_dns_query(
    packet: Vec<u8>,
    src: SocketAddr,
    socket: &UdpSocket,
    table: &ArcSwap<DnsResolutionTable>,
    upstream: SocketAddr,
    ttl: u32,
) {
    let query = match parse_dns_query(&packet) {
        Some(q) => q,
        None => return, // Malformed; drop silently
    };

    // Only handle A/AAAA queries for IN class
    if query.qclass != QCLASS_IN || (query.qtype != QTYPE_A && query.qtype != QTYPE_AAAA) {
        forward_to_upstream(&packet, src, socket, upstream).await;
        return;
    }

    let table = table.load();
    match table.resolve(&query.name) {
        Some(ips) => {
            // Filter by query type: A gets IPv4, AAAA gets IPv6
            let filtered: Vec<&IpAddr> = ips
                .iter()
                .filter(|ip| {
                    matches!(
                        (query.qtype, ip),
                        (QTYPE_A, IpAddr::V4(_)) | (QTYPE_AAAA, IpAddr::V6(_))
                    )
                })
                .collect();

            if filtered.is_empty() {
                // Have the name but no matching record type -- return empty (not NXDOMAIN)
                let response = build_dns_empty_response(&query);
                let _ = socket.send_to(&response, src).await;
            } else {
                let response = build_dns_response(&query, &filtered, ttl);
                let _ = socket.send_to(&response, src).await;
            }

            trace!(
                name = %query.name,
                qtype = query.qtype,
                answers = filtered.len(),
                "DNS query resolved from mesh table"
            );
        }
        None => {
            // Not a mesh name -- forward to upstream
            forward_to_upstream(&packet, src, socket, upstream).await;
        }
    }
}

async fn forward_to_upstream(
    packet: &[u8],
    original_src: SocketAddr,
    client_socket: &UdpSocket,
    upstream: SocketAddr,
) {
    // Create a temporary socket for the upstream query to avoid mixing
    // responses from different clients on the main socket.
    let bind_addr = if upstream.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let upstream_socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!(error = %e, "Failed to bind upstream DNS socket");
            return;
        }
    };

    if let Err(e) = upstream_socket.send_to(packet, upstream).await {
        debug!(error = %e, upstream = %upstream, "Failed to send DNS query to upstream");
        return;
    }

    let mut response_buf = vec![0u8; DNS_MAX_PACKET_SIZE];
    match tokio::time::timeout(
        std::time::Duration::from_secs(DNS_UPSTREAM_TIMEOUT_SECS),
        upstream_socket.recv_from(&mut response_buf),
    )
    .await
    {
        Ok(Ok((len, _))) => {
            let _ = client_socket
                .send_to(&response_buf[..len], original_src)
                .await;
        }
        Ok(Err(e)) => {
            debug!(error = %e, "Upstream DNS recv error");
        }
        Err(_) => {
            debug!(upstream = %upstream, "Upstream DNS query timed out");
        }
    }
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

    // Must be a standard query (QR=0, OPCODE=0)
    if flags & 0xF800 != 0 {
        return None;
    }

    // Must have exactly one question
    if qdcount != 1 {
        return None;
    }

    // Parse QNAME (label-encoded)
    let (name, offset) = parse_dns_name(packet, DNS_HEADER_SIZE)?;

    // Need at least 4 more bytes for QTYPE + QCLASS
    if offset + 4 > packet.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let question_end = offset + 4;

    let normalized = normalize_dns_name(&name);

    Some(DnsQuery {
        id,
        flags,
        name: normalized,
        qtype,
        qclass,
        question_end,
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
    let mut jumps = 0;
    let mut return_offset = None;

    loop {
        if offset >= packet.len() {
            return None;
        }

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
            jumps += 1;
            if jumps > 10 {
                return None; // Prevent infinite loops
            }
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
            name.push(byte as char);
        }
        offset += len;
    }

    Some((name, return_offset.unwrap_or(offset)))
}

/// Build a DNS response with answer records.
fn build_dns_response(query: &DnsQuery, answers: &[&IpAddr], ttl: u32) -> Vec<u8> {
    let answer_count = answers.len() as u16;
    let rd_flag = query.flags & FLAGS_RD;
    let ra_flag = if rd_flag != 0 { FLAGS_RA } else { 0 };
    let response_flags = FLAGS_QR | FLAGS_AA | rd_flag | ra_flag;

    // Pre-calculate total size
    let answer_size: usize = answers
        .iter()
        .map(|ip| {
            12 + match ip {
                // NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 16,
            }
        })
        .sum();
    let total = query.question_end + answer_size;
    let mut response = Vec::with_capacity(total);

    // Copy header + question section from original packet, then patch header
    response.extend_from_slice(&query.id.to_be_bytes());
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1

    response.extend_from_slice(&answer_count.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Encode the question section QNAME + QTYPE + QCLASS
    encode_dns_name(&query.name, &mut response);
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());

    // Answer records: use pointer compression back to QNAME at offset 12
    for ip in answers {
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

    response
}

/// Build an empty DNS response (name exists, but no records of the requested type).
fn build_dns_empty_response(query: &DnsQuery) -> Vec<u8> {
    let rd_flag = query.flags & FLAGS_RD;
    let ra_flag = if rd_flag != 0 { FLAGS_RA } else { 0 };
    let response_flags = FLAGS_QR | FLAGS_AA | rd_flag | ra_flag;

    let mut response = Vec::with_capacity(query.question_end);

    response.extend_from_slice(&query.id.to_be_bytes());
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    encode_dns_name(&query.name, &mut response);
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());

    response
}

/// Encode a hostname into DNS label format and append to the buffer.
fn encode_dns_name(name: &str, buf: &mut Vec<u8>) {
    for label in name.split('.') {
        let len = label.len();
        if len > 63 || len == 0 {
            continue;
        }
        buf.push(len as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // Root label terminator
}

// ── Unit tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::mesh::{AppProtocol, Workload, WorkloadPort, WorkloadSelector};
    use crate::config::mesh::{
        MeshEndpoint, MeshService, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
        WorkloadRef,
    };
    use crate::identity::TrustDomain;
    use crate::identity::spiffe::SpiffeId;
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
        let response = build_dns_response(&query, &[&ip], 60);

        // Verify header
        assert_eq!(response[0..2], query.id.to_be_bytes());
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!(flags & FLAGS_QR != 0); // Is response
        assert!(flags & FLAGS_AA != 0); // Authoritative
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
        let response = build_dns_response(&query, &[&ip], 120);

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
        let response = build_dns_response(&query, &[&ip1, &ip2], 60);

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 2);
    }

    #[test]
    fn build_dns_empty_response_correct_flags() {
        let packet = build_aaaa_query("no-aaaa.example.com");
        let query = parse_dns_query(&packet).unwrap();
        let response = build_dns_empty_response(&query);

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
        encode_dns_name(name, &mut encoded);
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
        assert!(table.resolve("deep.sub.example.com").is_some());

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
    fn resolution_table_skips_non_ip_endpoints() {
        let slice = MeshSlice {
            service_entries: vec![test_service_entry(
                vec!["mixed.example.com"],
                vec!["10.0.0.1", "not-an-ip", "::1"],
            )],
            ..MeshSlice::default()
        };

        let table = DnsResolutionTable::from_mesh_slice(&slice);
        let ips = table.resolve("mixed.example.com").unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
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
