//! Minimal DNS wire-format helpers — encode A/AAAA queries, parse responses.
//!
//! Mirrors the parser/encoder patterns in `src/modes/mesh/dns_proxy.rs`. Kept
//! deliberately small — we only need:
//!   - build_query(name, qtype, txid) -> Vec<u8>
//!   - parse_response(packet) -> ParsedResponse
//!   - frame_for_tcp(packet) / unframe_from_tcp(buf)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_OPT: u16 = 41;
pub const QCLASS_IN: u16 = 1;

const FLAGS_RD: u16 = 0x0100;
const FLAGS_QR: u16 = 0x8000;
const RCODE_MASK: u16 = 0x000F;

/// Build a single-question DNS query packet. Caller picks the transaction id.
pub fn build_query(name: &str, qtype: u16, txid: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(32 + name.len());
    // Header (12 bytes)
    packet.extend_from_slice(&txid.to_be_bytes());
    packet.extend_from_slice(&FLAGS_RD.to_be_bytes()); // RD=1, rest 0
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_dns_name(name, &mut packet);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
    packet
}

/// Build a query with an EDNS(0) OPT record advertising `udp_payload_size`.
/// Used to exercise the gateway's EDNS echo path.
pub fn build_query_with_edns(name: &str, qtype: u16, txid: u16, udp_payload_size: u16) -> Vec<u8> {
    let mut packet = build_query(name, qtype, txid);
    // Bump ARCOUNT from 0 to 1
    let ar_idx = 10;
    packet[ar_idx] = 0;
    packet[ar_idx + 1] = 1;
    // OPT pseudo-record: root name (0), TYPE=OPT, CLASS=udp_payload_size,
    // TTL=0 (no extended rcode / version / flags), RDLEN=0.
    packet.push(0); // root name
    packet.extend_from_slice(&QTYPE_OPT.to_be_bytes());
    packet.extend_from_slice(&udp_payload_size.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes()); // TTL
    packet.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
    packet
}

/// Encode a DNS name as length-prefixed labels terminated by a zero byte.
fn encode_dns_name(name: &str, buf: &mut Vec<u8>) {
    for label in name.split('.') {
        let bytes = label.as_bytes();
        // Caller is responsible for keeping labels under 63 bytes; this is a
        // test harness, not a validator. Truncate defensively.
        let len = bytes.len().min(63) as u8;
        buf.push(len);
        buf.extend_from_slice(&bytes[..len as usize]);
    }
    buf.push(0);
}

/// Frame a UDP-style DNS packet for TCP transport (RFC 1035 §4.2.2):
/// prepend a 2-byte length.
pub fn frame_for_tcp(packet: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(packet.len() + 2);
    framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    framed.extend_from_slice(packet);
    framed
}

/// Parsed view of a DNS response. Only the fields the harness uses.
#[derive(Debug, Clone, Default)]
pub struct ParsedResponse {
    pub txid: u16,
    pub rcode: u8,
    pub is_response: bool,
    pub answer_count: u16,
    pub answers: Vec<IpAddr>,
}

/// Best-effort DNS response parser. Returns None on truncation or malformed
/// packets.
pub fn parse_response(packet: &[u8]) -> Option<ParsedResponse> {
    if packet.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let mut cursor = 12usize;

    // Skip questions
    for _ in 0..qdcount {
        cursor = skip_name(packet, cursor)?;
        if cursor + 4 > packet.len() {
            return None;
        }
        cursor += 4; // qtype + qclass
    }

    let mut answers = Vec::with_capacity(ancount as usize);
    for _ in 0..ancount {
        cursor = skip_name(packet, cursor)?;
        if cursor + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        let rdlength = u16::from_be_bytes([packet[cursor + 8], packet[cursor + 9]]) as usize;
        cursor += 10;
        if cursor + rdlength > packet.len() {
            return None;
        }
        match rtype {
            QTYPE_A if rdlength == 4 => {
                let octets = [
                    packet[cursor],
                    packet[cursor + 1],
                    packet[cursor + 2],
                    packet[cursor + 3],
                ];
                answers.push(IpAddr::V4(Ipv4Addr::from(octets)));
            }
            QTYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[cursor..cursor + 16]);
                answers.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {} // ignore CNAME, OPT, SOA, etc.
        }
        cursor += rdlength;
    }

    Some(ParsedResponse {
        txid,
        rcode: (flags & RCODE_MASK) as u8,
        is_response: flags & FLAGS_QR != 0,
        answer_count: ancount,
        answers,
    })
}

/// Walk a (possibly compressed) DNS name and return the cursor just past the
/// terminating byte / pointer. Returns None on malformed input.
fn skip_name(packet: &[u8], mut cursor: usize) -> Option<usize> {
    let mut steps = 0;
    loop {
        if cursor >= packet.len() {
            return None;
        }
        let len = packet[cursor];
        if len == 0 {
            return Some(cursor + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Pointer — 2 bytes, terminates this name.
            if cursor + 2 > packet.len() {
                return None;
            }
            return Some(cursor + 2);
        }
        cursor += 1 + len as usize;
        steps += 1;
        // Defensive: a single name has at most ~127 labels (255-byte limit).
        if steps > 130 {
            return None;
        }
    }
}
