//! Tiny in-process UDP DNS resolver used by the perf harness as the
//! gateway's `FERRUM_MESH_DNS_UPSTREAM_ADDR` target.
//!
//! Answers any A query with 192.0.2.1 (TEST-NET-1, RFC 5737 §3) and any
//! AAAA query with 2001:db8::1 (RFC 3849). Deterministic by design.

use std::net::SocketAddr;

use clap::Parser;
use mesh_dns_e2e_perf::dns_wire::{QTYPE_A, QTYPE_AAAA, QTYPE_OPT, parse_response};
use tokio::net::UdpSocket;

#[derive(Parser, Debug)]
#[command(about = "Deterministic UDP DNS upstream stub for the mesh DNS perf harness")]
struct Args {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:17053")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let addr: SocketAddr = args.listen.parse()?;
    let socket = UdpSocket::bind(addr).await?;
    eprintln!("[dns_upstream_stub] UDP listening on {addr}");
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[dns_upstream_stub] recv error: {e}");
                continue;
            }
        };
        if let Some(reply) = build_stub_response(&buf[..len]) {
            let _ = socket.send_to(&reply, src).await;
        }
    }
}

fn build_stub_response(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    let qtype = extract_first_qtype(packet)?;
    let qname_end = find_qname_end(packet, 12)?;
    let client_opt_payload = extract_client_opt_payload_size(packet, qname_end + 4);

    let mut reply = Vec::with_capacity(packet.len() + 32);
    reply.extend_from_slice(&packet[..12]);
    // Flags: set QR=1 (response) and RA=1 (recursion available).
    reply[2] |= 0x80;
    reply[3] |= 0x80;
    // Copy the question section verbatim.
    reply.extend_from_slice(&packet[12..qname_end + 4]);

    let (set_ancount, rdata): (bool, &[u8]) = match qtype {
        QTYPE_A => (true, &[192, 0, 2, 1]),
        QTYPE_AAAA => (
            true,
            &[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
        ),
        _ => (false, &[]),
    };

    if set_ancount {
        reply[6] = 0;
        reply[7] = 1;
        // Answer: pointer back to qname (0xC00C), TYPE, CLASS=IN, TTL=60, RDLEN
        reply.extend_from_slice(&[0xC0, 0x0C]);
        reply.extend_from_slice(&qtype.to_be_bytes());
        reply.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        reply.extend_from_slice(&60u32.to_be_bytes()); // TTL
        reply.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        reply.extend_from_slice(rdata);
    } else {
        reply[6] = 0;
        reply[7] = 0;
    }

    // Echo an OPT record back when the client advertised one (RFC 6891
    // §6.1.1). Mirroring the client's payload size keeps the response
    // shape closer to what a real upstream would emit, so the gateway's
    // OPT-echo / cache-keying paths exercise representative data.
    let mut arcount: u16 = 0;
    if let Some(payload_size) = client_opt_payload {
        arcount += 1;
        reply.push(0); // root name
        reply.extend_from_slice(&QTYPE_OPT.to_be_bytes());
        reply.extend_from_slice(&payload_size.to_be_bytes());
        reply.extend_from_slice(&0u32.to_be_bytes()); // extended rcode + version + flags
        reply.extend_from_slice(&0u16.to_be_bytes()); // RDLEN
    }
    reply[10] = (arcount >> 8) as u8;
    reply[11] = (arcount & 0xff) as u8;

    debug_assert!(parse_response(&reply).is_some());
    Some(reply)
}

/// Walk the request's additional section looking for an OPT pseudo-RR.
/// Returns the OPT CLASS field (the requestor's UDP payload size) when
/// present. Defensive: returns None on malformed input.
fn extract_client_opt_payload_size(packet: &[u8], mut cursor: usize) -> Option<u16> {
    // Header byte 10..12 is ARCOUNT. We only look at additional RRs.
    let arcount = u16::from_be_bytes([*packet.get(10)?, *packet.get(11)?]);
    // Skip authority RRs (NSCOUNT) — none expected in a query, but be safe.
    let nscount = u16::from_be_bytes([*packet.get(8)?, *packet.get(9)?]);
    for _ in 0..nscount {
        cursor = skip_rr(packet, cursor)?;
    }
    for _ in 0..arcount {
        let name_end = find_qname_end(packet, cursor)?;
        if name_end + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let class = u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]);
        if rtype == QTYPE_OPT {
            return Some(class);
        }
        cursor = skip_rr(packet, cursor)?;
    }
    None
}

/// Skip a single resource record (NAME + 10-byte fixed header + RDATA).
fn skip_rr(packet: &[u8], cursor: usize) -> Option<usize> {
    let name_end = find_qname_end(packet, cursor)?;
    if name_end + 10 > packet.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
    let next = name_end + 10 + rdlength;
    if next > packet.len() {
        return None;
    }
    Some(next)
}

fn find_qname_end(packet: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    while cursor < packet.len() {
        let len = packet[cursor];
        if len == 0 {
            return Some(cursor + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(cursor + 2);
        }
        cursor += 1 + len as usize;
    }
    None
}

fn extract_first_qtype(packet: &[u8]) -> Option<u16> {
    let qname_end = find_qname_end(packet, 12)?;
    if packet.len() < qname_end + 4 {
        return None;
    }
    Some(u16::from_be_bytes([
        packet[qname_end],
        packet[qname_end + 1],
    ]))
}
