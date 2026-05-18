//! Tiny in-process UDP DNS resolver used by the perf harness as the
//! gateway's `FERRUM_MESH_DNS_UPSTREAM_ADDR` target.
//!
//! Answers any A query with 192.0.2.1 (TEST-NET-1, RFC 5737 §3) and any
//! AAAA query with 2001:db8::1 (RFC 3849). Deterministic by design.

use std::net::SocketAddr;

use clap::Parser;
use mesh_dns_e2e_perf::dns_wire::{QTYPE_A, QTYPE_AAAA, parse_response};
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

    debug_assert!(parse_response(&reply).is_some());
    Some(reply)
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
    Some(u16::from_be_bytes([packet[qname_end], packet[qname_end + 1]]))
}
