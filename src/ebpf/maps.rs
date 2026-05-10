//! Typed BPF map operations wrapping aya's map API.
//!
//! `BpfMaps` provides insert/remove helpers for each BPF map, converting
//! between Rust types and the `#[repr(C)]` shared types from
//! `ferrum-ebpf-common`. Only available on Linux with `--features ebpf`.

#![allow(dead_code)]

#[cfg(feature = "ebpf")]
use std::net::Ipv4Addr;

#[cfg(feature = "ebpf")]
use aya::Ebpf;
#[cfg(feature = "ebpf")]
use aya::maps::{HashMap as BpfHashMap, LpmTrie, MapData};
#[cfg(feature = "ebpf")]
use ferrum_ebpf_common::{CidrKey4, PodInfo as BpfPodInfo};

#[cfg(feature = "ebpf")]
use super::PodInfo;

#[cfg(feature = "ebpf")]
pub struct BpfMaps {
    pod_ips: BpfHashMap<MapData, u32, BpfPodInfo>,
    bypass_uids: BpfHashMap<MapData, u32, u8>,
    cidr_exclude4: LpmTrie<MapData, CidrKey4, u8>,
    cidr_include4: LpmTrie<MapData, CidrKey4, u8>,
    port_exclude: BpfHashMap<MapData, u16, u8>,
}

#[cfg(feature = "ebpf")]
impl BpfMaps {
    pub fn from_ebpf(bpf: &Ebpf) -> Result<Self, String> {
        let pod_ips = BpfHashMap::try_from(
            bpf.map("FERRUM_POD_IPS")
                .ok_or("FERRUM_POD_IPS map not found")?
                .clone(),
        )
        .map_err(|e| format!("FERRUM_POD_IPS type mismatch: {e}"))?;

        let bypass_uids = BpfHashMap::try_from(
            bpf.map("FERRUM_BYPASS_UIDS")
                .ok_or("FERRUM_BYPASS_UIDS map not found")?
                .clone(),
        )
        .map_err(|e| format!("FERRUM_BYPASS_UIDS type mismatch: {e}"))?;

        let cidr_exclude4 = LpmTrie::try_from(
            bpf.map("FERRUM_CIDR_EXCLUDE4")
                .ok_or("FERRUM_CIDR_EXCLUDE4 map not found")?
                .clone(),
        )
        .map_err(|e| format!("FERRUM_CIDR_EXCLUDE4 type mismatch: {e}"))?;

        let cidr_include4 = LpmTrie::try_from(
            bpf.map("FERRUM_CIDR_INCLUDE4")
                .ok_or("FERRUM_CIDR_INCLUDE4 map not found")?
                .clone(),
        )
        .map_err(|e| format!("FERRUM_CIDR_INCLUDE4 type mismatch: {e}"))?;

        let port_exclude = BpfHashMap::try_from(
            bpf.map("FERRUM_PORT_EXCLUDE")
                .ok_or("FERRUM_PORT_EXCLUDE map not found")?
                .clone(),
        )
        .map_err(|e| format!("FERRUM_PORT_EXCLUDE type mismatch: {e}"))?;

        Ok(Self {
            pod_ips,
            bypass_uids,
            cidr_exclude4,
            cidr_include4,
            port_exclude,
        })
    }

    pub fn insert_pod_ip(&self, ip: Ipv4Addr, info: &PodInfo) -> Result<(), String> {
        let key = u32::from(ip);
        let value = BpfPodInfo {
            proxy_port: info.proxy_port as u32,
            _pad: 0,
        };
        let mut map = self.pod_ips.clone();
        map.insert(key, value, 0)
            .map_err(|e| format!("Failed to insert pod IP {ip}: {e}"))
    }

    pub fn remove_pod_ip(&self, ip: Ipv4Addr) -> Result<(), String> {
        let key = u32::from(ip);
        let mut map = self.pod_ips.clone();
        map.remove(&key)
            .map_err(|e| format!("Failed to remove pod IP {ip}: {e}"))
    }

    pub fn insert_bypass_uid(&self, uid: u32) -> Result<(), String> {
        let mut map = self.bypass_uids.clone();
        map.insert(uid, 1u8, 0)
            .map_err(|e| format!("Failed to insert bypass UID {uid}: {e}"))
    }

    pub fn insert_cidr_exclude(&self, cidr: &str) -> Result<(), String> {
        let key = parse_cidr_to_lpm_key(cidr)?;
        let mut map = self.cidr_exclude4.clone();
        map.insert(&key, 1u8, 0)
            .map_err(|e| format!("Failed to insert exclude CIDR '{cidr}': {e}"))
    }

    pub fn insert_cidr_include(&self, cidr: &str) -> Result<(), String> {
        let key = parse_cidr_to_lpm_key(cidr)?;
        let mut map = self.cidr_include4.clone();
        map.insert(&key, 1u8, 0)
            .map_err(|e| format!("Failed to insert include CIDR '{cidr}': {e}"))
    }

    pub fn insert_port_exclude(&self, port: u16) -> Result<(), String> {
        let mut map = self.port_exclude.clone();
        map.insert(port, 1u8, 0)
            .map_err(|e| format!("Failed to insert exclude port {port}: {e}"))
    }
}

/// Parse a CIDR string (e.g. "10.0.0.0/8") into an LPM trie key.
#[cfg(feature = "ebpf")]
fn parse_cidr_to_lpm_key(cidr: &str) -> Result<aya::maps::lpm_trie::Key<CidrKey4>, String> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("CIDR '{cidr}' missing prefix length"))?;
    let addr: std::net::Ipv4Addr = addr_str
        .parse()
        .map_err(|e| format!("CIDR '{cidr}' invalid address: {e}"))?;
    let prefix_len: u32 = prefix_str
        .parse()
        .map_err(|e| format!("CIDR '{cidr}' invalid prefix length: {e}"))?;

    let data = CidrKey4::new(u32::from(addr).to_be(), prefix_len);
    Ok(aya::maps::lpm_trie::Key::new(data.prefix_len, data.addr))
}

use ferrum_ebpf_common::CidrKey4;

pub fn parse_cidr_to_lpm_key_data(cidr: &str) -> Result<CidrKey4, String> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("CIDR '{cidr}' missing prefix length"))?;
    let addr: std::net::Ipv4Addr = addr_str
        .parse()
        .map_err(|e| format!("CIDR '{cidr}' invalid address: {e}"))?;
    let prefix_len: u32 = prefix_str
        .parse()
        .map_err(|e| format!("CIDR '{cidr}' invalid prefix length: {e}"))?;

    Ok(CidrKey4::new(u32::from(addr).to_be(), prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_to_lpm_key_valid() {
        let key = parse_cidr_to_lpm_key_data("10.0.0.0/8").unwrap();
        assert_eq!(key.prefix_len, 8);
    }

    #[test]
    fn parse_cidr_to_lpm_key_host() {
        let key = parse_cidr_to_lpm_key_data("192.168.1.1/32").unwrap();
        assert_eq!(key.prefix_len, 32);
    }

    #[test]
    fn parse_cidr_missing_prefix() {
        assert!(parse_cidr_to_lpm_key_data("10.0.0.0").is_err());
    }

    #[test]
    fn parse_cidr_invalid_addr() {
        assert!(parse_cidr_to_lpm_key_data("not.an.ip/8").is_err());
    }

    #[test]
    fn parse_cidr_invalid_prefix() {
        assert!(parse_cidr_to_lpm_key_data("10.0.0.0/abc").is_err());
    }
}
