//! BPF map definitions shared across all Ferrum capture programs.
//!
//! Maps are pinned to `/sys/fs/bpf/` by the userspace loader so they persist
//! across program reloads and can be read by the proxy.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LpmTrie, LruHashMap};
use ferrum_ebpf_common::{
    BpfCaptureConfig, CidrKey4, CidrKey6, OrigDst4, OrigDst6, OrigDstKey, PodInfo,
};

/// Original IPv4 destination before connect rewrite, keyed by socket cookie.
/// The proxy reads this map (via pinned path) to discover the real target.
#[map]
pub static FERRUM_ORIG_DST4: LruHashMap<OrigDstKey, OrigDst4> =
    LruHashMap::with_max_entries(65536, 0);

/// Original IPv6 destination before connect rewrite.
#[map]
pub static FERRUM_ORIG_DST6: LruHashMap<OrigDstKey, OrigDst6> =
    LruHashMap::with_max_entries(65536, 0);

/// Enrolled pod IPs. Keyed by IPv4 address (network byte order `u32`).
/// TC ingress checks this to decide whether to redirect inbound packets.
#[map]
pub static FERRUM_POD_IPS: HashMap<u32, PodInfo> = HashMap::with_max_entries(4096, 0);

/// UIDs exempt from outbound capture (proxy UID 1337).
/// Connect hooks skip rewrite when the calling process matches.
#[map]
pub static FERRUM_BYPASS_UIDS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// IPv4 CIDRs to exclude from outbound capture (highest priority).
#[map]
pub static FERRUM_CIDR_EXCLUDE4: LpmTrie<CidrKey4, u8> = LpmTrie::with_max_entries(1024, 0);

/// IPv6 CIDRs to exclude from outbound capture.
#[map]
pub static FERRUM_CIDR_EXCLUDE6: LpmTrie<CidrKey6, u8> = LpmTrie::with_max_entries(1024, 0);

/// IPv4 CIDRs to include for outbound capture (default 0.0.0.0/0 = all).
#[map]
pub static FERRUM_CIDR_INCLUDE4: LpmTrie<CidrKey4, u8> = LpmTrie::with_max_entries(1024, 0);

/// IPv6 CIDRs to include for outbound capture.
#[map]
pub static FERRUM_CIDR_INCLUDE6: LpmTrie<CidrKey6, u8> = LpmTrie::with_max_entries(1024, 0);

/// Destination ports to exclude from outbound capture.
#[map]
pub static FERRUM_PORT_EXCLUDE: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

/// Singleton node-agent capture settings.
#[map]
pub static FERRUM_CAPTURE_CONFIG: HashMap<u32, BpfCaptureConfig> = HashMap::with_max_entries(1, 0);
