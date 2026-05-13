//! Mesh outbound registry plugin.
//!
//! Implements Istio `MeshConfig.outboundTrafficPolicy.mode: REGISTRY_ONLY`.
//! When the slice declares `RegistryOnly`, the gateway auto-injects this
//! global plugin with a pre-built set of known destinations from the slice
//! (services with their FQDN/namespace-qualified/bare-name forms, service
//! entries with their declared hosts, and workload addresses) plus their
//! declared ports. At request time the plugin reads the destination Host
//! header and rejects unknown destinations with 502 (configurable).
//!
//! The plugin is **not** registered when policy is `AllowAny` (default),
//! so non-mesh and permissive deployments pay zero per-request cost.
//!
//! ## Destination resolution
//!
//! - HTTP family only: the gate relies on the `Host` header, so raw TCP/UDP
//!   outbound traffic bypasses this plugin entirely. Operators relying on
//!   REGISTRY_ONLY for stream-protocol egress need additional controls
//!   (capture exclusions, ServiceEntry materialization).
//! - `Host` header is split into `host` and optional `:port`. The matcher
//!   checks both `host` and `host:port` against the registry so operators
//!   can register either form.
//! - Mesh-internal service-cluster-local hostnames are matched as-is; the
//!   registry-build helper records the short, namespace-qualified, `.svc`,
//!   and FQDN forms.
//! - Wildcard ServiceEntry hosts (`*.example.com`) match one DNS label below
//!   the suffix, consistent with Ferrum's host wildcard semantics.
//! - An empty registry is valid and fails closed: every request is rejected,
//!   but the plugin remains installed so REGISTRY_ONLY never silently falls
//!   back to ALLOW_ANY.
//! - Auto-injected mesh instances are scoped to the outbound capture listener
//!   port, so inbound sidecar/ambient traffic is not gated by an outbound
//!   policy. Operator-managed instances without `outbound_listen_ports`
//!   preserve the historical behavior and enforce wherever the plugin runs.
//!
//! ## Wire compatibility
//!
//! Registry is shipped as a serde `Vec<String>` in plugin config. Order is
//! stable (alphabetical) to keep `MeshSlice::content_eq` deterministic
//! across reloads.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, priority,
};

thread_local! {
    /// Scratch buffer for normalised host lookups. Reused across requests on
    /// the same worker thread so the steady-state hot path performs zero
    /// allocations for the contains() check. Sized for typical
    /// `service.namespace.svc.cluster.local:65535` lengths (~80 bytes).
    static HOST_NORMALISE_BUF: RefCell<String> = RefCell::new(String::with_capacity(96));
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutboundRegistryConfig {
    /// Operator-supplied list of known destinations. Each entry is either
    /// a bare hostname (`reviews.default.svc.cluster.local`) or a
    /// `host:port` pair. Matches are exact after ASCII-lowercase
    /// normalisation.
    #[serde(default)]
    pub registry: Vec<String>,
    /// Status code returned when a request's destination is not in the
    /// registry. Defaults to 502 (Bad Gateway). Operators may override
    /// to 404 when they prefer to mask unknown destinations.
    #[serde(default = "default_reject_status")]
    pub reject_status: u16,
    /// Optional frontend listener ports where the registry should be enforced.
    /// Mesh auto-injection sets this to the outbound capture listener port so
    /// the global plugin does not apply to inbound listeners. Empty keeps
    /// operator-managed plugin instances backwards compatible and enforces on
    /// every HTTP-family request that reaches this plugin.
    #[serde(default)]
    pub outbound_listen_ports: Vec<u16>,
}

fn default_reject_status() -> u16 {
    502
}

#[derive(Debug)]
pub struct OutboundRegistry {
    /// Bare-hostname entries from the operator-supplied registry, normalised
    /// to ASCII-lowercase at construction. A request matches if its Host
    /// header (port stripped) is present here, regardless of port.
    hosts: HashSet<String>,
    /// `host:port` entries from the operator-supplied registry. A request
    /// matches only when its Host header carries the same `host:port` pair.
    /// Stored separately from `hosts` so the request hot path can perform
    /// two zero-allocation `contains` lookups instead of building a single
    /// formatted key per request.
    host_ports: HashSet<String>,
    /// Suffixes from wildcard host entries such as `*.example.com`.
    wildcard_suffixes: Vec<String>,
    /// Port-specific wildcard host suffixes from entries like
    /// `*.example.com:443`.
    wildcard_port_suffixes: HashMap<u16, Vec<String>>,
    outbound_listen_ports: Vec<u16>,
    reject_status: u16,
}

impl OutboundRegistry {
    pub fn new(config: &Value) -> Result<Self, String> {
        let parsed: OutboundRegistryConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("mesh_outbound_registry: {e}"))?;
        if !(400..=599).contains(&parsed.reject_status) {
            return Err(format!(
                "mesh_outbound_registry: reject_status must be 4xx/5xx (got {})",
                parsed.reject_status
            ));
        }
        let mut hosts: HashSet<String> = HashSet::with_capacity(parsed.registry.len());
        let mut host_ports: HashSet<String> = HashSet::new();
        let mut wildcard_suffixes: Vec<String> = Vec::new();
        let mut wildcard_port_suffixes: HashMap<u16, Vec<String>> = HashMap::new();
        for entry in parsed.registry {
            let Some(normalised) = normalise_registry_entry(&entry) else {
                continue;
            };
            if let Some((host, port)) = split_registry_host_port(&normalised) {
                if let Some(suffix) = wildcard_suffix(host) {
                    wildcard_port_suffixes
                        .entry(port)
                        .or_default()
                        .push(suffix.to_string());
                } else {
                    host_ports.insert(format!("{host}:{port}"));
                }
            } else if let Some(suffix) = wildcard_suffix(&normalised) {
                wildcard_suffixes.push(suffix.to_string());
            } else {
                hosts.insert(normalised);
            }
        }
        wildcard_suffixes.sort();
        wildcard_suffixes.dedup();
        for suffixes in wildcard_port_suffixes.values_mut() {
            suffixes.sort();
            suffixes.dedup();
        }
        let mut outbound_listen_ports = parsed.outbound_listen_ports;
        outbound_listen_ports.retain(|port| *port != 0);
        outbound_listen_ports.sort_unstable();
        outbound_listen_ports.dedup();
        Ok(Self {
            hosts,
            host_ports,
            wildcard_suffixes,
            wildcard_port_suffixes,
            outbound_listen_ports,
            reject_status: parsed.reject_status,
        })
    }

    #[allow(dead_code)]
    pub fn registry_size(&self) -> usize {
        self.hosts.len()
            + self.host_ports.len()
            + self.wildcard_suffixes.len()
            + self
                .wildcard_port_suffixes
                .values()
                .map(Vec::len)
                .sum::<usize>()
    }

    /// Per-request hot-path lookup. Uses a thread-local scratch `String` so
    /// the steady-state cost is two `HashSet::contains` reads plus an
    /// in-place lowercase copy (no heap allocation after the first call on
    /// each worker thread).
    fn contains(&self, host: &str, port: Option<u16>) -> bool {
        HOST_NORMALISE_BUF.with(|cell| {
            let mut buf = cell.borrow_mut();
            buf.clear();
            buf.reserve(host.len() + 6); // host + ':' + up to 5-digit port
            normalise_request_host_into(host, &mut buf);
            if buf.is_empty() {
                return false;
            }
            if self.hosts.contains(buf.as_str()) {
                return true;
            }
            if wildcard_suffix_matches_any(buf.as_str(), &self.wildcard_suffixes) {
                return true;
            }
            let Some(port) = port else {
                return false;
            };
            if self
                .wildcard_port_suffixes
                .get(&port)
                .is_some_and(|suffixes| wildcard_suffix_matches_any(buf.as_str(), suffixes))
            {
                return true;
            }
            // Empty `host_ports` is common (operators register bare hosts
            // most often). Skip the format!-equivalent write entirely.
            if self.host_ports.is_empty() {
                return false;
            }
            // Reuse the same scratch buffer to append `:port` — no second
            // allocation. `write!` into `String` is infallible.
            let _ = write!(buf, ":{port}");
            self.host_ports.contains(buf.as_str())
        })
    }

    #[inline]
    fn should_enforce_for_request(&self, ctx: &RequestContext) -> bool {
        self.outbound_listen_ports.is_empty()
            || ctx
                .frontend_listen_port
                .is_some_and(|port| self.outbound_listen_ports.binary_search(&port).is_ok())
    }
}

fn normalise_registry_entry(entry: &str) -> Option<String> {
    let entry = entry.trim().to_ascii_lowercase();
    if entry.is_empty() {
        return None;
    }
    if let Some((host, port)) = split_registry_host_port(&entry) {
        return normalise_host_part(host).map(|host| format!("{host}:{port}"));
    }
    normalise_host_part(&entry)
}

fn normalise_host_part(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    if host.starts_with('[') {
        if host.ends_with(']')
            && let Ok(IpAddr::V6(addr)) = host[1..host.len() - 1].parse::<IpAddr>()
        {
            return Some(format!("[{addr}]"));
        }
        return Some(host.to_string());
    }
    if let Ok(IpAddr::V6(addr)) = host.parse::<IpAddr>() {
        return Some(format!("[{addr}]"));
    }
    Some(host.to_string())
}

fn normalise_request_host_into(host: &str, buf: &mut String) {
    let host = host.trim();
    let host = if host.starts_with('[') {
        host
    } else {
        host.trim_end_matches('.')
    };
    if host.starts_with('[')
        && host.ends_with(']')
        && let Ok(IpAddr::V6(addr)) = host[1..host.len() - 1].parse::<IpAddr>()
    {
        let _ = write!(buf, "[{addr}]");
        return;
    }
    for byte in host.bytes() {
        buf.push(byte.to_ascii_lowercase() as char);
    }
}

fn wildcard_suffix(host: &str) -> Option<&str> {
    let suffix = host.strip_prefix("*.")?;
    if suffix.is_empty() || suffix.contains('*') {
        return None;
    }
    Some(suffix)
}

fn wildcard_suffix_matches_any(host: &str, suffixes: &[String]) -> bool {
    suffixes
        .iter()
        .any(|suffix| single_label_wildcard_suffix_matches(host, suffix))
}

fn single_label_wildcard_suffix_matches(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return false;
    }
    let Some(prefix) = host.strip_suffix(suffix) else {
        return false;
    };
    prefix.ends_with('.')
        && !prefix[..prefix.len() - 1].is_empty()
        && !prefix[..prefix.len() - 1].contains('.')
}

fn split_registry_host_port(entry: &str) -> Option<(&str, u16)> {
    if entry.starts_with('[') {
        let end = entry.rfind("]:")?;
        let port = entry[end + 2..].parse::<u16>().ok()?;
        return Some((&entry[..end + 1], port));
    }
    let (host, port_str) = entry.rsplit_once(':')?;
    if host.contains(':') {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
    Some((host, port))
}

/// Classify a normalised registry entry as a `host:port` pair (port is a
/// 1-5 digit u16 suffix after a final `:`) or a bare hostname.
#[cfg(test)]
fn is_host_port_entry(entry: &str) -> bool {
    split_registry_host_port(entry).is_some()
}

#[async_trait]
impl Plugin for OutboundRegistry {
    fn name(&self) -> &str {
        "mesh_outbound_registry"
    }

    fn priority(&self) -> u16 {
        priority::MESH_OUTBOUND_REGISTRY
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        // Host-header gating only applies to HTTP-family traffic. Raw
        // TCP/UDP stream proxies have no Host header; mesh-level egress
        // scoping for those protocols is enforced at the connect stage via
        // SNI / destination IP (handled elsewhere by the mesh authz
        // pipeline), not by this plugin.
        HTTP_FAMILY_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if !self.should_enforce_for_request(ctx) {
            return PluginResult::Continue;
        }
        let Some(host_header) = ctx.headers.get("host") else {
            return reject(self.reject_status, "host header required");
        };
        let (host, port) = split_host_header(host_header);
        if !self.contains(host, port) {
            return reject(
                self.reject_status,
                "destination not in mesh registry (REGISTRY_ONLY policy)",
            );
        }
        PluginResult::Continue
    }
}

fn split_host_header(value: &str) -> (&str, Option<u16>) {
    // IPv6-bracketed literals: `[::1]:8080` — split on `]:`.
    if value.starts_with('[')
        && let Some(end) = value.rfind("]:")
    {
        let host = &value[..end + 1];
        let port = value[end + 2..].parse::<u16>().ok();
        return (host, port);
    }
    if let Some((host, port_str)) = value.rsplit_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        return (host, Some(port));
    }
    (value, None)
}

fn reject(status: u16, message: &str) -> PluginResult {
    PluginResult::Reject {
        status_code: status,
        body: format!("{{\"error\":\"{message}\"}}"),
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn registry_plugin(entries: &[&str]) -> OutboundRegistry {
        registry_plugin_with_ports(entries, &[])
    }

    fn registry_plugin_with_ports(
        entries: &[&str],
        outbound_listen_ports: &[u16],
    ) -> OutboundRegistry {
        let config = json!({
            "registry": entries,
            "outbound_listen_ports": outbound_listen_ports,
        });
        OutboundRegistry::new(&config).expect("valid registry")
    }

    #[test]
    fn empty_registry_matches_nothing() {
        let plugin = registry_plugin(&[]);
        assert_eq!(plugin.registry_size(), 0);
        assert!(!plugin.contains("reviews.svc", None));
        assert!(!plugin.contains("reviews.svc", Some(8080)));
    }

    #[test]
    fn rejects_invalid_status() {
        let err = OutboundRegistry::new(&json!({"registry": ["a.svc"], "reject_status": 200}))
            .unwrap_err();
        assert!(err.contains("reject_status"), "got: {err}");
    }

    #[test]
    fn host_only_match() {
        let plugin = registry_plugin(&["reviews.default.svc.cluster.local"]);
        assert!(plugin.contains("reviews.default.svc.cluster.local", None));
        assert!(plugin.contains("reviews.default.svc.cluster.local", Some(8080)));
        assert!(!plugin.contains("ratings.default.svc.cluster.local", None));
    }

    #[test]
    fn host_port_match_is_specific() {
        let plugin = registry_plugin(&["reviews.svc:8080"]);
        assert!(plugin.contains("reviews.svc", Some(8080)));
        // Bare host not present; falls through.
        assert!(!plugin.contains("reviews.svc", None));
        assert!(!plugin.contains("reviews.svc", Some(9090)));
    }

    #[test]
    fn case_insensitive_match() {
        let plugin = registry_plugin(&["Reviews.Default.Svc.Cluster.Local"]);
        assert!(plugin.contains("reviews.default.svc.cluster.local", None));
        assert!(plugin.contains("REVIEWS.DEFAULT.SVC.CLUSTER.LOCAL", None));
    }

    #[test]
    fn trailing_dot_match() {
        let plugin = registry_plugin(&["Reviews.Default.Svc.Cluster.Local."]);
        assert!(plugin.contains("reviews.default.svc.cluster.local", None));
        assert!(plugin.contains("reviews.default.svc.cluster.local.", Some(8080)));
    }

    #[test]
    fn wildcard_host_matches_one_label() {
        let plugin = registry_plugin(&["*.example.com"]);
        assert!(plugin.contains("api.example.com", None));
        assert!(plugin.contains("API.EXAMPLE.COM.", Some(443)));
        assert!(!plugin.contains("example.com", None));
        assert!(!plugin.contains("a.b.example.com", None));
    }

    #[test]
    fn wildcard_host_port_is_specific() {
        let plugin = registry_plugin(&["*.example.com:443"]);
        assert!(plugin.contains("api.example.com", Some(443)));
        assert!(!plugin.contains("api.example.com", None));
        assert!(!plugin.contains("api.example.com", Some(80)));
        assert!(!plugin.contains("a.b.example.com", Some(443)));
    }

    #[test]
    fn unbracketed_ipv6_registry_entry_is_canonicalized() {
        let plugin = registry_plugin(&["2001:db8::1"]);
        assert!(plugin.contains("[2001:db8::1]", None));
        assert!(plugin.contains("[2001:0DB8::1]", None));
        assert!(plugin.contains("[2001:db8::1]", Some(8080)));
        assert!(!is_host_port_entry("2001:db8::1"));
    }

    #[test]
    fn host_header_split_strips_port() {
        let (host, port) = split_host_header("reviews.svc:9090");
        assert_eq!(host, "reviews.svc");
        assert_eq!(port, Some(9090));
    }

    #[test]
    fn host_header_split_no_port() {
        let (host, port) = split_host_header("reviews.svc");
        assert_eq!(host, "reviews.svc");
        assert_eq!(port, None);
    }

    #[test]
    fn host_header_ipv6_split() {
        let (host, port) = split_host_header("[::1]:8080");
        assert_eq!(host, "[::1]");
        assert_eq!(port, Some(8080));
    }

    #[tokio::test]
    async fn rejects_unknown_destination() {
        let plugin = registry_plugin(&["reviews.svc"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let headers = HashMap::from([("host".to_string(), "evil.external.com:443".to_string())]);
        ctx.headers = headers;
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn scoped_plugin_skips_non_outbound_listener() {
        let plugin = registry_plugin_with_ports(&["reviews.svc"], &[15001]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.frontend_listen_port = Some(15006);
        ctx.headers = HashMap::from([("host".to_string(), "unknown.example.com".to_string())]);

        let result = plugin.on_request_received(&mut ctx).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    #[tokio::test]
    async fn scoped_plugin_enforces_outbound_listener() {
        let plugin = registry_plugin_with_ports(&["reviews.svc"], &[15001]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.frontend_listen_port = Some(15001);
        ctx.headers = HashMap::from([("host".to_string(), "unknown.example.com".to_string())]);

        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn unscoped_plugin_enforces_without_frontend_port() {
        let plugin = registry_plugin(&["reviews.svc"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.headers = HashMap::from([("host".to_string(), "unknown.example.com".to_string())]);

        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn passes_known_destination() {
        let plugin = registry_plugin(&["reviews.svc"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let headers = HashMap::from([("host".to_string(), "reviews.svc:9090".to_string())]);
        ctx.headers = headers;
        let result = plugin.on_request_received(&mut ctx).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    #[tokio::test]
    async fn rejects_missing_host_header() {
        let plugin = registry_plugin(&["reviews.svc"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[test]
    fn classify_host_port_vs_bare_host() {
        assert!(is_host_port_entry("reviews.svc:8080"));
        assert!(is_host_port_entry("api.example.com:443"));
        assert!(!is_host_port_entry("reviews.svc"));
        assert!(!is_host_port_entry("api.example.com"));
        // Trailing colon without digits → not a host:port pair.
        assert!(!is_host_port_entry("reviews.svc:"));
        // Non-numeric port → not a host:port pair.
        assert!(!is_host_port_entry("reviews.svc:http"));
        // u16 boundary: 65535 OK, 65536 must be rejected.
        assert!(is_host_port_entry("svc:65535"));
        assert!(!is_host_port_entry("svc:65536"));
        // Bracketed IPv6 literals.
        assert!(is_host_port_entry("[::1]:8080"));
        assert!(!is_host_port_entry("[::1]"));
        assert!(!is_host_port_entry("2001:db8::1"));
    }

    #[test]
    fn registry_with_only_whitespace_entries_matches_nothing() {
        // After trim+lowercase normalisation every entry is empty — the
        // plugin stays installed and rejects every destination.
        let plugin = OutboundRegistry::new(&json!({"registry": ["", "  ", "\t"]}))
            .expect("empty effective registry is valid");
        assert_eq!(plugin.registry_size(), 0);
        assert!(!plugin.contains("reviews.svc", Some(8080)));
    }

    #[test]
    fn supported_protocols_excludes_raw_streams() {
        let plugin = registry_plugin(&["reviews.svc"]);
        let protocols = plugin.supported_protocols();
        // Host-header gating is HTTP-family only.
        assert!(protocols.contains(&ProxyProtocol::Http));
        assert!(protocols.contains(&ProxyProtocol::Grpc));
        assert!(protocols.contains(&ProxyProtocol::WebSocket));
        assert!(!protocols.contains(&ProxyProtocol::Tcp));
        assert!(!protocols.contains(&ProxyProtocol::Udp));
    }

    #[test]
    fn registry_size_reflects_dual_buckets() {
        // Mixed bare-host + host:port entries are placed into separate
        // buckets internally; `registry_size()` reports the sum.
        let plugin = registry_plugin(&[
            "reviews.svc",
            "reviews.svc:8080",
            "api:443",
            "*.example.com",
            "*.example.com:443",
        ]);
        assert_eq!(plugin.registry_size(), 5);
    }

    #[test]
    fn lookup_avoids_alloc_on_already_lowercase_host() {
        // Smoke test the hot-path lookup with both buckets populated. The
        // important invariant is that bare-host registration matches any
        // port (Istio REGISTRY_ONLY semantics) while host:port registration
        // only matches the exact port.
        let plugin = registry_plugin(&["reviews.svc", "tightly-bound:8080"]);
        // Bare-host wildcards over port.
        assert!(plugin.contains("reviews.svc", None));
        assert!(plugin.contains("reviews.svc", Some(80)));
        assert!(plugin.contains("reviews.svc", Some(65535)));
        // host:port is exact.
        assert!(plugin.contains("tightly-bound", Some(8080)));
        assert!(!plugin.contains("tightly-bound", Some(8081)));
        assert!(!plugin.contains("tightly-bound", None));
    }

    #[tokio::test]
    async fn empty_host_header_rejected() {
        // RFC 9110 §7.2 requires Host be non-empty; defensive coverage in
        // case an upstream pre-processor leaves a blank `host: ` line.
        let plugin = registry_plugin(&["reviews.svc"]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.headers = HashMap::from([("host".to_string(), String::new())]);
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn empty_registry_rejects_all_requests() {
        let plugin = registry_plugin(&[]);
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.headers = HashMap::from([("host".to_string(), "reviews.svc".to_string())]);
        let result = plugin.on_request_received(&mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
            other => panic!("expected reject, got {:?}", other),
        }
    }
}
