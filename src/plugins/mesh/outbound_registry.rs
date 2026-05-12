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
//!   registry-build helper records the FQDN.
//! - Wildcard ServiceEntry hosts (`*.example.com`) are currently inserted
//!   verbatim into the registry, so an exact-match request to
//!   `client.example.com` does NOT match a wildcard registration. Suffix
//!   matching is a tracked follow-up; until then operators with wildcard
//!   ServiceEntry hosts should register the concrete hosts they expect.
//!
//! ## Wire compatibility
//!
//! Registry is shipped as a serde `Vec<String>` in plugin config. Order is
//! stable (alphabetical) to keep `MeshSlice::content_eq` deterministic
//! across reloads.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

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
    reject_status: u16,
}

impl OutboundRegistry {
    pub fn new(config: &Value) -> Result<Self, String> {
        let parsed: OutboundRegistryConfig = serde_json::from_value(config.clone())
            .map_err(|e| format!("mesh_outbound_registry: {e}"))?;
        if parsed.registry.is_empty() {
            return Err(
                "mesh_outbound_registry: registry must not be empty (use AllowAny policy to \
                 disable the gate)"
                    .to_string(),
            );
        }
        if !(400..=599).contains(&parsed.reject_status) {
            return Err(format!(
                "mesh_outbound_registry: reject_status must be 4xx/5xx (got {})",
                parsed.reject_status
            ));
        }
        let mut hosts: HashSet<String> = HashSet::with_capacity(parsed.registry.len());
        let mut host_ports: HashSet<String> = HashSet::new();
        for entry in parsed.registry {
            let normalised = entry.trim().to_ascii_lowercase();
            if normalised.is_empty() {
                continue;
            }
            if is_host_port_entry(&normalised) {
                host_ports.insert(normalised);
            } else {
                hosts.insert(normalised);
            }
        }
        if hosts.is_empty() && host_ports.is_empty() {
            return Err(
                "mesh_outbound_registry: registry must contain at least one non-empty entry"
                    .to_string(),
            );
        }
        Ok(Self {
            hosts,
            host_ports,
            reject_status: parsed.reject_status,
        })
    }

    #[allow(dead_code)]
    pub fn registry_size(&self) -> usize {
        self.hosts.len() + self.host_ports.len()
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
            for byte in host.bytes() {
                buf.push(byte.to_ascii_lowercase() as char);
            }
            if self.hosts.contains(buf.as_str()) {
                return true;
            }
            let Some(port) = port else {
                return false;
            };
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
}

/// Classify a normalised registry entry as a `host:port` pair (port is a
/// 1-5 digit u16 suffix after a final `:`) or a bare hostname. IPv6
/// literals registered without brackets would tickle this heuristic, but
/// the canonical Host-header form is bracketed (`[::1]:8080`) and the
/// `build_known_destinations` helper never emits unbracketed IPv6.
fn is_host_port_entry(entry: &str) -> bool {
    // Bracketed IPv6 literal: `[::1]` (no port) — not a host:port pair.
    // `[::1]:8080` — *is* a host:port pair, distinguished by `]:` suffix.
    if entry.starts_with('[') {
        return entry.rsplit_once("]:").is_some_and(|(_, p)| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
        });
    }
    entry.rsplit_once(':').is_some_and(|(_, p)| {
        !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
    })
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
        let config = json!({
            "registry": entries,
        });
        OutboundRegistry::new(&config).expect("valid registry")
    }

    #[test]
    fn empty_registry_rejected() {
        let err = OutboundRegistry::new(&json!({"registry": []})).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
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
    }

    #[test]
    fn registry_with_only_whitespace_entries_rejected() {
        // After trim+lowercase normalisation every entry is empty — the
        // construct should refuse instead of silently accepting an
        // unreachable plugin.
        let err = OutboundRegistry::new(&json!({"registry": ["", "  ", "\t"]})).unwrap_err();
        assert!(
            err.contains("at least one non-empty"),
            "expected non-empty error, got: {err}"
        );
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
        let plugin = registry_plugin(&["reviews.svc", "reviews.svc:8080", "api:443"]);
        assert_eq!(plugin.registry_size(), 3);
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
}
