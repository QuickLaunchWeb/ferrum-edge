use std::net::SocketAddr;

use tracing::warn;

use crate::dns::DnsCache;

/// Resolve `host:port` to a `SocketAddr` via the gateway's shared `DnsCache`,
/// falling back to the OS resolver only when the cache is unavailable or
/// returns an error. Mirrors `resolve_udp_endpoint` for plugins that open
/// their own TCP connections (log shippers, side-channel clients).
///
/// Plugins that hold this cache via `PluginHttpClient::dns_cache()` should
/// pass it in; the rare `None` case (test fallback) silently uses
/// `tokio::net::lookup_host`.
pub async fn resolve_tcp_endpoint(
    host: &str,
    port: u16,
    dns_cache: Option<&DnsCache>,
    plugin_name: &'static str,
) -> Result<SocketAddr, String> {
    if let Some(cache) = dns_cache {
        match cache.resolve(host, None, None).await {
            Ok(ip) => return Ok(SocketAddr::new(ip, port)),
            Err(error) => {
                warn!(
                    "{plugin_name}: DNS cache resolution failed for '{host}': {error} — falling back to system DNS"
                );
            }
        }
    }

    let addr = format!("{host}:{port}");
    tokio::net::lookup_host(&addr)
        .await
        .map_err(|error| format!("{plugin_name}: DNS resolution failed for {addr}: {error}"))?
        .next()
        .ok_or_else(|| format!("{plugin_name}: no addresses resolved for {addr}"))
}
