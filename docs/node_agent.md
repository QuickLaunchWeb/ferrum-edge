# Node Agent Capture Contract

`FERRUM_MODE=node_agent` runs the per-node capture manager separately from mesh proxy mode. It owns only capture enrollment, eBPF map programming, and the narrow IPC surface described here; it does not merge policy evaluation or proxy dispatch into the node-agent process.

## Contract Surface

`CaptureContract` formalizes the node-agent to proxy boundary:

| Surface | Name / default | Purpose |
|---|---|---|
| Proxy mode | `FERRUM_NODE_AGENT_PROXY_MODE=local_pod` | Selects the capture topology. `local_pod` redirects to the co-located pod proxy. `node_waypoint` reserves the Phase 2 node-waypoint topology surface. |
| Admin listener | `FERRUM_NODE_AGENT_ADMIN_ENABLED=false` | Opts in to the read-only admin listener for node-agent metrics/health. When enabled, `FERRUM_ADMIN_HTTP_PORT` controls the port and the listener defaults to loopback unless `FERRUM_ADMIN_BIND_ADDRESS` or `FERRUM_ADMIN_ALLOWED_CIDRS` is set. |
| Outbound capture port | `15001` | The port written into the BPF capture config map and used by cgroup connect hooks when rewriting outbound sockets. |
| HBONE redirect port | `FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT=15008` | The HBONE listener/redirect port carried in the same BPF config map for sidecarless topologies. Must match the mesh proxy HBONE listener (`15008` today). Node-agent startup automatically adds this port to outbound capture exclusions. |
| Unix socket | `/run/ferrum/node-agent.sock` | Reserved IPC path for future node-agent/proxy coordination. Phase 1 treats this as inert contract metadata; no socket is created yet. |
| BPF config map | `FERRUM_CAPTURE_CONFIG` | Singleton map keyed by `0`, containing outbound capture and HBONE redirect ports. |
| BPF pod map | `FERRUM_POD_IPS` | Pod IP to proxy-port metadata for enrolled workloads. |
| BPF original destination maps | `FERRUM_ORIG_DST4`, `FERRUM_ORIG_DST6` | Socket-cookie keyed original destination records consumed by the proxy. |
| BPF capture filters | `FERRUM_BYPASS_UIDS`, `FERRUM_CIDR_*`, `FERRUM_PORT_EXCLUDE` | UID, CIDR, and port exclusions applied before outbound rewrite. |

The eBPF connect programs read `FERRUM_CAPTURE_CONFIG` before rewriting to loopback. If the singleton config entry is absent, they fall back to ABI defaults so older loaders fail open to the historical `15001` behavior.

## Metrics

When node-agent mode starts its admin listener, `/metrics` includes:

| Metric | Meaning |
|---|---|
| `ferrum_node_agent_pods_enrolled_total` | Pods successfully enrolled for capture. |
| `ferrum_node_agent_pods_unenrolled_total` | Pods unenrolled due to deletion, label changes, or shutdown. |
| `ferrum_node_agent_attach_errors_total` | BPF attachment or map update failures. |

The node agent starts the read-only admin HTTP listener on `FERRUM_ADMIN_HTTP_PORT` unless that port is set to `0`. Node-agent mode does not start an HTTPS admin listener yet, even when `FERRUM_ADMIN_HTTPS_PORT` is set.

`/metrics` is unauthenticated, matching the rest of Ferrum's Prometheus surface. To prevent an opt-in to `FERRUM_NODE_AGENT_ADMIN_ENABLED=true` from accidentally exposing unauthenticated `/metrics` and `/health` to the network, the node-agent admin listener defaults to loopback (`127.0.0.1`) when **none** of the following operator signals are configured:

- `FERRUM_ADMIN_BIND_ADDRESS` is set explicitly (any value, including `0.0.0.0` if intentional), or
- `FERRUM_ADMIN_ALLOWED_CIDRS` is set to a non-empty allowlist.

`FERRUM_ADMIN_JWT_SECRET` does not affect the bind address because `/metrics` and `/health` remain unauthenticated. If either bind signal is set, the configured `FERRUM_ADMIN_BIND_ADDRESS` (default `0.0.0.0`) is honored as-is. When the loopback fallback engages, the gateway emits a `warn!` at startup pointing at the two escape hatches. For node-agent deployments scraped over the cluster network, prefer either an explicit `FERRUM_ADMIN_ALLOWED_CIDRS` allowlist or front the listener with a local sidecar scraper bound to loopback.
