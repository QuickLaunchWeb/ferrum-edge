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
| BPF original destination maps | `FERRUM_ORIG_DST4`, `FERRUM_ORIG_DST6` | Socket-cookie keyed original destination records consumed by the proxy. Node-waypoint records include pod UID and workload SPIFFE hash and must be keyed by the proxy accept-side socket cookie. |
| BPF capture filters | `FERRUM_BYPASS_UIDS`, `FERRUM_CIDR_*`, `FERRUM_PORT_EXCLUDE` | UID, CIDR, and port exclusions applied before outbound rewrite. |

The eBPF connect programs read `FERRUM_CAPTURE_CONFIG` before rewriting to loopback. If the singleton config entry is absent, they fall back to ABI defaults so older loaders fail open to the historical `15001` behavior.

## Pod Lifecycle Events

The node-agent watches pods on the local node via kube-rs (`spec.nodeName={node_name}` field selector) and reacts to three Kubernetes event flavors. `Event::Apply` from the watcher conflates "added" and "modified", so the same code path handles initial enrollment and mid-life updates.

| Event | Source trigger | Node-agent action |
|---|---|---|
| Initial `Apply` for a previously-unseen pod | Pod creation | Resolve cgroup path, attach `connect4`/`connect6`/`getpeername4`/`getpeername6` programs, write `FERRUM_POD_IPS`, write `FERRUM_INCLUDE_PORTS` if the pod carries `includeOutboundPorts`. Counts toward `ferrum_node_agent_pods_enrolled_total`. |
| Subsequent `Apply` for an already-tracked pod | Pod metadata, label, or annotation update; status/condition change; container restart | Re-evaluate enrollment criteria (opt-in/opt-out labels and annotations), reconcile pod IP, **diff the parsed `includeOutboundPorts` policy** against the stashed baseline. Identical policy is a structural no-op (no BPF syscalls). A changed policy re-programs `FERRUM_INCLUDE_PORTS` for that pod's cgroup id; removed annotation drops the entry. Opt-in→opt-out flip triggers un-enrollment, opt-out→opt-in triggers enrollment. |
| `Delete` | Pod deletion | Detach BPF programs, remove `FERRUM_POD_IPS` and `FERRUM_INCLUDE_PORTS` entries. Counts toward `ferrum_node_agent_pods_unenrolled_total`. |

Mid-life update guarantees:

- **Diff-skip:** comparison is against the parsed, sorted, deduplicated `IncludePortsPolicy`, not the raw annotation string. Reordering ports in the annotation is a no-op. Modified events from unrelated pod activity (image pulls, status updates) cost only the diff compare.
- **Long-lived flows are unaffected:** the BPF gate runs on `connect(2)`, so a re-applied policy applies only to new outbound connections. Already-established TCP flows continue using the redirect chosen at their original connect — explicit application restart is required to force them through the new policy.
- **Best-effort:** annotation parse errors and BPF map write errors keep the previous policy in place rather than silently widening capture. They are recorded in `ferrum_node_agent_pod_annotation_updates_failed_total`. Cgroup-id-unavailable retries (the Pod object reached the watcher before kubelet finished creating the cgroup) are intentionally not counted there because they are routinely observed during early pod startup and are retried on the next Apply event.

## Metrics

When node-agent mode starts its admin listener, `/metrics` includes:

| Metric | Meaning |
|---|---|
| `ferrum_node_agent_pods_enrolled_total` | Pods successfully enrolled for capture. |
| `ferrum_node_agent_pods_unenrolled_total` | Pods unenrolled due to deletion, label changes, or shutdown. |
| `ferrum_node_agent_attach_errors_total` | BPF attachment or map update failures. |
| `ferrum_node_agent_pod_annotation_updates_applied_total` | Mid-life `includeOutboundPorts` annotation changes successfully re-applied to the BPF map (excludes initial enrollment, excludes diff-skipped Modified events). |
| `ferrum_node_agent_pod_annotation_updates_failed_total` | Mid-life `includeOutboundPorts` annotation changes that failed to re-apply (annotation parse error or BPF map write error). The pod retains its previous policy. Cgroup-id-unavailable retries (Pod object reached the watcher before kubelet finished creating the cgroup) are not counted here — they are retried on the next Apply event. |
| `ferrum_mesh_node_topology_degraded{reason}` | Gauge. `1` with `reason` ∈ {`kernel_too_old`,`cgroup_v1`,`bpffs_missing`} when the node fell back from eBPF capture to iptables. `0` with `reason="none"` when the eBPF capture path is nominal. Cardinality is bounded per node (a single series at a time). Set once at startup after the kernel probe runs — a kernel/cgroup/bpffs change requires restarting the node agent for the gauge to refresh. |

## Kernel Fallback

The node agent probes the kernel once at startup (see `KernelProbeResult::supports_ebpf`):

1. Linux kernel version >= 5.7 (required for cgroup_sockaddr BPF programs).
2. cgroup v2 mounted at `FERRUM_NODE_AGENT_CGROUP_ROOT` (default `/sys/fs/cgroup`).
3. bpffs mounted at `FERRUM_NODE_AGENT_BPF_FS_PATH` (default `/sys/fs/bpf`).

If any prerequisite is missing, the node agent does not crash by default. It logs ONE structured `warn!` with the first-failing prerequisite as `degradation_reason`, sets the `ferrum_mesh_node_topology_degraded{reason="<...>"}` gauge to `1`, and applies host-level iptables rules to keep the data plane serving while operators remediate. `FERRUM_NODE_AGENT_FALLBACK_MODE` controls the behaviour:

| Value | Behaviour |
|---|---|
| `iptables` (default) | Apply host iptables capture rules and continue serving. The gauge records the reason; pod-level eBPF enrollment is skipped. Existing pods that were enrolled before degradation keep working until the next reconcile; new pods rely on the iptables capture path. |
| `fail` | Refuse to start, surface the kernel deficiency in the error log, and exit. Use this when you want degraded nodes to fail their readiness probe instead of silently routing without eBPF telemetry. |

Suggested remediations by reason label:

| `reason` | Remediation |
|---|---|
| `kernel_too_old` | Upgrade the node to a kernel >= 5.7. Most modern distributions (RHEL 9 / Ubuntu 22.04 / Debian 12 / Amazon Linux 2023) already satisfy this. |
| `cgroup_v1` | Mount the unified cgroup v2 hierarchy (`systemd.unified_cgroup_hierarchy=1` on systemd hosts). cgroup_sockaddr BPF programs require cgroup v2 and cannot attach to the v1 hierarchy. |
| `bpffs_missing` | Mount `bpffs` at the configured `FERRUM_NODE_AGENT_BPF_FS_PATH`: `mount -t bpf bpffs /sys/fs/bpf`. The DaemonSet manifest in `charts/ferrum-node-agent/` mounts this automatically when configured. |

### Mixed-kernel clusters

In a cluster with heterogeneous kernels, the recommended pattern is:

1. Deploy the node-agent DaemonSet to every node. Degraded nodes fall back to iptables capture for whole-host traffic and the gauge identifies them.
2. Configure the admission webhook (`FERRUM_MODE=injector`) to inject iptables init containers for pods scheduled on degraded nodes. The injector decides this from a Helm-templated `NodeSelector` driven by your node labels (e.g., `ferrum.io/capture-mode=iptables`).
3. Alert on `ferrum_mesh_node_topology_degraded == 1` so the degraded set stays small while operators upgrade kernels. The gauge is unauthenticated (`/metrics` is unauthenticated), so the same allowlist guidance applies as for the rest of the node-agent admin surface.

The mesh control plane is not changed by node-level degradation: slice apply, `mesh_authz`, `mesh_workload_metrics`, and HBONE all continue to function as ambient. Only the per-pod capture mechanism on the affected node changes.

The node agent starts the read-only admin HTTP listener on `FERRUM_ADMIN_HTTP_PORT` unless that port is set to `0`. Node-agent mode does not start an HTTPS admin listener yet, even when `FERRUM_ADMIN_HTTPS_PORT` is set.

`/metrics` is unauthenticated, matching the rest of Ferrum's Prometheus surface. To prevent an opt-in to `FERRUM_NODE_AGENT_ADMIN_ENABLED=true` from accidentally exposing unauthenticated `/metrics` and `/health` to the network, the node-agent admin listener defaults to loopback (`127.0.0.1`) when **none** of the following operator signals are configured:

- `FERRUM_ADMIN_BIND_ADDRESS` is set explicitly (any value, including `0.0.0.0` if intentional), or
- `FERRUM_ADMIN_ALLOWED_CIDRS` is set to a non-empty allowlist.

`FERRUM_ADMIN_JWT_SECRET` does not affect the bind address because `/metrics` and `/health` remain unauthenticated. If either bind signal is set, the configured `FERRUM_ADMIN_BIND_ADDRESS` (default `0.0.0.0`) is honored as-is. When the loopback fallback engages, the gateway emits a `warn!` at startup pointing at the two escape hatches. For node-agent deployments scraped over the cluster network, prefer either an explicit `FERRUM_ADMIN_ALLOWED_CIDRS` allowlist or front the listener with a local sidecar scraper bound to loopback.
