# Mesh Mode

Ferrum Edge runs as a service mesh data plane when `FERRUM_MODE=mesh`. In this mode the gateway consumes mesh configuration from a Ferrum Control Plane (native `MeshSubscribe` gRPC) or a standard xDS ADS server, materializes SPIFFE-identity-aware proxies and authorization policies, and serves traffic with automatic mTLS, identity propagation, and Istio-compatible observability. The mesh subsystem deliberately reuses the existing proxy/plugin chain so all 58+ gateway plugins work unchanged in mesh context.

Concepts map directly to the Istio service mesh model: `Workload` corresponds to a pod or VM identity, `MeshPolicy` to `AuthorizationPolicy`, `PeerAuthentication` to per-port mTLS modes, `ServiceEntry` to external service registration, and `MeshRequestAuthentication` to `RequestAuthentication` JWT declarations. The Ferrum mesh layer adds multi-cluster east-west gateways, egress gateway materialization, a transparent DNS proxy for `ServiceEntry` resolution, and a Kubernetes sidecar injector.

## Topologies

Mesh mode supports four topologies selected by `FERRUM_MESH_TOPOLOGY`. Each topology determines which listeners are created and how traffic is handled.

### Sidecar

Per-pod sidecar proxy deployed alongside application containers. This is the default topology.

| Listener | Address | Direction | Kind |
|---|---|---|---|
| Outbound capture | `127.0.0.1:15001` | Outbound | Plaintext capture |
| Inbound mTLS | `0.0.0.0:15006` | Inbound | mTLS termination |

The outbound listener intercepts application-originated traffic (redirected by iptables or eBPF) and routes it to the appropriate upstream. The inbound listener terminates mTLS from peer sidecars and forwards plaintext to the local application.

### Ambient

Ztunnel-style ambient mesh proxy that terminates HBONE (HTTP/2 CONNECT over mTLS) traffic. Does not require a per-pod sidecar.

| Listener | Address | Direction | Kind |
|---|---|---|---|
| Outbound capture | `127.0.0.1:15001` | Outbound | Plaintext capture |
| HBONE | `0.0.0.0:15008` | Inbound | HBONE termination |

The HBONE listener accepts HTTP/2 CONNECT streams over mTLS on port 15008. Source identity is extracted from the mTLS peer certificate and optionally from W3C Baggage headers. See [HBONE Protocol](#hbone-protocol) below.

### East-West Gateway

Multi-cluster SNI-routed passthrough gateway. Does not create listeners directly; instead materializes passthrough TCP proxies from `MultiClusterConfig.east_west_gateways` entries.

All east-west traffic flows through a shared TCP passthrough listener on port 15443 (configurable via `FERRUM_MESH_EAST_WEST_LISTEN_PORT`). Routing is by TLS SNI hostname. The gateway does not terminate TLS -- it passes encrypted bytes directly to the backend cluster.

### Egress Gateway

Controlled egress proxy for mesh-to-external traffic. Materializes HTTP-family proxies from `ServiceEntry` resources with `location: mesh_external`.

| Listener | Address | Direction | Kind |
|---|---|---|---|
| mTLS inbound | `0.0.0.0:15090` | Inbound | mTLS termination |

Sidecars route external traffic to the egress gateway over mTLS. The gateway terminates mTLS, evaluates authorization policies, and forwards to the external backend. Requires frontend TLS certificates and a client CA for mTLS verification.

## Configuration Consumption

Mesh mode consumes configuration from a Control Plane via one of two protocols, selected by `FERRUM_MESH_CONFIG_PROTOCOL`.

### Native MeshSubscribe (default)

The Ferrum-native protocol uses the `MeshConfigSync.MeshSubscribe` gRPC streaming RPC defined in `proto/ferrum.proto`. The CP pushes complete `MeshSlice` JSON payloads whenever configuration changes. The mesh node sends its identity (node ID, namespace, SPIFFE ID, workload labels) in the subscribe request so the CP can filter resources by scope.

- **Multi-CP failover**: ordered list of CP URLs in `FERRUM_DP_CP_GRPC_URLS`. Jittered exponential backoff (1s initial, 30s max, +/-25% jitter) per URL. Primary retry interval configurable via `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`.
- **Authentication**: JWT HS256 in gRPC `authorization` metadata, using `FERRUM_CP_DP_GRPC_JWT_SECRET`.
- **Transport security**: same TLS configuration as CP/DP mode (see [cp_dp_mode.md](cp_dp_mode.md)).
- **No-op suppression**: `MeshSlice::content_eq()` skips updates that do not change mesh-relevant fields (ignoring the transport version stamp).

### xDS ADS

Standard Envoy xDS Aggregated Discovery Service client. Consumes CDS, EDS, LDS, RDS, and SDS resource types via state-of-the-world mode with incremental version tracking.

- **25ms debounce** on slice application to batch rapid resource updates.
- **Multi-CP failover**: same URL list and backoff as native mode.
- **Node identity**: `FERRUM_MESH_XDS_NODE_CLUSTER` sets the `node.cluster` field in DiscoveryRequest (defaults to `FERRUM_NAMESPACE`).
- **Connect timeout**: `FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS` (default 10).
- **DestinationRule limitation**: standard xDS bakes DestinationRule traffic policy (LB algorithm, outlier detection, connection pool, subsets) into the Envoy `Cluster` resource at the CP, so the original DR is not recoverable from CDS/EDS. Operators relying on Ferrum's DR translation must use `FERRUM_MESH_CONFIG_PROTOCOL=native`. The xDS consumer logs a warning at startup.

### Bootstrap Behavior

Both protocols share the same startup contract:

1. The mesh data plane waits for an initial valid slice before serving traffic.
2. Valid updates are applied atomically via `ArcSwap`.
3. Invalid updates are logged and ignored; the last accepted configuration continues serving.
4. On config source unavailability, the gateway keeps serving cached configuration (resilience principle).

## Mesh Data Model

The mesh data model lives in `src/modes/mesh/config.rs`. All types carry `namespace` for scope isolation and use `#[serde(default)]` so non-mesh `GatewayConfig` round-trips byte-identical.

### Workload

The unit of identity. Every SPIFFE SVID is issued to one workload.

```yaml
spiffe_id: "spiffe://cluster.local/ns/default/sa/my-service"
selector:
  labels:
    app: my-service
service_name: "my-service"
addresses: ["10.0.1.5"]
ports:
  - port: 8080
    protocol: http
    name: http
trust_domain: "cluster.local"
namespace: "default"
```

### MeshService

Logical service grouping workloads by SPIFFE ID reference.

```yaml
name: "my-service"
namespace: "default"
ports:
  - port: 8080
    protocol: http
workloads:
  - spiffe_id: "spiffe://cluster.local/ns/default/sa/my-service"
```

### MeshPolicy

Identity-based authorization policy (mirrors Istio `AuthorizationPolicy`).

```yaml
name: "deny-unauthenticated"
namespace: "default"
scope:
  kind: namespace
  namespace: "default"
rules:
  - from:
      - spiffe_id_pattern: "spiffe://cluster.local/ns/*/sa/*"
    to:
      - methods: ["GET", "POST"]
        paths: ["/api/*"]
    action: allow
```

### ServiceEntry

External service registration for DNS resolution and egress materialization.

```yaml
name: "external-api"
namespace: "default"
hosts: ["api.external.com"]
endpoints:
  - address: "203.0.113.10"
resolution: static
location: mesh_external
ports:
  - port: 443
    protocol: tls
export_to: ["*"]
```

### PeerAuthentication

Per-workload mTLS mode with optional per-port overrides.

### MeshRequestAuthentication

Declares valid JWTs for a workload scope. Permissive by default (see [RequestAuthentication](#requestauthentication)).

### MeshTelemetryResource

Per-scope telemetry configuration for tracing, metrics, and access logging (see [Observability](#observability)).

### MeshProxyConfig (Istio ProxyConfig)

Maps an Istio `ProxyConfig` (`networking.istio.io/v1beta1`) onto a config-time, read-only data structure consumed by the mesh runtime at slice-apply time. ProxyConfig has **no data-plane request-path impact** — it shapes startup posture (concurrency, image, environment variables) and tracing sampling.

```yaml
name: "api-defaults"
namespace: "default"
scope:                  # resolved from spec.selector + Istio root-namespace rule
  workload_selector:
    selector:
      labels: { app: "api" }
      namespace: "default"  # absent when the resource lives in the Istio root namespace
concurrency: 4          # spec.concurrency (informational; rejected if outside u32 range)
image: "distroless"     # spec.image.imageType (informational)
environment:            # spec.environmentVariables (informational)
  GOMAXPROCS: "4"
tracing_sampling: 42.5  # spec.tracing.sampling — percentage 0-100
```

**Honored fields**:

| Istio field | MeshProxyConfig field | Notes |
|---|---|---|
| `metadata.name` | `name` | |
| `metadata.namespace` | `namespace` | |
| `spec.selector` + root-namespace rule | `scope` ([`PolicyScope`](#policyscope)) | See "Scope resolution" below — same semantics as Telemetry / PeerAuthentication |
| `spec.concurrency` | `concurrency` | Informational; rejected as `InvalidResource` if it does not fit in `u32` |
| `spec.image.imageType` | `image` | Informational; surfaced to operator tooling |
| `spec.environmentVariables` | `environment` | Informational; surfaced to operator tooling |
| `spec.tracing.sampling` | `tracing_sampling` | Percentage 0-100; merged into the injected `workload_metrics` plugin's `sampling_percentage` |

**Scope resolution**: ProxyConfig honors the same Istio root-namespace + selector rules used by `Telemetry`, `RequestAuthentication`, and `PeerAuthentication`. The K8s translator routes through the shared `istio_policy_scope` helper, so [`scope`](../src/modes/mesh/config.rs) ends up as:

- `MeshWide` — resource in the Istio root namespace (`FERRUM_K8S_ISTIO_ROOT_NAMESPACE`, default `istio-system`) with no selector. Applies to every workload in the mesh.
- `WorkloadSelector { namespace: None, labels: ... }` — resource in the Istio root namespace with a selector. Applies to matching workloads across all namespaces.
- `Namespace { namespace }` — resource in any other namespace with no selector. Applies to all workloads in that namespace.
- `WorkloadSelector { namespace: Some(ns), labels: ... }` — resource in any other namespace with a selector. Applies to matching workloads in that namespace.

Within the resolved slice, [`MeshSlice::resolved_proxy_config()`](../src/modes/mesh/slice.rs) returns the most-specific applicable entry:

1. `WorkloadSelector` > `Namespace` > `MeshWide`.
2. Among same-tier matches, the ASCII-smallest `name` wins (deterministic tiebreaker mirroring the accumulator's `(namespace, name)` sort).

**`tracing.sampling` merge with `Telemetry`**: ProxyConfig `tracing_sampling` is applied first as a baseline, then `Telemetry.tracing.randomSamplingPercentage` overrides on the same `sampling_percentage` key when both are present. The more granular Telemetry API wins because it can be per-section scoped; ProxyConfig provides a per-workload-config-level default.

**xDS protocol**: ProxyConfig is config-time and not exposed via standard xDS. Operators relying on ProxyConfig translation must use `FERRUM_MESH_CONFIG_PROTOCOL=native`.

### TrustBundleSet

Local and federated X.509/JWT authority bundles for cross-cluster trust.

### MultiClusterConfig

Multi-cluster settings: local cluster identity, remote clusters, east-west gateways, and SPIFFE federation endpoints.

### MeshDestinationRule

Maps an Istio `DestinationRule` onto Ferrum's existing `Upstream` / `PassiveHealthCheck` / `LoadBalancerAlgorithm` primitives. Applied at slice-apply time in `prepare_normalized_gateway_config_for_mesh()` after upstream materialization.

```yaml
name: "reviews-policy"
namespace: "default"
host: "reviews.default.svc.cluster.local"
traffic_policy:
  connect_timeout_ms: 5000
  outlier_detection:
    consecutive_errors: 5
    interval_seconds: 10
    base_ejection_seconds: 30
    max_ejection_percent: 50
  load_balancer:
    consistent_hash:
      http_header_name: "x-user-id"
subsets:
  - name: "v1"
    labels:
      version: "v1"
```

**Host matching**: the DR `host` is matched against upstream targets, the upstream `name`, and the upstream `id`. Short hostnames are namespace-completed (`reviews` ⇒ `reviews.{namespace}.svc.*`); namespaced (`reviews.ns`) and `.svc`-suffixed forms are also supported. Cross-namespace matches require the FQDN form because slice filtering already restricts DRs to the subscriber's namespace.

**Multiple DRs targeting the same upstream**: applied in deterministic `(namespace, name)` order — the alphabetically last entry wins, last-writer-wins per field. Operators see `debug!` log lines when subsets or proxy `backend_connect_timeout_ms` get overwritten.

**Support matrix** (canonical Istio field → Ferrum target):

| Istio field | Status | Notes |
|---|---|---|
| `host` | Supported | Required, lowercased at admission, empty/dot-only rejected |
| `trafficPolicy.connectionPool.tcp.connectTimeout` | Supported | Applied to `Proxy.backend_connect_timeout_ms` for every proxy referencing the matching upstream |
| `trafficPolicy.outlierDetection.consecutive5xxErrors` / `consecutiveErrors` | Supported | → `PassiveHealthCheck.unhealthy_threshold` |
| `trafficPolicy.outlierDetection.interval` | Supported | → `PassiveHealthCheck.unhealthy_window_seconds` (zero filtered out, sub-second rounded up) |
| `trafficPolicy.outlierDetection.baseEjectionTime` | Supported | → `PassiveHealthCheck.healthy_after_seconds` |
| `trafficPolicy.outlierDetection.maxEjectionPercent` | Supported | → `PassiveHealthCheck.max_ejection_percent`; values >100 rejected |
| `trafficPolicy.loadBalancer.simple = ROUND_ROBIN` | Supported | → `LoadBalancerAlgorithm::RoundRobin` |
| `trafficPolicy.loadBalancer.simple = LEAST_REQUEST` / `LEAST_CONN` | Supported | → `LoadBalancerAlgorithm::LeastConnections` |
| `trafficPolicy.loadBalancer.simple = RANDOM` | Supported | → `LoadBalancerAlgorithm::Random` |
| `trafficPolicy.loadBalancer.simple = PASSTHROUGH` | Approximated (warns) | → `RoundRobin`; Ferrum cannot preserve the original destination IP |
| `trafficPolicy.loadBalancer.simple = MAGLEV` | Rejected | Hard error at translate time |
| `trafficPolicy.loadBalancer.consistentHash.{httpHeaderName,httpCookie.name,useSourceIp}` | Supported | Exactly one of the three required (rejected otherwise); → `LoadBalancerAlgorithm::ConsistentHashing` + `Upstream.hash_on` |
| `subsets[].name` / `subsets[].labels` | Supported | → `SubsetDefinition` entries on the upstream; second DR overwrites the first |
| `subsets[].trafficPolicy.loadBalancer` | Supported | → `SubsetTrafficPolicy.load_balancer_algorithm` |
| `subsets[].trafficPolicy.connectionPool` | Ignored (warns) | Top-level `trafficPolicy.connectionPool` is the only path to per-upstream connect timeout |
| `subsets[].trafficPolicy.outlierDetection` | Ignored (warns) | Top-level `trafficPolicy.outlierDetection` is the only path to passive health checks |
| `trafficPolicy.connectionPool.http.*` | Ignored | Per-protocol connection pool not surfaced |
| `trafficPolicy.connectionPool.tcp.maxConnections` / `tcpKeepalive` | Ignored | Pool sizing handled globally via `FERRUM_POOL_*` |
| `trafficPolicy.tls` | Supported | Overrides the `PeerAuthentication`-derived backend posture per matching `Upstream` when set. Mode mapping: `DISABLE` → clears `Upstream.backend_tls_*`; `SIMPLE` → enables server-cert verify + `backend_tls_server_ca_cert_path = caCertificates` (client cert/key cleared); `MUTUAL` → enables server-cert verify + projects `caCertificates`/`clientCertificate`/`privateKey` onto `Upstream.backend_tls_server_ca_cert_path`/`_client_cert_path`/`_client_key_path`; `ISTIO_MUTUAL` → enables server-cert verify and leaves any existing client material untouched (Ferrum's `spiffe_identity`/`mtls_auth` plugins continue to supply the workload SVID — DR.tls does not yet project SPIFFE material onto `Upstream.backend_tls_*` directly). `insecureSkipVerify: true` forces `backend_tls_verify_server_cert = false`. `sni` and `subjectAltNames` are parsed and warned (no per-`Upstream` SNI/SAN override field today). When the field is unset, behavior is identical to today and `PeerAuthentication` continues to drive the default mTLS posture. |
| `trafficPolicy.portLevelSettings[].port.number` + nested `connectionPool.tcp.connectTimeout` | Supported | Top-level policy applies first; per-port `connectTimeout` lands on `Upstream.port_overrides[port].connect_timeout_ms` at apply time, then `GatewayConfig::resolve_dispatch_port_overrides()` projects it onto `Proxy.dispatch_port_overrides` for O(1) hot-path lookup. All four dispatch families consult it: HTTP/H2/H3 via `resolve_effective_proxy_for_target` (`src/proxy/mod.rs`), gRPC via the same helper threaded through `proxy_grpc_request*` (`src/proxy/grpc_proxy.rs`), TCP via `effective_backend_connect_timeout_ms` in `TcpConnParams` (`src/proxy/tcp_proxy.rs`), and HBONE via `effective_connect_timeout_ms` in `connect_backend` (`src/proxy/hbone_proxy.rs`). Ports outside 1-65535 rejected; duplicate port entries rejected; phantom ports (DR entry references a port unused by any `Upstream.target`) skipped with a warning at apply time. The admin API rejects POST/PUT setting `Upstream.port_overrides` directly — express per-port policy as a DestinationRule (SQL/MongoDB schemas don't persist the field) |
| `trafficPolicy.portLevelSettings[].loadBalancer` / `outlierDetection` | Parsed but not enforced (warns) | Gateway keeps a single `LoadBalancer` and `PassiveHealthCheck` per upstream — switching algorithm / hash ring / outlier thresholds per destination port is not yet wired up. Warnings surface BOTH from the K8s translator (so YAML pushes flag the gap at translate time) AND from `apply_destination_rules` (so native MeshSubscribe / xDS slices flag it at apply time on the data plane) |
| `exportTo` | Ignored | DRs are scoped to their declared namespace at slice-filter time |

Translator warnings surface in the `K8sTranslation.warnings` returned from `translate_k8s_objects`, so operators see them at apply time.

## MeshSlice

`MeshSlice` is the per-node filtered view of mesh configuration, built by `MeshSlice::from_gateway_config()`. The CP computes a slice per subscriber; in native mode the slice is pushed directly, in xDS mode the translated resources are sliced locally.

The slice builder:

1. Filters workloads by namespace.
2. Finds the selected workload (if `workload_spiffe_id` is provided) for effective namespace/labels.
3. Filters `MeshPolicy` entries by `PolicyScope` matching against the proxy's namespace and labels.
4. Filters `PeerAuthentication` entries by workload selector.
5. Filters `ServiceEntry` entries by `export_to` visibility.
6. Filters `MeshRequestAuthentication` entries by scope.
7. Filters `MeshTelemetryResource` entries by scope.
8. Filters `MeshProxyConfig` entries by [`PolicyScope`](#policyscope) — same predicate as `MeshPolicy`, so root-namespace ProxyConfigs apply mesh-wide.

## Authorization

Mesh authorization is evaluated by the auto-injected `mesh_authz` plugin (priority 2075) on every request. The plugin pre-filters applicable policies at construction time (cold path) so the request hot path evaluates only the relevant subset.

### PolicyScope Filtering

Every `MeshPolicy` carries a `PolicyScope`:

| Scope | Matches when |
|---|---|
| `MeshWide` | Always |
| `Namespace { namespace }` | `proxy_namespace == policy_namespace` |
| `WorkloadSelector { selector }` | Selector namespace matches (or is unset) AND all selector labels are present on the proxy with matching values (subset match) |

An empty `WorkloadSelector` (`labels: {}`, `namespace: None`) intentionally matches any workload.

The canonical matching helper `policy_scope_applies_to_workload()` is shared between the slice builder and the plugin filter so scope semantics stay byte-identical across both surfaces.

### Evaluation Semantics

`evaluate_mesh_authorization()` processes policies in order:

1. **DENY rules checked first** -- first match returns `Deny`.
2. **ALLOW rules** -- if any ALLOW rule exists in the policy set but none matched, the result is **implicit deny** (Istio semantics).
3. **AUDIT rules** -- matched audit policies are returned for logging.
4. If no DENY or ALLOW rules exist, the result is `Allow`.

**Istio empty-rule semantics**: `ALLOW` with no rules is allow-nothing (emits a `never_matches` rule so the implicit deny applies). `DENY`/`AUDIT` with no rules are no-ops.

### Rule Matching

Each `MeshRule` checks four dimensions (all must match):

- **Principal matching**: SPIFFE ID patterns (glob), namespace patterns (glob), trust domain restriction.
- **Request principal matching**: `request_principals` glob patterns matched against the `{issuer}/{subject}` composite extracted by `jwks_auth`. When `request_principals` is non-empty and no JWT is present, the rule does not match (Istio semantics: anonymous requests fail the principal check). An empty `request_principals` list matches any request including unauthenticated ones.
- **Request matching**: methods, paths (glob), hosts (normalized, case-insensitive), ports (exact + glob patterns), headers (case-insensitive keys, normalized at config load).
- **Condition matching**: attribute-based with `values` (OR semantics) and `not_values` (NOT semantics).

### SPIFFE Identity

The `spiffe_identity` plugin (priority 940) extracts the peer SPIFFE ID from TLS/DTLS client certificates on every inbound request. This identity feeds into:

- `mesh_authz` principal matching
- Workload metrics labels (`source.principal`, `destination.principal`)
- Transaction summary `auth_method` tracking

### HBONE Protocol

HBONE (HTTP-Based Overlay Network Environment) is HTTP/2 CONNECT over mTLS, used by the ambient topology on port 15008.

Detection by `is_hbone_connect()`:
- Method must be `CONNECT`, version must be HTTP/2.
- Optional marker headers: `x-ferrum-mesh-protocol` or `x-istio-protocol` (value `hbone` or absent).

Identity extraction from W3C Baggage headers:
- Source principal keys (with fallback aliases): `source.principal`, `source_principal`, `source.identity`, `source_identity`, `src.identity`, `src_identity`.
- Values are percent-decoded per the Baggage spec.

Gateway DPs can also originate HBONE when they have a gateway SVID loaded and an upstream target is tagged `mesh.hbone=true`. The gateway probes the target's sidecar HBONE port (`15008`, or `mesh.hbone_port`) during backend capability refresh, then sends eligible plain HTTP traffic through HTTP/2 CONNECT over SPIFFE mTLS before trying the ordinary direct backend transports. The HBONE pool honors the proxy's effective `pool_*` overrides, including connection count, idle timeout, TCP keepalive, and HTTP/2 flow-control settings, and coalesces concurrent first connects for the same target/SVID key within the proxy's `backend_connect_timeout_ms` budget. Requests that require replayable retries or request-body buffering continue to use the direct backend transports. The CONNECT request carries `source.principal` baggage derived from the gateway SVID; mesh-side authz still requires the baggage to agree with the authenticated peer identity. The tunneled inner HTTP request strips client-supplied identity baggage (`source.*`, `destination.*`, and aliases) while preserving non-identity baggage, so untrusted client claims cannot reach the mesh backend as application headers.

Gateways with a loaded SVID auto-enable source identity labels for the `workload_metrics` plugin. The runtime injects an internal global `workload_metrics` plugin when none exists, or augments an existing global plugin with `workload_spiffe_id` when the operator has not set one explicitly. Successful HBONE-dispatched transactions are labeled with `mesh.connection_security_policy=mutual_tls` and `mesh.gateway.transport=hbone`; mesh-aware upstream target tags such as `mesh.spiffe_id`, `mesh.namespace`, `mesh.service`, and `mesh.trust_domain` are copied to destination metadata.

### Trust Domain Aliasing

`FERRUM_MESH_TRUST_DOMAIN_ALIASES` configures additional trust domains accepted as equivalent to the peer certificate's trust domain when validating HBONE baggage `source.principal`. By default (empty), strict same-trust-domain matching applies. This mirrors Istio's `MeshConfig.trustDomainAliases`.

## RequestAuthentication

`MeshRequestAuthentication` declares which JWTs are valid for a workload scope. When applicable resources with JWT rules exist in the mesh slice, the mesh runtime auto-injects a `jwks_auth` global plugin (`__mesh_request_auth`) configured from the JWT rules.

**Permissive semantics** (matching Istio): RequestAuthentication only declares which JWTs are *valid*, not which are *required*. A request with no JWT passes through. An invalid JWT is rejected. Enforcement (requiring a JWT) comes from `AuthorizationPolicy` ALLOW/DENY rules that check for authenticated identity.

Each `MeshJwtRule` specifies:

| Field | Description |
|---|---|
| `issuer` | Expected JWT issuer (`iss` claim) |
| `audiences` | Accepted audience values (`aud` claim) |
| `jwks_uri` | URL to fetch the JWKS key set |
| `jwks` | Inline JWKS JSON (alternative to `jwks_uri`) |
| `from_headers` | Headers to extract the JWT from (with optional prefix stripping) |
| `from_params` | Query parameters to extract the JWT from |
| `forward_original_token` | Whether to forward the original token to the backend |

## PeerAuthentication

`PeerAuthentication` controls per-workload mTLS behavior with optional per-port overrides.

mTLS modes:

| Mode | Description |
|---|---|
| `strict` | Require mTLS on all connections. Reject plaintext. |
| `permissive` (default) | Accept both mTLS and plaintext. |
| `disable` | Disable mTLS. Accept plaintext only. |

Per-port overrides allow mixed-mode operation on the same workload:

```yaml
name: "mixed-mode"
namespace: "default"
selector:
  labels:
    app: my-service
mtls_mode: strict
port_overrides:
  8081: permissive   # Health check port accepts plaintext
```

Selector-less `PeerAuthentication` applies to all workloads in its namespace (or mesh-wide if namespace-scoped).

### Resolution and listener wiring

The effective mTLS mode for the inbound TLS-terminating listener is resolved at startup from the initial mesh slice via `resolve_effective_mtls_mode()`. Scope precedence (highest wins): `WorkloadSelector` > `Namespace` > `MeshWide`. Port-level overrides within the winning policy then take precedence over its top-level `mtls_mode`.

The resulting `MeshClientAuth` is plumbed into the inbound TLS acceptor:

- `strict` -> TLS `Required` (client cert mandatory; plaintext rejected).
- `permissive` -> TLS `Optional` (TLS accepted with optional client cert; plaintext can be accepted by the mesh listener).
- `disable` -> TLS `Disabled` (plaintext only; mTLS connections rejected).

The port used for `port_overrides` lookup follows the topology's TLS-terminating listener (see `MeshRuntimeConfig::listener_plan()`):

| Topology | Resolution port (default) | Override key example |
|---|---|---|
| `Sidecar` | `inbound_listen_addr` (15006) | `port_overrides: {15006: strict}` |
| `Ambient` | `hbone_listen_addr` (15008) | `port_overrides: {15008: strict}` |
| `EgressGateway` | `egress_listen_addr` (15090) | `port_overrides: {15090: strict}` |
| `EastWestGateway` | n/a (SNI passthrough, no termination) | — |

The resolved mode is captured **once at startup** from the first valid slice. Subsequent `PeerAuthentication` changes pushed via the control plane update the in-memory slice and are honored by other plugin paths (e.g. `mesh_authz`, plugin chains), but the inbound TLS `ServerConfig` is **not** re-built — consistent with the project's static-TLS-material rotation model. To change the inbound mTLS mode, restart the data plane.

### Disable-mode topology guard

`PeerAuthentication.mode: disable` resolved against an `Ambient` or `EgressGateway` workload causes startup to fail closed:

- **Ambient**: HBONE is HTTP/2 CONNECT over mTLS — running the inbound listener plaintext is not a valid HBONE listener. Use `permissive` or `strict`, or move the workload to `Sidecar` topology if plaintext-only inbound is intended.
- **EgressGateway**: the egress listener must verify sidecar client certificates. Use `permissive` or `strict`.

`Sidecar` and `EastWestGateway` accept any resolved mode (`Disable` on Sidecar produces a plaintext inbound listener; on EastWestGateway the resolved mode is unused because there is no TLS termination).

## Transparent DNS Proxy

The mesh DNS proxy intercepts DNS queries and resolves mesh-internal hostnames from a pre-built resolution table. Non-mesh queries are forwarded to the upstream system resolver.

### Enablement

The DNS proxy is opt-in because it requires iptables or eBPF redirect to be useful:

```bash
FERRUM_MESH_DNS_PROXY_ENABLED=true
FERRUM_MESH_DNS_LISTEN_ADDR=127.0.0.1:15053    # default
FERRUM_MESH_DNS_UPSTREAM_ADDR=127.0.0.53:53     # default
```

### How It Works

1. The `DnsResolutionTable` is built atomically from the `MeshSlice` on every config update via `ArcSwap` -- no locks on the query hot path.
2. Incoming DNS queries (UDP and TCP) are parsed for hostname and query type (A/AAAA).
3. Exact matches are checked first, then wildcard suffix matches.
4. Mesh-resolved responses are served with configurable TTL (`FERRUM_MESH_DNS_TTL_SECONDS`, default 60).
5. Non-mesh queries are forwarded transparently to the upstream resolver.

### Resolution Sources

**ServiceEntry hosts**: endpoint IP addresses are indexed by hostname.

```
api.external.com -> [203.0.113.10]
```

**MeshService names**: workload addresses are resolved through SPIFFE ID references and registered under both FQDN and short name forms:

```
my-service.default.svc.cluster.local -> [10.0.1.5, 10.0.1.6]
my-service.default                   -> [10.0.1.5, 10.0.1.6]
```

The cluster domain suffix is configurable via `FERRUM_MESH_CLUSTER_DOMAIN` (default `cluster.local`).

### Wildcard Support

Wildcard hosts (`*.example.com`) are supported via bucketed suffix matching. The DNS proxy maintains a suffix index so lookup is bounded rather than linear.

### Protocol Details

- Supports A (IPv4) and AAAA (IPv6) queries.
- EDNS(0) OPT pseudo-records are echoed when they fit.
- UDP responses are clamped to the client's advertised payload size (or 512 bytes without EDNS).
- TCP fallback for large responses.
- Concurrent query limiting via `FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES` (default 1024) using a semaphore.
- Upstream forwarding timeout: 5 seconds.

## Multi-Cluster

Multi-cluster mesh support enables cross-cluster service discovery and traffic routing.

### East-West Gateways

When `FERRUM_MESH_TOPOLOGY=east_west_gateway`, the mesh runtime materializes passthrough TCP proxies from `MultiClusterConfig.east_west_gateways` entries. Each gateway entry specifies:

- `host` / `port`: backend cluster endpoint.
- `sni_hosts`: TLS SNI hostnames routed through this gateway.
- `trust_domain` / `network`: optional cross-cluster identity and network labels.

The materialized proxies use `passthrough: true` (no TLS termination), route by SNI, and share the listener on `FERRUM_MESH_EAST_WEST_LISTEN_PORT` (default 15443). Only entries matching the gateway's namespace are materialized.

In addition to remote-cluster gateways, the east-west topology materializes a TCP passthrough proxy for each local `MeshService` in the mesh slice. The SNI routing host is the service FQDN (e.g., `reviews.default.svc.cluster.local`), enabling cross-cluster clients to reach local services through the east-west gateway without separate per-service configuration.

### Trust Federation

`TrustBundleSet` carries local and federated X.509/JWT authority bundles:

- `local`: the trust bundle for the local cluster's trust domain.
- `federated`: trust bundles from remote clusters, enabling cross-cluster mTLS verification.

X.509 authorities are stored as base64-encoded DER for serialization-friendly persistence. JWT authorities carry `key_id` and `public_key_pem`.

### Remote Clusters

`RemoteCluster` entries identify peer clusters:

```yaml
multi_cluster:
  local_cluster: "us-east-1"
  remote_clusters:
    - name: "eu-west-1"
      trust_domain: "eu-west-1.example.com"
      network: "network-eu"
      control_plane_url: "https://cp.eu-west-1.internal:50051"
      federation_endpoint: "https://cp.eu-west-1.internal/.well-known/spiffe"
```

## Egress Gateway

When `FERRUM_MESH_TOPOLOGY=egress_gateway`, the mesh runtime materializes HTTP-family proxies from `ServiceEntry` resources with `location: mesh_external`.

### Materialization Rules

- Only `MeshExternal` entries are materialized (internal entries are skipped).
- Each entry port produces one `Upstream` (targets from endpoints or DNS hosts) and one `Proxy` per host.
- HTTP-family protocols are materialized (`http`, `http2`, `grpc`, `tls`). Non-HTTP protocols (`tcp`, `mongo`, `redis`, `mysql`, `postgres`) are skipped.
- DNS-resolution entries use ServiceEntry hosts as backend targets; static-resolution entries use endpoint addresses.
- Materialized proxies use host-only routing (no `listen_path`), `preserve_host_header: true`, and passive health checks.

### ServiceEntry Visibility

`export_to` controls which namespaces can see a ServiceEntry:

| `export_to` value | Visibility |
|---|---|
| (empty) | Namespace-local (same namespace as the entry) |
| `"*"` | Mesh-wide |
| `"."` | Same namespace as the entry |
| `"namespace-name"` | Exported to that specific namespace |

### Baggage Stripping

`FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS` configures baggage header keys to strip before forwarding to external backends, preventing identity leakage outside the mesh.

## Sidecar Egress Scoping

Istio `Sidecar` resources narrow which mesh service configuration a workload receives for egress. Ferrum translates the egress portion of a `Sidecar` into a `MeshSidecar` record and applies it at slice build time. Ingress listener configuration on `Sidecar` is intentionally not modeled — egress config scoping is the immediate compatibility gap.

### Behavior

When `FERRUM_MESH_SIDECAR_ENFORCED=true`, the `MeshSlice` projection narrows `services`, `service_entries`, and `destination_rules` to the set admitted by the workload's applicable `Sidecar`. When `false` (the default), `Sidecar` resources are still parsed and persisted in `MeshConfig` for future use, but slice narrowing is skipped and behavior is identical to today.

### Resolution Precedence

Most specific wins:

1. **Workload-scoped** Sidecar (`spec.workloadSelector.matchLabels` matches the workload's labels)
2. **Namespace-default** Sidecar (no `workloadSelector`)
3. **No Sidecar applies** → no narrowing (existing behavior)

### Host Pattern Syntax

Each `spec.egress[].hosts` entry follows Istio scope-host syntax:

| Pattern | Meaning |
|---|---|
| `*/*` | Allow everything (effective no-op) |
| `*/host` | `host` in any namespace |
| `./host` | `host` in the Sidecar's own namespace |
| `namespace/host` | Exact namespace + host match |
| `namespace/*` | Anything in the specified namespace |
| `~/*` | No namespace; trims all service config from the slice |
| `host` (bare) | Treated as `./host` — current Sidecar's namespace |

The `host` portion may itself be a single-label DNS wildcard (e.g. `*/*.example.com` admits `api.example.com` but not `example.com` nor `a.b.example.com`). This is the same single-label wildcard semantic Ferrum uses elsewhere (`config::types::wildcard_matches`, mesh DNS proxy); operators relying on deeper-than-one-label wildcards should list the additional surfaces explicitly. `MeshService` entries match their short name, `{name}.{namespace}`, `{name}.{namespace}.svc`, and `{name}.{namespace}.svc.{cluster_domain}` aliases. On the control plane this suffix follows `FERRUM_K8S_CLUSTER_DOMAIN`; in local mesh mode it follows `FERRUM_MESH_CLUSTER_DOMAIN`.

When Kubernetes `spec.egress` is omitted, Istio inherits the namespace-default outbound scope; Ferrum preserves that distinction so an ingress-only workload Sidecar does not override a namespace default. If no namespace default Sidecar exists, omitted egress is treated as no narrowing. An explicit native/file `egress: []` or `~/*` trims all service config from the slice. The optional `spec.egress[].port.number` is parsed and recorded but does not yet narrow by listener port — port matching for egress is a follow-up.

When multiple `Sidecar` resources in the same namespace apply at the same scope tier (two namespace-defaults, or two workload-scoped Sidecars both matching the same workload), the resolver picks the ASCII-smallest `name` as the deterministic tiebreak so reconciles are stable across pods and restarts.

### Known Limitations

- `Sidecar` resources placed in the Istio root namespace (`istio-system` by default) are not yet treated as cluster-wide defaults. They apply only to workloads in their own namespace. Operators relying on a mesh-wide default `Sidecar` should declare a namespace-default `Sidecar` in each workload namespace until the root-namespace plumbing lands.
- Slice narrowing today filters `services`, `service_entries`, and `destination_rules`. **Workload identity entries are not filtered** by Sidecar scope — every workload in the workload's own namespace continues to appear in the slice even when the applicable Sidecar only allows egress to a subset of services. This avoids breaking introspection and mTLS peer-identity lookups; workload-identity narrowing is tracked as a follow-up.

### Migration Notes

The flag defaults `false` so existing deployments see zero behavior change on upgrade. Operators should:

1. Apply `Sidecar` CRDs and verify the translator parses them without errors.
2. Inspect mesh slices (via the CP debug endpoint) to confirm the expected narrowing would apply.
3. Set `FERRUM_MESH_SIDECAR_ENFORCED=true` on the CP and roll. DPs receive the already-narrowed slice — no DP-side configuration is required.

## DestinationRule

Istio `DestinationRule` resources are translated into Ferrum upstream and proxy configuration at the Kubernetes translation layer. The following fields are supported:

### Traffic Policy

- **`connectionPool.tcp.connectTimeout`**: mapped to the proxy's `backend_connect_timeout_ms`.
- **`outlierDetection`**: translated to Ferrum passive health checks:
  - `consecutive5xxErrors` -> `passive_health_check.consecutive_failures`
  - `interval` -> `passive_health_check.check_interval_seconds`
  - `baseEjectionTime` -> `passive_health_check.eject_duration_seconds`

### Load Balancer

Simple load balancer algorithms are mapped directly:

| Istio `simple` | Ferrum algorithm |
|---|---|
| `ROUND_ROBIN` | `round_robin` |
| `LEAST_REQUEST` / `LEAST_CONN` | `least_connections` |
| `RANDOM` | `random` |

Consistent hash load balancing (`consistentHash`) is translated to Ferrum's `consistent_hashing` algorithm with the hash key derived from `httpHeaderName`, `httpCookie`, or `useSourceIp`.

### Subsets

DestinationRule `subsets` are preserved as named subsets in the Ferrum upstream. Each subset can carry its own traffic policy overrides (connection pool, outlier detection, load balancer) that take precedence over the top-level traffic policy.

### Deferred Fields

TLS settings on DestinationRule (`trafficPolicy.tls`) are not yet translated -- use per-proxy `backend_tls_*` fields. Port-level traffic policy overrides are also deferred.

## Observability

### RED Metrics

The auto-injected `workload_metrics` plugin emits Istio/GAMMA-shaped RED (Rate, Errors, Duration) metrics:

- `ferrum_mesh_requests_total` -- request counter.
- `ferrum_mesh_request_duration_ms` -- request duration histogram.

Labels include:

| Label | Description |
|---|---|
| `source_workload` | Source workload name |
| `source_namespace` | Source workload namespace |
| `source_principal` | Source SPIFFE ID |
| `source_app` | Source `app` label |
| `destination_workload` | Destination workload name |
| `destination_namespace` | Destination workload namespace |
| `destination_principal` | Destination SPIFFE ID |
| `destination_service` | Destination service name |
| `destination_app` | Destination `app` label |
| `request_protocol` | Protocol (http, grpc, tcp) |
| `response_code` | HTTP status code |
| `response_flags` | Error flags |
| `connection_security_policy` | `mutual_tls` or `none` |

### Telemetry API

`MeshTelemetryResource` provides per-scope telemetry configuration, merged by specificity (most specific scope wins per section):

**Scope precedence**: `WorkloadSelector` > `Namespace` > `MeshWide`

Each section (tracing, metrics, access logging) is merged independently. Within the same scope level, later resources win. Deterministic ordering is ensured by namespace/name tie-breaking.

**Tracing configuration**:

- `sampling_percentage`: 0.0--100.0 (deterministic hash-based sampling).
- `custom_tags`: literal key-value tags injected into every span.
- `custom_header_tags`: tags resolved from request headers at runtime.

**Metrics configuration**:

- `tag_overrides`: rename, remove, or set custom values for metric tags.
- `disabled_metrics`: specific metric names to suppress.

**Access logging configuration**:

- `enabled`: toggle (default true). When false, the access log plugin is not injected.
- `filter`: optional `AccessLogFilter` with `status_code_min`, `status_code_max`, `min_latency_ms`, and `errors_only`.

## Kubernetes Injector

`FERRUM_MODE=injector` runs a Kubernetes admission webhook that injects Ferrum mesh sidecars into pods. The injector only produces JSON patches; all mesh runtime work happens in `FERRUM_MODE=mesh`.

### Webhook Setup

The injector listens on `FERRUM_INJECTOR_LISTEN_ADDR` (default `0.0.0.0:9443`) and handles `POST /mutate`. TLS is configured via `FERRUM_INJECTOR_TLS_CERT_PATH` and `FERRUM_INJECTOR_TLS_KEY_PATH` (both required for HTTPS, which Kubernetes mandates for admission webhooks).

Register with Kubernetes:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: ferrum-edge-injector
webhooks:
  - name: ferrum-inject.ferrum.io
    clientConfig:
      service:
        name: ferrum-edge-injector
        namespace: ferrum-system
        path: /mutate
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
        operations: ["CREATE"]
```

### Annotation Control

The injector checks annotations and labels to decide whether to inject:

| Annotation/Label | Effect |
|---|---|
| `ferrum.io/inject: "true"` | Opt-in injection |
| `ferrum.io/mesh: "enabled"` (label) | Opt-in injection |
| `ferrum.io/inject: "false"` | Skip injection |
| `sidecar.istio.io/inject: "false"` | Skip injection (Istio compat) |
| `ferrum.io/injected` | Skip (already injected) |

When `FERRUM_INJECTOR_REQUIRE_ANNOTATION=true` (default), pods must explicitly opt in via `ferrum.io/inject: "true"` or the `ferrum.io/mesh: "enabled"` label. When `false`, all pods are injected unless explicitly opted out.

### Port and IP-Range Exclusions

The injector supports per-pod capture overrides via annotations. The Istio annotation namespace is honored byte-for-byte so workloads can migrate without rewriting metadata; Ferrum-native annotations are accepted as aliases for the port lists.

| Annotation | Direction | Semantics |
|---|---|---|
| `traffic.sidecar.istio.io/excludeOutboundPorts` | outbound | Comma-separated TCP destination ports excluded from outbound capture (Istio-compatible) |
| `ferrum.io/excludeOutboundPorts` | outbound | Ferrum-native alias for the above |
| `traffic.sidecar.istio.io/excludeInboundPorts` | inbound | Comma-separated TCP destination ports excluded from inbound capture (Istio-compatible). RETURN rules are emitted BEFORE the inbound REDIRECT so the exclusion is honored |
| `ferrum.io/excludeInboundPorts` | inbound | Ferrum-native alias for the above |
| `traffic.sidecar.istio.io/excludeOutboundIPRanges` | outbound | Comma-separated CIDRs appended to the env-derived outbound exclude list (matches Istio: per-pod additive) |
| `traffic.sidecar.istio.io/includeOutboundIPRanges` | outbound | Comma-separated CIDRs that REPLACE the env-derived outbound include list when present (matches Istio: include-overrides-include) |

Port-list annotations merge with each other and with the injector-level `FERRUM_MESH_EXCLUDE_OUTBOUND_PORTS` / `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` defaults; results are deduplicated. CIDR annotations are validated at admission time -- invalid ports or CIDRs are rejected with a webhook error that names the offending annotation, so a typo cannot silently produce a broken iptables plan.

**Pod-restart caveat:** annotations are evaluated at pod admission time only. Existing pods retain their previous capture rules until restart; bouncing affected workloads is required for previously-ignored annotations to take effect.

**IPv6 CIDRs:** `includeOutboundIPRanges` / `excludeOutboundIPRanges` accept IPv6 CIDR literals (e.g. `fd00::/8`) at admission for forward compatibility, but `IptablesPlan::for_config` strips non-IPv4 CIDRs before emitting rules (with a `warn!` log naming each skipped CIDR). The init container only invokes the IPv4 `iptables` binary; feeding it a raw `-d fd00::/8` would fail the rule append and leave the capture chain half-populated. `ip6tables` fan-out is deferred. If an include list contains ONLY IPv6 CIDRs the outbound REDIRECT will not be emitted at all, so outbound capture is disabled for that pod — check init-container logs for the skip warning.

### SPIFFE ID Derivation

The injector derives the workload SPIFFE ID from the pod's service account:

```
spiffe://{TRUST_DOMAIN}/ns/{NAMESPACE}/sa/{SERVICE_ACCOUNT}
```

`FERRUM_INJECTOR_TRUST_DOMAIN` (default `cluster.local`) sets the trust domain.

### Sidecar Container

The injected sidecar container runs `ferrum-edge run` with environment variables:

- `FERRUM_MODE=mesh`
- `FERRUM_NAMESPACE={pod_namespace}`
- `FERRUM_MESH_TOPOLOGY=sidecar`
- `FERRUM_MESH_CAPTURE_MODE={capture_mode}`
- `FERRUM_MESH_WORKLOAD_SPIFFE_ID=spiffe://...`
- CP connection variables forwarded from `FERRUM_DP_CP_GRPC_URLS`, TLS paths, etc.
- `FERRUM_CP_DP_GRPC_JWT_SECRET` via `valueFrom.secretKeyRef` (never plaintext)

The container runs as `FERRUM_MESH_PROXY_UID` (default 1337) with `allowPrivilegeEscalation: false`.

### Capture Modes

`FERRUM_MESH_CAPTURE_MODE` controls traffic interception:

| Mode | Description |
|---|---|
| `explicit` (default) | No automatic capture; applications must explicitly route to the proxy |
| `iptables` | Inject init container with `NET_ADMIN`/`NET_RAW` capabilities that sets up iptables rules to redirect traffic through the sidecar (inbound to 15006, outbound to 15001) |
| `ebpf` | eBPF-based capture handled by a node-level agent (requires kernel 5.7+). The injector does not inject a privileged init container for this mode -- the node agent's DaemonSet manages eBPF program attachment. Capture planning infrastructure (`EbpfPlan` with iptables fallback for pre-5.7 kernels) is available in `src/capture/mod.rs` for the node agent path |

## Control Plane Integration

### MeshGrpcServer

The `MeshConfigSync.MeshSubscribe` streaming RPC is served by `MeshGrpcServer` in `src/grpc/mesh_server.rs`. It runs on the Control Plane alongside the regular `ConfigSync` service.

- **JWT authentication** on every subscribe request.
- **Namespace validation**: a single CP serves a single namespace. Mesh nodes requesting a different namespace are rejected with `FAILED_PRECONDITION`.
- **Version compatibility**: the CP validates the mesh node's Ferrum version for protocol compatibility.
- **Initial snapshot**: on subscribe, the CP loads the current `GatewayConfig`, computes a `MeshSlice` for the subscriber's identity (node ID, namespace, SPIFFE ID, labels), and sends it as the first update.
- **Delta vs full**: subsequent config changes are broadcast via tokio `broadcast` channel (capacity `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`). The server computes `content_eq()` to suppress no-op updates. Lagging subscribers automatically receive a full snapshot.
- **Incremental apply**: DB polling deltas are applied incrementally to each stream's config shadow, and a new slice is computed and sent only if the content changed.

### MeshNodeRegistry

The CP tracks connected mesh nodes in `MeshNodeRegistry` (DashMap, `src/grpc/mesh_registry.rs`). Each entry records the node ID, version, namespace, and connection timestamps.

- Nodes are automatically removed when their gRPC stream drops (via `TrackedMeshStream`'s `Drop` implementation).
- `touch_all()` updates `last_update_at` on every broadcast.
- Stale removal uses `remove_if_stale()` with timestamp comparison to handle reconnects that raced with the old stream's drop.

### Gateway Mesh Service Discovery

Gateway database/file/DP modes can resolve mesh services through an upstream `service_discovery` block with `provider: mesh`. The provider reads the current CP-delivered `GatewayConfig.mesh` snapshot, finds a `MeshService` by `service_name` and namespace, resolves its workload SPIFFE references to workload addresses, and publishes ordinary `UpstreamTarget` entries into the existing load balancer cache.

Generated targets are tagged with `mesh.spiffe_id`, `mesh.namespace`, `mesh.service`, `mesh.trust_domain`, and `mesh.hbone=true`. This keeps the north-south gateway on the same discovery model as mesh mode while giving later gateway-to-mesh transport phases enough metadata to prefer HBONE/mTLS paths.

### Auto-Injected Plugins

Mesh mode automatically injects these global plugins with reserved IDs:

| Plugin ID | Plugin Type | Priority | Purpose |
|---|---|---|---|
| `__mesh_spiffe_identity` | `spiffe_identity` | 940 | Extract peer SPIFFE ID from TLS/DTLS client certs |
| `__mesh_authz` | `mesh_authz` | 2075 | Evaluate MeshPolicy authorization rules |
| `__mesh_workload_metrics` | `workload_metrics` | (default) | Istio/GAMMA RED metric labels from SPIFFE/HBONE identity |
| `__mesh_request_auth` | `jwks_auth` | (default) | JWT validation from MeshRequestAuthentication rules |
| `__mesh_access_log` | `access_log` | (default) | Access logging with optional Telemetry API filters |

An operator-managed global plugin of the same type takes precedence over mesh-injected plugins (explicit override). See [plugin_execution_order.md](plugin_execution_order.md) for the full lifecycle phase matrix.

## Gateway-to-Mesh Bridge

Non-mesh gateway modes (`database`, `file`, `cp`, `dp`) can route traffic into the mesh via the gateway-to-mesh bridge. This enables a Ferrum gateway operating as an ingress or API gateway to forward requests to mesh workloads over HBONE with full SPIFFE mTLS.

### Trust Bundle Distribution

The Control Plane distributes gateway SPIFFE trust bundles to Data Planes via a `trust_bundles_json` side channel on the `ConfigUpdate` proto message. DPs hot-swap received bundles into the gateway SVID identity slot, enabling mutual TLS with mesh sidecars without requiring the DP to independently obtain certificates.

### HBONE Outbound Pool

When an upstream target is tagged with `mesh.hbone=true` metadata, the gateway routes requests through an HBONE HTTP/2 CONNECT pool (`HboneOutboundPool`) instead of direct HTTP. The pool uses the gateway's SPIFFE identity for mTLS and keys connections by SVID fingerprint so certificate rotation triggers fresh connections. DNS resolution uses the shared `DnsCacheResolver`.

On HBONE connect failure, the gateway falls back to plain HTTP dispatch so partially-mesh-enabled upstreams degrade gracefully.

### Mesh Service Discovery

A `service_discovery.provider: mesh` option resolves upstream targets from CP-delivered mesh service and workload snapshots. The provider maps workload addresses and ports into upstream targets with SPIFFE/HBONE metadata tags, enabling the HBONE outbound pool to route transparently. Target lists are refreshed on every mesh slice update.

Identity baggage from the client request is stripped from tunneled inner HBONE requests to prevent identity spoofing across the gateway boundary.

## Mesh Identity

### SPIRE Agent CA

`FERRUM_MESH_CA_BACKEND=spire_agent` delegates SVID issuance to a SPIRE Agent via the SPIFFE Workload API. The mesh data plane connects to the SPIRE Agent socket and receives X.509 SVIDs for its configured workload identity.

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_CA_BACKEND` | `none` | CA backend: `none` (no automatic identity), `internal` (self-signed dev CA), `spire_agent` (SPIRE Workload API) |
| `FERRUM_MESH_SPIRE_AGENT_SOCKET` | `/run/spire/sockets/agent.sock` | SPIRE Agent Workload API Unix socket path |
| `FERRUM_MESH_CERT_TTL_SECONDS` | `3600` | Requested certificate TTL for issued SVIDs |

The SPIRE backend is the recommended production path for mesh identity. `internal` is intended for development and testing only -- it generates a self-signed root CA at startup with no external trust anchor.

## Node Agent Mode

`FERRUM_MODE=node_agent` runs a per-node DaemonSet agent that manages eBPF-based traffic capture for mesh sidecars. The node agent replaces the per-pod privileged init container used by iptables capture mode, providing lower-privilege pod injection and centralized capture management.

### Architecture

The node agent runs on each Kubernetes node with the following responsibilities:

1. **Kernel probing**: verifies Linux kernel >= 5.7 and cgroup v2 + bpffs availability for eBPF program attachment.
2. **Pod watching**: monitors the Kubernetes API for pod events on the local node, matching pods that have opted into mesh injection.
3. **eBPF program attachment**: attaches cgroup-level and tc-level BPF programs to enrolled pods for transparent traffic redirection (4 cgroup + 1 tc program per pod).
4. **Lifecycle management**: enrolls/unenrolls pods with rollback on attach failure, graceful cleanup on pod deletion or agent shutdown.
5. **Iptables fallback**: on kernels that lack eBPF support, falls back to per-pod iptables rule programming with cleanup commands on teardown.

### Deployment

The node agent is deployed as a Kubernetes DaemonSet with the Helm chart (`charts/ferrum-node-agent/`):

```yaml
nodeAgent:
  enabled: true
  image: ferrum-edge:latest
  captureMode: ebpf       # or "iptables_fallback"
  resources:
    limits:
      cpu: 250m
      memory: 256Mi
  meshCapture:
    includeCidrs: []       # empty = capture all
    excludeCidrs: []
    excludePorts: []
```

Required capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`. Volume mounts: `/sys/fs/bpf` (bpffs), `/sys/fs/cgroup` (cgroup v2).

### Metrics

The node agent exposes atomic counters for operational monitoring:

- `pods_enrolled` -- total pods successfully enrolled for capture.
- `pods_unenrolled` -- total pods unenrolled (deletion or shutdown).
- `attach_errors` -- total BPF/iptables attach failures.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FERRUM_NODE_AGENT_NODE_NAME` | (required) | Kubernetes node name, set via downward API (`spec.nodeName`) |
| `FERRUM_NODE_AGENT_CGROUP_ROOT` | `/sys/fs/cgroup` | cgroup v2 mount point for pod cgroup resolution |
| `FERRUM_NODE_AGENT_BPF_FS_PATH` | `/sys/fs/bpf` | BPF filesystem mount point for pinned maps |
| `FERRUM_NODE_AGENT_BPF_ELF_PATH` | build-tree path | Compiled `ferrum-ebpf` ELF loaded by the aya backend (Linux `ebpf` feature only) |
| `FERRUM_NODE_AGENT_FALLBACK_MODE` | `iptables` | Behavior on kernel < 5.7: `iptables` or `fail` |
| `FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES` | (empty) | Extra namespaces to exclude from capture (`kube-system`, `kube-public`, `kube-node-lease` always excluded) |
| `FERRUM_MESH_CAPTURE_INCLUDE_CIDRS` | `0.0.0.0/0` | CIDRs to capture for outbound traffic |
| `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS` | (empty) | CIDRs to exclude from outbound capture (highest priority) |
| `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS` | `15001,15006,15008,15020` | Destination TCP ports excluded from outbound capture |
| `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` | (empty) | Destination TCP ports excluded from inbound capture (mirrors Istio `excludeInboundPorts`; pod annotation `traffic.sidecar.istio.io/excludeInboundPorts` is additive) |

## VirtualService Translation

Istio `VirtualService` resources are translated at the Kubernetes translation layer into Ferrum proxy configuration. Beyond basic route splitting (documented in [configuration.md](configuration.md)), the following per-route features are supported:

### Retries

VirtualService `retries` are translated to Ferrum `RetryConfig`:

- `attempts` -> `retry_count`
- `retryOn` tokens: `5xx`, `gateway-error`, `connect-failure`, `reset`, `retriable-4xx`, and numeric status codes (e.g., `503`).
- `perTryTimeout` -> per-attempt timeout.

### Timeout

VirtualService `timeout` is translated to the proxy's `backend_read_timeout_ms`. Supports Go-style duration strings (`10s`, `500ms`, `1m`, `1h`).

### Fault Injection

Per-route `fault` configuration is translated to proxy-scoped `fault_injection` plugin instances:

- `fault.abort.httpStatus` + `fault.abort.percentage` -> abort with status code at the configured rate.
- `fault.delay.fixedDelay` + `fault.delay.percentage` -> inject latency at the configured rate.

### Destination Port Resolution

`route.destination.port` accepts either `number` (integer) or `name` (string). When a name is given, the translator resolves it against the `Service.spec.ports[].name` index built from collected core/v1 `Service` objects in the same translation batch (input order is irrelevant — Services are gathered in a pre-pass). `port.number` always wins when both are set. An unknown port name fails translation closed with the offending name in the error. Hosts are parsed as `<svc>`, `<svc>.<ns>`, `<svc>.<ns>.svc`, or `<svc>.<ns>.svc.cluster.local` (with or without a trailing dot); short hosts fall back to the VirtualService's own namespace, so port-name lookups for the same short host resolve differently depending on which namespace the VS lives in. Service ports without a `name` are silently skipped by the indexer (no panic). Numeric-port-only deployments need no changes.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: reviews
  namespace: default
spec:
  ports:
    - name: http
      port: 8080
    - name: grpc
      port: 9090
---
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: reviews-vs
  namespace: default
spec:
  hosts:
    - reviews.default.svc.cluster.local
  http:
    - match:
        - uri:
            prefix: /api
      route:
        - destination:
            host: reviews.default.svc.cluster.local
            port:
              name: http        # resolves to 8080 via the Service index above
```

## xDS ADS Compatibility

Ferrum's ADS server honors explicit SotW (State-of-the-World) resource subscriptions per type URL across CDS/EDS/LDS/RDS/SDS. A SotW request with a non-empty `resource_names` returns only the named resources for that type URL, while a wildcard subscription (`*` or an initial empty `resource_names`) returns the full collection per the Envoy ADS protocol. Subsequent empty SotW requests on the same stream preserve the established wildcard or explicit state rather than re-broadcasting it as a fresh subscription.

Delta-xDS subscriptions across the same CDS/EDS/LDS/RDS/SDS type URLs are additive: `resource_names_subscribe` appends to the per-stream subscription set and `resource_names_unsubscribe` removes from it, with empty lists treated as no-ops. Subscriptions persist across requests on the same stream, and updates only mutate the explicit subscription state without broadcasting unrelated resources.

Delta xDS wire-byte optimization and ECDS `TypedExtensionConfig` resources remain staged follow-ups in the GAP-2L track; the current support is the explicit-resource subscription state machine.

## Istio Compatibility Gaps

The following Istio mesh surfaces are either deferred or have Ferrum-specific support notes:

| Surface | Status | Workaround |
|---|---|---|
| `EnvoyFilter` | Not planned | Use Ferrum custom plugins |
| `WasmPlugin` | Not planned | Use Ferrum custom plugins (`custom_plugins/`) |
| Outbound traffic policy (`REGISTRY_ONLY` / `ALLOW_ANY`) | Supported | `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY=registry_only` (or native/CRD slice-supplied `outbound_traffic_policy`) auto-injects the `mesh_outbound_registry` plugin on topologies with an outbound capture listener; unknown destinations are rejected at the outbound gate with `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` (default 502), inbound sidecar/ambient traffic is not gated by this outbound policy, wildcard ServiceEntry hosts match one DNS label, resources with no declared ports admit any explicit Host port for that known destination, and empty registries fail closed |
| `VirtualService` header/method/queryParam predicates beyond plugin capture | Partial | Plumbing in place via `mesh_route_dispatch` plugin (`FERRUM_MESH_VS_HEADER_ROUTING_EXPERIMENTAL=true`); supported predicates are captured as plugin config. Routing-decision rewrites via `RequestContext.route_override_*` flow through HTTP-family dispatch sites (pool keys, capability registry, circuit breaker). Translator emits the plugin with `reject_unmatched: true` so requests that miss the predicates return 404 instead of falling through to the default backend (Envoy parity for VS match semantics; e.g., a `match.method=GET` route does not serve POST traffic). Same-path and URI-less ordered canary/default routes collapse into one Proxy with ordered dispatch rules so predicate misses can fall through when a later route exists. That collapse is destination-only; if route-local `fault`, `retries`, or `timeout` policy would have to apply to one dispatch rule but not its merged siblings, the VirtualService is rejected rather than widened. Unsupported predicate-only candidates (`regex`/`prefix` method/header/queryParam matchers, `authority`, `sourceNamespace`, `ignoreUriCase`, etc.) emit proxy-scoped `request_termination` instead of widening traffic. Admission plugins such as `mesh_authz` and rate limiting still evaluate the original public proxy identity; WebSocket overrides apply to the upgrade backend only, and HBONE CONNECT is not routed by this plugin because it branches before `before_proxy`. Query-param rules opt the whole proxy into decoded HTTP/3 query-param materialization so all plugins on that proxy observe decoded `ctx.query_params`. Multi-destination splits within a single `http[].route[]` still use generated upstreams; per-destination TLS on those generated upstreams comes from the upstream/DestinationRule materialization rather than per-rule `backend_tls`. |
| Pod auto-discovery (K8s native service registry) | Deferred | Declare `WorkloadEntry` / `ServiceEntry` explicitly until a Pod watcher lands |
| `WorkloadEntry` `weight` / `locality` / `serviceAccount` | Partial | Translated as workload metadata; locality-aware load balancing not yet wired (consumed by an upcoming PR). `serviceAccount` is kept separately from the SPIFFE path so introspection/audit doesn't need to parse it. |
| `Telemetry.tracing[].providers[]` span emission | Partial | **Inline provider config only** — provider type inferred from the `name` field (`zipkin`/`datadog`/`lightstep`/`opentelemetry`) with required URL/endpoint fields on the entry itself; captured into the mesh slice and merged into `workload_metrics.tracing_provider`. Name-only references (`{name: "my-zipkin"}`) that rely on `meshConfig.extensionProviders` / `meshConfig.defaultProviders` lookup are **not yet supported** — they are gracefully skipped with a warning. Unrecognised provider names are also skipped (not hard-failed). Only the first `providers[]` entry is surfaced; multi-provider fan-out is deferred. Span emission to provider backends is not yet wired — sink-plugin follow-up. `Telemetry.tracing[].disableSpanReporting` and per-tag `CLIENT`/`SERVER` modes are deferred. |

## Environment Variables

Mesh-specific environment variables are listed below. For the full reference of all `FERRUM_*` variables, see [configuration.md](configuration.md).

### Core

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_CONFIG_PROTOCOL` | `native` | Config consumption protocol: `native` or `xds` |
| `FERRUM_MESH_NODE_ID` | `$HOSTNAME` or `ferrum-mesh-node` | Node identifier sent to the CP |
| `FERRUM_MESH_TOPOLOGY` | `sidecar` | Topology: `sidecar`, `ambient`, `east_west_gateway`, `egress_gateway` |
| `FERRUM_MESH_WORKLOAD_SPIFFE_ID` | (none) | SPIFFE ID of this mesh workload |
| `FERRUM_MESH_WORKLOAD_LABELS` | (none) | Comma-separated `key=value` workload labels for PolicyScope matching |
| `FERRUM_MESH_TRUST_DOMAIN_ALIASES` | (none) | Additional trust domains for HBONE baggage validation |
| `FERRUM_MESH_SIDECAR_ENFORCED` | `false` | When `true`, applies Istio `Sidecar` egress scope narrowing to `services` / `service_entries` / `destination_rules` per workload. Sidecars are always parsed; this flag gates only the slice-narrowing pass. Opt in after vetting your `Sidecar` resources |
| `FERRUM_MESH_VS_HEADER_ROUTING_EXPERIMENTAL` | `false` | Enables Istio `VirtualService` method/header/queryParam predicate capture through proxy-scoped `mesh_route_dispatch` plugins; unsupported predicate-only candidates fail closed through proxy-scoped `request_termination`, and destination-only collapse rejects route-local policy that cannot be carried per rule |

### Listeners

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_INBOUND_LISTEN_ADDR` | `0.0.0.0:15006` | Sidecar inbound mTLS listener |
| `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` | `127.0.0.1:15001` | Sidecar/ambient outbound capture listener |
| `FERRUM_MESH_HBONE_LISTEN_ADDR` | `0.0.0.0:15008` | Ambient HBONE listener |
| `FERRUM_MESH_EAST_WEST_LISTEN_PORT` | `15443` | East-west gateway shared listener port |
| `FERRUM_MESH_EGRESS_LISTEN_ADDR` | `0.0.0.0:15090` | Egress gateway mTLS listener |

### DNS Proxy

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_DNS_PROXY_ENABLED` | `false` | Enable the transparent DNS proxy |
| `FERRUM_MESH_DNS_LISTEN_ADDR` | `127.0.0.1:15053` | DNS proxy listen address (UDP + TCP) |
| `FERRUM_MESH_DNS_UPSTREAM_ADDR` | `127.0.0.53:53` | Upstream resolver for non-mesh queries |
| `FERRUM_MESH_DNS_TTL_SECONDS` | `60` | TTL for mesh-resolved DNS responses |
| `FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES` | `1024` | Concurrent query semaphore limit |
| `FERRUM_MESH_CLUSTER_DOMAIN` | `cluster.local` | Kubernetes cluster domain for FQDN synthesis |
| `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY` | `allow_any` | Mesh-wide outbound policy: `allow_any` or `registry_only` |
| `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` | `502` | HTTP 4xx/5xx status returned when `registry_only` rejects an unknown HTTP-family destination |

### Identity / CA

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_CA_BACKEND` | `none` | CA backend for mesh SVID issuance: `none`, `internal`, `spire_agent` |
| `FERRUM_MESH_SPIRE_AGENT_SOCKET` | `/run/spire/sockets/agent.sock` | SPIRE Agent Workload API socket path |
| `FERRUM_MESH_CERT_TTL_SECONDS` | `3600` | Requested certificate TTL |

### xDS

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_XDS_NODE_CLUSTER` | (from `FERRUM_NAMESPACE`) | xDS `node.cluster` identity |
| `FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS` | `10` | xDS client connect timeout |

### Node Agent

| Variable | Default | Description |
|---|---|---|
| `FERRUM_NODE_AGENT_NODE_NAME` | (required) | Kubernetes node name, set via downward API (`spec.nodeName`) |
| `FERRUM_NODE_AGENT_CGROUP_ROOT` | `/sys/fs/cgroup` | cgroup v2 mount point for pod cgroup resolution |
| `FERRUM_NODE_AGENT_BPF_FS_PATH` | `/sys/fs/bpf` | BPF filesystem mount point for pinned maps |
| `FERRUM_NODE_AGENT_BPF_ELF_PATH` | build-tree path | Compiled `ferrum-ebpf` ELF (Linux `ebpf` feature only) |
| `FERRUM_NODE_AGENT_FALLBACK_MODE` | `iptables` | Behavior on kernel < 5.7: `iptables` or `fail` |
| `FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES` | (empty) | Extra namespaces to exclude (`kube-system`, `kube-public`, `kube-node-lease` always excluded) |
| `FERRUM_MESH_CAPTURE_INCLUDE_CIDRS` | `0.0.0.0/0` | CIDRs to capture for outbound traffic |
| `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS` | (empty) | CIDRs to exclude from outbound capture (highest priority) |
| `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS` | `15001,15006,15008,15020` | Destination TCP ports excluded from outbound capture |
| `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` | (empty) | Destination TCP ports excluded from inbound capture (mirrors Istio `excludeInboundPorts`; pod annotation `traffic.sidecar.istio.io/excludeInboundPorts` is additive) |

### Injector

| Variable | Default | Description |
|---|---|---|
| `FERRUM_INJECTOR_LISTEN_ADDR` | `0.0.0.0:9443` | Webhook listen address |
| `FERRUM_INJECTOR_SIDECAR_IMAGE` | `ferrum-edge:latest` | Sidecar container image |
| `FERRUM_INJECTOR_REQUIRE_ANNOTATION` | `true` | Require opt-in annotation |
| `FERRUM_INJECTOR_TLS_CERT_PATH` | (none) | Webhook TLS certificate |
| `FERRUM_INJECTOR_TLS_KEY_PATH` | (none) | Webhook TLS private key |
| `FERRUM_INJECTOR_TRUST_DOMAIN` | `cluster.local` | SPIFFE trust domain for ID derivation |
| `FERRUM_MESH_CAPTURE_MODE` | `explicit` | Traffic capture mode: `explicit`, `iptables`, `ebpf` |
| `FERRUM_MESH_PROXY_UID` | `1337` | Proxy user ID in injected sidecars |

### Shared with CP/DP

Mesh mode reuses several CP/DP environment variables. See [cp_dp_mode.md](cp_dp_mode.md) for details:

- `FERRUM_DP_CP_GRPC_URLS` (required) -- CP endpoints for config subscription.
- `FERRUM_CP_DP_GRPC_JWT_SECRET` (required) -- shared JWT secret for gRPC auth.
- `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` -- primary CP retry interval on fallback.
- `FERRUM_XDS_STREAM_CHANNEL_CAPACITY` -- per-ADS-stream response queue capacity.
- DP gRPC TLS variables (`FERRUM_DP_GRPC_TLS_*`).
