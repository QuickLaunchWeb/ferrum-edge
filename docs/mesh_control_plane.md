# Mesh Control Plane (Phase B — Layer 3)

Ferrum Edge ships two complementary mesh control protocols:

- **Envoy-compatible xDS Aggregated Discovery Service (ADS)** — the
  industry-standard mesh control protocol. Every major mesh except
  Linkerd uses xDS — Istio, Consul, Kuma, OSM, Cilium service mesh.
  This is the primary integration path: drop a Ferrum CP into an
  existing Istio cluster, point sidecars at it as the xDS server.
- **Native `MeshSubscribe` RPC** — an extension of Ferrum's existing
  `ConfigSync` gRPC service that streams a per-workload `MeshSlice` to
  Ferrum mesh data planes (Phase C). Lower-overhead than xDS for
  Ferrum-native deployments.

The same internal model (`crate::config::types::GatewayConfig` + the
`crate::config::mesh::*` types) feeds both servers.

> **Phase scope.** Phase B builds the **control protocols**. The data
> plane consumer for these protocols ships in Phase C. With
> `FERRUM_XDS_ENABLED=false` (the default) the gateway behaves
> byte-identically to a non-mesh deployment.

## Quick start

```bash
# Drop xDS into the CP runtime mode
FERRUM_MODE=cp \
  FERRUM_DB_TYPE=sqlite \
  FERRUM_DB_URL=sqlite://ferrum.db \
  FERRUM_ADMIN_JWT_SECRET="$(openssl rand -hex 32)" \
  FERRUM_CP_DP_GRPC_JWT_SECRET="$(openssl rand -hex 32)" \
  FERRUM_XDS_ENABLED=true \
  FERRUM_XDS_LISTEN_ADDR=0.0.0.0:18000 \
  ferrum-edge run
```

Verify the xDS server is running:

```bash
grpcurl -plaintext localhost:18000 list
# envoy.service.discovery.v3.AggregatedDiscoveryService
```

## xDS protocol scope

| Capability | Status |
| --- | --- |
| `StreamAggregatedResources` (SotW) | Implemented |
| `DeltaAggregatedResources` (delta) | Implemented |
| LDS (`Listener`) | Implemented |
| RDS (`RouteConfiguration`) | Implemented |
| CDS (`Cluster`) | Implemented |
| EDS (`ClusterLoadAssignment`) | Implemented |
| SDS (`Secret` — TLSCertificate + ValidationContext) | Implemented |
| Per-node ACK / NACK state | Implemented |
| Per-node snapshot isolation (security boundary) | Implemented |
| Backpressure (drop overlapping versions, never queue) | Implemented |
| `xdstp://` resource locators | Phase C |
| RBAC filter typed_per_filter_config | Phase C |
| `JwtAuthn` filter | Phase C |
| LRS (`LoadStatsReporting`) | Phase D |

Translation maps the canonical mesh model to Envoy resources. See
`src/xds/translate/{lds,rds,cds,eds,sds}.rs` for the per-resource
detail. Cluster names follow Istio's
`outbound|<port>||<svc>.<ns>.svc.cluster.local` convention so existing
tooling (`istioctl pc cluster`, Envoy `/clusters` admin) sees familiar
output.

### Per-node snapshot isolation

The xDS snapshot cache is keyed by the requesting sidecar's `Node.id`.
Workload A NEVER receives workload B's `MeshPolicy`,
`PeerAuthentication`, or trust bundle — even when both sidecars
subscribe concurrently to the same xDS server. This is a **security
boundary, not an optimisation**. The slice computation lives in
[`crate::config::mesh::slice::MeshSlice::for_workload`] and is the
single source of truth for both xDS and native `MeshSubscribe`.

## Native `MeshSubscribe` RPC

Defined in `proto/ferrum.proto` as an additive extension of the existing
`ConfigSync` service. **The existing `Subscribe` and `GetFullConfig`
RPCs are byte-identical to before** — non-mesh CP/DP deployments
observe zero regression.

```proto
service ConfigSync {
  rpc Subscribe(SubscribeRequest) returns (stream ConfigUpdate);              // existing
  rpc GetFullConfig(FullConfigRequest) returns (FullConfigResponse);          // existing
  rpc MeshSubscribe(MeshSubscribeRequest) returns (stream MeshConfigUpdate);  // new
}

message MeshSubscribeRequest {
  string node_id = 1;
  string ferrum_version = 2;
  string namespace = 3;
  string spiffe_id = 4;
  string trust_domain = 5;
}

message MeshConfigUpdate {
  enum UpdateType { FULL_SNAPSHOT = 0; DELTA = 1; }
  UpdateType update_type = 1;
  string mesh_slice_json = 2;
  string version = 3;
  int64 timestamp = 4;
  string ferrum_version = 5;
}
```

`mesh_slice_json` is the JSON-encoded
[`MeshSlice`](../src/config/mesh/slice.rs) — only the resources the
workload identified by `spiffe_id` needs:

- The `Workload` itself
- `MeshService`s it can reach as a client (same-namespace + reachable
  ServiceEntries)
- `MeshPolicy`s scoping it OR naming it in `from`
- `PeerAuthentication`s scoping it
- `ServiceEntry`s in scope (same-namespace + mesh-external)
- `TrustBundleSet` (full federated set)

JSON keeps the wire format mirror-symmetric with the existing
`ConfigSync` RPCs and lets us add mesh fields without per-field proto
schema churn.

### Authentication

Both `MeshSubscribe` and the existing `Subscribe`/`GetFullConfig` use
the same HS256 JWT in the `authorization` gRPC metadata key, signed
with `FERRUM_CP_DP_GRPC_JWT_SECRET`. JWT secret rotation is per CP
restart (matches the existing CP/DP rotation contract).

## Migration path: drop into Istio

The most common Phase B integration is replacing pilot's xDS with
Ferrum's xDS:

1. Run Ferrum CP with `FERRUM_XDS_ENABLED=true` and
   `FERRUM_XDS_LISTEN_ADDR=0.0.0.0:15010` (Istio's plaintext xDS port)
   or `:15012` (mTLS).
2. Update each workload's `discoveryAddress` (Istio sidecar config) to
   point at the Ferrum CP instead of `istiod`.
3. Provision Ferrum-side `Workload` / `MeshService` /
   `PeerAuthentication` / `MeshPolicy` resources to mirror the
   equivalent Istio CRDs. Phase D will introduce CRD watchers that
   automate this; for Phase B operators provision via the admin API.
4. Sidecars subscribe to Ferrum's xDS server. The Istio
   sidecar-injection annotations remain unchanged — the sidecar still
   speaks xDS, only the management server changed.

## Environment variables

| Var | Default | Purpose |
| --- | --- | --- |
| `FERRUM_XDS_ENABLED` | `false` | Gate the xDS server. When false, all xDS code paths are dormant. |
| `FERRUM_XDS_LISTEN_ADDR` | `0.0.0.0:18000` | xDS gRPC bind address. Istio's pilot default is 15010 plaintext / 15012 mTLS — set this to match if you're replacing pilot. |
| `FERRUM_XDS_TLS_CERT_PATH` | unset | Optional PEM cert. With `FERRUM_XDS_TLS_KEY_PATH` enables mTLS-protected xDS. |
| `FERRUM_XDS_TLS_KEY_PATH` | unset | Optional PEM key matching `FERRUM_XDS_TLS_CERT_PATH`. |
| `FERRUM_XDS_REQUIRE_AUTHENTICATED_CLIENT` | `true` | Reject xDS subscriptions without a verified JWT (uses `FERRUM_CP_DP_GRPC_JWT_SECRET`). Set to `false` only for local testing. |
| `FERRUM_XDS_MAX_CONCURRENT_STREAMS` | `1000` | HTTP/2 max concurrent streams. Soft cap on parallel sidecar subscriptions. |

## Testing

- **Unit tests** (`tests/unit/xds/`):
  - `node_tests.rs` — Node parsing, metadata extraction
  - `snapshot_tests.rs` — version bump on change, no-bump on no-change, per-node isolation
  - `translate_tests.rs` — round-trip Layer-2-model → Envoy proto, asserting on critical fields
  - `delta_tests.rs` — added/removed/updated resource diff math
  - `mesh_slice_tests.rs` — security-boundary tests for slice isolation
- **Integration tests** (`tests/integration/`):
  - `xds_sotw_tests.rs` — minimal in-test xDS client over tonic; full SotW flow including ACK suppression
  - `xds_delta_tests.rs` — same flow over delta xDS, plus removed-resource diff
  - `xds_node_isolation_tests.rs` — two nodes with different identities subscribed concurrently get disjoint resources
  - `mesh_subscribe_tests.rs` — `MeshSubscribe` end-to-end + smoke check that the existing `Subscribe` RPC is unchanged

Run the full xDS test set with:

```bash
cargo test --test unit_tests xds
cargo test --test integration_tests xds
cargo test --test integration_tests mesh_subscribe
```

## Out of scope for Phase B (tracked for later phases)

- Mesh runtime mode for the data plane (Phase C)
- Data-plane consumers for xDS / `MeshSubscribe` (Phase C)
- CRD watchers for K8s `AuthorizationPolicy` / `PeerAuthentication` /
  `Service` (Phase D)
- HBONE / traffic capture / sidecar injection (out of plan)
- LRS / EDS load reporting (Phase D)

See `CLAUDE.md` for the broader mesh layering plan.
