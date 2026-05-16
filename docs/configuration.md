# Configuration Reference

Ferrum Edge is configured primarily through environment variables. An optional `ferrum.conf` file can provide defaults.

This page is the canonical human-readable reference for `FERRUM_*` variables and built-in defaults. Runtime behavior is defined in [`src/config/env_config.rs`](../src/config/env_config.rs); the root `ferrum.conf` is an editable operator template that mirrors this reference with concise comments and example values. When variables or defaults change, update the code, this reference, and then `ferrum.conf` so the template stays in sync without becoming the primary reference.

## Environment Variables

### Core Settings

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_CONF_PATH` | No | `./ferrum.conf` | Path to optional conf file (provides defaults; env vars override) |
| `FERRUM_MODE` | **Yes** | — | Operating mode: `database`, `file`, `cp`, `dp`, `mesh`, `injector`, `migrate` |
| `FERRUM_NAMESPACE` | No | `ferrum` | Namespace this gateway loads and manages |
| `FERRUM_LOG_LEVEL` | No | `error` | Log verbosity: `error`, `warn`, `info`, `debug`, `trace` |
| `FERRUM_LOG_BUFFER_CAPACITY` | No | `128000` | Max buffered log lines in the non-blocking writer channel. When full, new events are dropped to avoid backpressure on request threads |
| `FERRUM_LOG_REDACT_METADATA_KEYS` | No | — | Comma-separated additional metadata-key substrings to redact from `TransactionSummary.metadata` and `StreamTransactionSummary.metadata` before log serialization. Built-in sensitive substrings such as `authorization`, `cookie`, `password`, `secret`, and `token` are always redacted. Operators can further reshape per-plugin log output (rename keys, drop fields, reorder, add static / derived fields, flatten metadata, change timestamp format) via per-logging-plugin `schema:` blocks or a shared `transaction_log_schema` plugin — see [docs/log_schema.md](log_schema.md) |
| `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` | No | `30` | Timeout for each external secret fetch during startup |

### Proxy Listener

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_PROXY_HTTP_PORT` | No | `8000` | HTTP proxy listener port. Set to `0` to disable the plaintext HTTP listener (TLS-only operation) |
| `FERRUM_PROXY_HTTPS_PORT` | No | `8443` | HTTPS proxy listener port |
| `FERRUM_PROXY_BIND_ADDRESS` | No | `0.0.0.0` | Bind address for proxy listeners (HTTP, HTTPS, HTTP/3). Set to `::` for dual-stack IPv4+IPv6 |
| `FERRUM_FRONTEND_TLS_CERT_PATH` | If HTTPS | — | PEM certificate the gateway presents to incoming clients (HTTPS, WebSocket, gRPC, TCP/TLS) |
| `FERRUM_FRONTEND_TLS_KEY_PATH` | If HTTPS | — | PEM private key for the gateway's frontend TLS certificate |
| `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` | No | `10` | Seconds allowed for frontend TLS/DTLS handshakes before HTTP header parsing or stream proxy handling begins. `0` disables |

### Admin API

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ADMIN_HTTP_PORT` | No | `9000` | Admin API HTTP port. Set to `0` to disable the plaintext admin HTTP listener (TLS-only operation) |
| `FERRUM_ADMIN_HTTPS_PORT` | No | `9443` | Admin API HTTPS port |
| `FERRUM_ADMIN_BIND_ADDRESS` | No | `0.0.0.0` | Bind address for admin listeners (HTTP, HTTPS). Set to `::` for dual-stack IPv4+IPv6 |
| `FERRUM_ADMIN_ALLOWED_CIDRS` | No | — | Comma-separated CIDRs/IPs allowed to connect to the admin API. Empty permits all |
| `FERRUM_ADMIN_TLS_CERT_PATH` | If HTTPS | — | Path to admin TLS certificate |
| `FERRUM_ADMIN_TLS_KEY_PATH` | If HTTPS | — | Path to admin TLS private key |
| `FERRUM_ADMIN_JWT_SECRET` | DB/CP modes | — | HS256 secret for Admin API JWT auth. Must be at least 32 characters |
| `FERRUM_ADMIN_JWT_ISSUER` | No | `ferrum-edge` | Required `iss` claim for Admin API JWT tokens |
| `FERRUM_ADMIN_JWT_MAX_TTL` | No | `3600` | Maximum accepted token lifetime (`exp - iat`) for externally minted Admin API JWTs |
| `FERRUM_ADMIN_READ_ONLY` | No | `false` | Set Admin API to read-only mode (DP mode defaults to true) |
| `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` | No | — | PEM CA bundle for Admin API client certificate verification |
| `FERRUM_ADMIN_TLS_NO_VERIFY` | No | `false` | Skip Admin API TLS certificate verification (testing only) |
| `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` | No | `100` | Max request body size in MiB for `POST /restore` |
| `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB` | No | `25` | Max request body size in MiB for `POST/PUT /api-specs`. Specs are stored gzip-compressed; large API definitions (e.g. AWS combined services) can approach 30–50 MiB uncompressed. MongoDB backends are additionally bounded by the BSON 16 MB document limit, enforced at write time |

### Database

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DB_TYPE` | DB/CP modes | — | Database type: `postgres`, `mysql`, `sqlite`, `mongodb` |
| `FERRUM_DB_URL` | DB/CP modes | — | Database connection string. For MongoDB: `mongodb://` or `mongodb+srv://` |
| `FERRUM_DB_POLL_INTERVAL` | No | `30` | Seconds between DB config polls. Incremental polling is always enabled with automatic fallback to full reload on error. |
| `FERRUM_DB_CONFIG_BACKUP_PATH` | No | — | Path to externally provided JSON config backup. Used as startup fallback when the database is unreachable. |
| `FERRUM_DB_FAILOVER_URLS` | No | — | Comma-separated failover database URLs. For MongoDB replica sets, prefer listing all members in `FERRUM_DB_URL` instead |
| `FERRUM_DB_READ_REPLICA_URL` | No | — | Read replica URL for config polling (SQL only). For MongoDB, use `readPreference` in the connection string |
| `FERRUM_DB_SLOW_QUERY_THRESHOLD_MS` | No | — | Log database queries slower than this threshold |
| `FERRUM_DB_FULL_LOAD_PAGE_SIZE` | No | `10000` | Max rows per query during full config loading (SQL only). Clamped to 100..=100000 |

#### Database Backend Applicability

| Setting family | PostgreSQL | MySQL | SQLite | MongoDB |
|---|---|---|---|---|
| Core `FERRUM_DB_TYPE`, `FERRUM_DB_URL`, `FERRUM_DB_POLL_INTERVAL`, `FERRUM_DB_CONFIG_BACKUP_PATH`, `FERRUM_DB_SLOW_QUERY_THRESHOLD_MS` | Yes | Yes | Yes | Yes |
| `FERRUM_DB_FAILOVER_URLS` | Yes | Yes | Yes | Yes, but replica sets should list all members in `FERRUM_DB_URL` |
| `FERRUM_DB_READ_REPLICA_URL` | Yes | Yes | No | No; use MongoDB `readPreference` |
| `FERRUM_DB_TLS_MODE` and DB TLS certificate paths | Yes | Yes | `disable` only as a no-op; cert paths rejected | Yes; `disable`, `require`, and `verify-full` via MongoDB driver `TlsOptions` |
| `FERRUM_DB_FULL_LOAD_PAGE_SIZE` | Yes | Yes | Yes | Ignored; MongoDB uses cursor-based loading |
| `FERRUM_DB_POOL_*` SQL pool fields | Yes | Yes | Yes | Ignored; use MongoDB URI pool options such as `maxPoolSize` and `minPoolSize` |
| `FERRUM_MONGO_*` fields | No | No | No | Yes |

#### MySQL minimum version

MySQL backends require **MySQL 8.0+**. The V001 schema applies an explicit
`COLLATE utf8mb4_0900_as_cs` on identifier columns (`id`, `namespace`, `name`,
`username`, `custom_id`, `plugin_name`, `proxy_id`, `upstream_id`,
`upstream_subset`, `api_spec_id`, `content_hash`, `spec_version`,
`backend_host`, `backend_tls_sni`), which is only available on MySQL 8.0 and
later. This makes uniqueness on `(namespace, name)`, `(namespace, username)`,
etc. **byte-exact** rather than the case-insensitive default — so `Alpha` and
`alpha` are distinct identifiers on MySQL just as they are on PostgreSQL and
SQLite. Operators upgrading a populated 5.x MySQL deployment must run the
matching `ALTER TABLE ... CONVERT TO CHARACTER SET utf8mb4 COLLATE
utf8mb4_0900_as_cs` themselves; this is consistent with the build-out
compatibility policy of folding schema changes into the V001 baseline rather
than shipping incremental migrations.

### Database TLS

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DB_TLS_MODE` | No | — | Database TLS policy. PostgreSQL: `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`; MySQL: `disable`, `prefer`, `require`, `verify-ca`, `verify-full`; MongoDB: `disable`, `require`, `verify-full` |
| `FERRUM_DB_TLS_CA_CERT_PATH` | No | — | Path to CA certificate for database server verification |
| `FERRUM_DB_TLS_CLIENT_CERT_PATH` | No | — | Path to client certificate for database mTLS. SQL requires pairing with `FERRUM_DB_TLS_CLIENT_KEY_PATH`; MongoDB may use this alone as an already-combined cert+key PEM |
| `FERRUM_DB_TLS_CLIENT_KEY_PATH` | No | — | Path to client private key for database mTLS; must be paired with `FERRUM_DB_TLS_CLIENT_CERT_PATH` |

See [database_tls.md](database_tls.md) for detailed configuration examples and TLS mode descriptions.

### Database Pool

SQL pool settings apply to PostgreSQL, MySQL, and SQLite. MongoDB uses driver connection-string pool options such as `maxPoolSize` and `minPoolSize`.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DB_POOL_MAX_CONNECTIONS` | No | `32` | Maximum SQL pool connections |
| `FERRUM_DB_POOL_MIN_CONNECTIONS` | No | `1` | Minimum idle SQL pool connections |
| `FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS` | No | `30` | Max wait for a pool connection |
| `FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS` | No | `600` | Max idle age before a SQL connection is closed |
| `FERRUM_DB_POOL_MAX_LIFETIME_SECONDS` | No | `300` | Max SQL connection lifetime |
| `FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS` | No | `10` | Max TCP connect time for new database connections; `0` disables |
| `FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS` | No | `30` | Per-statement SQL timeout; `0` disables |

### MongoDB

These settings only apply when `FERRUM_DB_TYPE=mongodb`. `FERRUM_DB_POOL_*` settings are SQL-only and ignored for MongoDB.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MONGO_DATABASE` | No | `ferrum` | MongoDB database name |
| `FERRUM_MONGO_APP_NAME` | No | — | App name for server-side connection tracking |
| `FERRUM_MONGO_REPLICA_SET` | No | — | Replica set name. Required for transactions and change streams |
| `FERRUM_MONGO_AUTH_MECHANISM` | No | (auto) | Auth mechanism override: `SCRAM-SHA-256`, `MONGODB-X509`, etc. |
| `FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS` | No | `30` | Server selection timeout |
| `FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS` | No | `10` | TCP connection timeout |

See [mongodb.md](mongodb.md) for the full deployment guide including read preference, replica sets, Atlas, and Kubernetes examples.

### File Mode

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_FILE_CONFIG_PATH` | File mode | — | Path to YAML/JSON config file |

### Control Plane / Data Plane

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_CP_GRPC_LISTEN_ADDR` | No | `0.0.0.0:50051` in CP mode | gRPC listen address. Port `0` disables plaintext gRPC |
| `FERRUM_CP_DP_GRPC_JWT_SECRET` | CP, DP & mesh modes | — | Shared JWT secret for CP/DP/mesh gRPC auth (DP/mesh clients generate short-lived JWTs, CP validates). Must be at least 32 characters |
| `FERRUM_CP_GRPC_TLS_CERT_PATH` | If CP gRPC TLS | — | CP gRPC server TLS certificate |
| `FERRUM_CP_GRPC_TLS_KEY_PATH` | If CP gRPC TLS | — | CP gRPC server TLS private key |
| `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` | No | — | CA bundle for verifying DP client certificates (mTLS) |
| `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY` | No | `128` | Per-channel capacity for the CP's two independent broadcast channels (one for DP `ConfigSync.Subscribe`, one for mesh `MeshConfigSync.MeshSubscribe`). Lagging subscribers on either channel auto-recover with a full snapshot |
| `FERRUM_XDS_ENABLED` | No | `false` | Enable Phase B xDS ADS (`StreamAggregatedResources` and `DeltaAggregatedResources`) on the CP gRPC listener |
| `FERRUM_XDS_STREAM_CHANNEL_CAPACITY` | No | `32` | Per-ADS-stream response queue capacity before slow xDS readers apply backpressure to their own stream task |
| `FERRUM_DP_CP_GRPC_URLS` | DP/mesh mode | — | Comma-separated priority-ordered CP URLs for DP/mesh failover |
| `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` | No | `300` | Retry primary CP interval (seconds) when connected to a fallback. `0` = disabled |
| `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` | No | — | CA certificate for verifying the CP server |
| `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` | No | — | DP client certificate for CP mTLS |
| `FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH` | No | — | DP client private key for CP mTLS |
| `FERRUM_DP_GRPC_TLS_NO_VERIFY` | No | `false` | Skip DP gRPC TLS verification (testing only) |

See [cp_dp_mode.md](cp_dp_mode.md) for CP/DP TLS environment variables (`FERRUM_CP_GRPC_TLS_*`, `FERRUM_DP_GRPC_TLS_*`) and [multi_region_ha.md](multi_region_ha.md) for multi-region deployment patterns.

### Mesh Runtime

Mesh mode consumes Layer 2 mesh slices from the control protocols and prepares the shared sidecar/ambient data-plane listeners. Non-mesh modes do not instantiate this runtime.

With the native `MeshSubscribe` protocol, mesh mode waits for the first delivered mesh slice before serving, builds the proxy/plugin runtime from that slice, and hot-applies later valid slices atomically. Duplicate-content slices are skipped before rebuilding the proxy runtime. Invalid slice updates are logged and ignored so the last accepted runtime config keeps serving. The xDS ADS consumer coalesces bursts with a short debounce and a bounded max-delay cap, so continuous control-plane churn cannot indefinitely postpone applying the latest valid snapshot.

With the xDS ADS protocol, invalid resource updates are NACKed and the last accepted snapshot remains active. If one known xDS resource type produces 5 consecutive NACKs without an ACK, the mesh client closes that ADS stream and relies on the existing reconnect/failover loop instead of NACKing the same bad control-plane state forever. In a single-CP deployment that keeps serving the same invalid resource, this becomes a bounded reconnect/NACK cycle governed by the normal jittered backoff until the CP config is corrected. Unknown type URLs are NACKed but not counted in the breaker because this client can never ACK them. Any already-ACKed slice waiting in the debounce window is applied before the stream is closed so reconnect version hints cannot advance past the local runtime.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MESH_CONFIG_PROTOCOL` | No | `native` | Mesh config source. `native` uses Ferrum `MeshSubscribe`; `xds` uses the mesh ADS client against a Ferrum or compatible xDS control plane |
| `FERRUM_MESH_XDS_NODE_CLUSTER` | No | `FERRUM_NAMESPACE` | xDS `Node.cluster` identity sent by mesh-mode ADS clients |
| `FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS` | No | `10` | Mesh xDS client connect timeout. `0` disables the explicit tonic connect timeout |
| `FERRUM_MESH_NODE_ID` | No | `$HOSTNAME` or `ferrum-mesh-node` | Stable mesh data-plane node ID used for xDS/MeshSubscribe |
| `FERRUM_MESH_TOPOLOGY` | No | `sidecar` | Mesh topology flag: `sidecar`, `ambient`, `east_west_gateway`, or `egress_gateway`. All share the same data-plane path |
| `FERRUM_MESH_INBOUND_LISTEN_ADDR` | No | `0.0.0.0:15006` | Sidecar inbound mTLS listener address |
| `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` | No | `127.0.0.1:15001` | Mesh outbound capture listener address for plaintext-in to mTLS-out or HBONE encapsulation |
| `FERRUM_MESH_HBONE_LISTEN_ADDR` | No | `0.0.0.0:15008` | Ambient HBONE termination listener address (Istio-flavored HBONE over mTLS) |
| `FERRUM_MESH_EAST_WEST_LISTEN_PORT` | No | `15443` | Shared TCP passthrough listener port for `east_west_gateway` topology; routes by TLS SNI using `mesh.multi_cluster.east_west_gateways` |
| `FERRUM_MESH_EGRESS_LISTEN_ADDR` | No | `0.0.0.0:15090` | Egress gateway mTLS listener address for `egress_gateway` topology. Requires `FERRUM_FRONTEND_TLS_CERT_PATH`, `FERRUM_FRONTEND_TLS_KEY_PATH`, and `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` |
| `FERRUM_MESH_WORKLOAD_SPIFFE_ID` | No | — | Optional workload SPIFFE ID hint sent to native MeshSubscribe |
| `FERRUM_MESH_WORKLOAD_LABELS` | No | — | Workload labels for this mesh data plane (`k1=v1,k2=v2`). Drives `mesh_authz` `PolicyScope` filtering and `PeerAuthentication` selector filtering. For authorization, only policies whose scope (`MeshWide`, `Namespace`, or `WorkloadSelector`) matches these labels apply to this proxy. Set explicitly for current Kubernetes and non-K8s deployments; the injector can later populate this from pod labels via the downward API |
| `FERRUM_MESH_CA_BACKEND` | No | `none` | Mesh certificate authority backend: `internal` (Ferrum's own CA, requires `FERRUM_MESH_CA_CERT_PATH` / `FERRUM_MESH_CA_KEY_PATH`), `spire` (delegate to a SPIRE Agent over UDS), `none` (mesh identity disabled) |
| `FERRUM_MESH_SPIRE_AGENT_SOCKET` | No | `/run/spire/sockets/agent.sock` | Path to the SPIRE Agent's Workload API Unix domain socket. Only used when `FERRUM_MESH_CA_BACKEND=spire` |
| `FERRUM_MESH_CERT_TTL_SECONDS` | No | `3600` | SVID lifetime hint (seconds) passed to the CA backend. The CA may clamp or ignore this value |
| `FERRUM_MESH_CAPTURE_MODE` | No | `explicit` | Traffic capture mode used by injector/capture planning: `explicit`, `iptables`, or `ebpf`. eBPF always falls back to iptables when unsupported |
| `FERRUM_MESH_PROXY_UID` | No | `1337` in injector patches | UID used to exempt Ferrum's own outbound traffic from iptables capture |
| `FERRUM_MESH_IP6TABLES_ENABLED` | No | `auto` | IPv6 iptables fan-out: `auto` probes and skips IPv6 rules when `ip6tables` is unavailable, `true` requires it when IPv6 CIDRs are configured and fails all capture setup before IPv4 rules if unavailable, `false` emits IPv4-only capture rules |
| `FERRUM_MESH_TRUST_DOMAIN_ALIASES` | No | — | Comma-separated SPIFFE trust domains accepted as equivalent to the peer cert's trust domain when validating HBONE baggage `source.principal`. Default empty: strict same-trust-domain match. Mirror of Istio `MeshConfig.trustDomainAliases` for federated multi-cluster setups |
| `FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS` | No | — | Comma-separated W3C `baggage` key prefixes stripped from outbound requests at dispatch. Default empty: forward unchanged for ordinary egress. Gateway-originated HBONE inner requests always strip identity-shaped baggage keys (`source.*`, `destination.*`, and aliases) while preserving non-identity baggage |
| `FERRUM_MESH_SIDECAR_ENFORCED` | No | `false` | When `true`, the slice builder applies Istio `Sidecar` egress scope narrowing: services, service-entries, and destination-rules outside the applicable `Sidecar`'s egress scope are filtered out before being sent to data planes. `Sidecar` resources are parsed and persisted unconditionally; this flag only gates the slice-narrowing pass so operators can opt in after vetting their `Sidecar` definitions |
| `FERRUM_MESH_DNS_PROXY_ENABLED` | No | `false` | Enable the transparent mesh DNS proxy. Requires traffic capture rules to redirect workload DNS traffic to `FERRUM_MESH_DNS_LISTEN_ADDR` |
| `FERRUM_MESH_DNS_LISTEN_ADDR` | No | `127.0.0.1:15053` | UDP/TCP listen address for transparent DNS. TCP is used for truncated responses and resolver fallback |
| `FERRUM_MESH_DNS_UPSTREAM_ADDR` | No | `127.0.0.53:53` | Upstream DNS resolver for non-mesh names. The default targets systemd-resolved; set this to your node, pod, or cluster resolver (for example CoreDNS) in non-systemd environments |
| `FERRUM_MESH_DNS_TTL_SECONDS` | No | `60` | TTL used for synthetic A/AAAA records resolved from mesh ServiceEntry and MeshService state |
| `FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES` | No | `1024` | Maximum admitted DNS query tasks and outstanding upstream UDP forwards before the proxy returns SERVFAIL |
| `FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES` | No | `4096` | Maximum per-slice cached synthetic mesh DNS response templates. Raise for very large meshes with many service names, qtypes, EDNS sizes, or wildcard variants |
| `FERRUM_MESH_CLUSTER_DOMAIN` | No | `cluster.local` | Kubernetes cluster DNS domain used when synthesizing `{service}.{namespace}.svc.<domain>` names |
| `FERRUM_MESH_CA_BACKEND` | No | `none` | CA backend for mesh SVID issuance: `none` (no automatic identity), `internal` (self-signed dev CA), `spire_agent` (SPIRE Workload API) |
| `FERRUM_MESH_SPIRE_AGENT_SOCKET` | No | `/run/spire/sockets/agent.sock` | SPIRE Agent Workload API Unix socket path. Only used when `FERRUM_MESH_CA_BACKEND=spire_agent` |
| `FERRUM_MESH_CERT_TTL_SECONDS` | No | `3600` | Requested certificate TTL for issued SVIDs |
| `FERRUM_MESH_VS_HEADER_ROUTING_EXPERIMENTAL` | No | `false` | Opt-in: emit `mesh_route_dispatch` plugin instances for Istio VirtualService routes with method/header/queryParam predicates. The K8s translator captures supported predicates as plugin config (with `reject_unmatched: true` so requests that miss the predicates return 404 instead of falling through to the default backend, preserving VS match semantics); unsupported predicate-only route candidates emit proxy-scoped `request_termination` instead of widening traffic. Same-path and URI-less ordered canary/default routes collapse into one Proxy with ordered dispatch rules so misses can fall through when a later route exists. If such a collapse would need per-route `fault`, `retries`, or `timeout` behavior to apply only to one dispatch rule, translation fails closed because that policy cannot yet be represented per rule. The data plane plumbs route overrides through `RequestContext.route_override_*` so downstream pool keys, capability registry, and circuit-breaker target keys derive from the effective destination. Admission plugins still evaluate the original public proxy identity. Default false (predicates dropped — existing behavior) |
| `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY` | No | `allow_any` | Istio-compatible mesh-wide outbound policy: `allow_any` (no gate) or `registry_only` (auto-inject `mesh_outbound_registry` plugin on topologies with an outbound capture listener; destinations outside services, ServiceEntries including wildcard hosts, and workload addresses are rejected with `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS`; inbound sidecar/ambient traffic is not gated; an empty registry fails closed). Native/CRD slice-supplied `outbound_traffic_policy` takes precedence when present; xDS ADS uses this env fallback until MeshConfig translation is wired |
| `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` | No | `502` | HTTP 4xx/5xx status returned by the auto-injected `mesh_outbound_registry` plugin when `registry_only` rejects an unknown destination |

Mesh DNS caches serialized response templates per mesh slice for mesh-owned names, bounded by `FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES` (default 4,096). The cache is rebuilt with the slice, excludes the client transaction ID, and patches the caller's ID into each returned response, so repeated A/AAAA and mesh-owned empty responses avoid repeated wire-format serialization without leaking IDs across clients.

Mesh DNS forwards non-mesh UDP queries through a shared upstream socket with rewritten transaction IDs. If all 65,536 upstream IDs are simultaneously in flight, the proxy SERVFAILs the new query and increments `ferrum_mesh_dns_upstream_id_exhaustions_total` in the Prometheus registry so resolver outages or pathological query bursts are visible. The counter is process-wide and intentionally has no namespace label because the upstream UDP socket is process-wide. The counter is emitted from startup with value `0` so first-event alerting has a stable series.

Mesh observability emits Istio/GAMMA-shaped RED metrics through the existing Prometheus plugin when mesh metadata is present. The added series are `ferrum_mesh_requests_total` and `ferrum_mesh_request_duration_ms`, labelled with source/destination workload, namespace, principal, app, service, request protocol, response code, response flags, and connection security policy. HBONE tunnel copy failures after a CONNECT response has already been sent increment `ferrum_mesh_hbone_relay_failures_total` with `proxy_id`, `direction`, and `error_class` labels.

HBONE identity metadata is read from all `baggage` headers on authenticated HBONE requests where the peer already presented a SPIFFE identity. Baggage values may be percent-encoded, and Ferrum decodes them before extracting `source.principal` or `destination.principal`. Baggage parsing and egress stripping are quoted-value aware, so user-defined members with quoted commas are preserved. Plain HTTP requests, or requests without an authenticated peer, cannot supply `source.principal` through baggage for `mesh_authz` or `workload_metrics`; when unauthenticated HBONE baggage is present, Ferrum stamps `mesh_authz.ignored_baggage.unauthenticated = "true"` and `mesh.ignored_baggage = "unauthenticated_hbone"` for log triage.

Baggage SPIFFE identities are additionally gated by trust-domain matching: a baggage `source.principal` is honored only when its SPIFFE trust domain matches the peer cert's trust domain, or appears in `FERRUM_MESH_TRUST_DOMAIN_ALIASES`. Mismatches stamp `mesh_authz.ignored_baggage.trust_domain_mismatch = "true"` and keep `mesh_authz.ignored_baggage` as a comma-separated compatibility summary (and `mesh.ignored_baggage` from `workload_metrics`); the gateway falls back to the peer cert's identity. When the resulting authorization is rejected, the deny policy is annotated as `trust_domain_mismatch` for audit log triage.

HBONE CONNECT streams are always kept in streaming mode through authentication so the HTTP/2 upgrade handle remains available to the tunnel relay. Request-body plugins that run after authentication are skipped by the HBONE relay path. Security note: auth plugins that normally require pre-auth body buffering, such as digest-backed `hmac_auth`, authenticate against the CONNECT headers and an empty request body digest instead of consuming DATA frames before the tunnel is established. Do not rely on HMAC body-integrity checks to cover HBONE tunnel payload bytes; enforce tunnel payload policy with mesh identity, authorization, and workload controls instead.

Operators may strip mesh-internal baggage members at egress via `FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS`. Members whose key starts with any configured prefix are removed from the `baggage` header before backend dispatch; the rest of the baggage (e.g., user-defined tracing keys) propagates verbatim. The default empty list is a no-op for ordinary egress. Gateway-originated HBONE tunnels additionally strip identity-shaped baggage (`source.*`, `source_*`, `destination.*`, `destination_*`, `src.*`, `src_*`, `dst.*`, `dst_*`) from the inner HTTP request; the trusted gateway identity is sent only on the CONNECT-level baggage that the receiving sidecar validates against SPIFFE mTLS.

Layer 10 multi-cluster configuration lives under `mesh.multi_cluster` in the canonical config. Remote clusters carry trust domains and federation endpoints, VM `WorkloadEntry` resources populate workload addresses/network/cluster metadata, and east-west gateway entries are materialized as SNI-routed passthrough stream proxies only in `east_west_gateway` topology.

### Kubernetes Mesh Integration

Phase D adds Kubernetes source translation and sidecar-injector scaffolding. Kubernetes resources translate into `GatewayConfig` / `MeshConfig`; no config source talks directly to the proxy runtime or xDS server.

Istio `DestinationRule` resources are translated: `connectionPool.tcp.connectTimeout` maps to `backend_connect_timeout_ms`, `outlierDetection` maps to passive health checks (`consecutive5xxErrors`, `interval`, `baseEjectionTime`), `loadBalancer` maps to Ferrum algorithms (`ROUND_ROBIN`, `LEAST_REQUEST`/`LEAST_CONN`, `RANDOM`, `consistentHash`), and `subsets` are preserved with per-subset traffic policy overrides. DestinationRule TLS settings (`trafficPolicy.tls`) and port-level traffic policy overrides are deferred — use per-proxy `backend_tls_*` fields.

Istio `VirtualService` per-route features are translated: `retries` maps to Ferrum `RetryConfig` (with `retryOn` tokens for `5xx`, `gateway-error`, `connect-failure`, `reset`, `retriable-4xx`, and numeric status codes), `timeout` maps to `backend_read_timeout_ms` (Go-style duration strings: `10s`, `500ms`, `1m`, `1h`), and `fault` injection maps to proxy-scoped `fault_injection` plugin instances (`abort.httpStatus`/`percentage` and `delay.fixedDelay`/`percentage`).

Istio `AuthorizationPolicy` `requestPrincipals` field is enforced: the `jwks_auth` plugin emits `{issuer}/{subject}` as `request_principal` metadata, and `mesh_authz` evaluates `request_principals` glob patterns against it. Non-empty `request_principals` with no JWT present results in implicit deny (Istio semantics for anonymous requests).

The following Istio surfaces remain deferred: `EnvoyFilter`, `ProxyConfig`, `WasmPlugin`, `WorkloadEntry` VM lifecycle (Pod auto-discovery and status reporting — `weight`, `locality`, `serviceAccount` are translated as metadata; locality-aware load balancing follows in a separate PR), and `AuthorizationPolicy` negative-match fields (`notMethods`, `notPaths`, `notHosts`, `notPorts` — rejected at translation time). Configure equivalent behavior with Ferrum proxy/upstream fields where available. Telemetry tracing providers support inline config plus name-only lookup through `meshConfig.extensionProviders` and `meshConfig.defaultProviders.tracing`. The outbound port inclusion annotations (`traffic.sidecar.istio.io/includeOutboundPorts` and `ferrum.io/includeOutboundPorts`), outbound port exclusion annotations (`traffic.sidecar.istio.io/excludeOutboundPorts` and `ferrum.io/excludeOutboundPorts`), inbound port exclusion annotations (`traffic.sidecar.istio.io/excludeInboundPorts` and `ferrum.io/excludeInboundPorts`), and CIDR-range capture annotations (`traffic.sidecar.istio.io/excludeOutboundIPRanges`, `traffic.sidecar.istio.io/includeOutboundIPRanges`) are supported and merged into the iptables capture plan.

Gateway API `HTTPRoute.backendRefs` and Istio `VirtualService.http[].route` splits are preserved during translation. A single backend becomes a direct Ferrum proxy backend; multiple non-zero backends create a generated `Upstream` and the proxy references it through `upstream_id`. Generated upstreams use `weighted_round_robin` only when backend weights differ, otherwise `round_robin`. Each HTTPRoute `matches[]` path and each VirtualService `match[]` URI, including regex URI matches, becomes its own proxy, so path alternatives are not collapsed into the first match. Empty HTTPRoute match entries and omitted `matches` / `match` fields create the route's default catch-all `/` proxy. Explicit HTTPRoute header/method-only matches are skipped because Ferrum route proxies do not encode those predicates yet. Istio `VirtualService` method/header/queryParam matches are emitted only when `FERRUM_MESH_VS_HEADER_ROUTING_EXPERIMENTAL=true`, using `mesh_route_dispatch`; same-path and URI-less ordered routes are collapsed into ordered dispatch-rule lists when needed to preserve fall-through to later routes, URI-less matches use a regex catch-all so they do not shadow real regex URI routes, and unsupported predicate-only candidates emit proxy-scoped `request_termination` instead of materializing unguarded proxies or falling through to later broader routes. Ordered-route collapse is destination-only today: if a collapsed candidate or the proxy it would decorate has route-local `fault`, `retries`, or `timeout` policy that would need to vary per dispatch rule, translation rejects the VirtualService instead of applying that policy to the wrong traffic. GRPCRoute method/service matches continue to translate to a deduplicated catch-all `/` proxy because gRPC method selection is encoded in the HTTP path at request time. Gateway API `weight: 0` backendRefs are skipped; if every backendRef in a matched rule has `weight: 0`, Ferrum emits a generated `ferrum-zero-weight.invalid:65535` blackhole backend so the rule still captures traffic instead of falling through to a later route. That blackhole currently fails as a backend/DNS resolution failure, typically a 502, rather than a synthesized 503. In Istio multi-destination splits, omitted weights and `weight: 0` destinations are inactive; a lone Istio destination still receives all traffic. Malformed or out-of-range route weights are rejected during translation. Kubernetes Gateway API route translation currently supports numeric backend ports only; resolving `Service.spec.ports[].name` from a Gateway API `backendRef` is not yet implemented. Istio `VirtualService` destinations support both `port.number` and `port.name`; named ports are resolved against the `Service.spec.ports[].name` index built from collected core/v1 `Service` objects in the same translation batch. The cluster domain suffix for FQDN host matching is configurable via `FERRUM_K8S_CLUSTER_DOMAIN` (default `cluster.local`).

Translation notes: Istio `AuthorizationPolicy` resources preserve Istio's action semantics. An `ALLOW` policy with no `rules` is treated as allow-nothing for the selected workload, so it creates a mesh authorization rule that never matches instead of accidentally broadening access. `DENY` and `AUDIT` policies with no `rules` remain no-ops.

Gateway API `HTTPRoute` path matches preserve Kubernetes semantics: `PathPrefix` stays a prefix route, `Exact` is translated to an exact-path route for whole-path matching, and `RegularExpression` is passed through as a Ferrum regex route. Istio `VirtualService` URI matches follow the same shape for `prefix`, `exact`, and `regex`. Translated mesh routes do not strip the listen path before forwarding, so upgrades from older mesh previews should expect backends to receive the original Kubernetes request path.

Gateway API cross-namespace `backendRefs` require an exact matching `ReferenceGrant`, including the source API group/kind and target group/kind. Ferrum currently supports core Kubernetes `Service` backend references and fails closed for other backend target kinds in both same-namespace and cross-namespace routes.

Kubernetes Gateway API and Istio mesh translators fail closed when a resource declares a port outside the Kubernetes service-port range (`1`-`65535`). Invalid ports are rejected during translation instead of wrapping into an unintended backend/listener port. Istio `AuthorizationPolicy.rules[].to[].operation.ports` also preserves wildcard string matches such as `"*"` and `"8*"` through Ferrum mesh policy `port_patterns`; non-numeric, non-pattern port strings still fail closed.

The Istio `AuthorizationPolicy` translator only consumes the four positive-match operation fields Ferrum can enforce: `methods`, `paths`, `hosts`, and `ports`. Any other field on `rules[].to[].operation` — including the negative-match siblings `notMethods`, `notPaths`, `notHosts`, and `notPorts` — is rejected at translation time so policies do not silently weaken authorization. Operators who relied on those fields being silently dropped by older Ferrum builds must drop them from the AuthorizationPolicy (or split the policy) before upgrading; otherwise the entire mesh translation fails closed and the gateway keeps its previous cached config. `RequestMatch.hosts` host patterns submitted directly to mesh config are likewise validated at config-load — bare hostnames, bracketed IPv6 literals, and `host:port` / `host:*` are accepted, while `host:`, `host:abc`, or values with multiple unbracketed colons are rejected.

Service / namespace names embedded in destination hosts are matched case-sensitively against the collected Kubernetes object metadata (matching how the API server stores those names). The trailing cluster-domain suffix is matched case-insensitively per DNS semantics, so `<svc>.<ns>.svc.Cluster.Local` resolves the same as `<svc>.<ns>.svc.cluster.local`, but `Reviews.Default.svc.cluster.local` will not match a Service whose stored name is `reviews` in namespace `default`.

`FERRUM_K8S_POD_DISCOVERY_ENABLED=true` enables the CP-side native Kubernetes registry bridge when `FERRUM_K8S_CONTROLLER_ENABLED=true`. The controller watches Pods, Services, and EndpointSlices; translates ready Pods into mesh workloads; translates Services into mesh services using `spec.ports[]`; and links Services to Pods through EndpointSlices. Pending, terminating, failed, succeeded, or not-ready Pods are not surfaced. Explicit Istio `WorkloadEntry` / `ServiceEntry` resources override the auto-derived Pod/Service entries for the same service. The controller service account needs `get`, `list`, and `watch` permissions for namespaced `pods`, `services`, and `endpointslices`. Set `FERRUM_K8S_NODE_LOCALITY_ENABLED=true` only when the controller service account also has cluster-scoped `nodes` permissions; then Node topology labels are copied into workload locality.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_K8S_POD_DISCOVERY_ENABLED` | No | `false` | Enables opt-in native Kubernetes Pod/Service/EndpointSlice discovery in the CP K8s controller |
| `FERRUM_K8S_NODE_LOCALITY_ENABLED` | No | `false` | Enables optional cluster-scoped Node watching so topology labels can enrich auto-discovered pod workload locality |
| `FERRUM_K8S_CLUSTER_DOMAIN` | No | `cluster.local` | Kubernetes cluster DNS domain used by the source translator for FQDN host matching. VirtualService destinations of the form `<svc>.<ns>.svc.<cluster_domain>` (and bare/short forms) resolve port names against the matching `Service` |
| `FERRUM_K8S_ISTIO_ROOT_NAMESPACE` | No | `istio-system` | Istio root namespace used by the K8s source translator for mesh-wide resources, including root-namespace `Sidecar` defaults/selectors and root-scoped `PeerAuthentication`, `RequestAuthentication`, `Telemetry`, and `ProxyConfig` resources |
| `FERRUM_K8S_WATCH_MESH_CONFIG` | No | `true` | Watch the root-namespace `istio` ConfigMap for `meshConfig.extensionProviders` / `defaultProviders.tracing` lookup. Requires `configmaps` `get/list/watch` RBAC in the istio root namespace (the watcher is scoped with a `metadata.name=istio` field selector). Set to `false` to skip the watch when the gateway runs in a different trust boundary from `istio-system` and cannot easily grant cross-namespace ConfigMap access. Only effective when `FERRUM_K8S_WATCH_ISTIO_CRDS=true` |
| `FERRUM_INJECTOR_LISTEN_ADDR` | Injector mode | `0.0.0.0:9443` | Admission webhook bind address for `POST /mutate` |
| `FERRUM_INJECTOR_SIDECAR_IMAGE` | No | `ferrum-edge:latest` | Image injected into workload pods as the Ferrum mesh sidecar |
| `FERRUM_INJECTOR_REQUIRE_ANNOTATION` | No | `true` | Require pod label `ferrum.io/mesh=enabled` or annotation `ferrum.io/inject=true` before injecting |
| `FERRUM_INJECTOR_TRUST_DOMAIN` | No | `cluster.local` | Trust domain used to derive injected sidecar `FERRUM_MESH_WORKLOAD_SPIFFE_ID` from pod namespace and service account |
| `FERRUM_INJECTOR_JWT_SECRET_REF_NAME` | No | — | Kubernetes Secret name used as the injected sidecar `FERRUM_CP_DP_GRPC_JWT_SECRET` source |
| `FERRUM_INJECTOR_JWT_SECRET_REF_KEY` | No | — | Key inside `FERRUM_INJECTOR_JWT_SECRET_REF_NAME` used as the injected sidecar `FERRUM_CP_DP_GRPC_JWT_SECRET` source |
| `FERRUM_MESH_EXCLUDE_OUTBOUND_PORTS` | No | — | Comma-separated TCP destination ports that the injector excludes from outbound iptables capture |
| `FERRUM_INJECTOR_SIDECAR_CPU_REQUEST` | No | `25m` | CPU request injected for the Ferrum sidecar container |
| `FERRUM_INJECTOR_SIDECAR_MEMORY_REQUEST` | No | `64Mi` | Memory request injected for the Ferrum sidecar container |
| `FERRUM_INJECTOR_SIDECAR_CPU_LIMIT` | No | `250m` | CPU limit injected for the Ferrum sidecar container |
| `FERRUM_INJECTOR_SIDECAR_MEMORY_LIMIT` | No | `256Mi` | Memory limit injected for the Ferrum sidecar container |
| `FERRUM_INJECTOR_INIT_CPU_REQUEST` | No | `10m` | CPU request injected for the iptables init container |
| `FERRUM_INJECTOR_INIT_MEMORY_REQUEST` | No | `32Mi` | Memory request injected for the iptables init container |
| `FERRUM_INJECTOR_INIT_CPU_LIMIT` | No | `100m` | CPU limit injected for the iptables init container |
| `FERRUM_INJECTOR_INIT_MEMORY_LIMIT` | No | `128Mi` | Memory limit injected for the iptables init container |
| `FERRUM_INJECTOR_TLS_CERT_PATH` | Kubernetes webhook deployments | — | TLS certificate presented by the injector webhook server |
| `FERRUM_INJECTOR_TLS_KEY_PATH` | Kubernetes webhook deployments | — | TLS private key for `FERRUM_INJECTOR_TLS_CERT_PATH` |
| `FERRUM_MESH_IP6TABLES_ENABLED` | No | `auto` | IPv6 iptables fan-out for injected init containers and capture fallback: `auto` probes and skips IPv6 rules when `ip6tables` is unavailable, `true` requires it whenever IPv6 CIDRs are configured and fails all capture setup before IPv4 rules if unavailable, `false` emits IPv4-only capture rules |

The injector copies non-secret mesh sidecar control-plane env vars from its own environment into injected containers when set: `FERRUM_DP_CP_GRPC_URLS`, `FERRUM_CP_DP_GRPC_JWT_ISSUER`, DP gRPC TLS vars, and `FERRUM_MESH_CONFIG_PROTOCOL`. It does not copy plaintext `FERRUM_CP_DP_GRPC_JWT_SECRET`; set `FERRUM_INJECTOR_JWT_SECRET_REF_NAME` and `FERRUM_INJECTOR_JWT_SECRET_REF_KEY` to inject that variable via `valueFrom.secretKeyRef`.

Outbound capture can be narrowed per pod with `traffic.sidecar.istio.io/includeOutboundPorts` or `ferrum.io/includeOutboundPorts`, using comma-separated TCP destination ports or `*` for all outbound ports. When explicit ports are present without an explicit include-CIDR annotation, the init container suppresses the implicit `0.0.0.0/0` catch-all and renders per-port outbound REDIRECT rules. When explicit include CIDRs are also set, capture is additive: all ports inside those CIDRs are captured, plus the listed ports to any destination. The `*` wildcard captures all outbound ports to any destination, even when explicit include CIDRs are also configured. IPv6 port rules are rendered through `ip6tables` whenever an IPv6 include or exclude CIDR activates the IPv6 address family.

Outbound capture exclusions can also be set per pod with `traffic.sidecar.istio.io/excludeOutboundPorts` or `ferrum.io/excludeOutboundPorts`, using comma-separated TCP ports. Global and pod-local lists are merged and deduplicated before the init container renders iptables `RETURN` rules.

Inbound port exclusions use the parallel annotations `traffic.sidecar.istio.io/excludeInboundPorts` / `ferrum.io/excludeInboundPorts`; the RETURN rules are emitted BEFORE the inbound REDIRECT so the exclusion is honored. CIDR-range exclusions use `traffic.sidecar.istio.io/excludeOutboundIPRanges` (APPENDS to the env-derived `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS`) and `traffic.sidecar.istio.io/includeOutboundIPRanges` (REPLACES the env-derived `FERRUM_MESH_CAPTURE_INCLUDE_CIDRS` when present, matching Istio's include-overrides-include semantics). Invalid ports or CIDRs in any annotation are rejected by the admission webhook with an error naming the offending annotation. Any IPv6 CIDR in include or exclude ranges activates IPv6 capture planning; IPv6 rules are partitioned into an `ip6tables` rule block. `FERRUM_MESH_IP6TABLES_ENABLED=auto` skips that block when the binary is missing, `true` requires it and fails before applying IPv4 rules if unavailable, and `false` emits IPv4-only rules.

Injected sidecars run as the configured mesh proxy UID with `runAsNonRoot=true`, `allowPrivilegeEscalation=false`, `readOnlyRootFilesystem=true`, `seccompProfile=RuntimeDefault`, and all Linux capabilities dropped. `FERRUM_MESH_PROXY_UID=0` is rejected at injector startup because Kubernetes would reject a sidecar that combines UID 0 with `runAsNonRoot=true`. The iptables init container explicitly sets `runAsUser=0`, `runAsNonRoot=false`, and `seccompProfile=RuntimeDefault`; it runs as root only long enough to program capture rules, drops all capabilities before adding back `NET_ADMIN` and `NET_RAW`, disables privilege escalation, and receives bounded CPU/memory requests and limits. Injector startup validates those resource quantity env vars so malformed values fail before admission requests are served. Its root filesystem remains writable because iptables needs the xtables lock path while programming capture rules.

### Node Agent

`FERRUM_MODE=node_agent` runs a per-node DaemonSet agent that manages eBPF-based traffic capture for mesh sidecars, replacing the per-pod privileged init container. See [mesh.md](mesh.md#node-agent-mode) for architecture details.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_NODE_AGENT_NODE_NAME` | Yes (node_agent) | — | Kubernetes node name, set via downward API (`spec.nodeName`) |
| `FERRUM_NODE_AGENT_CGROUP_ROOT` | No | `/sys/fs/cgroup` | cgroup v2 mount point for pod cgroup resolution |
| `FERRUM_NODE_AGENT_BPF_FS_PATH` | No | `/sys/fs/bpf` | BPF filesystem mount point for pinned maps |
| `FERRUM_NODE_AGENT_BPF_ELF_PATH` | Linux `ebpf` feature | build-tree eBPF target path | Compiled `ferrum-ebpf` ELF loaded by the aya backend |
| `FERRUM_NODE_AGENT_PROXY_MODE` | No | `local_pod` | Capture topology contract: `local_pod` or `node_waypoint` |
| `FERRUM_NODE_AGENT_ADMIN_ENABLED` | No | `false` | Enables the node-agent read-only admin listener for metrics/health. When enabled, defaults to loopback unless `FERRUM_ADMIN_BIND_ADDRESS` or `FERRUM_ADMIN_ALLOWED_CIDRS` is set; JWT does not affect bind because metrics/health are unauthenticated |
| `FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT` | No | `15008` | HBONE redirect/listener port written into the node-agent capture contract and BPF config map. Must match the mesh proxy HBONE listener (`15008` today) |
| `FERRUM_NODE_AGENT_FALLBACK_MODE` | No | `iptables` | Behavior on kernel < 5.7: `iptables` or `fail` |
| `FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES` | No | — | Extra namespaces to exclude from capture (comma-separated; `kube-system`, `kube-public`, `kube-node-lease` always excluded) |
| `FERRUM_MESH_CAPTURE_INCLUDE_CIDRS` | No | `0.0.0.0/0` | CIDRs to capture for outbound traffic (comma-separated). Per-pod annotation `traffic.sidecar.istio.io/includeOutboundIPRanges` REPLACES this value when present |
| `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS` | No | — | CIDRs to exclude from outbound capture (comma-separated, highest priority). Per-pod annotation `traffic.sidecar.istio.io/excludeOutboundIPRanges` APPENDS to this value |
| `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS` | No | `15001,15006,15008,15020` | Destination TCP ports excluded from outbound capture (comma-separated) |
| `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` | No | — | Destination TCP ports excluded from inbound capture (comma-separated; mirrors Istio `excludeInboundPorts`). Per-pod annotation `traffic.sidecar.istio.io/excludeInboundPorts` is additive. RETURN rules are emitted before the inbound REDIRECT so the exclusion is honored |
| `FERRUM_MESH_IP6TABLES_ENABLED` | No | `auto` | IPv6 iptables fan-out: `auto` probes and skips IPv6 rules when `ip6tables` is unavailable, `true` requires it when IPv6 CIDRs are configured and fails all capture setup before IPv4 rules if unavailable, `false` emits IPv4-only capture rules |

### Migration

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MIGRATE_ACTION` | No | `up` | Migration action: `up`, `status`, or `config` |
| `FERRUM_MIGRATE_DRY_RUN` | No | `false` | Preview migration work without applying changes |

### Size Limits

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MAX_HEADER_SIZE_BYTES` | No | `32768` | Maximum total request header size (all headers combined) |
| `FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES` | No | `16384` | Maximum size of any single request header (name + value) |
| `FERRUM_MAX_HEADER_COUNT` | No | `100` | Max number of request headers allowed (0=unlimited) |
| `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` | No | `10485760` | Maximum request body size (0=unlimited) |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` | No | `10485760` | Maximum response body size from backends (0=unlimited) |
| `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` | No | `65536` | Eager-buffer known-size responses at or below this size; `0` always streams |
| `FERRUM_H2_COALESCE_TARGET_BYTES` | No | `131072` | Target chunk size for HTTP/2 response body coalescing; clamped 16 KiB..1 MiB |
| `FERRUM_MAX_URL_LENGTH_BYTES` | No | `8192` | Maximum URL length in bytes (path + query string, 0=unlimited) |
| `FERRUM_MAX_QUERY_PARAMS` | No | `100` | Maximum number of query parameters allowed (0=unlimited) |
| `FERRUM_MAX_GRPC_RECV_SIZE_BYTES` | No | `4194304` | Maximum total received gRPC payload size in bytes (0=unlimited) |
| `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` | No | `16777216` | Maximum WebSocket frame size in bytes; max message size = 4x frame size |
| `FERRUM_WEBSOCKET_WRITE_BUFFER_SIZE` | No | `131072` | WebSocket write buffer size (128 KB). Increase for large WS frames (1 MB+). Only applies when frame-level plugins are active |
| `FERRUM_WEBSOCKET_TUNNEL_MODE` | No | `false` | When true and no frame-level plugins are configured, bypass WebSocket frame parsing and use raw TCP bidirectional copy. Significantly improves throughput for large payloads (9 MB: 25→110 RPS). Trade-off: `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` is not enforced (no DoS risk — data streams through fixed-size copy buffer) |
| `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` | No | `10` | HTTP/1.1 header read timeout; `0` disables |

See [size_limits.md](size_limits.md) for detailed sizing guidance.

### DNS

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DNS_TTL_OVERRIDE_SECONDS` | No | Disabled | Global TTL override — forces all records to use this fixed TTL. Disabled by default (native record TTL is respected) |
| `FERRUM_DNS_MIN_TTL_SECONDS` | No | `5` | Minimum TTL floor to prevent 0-TTL abuse |
| `FERRUM_DNS_OVERRIDES` | No | `{}` | JSON map of hostname→IP static overrides |
| `FERRUM_DNS_RESOLVER_ADDRESS` | No | resolv.conf | Comma-separated nameservers (ip[:port]) |
| `FERRUM_DNS_RESOLVER_HOSTS_FILE` | No | `/etc/hosts` | Path to custom hosts file |
| `FERRUM_DNS_ORDER` | No | `CACHE,SRV,A,CNAME` | Record type query order (comma-separated) |
| `FERRUM_DNS_STALE_TTL` | No | `3600` | Stale data usage time (seconds) during refresh |
| `FERRUM_DNS_ERROR_TTL` | No | `5` | TTL (seconds) for errors/empty responses |
| `FERRUM_DNS_CACHE_MAX_SIZE` | No | `10000` | Maximum DNS cache entries |
| `FERRUM_DNS_WARMUP_CONCURRENCY` | No | `500` | Maximum concurrent DNS warmup resolutions during startup/config reload |
| `FERRUM_DNS_SLOW_THRESHOLD_MS` | No | Disabled | Log slow DNS resolutions above this threshold (ms) |
| `FERRUM_DNS_REFRESH_THRESHOLD_PERCENT` | No | `90` | Percentage of TTL elapsed before background refresh (1-99) |
| `FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS` | No | `10` | Interval (seconds) for retrying failed DNS lookups. `0` = disabled |
| `FERRUM_DNS_TRY_TCP_ON_ERROR` | No | `true` | Retry over TCP when UDP DNS responses are truncated or fail |
| `FERRUM_DNS_NUM_CONCURRENT_REQS` | No | `3` | Nameservers to query concurrently per lookup; clamped 1..10 |
| `FERRUM_DNS_MAX_ACTIVE_REQUESTS` | No | `512` | Max in-flight queries per multiplexed DNS connection; clamped 1..4096 |
| `FERRUM_DNS_MAX_CONCURRENT_REFRESHES` | No | `64` | Maximum concurrent stale-while-revalidate background refresh tasks system-wide. Prevents unbounded task spawning when many stale hostnames are hit simultaneously. Range: 1-1000 |

See [dns_resolver.md](dns_resolver.md) for full configuration reference.

### TLS / mTLS

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_TLS_CA_BUNDLE_PATH` | No | — | Path to PEM CA bundle for all outbound TLS verification |
| `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH` | No | — | Path to client certificate for backend mTLS |
| `FERRUM_BACKEND_TLS_CLIENT_KEY_PATH` | No | — | Path to client private key for backend mTLS |
| `FERRUM_GATEWAY_SVID_CERT_PATH` | No | — | Leaf-first PEM X.509-SVID certificate chain used as the gateway's SPIFFE identity for gateway-to-mesh TLS |
| `FERRUM_GATEWAY_SVID_KEY_PATH` | No | — | Unencrypted PKCS#8 private key for `FERRUM_GATEWAY_SVID_CERT_PATH`; legacy `BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY` files are rejected |
| `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH` | No | — | PEM trust bundle used to verify mesh SPIFFE peers for gateway-to-mesh TLS |
| `FERRUM_GATEWAY_SPIFFE_ID` | No | — | Explicit SPIFFE URI fallback when the gateway SVID certificate has no SPIFFE URI SAN |
| `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` | No | — | Path to client CA bundle for mTLS verification |
| `FERRUM_TLS_NO_VERIFY` | No | `false` | Disable outbound TLS verification for all connections (testing only) |
| `FERRUM_TLS_CRL_FILE_PATH` | No | — | PEM CRL bundle for revocation checks across TLS/DTLS surfaces |
| `FERRUM_TLS_MIN_VERSION` | No | `1.2` | Minimum TLS protocol version, inbound + outbound (`1.2` or `1.3`) |
| `FERRUM_TLS_MAX_VERSION` | No | `1.3` | Maximum TLS protocol version, inbound + outbound (`1.2` or `1.3`) |
| `FERRUM_TLS_CIPHER_SUITES` | No | *(secure defaults)* | Comma-separated cipher suites, inbound + outbound (see [TLS Policy Hardening](frontend_tls.md#tls-policy-hardening)) |
| `FERRUM_TLS_CURVES` | No | `X25519,secp256r1` | Comma-separated key exchange groups, inbound + outbound |
| `FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER` | No | `true` | Prefer server cipher order during TLS 1.2 negotiation (inbound only) |
| `FERRUM_TLS_SESSION_CACHE_SIZE` | No | `4096` | TLS session resumption cache size (inbound only, TLS 1.2 stateful session IDs) |
| `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS` | No | `30` | Warn when configured certificates expire within this many days; `0` disables warnings |
| `FERRUM_TLS_EARLY_DATA_METHODS` | No | — | Comma-separated methods allowed as TLS 1.3 0-RTT early data |

These TLS policy settings apply uniformly to both inbound (frontend) and outbound (backend) connections across all TLS-capable protocols (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket, TCP-TLS). DTLS uses a separate library and is not affected. See [frontend_tls.md](frontend_tls.md) and [backend_mtls.md](backend_mtls.md) for detailed TLS configuration guides.

Gateway SVID files are static startup inputs. Set all three SVID path variables together; the gateway rejects partial configuration and validates the leaf certificate, intermediate certificate freshness, PKCS#8 key match, and trust bundle before serving. The SPIFFE ID is read from the leaf URI SAN when present; `FERRUM_GATEWAY_SPIFFE_ID` is only a fallback for file bundles without a SPIFFE URI SAN. Private keys must be unencrypted PKCS#8 PEM (`BEGIN PRIVATE KEY`; `openssl pkcs8 -topk8 -nocrypt` can convert legacy RSA/EC PEM keys); legacy `BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY` files are rejected.

Gateway DPs can also receive mesh SPIFFE trust bundles from the CP. `GatewayConfig.trust_bundles` uses the same serializable `TrustBundleSet` shape as mesh config on the CP side, but CP `ConfigUpdate` and `FullConfigResponse` messages carry that material only in the `trust_bundles_json` side channel so older DPs can keep deserializing full snapshot `GatewayConfig` JSON safely. Stream snapshots, stream deltas, and unary full snapshots all refresh gateway-to-mesh trust material; JSON `null` explicitly clears previously delivered CP trust, including when the CP rejects invalid trust-bundle material and must revoke stale anchors instead of leaving them unchanged. When a gateway SVID is loaded from files, received trust bundles temporarily override the SVID bundle's trust material in the lock-free slot; if a later authoritative CP update clears them, the DP restores the startup file trust. Without a local SVID, the DP still stores CP-delivered bundles for later gateway-mesh features.

Gateway-to-mesh HBONE dispatch is opt-in per upstream target. A target tagged `mesh.hbone=true` is probed on the standard sidecar HBONE port `15008` (override with `mesh.hbone_port`) when the gateway has a loaded SVID. If the probe succeeds, plain HTTP requests to that target are sent through an HTTP/2 CONNECT tunnel with SPIFFE mTLS before the ordinary H3/H2/reqwest backend chain is considered. The HBONE pool uses the proxy's effective `pool_*` overrides for connection count, idle timeout, TCP keepalive, and HTTP/2 flow-control settings, and coalesces concurrent first connects for the same target/SVID key within the proxy's `backend_connect_timeout_ms` budget. Requests that require replayable retries or request-body buffering stay on the existing direct backend transports. Ferrum injects `source.principal` baggage from the gateway SVID on the CONNECT request; mesh sidecars still validate baggage against the authenticated peer identity before trusting it. Capability-level tunnel establishment failures such as TCP, TLS, DNS, or HTTP/2 handshake errors downgrade only the cached HBONE capability for that target, so later requests fall back to the normal direct backend transports until the next capability refresh succeeds. Per-request CONNECT rejections do not downgrade HBONE support.

When a gateway SVID is loaded, Ferrum also enables gateway-originated mesh metrics. If no global `workload_metrics` plugin exists, the runtime adds an internal global plugin with `workload_spiffe_id` set to the gateway SPIFFE ID. If an operator-managed global `workload_metrics` plugin already exists in the gateway namespace, Ferrum leaves the plugin in place and fills `workload_spiffe_id` only when it is missing. Requests actually dispatched through HBONE are labeled with `mesh.connection_security_policy=mutual_tls`, `mesh.gateway.transport=hbone`, and any mesh destination tags present on the selected upstream target.

Admin listener TLS and mTLS variables are listed in [Admin API](#admin-api).

### HTTP/3 (QUIC)

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ENABLE_HTTP3` | No | `false` | Enable HTTP/3 (QUIC) listener on the HTTPS port |
| `FERRUM_HTTP3_IDLE_TIMEOUT` | No | `30` | HTTP/3 connection idle timeout in seconds |
| `FERRUM_HTTP3_MAX_STREAMS` | No | `1000` | Maximum concurrent HTTP/3 streams per connection |
| `FERRUM_HTTP3_STREAM_RECEIVE_WINDOW` | No | `8388608` | HTTP/3 per-stream receive window in bytes (default: 8 MiB) |
| `FERRUM_HTTP3_RECEIVE_WINDOW` | No | `33554432` | HTTP/3 connection-level receive window in bytes (default: 32 MiB) |
| `FERRUM_HTTP3_SEND_WINDOW` | No | `8388608` | HTTP/3 per-connection send window in bytes (default: 8 MiB) |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | No | `4` | QUIC connections per H3 backend (pool sharding) |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | No | `120` | H3 backend connection idle eviction in seconds |
| `FERRUM_HTTP3_COALESCE_MIN_BYTES` | No | `32768` | Response coalesce flush target (native H3 + cross-protocol bridge) |
| `FERRUM_HTTP3_COALESCE_MAX_BYTES` | No | `32768` | Response coalesce buffer capacity and `min_bytes` clamp |
| `FERRUM_HTTP3_FLUSH_INTERVAL_MICROS` | No | `200` | Response coalesce time-based flush interval (µs) |
| `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY` | No | `32` | Bounded mpsc capacity for the H3→non-H3 cross-protocol request-body bridge. Bounds in-flight request memory to approximately `capacity × average_h3_chunk_size` during streaming uploads. Range: 1–1024. |
| `FERRUM_HTTP3_WEBSOCKET_ENABLED` | No | `true` | Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` and accept RFC 9220 Extended CONNECT (`:method=CONNECT`, `:protocol=websocket`) on the H3 listener. When `false`, the H3 server does not advertise the setting and the bridge returns 501. The WebSocket plugin pipeline (`on_ws_frame`, `on_ws_disconnect`, `ws_rate_limit`, `ws_message_size_limiting`, `ws_frame_logging`) and admission control (`FERRUM_WEBSOCKET_MAX_CONNECTIONS`) work on H3 sessions whether or not `FERRUM_WEBSOCKET_TUNNEL_MODE` is set — H3 always frame-parses since there is no raw TCP underneath QUIC. See [docs/http3.md](http3.md#websocket-over-http3-rfc-9220-extended-connect). |
| `FERRUM_HTTP3_INITIAL_MTU` | No | `1500` | Initial QUIC path MTU (clamped 1200–65527) |
| `FERRUM_H3_REQUEST_BODY_DRAIN_MS` | No | `50` | Courtesy drain window before STOP_SENDING on small/successful H3 responses |

See [docs/http3.md](http3.md) for the full HTTP/3 dispatch model, cross-protocol bridge behavior, and WebSocket-over-H3 bridging.

### Stream Proxy (TCP/UDP/DTLS)

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_STREAM_PROXY_BIND_ADDRESS` | No | `0.0.0.0` | Bind address for TCP/UDP/DTLS stream proxy listeners |
| `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` | No | `300` | Default TCP idle timeout; `0` disables |
| `FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS` | No | `300` | Hard cap for TCP half-close drain; the relay fast path requires this, `FERRUM_TCP_IDLE_TIMEOUT_SECONDS`, `backend_read_timeout_ms`, and `backend_write_timeout_ms` all set to `0` |
| `FERRUM_UDP_MAX_SESSIONS` | No | `10000` | Maximum concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | No | `10` | UDP session cleanup interval |
| `FERRUM_UDP_RECVMMSG_BATCH_SIZE` | No | `64` | Linux `recvmmsg` receive batch size; clamped 1..1024 |
| `FERRUM_DTLS_CERT_PATH` | No | — | PEM certificate for frontend DTLS termination (ECDSA P-256 or P-384 only) |
| `FERRUM_DTLS_KEY_PATH` | No | — | PEM private key for frontend DTLS termination |
| `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | No | — | PEM CA certificate for verifying DTLS client certs (frontend mTLS) |
| `FERRUM_DTLS_MAX_PLAINTEXT_BYTES` | No | `16384` | Maximum plaintext payload bytes per DTLS record |
| `FERRUM_DTLS_RECORD_OVERHEAD_BYTES` | No | `64` | DTLS record overhead budget for per-session output buffers |
| `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` | No | `10` | Shared frontend TCP+TLS and UDP+DTLS handshake timeout. DTLS peers still in handshake count against `FERRUM_UDP_MAX_SESSIONS` until this deadline releases them |

See [tcp_udp_proxy.md](tcp_udp_proxy.md) for full TCP/UDP proxy documentation.

### Authentication

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_BASIC_AUTH_HMAC_SECRET` | No | `ferrum-edge-change-me-in-production` | Server secret for HMAC-SHA256 password verification (~1μs). The Admin API stores `hmac_sha256:<hex>` hashes. **Must be changed in production** — using the default allows anyone who knows it to compute valid credential hashes. |
| `FERRUM_MAX_CREDENTIALS_PER_TYPE` | No | `2` | Maximum active credential entries per type per consumer |
| `FERRUM_TRUSTED_PROXIES` | No | — | Comma-separated trusted proxy CIDRs/IPs for client IP resolution via `X-Forwarded-For` |
| `FERRUM_BACKEND_ALLOW_IPS` | No | `both` | Backend SSRF policy: `both`, `private`, or `public` |
| `FERRUM_ADD_VIA_HEADER` | No | `true` | Add `Via` on request and response paths |
| `FERRUM_VIA_PSEUDONYM` | No | `ferrum-edge` | Pseudonym used in the `Via` header |
| `FERRUM_ADD_FORWARDED_HEADER` | No | `false` | Add RFC 7239 `Forwarded` alongside `X-Forwarded-*` |
| `FERRUM_REAL_IP_HEADER` | No | — | Authoritative real-IP header name (e.g., `CF-Connecting-IP`, `X-Real-IP`) |

See [client_ip_resolution.md](client_ip_resolution.md) for the security model and deployment examples.

### Observability

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING` | No | `false` | Track streaming response total latency (adds per-stream overhead) |
| `FERRUM_METRICS_SYSTEM_SAMPLE_INTERVAL_MS` | No | `1000` | Background sampler interval for `/metrics/runtime` system metrics (minimum 100ms) |
| `FERRUM_METRICS_WINDOW_1M_SECONDS` | No | `60` | Short status-code/request-rate window exposed by `/metrics/runtime` |
| `FERRUM_METRICS_WINDOW_5M_SECONDS` | No | `300` | Long status-code/request-rate window exposed by `/metrics/runtime` |
| `FERRUM_METRICS_LOG_COUNTER_ENABLED` | No | `true` | Count Ferrum tracing events by level and bounded category for `/metrics/runtime`, after applying the output `FERRUM_LOG_LEVEL` / `RUST_LOG` filter |
| `FERRUM_METRICS_RUNTIME_CACHE_MS` | No | `1000` | Admin JSON cache TTL for `GET /metrics/runtime` |
| `FERRUM_METRICS_POOL_TRACKING_ENABLED` | No | `true` | Count backend pool creation, failure, and eviction churn in `/metrics/runtime` |
| `FERRUM_METRICS_STATUS_TRACKING_ENABLED` | No | `true` | Count extra 1m/5m HTTP status windows for `/metrics/runtime`; disable to remove the additional per-request status-window counters |
| `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS` | No | `1000` | Threshold (ms) for logging slow plugin outbound HTTP calls |
| `FERRUM_PLUGIN_HTTP_MAX_RETRIES` | No | `0` | Retry count for safe plugin outbound HTTP calls on transport failures (JWKS/OIDC fetches, etc.) |
| `FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS` | No | `100` | Delay between plugin HTTP transport retry attempts |

### Runtime Tuning

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_WORKER_THREADS` | No | CPU cores | Tokio async worker threads |
| `FERRUM_BLOCKING_THREADS` | No | `512` | Max tokio blocking threads for file/DNS I/O |
| `FERRUM_MAX_CONNECTIONS` | No | `100000` | Max concurrent proxy connections; queues when full, `0` = unlimited |
| `FERRUM_MAX_REQUESTS` | No | `0` | Max concurrent in-flight requests/streams; `0` = unlimited |
| `FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP` | No | `0` | Per-client-IP concurrent request cap; `0` disables |
| `FERRUM_PER_IP_CLEANUP_INTERVAL_SECONDS` | No | `60` | Cleanup interval for per-IP request counters |
| `FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES` | No | `10000` | Max circuit breaker cache entries |
| `FERRUM_STATUS_COUNTS_MAX_ENTRIES` | No | `200` | Max distinct HTTP status code counter entries |
| `FERRUM_TCP_LISTEN_BACKLOG` | No | `2048` | TCP listen backlog size (min 128); raise `net.core.somaxconn` to match |
| `FERRUM_ACCEPT_THREADS` | No | `0` (auto-detect) | Parallel accept() loops per proxy listener port via SO_REUSEPORT. `0` = CPU cores, `1` = single listener. Parallelizes kernel-level connection intake independently of worker threads. Unix only (Linux 3.9+, macOS, BSDs); non-Unix platforms warn and run one accept loop |
| `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` | No | `1000` | Server-side HTTP/2 max concurrent streams per inbound connection |
| `FERRUM_SERVER_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS` | No | `64` | Rapid-reset mitigation threshold for pending accept-reset streams |
| `FERRUM_SERVER_HTTP2_MAX_LOCAL_ERROR_RESET_STREAMS` | No | `256` | Rapid-reset mitigation threshold for locally reset streams |
| `FERRUM_WEBSOCKET_MAX_CONNECTIONS` | No | `20000` | Dedicated cap for upgraded WebSocket connections; `0` disables |
| `FERRUM_SHUTDOWN_DRAIN_SECONDS` | No | `30` | Graceful shutdown drain period; `0` skips draining |
| `FERRUM_STATUS_METRICS_WINDOW_SECONDS` | No | `30` | Rate window for admin `/status` metrics |

See [infrastructure_sizing.md](infrastructure_sizing.md) for detailed tuning guidance.

### Connection Pooling

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_POOL_WARMUP_ENABLED` | No | `true` | Pre-establish backend connections at startup after DNS warmup. Skipped for TCP/UDP stream proxies |
| `FERRUM_POOL_WARMUP_CONCURRENCY` | No | `500` | Maximum concurrent connection warmup attempts at startup |
| `FERRUM_POOL_CLEANUP_INTERVAL_SECONDS` | No | `30` | Cleanup sweep interval for all connection pools |
| `FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS` | No | `86400` | Background interval for reproving backend HTTP/2, HTTP/3, and h2c capabilities |
| `FERRUM_GRPC_POOL_READY_WAIT_MS` | No | `1` | Time the gRPC pool waits for stream capacity before opening another backend connection |
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | No | `64` | Maximum idle connections per backend host (min: 4, max: 1024) |
| `FERRUM_POOL_IDLE_TIMEOUT_SECONDS` | No | `90` | Seconds before idle connections are closed |
| `FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE` | No | `true` | Enable HTTP keep-alive for backend connection reuse |
| `FERRUM_POOL_ENABLE_HTTP2` | No | `true` | Enable HTTP/2 multiplexing when supported |
| `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST` | No | CPU cores (2-8) | HTTP/2 connections per backend host |
| `FERRUM_POOL_TCP_KEEPALIVE_SECONDS` | No | `60` | TCP keep-alive interval in seconds |
| `FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS` | No | `30` | HTTP/2 keep-alive ping interval in seconds |
| `FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS` | No | `45` | HTTP/2 keep-alive ping timeout in seconds |
| `FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE` | No | `8388608` | HTTP/2 per-stream flow-control window in bytes (8 MiB). Clamped to 65535..128 MiB |
| `FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE` | No | `33554432` | HTTP/2 connection-level flow-control window in bytes (32 MiB). Clamped to 65535..128 MiB |
| `FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW` | No | `true` | Enable adaptive flow-control window sizing based on observed throughput |
| `FERRUM_POOL_HTTP2_MAX_FRAME_SIZE` | No | `1048576` | Maximum HTTP/2 frame payload in bytes (1 MiB). Clamped to 16384..1 MiB |
| `FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS` | No | `1000` | Max concurrent HTTP/2 streams per backend connection |

See [connection_pooling.md](connection_pooling.md) for the full configuration reference and pool warmup details.

### Router Cache

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ROUTER_CACHE_MAX_ENTRIES` | No | `0` | Router prefix/negative lookup cache size. `0` auto-scales as `max(10000, proxies × 3)` |

### Overload Management

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_OVERLOAD_CHECK_INTERVAL_MS` | No | `1000` | Resource pressure monitor interval; minimum 100ms |
| `FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD` | No | `0.80` | FD usage ratio above which keepalive is disabled |
| `FERRUM_OVERLOAD_FD_CRITICAL_THRESHOLD` | No | `0.95` | FD usage ratio above which new connections are rejected |
| `FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD` | No | `0.85` | Connection usage ratio above which keepalive is disabled |
| `FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD` | No | `0.95` | Connection usage ratio above which new connections are rejected |
| `FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD` | No | `0.85` | Request usage ratio above which keepalive is disabled |
| `FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD` | No | `0.95` | Request usage ratio above which new requests receive 503 |
| `FERRUM_OVERLOAD_LOOP_WARN_US` | No | `10000` | Event-loop latency warning threshold |
| `FERRUM_OVERLOAD_LOOP_CRITICAL_US` | No | `500000` | Event-loop latency threshold for rejecting new connections |

### Advanced Performance

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ADAPTIVE_BUFFER_ENABLED` | No | `true` | Enable adaptive TCP/WebSocket tunnel copy buffer sizing |
| `FERRUM_ADAPTIVE_BATCH_LIMIT_ENABLED` | No | `true` | Enable adaptive UDP batch limit sizing |
| `FERRUM_ADAPTIVE_BUFFER_EWMA_ALPHA` | No | `300` | EWMA smoothing factor, clamped 1..999 |
| `FERRUM_ADAPTIVE_BUFFER_MIN_SIZE` | No | `8192` | Adaptive buffer floor in bytes |
| `FERRUM_ADAPTIVE_BUFFER_MAX_SIZE` | No | `262144` | Adaptive buffer ceiling in bytes |
| `FERRUM_ADAPTIVE_BUFFER_DEFAULT_SIZE` | No | `65536` | Initial adaptive buffer size before traffic data exists |
| `FERRUM_ADAPTIVE_BATCH_LIMIT_DEFAULT` | No | `6000` | Initial adaptive UDP batch limit |
| `FERRUM_TLS_OFFLOAD_THREADS` | No | `0` | Dedicated TLS handshake offload threads; `0` disables |
| `FERRUM_TCP_FASTOPEN_ENABLED` | No | `auto` | TCP Fast Open toggle: `auto`, `true`, or `false` |
| `FERRUM_TCP_FASTOPEN_QUEUE_LEN` | No | `256` | TCP Fast Open server queue length |
| `FERRUM_KTLS_ENABLED` | No | `auto` | Linux kTLS splice acceleration toggle |
| `FERRUM_IO_URING_SPLICE_ENABLED` | No | `auto` | Linux io_uring splice toggle |
| `FERRUM_UDP_GRO_ENABLED` | No | `auto` | Linux UDP GRO toggle; currently reserved/no-op |
| `FERRUM_UDP_GSO_ENABLED` | No | `auto` | Linux UDP GSO send batching toggle |
| `FERRUM_UDP_PKTINFO_ENABLED` | No | `auto` | Linux IP_PKTINFO/IPV6_PKTINFO reply-source optimization toggle |
| `FERRUM_SO_BUSY_POLL_US` | No | `0` | Linux SO_BUSY_POLL duration for latency-sensitive UDP sockets |

Core environment parsing lives in `src/config/env_config.rs`; early startup/pool settings use the same `FERRUM_*` names via conf-aware helpers.

## Configuration File (`ferrum.conf`)

As an alternative to environment variables, the gateway supports a `ferrum.conf` configuration file for setting reasonable defaults. Environment variables **take precedence** over values in the conf file, allowing operators to define baseline configuration in the file and override specific values per deployment via env vars.

**File location:**
- Default: `./ferrum.conf` (current working directory)
- Override with the `FERRUM_CONF_PATH` environment variable (the only setting that must remain an env var)
- If the file does not exist at the default path, it is silently skipped

**Format:** Simple key-value pairs using the same `FERRUM_*` names as environment variables:

```conf
# Operating mode
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = /etc/ferrum/config.yaml
FERRUM_LOG_LEVEL = info

# Proxy ports
FERRUM_PROXY_HTTP_PORT = 8080
FERRUM_PROXY_HTTPS_PORT = 8443

# TLS hardening
FERRUM_TLS_MIN_VERSION = 1.3

# Quoted values for paths with spaces
FERRUM_FRONTEND_TLS_CERT_PATH = "/path/with spaces/cert.pem"
```

- Lines starting with `#` are comments
- Inline comments are supported: `KEY = value # comment`
- Values can be quoted with double or single quotes (quotes are stripped)
- Empty lines are ignored

A reference `ferrum.conf` with all available fields and descriptions is included in the repository root.

**Precedence order:** environment variables > `ferrum.conf` > built-in defaults

## File Mode Configuration Format

Configuration files can be YAML or JSON. See `tests/config.yaml` for a complete example.

```yaml
proxies:
  - id: "my-api"
    name: "My Backend API"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "backend-service"
    backend_port: 3000
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 5000
    backend_read_timeout_ms: 30000
    backend_write_timeout_ms: 30000
    # Response body mode: "stream" (default) or "buffer"
    # response_body_mode: stream
    # Connection pooling settings (optional - override global defaults)
    pool_idle_timeout_seconds: 120
    auth_mode: single
    plugins:
      - plugin_config_id: "log-plugin"

consumers:
  - id: "user-1"
    username: "alice"
    credentials:
      keyauth:
        - key: "alice-api-key"
        - key: "alice-rotated-key"

plugin_configs:
  - id: "log-plugin"
    plugin_name: "stdout_logging"
    config: {}
    scope: global
    enabled: true
```

### Stream Proxy (TCP/UDP/DTLS)

Stream proxies use `listen_port` instead of `listen_path` and bind to dedicated ports:

Stream proxies route on `listen_port` and MUST NOT set `listen_path`.

```yaml
proxies:
  # TCP proxy with TLS origination to backend
  - id: "postgres-proxy"
    listen_port: 5432
    backend_scheme: tcps
    backend_host: "db.internal"
    backend_port: 5432

  # UDP proxy with DTLS encryption to backend
  - id: "iot-proxy"
    listen_port: 5684
    backend_scheme: dtls
    backend_host: "iot-backend.internal"
    backend_port: 5684
    backend_tls_verify_server_cert: false
    udp_idle_timeout_seconds: 120

  # Full DTLS e2e: DTLS client → gateway → DTLS backend
  - id: "secure-iot"
    listen_port: 5685
    backend_scheme: dtls
    backend_host: "secure-iot.internal"
    backend_port: 5684
    frontend_tls: true
    backend_tls_verify_server_cert: false
```

**Port validation:** Each `listen_port` must be unique across all stream proxies and must not conflict with gateway reserved ports (`FERRUM_PROXY_HTTP_PORT`, `FERRUM_PROXY_HTTPS_PORT`, `FERRUM_ADMIN_HTTP_PORT`, `FERRUM_ADMIN_HTTPS_PORT`, CP gRPC port). Ports set to `0` (disabled) are excluded from conflict checks. In database mode, the Admin API also probes OS-level port availability before accepting the config. See [tcp_udp_proxy.md](tcp_udp_proxy.md) for full documentation including per-mode behavior.

### Service Discovery

Upstreams can discover targets dynamically using a `service_discovery` block. Four providers are supported:

**DNS-SD** (DNS Service Discovery):
```yaml
upstreams:
  - id: "my-upstream"
    targets: []
    algorithm: round_robin
    service_discovery:
      provider: dns_sd
      dns_sd:
        service_name: "_http._tcp.my-service.local"
        poll_interval_seconds: 30
```

**Kubernetes**:
```yaml
upstreams:
  - id: "k8s-upstream"
    targets: []
    algorithm: least_connections
    service_discovery:
      provider: kubernetes
      kubernetes:
        namespace: "default"
        service_name: "my-service"
        port_name: "http"
        poll_interval_seconds: 15
```

**Consul**:
```yaml
upstreams:
  - id: "consul-upstream"
    targets:
      - host: "fallback.example.com"
        port: 8080
        weight: 1
    algorithm: round_robin
    service_discovery:
      provider: consul
      consul:
        address: "http://consul.internal:8500"
        service_name: "my-service"
        datacenter: "dc1"
        poll_interval_seconds: 10
        token: "consul-acl-token"
```

**Ferrum Mesh**:
```yaml
upstreams:
  - id: "mesh-payments"
    targets: []
    algorithm: round_robin
    service_discovery:
      provider: mesh
      mesh:
        service_name: "payments"
        namespace: "backend"   # optional; defaults to the upstream namespace
        port: 8080             # optional; defaults to the first mesh service port
        poll_interval_seconds: 5
```

The mesh provider reads the CP-delivered `mesh.services` and `mesh.workloads` snapshot already present in gateway DP config. It converts matching workload addresses into upstream targets tagged with `mesh.spiffe_id`, `mesh.namespace`, and `mesh.hbone=true`, allowing later gateway-to-mesh transport features to select mesh-aware backends without a separate registry.

Discovered targets are merged with any statically defined `targets`. If the provider is unreachable, the upstream keeps its last-known targets to maintain availability.

## Database Schema

When using Database or CP modes, Ferrum auto-creates the following tables on startup:

- **`proxies`** — Proxy route definitions (with `UNIQUE` constraint on `listen_path`)
- **`consumers`** — API consumer/user definitions
- **`plugin_configs`** — Plugin configurations (global, per-proxy, or proxy-group scoped)
- **`proxy_plugins`** — Many-to-many linking proxies to plugin configs
- **`upstreams`** — Upstream groups for load-balanced backends (targets stored as JSON, with algorithm and health check configuration)

See [migrations.md](migrations.md) for schema migration details.
