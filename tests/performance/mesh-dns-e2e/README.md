# Mesh DNS Proxy E2E Perf Suite

End-to-end performance harness for Ferrum Edge's transparent mesh DNS proxy (`src/modes/mesh/dns_proxy.rs`). Companion to `tests/performance/mesh/` — that suite is in-process criterion micro-benches; this one spins up the gateway and sends real DNS queries over UDP/TCP.

## Architecture

```
dns_loadgen ──UDP/TCP DNS──► ferrum-edge (15053) ──UDP DNS──► dns_upstream_stub
                                  │                                (17053)
                                  ▼
                            mesh_cp_stub
                            (gRPC 17070 — pushes synthetic mesh slice via
                             native MeshSubscribe)
```

Three name classes are measured:

| Class | Example | Resolves to | Path inside gateway |
|---|---|---|---|
| mesh-internal | `reviews.default.svc.cluster.local` | 10.0.0.1 | exact match in `DnsResolutionTable.exact` |
| mesh-wildcard | `pod-7.headless.default.svc.cluster.local` | 10.0.0.99 | one-label wildcard suffix match |
| upstream-forward | `example.com` | 192.0.2.1 (from stub) | UDP forward through `run_udp_forwarder` to `FERRUM_MESH_DNS_UPSTREAM_ADDR` |

## Quick start

```bash
cd tests/performance/mesh-dns-e2e

./run.sh                            # 30s, c=100, udp+tcp
./run.sh --duration 60 --concurrency 200
./run.sh --protocol udp             # UDP only
./run.sh --edns 1232                # send EDNS(0) OPT records
./run.sh --json > results.json      # machine-readable output
./run.sh --skip-build               # reuse existing release binaries
```

The first run will `cargo build --release` both the harness crate and (in `$PROJECT_ROOT`) the root `ferrum-edge` binary. Subsequent runs reuse those artefacts unless source changes. Add `--skip-build` to short-circuit even the freshness check.

## Why a stub control plane?

The mesh DNS proxy listener only spawns from `src/modes/mesh/mod.rs::run()`, which requires a `MeshConfigSync` source (native or xDS). File-mode gateways do not run mesh, so there is no `FERRUM_MODE=file` shortcut. `mesh_cp_stub` is the smallest viable CP — it implements only the `MeshSubscribe` RPC, returns a single hand-crafted `MeshSlice` JSON, and parks the stream open forever. JWT validation is intentionally permissive (the gateway's own issuer/secret check is the real boundary; harness traffic doesn't need auth coverage).

The CP stub's `ferrum_version` must match the gateway's major.minor (the DP client `check_cp_version_compatibility` enforces this). `run.sh` reads it from `ferrum-edge version --json` automatically.

## Why an in-process upstream stub?

The gateway's upstream forward path issues UDP queries to `FERRUM_MESH_DNS_UPSTREAM_ADDR`. Pointing it at `127.0.0.53:53` (the host resolver) introduces network jitter that drowns the gateway overhead in the forward-path numbers. `dns_upstream_stub` is a 100-line tokio UDP server that answers `A` queries with `192.0.2.1` (RFC 5737 TEST-NET-1) and `AAAA` queries with `2001:db8::1` (RFC 3849).

## Reporting

Per name class × per transport (UDP/TCP):

| Metric | Source |
|---|---|
| qps | `total_queries / duration` |
| p50/p90/p95/p99 latency | hdrhistogram quantiles, microseconds |
| total_errors | malformed / mismatched response or timeout |
| total_nxdomain | RCODE=3 responses (expected for nothing in the synthetic slice; useful regression signal) |

A direct-stub baseline run is appended for the `upstream-forward` class so operators can compute gateway overhead. Mesh-internal and mesh-wildcard classes have **no baseline** — those names only exist inside the gateway's resolution table, so the reported numbers are an absolute gateway-overhead measure, not a comparison.

## Caveats and known limitations

- **Localhost-only.** The default DNS listener is `127.0.0.1:15053`. The harness binds load gen, gateway, CP stub, and upstream stub all on `127.0.0.1`, so this is single-host. No remote-client measurements.
- **No baseline for mesh-internal traffic.** Mesh-internal hostnames are synthesised by `DnsResolutionTable::from_mesh_slice` from the slice — they don't exist anywhere else. Report numbers absolute, not comparative.
- **macOS vs Linux UDP recv.** Linux uses `recvmmsg` for the gateway UDP frontend recv; macOS falls back to `recvfrom`. Same query/response shape but somewhat different cliff-edge throughput. Capture baselines per-OS.
- **No mTLS to the CP stub.** `FERRUM_DP_CP_GRPC_URLS=http://...` keeps the gRPC channel plaintext. Production mesh DPs would use `https://` + the CA bundle; this harness skips that on purpose.
- **Slice churn is not measured.** The CP stub publishes one slice and idles. The slice-apply path (which atomically rebuilds `DnsResolutionTable` via `ArcSwap`) is exercised exactly once at startup. For slice-churn perf, run `tests/performance/mesh/`'s `slice_apply` bench.
- **No response-cache eviction stress.** The default cache (4096 entries) is large enough that all of the harness's queries fit. To exercise eviction, generate distinct wildcard names per worker and set `FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES=64`.

## Extending

Add a name class:
1. Extend `slice::build_synthetic_slice` with the workload / ServiceEntry the class depends on.
2. Add an entry to `slice::workload_names()`.
3. Add a `NameClass` variant in `metrics.rs` and append it to `NameClass::ALL`.
4. The load gen and report path pick it up automatically.

Add a different mesh topology:
1. Set `FERRUM_MESH_TOPOLOGY=...` in `run.sh::start_gateway`.
2. Update the listener ports if the topology binds different defaults.
3. The DNS proxy is topology-independent — same numbers apply.
