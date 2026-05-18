# Mesh DNS Proxy E2E Baseline

**Directional reference numbers only.** Hardware-specific. Regenerate on the production-equivalent host before treating any of these as targets.

To regenerate:
```bash
cd tests/performance/mesh-dns-e2e
./run.sh --duration 60 --concurrency 100
```

## Via gateway (127.0.0.1:15053)

UDP transport:

| Name class | qps | p50 | p90 | p99 | Notes |
|---|---|---|---|---|---|
| mesh-internal | _TBD_ | _TBD_ | _TBD_ | _TBD_ | exact `DnsResolutionTable.exact` hit |
| mesh-wildcard | _TBD_ | _TBD_ | _TBD_ | _TBD_ | one-label wildcard suffix match |
| upstream-forward | _TBD_ | _TBD_ | _TBD_ | _TBD_ | UDP forward to `dns_upstream_stub` |

TCP transport (RFC 1035 §4.2.2 length-framed):

| Name class | qps | p50 | p90 | p99 | Notes |
|---|---|---|---|---|---|
| mesh-internal | _TBD_ | _TBD_ | _TBD_ | _TBD_ | |
| mesh-wildcard | _TBD_ | _TBD_ | _TBD_ | _TBD_ | |
| upstream-forward | _TBD_ | _TBD_ | _TBD_ | _TBD_ | |

## Direct baseline (dns_upstream_stub)

Only the upstream-forward class is meaningful here (mesh-internal / mesh-wildcard names exist only inside the gateway).

| Class | Transport | qps | p50 | p90 | p99 |
|---|---|---|---|---|---|
| upstream-forward | UDP | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| upstream-forward | TCP | _TBD_ | _TBD_ | _TBD_ | _TBD_ |

## Interpretation

- **Mesh-internal hit latency** measures `DnsResolutionTable::resolve` exact-path plus response template construction. Should be dominated by the `DashMap` cache hit on the second-and-later identical queries (`cached_mesh_response`).
- **Mesh-wildcard latency** adds a one-label suffix scan (sorted by suffix length) — expect a small p99 bump versus exact matches.
- **Upstream-forward latency** = round-trip to `dns_upstream_stub` + gateway txid rewriting cost. Subtract the direct-stub baseline to attribute gateway overhead.
- **EDNS(0)** (`--edns 1232`): adds OPT record echo work in `append_opt_record` and one cache-key dimension. Expect modest p99 widening if the response cache thrashes.
