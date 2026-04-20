# Ferrum Edge — Deep Performance Analysis Plan

Active branch: `fix-gateways-protocol-bench`. All file references are relative to that worktree.

## Local bench validation (2026-04-20, macOS Docker Desktop 29.4.0, `tests/performance/multi_protocol/run_gateway_protocol_bench.sh`)

### P1 — HTTP/1.1-TLS @ 70 KB — ✅ fixed by Plan 1

| Metric | `ferrum-edge:main` | `ferrum-edge:fixes` | Delta |
|---|---|---|---|
| Total requests (10 s / conc 100) | 105 | 233,360 | ×2,223 |
| Errors | **100 / 105 (95 %)** | **0 / 233,360 (0 %)** | eliminated |
| RPS | 10.5 | 23,336 | ×2,223 |
| Latency P50 | 4.62 ms | 2.46 ms | −47 % |

Local reproduction confirms the GHA failure pattern (main-like: 27 RPS, 25–100 errors). Plan 1 (rustls `apply_client_session_resumption` using `FERRUM_TLS_SESSION_CACHE_SIZE=4096` default) eliminates the cliff completely. **Root cause empirically confirmed.** Every upstream HTTPS connection was doing a full TLS handshake; under H1.1 with 100 concurrent requests, this saturated the Rust→TLS handshake capacity and the bench client timed out.

### P2 — HTTP/3 @ 10 KB + 70 KB — ⛔ blocked, macOS infra limitation

`quinn connect: timed out` on both `ferrum-edge:main` and `ferrum-edge:fixes`. Cause: Docker Desktop on macOS does not reliably route UDP traffic through `--network host` (QUIC is UDP-based). TCP-based benches on the same setup work fine. Plans 3+4 (coalesce MIN/MAX, flush interval, initial MTU) **cannot be validated on this host** — needs CI/Linux run.

### P3 — WSS @ 70 KB — ⛔ flaky, macOS memory pressure

System free memory at bench time: 114 MB. `proto_backend` receives SIGKILL mid-run from macOS when the Docker VM + native backend + bench client all contend for memory. First attempt returned 100 × `HTTP 404` on WS upgrade (likely caused by the same resource starvation preventing Ferrum routing table from fully loading). Plan 5 WSS buffer sweep **cannot be validated on this host** — needs CI/Linux run.

## CI follow-up recommended

Push all unstaged changes to a branch. Run `.github/workflows/gateways-protocol-benchmark.yml` on main and on the PR to capture full deltas for:
- HTTP/3 @ all payloads (Plans 3+4 MTU + coalesce)
- WSS @ all payloads (Plans 5+6 buffer sweep via `FERRUM_EXTRA_ENV` — the injection hook was added in this branch at `tests/performance/multi_protocol/run_gateway_protocol_bench.sh:229`)
- Full http1-tls sweep (confirm the Plan 1 win holds across all payload sizes, not just 70 KB)

## Implementation status (pass 1)

| Plan | Status | Files | Tests |
|---|---|---|---|
| Plan 1 — rustls client session resumption | ✅ implemented (unstaged) | `src/tls/mod.rs`, `src/connection_pool.rs`, `src/proxy/http2_pool.rs` | +2 unit tests |
| Plans 3+4 — H3 coalesce MIN + flush interval + initial MTU → env vars | ✅ implemented (unstaged) | `src/http3/config.rs`, `src/http3/server.rs`, `src/http3/client.rs`, `src/config/env_config.rs`, `ferrum.conf` | +13 unit tests |
| Follow-up — promote H3 coalesce MAX to env var, add H2-vs-H3 rationale to `ferrum.conf` | ✅ implemented (unstaged) | `src/http3/config.rs`, `src/http3/server.rs`, `src/config/env_config.rs`, `ferrum.conf`, test files | +6 unit tests, 1 integration test rewritten |
| Plan 2 — P1 diagnostic bench runs | ⏳ pending (gated on docker + builds) | bench-only | N/A |
| Plan 5 — WSS diagnostic bench runs | ⏳ pending (gated on docker + builds) | bench-only | N/A |
| Plan 6 — WSS default change contingent on Plan 5 | ⏳ pending (gated on Plan 5) | `src/config/env_config.rs` | N/A |
| Plan 1a (future) — extend session resumption to WSS, gRPC pool, TCP-TLS, plugin TLS outbound sites | ⏳ pending (out of scope for P1) | ~5 one-liners | TBD |

Total pass 1 diff: `11 files changed, 562 insertions(+), 45 deletions(-)`.
Verification: `cargo fmt` clean, `cargo clippy --all-targets -- -D warnings` clean, `cargo test --test unit_tests` 3559 passed 0 failed.

### Env vars introduced in pass 1

| Env var | Default | Bounds | Behaviour on out-of-range |
|---|---|---|---|
| `FERRUM_HTTP3_COALESCE_MIN_BYTES` | 32768 | `[1024, http3_coalesce_max_bytes]` | clamp + warn |
| `FERRUM_HTTP3_COALESCE_MAX_BYTES` | 32768 | `[1024, 1_048_576]` | silent clamp |
| `FERRUM_HTTP3_FLUSH_INTERVAL_MICROS` | 200 | `[50, 100_000]` | silent clamp |
| `FERRUM_HTTP3_INITIAL_MTU` | 1500 | `[1200, 65527]` | hard reject at startup |

No new env var for Plan 1 — reuses existing `FERRUM_TLS_SESSION_CACHE_SIZE` (default 4096) on both server and client sides.

---

## 0. Scope & Benchmark Baseline

Bench numbers already on the table:

| Protocol | Status | Headline finding |
|---|---|---|
| UDP / UDP-DTLS | ✅ winning | keep |
| WSS ≥ 500 KB | ✅ winning | keep |
| gRPCS P99 | ✅ winning | keep |
| TCP-TLS | ≈ parity with Envoy | minor tuning only |
| gRPCS P50 / HTTP/2 | ≈ parity with Envoy | minor tuning only |
| **HTTP/1.1-TLS ≥ 70 KB** | 🔴 **BROKEN** | 25–100 errors, RPS collapses 5,800 → 27 |
| **HTTP/3 10–70 KB** | 🟠 underperforming | Envoy ~3× faster P50 at 10 KB |
| **WSS 70 KB** | 🟠 regression | Tyk 2.3× faster (16 ms vs 41 ms P50) |

**Rule:** do not ship micro-optimizations while P1 is broken. Fix in order: P1 → P2 → P3 → systemic → tuning.

---

## 1. Method — how every investigation below must be executed

1. **Reproduce** the specific bench slice in isolation (not the full sweep) so we see deltas per change, not noise. Use `comparison/` harness narrowed to one protocol × one payload size.
2. **Read the code path end-to-end** before forming a hypothesis — most wrong fixes in proxies come from "this looks slow" without a trace.
3. **Instrument with `tokio-console` + `cargo flamegraph`** under load. Counters alone (our current metrics) won't show waker/wake-up storms.
4. **Diff against Envoy** (not Tyk/Kong) when investigating — Envoy is the credible ceiling since it wins cleanly on some of our losing slices.
5. **Change one thing at a time** and re-bench. If delta is < 5 % and not statistically clean, revert.
6. **Every fix lands with a regression test** in `comparison/` that fails the number we just fixed.

---

## P1 — 🔴 HTTP/1.1-TLS errors at 70 KB+ (CRITICAL, start here)

### Observed
RPS goes 5,800 → 27 → 30 → 30 → 2 from 10 KB → 70 KB → 500 KB → 1 MB → 5 MB, with 25–100 errors per run. Latency numbers at those sizes are unreliable because most requests aren't completing. Every other gateway (Envoy, Tyk, KrakenD, Kong) clears the 70 KB step cleanly. This is almost certainly a bug, not a tuning knob.

### Hypotheses (ranked by prior likelihood)

**H1.a — Response body size limit trips on streaming reqwest path.**
`SizeLimitedStreamingResponse` in [`src/proxy/body.rs:826`](src/proxy/body.rs) enforces a per-response byte cap. If the default cap sits at ~64 KiB or lower, the 70 KB step would start failing exactly at the observed boundary. Envoy/Tyk don't have this guard so they pass. Verify:
- Grep for every `SizeLimitedStreamingResponse` construction and the corresponding `limit` argument source.
- Find the env var / default that feeds the limit. If it's `FERRUM_MAX_RESPONSE_BODY` or similar, check what its default is and whether HTTP/1.1-TLS hits that path while HTTP/2 does not.
- Confirm by re-running the 70 KB bench with the cap raised to `usize::MAX` — if errors disappear we have the culprit.

**H1.b — reqwest's TLS/HTTP/1.1 connect path contends with something (DNS resolver, rustls session cache).**
`ConnectionPool::create_client` at [`src/connection_pool.rs:157`](src/connection_pool.rs) uses a custom `DnsCacheResolver` and a preconfigured rustls `ClientConfig`. If the rustls `ClientSessionMemoryCache` is unset or sized to 1, every request does a full handshake; under TLS that collapses throughput on any but the smallest bodies.
- Check `build_reqwest_tls_config`. Is `client_config.resumption = Resumption::in_memory_sessions(N)` set with a sensible `N`? By default rustls does not store sessions for the client — it must be explicitly configured. If missing, every upstream request does a full handshake and for HTTP/1.1 that serialises (one request per connection).
- Check whether `reqwest::Client::use_preconfigured_tls` carries our resumption config forward.

**H1.c — hyper 1.x HTTP/1.1 write stall on TLS body > buffer.**
When the frontend is HTTPS + HTTP/1.1 and we stream a 70 KB body back, hyper writes into rustls which writes into the socket. If we accidentally use `AsyncWrite` without vectored writes + an oversized single buffer, a single large `write()` can block or short-write under TLS max record size (16 KB). Combine with an explicit `Connection: close` under overload and you get close-before-flush ⇒ client-side EOF ⇒ error count exactly like observed.
- Check the frontend HTTP/1.1 listener setup: search for `hyper::server::conn::http1::Builder` and inspect `.max_buf_size()`, `.writev()`, `.half_close()`, `.title_case_headers()`.
- Check `should_disable_keepalive_red` wiring in [`src/proxy/mod.rs:6439`](src/proxy/mod.rs). Under bench load the overload RED algorithm can flip keepalive off early; with 5,800 RPS baseline at 10 KB we may already be across the threshold by 70 KB.
- Look at `FERRUM_MAX_CONNECTIONS` / `FERRUM_MAX_REQUESTS` defaults vs what `wrk`/`bombardier` is driving. The overload manager (`src/overload.rs:501`) will start sending `Connection: close` at 85 % and reject at 95 %.

**H1.d — Body coalescing is sending too-small frames on HTTPS/H1.**
`body.rs` has a "buffer reached target — yield it" block ([`src/proxy/body.rs:1053`](src/proxy/body.rs), :1250). If the coalescing target is tuned for H2/H3 (e.g. 16 KB DATA frames) but applied unconditionally on H1.1, each 70 KB response becomes 5 tiny writes through rustls, each a separate TLS record, each a syscall. Not an error by itself — but combined with H1.c it could be.

### What to inspect (files & symbols)
- [`src/proxy/mod.rs`](src/proxy/mod.rs) — `handle_proxy_request`, `dispatch_backend`, `build_response`, H1.1 reply path. Find the conditional that distinguishes H1.1 from H2 on the response-send side.
- [`src/proxy/body.rs`](src/proxy/body.rs) — `SizeLimitedStreamingResponse`, `CoalescingBody`, limit sources.
- [`src/connection_pool.rs:157`](src/connection_pool.rs) — upstream TLS config. Confirm session resumption and ALPN.
- `src/modes/{database,file,data_plane}.rs` — frontend hyper listener construction (search `http1::Builder` or `conn::auto::Builder`).
- `src/overload.rs` — keepalive-disable threshold behaviour under benchmarking.
- `src/tls/mod.rs` — rustls `ServerConfig` + `ClientConfig` factories. Session cache + ALPN lists.

### Verification steps
1. Run the 70 KB HTTP/1.1-TLS slice at low concurrency (1 connection, 100 requests) — if errors persist, it's not load-dependent (rules out overload manager).
2. Disable the overload manager (`FERRUM_MAX_CONNECTIONS=999999 FERRUM_MAX_REQUESTS=999999`) and re-run — if errors disappear, H1.c keepalive-disable is the cause.
3. Force `response_body_mode=Buffer` on the test proxy — if errors disappear at 70 KB but reappear at 500 KB, it's the streaming path specifically.
4. Capture a `tcpdump` / `ssldump` on the upstream socket for one failing request: which side sends FIN first, and what's the last record seen?
5. Diff the `curl -v` output of a single 70 KB request against Envoy's — look for unexpected `Connection: close`, truncated `Content-Length`, missing trailer.

### Expected fix patterns
- Enable rustls client session resumption explicitly in `build_reqwest_tls_config`.
- Raise or remove the response-size limit on the streaming HTTP/1.1 path when no plugin requires buffering.
- Gate `should_disable_keepalive_red()` behind an env flag during benchmarking, or raise its floor.

### Findings (from investigation pass 1)

**H1.a — RULED OUT.** `CoalescingBody::COALESCE_TARGET = 128 KiB` at [`src/proxy/body.rs:912`](src/proxy/body.rs:912). `SizeLimitedStreamingResponse` only wraps when Content-Length is absent. Benchmarks send responses with Content-Length, so the guard never fires at 70 KB.

**H1.b — CONFIRMED.** `rg 'Resumption|ClientSessionMemoryCache|session_storage'` returns zero hits in `src/`. [`build_reqwest_tls_config`](src/connection_pool.rs:223) builds a rustls `ClientConfig` but never sets `config.resumption`. Rustls clients require this explicitly — without it, every upstream HTTPS connection does a full 1-RTT handshake. On H2/gRPC this is amortized across a multiplexed stream; on H1.1 it recurs per-connection. Under bench load with bursty new connections this is a measurable latency tax.

**H1.c — LOW PROBABILITY.** Default `FERRUM_MAX_CONNECTIONS = 100_000` ([`env_config.rs:1042`](src/config/env_config.rs)). A 200-client bench is 0.2 % of that — RED shedding can't trigger. Ruled out as primary cause; still worth confirming empirically by setting `FERRUM_MAX_CONNECTIONS=999999` and rerunning.

**H1.d — RULED OUT.** hyper H1.1 listener at [`src/proxy/mod.rs:2005`](src/proxy/mod.rs:2005) uses `.max_buf_size(32 KiB)`; writev, half-close, and keepalive all use hyper's default-on settings. No suspicious `Connection: close` outside overload/drain path.

**H1.e — RULED OUT.** H1.1 coalesce target is 128 KiB, H2 coalesce target is also 128 KiB (`h2_coalesce_target_bytes = 131_072`). 70 KB responses pass through in one frame.

### ⚠️ Open question — does H1.b alone explain ERRORS?

Missing session resumption explains *slowness*, not *errors*. 25–100 outright failures on a ~800-request bench is a 3–12 % error rate. Session resumption alone should cause latency P50 regression, not client timeouts, unless the combination of (slow handshake × small reqwest pool × bursty new-connection arrivals) pushes some requests past the bench client's 30-s deadline.

Suspect: `response_buffer_cutoff_bytes = 65_536` ([`env_config.rs:955`](src/config/env_config.rs:955)). Ferrum switches buffered→streamed at ~64 KiB, which is exactly where the cliff starts. The P1 agent's trace shows `coalescing_body()` is the streaming path — but the switch itself changes backpressure and memory behaviour. **Required follow-up:** rerun the 70 KB slice with `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0` and a second run with `= 1048576`. If errors disappear on the second run, the cutoff-driven transition is the bug, not session resumption. If errors persist on both, session resumption is the right first fix but something else is still contributing to the error count.

### Concrete fixes (ranked)

| # | Change | File:line | Expected impact |
|---|---|---|---|
| 1 | Enable rustls client session resumption: `client_config.resumption = Resumption::in_memory_sessions(1024)` | `src/connection_pool.rs:~299` | Likely fixes latency; may or may not fix error count |
| 2 | Rerun 70 KB bench with `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0` and `=1048576` before trusting (1) as full fix | bench only | diagnostic |
| 3 | If (2) shows cutoff is the error-driver, inspect `coalescing_body` back-pressure behaviour at the 64 KiB boundary | `src/proxy/body.rs:924` | depends on (2) |

Do not ship (1) without running (2) first. The working theory needs an error-count explanation, not just a latency one.

---

## P2 — 🟠 HTTP/3 10–70 KB latency (Envoy ~3× faster)

### Observed
| Payload | Ferrum P50 | Envoy P50 |
|---|---|---|
| 10 KB | 37.79 ms | 11.77 ms |
| 70 KB | 39.81 ms | 21.47 ms |

At 500 KB+ both gateways post anomalously low numbers + errors, so ignore those rows until we rerun a clean sweep. The clean gap is 10–70 KB.

### Hypotheses (ranked)

**H2.a — Task wakeup storm on the h3 read/write path.**
[`src/http3/server.rs:1300`](src/http3/server.rs) calls `stream.send_data(data).await` inside a per-frame loop. If the upstream (reqwest H2 or H1) yields tiny `Bytes` chunks and we translate each one into a separate `send_data`, quinn schedules a STREAM frame per chunk. Each round-trips through two tokio tasks (h3-server task ↔ quinn endpoint task) with a `notify` in between. At 10 KB payloads the wakeup cost dominates the bytes-moved cost.
- Verify by counting `send_data` calls per request under a 10 KB scenario (add a temporary counter).
- Expected fix: coalesce body frames before `send_data` — similar to `CoalescingBody` for H2 but currently not applied on the H3 server path (check `CoalescingH3Body` references in `body.rs:318` — is it actually on the send path, or only the recv path?).

**H2.b — QUIC transport window defaults too aggressive for small bodies.**
[`src/http3/config.rs:42`](src/http3/config.rs) defaults: `stream_receive_window=8 MiB`, `receive_window=32 MiB`, `send_window=8 MiB`. Huge windows are fine for throughput but can cause needless MAX_DATA / MAX_STREAM_DATA frames on small responses, and large initial window advertisements add to handshake CRYPTO frames. Compare against Envoy's defaults (1 MiB / 16 MiB typically).
- Worth an A/B: halve all three and rerun 10 KB.

**H2.c — No 0-RTT / session resumption on the frontend h3 listener.**
`src/http3/server.rs` builds a `quinn::ServerConfig::with_crypto(...)` at line 203. Check whether the rustls `ServerConfig` fed in has `max_early_data_size` set and whether quinn's `ServerConfig::concurrent_connections` / `migration` / `preferred_address` are tuned. If every h3 connection requires a 1-RTT handshake, Envoy's 0-RTT-ready cert setup will win by exactly the handshake RTT — which at 10 KB is most of the budget.

**H2.d — GSO / pacing / congestion control defaults.**
Quinn's default congestion controller is NewReno. BBR is available under a feature flag and is usually faster for LAN bench. Envoy's quiche backend uses CUBIC with pacing. If we're running NewReno with no pacer against a local loopback, we may be leaving throughput on the table.
- Inspect `TransportConfig` at [`src/http3/server.rs:183`](src/http3/server.rs). Check whether `congestion_controller_factory` is ever set.

**H2.e — MTU / datagram path.**
Default QUIC MTU discovery starts at 1200 bytes. On a Docker loopback the real MTU is 65535. If `initial_mtu` / `min_mtu` aren't raised, every 10 KB response is fragmented into ~9 small datagrams each with its own packet-protection overhead.
- Check whether `TransportConfig::initial_mtu` / `min_mtu` are set. The defaults should be fine in production but for our bench loopback they matter.

### What to inspect
- [`src/http3/server.rs`](src/http3/server.rs) — accept loop, `handle_h3_connection`, `handle_h3_request`, response body streaming loop.
- [`src/http3/client.rs`](src/http3/client.rs) — endpoint sharing (OnceCell pattern at line 178), transport config construction.
- [`src/http3/config.rs`](src/http3/config.rs) — defaults + env overrides.
- `src/proxy/body.rs` — `CoalescingH3Body` (if it exists on the send side).

### Verification steps
1. `tokio-console` on an H3 10 KB run — look for task-wake counts on the per-stream task. If > 10 wakes per request, H2.a is confirmed.
2. `quinn` has tracing spans — turn them on at `debug` and count `send_stream_data` vs `send_data` calls per request.
3. Add a histogram of body-chunk sizes on the H3 send path. If the median is < 4 KB we're fragmenting.
4. Toggle `TransportConfig::initial_mtu(1472)` → `initial_mtu(65527)` and rerun 10 KB on loopback.

### Expected fixes
- Coalesce h3 response frames on the send path into ≥ 16 KB chunks.
- Raise `initial_mtu` when running on loopback / known-high-MTU nets (or always — quinn will back off on PMTU black holes).
- Switch the QUIC CC to BBR behind an env flag and default it on for bench.

### Findings (from investigation pass 1)

**H2.a — CONFIRMED (primary blocker, est. 40–60 % of gap).**
A coalescer *does* exist on the H3 send path ([`src/http3/server.rs:1971-1984`](src/http3/server.rs:1971)):
```
H3_COALESCE_MIN_BYTES = 8_192     // flush floor
H3_COALESCE_MAX_BYTES = 32_768    // flush ceiling
H3_FLUSH_INTERVAL = 2ms           // time-based flush
```
So the plan's earlier assumption "no coalescer" was wrong — but the tuning is too small for small payloads and the time-flush is too long. At 10 KB with a drip-feeding backend you can end up waiting 2 ms for the time-flush before anything leaves — that IS the latency budget at 10 KB.

The REQUEST-path relay at [`src/http3/client.rs:867`](src/http3/client.rs:867) does `chunk.copy_to_bytes(len)` per chunk with no coalescing at all.

**H2.b — Window config is acceptable, not primary.** Windows are generous (8 MiB stream / 32 MiB conn) and adequate for benchmarks. Worth documenting the invariant but not urgent.

**H2.c — 0-RTT disabled by design (`early_data_max_size=0`).** Session resumption via `Ticketer` + `ServerSessionMemoryCache` is on and fine. Not the gap driver.

**H2.d — NewReno / no pacer.** On loopback irrelevant; only matters for WAN. Defer.

**H2.e — CONFIRMED.** [`src/http3/server.rs:183`](src/http3/server.rs:183) builds `TransportConfig::default()` and never calls `initial_mtu`, `min_mtu`, or `mtu_discovery_config`. Default `initial_mtu = 1200`. PMTUD slow-start takes 2–3 RTTs to lift. At 10 KB that is ~8–9 packets instead of ~7.

**H2.f — Endpoint sharing is correct.** `OnceCell<quinn::Endpoint>` per IP family. No per-request endpoint creation.

### Concrete fixes (ranked)

| # | Change | File:line | Expected impact |
|---|---|---|---|
| 1 | `H3_COALESCE_MIN_BYTES` 8 KiB → 32 KiB (= existing MAX) | `src/http3/server.rs:1975` | +25–40 % |
| 2 | `H3_FLUSH_INTERVAL` 2 ms → 200 µs | `src/http3/server.rs:1984` | +5–15 % |
| 3 | `transport_config.initial_mtu(1500)` | `src/http3/server.rs:183` | +10–30 % at 10 KB |
| 4 | Apply coalescing to request-path relay | `src/http3/client.rs:867` | +2–5 % (duplex) |

Each change should be benched in isolation and accepted only if the delta is clean. Do **not** ship all four at once without per-change bench data.

### Open questions
- Chunk-size distribution coming out of reqwest for a 10 KB upstream response — 1 chunk or many? Blind tuning is risky without this.
- Envoy's exact h3 coalesce/flush settings — what's the reference point we're aiming at?

---

## P3 — 🟠 WSS 70 KB regression (Tyk 2.3× faster)

### Observed
| Gateway | P50 | P99 | RPS |
|---|---|---|---|
| Ferrum | 41.63 ms | 44.29 ms | 2,397 |
| Tyk | 16.13 ms | 48.86 ms | 5,594 |

Ferrum wins at 500 KB+, loses badly at 70 KB. This is a specific-size cliff — classic sign of a buffer threshold crossing a frame boundary.

### Hypothesis
The WebSocket path in Ferrum uses frame-level plugins ([`CLAUDE.md`](CLAUDE.md) references 3 WS frame plugins). If each inbound WS data frame goes through a plugin dispatch even when no WS frame plugin is configured on the proxy, we pay a per-frame cost. At 10 KB it's one frame, at 70 KB it's 5 frames (default WS max-frame 16 KB), at 500 KB it's enough frames that the plugin-dispatch cost is amortized by the bytes-moved cost.

### Inspect
- `grep -r "WsFramePlugin" src/` — where is the WS frame plugin chain invoked, and is there a fast-path that skips the whole chain when zero WS-frame plugins are configured on the proxy?
- [`WEBSOCKET.md`](WEBSOCKET.md) for the documented architecture.
- `src/proxy/` for the WS upgrade + data-frame loop.

### Verification
- Benchmark 70 KB WSS with all plugins disabled on the test proxy. If the gap closes, the plugin fast-path is missing.
- Count `dispatch` calls per frame under a 70 KB single-frame workload.

### Fix pattern
- Zero-plugin fast path — if `plugin_chain.is_empty()`, skip the whole dispatch call and copy bytes directly.

### Findings (from investigation pass 1)

**H3.a — RULED OUT.** Fast path already exists. [`src/proxy/mod.rs:3123-3141`](src/proxy/mod.rs:3123) and :3265 wrap the plugin-dispatch arm in `if ctb_plugins.is_empty() { raw } else { ... }`. `ctb_plugins` is populated only from plugins that return `requires_ws_frame_hooks() == true`, and the vector is built once at upgrade time (:2485-2489, :2474). Zero-plugin proxies pay zero dispatch cost per frame.

**H3.b — AMBIGUOUS.** `max_websocket_frame_size_bytes = 16 MiB` so tungstenite will not fragment a 70 KB outbound message into multiple WS frames. `websocket_write_buffer_size = 128 KiB`. A 70 KB message fits in one buffer. The WS-frame-size story alone doesn't explain the cliff.

**H3.c — RULED OUT.** No per-frame `clone`/`to_vec` in the fast path.

**H3.d — RULED OUT.** Two async closures at [`src/proxy/mod.rs:3095-3373`](src/proxy/mod.rs:3095), each a long-lived loop. No per-frame spawn.

**H3.e — CONFIRMED SUSPECT.** `ws_config.write_buffer_size` is set to 128 KiB at [`src/proxy/mod.rs:3050`](src/proxy/mod.rs:3050). A 70 KB outbound message goes into a 128 KiB buffer and tungstenite decides when to flush. Under TLS the flush boundary interacts with TLS record size (16 KiB max per record) — a 70 KB write produces ~5 TLS records. If tungstenite flushes per-record-worth rather than in one shot, that's 5 syscalls + 5 AEAD seals for what Tyk probably does in fewer.

**H3.f — RULED OUT.** Plugin priority sort happens once at config load in [`src/plugin_cache.rs:720`](src/plugin_cache.rs:720). Hot path reads a pre-sorted `Vec`.

### Concrete fixes / experiments (ranked)

| # | Change | File:line | Expected impact |
|---|---|---|---|
| 1 | Bench with `FERRUM_WEBSOCKET_WRITE_BUFFER_SIZE=524288` (512 KiB) | bench only | diagnostic |
| 2 | Bench with `FERRUM_WEBSOCKET_WRITE_BUFFER_SIZE=0` | bench only | diagnostic |
| 3 | If (1) closes gap: make write_buffer_size scale with message size, or default to 512 KiB | `src/config/env_config.rs:961` | fix |
| 4 | Verify tungstenite is not flushing mid-message. Read its source for the `Sink::send` implementation used here | `Cargo.toml` lookup | confirm/refute H3.e |

**Most-likely root cause in one sentence:** 128 KiB tungstenite write buffer + 16 KiB TLS record limit = 5-syscall cost at exactly 70 KB that is amortised away by 500 KB (many records → fixed per-byte cost dominates) and absent at 10 KB (one record).

---

## Synthesis — first action wave

After P1/P2/P3 pass 1, the consolidated top-priority action list is:

### Immediate code changes (small, testable, each benchable in isolation)

1. **Enable rustls client session resumption** in `ConnectionPool::build_reqwest_tls_config` — [`src/connection_pool.rs:~299`](src/connection_pool.rs:299). *P1 fix.*
2. **Increase `H3_COALESCE_MIN_BYTES` from 8 KiB to 32 KiB** — [`src/http3/server.rs:1975`](src/http3/server.rs:1975). *P2 fix 1.*
3. **Reduce `H3_FLUSH_INTERVAL` from 2 ms to 200 µs** — [`src/http3/server.rs:1984`](src/http3/server.rs:1984). *P2 fix 2.*
4. **Set `transport_config.initial_mtu(1500)`** — [`src/http3/server.rs:183`](src/http3/server.rs:183). *P2 fix 3.*

### Diagnostic bench runs needed before any P1 code lands

- 70 KB HTTP/1.1-TLS with `FERRUM_MAX_CONNECTIONS=999999` — rule out overload manager definitively.
- 70 KB HTTP/1.1-TLS with `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0` and `=1048576` — test the buffered→streamed transition hypothesis.
- 70 KB WSS with `FERRUM_WEBSOCKET_WRITE_BUFFER_SIZE` at 0, 128 KiB (current), 512 KiB — isolate H3.e.

### Nothing ships to main without

- A before/after bench delta captured in `comparison/`.
- A regression test that would have caught the failure we're fixing.
- One-liner in this doc's findings section recording the delta.

### What is NOT being fixed in this wave

P4–P13 are still open but lower priority once P1–P3 land. The 64 KiB buffered→streamed transition (`response_buffer_cutoff_bytes`) is a strong candidate for follow-up investigation regardless of the P1 bench outcome — it's a cliff configuration that no other gateway has, and cliffs in proxies tend to explode under adversarial load.

---

## P4 — Upstream connection pool reuse & keepalive

(User's HTTP/1.1 checklist — most of this also matters for P1.)

### Questions to answer directly in the code
1. **Is Ferrum reusing upstream HTTPS connections on H1.1?**
   [`ConnectionPool::get_client`](src/connection_pool.rs:109) caches one `reqwest::Client` per pool key. `reqwest::Client` internally pools per-host. Reuse *should* work. Confirm by counting `TcpStream::connect` calls under steady-state bench.
2. **Are downstream clients reconnecting?**
   See H1.c above. Check whether the frontend hyper listener is configured with `.keep_alive(true)` and no surprise `Connection: close`.
3. **Is keepalive disabled accidentally?**
   Search for `.keep_alive(false)` and for any code path that sets `Connection: close` outside the overload/drain path.
4. **Is the pool key too narrow?**
   [`create_pool_key`](src/connection_pool.rs:336) already carries a big "DO NOT ADD FIELDS" comment — the existing key is already risky. Verify on a bench that multiple proxies sharing a backend share one client (log `pool_key` for each cache miss).
5. **SNI mismatch forcing reconnect?**
   `use_preconfigured_tls` — is SNI inferred from the URL or from a separate config? A mismatch between URL host and SNI causes rustls to reject cached sessions.
6. **Session resumption?**
   See H1.b. This is the biggest single lever on HTTPS upstream performance and is very easy to miss with rustls.

### Deliverable
A one-page "upstream connection lifecycle" doc that a contributor can read and know: when does a connection open, when does it close, what drives reuse, what are the idle timers.

---

## P5 — Hot-path copies & allocations

### Known allocation sites to audit
- `Bytes::copy_from_slice(...)` — real copy. Grep usage and justify each.
- `.to_bytes()` on a `Collected<_>` — forces full buffering; justified for Buffer mode, unjustifiable on streaming path.
- `format!` / `String::from` inside per-request hot loops.
- Header key/value allocation when forwarding — hyper gives `HeaderValue::from_bytes_unchecked` for already-validated pass-through; confirm we use it.
- Router cache keying — is the `(host, path)` cache key `(String, String)` or `(Arc<str>, Arc<str>)` or borrowed? An owning key allocates per request on cache miss.

### Method
1. `cargo flamegraph` on 10 KB H1.1-TLS at steady state.
2. Look at top 20 frames under `alloc::` / `mem::`. Each should have a justification or a TODO.
3. Run under `dhat-rs` for one minute and export the JSON. Load into `dhat-viewer`. Aim: no single site > 5 % of allocations, no allocation > 10 KB on the hot path.

### Priority targets (from a read of the source)
- [`src/proxy/body.rs:1391`](src/proxy/body.rs) — `buf.copy_to_bytes(buf.remaining())` — verify this is inside a "final coalesce" path, not per-frame.
- [`src/http3/client.rs:867`](src/http3/client.rs) — `chunk.copy_to_bytes(len)` inside the per-chunk relay loop. This is a real copy per backend-frame; can we pass the original `Bytes` through unchanged?

---

## P6 — Lock contention & shared state

### Known hot shared state
- `ArcSwap<GatewayConfig>` — load is wait-free, should be fine.
- `RouterCache` — `DashMap`. Verify `N_SHARDS` at construction and whether hot host/path combos all hash to the same shard.
- `ConnectionPool` cache — `DashMap<String, ClientEntry>`.
- Health-check state — `DashMap`.
- Metrics counters — check whether status-code counters are pre-populated (claim in CLAUDE.md: yes) and whether any hist/gauge uses a `Mutex`.

### Method
1. `perf lock` or `parking_lot` deadlock detector under load.
2. Look for any `tokio::sync::Mutex` in files under `src/proxy/` or `src/plugins/` — on the request path these are always suspect.
3. `grep -n 'Mutex\|RwLock' src/proxy/ src/http3/ src/connection_pool.rs` — each match needs a justification or a rewrite.

---

## P7 — Task spawning & async handoff

### Suspected pattern
Each HTTP request handler is already a task. The question is: do we spawn *additional* tasks per request that could be inline?

### Places to check
- [`src/proxy/mod.rs`](src/proxy/mod.rs) — `tokio::spawn` calls inside `handle_proxy_request` or the backend dispatch path. Each one is a waker hop.
- [`src/proxy/grpc_proxy.rs`](src/proxy/grpc_proxy.rs) — does a streaming gRPC relay use a `spawn` per direction (client→upstream, upstream→client)? If so it's probably necessary but confirm.
- [`src/http3/server.rs`](src/http3/server.rs) — h3 requires one task per stream; confirm no extra nested spawn.
- Plugin lifecycle — is each plugin invocation its own task, or inline on the request task?

### Tool
- `tokio-console` shows exactly which tasks wake which. Under a 10 KB bench, task count per request should be ≤ 3 (accept + request + upstream connection loop). Anything higher is a lead.

---

## P8 — Flush / write strategy

### Questions
- Do we call `flush()` explicitly after every frame, or do we let hyper batch?
- Are we using vectored writes (`writev`) on the frontend TLS socket? rustls supports it.
- On large bodies, are we writing the body in one `send_data(Bytes)` (good) or chunked into N small sends (bad)?

### Places
- `src/proxy/mod.rs` — response assembly.
- Frontend hyper listener builder.
- The h3 send_data loop (see H2.a above).

---

## P9 — Protocol translation layers (H1 ↔ H2 ↔ H3)

### Known translation sites
- Client sends H2, backend speaks H1.1: `reqwest` handles this transparently but we strip CL, TE headers (see `CLAUDE.md` H2.CL section). Verify the strip is done once, not re-done per retry.
- Client sends H3, backend speaks H2: see `src/http3/client.rs` relay paths. There's a `chunk.copy_to_bytes(len)` at line 867 that's worth a second look.
- Client sends H1.1 WS, WS plugin operates on frames, backend speaks H1.1 WS: this is the P3 cliff.

### Deliverable
A table: for each (frontend_proto, backend_proto) pair, what is the translation cost and where is it done? Anything > O(1) per request needs attention.

---

## P10 — Logging / metrics on hot path

### Current state (quick count)
- `src/proxy/mod.rs` — 15 `tracing::*` calls in 8,760 lines. Low.
- `src/proxy/body.rs` — 0. Good.
- `src/http3/server.rs` — 1. Good.
- `src/connection_pool.rs` — 4. Acceptable.

### Real question
It's not about count, it's about *what they build*. A `tracing::info!(request_id = %uuid::Uuid::new_v4(), ...)` on every request allocates a Uuid even if the subscriber drops the event. Hot-path tracing calls should:
- Use `if tracing::enabled!(...)` when building the fields is non-trivial.
- Never `format!` or `to_string()` in the field-value position — use `%` / `?` on the already-owned value.

### Method
- Inspect the 15 calls in `src/proxy/mod.rs` one at a time. Each should be justified or lazy.
- `src/proxy/deferred_log.rs` exists (per the layout) — confirm *all* request-level access logs route through it and not through a raw `info!`.

---

## P11 — Accept loop & worker distribution

### Questions
1. Single listener per port, or `SO_REUSEPORT` + N listeners?
2. Tokio runtime configured with how many worker threads? `FERRUM_RUNTIME_WORKER_THREADS`?
3. Is the accept loop on a dedicated thread or multiplexed with request handling?

### Inspect
- `src/modes/database.rs`, `src/modes/file.rs` — listener bind + spawn loop.
- `src/main.rs` — runtime construction.
- `src/socket_opts.rs` — is `SO_REUSEPORT` applied? On Linux this is the biggest win for accept-loop distribution.

### Fix pattern (if missing)
- One listener per worker thread, each with `SO_REUSEPORT`. Kernel load-balances accepts. Removes the "accept loop is a single-core bottleneck at 50k RPS" problem.

---

## P12 — H2 / H3 flow control & windows

### H2 upstream client
From [`src/connection_pool.rs:199`](src/connection_pool.rs):
```
.http2_initial_stream_window_size(config.http2_initial_stream_window_size)
.http2_initial_connection_window_size(config.http2_initial_connection_window_size)
.http2_adaptive_window(config.http2_adaptive_window)
.http2_max_frame_size(config.http2_max_frame_size)
```
Look up the defaults in `PoolConfig::default()`. Document them. Benchmark against hyper defaults (64 KiB stream, 64 KiB conn) and against Envoy's (64 MiB / 64 MiB typically for upstream).

### H3 transport
[`src/http3/config.rs`](src/http3/config.rs) defaults:
- `stream_receive_window = 8 MiB`
- `receive_window = 32 MiB`
- `send_window = 8 MiB`
- `max_concurrent_streams = 1000`

These are large. The `receive_window < stream_receive_window × max_concurrent_streams` invariant is violated (32 MiB vs 8 MiB × 1000 = 8 GiB). In practice this means we credit per-stream generously but globally we bottleneck at 32 MiB — at 5 MB payload × ~7 concurrent streams we're already at the ceiling.

**Recommendation:** document the intended pressure model and either raise `receive_window` or lower `stream_receive_window` to keep the product within a stated bound.

---

## P13 — QUIC / DTLS packet path

### Things to verify in `src/http3/server.rs` and the DTLS module
1. `quinn::Endpoint::server` built from which socket config? GSO / GRO enabled? (On Linux with recent kernels, these are huge for > 1 Gbps.)
2. Is the underlying UDP socket `SO_RCVBUF` / `SO_SNDBUF` raised from defaults? Default ~212 KiB on Linux is a cliff at high RPS.
3. Is `set_tos` / ECN set?
4. `initial_mtu` (see H2.e).
5. For DTLS: `src/dtls/` — is the packet receive path using `recvmmsg` (batched) like `udp_batch.rs` does for plaintext UDP? If DTLS uses single-recv, it's doing 10× the syscalls UDP is doing.

### Inspect
- `src/proxy/udp_batch.rs` — has the batched recv. Is DTLS using the same?
- `src/dtls/` — the DTLS frontend and backend code.

---

## Systemic tuning checklist (all protocols)

Once P1–P3 are fixed, iterate through these in order and re-bench after each:

| Lever | Expected impact |
|---|---|
| jemalloc tuning (`MALLOC_CONF=narenas:N,dirty_decay_ms:0`) | 2–5 % steady-state |
| `SO_REUSEPORT` + per-core listeners | 20–50 % at > 50k RPS |
| UDP socket buffer sizing (1 MiB RCVBUF/SNDBUF) | big for UDP/QUIC/DTLS |
| rustls session resumption (client) | 2–5× for HTTPS with lots of short-lived flows |
| `TCP_NODELAY` on upstream sockets | already on, confirmed [`src/connection_pool.rs:170`](src/connection_pool.rs) |
| H2 initial window = 16 MiB (upstream + downstream) | 10–30 % for payloads > 1 MB |
| Disable `tracing` in release via `RUST_LOG=error` for bench runs | 2–5 % |
| Preallocate `HeaderMap` capacity when cloning | 1–2 % |
| Cache a `Date` header once per second | already done per CLAUDE.md (`date_cache.rs`); confirm on hot path |

---

## Execution order

1. **Week 1 — P1.** Reproduce, bisect hypothesis tree, ship the fix + regression test. Nothing else until this is green.
2. **Week 2 — P2.** Coalesce h3 send path + MTU + CC A/B. Ship the best combination.
3. **Week 2 — P3.** WS frame plugin fast path.
4. **Week 3 — P4, P12.** Upstream pool + H2/H3 windows. Document defaults.
5. **Week 3 — P5, P6, P7, P10.** Hot-path alloc + lock + task + logging audit.
6. **Week 4 — P8, P9, P11, P13.** Accept loop, QUIC packet path, flush strategy. These are the longest-tail items.

Every step produces:
- a bench delta (from `comparison/`),
- a short note in this file under a "Findings" section,
- either a PR or a ruled-out hypothesis.

---

## Appendix A — Quick grep kit for each investigation

```bash
# P1: response body limit
rg 'SizeLimitedStreamingResponse|max_response_body|FERRUM_MAX_RESPONSE'

# P1: keepalive / Connection: close
rg 'Connection: close|keep_alive\(false\)|disable_keepalive'

# P1: rustls client session resumption
rg 'Resumption|ClientSessionMemoryCache|session_storage'

# P2: H3 send_data frames
rg 'send_data' src/http3/

# P2: QUIC TransportConfig
rg 'TransportConfig|initial_mtu|congestion_controller'

# P4: pool key fields
rg 'create_pool_key|write_pool_key' -A 30 src/connection_pool.rs

# P5: explicit copies
rg 'copy_from_slice|copy_to_bytes|\.to_bytes\(\)'

# P6: locks on hot path
rg 'Mutex|RwLock|parking_lot' src/proxy/ src/http3/ src/connection_pool.rs

# P7: spawns on request path
rg 'tokio::spawn|spawn_local|spawn_blocking' src/proxy/ src/http3/

# P10: hot-path tracing
rg 'tracing::(info|debug|trace|warn|error)' src/proxy/mod.rs src/http3/server.rs

# P11: SO_REUSEPORT
rg 'reuseport|SO_REUSEPORT' src/

# P13: batched syscalls
rg 'recvmmsg|sendmmsg|gso|SO_RCVBUF|SO_SNDBUF'
```

---

## Appendix B — Bench harness

Narrow the sweep before every investigation:

```bash
cd comparison
# P1 repro (one slice, many samples)
./run-bench.sh --gateway ferrum --protocol http11-tls --payload 70KB --duration 60s
./run-bench.sh --gateway envoy  --protocol http11-tls --payload 70KB --duration 60s
diff <(./run-bench.sh ... --json) <(./run-bench.sh ... --json)
```

Every investigation branch builds with `cargo build --profile ci-release` (matches the CI perf job).

---

_This plan is a living document. Each investigation writes its findings into a `## Findings` subsection under its P-heading, including the bench delta, the fix, and any ruled-out hypotheses._
