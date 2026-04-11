# Multi-Protocol Performance Tests

Performance test suite that benchmarks Ferrum Edge across all supported protocols: HTTP/1.1, HTTP/1.1+TLS, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, TCP, TCP+TLS, UDP, and UDP+DTLS.

Each test runs a **three-tier setup**: `proto_bench` (load generator) &rarr; `ferrum-edge` (proxy) &rarr; `proto_backend` (echo backend), then a direct baseline without the gateway for comparison.

## Quick Start

```bash
cd tests/performance/multi_protocol

# Run a single protocol test
./run_protocol_test.sh http2

# Run all protocol tests sequentially
./run_protocol_test.sh all

# Custom parameters
./run_protocol_test.sh grpc --duration 60 --concurrency 200

# JSON output (for CI / scripting)
./run_protocol_test.sh tcp --json

# Compare Ferrum Edge vs Envoy (requires envoy in PATH)
./run_protocol_test.sh all --envoy

# Compare a single protocol against Envoy
./run_protocol_test.sh http2 --envoy --duration 30 --concurrency 200
```

## Supported Protocols

| Protocol | Client &rarr; Gateway | Gateway &rarr; Backend | Gateway Port | Backend Port |
|----------|----------------------|----------------------|--------------|--------------|
| HTTP/1.1 | HTTP                 | HTTP                 | 8000         | 3001         |
| HTTP/1.1+TLS | HTTPS (ALPN http/1.1) | HTTP              | 8443         | 3001         |
| HTTP/2   | HTTPS + ALPN h2      | HTTPS + H2           | 8443         | 3443         |
| HTTP/3   | QUIC / HTTP3         | QUIC / HTTP3         | 8443         | 3445         |
| WebSocket| ws:// upgrade        | ws://                | 8000         | 3003         |
| gRPC     | h2c (HTTP/2 clear)   | h2c                  | 8000         | 50052        |
| TCP      | raw TCP              | raw TCP              | 5010         | 3004         |
| TCP+TLS  | TLS &rarr; gateway terminates | raw TCP       | 5001         | 3004         |
| UDP      | raw UDP              | raw UDP              | 5003         | 3005         |
| UDP+DTLS | DTLS &rarr; gateway terminates | raw UDP      | 5004         | 3005         |

## Architecture

```
                ┌───────────┐         ┌───────────────┐         ┌──────────────┐
                │proto_bench│ ──────► │ferrum-edge  │ ──────► │proto_backend │
                │(load gen) │         │(reverse proxy) │         │(echo server) │
                └───────────┘         └───────────────┘         └──────────────┘
                                           │
                proto_bench ───────────────►│ (direct baseline, no gateway)
```

### proto_backend

Multi-protocol echo backend that starts all servers on fixed ports:

| Server       | Port  | Description                         |
|-------------|-------|--------------------------------------|
| HTTP/1.1    | 3001  | HTTP/1.1 with keep-alive            |
| HTTP/2 h2c  | 3002  | Cleartext HTTP/2 with prior knowledge|
| HTTPS/H2    | 3443  | HTTP/2 over TLS (ALPN negotiated)    |
| WebSocket   | 3003  | WS echo (text + binary)             |
| gRPC h2c    | 50052 | Protobuf BenchService (UnaryEcho)   |
| TCP echo    | 3004  | Bidirectional byte echo             |
| TCP+TLS     | 3444  | TLS-wrapped TCP echo                |
| UDP echo    | 3005  | Datagram echo                       |
| HTTP/3      | 3445  | QUIC/HTTP3 server                   |
| DTLS echo   | 3006  | DTLS-wrapped datagram echo          |

Self-signed TLS certificates are generated at startup into `./certs/` (gitignored).

### proto_bench

Load testing binary with subcommands for each protocol:

```
proto_bench <http1|http2|http3|ws|grpc|tcp|udp> [OPTIONS]

Options:
  --target <URL|ADDR>     Target URL or address
  --duration <SECS>       Test duration (default: 30)
  --concurrency <N>       Concurrent connections (default: 100)
  --payload-size <BYTES>  Payload for echo tests (default: 64)
  --tls                   Use TLS/DTLS for TCP/UDP tests
  --json                  Output JSON instead of text
```

## Configuration

Gateway configs are in `configs/`. Each protocol has its own YAML file that configures the appropriate `backend_protocol` and ports.

Key environment variables set by the test runner:

| Variable | Value | Purpose |
|----------|-------|---------|
| `FERRUM_MODE` | `file` | File-based config |
| `FERRUM_LOG_LEVEL` | `error` | Minimize logging overhead during benchmarks |
| `FERRUM_ADD_VIA_HEADER` | `false` | Skip Via header to reduce per-request overhead |
| `FERRUM_ADD_FORWARDED_HEADER` | `false` | Skip Forwarded header construction |
| `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` | `0` | Disable request body size checking (no plugins = safe) |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` | `0` | Take fastest streaming path (no size limit checks) |
| `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` | `0` | Disable slowloris timer (avoids per-connection timer overhead) |
| `FERRUM_MAX_CONNECTIONS` | `0` | Disable connection semaphore (unlimited) |
| `FERRUM_MAX_HEADER_COUNT` | `0` | Disable per-request header count check |
| `FERRUM_MAX_URL_LENGTH_BYTES` | `0` | Disable per-request URL length check |
| `FERRUM_MAX_QUERY_PARAMS` | `0` | Disable per-request query param count check |
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | `200` | Prevent connection churn |
| `FERRUM_POOL_WARMUP_ENABLED` | `true` | Pre-establish backend connections at startup |
| `FERRUM_TLS_NO_VERIFY` | `true` | Accept self-signed certs |
| `FERRUM_ENABLE_HTTP3` | `true` | Enable QUIC listener (HTTP/3 test) |
| `FERRUM_FRONTEND_TLS_CERT_PATH` | `certs/cert.pem` | Gateway TLS cert |
| `FERRUM_DTLS_CERT_PATH` | `certs/cert.pem` | Gateway DTLS cert |
| `FERRUM_POOL_HTTP2_*` | (tuned) | H2 flow control: 8 MiB stream, 32 MiB conn windows |
| `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` | `1000` | Server-side H2 stream limit |
| `FERRUM_HTTP3_*` | (tuned) | H3/QUIC: 8 MiB stream, 32 MiB conn, 1000 max streams |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | `4` | QUIC connections per backend |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | `120` | H3 pool idle eviction timeout |
| `FERRUM_GRPC_POOL_READY_WAIT_MS` | `1` | gRPC pool sender wait before opening another backend H2 connection |
| `FERRUM_POOL_CLEANUP_INTERVAL_SECONDS` | `30` | Pool cleanup sweep interval (all pools) |
| `FERRUM_UDP_MAX_SESSIONS` | `10000` | Max concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | `10` | UDP session cleanup interval |
| `FERRUM_UDP_RECVMMSG_BATCH_SIZE` | `64` | Batched UDP recv (Linux only, falls back to try_recv_from on macOS) |

## Metrics Output

Text output (wrk-like format):

```
Running 30s test @ https://127.0.0.1:8443/api/users
  Protocol: HTTP/2
  100 concurrent connections

  Latency     Avg         Stdev       Max         +/- Stdev
              1.23ms      456.78us    12.34ms     72.31%

  Latency Distribution
     50%    1.05ms
     75%    1.45ms
     90%    2.10ms
     99%    5.80ms

  158340 requests in 30.00s, 22.45MB read
  Errors: 0

Requests/sec:  5278.00
Transfer/sec:      0.75MB
```

JSON output (`--json`):

```json
{
  "protocol": "HTTP/2",
  "target": "https://127.0.0.1:8443/api/users",
  "duration_secs": 30,
  "concurrency": 100,
  "total_requests": 158340,
  "total_errors": 0,
  "rps": 5278.0,
  "latency_avg_us": 1230,
  "latency_stdev_us": 456,
  "latency_max_us": 12340,
  "p50_us": 1050,
  "p75_us": 1450,
  "p90_us": 2100,
  "p99_us": 5800,
  "total_bytes": 23534280,
  "throughput_mbps": 6.28
}
```

## Benchmark Results

**Date**: 2026-04-10
**Environment**: macOS Darwin 25.4.0, Apple Silicon
**Duration**: 10s per test, 200 concurrent connections, 64-byte echo payload
**Build**: Release build with response body coalescing + adaptive buffering optimizations

### Through Gateway (client → gateway → backend)

| Protocol | Requests/sec | Avg Latency | P50 | P99 | Max | Errors |
|----------|-------------|-------------|------|------|------|--------|
| HTTP/1.1 | 93,976 | 2.12ms | 2.03ms | 4.42ms | 30.91ms | 0 |
| HTTP/1.1+TLS | 96,735 | 2.06ms | 1.99ms | 4.06ms | 26.96ms | 0 |
| HTTP/2 (TLS) | 56,268 | 3.55ms | 3.55ms | 4.88ms | 7.15ms | 0 |
| HTTP/3 (QUIC) | 53,722 | 3.71ms | 3.46ms | 5.95ms | 133.76ms | 0 |
| WebSocket | 104,322 | 1.91ms | 1.87ms | 3.21ms | 22.18ms | 0 |
| gRPC | 35,379 | 5.65ms | 5.61ms | 8.98ms | 16.16ms | 0 |
| TCP | 105,670 | 1.89ms | 1.86ms | 2.79ms | 33.82ms | 0 |
| TCP+TLS | 105,339 | 1.90ms | 1.86ms | 2.92ms | 7.12ms | 0 |
| UDP | 80,805 | 2.47ms | 2.48ms | 3.15ms | 14.10ms | 0 |
| UDP+DTLS | 74,221 | 2.68ms | 2.65ms | 3.83ms | 24.73ms | 0 |

### Direct Backend (client → backend, no gateway)

| Protocol | Requests/sec | Avg Latency | P50 | P99 | Max |
|----------|-------------|-------------|------|------|------|
| HTTP/1.1 | 201,006 | 993μs | 949μs | 2.11ms | 30.56ms |
| HTTP/1.1+TLS | 207,915* | 960μs | 939μs | 1.87ms | 4.66ms |
| HTTP/2 (TLS) | 344,923 | 578μs | 498μs | 1.60ms | 125.50ms |
| HTTP/3 (QUIC) | 78,146 | 2.56ms | 2.42ms | 3.68ms | 182.66ms |
| WebSocket | 207,763 | 961μs | 936μs | 1.86ms | 8.23ms |
| gRPC | 194,914 | 1.02ms | 861μs | 3.48ms | 127.55ms |
| TCP | 208,631 | 957μs | 945μs | 1.73ms | 3.63ms |
| TCP+TLS | 206,150 | 968μs | 953μs | 1.80ms | 13.90ms |
| UDP | 253,762 | 787μs | 717μs | 1.58ms | 12.02ms |
| UDP+DTLS | 99,200 | 2.01ms | 2.00ms | 2.51ms | 17.76ms |

*\*HTTP/1.1+TLS direct baseline uses plain HTTP since the backend has no TLS; the TLS overhead is entirely at the gateway.*

### Gateway Overhead

| Protocol | Gateway RPS | Direct RPS | Overhead | Notes |
|----------|------------|------------|----------|-------|
| HTTP/1.1 | 93,976 | 201,006 | ~53% | reqwest connection pool with keep-alive |
| HTTP/1.1+TLS | 96,735 | 207,915 | ~53% | TLS termination at gateway, plain HTTP to backend |
| HTTP/2 (TLS) | 56,268 | 344,923 | ~84% | hyper-native H2 pool with two-phase ready() multiplexing |
| HTTP/3 (QUIC) | 53,722 | 78,146 | ~31% | QUIC connection pool via quinn |
| WebSocket | 104,322 | 207,763 | ~50% | Tunnel mode (raw TCP copy, no frame parsing) |
| gRPC | 35,379 | 194,914 | ~82% | H2 multiplexing + protobuf passthrough |
| TCP | 105,670 | 208,631 | ~49% | Bidirectional copy with adaptive buffer sizing |
| TCP+TLS | 105,339 | 206,150 | ~49% | TLS termination + bidirectional copy (cached TLS config) |
| UDP | 80,805 | 253,762 | ~68% | Per-datagram session lookup + forwarding |
| UDP+DTLS | 74,221 | 99,200 | ~25% | DTLS termination + plain UDP forwarding |

> **Note:** Benchmark numbers vary between runs due to system load, thermal
> throttling, and background processes. Focus on the overhead ratios and relative
> comparisons rather than absolute RPS numbers.

> Tuning note: in one back-to-back local comparison, lowering the gRPC pool
> sender-ready wait from `5ms` to `1ms` improved gateway throughput by about
> `3.8%` (`64,278` -> `66,734` requests/sec at `10s`, `200` concurrency).
> Ferrum now defaults this knob to `1ms` via `FERRUM_GRPC_POOL_READY_WAIT_MS`.

## Envoy Comparison Mode

The `--envoy` flag runs each protocol benchmark through both Ferrum Edge and Envoy (native binary), using the **same backend, same load generator, same ports** — a true apples-to-apples comparison.

```bash
# Compare all supported protocols
./run_protocol_test.sh all --envoy --duration 30 --concurrency 200

# Compare a single protocol
./run_protocol_test.sh grpc --envoy
```

### How It Works

For each protocol, the runner:

1. Starts Ferrum Edge with its config, runs `proto_bench`, captures JSON results, stops Ferrum
2. Starts Envoy with an equivalent config, runs `proto_bench`, captures JSON results, stops Envoy
3. Runs the direct-backend baseline (same for both)
4. After all protocols, prints a comparison table

Both gateways run natively (no Docker), bind the same ports (sequentially), and connect to the same `proto_backend` echo server.

### Envoy-Compared Protocols

| Protocol | Envoy Config | Notes |
|----------|-------------|-------|
| HTTP/1.1 | `configs/envoy/http1.yaml` | `http_connection_manager` with `codec_type: HTTP1` |
| HTTP/1.1+TLS | `configs/envoy/http1_tls.yaml` | Downstream TLS termination, plain HTTP to backend |
| WebSocket | `configs/envoy/ws.yaml` | `upgrade_configs: websocket` on HCM |
| gRPC | `configs/envoy/grpc.yaml` | h2c (cleartext HTTP/2) on both sides |
| TCP | `configs/envoy/tcp.yaml` | `tcp_proxy` network filter |
| TCP+TLS | `configs/envoy/tcp_tls.yaml` | Downstream TLS + `tcp_proxy` |
| UDP | `configs/envoy/udp.yaml` | `udp_proxy` listener filter with matcher-based routing |

**Skipped protocols:**
- **HTTP/2** — hyper's raw h2c client gets `ConnectionReset` from Envoy on macOS (known h2c compatibility issue); gRPC already covers HTTP/2 semantics via tonic which works fine
- **HTTP/3 (QUIC)** — Envoy's QUIC support requires a special build with BoringSSL
- **UDP+DTLS** — No native Envoy DTLS termination

### Envoy Tuning

Envoy configs are tuned to match Ferrum Edge where applicable:

- HTTP/2 flow control: 8 MiB stream window, 32 MiB connection window, 1000 max concurrent streams
- Access logging disabled (`access_log: []`)
- Log level: `error` (`-l error`)
- Worker threads: auto (`--concurrency auto`, matches CPU cores)
- Admin interface on port 15000 (not benchmarked)

### Sample Comparison Output

Results from a local run on macOS (Apple Silicon M4 Max), 10s duration, 200 concurrent connections, 64-byte payload, Envoy 1.37.1.

```
=========================================================================================================
  Ferrum Edge vs Envoy — Through-Gateway Comparison
  Duration: 10s | Concurrency: 200 | Payload: 64 bytes
=========================================================================================================

| Protocol       |   Ferrum RPS |    Envoy RPS |    Δ RPS |  Winner |  Ferrum P50 |   Envoy P50 |  Ferrum P99 |   Envoy P99 |  Ferrum Avg |   Envoy Avg |
|----------------|--------------|--------------|----------|---------|-------------|-------------|-------------|-------------|-------------|-------------|
| http1          |      101,403 |       94,324 |    +7.5% |  Ferrum |      1.90ms |      1.33ms |      3.89ms |     14.10ms |      1.97ms |      2.12ms |
| http1-tls      |       90,066 |       77,713 |   +15.9% |  Ferrum |      2.11ms |       779μs |      4.70ms |     33.85ms |      2.21ms |      2.57ms |
| ws             |       89,057 |       89,782 |    -0.8% |   ~tie  |      1.90ms |       445μs |      7.84ms |     47.77ms |      2.24ms |      2.22ms |
| grpc           |       30,602 |       39,655 |   -22.8% |  Envoy  |      6.18ms |       970μs |     13.56ms |    131.84ms |      6.53ms |      5.04ms |
| tcp            |       95,637 |       75,349 |   +26.9% |  Ferrum |      1.88ms |       685μs |      6.25ms |     57.85ms |      2.09ms |      2.65ms |
| tcp-tls        |      108,622 |      106,695 |    +1.8% |   ~tie  |      1.80ms |      1.13ms |      3.06ms |     19.07ms |      1.84ms |      1.87ms |
| udp            |       91,102 |      104,969 |   -13.2% |  Envoy  |      2.18ms |      1.90ms |      2.75ms |      3.39ms |      2.19ms |      1.90ms |

======================================================================
  Gateway Overhead vs Direct Backend
======================================================================

| Protocol       |   Direct RPS |   Ferrum RPS |  Ferrum OH |    Envoy RPS |   Envoy OH |
|----------------|--------------|--------------|------------|--------------|------------|
| http1          |      212,915 |      101,403 |       ~52% |       94,324 |       ~55% |
| http1-tls      |      162,333 |       90,066 |       ~44% |       77,713 |       ~52% |
| ws             |      197,534 |       89,057 |       ~54% |       89,782 |       ~54% |
| grpc           |      110,513 |       30,602 |       ~72% |       39,655 |       ~64% |
| tcp            |      199,242 |       95,637 |       ~51% |       75,349 |       ~62% |
| tcp-tls        |      212,016 |      108,622 |       ~48% |      106,695 |       ~49% |
| udp            |      276,908 |       91,102 |       ~67% |      104,969 |       ~62% |
```

### Analysis

**Where Ferrum Edge wins:**

1. **HTTP/1.1 (+7.5%)** — Ferrum beats Envoy on raw throughput with significantly better P99 tail latency (3.89ms vs 14.10ms — 3.6× better). The reqwest connection pool with keep-alive and response body coalescing provides consistent performance.

2. **HTTP/1.1+TLS (+15.9%)** — Ferrum's largest advantage. TLS termination via rustls outperforms Envoy's BoringSSL at this concurrency level, with P99 of 4.70ms vs 33.85ms (7.2× better). This confirms rustls is highly competitive for TLS proxy workloads.

3. **TCP (+26.9%)** — Ferrum's adaptive buffer sizing and `copy_bidirectional` outperform Envoy on raw TCP proxying. On Linux, `splice(2)` zero-copy relay further reduces CPU overhead for plaintext TCP paths. Ferrum's P99 is 9.3× better (6.25ms vs 57.85ms).

4. **TCP+TLS (~tie, +1.8%)** — TLS termination + raw TCP proxying is effectively tied on throughput, with Ferrum again showing 6.2× better P99 (3.06ms vs 19.07ms).

5. **WebSocket (~tie, -0.8%)** — Tunnel mode (raw TCP copy with no frame parsing) matches Envoy's WebSocket proxying. Ferrum's P99 is 6.1× better (7.84ms vs 47.77ms).

**Where Envoy wins:**

1. **gRPC (-22.8%)** — Envoy's native HTTP/2 codec (C++ with writev scatter-gather I/O) achieves higher throughput for small (64-byte) gRPC payloads. However, Ferrum's P99 is 9.7× better (13.56ms vs 131.84ms), meaning Ferrum delivers far more predictable latency despite lower peak throughput. As payload size increases (see `tests/performance/payload_size/`), Ferrum's H2 response coalescing closes the gap and wins at 10KB+ payloads.

2. **UDP (-13.2%)** — Envoy uses GRO (Generic Receive Offload) to batch UDP datagrams at the kernel level. Ferrum's `recvmmsg(2)` batching is Linux-only; on macOS it falls back to per-datagram `try_recv_from`. Re-benchmark on Linux where `FERRUM_UDP_RECVMMSG_BATCH_SIZE=64` enables batched recv to close this gap.

**P99 tail latency — Ferrum's consistent advantage:**

Across every protocol where both proxies are compared, Ferrum delivers **significantly better P99 tail latency**:

| Protocol | Ferrum P99 | Envoy P99 | Ratio |
|----------|-----------|-----------|-------|
| HTTP/1.1 | 3.89ms | 14.10ms | 3.6× better |
| HTTP/1.1+TLS | 4.70ms | 33.85ms | 7.2× better |
| WebSocket | 7.84ms | 47.77ms | 6.1× better |
| gRPC | 13.56ms | 131.84ms | 9.7× better |
| TCP | 6.25ms | 57.85ms | 9.3× better |
| TCP+TLS | 3.06ms | 19.07ms | 6.2× better |
| UDP | 2.75ms | 3.39ms | 1.2× better |

This means Ferrum provides more predictable latency under load — critical for SLA-sensitive traffic where P99 matters more than peak throughput.

## Prerequisites

- **Rust toolchain** (cargo, rustc)
- **protoc** (protobuf compiler) for gRPC support
- **Envoy** (optional, for `--envoy` comparison mode)
- The following ports must be free: 3001-3006, 3010, 3443-3445, 5001, 5003-5004, 5010, 8000, 8443, 50052
- Port 15000 must also be free when using `--envoy` (Envoy admin)

Install dependencies:
```bash
# macOS
brew install protobuf
brew install envoy   # optional, for --envoy mode

# Ubuntu/Debian
sudo apt-get install protobuf-compiler
# See https://www.envoyproxy.io/docs/envoy/latest/start/install for Envoy
```

## Adding a New Protocol Test

1. Add a backend server in `proto_backend.rs`
2. Add a load generator subcommand in `proto_bench.rs`
3. Create a gateway config in `configs/<protocol>_perf.yaml`
4. Add `test_<protocol>()` and `stop_gateway` call in `run_protocol_test.sh`
5. (Optional) Add an Envoy config in `configs/envoy/<protocol>.yaml` and register in `envoy_compare_protocol()`
