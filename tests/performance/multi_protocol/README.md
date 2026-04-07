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

Results from a local run on macOS (Apple Silicon), 10s duration, 200 concurrent connections, 64-byte echo payload.

### Through Gateway (client → gateway → backend)

| Protocol | Requests/sec | Avg Latency | P50 | P99 | Max | Errors |
|----------|-------------|-------------|------|------|------|--------|
| HTTP/1.1 | 102,183 | 1.96ms | 1.89ms | 3.85ms | 28.41ms | 0 |
| HTTP/1.1+TLS | 101,317 | 1.97ms | 1.90ms | 3.84ms | 26.25ms | 0 |
| HTTP/2 (TLS) | 108,138 | 1.85ms | 1.67ms | 6.38ms | 120.19ms | 0 |
| HTTP/3 (QUIC) | 53,085 | 3.76ms | 3.51ms | 5.87ms | 150.91ms | 0 |
| WebSocket | 103,830 | 1.92ms | 1.88ms | 3.15ms | 15.27ms | 0 |
| gRPC | 68,352 | 2.92ms | 2.53ms | 12.02ms | 128.06ms | 0 |
| TCP | 108,841 | 1.83ms | 1.83ms | 2.59ms | 10.63ms | 0 |
| TCP+TLS | 107,340 | 1.86ms | 1.84ms | 2.68ms | 13.35ms | 0 |
| UDP | 82,042 | 2.44ms | 2.46ms | 2.93ms | 10.24ms | 0 |
| UDP+DTLS | 76,107 | 2.61ms | 2.61ms | 3.69ms | 11.81ms | 0 |

### Direct Backend (client → backend, no gateway)

| Protocol | Requests/sec | Avg Latency | P50 | P99 | Max |
|----------|-------------|-------------|------|------|------|
| HTTP/1.1 | 209,910 | 951μs | 939μs | 1.81ms | 4.54ms |
| HTTP/1.1+TLS | 209,361* | 953μs | 941μs | 1.81ms | 5.24ms |
| HTTP/2 (TLS) | 355,544 | 561μs | 486μs | 1.53ms | 126.40ms |
| HTTP/3 (QUIC) | 83,592 | 2.39ms | 2.38ms | 2.80ms | 4.93ms |
| WebSocket | 207,507 | 962μs | 952μs | 1.72ms | 3.16ms |
| gRPC | 205,927 | 970μs | 821μs | 3.15ms | 90.81ms |
| TCP | 214,113 | 933μs | 928μs | 1.65ms | 8.48ms |
| TCP+TLS | 207,103 | 964μs | 949μs | 1.78ms | 9.51ms |
| UDP | 276,526 | 722μs | 682μs | 1.27ms | 3.48ms |
| UDP+DTLS | 101,839 | 1.95ms | 1.96ms | 2.47ms | 4.75ms |

*\*HTTP/1.1+TLS direct baseline uses plain HTTP since the backend has no TLS; the TLS overhead is entirely at the gateway.*

### Gateway Overhead

| Protocol | Gateway RPS | Direct RPS | Overhead | Notes |
|----------|------------|------------|----------|-------|
| HTTP/1.1 | 102,183 | 209,910 | ~51% | reqwest connection pool with keep-alive |
| HTTP/1.1+TLS | 101,317 | 209,361 | ~52% | TLS termination at gateway, plain HTTP to backend |
| HTTP/2 (TLS) | 108,138 | 355,544 | ~70% | hyper-native H2 pool with two-phase ready() multiplexing |
| HTTP/3 (QUIC) | 53,085 | 83,592 | ~37% | QUIC connection pool via quinn |
| WebSocket | 103,830 | 207,507 | ~50% | Upgrade overhead amortized over many messages |
| gRPC | 68,352 | 205,927 | ~67% | H2 multiplexing + protobuf passthrough |
| TCP | 108,841 | 214,113 | ~49% | Bidirectional copy, minimal per-byte overhead |
| TCP+TLS | 107,340 | 207,103 | ~48% | TLS termination + bidirectional copy (cached TLS config) |
| UDP | 82,042 | 276,526 | ~70% | Per-datagram session lookup + forwarding |
| UDP+DTLS | 76,107 | 101,839 | ~25% | DTLS termination + plain UDP forwarding |

> **Note:** Benchmark numbers vary between runs due to system load, thermal
> throttling, and background processes. Focus on the overhead ratios and relative
> comparisons rather than absolute RPS numbers.

> Tuning note: in one back-to-back local comparison, lowering the gRPC pool
> sender-ready wait from `5ms` to `1ms` improved gateway throughput by about
> `3.8%` (`64,278` -> `66,734` requests/sec at `10s`, `200` concurrency).
> Ferrum now defaults this knob to `1ms` via `FERRUM_GRPC_POOL_READY_WAIT_MS`.

## Prerequisites

- **Rust toolchain** (cargo, rustc)
- **protoc** (protobuf compiler) for gRPC support
- The following ports must be free: 3001-3006, 3010, 3443-3445, 5001, 5003-5004, 5010, 8000, 8443, 50052

Install protoc:
```bash
# macOS
brew install protobuf

# Ubuntu/Debian
sudo apt-get install protobuf-compiler
```

## Adding a New Protocol Test

1. Add a backend server in `proto_backend.rs`
2. Add a load generator subcommand in `proto_bench.rs`
3. Create a gateway config in `configs/<protocol>_perf.yaml`
4. Add `test_<protocol>()` and `stop_gateway` call in `run_protocol_test.sh`
