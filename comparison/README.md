# API Gateway Comparison Benchmarks

Performance comparison suite that benchmarks **Ferrum Gateway** against **Kong** and **Tyk** API Gateways under identical conditions.

## What It Measures

Each gateway is tested as a pure reverse proxy (no authentication, rate limiting, or transformation plugins) with two scenarios:

| Scenario | Description |
|----------|-------------|
| **HTTP (plaintext)** | Client → Gateway (port 8000) → Backend. Measures raw proxy overhead. |
| **HTTPS (TLS termination)** | Client → Gateway (port 8443, TLS) → Backend (plaintext). Measures TLS handshake and encryption overhead at the gateway. |

Two endpoints are tested per scenario:
- `/health` — instant backend response, measures pure gateway latency
- `/api/users` — 100 microsecond simulated delay, represents a typical API call

A direct backend baseline (no gateway) is run first for comparison.

### Test Approach

- Gateways are tested **sequentially** (one at a time) to avoid resource contention
- Each test gets a **5-second warm-up** (results discarded) before the measured 30-second run
- The same backend echo server, wrk parameters, and endpoints are used across all gateways
- Ferrum runs as a native binary; Kong and Tyk run in Docker containers

## Prerequisites

| Dependency | Install |
|------------|---------|
| **wrk** | `brew install wrk` (macOS) or `apt install wrk` (Ubuntu) |
| **Docker** | [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) |
| **Python 3** | Usually pre-installed; needed for report generation |
| **Rust/Cargo** | [rustup.rs](https://rustup.rs/) — builds Ferrum and the backend server |
| **curl** | Usually pre-installed; used for health checks |

**System recommendations:** Run on a dedicated machine or close resource-intensive applications. CPU governor set to "performance" improves consistency on Linux.

## Quick Start

```bash
# From the project root
./comparison/run_comparison.sh
```

The script will:
1. Pull Kong and Tyk Docker images
2. Build Ferrum Gateway and the backend server (release mode)
3. Run baseline → Ferrum → Kong → Tyk tests sequentially
4. Generate an HTML comparison report in `comparison/results/`

Open `comparison/results/comparison_report.html` in a browser to view the results.

## Configuration

Override any parameter via environment variables:

```bash
# Custom test parameters
WRK_DURATION=60s WRK_THREADS=12 WRK_CONNECTIONS=200 ./comparison/run_comparison.sh

# Skip a gateway (e.g., if you don't have Docker)
SKIP_GATEWAYS=tyk,kong ./comparison/run_comparison.sh

# Only test Ferrum vs Kong
SKIP_GATEWAYS=tyk ./comparison/run_comparison.sh
```

| Variable | Default | Description |
|----------|---------|-------------|
| `WRK_DURATION` | `30s` | Duration of each measured test run |
| `WRK_THREADS` | `8` | wrk thread count |
| `WRK_CONNECTIONS` | `100` | wrk concurrent connections |
| `WARMUP_DURATION` | `5s` | Warm-up duration before each test (results discarded) |
| `KONG_VERSION` | `3.9` | Kong Docker image tag |
| `TYK_VERSION` | `v5.7` | Tyk Docker image tag |
| `SKIP_GATEWAYS` | _(empty)_ | Comma-separated gateways to skip: `ferrum`, `kong`, `tyk` |

## Swapping Gateway Versions

To re-run benchmarks with newer Kong or Tyk releases:

```bash
# Test against Kong 3.10 and Tyk v5.8
KONG_VERSION=3.10 TYK_VERSION=v5.8 ./comparison/run_comparison.sh
```

The script pulls the specified Docker image tags automatically. Results are overwritten in `comparison/results/` — copy or rename the directory if you want to preserve previous runs.

### Version-specific considerations

- **Kong** uses DB-less declarative mode. The config format (`_format_version: "3.0"`) is stable across 3.x releases. If Kong 4.x changes the format, update `comparison/configs/kong.yaml`.
- **Tyk** uses standalone mode with file-based API definitions. The API definition schema has been stable across v5.x. If Tyk v6 changes it, update the files in `comparison/configs/tyk/apps/`.
- **Ferrum** is built from source in the current checkout, so it always tests the latest local code.

## Interpreting Results

The HTML report contains four sections:

### 1. Direct Backend Baseline
Raw backend throughput and latency without any gateway. This is the theoretical maximum. Any gateway will add overhead.

### 2. HTTP Performance (Plaintext)
Compares all three gateways proxying plaintext HTTP. Key metrics:
- **Requests/sec** — higher is better. The gateway closest to baseline has the least overhead.
- **Avg Latency** — lower is better. The difference from baseline is the gateway's added latency.
- **P99 Latency** — tail latency matters for user experience. Large P99 spikes indicate inconsistent performance.
- **Errors** — should be zero. Non-zero errors indicate the gateway couldn't handle the load.
- **vs Baseline** — percentage RPS difference from direct backend.

### 3. HTTPS Performance (TLS Termination)
Same metrics but with TLS between wrk and the gateway. Expect lower throughput and higher latency than HTTP due to TLS handshake cost.

### 4. TLS Overhead
Per-gateway comparison of HTTP vs HTTPS performance. Shows the RPS drop and latency increase each gateway pays for TLS. A gateway with lower TLS overhead has a more efficient TLS implementation.

### Color coding
- **Green cells** = best in category (highest RPS, lowest latency)
- **Red cells** = worst in category

## Adding a New Gateway

To add a new gateway (e.g., Envoy, NGINX, Traefik):

1. **Create config files** in `comparison/configs/` for the gateway
2. **Add functions** to `run_comparison.sh`:
   - `start_<gateway>_http()` / `start_<gateway>_https()` — launch the gateway
   - `stop_<gateway>()` — tear it down
   - `test_<gateway>()` — orchestrate HTTP + HTTPS test sequences
3. **Add the gateway name** to the `GATEWAYS` list in `scripts/generate_comparison_report.py`
4. **Call `test_<gateway>()`** in the `main()` function of `run_comparison.sh`
5. **Add a `should_skip` check** so users can skip it via `SKIP_GATEWAYS`

Each test function should follow the pattern: start → run_wrk (per endpoint) → stop. Use the same ports (8000/8443) since gateways run sequentially.

## Known Limitations

- **Docker overhead:** Kong and Tyk run inside Docker containers while Ferrum runs as a native binary. This gives Ferrum a slight advantage from lower syscall overhead and no container networking layer. For a truly apples-to-apples comparison on Linux, use `--network host` (already configured) which minimizes Docker networking overhead. On macOS, Docker Desktop runs in a Linux VM which adds additional overhead for Kong/Tyk.

- **No plugins enabled:** Tests measure pure proxy overhead only. Real-world performance with authentication, rate limiting, or transformation plugins will differ. Each gateway has different plugin performance characteristics.

- **TLS termination only:** The HTTPS tests terminate TLS at the gateway and proxy to the backend over plaintext HTTP. This is the most common production pattern but does not test gateway-to-backend TLS (re-encryption). Ferrum, Kong, and Tyk all support backend TLS but it is not benchmarked here.

- **Single-node only:** All tests run on localhost. Distributed deployment characteristics (network latency, cluster synchronization) are not captured.

- **In-memory state:** Tyk requires Redis even in standalone mode. The Redis instance runs locally and is fast, but it's a dependency that Kong and Ferrum don't need, which could slightly affect Tyk's resource usage.

## File Structure

```
comparison/
├── README.md                          # This file
├── run_comparison.sh                  # Main orchestrator script
├── configs/
│   ├── ferrum_comparison.yaml         # Ferrum file-mode config
│   ├── kong.yaml                      # Kong DB-less declarative config
│   └── tyk/
│       ├── tyk.conf                   # Tyk standalone config (HTTP)
│       ├── tyk_tls.conf               # Tyk config with TLS enabled
│       └── apps/
│           ├── health_api.json        # Tyk API definition for /health
│           └── users_api.json         # Tyk API definition for /api/users
├── lua/
│   └── comparison_test.lua            # Unified wrk Lua script
├── scripts/
│   └── generate_comparison_report.py  # HTML report generator
└── results/                           # Generated at runtime (gitignored)
    ├── .gitkeep
    ├── comparison_report.html         # HTML report (after running)
    ├── meta.json                      # Test metadata (after running)
    └── *_results.txt                  # Raw wrk output per test
```
