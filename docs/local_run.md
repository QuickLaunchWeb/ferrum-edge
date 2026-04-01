# Running Ferrum Edge on Windows, macOS, and Linux

This guide shows the fastest ways to run Ferrum Edge locally on each major platform.

## Choose a Path

- Use Docker if you want the same workflow on Windows, macOS, and Linux.
- Use a native Rust build if you are developing Ferrum Edge itself.
- If you already have a release binary, replace `cargo run --release` with the binary path (`./ferrum-edge` or `.\ferrum-edge.exe`).

## Default Ports

| Port | Purpose |
|---|---|
| `8000` | Proxy HTTP listener |
| `8443` | Proxy HTTPS listener |
| `9000` | Admin HTTP listener |
| `9443` | Admin HTTPS listener |
| `50051` | CP gRPC listener |

Notes:

- The admin listener serves `/health` and `/status` without JWT auth.
- In file mode, the admin API is read-only but still useful for health checks and monitoring.
- File mode reload via `SIGHUP` is available on Unix platforms only. On Windows, restart the process to apply file config changes.

## Docker on Any OS

This is the quickest way to get Ferrum Edge running the same way everywhere:

```bash
docker run --rm -it \
  --name ferrum-edge \
  -p 8000:8000 \
  -p 9000:9000 \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=sqlite \
  -e FERRUM_DB_URL="sqlite:////data/ferrum.db?mode=rwc" \
  -e FERRUM_ADMIN_JWT_SECRET="dev-secret" \
  -e FERRUM_LOG_LEVEL=info \
  -v ferrum_data:/data \
  ghcr.io/quicklaunchweb/ferrum-edge:latest
```

## Windows

The simplest Windows path is Docker Desktop or WSL2. Native builds also work, but you need Rust and `protoc` available on `PATH`.

### Native Build Prerequisites

1. Install the stable Rust toolchain with `rustup`.
2. Install the Protocol Buffers compiler (`protoc`).
3. Verify both are available:

```powershell
rustc --version
cargo --version
protoc --version
```

### Run in File Mode

From the repository root in PowerShell:

```powershell
$env:FERRUM_MODE = "file"
$env:FERRUM_FILE_CONFIG_PATH = "tests/config.yaml"
$env:FERRUM_LOG_LEVEL = "info"
cargo run --release
```

### Run in Database Mode with SQLite

```powershell
$env:FERRUM_MODE = "database"
$env:FERRUM_DB_TYPE = "sqlite"
$env:FERRUM_DB_URL = "sqlite://ferrum.db?mode=rwc"
$env:FERRUM_ADMIN_JWT_SECRET = "dev-secret"
$env:FERRUM_LOG_LEVEL = "info"
cargo run --release
```

### Run a Built Binary

```powershell
.\target\release\ferrum-edge.exe
```

## macOS

Install native prerequisites first:

```bash
brew install protobuf openssl@3 pkg-config
```

Then build:

```bash
cargo build --release
```

### Run in File Mode

```bash
FERRUM_MODE=file \
FERRUM_FILE_CONFIG_PATH=tests/config.yaml \
FERRUM_LOG_LEVEL=info \
cargo run --release
```

### Run in Database Mode with SQLite

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="dev-secret" \
FERRUM_LOG_LEVEL=info \
cargo run --release
```

### Reload File Mode Config

If Ferrum Edge is already running in file mode on macOS, you can reload the config without restarting:

```bash
kill -HUP <ferrum-edge-pid>
```

## Linux

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev protobuf-compiler
```

### RHEL / Fedora / CentOS Stream

```bash
sudo dnf install -y gcc pkgconf-pkg-config openssl-devel protobuf-compiler
```

### Build

```bash
cargo build --release
```

### Run in File Mode

```bash
FERRUM_MODE=file \
FERRUM_FILE_CONFIG_PATH=tests/config.yaml \
FERRUM_LOG_LEVEL=info \
cargo run --release
```

### Run in Database Mode with SQLite

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="dev-secret" \
FERRUM_LOG_LEVEL=info \
cargo run --release
```

### Reload File Mode Config

```bash
kill -HUP <ferrum-edge-pid>
```

## Verify the Gateway

In another shell:

```bash
curl http://localhost:9000/health
curl http://localhost:8000/httpbin/get
```

Expected behavior:

- `/health` returns JSON from the admin listener.
- `/httpbin/get` is routed by the sample file config in `tests/config.yaml`.

## Platform Notes

- `FERRUM_PROXY_BIND_ADDRESS=::` and `FERRUM_ADMIN_BIND_ADDRESS=::` enable dual-stack listeners on platforms where IPv4-mapped IPv6 is enabled.
- On Windows, file mode reload is restart-based because `SIGHUP` is Unix-only.
- On Linux and macOS, `Ctrl+C` performs a graceful shutdown and `SIGTERM` is handled cleanly.
