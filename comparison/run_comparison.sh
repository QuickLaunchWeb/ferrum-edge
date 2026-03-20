#!/bin/bash

# ===========================================================================
# API Gateway Comparison Benchmark
# Ferrum Gateway vs Kong vs Tyk
#
# Runs each gateway sequentially (one at a time) against the same backend
# echo server, testing both HTTP and HTTPS (TLS termination), then generates
# a comparison report with throughput, latency, and error rate analysis.
#
# Usage:
#   ./comparison/run_comparison.sh
#
# Environment variable overrides:
#   WRK_DURATION=30s        Duration of each wrk test run
#   WRK_THREADS=8           wrk thread count
#   WRK_CONNECTIONS=100     wrk concurrent connections
#   KONG_VERSION=3.9        Kong Docker image tag
#   TYK_VERSION=v5.7        Tyk Docker image tag
#   SKIP_GATEWAYS=tyk       Comma-separated gateways to skip (ferrum,kong,tyk)
#   WARMUP_DURATION=5s      Warm-up duration before measured test
# ===========================================================================

set -euo pipefail

COMP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$COMP_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
BACKEND_PORT=3001
GATEWAY_HTTP_PORT=8000
GATEWAY_HTTPS_PORT=8443
WRK_DURATION=${WRK_DURATION:-30s}
WRK_THREADS=${WRK_THREADS:-8}
WRK_CONNECTIONS=${WRK_CONNECTIONS:-100}
WARMUP_DURATION=${WARMUP_DURATION:-5s}
KONG_VERSION=${KONG_VERSION:-3.9}
TYK_VERSION=${TYK_VERSION:-v5.7}
SKIP_GATEWAYS=${SKIP_GATEWAYS:-}

RESULTS_DIR="$COMP_DIR/results"
CERTS_DIR="$PROJECT_ROOT/tests/certs"
PERF_DIR="$PROJECT_ROOT/tests/performance"
LUA_SCRIPT="$COMP_DIR/lua/comparison_test.lua"

# Docker container names (prefixed for easy cleanup)
KONG_CONTAINER="ferrum-bench-kong"
TYK_CONTAINER="ferrum-bench-tyk"
REDIS_CONTAINER="ferrum-bench-redis"

# PIDs to track
BACKEND_PID=""
FERRUM_PID=""

# Detect platform for Docker networking
if [[ "$(uname -s)" == "Darwin" ]]; then
    BACKEND_HOST="host.docker.internal"
else
    BACKEND_HOST="127.0.0.1"
fi

# ===========================================================================
# Utility functions
# ===========================================================================

log_header() {
    echo ""
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
}

log_info() {
    echo -e "${CYAN}  ▸ $1${NC}"
}

log_ok() {
    echo -e "${GREEN}  ✓ $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}  ⚠ $1${NC}"
}

log_err() {
    echo -e "${RED}  ✗ $1${NC}"
}

should_skip() {
    local gw="$1"
    echo "$SKIP_GATEWAYS" | tr ',' '\n' | grep -qx "$gw"
}

wait_for_http() {
    local url="$1"
    local label="$2"
    local max_retries="${3:-15}"
    for i in $(seq 1 "$max_retries"); do
        if curl -skf "$url" > /dev/null 2>&1; then
            log_ok "$label is ready"
            return 0
        fi
        sleep 1
    done
    log_err "$label failed to start after ${max_retries}s"
    return 1
}

kill_port() {
    lsof -ti:"$1" 2>/dev/null | xargs kill -9 2>/dev/null || true
}

# ===========================================================================
# Cleanup (always runs on exit)
# ===========================================================================

cleanup() {
    echo ""
    log_header "Cleaning up"

    if [[ -n "$BACKEND_PID" ]]; then
        kill "$BACKEND_PID" 2>/dev/null || true
        log_ok "Backend server stopped"
    fi
    if [[ -n "$FERRUM_PID" ]]; then
        kill "$FERRUM_PID" 2>/dev/null || true
        log_ok "Ferrum gateway stopped"
    fi

    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    docker rm -f "$REDIS_CONTAINER" 2>/dev/null || true

    # Clean up temporary config files
    rm -f "$COMP_DIR/configs/.kong_runtime.yaml" 2>/dev/null || true
    rm -rf "$COMP_DIR/configs/.tyk_runtime_apps" 2>/dev/null || true

    kill_port "$BACKEND_PORT"
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
}

trap cleanup EXIT

# ===========================================================================
# Dependency checks
# ===========================================================================

check_dependencies() {
    log_header "Checking dependencies"

    local missing=0
    for cmd in wrk docker python3 cargo curl; do
        if command -v "$cmd" &>/dev/null; then
            log_ok "$cmd"
        else
            log_err "$cmd not found"
            missing=1
        fi
    done

    if [[ "$missing" -eq 1 ]]; then
        echo ""
        log_err "Install missing dependencies before running."
        echo "  wrk:    brew install wrk (macOS) / apt install wrk (Ubuntu)"
        echo "  docker: https://docs.docker.com/get-docker/"
        exit 1
    fi

    # Check Docker daemon is running
    if ! docker info &>/dev/null; then
        log_err "Docker daemon is not running. Start Docker and try again."
        exit 1
    fi
}

# ===========================================================================
# Docker image pull (do this upfront so it doesn't affect timing)
# ===========================================================================

pull_images() {
    log_header "Pulling Docker images"

    if ! should_skip "kong"; then
        log_info "Pulling kong/kong-gateway:${KONG_VERSION}..."
        docker pull "kong/kong-gateway:${KONG_VERSION}" --quiet || {
            log_warn "Failed to pull Kong image. Will try to use cached version."
        }
    fi

    if ! should_skip "tyk"; then
        log_info "Pulling tykio/tyk-gateway:${TYK_VERSION}..."
        docker pull "tykio/tyk-gateway:${TYK_VERSION}" --quiet || {
            log_warn "Failed to pull Tyk image. Will try to use cached version."
        }
        log_info "Pulling redis:7-alpine..."
        docker pull redis:7-alpine --quiet || true
    fi
}

# ===========================================================================
# Build Ferrum + backend
# ===========================================================================

build_project() {
    log_header "Building Ferrum Gateway and backend server"

    log_info "Building gateway (release)..."
    cd "$PROJECT_ROOT"
    cargo build --release --bin ferrum-gateway 2>&1 | tail -1

    log_info "Building backend server (release)..."
    cd "$PERF_DIR"
    cargo build --release --bin backend_server 2>&1 | tail -1

    log_ok "Build completed"
}

# ===========================================================================
# Backend server
# ===========================================================================

start_backend() {
    log_info "Starting backend server on port $BACKEND_PORT..."
    kill_port "$BACKEND_PORT"
    "$PERF_DIR/target/release/backend_server" > "$RESULTS_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!
    wait_for_http "http://127.0.0.1:$BACKEND_PORT/health" "Backend server"
}

# ===========================================================================
# wrk test runner
# ===========================================================================

run_wrk() {
    local gateway="$1"
    local protocol="$2"
    local endpoint="$3"
    local port="$4"
    local label="${gateway}/${protocol}/${endpoint}"
    local result_file="${RESULTS_DIR}/${gateway}_${protocol}_${endpoint}_results.txt"

    local url
    if [[ "$protocol" == "https" ]]; then
        url="https://127.0.0.1:${port}${endpoint}"
    else
        url="http://127.0.0.1:${port}${endpoint}"
    fi

    echo -e "    ${CYAN}Testing ${label}${NC}  →  ${url}"

    # Warm-up (results discarded)
    wrk -t2 -c20 -d"$WARMUP_DURATION" -s "$LUA_SCRIPT" "$url" > /dev/null 2>&1 || true

    # Measured run
    wrk -t"$WRK_THREADS" -c"$WRK_CONNECTIONS" -d"$WRK_DURATION" \
        --latency -s "$LUA_SCRIPT" "$url" > "$result_file" 2>&1

    # Print summary line
    local rps
    rps=$(grep "Requests/sec:" "$result_file" | awk '{print $2}')
    local latency
    latency=$(grep "Latency " "$result_file" | awk '{print $2}')
    echo -e "    ${GREEN}→ ${rps} req/s, ${latency} avg latency${NC}"
}

# ===========================================================================
# Ferrum Gateway
# ===========================================================================

start_ferrum_http() {
    log_info "Starting Ferrum Gateway (HTTP) on port $GATEWAY_HTTP_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    cd "$PROJECT_ROOT"
    FERRUM_MODE=file \
    FERRUM_FILE_CONFIG_PATH="$COMP_DIR/configs/ferrum_comparison.yaml" \
    FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
    FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
    FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
    FERRUM_POOL_ENABLE_HTTP2=false \
    FERRUM_LOG_LEVEL=warn \
    ./target/release/ferrum-gateway > "$RESULTS_DIR/ferrum_http.log" 2>&1 &
    FERRUM_PID=$!
    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Ferrum (HTTP)"
}

start_ferrum_https() {
    log_info "Starting Ferrum Gateway (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    cd "$PROJECT_ROOT"
    FERRUM_MODE=file \
    FERRUM_FILE_CONFIG_PATH="$COMP_DIR/configs/ferrum_comparison.yaml" \
    FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
    FERRUM_PROXY_HTTPS_PORT="$GATEWAY_HTTPS_PORT" \
    FERRUM_PROXY_TLS_CERT_PATH="$CERTS_DIR/server.crt" \
    FERRUM_PROXY_TLS_KEY_PATH="$CERTS_DIR/server.key" \
    FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
    FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
    FERRUM_POOL_ENABLE_HTTP2=false \
    FERRUM_LOG_LEVEL=warn \
    ./target/release/ferrum-gateway > "$RESULTS_DIR/ferrum_https.log" 2>&1 &
    FERRUM_PID=$!
    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Ferrum (HTTPS)" 15
}

stop_ferrum() {
    if [[ -n "$FERRUM_PID" ]]; then
        kill "$FERRUM_PID" 2>/dev/null || true
        wait "$FERRUM_PID" 2>/dev/null || true
        FERRUM_PID=""
    fi
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_ferrum() {
    log_header "Testing Ferrum Gateway"

    # HTTP tests
    start_ferrum_http
    run_wrk "ferrum" "http" "/health" "$GATEWAY_HTTP_PORT"
    run_wrk "ferrum" "http" "/api/users" "$GATEWAY_HTTP_PORT"
    stop_ferrum

    # HTTPS tests
    start_ferrum_https
    run_wrk "ferrum" "https" "/health" "$GATEWAY_HTTPS_PORT"
    run_wrk "ferrum" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
    stop_ferrum
}

# ===========================================================================
# Kong Gateway
# ===========================================================================

prepare_kong_config() {
    # Replace BACKEND_HOST placeholder in Kong config
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/kong.yaml" > "$COMP_DIR/configs/.kong_runtime.yaml"
}

start_kong_http() {
    log_info "Starting Kong Gateway (HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    docker run -d --name "$KONG_CONTAINER" \
        --network host \
        -v "$COMP_DIR/configs/.kong_runtime.yaml:/etc/kong/kong.yml:ro" \
        -e KONG_DATABASE=off \
        -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
        -e KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT" \
        -e KONG_ADMIN_LISTEN="off" \
        -e KONG_PROXY_ACCESS_LOG=/dev/null \
        -e KONG_PROXY_ERROR_LOG=/dev/stderr \
        -e KONG_LOG_LEVEL=warn \
        "kong/kong-gateway:${KONG_VERSION}" > /dev/null

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Kong (HTTP)" 20
}

start_kong_https() {
    log_info "Starting Kong Gateway (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    docker run -d --name "$KONG_CONTAINER" \
        --network host \
        -v "$COMP_DIR/configs/.kong_runtime.yaml:/etc/kong/kong.yml:ro" \
        -v "$CERTS_DIR/server.crt:/etc/kong/ssl/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/kong/ssl/server.key:ro" \
        -e KONG_DATABASE=off \
        -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
        -e KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT, 0.0.0.0:$GATEWAY_HTTPS_PORT ssl" \
        -e KONG_SSL_CERT=/etc/kong/ssl/server.crt \
        -e KONG_SSL_CERT_KEY=/etc/kong/ssl/server.key \
        -e KONG_ADMIN_LISTEN="off" \
        -e KONG_PROXY_ACCESS_LOG=/dev/null \
        -e KONG_PROXY_ERROR_LOG=/dev/stderr \
        -e KONG_LOG_LEVEL=warn \
        "kong/kong-gateway:${KONG_VERSION}" > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Kong (HTTPS)" 20
}

stop_kong() {
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_kong() {
    log_header "Testing Kong Gateway (${KONG_VERSION})"

    prepare_kong_config

    # HTTP tests
    start_kong_http
    run_wrk "kong" "http" "/health" "$GATEWAY_HTTP_PORT"
    run_wrk "kong" "http" "/api/users" "$GATEWAY_HTTP_PORT"
    stop_kong

    # HTTPS tests
    start_kong_https
    run_wrk "kong" "https" "/health" "$GATEWAY_HTTPS_PORT"
    run_wrk "kong" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
    stop_kong
}

# ===========================================================================
# Tyk Gateway
# ===========================================================================

prepare_tyk_config() {
    # Replace BACKEND_HOST placeholder in Tyk API definitions
    mkdir -p "$COMP_DIR/configs/.tyk_runtime_apps"
    for f in "$COMP_DIR/configs/tyk/apps"/*.json; do
        sed "s/BACKEND_HOST/$BACKEND_HOST/g" "$f" > "$COMP_DIR/configs/.tyk_runtime_apps/$(basename "$f")"
    done
}

start_redis() {
    log_info "Starting Redis for Tyk..."
    docker rm -f "$REDIS_CONTAINER" 2>/dev/null || true
    docker run -d --name "$REDIS_CONTAINER" \
        --network host \
        redis:7-alpine > /dev/null
    sleep 2
    log_ok "Redis started"
}

stop_redis() {
    docker rm -f "$REDIS_CONTAINER" 2>/dev/null || true
}

start_tyk_http() {
    log_info "Starting Tyk Gateway (HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    docker run -d --name "$TYK_CONTAINER" \
        --network host \
        -v "$COMP_DIR/configs/tyk/tyk.conf:/opt/tyk-gateway/tyk.conf:ro" \
        -v "$COMP_DIR/configs/.tyk_runtime_apps:/etc/tyk/apps:ro" \
        "tykio/tyk-gateway:${TYK_VERSION}" > /dev/null

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Tyk (HTTP)" 20
}

start_tyk_https() {
    log_info "Starting Tyk Gateway (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    docker run -d --name "$TYK_CONTAINER" \
        --network host \
        -v "$COMP_DIR/configs/tyk/tyk_tls.conf:/opt/tyk-gateway/tyk.conf:ro" \
        -v "$COMP_DIR/configs/.tyk_runtime_apps:/etc/tyk/apps:ro" \
        -v "$CERTS_DIR/server.crt:/etc/tyk/certs/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/tyk/certs/server.key:ro" \
        "tykio/tyk-gateway:${TYK_VERSION}" > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Tyk (HTTPS)" 20
}

stop_tyk() {
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_tyk() {
    log_header "Testing Tyk Gateway (${TYK_VERSION})"

    prepare_tyk_config
    start_redis

    # HTTP tests
    start_tyk_http
    run_wrk "tyk" "http" "/health" "$GATEWAY_HTTP_PORT"
    run_wrk "tyk" "http" "/api/users" "$GATEWAY_HTTP_PORT"
    stop_tyk

    # HTTPS tests
    start_tyk_https
    run_wrk "tyk" "https" "/health" "$GATEWAY_HTTPS_PORT"
    run_wrk "tyk" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
    stop_tyk
    stop_redis
}

# ===========================================================================
# Baseline (direct backend)
# ===========================================================================

test_baseline() {
    log_header "Testing Direct Backend (Baseline)"
    run_wrk "baseline" "http" "/health" "$BACKEND_PORT"
    run_wrk "baseline" "http" "/api/users" "$BACKEND_PORT"
}

# ===========================================================================
# Report generation
# ===========================================================================

write_metadata() {
    cat > "$RESULTS_DIR/meta.json" <<METAEOF
{
    "duration": "$WRK_DURATION",
    "threads": "$WRK_THREADS",
    "connections": "$WRK_CONNECTIONS",
    "kong_version": "$KONG_VERSION",
    "tyk_version": "$TYK_VERSION",
    "os": "$(uname -s) $(uname -r) $(uname -m)",
    "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
METAEOF
}

generate_report() {
    log_header "Generating comparison report"
    write_metadata
    python3 "$COMP_DIR/scripts/generate_comparison_report.py" "$RESULTS_DIR"
    log_ok "Report saved to $RESULTS_DIR/comparison_report.html"
}

# ===========================================================================
# Main
# ===========================================================================

main() {
    echo -e "${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════════╗"
    echo "  ║       API Gateway Comparison Benchmark Suite          ║"
    echo "  ║       Ferrum  vs  Kong  vs  Tyk                      ║"
    echo "  ╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "  Duration: ${WRK_DURATION}  Threads: ${WRK_THREADS}  Connections: ${WRK_CONNECTIONS}"
    echo "  Kong: ${KONG_VERSION}  Tyk: ${TYK_VERSION}  Backend host: ${BACKEND_HOST}"
    if [[ -n "$SKIP_GATEWAYS" ]]; then
        echo -e "  ${YELLOW}Skipping: ${SKIP_GATEWAYS}${NC}"
    fi

    check_dependencies
    pull_images
    build_project

    mkdir -p "$RESULTS_DIR"

    start_backend
    test_baseline

    if ! should_skip "ferrum"; then
        test_ferrum
    fi

    if ! should_skip "kong"; then
        test_kong
    fi

    if ! should_skip "tyk"; then
        test_tyk
    fi

    generate_report

    echo ""
    log_header "Benchmark Complete"
    echo -e "  ${GREEN}Results: ${RESULTS_DIR}/${NC}"
    echo -e "  ${GREEN}Report:  ${RESULTS_DIR}/comparison_report.html${NC}"
    echo ""
}

main "$@"
