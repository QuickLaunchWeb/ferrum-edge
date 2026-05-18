#!/bin/bash
# Mesh HBONE end-to-end throughput harness for Ferrum Edge.
# Topology:
#   hbone_loadgen ──► ferrum-edge (file mode) ──HBONE──► hbone_sidecar ──► hbone_backend
#   hbone_loadgen ───────────────────────────────────────────────────────► hbone_backend  (baseline)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

DURATION=30
CONCURRENCY=50
PAYLOAD_SIZE=1024
JSON_FLAG=""
SKIP_BUILD=false
SIDECAR_PORT=15008

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)      DURATION="$2"; shift 2 ;;
        --concurrency)   CONCURRENCY="$2"; shift 2 ;;
        --payload-size)  PAYLOAD_SIZE="$2"; shift 2 ;;
        --skip-build)    SKIP_BUILD=true; shift ;;
        --json)          JSON_FLAG="--json"; shift ;;
        --sidecar-port)  SIDECAR_PORT="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

GATEWAY_HTTP_PORT=18000
RUNTIME_DIR="$SCRIPT_DIR/runtime"
CERTS_DIR="$RUNTIME_DIR/certs"

BACKEND_PID=""
SIDECAR_PID=""
GATEWAY_PID=""
BACKEND_PORT=""

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    [ -n "$GATEWAY_PID" ] && kill "$GATEWAY_PID" 2>/dev/null || true
    [ -n "$SIDECAR_PID" ] && kill "$SIDECAR_PID" 2>/dev/null || true
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
    for port in "$GATEWAY_HTTP_PORT" "$SIDECAR_PORT" 19999 ${BACKEND_PORT:-0}; do
        [ "$port" = "0" ] && continue
        lsof -ti:"$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    rm -rf "$RUNTIME_DIR"
    echo -e "${GREEN}Cleanup complete${NC}"
}
trap cleanup EXIT

build() {
    if $SKIP_BUILD; then
        echo -e "${YELLOW}Skipping build (--skip-build)${NC}"
        return
    fi
    echo -e "${BLUE}Building gateway and harness binaries...${NC}"
    (cd "$PROJECT_ROOT" && cargo build --release --bin ferrum-edge 2>&1 | tail -1)
    (cd "$SCRIPT_DIR" && cargo build --release 2>&1 | tail -1)
    echo -e "${GREEN}Build complete${NC}"
}

mkdirs() {
    rm -rf "$RUNTIME_DIR"
    mkdir -p "$RUNTIME_DIR" "$CERTS_DIR"
}

generate_certs() {
    echo -e "${YELLOW}Generating mesh-shaped SPIFFE certs in $CERTS_DIR ...${NC}"
    "$SCRIPT_DIR/target/release/hbone_loadgen" \
        generate-certs \
        --out-dir "$CERTS_DIR" \
        --trust-domain cluster.local
    echo -e "${GREEN}Certs ready${NC}"
}

start_backend() {
    echo -e "${YELLOW}Starting plaintext echo backend...${NC}"
    "$SCRIPT_DIR/target/release/hbone_backend" --listen 127.0.0.1:0 \
        > "$RUNTIME_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!
    for i in $(seq 1 20); do
        BACKEND_PORT=$(grep -oE 'listening on 127\.0\.0\.1:[0-9]+' "$RUNTIME_DIR/backend.log" 2>/dev/null \
            | head -1 | grep -oE '[0-9]+$' || true)
        [ -n "$BACKEND_PORT" ] && break
        sleep 0.1
    done
    if [ -z "$BACKEND_PORT" ]; then
        echo -e "${RED}backend failed to report its port${NC}"
        cat "$RUNTIME_DIR/backend.log" | tail -20
        exit 1
    fi
    echo -e "${GREEN}Backend ready on 127.0.0.1:$BACKEND_PORT (PID $BACKEND_PID)${NC}"
}

start_sidecar() {
    echo -e "${YELLOW}Starting stub HBONE sidecar on 127.0.0.1:$SIDECAR_PORT ...${NC}"
    "$SCRIPT_DIR/target/release/hbone_sidecar" \
        --listen "127.0.0.1:$SIDECAR_PORT" \
        --cert "$CERTS_DIR/sidecar-cert.pem" \
        --key "$CERTS_DIR/sidecar-key.pem" \
        --ca "$CERTS_DIR/ca.pem" \
        --backend-host 127.0.0.1 \
        --backend-port "$BACKEND_PORT" \
        > "$RUNTIME_DIR/sidecar.log" 2>&1 &
    SIDECAR_PID=$!
    for i in $(seq 1 40); do
        (echo > /dev/tcp/127.0.0.1/"$SIDECAR_PORT") 2>/dev/null && {
            echo -e "${GREEN}Sidecar ready (PID $SIDECAR_PID)${NC}"; return
        }
        sleep 0.1
    done
    echo -e "${RED}Sidecar failed to bind 127.0.0.1:$SIDECAR_PORT${NC}"
    tail -30 "$RUNTIME_DIR/sidecar.log"
    exit 1
}

write_gateway_config() {
    cat > "$RUNTIME_DIR/gateway.yaml" <<EOF
version: "1"
proxies:
  - id: hbone-edge
    name: "hbone edge"
    namespace: ferrum
    hosts:
      - "edge.local"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: $SIDECAR_PORT
    strip_listen_path: false
    backend_connect_timeout_ms: 5000
    backend_read_timeout_ms: 30000
    backend_write_timeout_ms: 30000
    upstream_id: hbone-upstream
upstreams:
  - id: hbone-upstream
    name: "hbone upstream"
    namespace: ferrum
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: $SIDECAR_PORT
        weight: 1
        tags:
          "mesh.hbone": "true"
          "mesh.hbone_port": "$SIDECAR_PORT"
consumers: []
plugin_configs: []
EOF
}

start_gateway() {
    echo -e "${YELLOW}Starting ferrum-edge in file mode...${NC}"
    write_gateway_config

    cd "$PROJECT_ROOT"
    env \
        FERRUM_MODE=file \
        FERRUM_FILE_CONFIG_PATH="$RUNTIME_DIR/gateway.yaml" \
        FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
        FERRUM_PROXY_HTTPS_PORT=0 \
        FERRUM_ADMIN_HTTP_PORT=19999 \
        FERRUM_ADMIN_HTTPS_PORT=0 \
        FERRUM_LOG_LEVEL=error \
        FERRUM_POOL_WARMUP_ENABLED=true \
        FERRUM_TLS_NO_VERIFY=true \
        FERRUM_GATEWAY_SVID_CERT_PATH="$CERTS_DIR/gateway-cert.pem" \
        FERRUM_GATEWAY_SVID_KEY_PATH="$CERTS_DIR/gateway-key.pem" \
        FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH="$CERTS_DIR/ca.pem" \
        FERRUM_GATEWAY_SPIFFE_ID="spiffe://cluster.local/ns/edge/sa/gateway" \
        FERRUM_BACKEND_ALLOW_IPS="127.0.0.1/32" \
        ./target/release/ferrum-edge \
        > "$RUNTIME_DIR/gateway.log" 2>&1 &
    GATEWAY_PID=$!

    for i in $(seq 1 40); do
        if curl -sf "http://127.0.0.1:19999/health" > /dev/null 2>&1; then
            echo -e "${GREEN}Gateway ready (PID $GATEWAY_PID)${NC}"
            return
        fi
        sleep 0.25
    done
    echo -e "${RED}Gateway failed to start${NC}"
    tail -40 "$RUNTIME_DIR/gateway.log"
    exit 1
}

run_phase() {
    local label="$1"
    local target="$2"

    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}  $label${NC}"
    echo -e "${CYAN}  Target: $target${NC}"
    echo -e "${CYAN}  Duration ${DURATION}s · Concurrency $CONCURRENCY · Payload ${PAYLOAD_SIZE}B${NC}"
    echo -e "${CYAN}========================================${NC}"

    "$SCRIPT_DIR/target/release/hbone_loadgen" \
        run \
        --target "$target" \
        --host-header "edge.local" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --payload-size "$PAYLOAD_SIZE" \
        $JSON_FLAG
}

# Main
echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}  Ferrum Edge HBONE E2E Throughput Harness      ${NC}"
echo -e "${BLUE}=================================================${NC}"

mkdirs
build
generate_certs
start_backend
start_sidecar
start_gateway

# Phase 1: Gateway + HBONE tunnel
run_phase "Gateway → HBONE → Backend" "http://127.0.0.1:$GATEWAY_HTTP_PORT/echo"

# Phase 2: Direct baseline (no gateway, no sidecar, no tunnel)
run_phase "Direct baseline" "http://127.0.0.1:$BACKEND_PORT/echo"

echo -e "\n${GREEN}=============================================${NC}"
echo -e "${GREEN}  Run complete. Logs under $RUNTIME_DIR/.${NC}"
echo -e "${GREEN}=============================================${NC}"
