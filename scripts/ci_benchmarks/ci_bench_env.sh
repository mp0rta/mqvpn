#!/bin/bash
# ci_bench_env.sh — Shared CI benchmark environment setup
#
# Source this file from CI benchmark scripts:
#   source "$(dirname "$0")/ci_bench_env.sh"
#
# CI-specific additions over manual benchmarks:
#   - Commit SHA in all JSON output
#   - Stale process/netns cleanup at start
#   - iperf3 killed inside netns only (safe for shared runners)
#   - Sanity check helper
#   - python3/tc dependency checks

CI_BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MQVPN="${MQVPN:-${CI_BENCH_DIR}/../../build/mqvpn}"
CI_BENCH_RESULTS="${CI_BENCH_RESULTS:-${CI_BENCH_DIR}/../../ci_bench_results}"

# Git commit SHA for JSON output
CI_BENCH_COMMIT="${CI_BENCH_COMMIT:-$(git -C "$CI_BENCH_DIR" rev-parse HEAD 2>/dev/null || echo unknown)}"

# Namespace and veth names
NS_SERVER="ci-bench-server"
NS_CLIENT="ci-bench-client"
VETH_A0="ci-a0"
VETH_A1="ci-a1"
VETH_B0="ci-b0"
VETH_B1="ci-b1"

# IP addressing
IP_A_CLIENT="10.100.0.2/24"
IP_A_SERVER="10.100.0.1/24"
IP_B_CLIENT="10.200.0.2/24"
IP_B_SERVER="10.200.0.1/24"
IP_A_SERVER_ADDR="10.100.0.1"
TUNNEL_SERVER_IP="10.0.0.1"
VPN_LISTEN_PORT="4433"
CI_BENCH_SCHEDULER="${CI_BENCH_SCHEDULER:-wlb}"
CI_BENCH_LOG_LEVEL="${CI_BENCH_LOG_LEVEL:-warn}"

# Process PIDs
_CB_SERVER_PID=""
_CB_CLIENT_PID=""
_CB_WORK_DIR=""
_CB_PSK=""

# ── Dependency checks ──

ci_bench_check_deps() {
    if [ ! -f "$MQVPN" ]; then
        echo "error: mqvpn binary not found at $MQVPN"
        exit 1
    fi
    MQVPN="$(realpath "$MQVPN")"

    for cmd in iperf3 openssl python3 tc; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "error: $cmd not found"
            exit 1
        fi
    done

    mkdir -p "$CI_BENCH_RESULTS"
}

# ── Stale state cleanup (run before setup) ──

ci_bench_cleanup_stale() {
    pkill -f "mqvpn.*ci-bench" 2>/dev/null || true
    ip netns exec "$NS_SERVER" pkill -f "iperf3" 2>/dev/null || true
    ip netns exec "$NS_CLIENT" pkill -f "iperf3" 2>/dev/null || true
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true
}

# ── Network namespace setup ──

ci_bench_setup_netns() {
    echo "Setting up network namespaces..."

    ci_bench_cleanup_stale

    ip netns add "$NS_SERVER"
    ip netns add "$NS_CLIENT"

    # Path A: 10.100.0.0/24
    ip link add "$VETH_A0" type veth peer name "$VETH_A1"
    ip link set "$VETH_A0" netns "$NS_CLIENT"
    ip link set "$VETH_A1" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0"
    ip netns exec "$NS_SERVER" ip addr add "$IP_A_SERVER" dev "$VETH_A1"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
    ip netns exec "$NS_SERVER" ip link set "$VETH_A1" up

    # Path B: 10.200.0.0/24
    ip link add "$VETH_B0" type veth peer name "$VETH_B1"
    ip link set "$VETH_B0" netns "$NS_CLIENT"
    ip link set "$VETH_B1" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$IP_B_CLIENT" dev "$VETH_B0"
    ip netns exec "$NS_SERVER" ip addr add "$IP_B_SERVER" dev "$VETH_B1"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" up
    ip netns exec "$NS_SERVER" ip link set "$VETH_B1" up

    # Loopback
    ip netns exec "$NS_CLIENT" ip link set lo up
    ip netns exec "$NS_SERVER" ip link set lo up

    # IP forwarding
    ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # Verify
    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$IP_A_SERVER_ADDR" >/dev/null
    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 10.200.0.1 >/dev/null

    echo "OK: netns created"
}

# ── tc netem ──

ci_bench_apply_netem() {
    local netem_a="${1:-delay 10ms rate 300mbit}"
    local netem_b="${2:-delay 30ms rate 80mbit}"

    # Clear existing
    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_A0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_A1" root 2>/dev/null || true
    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_B0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_B1" root 2>/dev/null || true

    # Apply on both ends (RTT = 2 × delay)
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_A0" root netem ${netem_a}
    ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_A1" root netem ${netem_a}
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_B0" root netem ${netem_b}
    ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_B1" root netem ${netem_b}

    echo "OK: netem applied (A: ${netem_a}, B: ${netem_b})"
}

# ── VPN server ──

ci_bench_start_server() {
    local scheduler="${1:-$CI_BENCH_SCHEDULER}"
    _CB_WORK_DIR="$(mktemp -d)"

    _CB_PSK=$("$MQVPN" --genkey 2>/dev/null)

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${_CB_WORK_DIR}/server.key" -out "${_CB_WORK_DIR}/server.crt" \
        -days 365 -nodes -subj "/CN=ci-bench" 2>/dev/null

    ip netns exec "$NS_SERVER" "$MQVPN" \
        --mode server \
        --listen "0.0.0.0:${VPN_LISTEN_PORT}" \
        --subnet 10.0.0.0/24 \
        --cert "${_CB_WORK_DIR}/server.crt" \
        --key "${_CB_WORK_DIR}/server.key" \
        --auth-key "$_CB_PSK" \
        --scheduler "$scheduler" \
        --log-level "$CI_BENCH_LOG_LEVEL" &
    _CB_SERVER_PID=$!
    sleep 2

    if ! kill -0 "$_CB_SERVER_PID" 2>/dev/null; then
        echo "ERROR: VPN server died"
        return 1
    fi
    echo "VPN server running (PID $_CB_SERVER_PID, scheduler=$scheduler)"
}

# ── VPN client ──

ci_bench_start_client() {
    local paths="$1"
    local scheduler="${2:-$CI_BENCH_SCHEDULER}"

    # Kill previous client
    if [ -n "$_CB_CLIENT_PID" ] && kill -0 "$_CB_CLIENT_PID" 2>/dev/null; then
        kill "$_CB_CLIENT_PID" 2>/dev/null || true
        wait "$_CB_CLIENT_PID" 2>/dev/null || true
        _CB_CLIENT_PID=""
        sleep 1
    fi

    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server "${IP_A_SERVER_ADDR}:${VPN_LISTEN_PORT}" \
        ${paths} \
        --auth-key "$_CB_PSK" \
        --scheduler "$scheduler" \
        --insecure \
        --log-level "$CI_BENCH_LOG_LEVEL" &
    _CB_CLIENT_PID=$!
    sleep 3

    if ! kill -0 "$_CB_CLIENT_PID" 2>/dev/null; then
        echo "ERROR: VPN client died"
        return 1
    fi
    echo "VPN client running (PID $_CB_CLIENT_PID)"
}

# ── Tunnel wait ──

ci_bench_wait_tunnel() {
    local timeout="${1:-15}"
    local elapsed=0

    while [ "$elapsed" -lt "$timeout" ]; do
        if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
            echo "OK: tunnel up (${elapsed}s)"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "ERROR: tunnel not reachable after ${timeout}s"
    return 1
}

# ── Stop VPN ──

ci_bench_stop_client() {
    if [ -n "$_CB_CLIENT_PID" ]; then
        kill "$_CB_CLIENT_PID" 2>/dev/null || true
        wait "$_CB_CLIENT_PID" 2>/dev/null || true
        _CB_CLIENT_PID=""
        sleep 1
    fi
}

ci_bench_stop_vpn() {
    ci_bench_stop_client
    if [ -n "$_CB_SERVER_PID" ]; then
        kill "$_CB_SERVER_PID" 2>/dev/null || true
        wait "$_CB_SERVER_PID" 2>/dev/null || true
        _CB_SERVER_PID=""
        sleep 1
    fi
}

# ── iperf3 helpers ──

# Run iperf3 and return JSON file path.
# Usage: ci_bench_run_iperf TCP DL 10 4
#        ci_bench_run_iperf UDP UL 10 4 500M
ci_bench_run_iperf() {
    local proto="$1"    # TCP or UDP
    local dir="$2"      # DL or UL
    local duration="$3"
    local parallel="$4"
    local target_bw="${5:-}"

    local json_file
    json_file="$(mktemp)"

    # iperf3 server always in NS_SERVER (bound to tunnel IP).
    # iperf3 client always in NS_CLIENT.
    # Direction controlled by -R flag:
    #   DL (server→client): -R (reverse)
    #   UL (client→server): no flag (default iperf3 direction)
    ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" -1 &>/dev/null &
    local iperf_srv_pid=$!
    sleep 1

    local args="-c $TUNNEL_SERVER_IP -t $duration -P $parallel --json"
    [ "$proto" = "UDP" ] && args="$args -u"
    [ -n "$target_bw" ] && args="$args -b $target_bw"
    [ "$dir" = "DL" ] && args="$args -R"

    ip netns exec "$NS_CLIENT" iperf3 $args > "$json_file" 2>&1 || true

    wait "$iperf_srv_pid" 2>/dev/null || true

    echo "$json_file"
}

# Extract throughput (Mbps) from iperf3 JSON
ci_bench_parse_throughput() {
    local json_file="$1"
    python3 -c "
import json
try:
    with open('${json_file}') as f:
        data = json.load(f)
    end = data.get('end', {})
    if 'sum_received' in end:
        print(f\"{end['sum_received']['bits_per_second'] / 1e6:.1f}\")
    elif 'sum' in end:
        print(f\"{end['sum']['bits_per_second'] / 1e6:.1f}\")
    else:
        print('0.0')
except Exception:
    print('0.0')
"
}

# ── Sanity check ──

ci_bench_sanity_check() {
    local json_file="$1"
    local desc="${2:-benchmark}"

    local has_nonzero
    has_nonzero=$(python3 -c "
import json
with open('${json_file}') as f:
    data = json.load(f)

def check(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            if check(v): return True
    elif isinstance(obj, list):
        for v in obj:
            if check(v): return True
    elif isinstance(obj, (int, float)):
        if obj > 0: return True
    return False

results = data.get('results', data)
print('1' if check(results) else '0')
")

    if [ "$has_nonzero" = "0" ]; then
        echo "ERROR: $desc — all results are zero (iperf3 likely failed)"
        exit 1
    fi
}

# ── Cleanup ──

ci_bench_cleanup() {
    echo ""
    echo "Cleaning up..."

    [ -n "$_CB_CLIENT_PID" ] && kill "$_CB_CLIENT_PID" 2>/dev/null || true
    [ -n "$_CB_SERVER_PID" ] && kill "$_CB_SERVER_PID" 2>/dev/null || true
    _CB_CLIENT_PID=""
    _CB_SERVER_PID=""

    ip netns exec "$NS_SERVER" pkill -f "iperf3" 2>/dev/null || true
    ip netns exec "$NS_CLIENT" pkill -f "iperf3" 2>/dev/null || true
    sleep 1

    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_A0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_A1" root 2>/dev/null || true
    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_B0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_B1" root 2>/dev/null || true

    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true

    [ -n "$_CB_WORK_DIR" ] && rm -rf "$_CB_WORK_DIR" || true
}
