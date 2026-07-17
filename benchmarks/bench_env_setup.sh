#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# bench_env_setup.sh — Netns environment setup for mqvpn benchmarks
#
# Source this file from other benchmark scripts:
#   source "$(dirname "$0")/bench_env_setup.sh"
#
# Provides functions:
#   bench_setup_netns      - Create veth pairs and network namespaces
#   bench_apply_netem      - Apply tc netem shaping (Path A/B defaults)
#   bench_start_vpn_server - Start mqvpn server in server netns
#   bench_start_vpn_client - Start mqvpn client in client netns
#   bench_wait_tunnel      - Wait for TUN device ping reachability
#   bench_cleanup          - Remove all netns/veth/processes

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MQVPN="${MQVPN:-${BENCH_DIR}/../build/mqvpn}"
RESULTS_DIR="${RESULTS_DIR:-${BENCH_DIR}/../bench_results}"

# Namespace names
NS_SERVER="bench-server"
NS_CLIENT="bench-client"

# Slot 0/1 keep historical letters+octets (a/100, b/200) for 2-path
# benchmark backward compat; slots 2..7 use the next free octets.
BENCH_PATH_LETTERS=(a b c d e f g h)
BENCH_PATH_OCTETS=(100 200 110 120 130 140 150 160)
BENCH_MAX_PATHS=${#BENCH_PATH_LETTERS[@]}

# Convenience accessors for path slot $1 (0-indexed)
bench_path_veth_client() { echo "veth-${BENCH_PATH_LETTERS[$1]}0"; }
bench_path_veth_server() { echo "veth-${BENCH_PATH_LETTERS[$1]}1"; }
bench_path_client_ip()   { echo "10.${BENCH_PATH_OCTETS[$1]}.0.2"; }
bench_path_server_ip()   { echo "10.${BENCH_PATH_OCTETS[$1]}.0.1"; }

# Backward-compat variable names (2-path scripts read these)
VETH_A0="$(bench_path_veth_client 0)"
VETH_A1="$(bench_path_veth_server 0)"
VETH_B0="$(bench_path_veth_client 1)"
VETH_B1="$(bench_path_veth_server 1)"
IP_A_CLIENT="$(bench_path_client_ip 0)/24"
IP_A_SERVER="$(bench_path_server_ip 0)/24"
IP_B_CLIENT="$(bench_path_client_ip 1)/24"
IP_B_SERVER="$(bench_path_server_ip 1)/24"
IP_A_SERVER_ADDR="$(bench_path_server_ip 0)"
TUNNEL_SERVER_IP="10.0.0.1"
VPN_LISTEN_PORT="4433"
BENCH_SCHEDULER="${BENCH_SCHEDULER:-wlb}"
BENCH_LOG_LEVEL="${BENCH_LOG_LEVEL:-info}"

# Process PIDs (managed by start/cleanup functions)
_BENCH_SERVER_PID=""
_BENCH_CLIENT_PID=""
_BENCH_WORK_DIR=""
_BENCH_PSK=""

# ─── Shared netem profile table (BENCH_ENV_NETEM) ────────────────────────────
# Used by sweep_reorder.sh and sweep_single_path.sh. Each value is
# "<pathA netem>|<pathB netem>" (split on '|' for bench_apply_netem).
#
# Sourcing this once from a shared file is load-bearing: the 3-way comparison
# in sweep_reorder_analyze.py joins the perf-sweep CSV, the OFF-baseline CSV
# and the single-path CSV purely on env_name. Silent drift (raise jit_20
# jitter in one sweep but not the other) would produce a meaningless
# comparison with no error surface. Keep this table the single source of
# truth; the analyzer's RTT_SPREAD_MS map mirrors the delays here.
#
# netem syntax notes:
# - Jitter is the 2nd TIME arg to `delay` (`delay TIME JITTER`); netem has no
#   literal `jitter` keyword (writing it crashes tc).
# - Every jittered entry pins `distribution normal`: netem's implicit default
#   is a bounded-uniform delay whose hard ±JITTER cutoff would bias the
#   sweep's p99 (and the MaxWaitMs it picks) low; normal gives the heavier,
#   more realistic tail. Random per-packet delay also induces the reordering
#   that arms the reorder engine. (Requires /usr/lib*/tc/normal.dist, shipped
#   with iproute2.)
declare -gA BENCH_ENV_NETEM=(
  [baseline]="delay 20ms rate 50mbit|delay 20ms rate 50mbit"
  [rtt_40]="delay 20ms rate 50mbit|delay 40ms rate 50mbit"
  [rtt_70]="delay 20ms rate 50mbit|delay 70ms rate 50mbit"
  [rtt_120]="delay 20ms rate 50mbit|delay 120ms rate 50mbit"
  [rtt_320]="delay 20ms rate 50mbit|delay 320ms rate 50mbit"
  [jit_5]="delay 20ms 5ms distribution normal rate 50mbit|delay 20ms 5ms distribution normal rate 50mbit"
  [jit_20]="delay 20ms 20ms distribution normal rate 50mbit|delay 20ms 20ms distribution normal rate 50mbit"
  [loss_05]="delay 20ms loss 0.5% rate 50mbit|delay 20ms loss 0.5% rate 50mbit"
  [loss_2]="delay 20ms loss 2% rate 50mbit|delay 20ms loss 2% rate 50mbit"
  [bw_4to1]="delay 20ms rate 50mbit|delay 20ms rate 12mbit"
  [bw_10to1]="delay 20ms rate 100mbit|delay 20ms rate 10mbit"
  [dual_lte]="delay 30ms 5ms distribution normal loss 0.5% rate 40mbit|delay 45ms 8ms distribution normal loss 0.5% rate 25mbit"
  [fiber_lte]="delay 8ms rate 300mbit|delay 40ms 8ms distribution normal loss 0.5% rate 30mbit"
  [lte_starlink]="delay 35ms 8ms distribution normal rate 40mbit|delay 50ms 25ms distribution normal loss 1% rate 100mbit"
  [lte_geo]="delay 35ms rate 40mbit|delay 320ms 20ms distribution normal loss 0.5% rate 20mbit"
  [congested]="delay 50ms 20ms distribution normal loss 2% rate 20mbit|delay 60ms 25ms distribution normal loss 2% rate 15mbit"
)

# Lightweight dep check for e2e tests (deps differ from bench_check_deps which
# requires iperf3/openssl). Verifies binaries listed in $@ exist; if "nc" is
# requested, also verifies it's the OpenBSD variant (the only one whose
# stdin-EOF semantics match the control API protocol). Sets MQVPN to realpath.
bench_check_test_deps() {
    if [ ! -f "$MQVPN" ]; then
        echo "error: mqvpn binary not found at $MQVPN" >&2
        return 1
    fi
    MQVPN="$(realpath "$MQVPN")"
    local d
    for d in "$@"; do
        if ! command -v "$d" >/dev/null 2>&1; then
            echo "error: $d not found (install: apt install $d)" >&2
            return 1
        fi
        if [ "$d" = "nc" ] && ! nc -h 2>&1 | grep -qi "openbsd"; then
            echo "error: requires OpenBSD netcat for control API protocol (apt install netcat-openbsd)" >&2
            return 1
        fi
    done
}

# Add /32 host routes for the server VPN-listen address via every path so
# the client can reach it through any of the path interfaces. Run after
# bench_setup_netns_n.
bench_add_server_host_routes() {
    local n="$1"
    ip netns exec "$NS_SERVER" ip addr add "${IP_A_SERVER_ADDR}/32" dev lo
    local i
    for (( i=1; i<n; i++ )); do
        ip netns exec "$NS_CLIENT" ip route add "${IP_A_SERVER_ADDR}/32" \
            via "$(bench_path_server_ip "$i")" \
            dev "$(bench_path_veth_client "$i")" \
            metric "$((100 + i))" 2>/dev/null || true
    done
}

# Query the server control API. Echoes the raw JSON response.
bench_query_control() {
    local port="$1"
    local cmd="$2"
    ip netns exec "$NS_SERVER" bash -c \
        "echo '{\"cmd\":\"${cmd}\"}' | timeout 3 nc 127.0.0.1 ${port}" 2>/dev/null
}

# Poll get_status until clients[0].n_paths == target (or timeout). Echoes the
# last observed n_paths value; returns 0 if matched, 1 on timeout, 2 if server
# died (caller should distinguish — diagnostic differs).
bench_wait_for_n_paths() {
    local target="$1"
    local timeout="${2:-30}"
    local port="$3"
    local elapsed=0
    local n=0 resp
    while [ "$elapsed" -lt "$timeout" ]; do
        if [ -n "$_BENCH_SERVER_PID" ] && ! kill -0 "$_BENCH_SERVER_PID" 2>/dev/null; then
            echo "$n"
            return 2
        fi
        resp="$(bench_query_control "$port" get_status)"
        n=$(echo "$resp" | jq -r '.clients[0].n_paths // 0' 2>/dev/null || echo 0)
        if [ "$n" -ge "$target" ]; then
            echo "$n"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "$n"
    return 1
}

bench_check_deps() {
    if [ ! -f "$MQVPN" ]; then
        echo "error: mqvpn binary not found at $MQVPN"
        echo "Build first: mkdir build && cd build && cmake .. && make -j"
        exit 1
    fi
    MQVPN="$(realpath "$MQVPN")"

    if ! command -v iperf3 &>/dev/null; then
        echo "error: iperf3 not found. Install: sudo apt install iperf3"
        exit 1
    fi

    if ! command -v openssl &>/dev/null; then
        echo "error: openssl not found"
        exit 1
    fi

    mkdir -p "$RESULTS_DIR"
}

bench_setup_netns_n() {
    local n="${1:-2}"
    if [ "$n" -lt 1 ] || [ "$n" -gt "$BENCH_MAX_PATHS" ]; then
        echo "error: bench_setup_netns_n needs 1..${BENCH_MAX_PATHS} paths, got $n" >&2
        return 1
    fi

    echo "Setting up network namespaces with $n path(s)..."

    # Clean any leftovers (try all possible slots so a previous higher-N
    # run that crashed before cleanup doesn't leak veth pairs).
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    local i
    for (( i=0; i<BENCH_MAX_PATHS; i++ )); do
        ip link del "$(bench_path_veth_client "$i")" 2>/dev/null || true
    done

    ip netns add "$NS_SERVER"
    ip netns add "$NS_CLIENT"

    for (( i=0; i<n; i++ )); do
        local vc vs ic is
        vc="$(bench_path_veth_client "$i")"
        vs="$(bench_path_veth_server "$i")"
        ic="$(bench_path_client_ip "$i")/24"
        is="$(bench_path_server_ip "$i")/24"

        ip link add "$vc" type veth peer name "$vs"
        ip link set "$vc" netns "$NS_CLIENT"
        ip link set "$vs" netns "$NS_SERVER"
        ip netns exec "$NS_CLIENT" ip addr add "$ic" dev "$vc"
        ip netns exec "$NS_SERVER" ip addr add "$is" dev "$vs"
        ip netns exec "$NS_CLIENT" ip link set "$vc" up
        ip netns exec "$NS_SERVER" ip link set "$vs" up
    done

    ip netns exec "$NS_CLIENT" ip link set lo up
    ip netns exec "$NS_SERVER" ip link set lo up

    ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null
    # Loose rp_filter so >2-path topologies with multiple /32 routes to the
    # same server addr don't get their reverse-path replies dropped by the
    # kernel on strict-mode hosts.
    ip netns exec "$NS_CLIENT" sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
    ip netns exec "$NS_SERVER" sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null

    # Verify L3 connectivity over every path — bail loudly if any path is unreachable
    for (( i=0; i<n; i++ )); do
        if ! ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$(bench_path_server_ip "$i")" >/dev/null 2>&1; then
            echo "ERROR: path $i ($(bench_path_veth_client "$i") <-> $(bench_path_veth_server "$i")) failed L3 verify" >&2
            return 1
        fi
    done

    echo "OK: netns created with $n path(s)"
}

# 2-path default — preserved for existing benchmarks that source this file.
bench_setup_netns() {
    bench_setup_netns_n 2
}

bench_apply_netem() {
    # Default: Path A = delay 10ms rate 300mbit, Path B = delay 30ms rate 80mbit
    local netem_a="${1:-delay 10ms rate 300mbit}"
    local netem_b="${2:-delay 30ms rate 80mbit}"

    echo "Applying tc netem: Path A = ${netem_a}, Path B = ${netem_b}"

    # Clear existing rules
    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_A0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_A1" root 2>/dev/null || true
    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_B0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_B1" root 2>/dev/null || true

    # Apply on both ends for realistic behavior
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_A0" root netem ${netem_a}
    ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_A1" root netem ${netem_a}
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_B0" root netem ${netem_b}
    ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_B1" root netem ${netem_b}

    echo "OK: tc netem applied"
}

bench_start_vpn_server() {
    # Optional first arg: extra CLI flags (e.g. "--control-port 9091")
    local extra="${1:-}"
    local logfile="${2:-/dev/null}"

    _BENCH_WORK_DIR="$(mktemp -d)"

    # Generate PSK
    _BENCH_PSK=$("$MQVPN" --genkey 2>/dev/null)
    echo "Generated PSK: ${_BENCH_PSK:0:8}..."

    # Generate self-signed cert
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${_BENCH_WORK_DIR}/server.key" -out "${_BENCH_WORK_DIR}/server.crt" \
        -days 365 -nodes -subj "/CN=mqvpn-bench" 2>/dev/null

    ip netns exec "$NS_SERVER" "$MQVPN" \
        --mode server \
        --listen "0.0.0.0:${VPN_LISTEN_PORT}" \
        --subnet 10.0.0.0/24 \
        --cert "${_BENCH_WORK_DIR}/server.crt" \
        --key "${_BENCH_WORK_DIR}/server.key" \
        --auth-key "$_BENCH_PSK" \
        --scheduler "$BENCH_SCHEDULER" \
        --log-level "$BENCH_LOG_LEVEL" \
        ${extra} >"$logfile" 2>&1 &
    _BENCH_SERVER_PID=$!
    sleep 2

    if ! kill -0 "$_BENCH_SERVER_PID" 2>/dev/null; then
        echo "ERROR: VPN server process died"
        return 1
    fi
    echo "VPN server running (PID $_BENCH_SERVER_PID)"
}

bench_start_vpn_client() {
    local paths="$1"  # e.g. "--path veth-a0 --path veth-b0"
    local logfile="${2:-/dev/null}"

    # Kill previous client if running
    if [ -n "$_BENCH_CLIENT_PID" ] && kill -0 "$_BENCH_CLIENT_PID" 2>/dev/null; then
        kill "$_BENCH_CLIENT_PID" 2>/dev/null || true
        wait "$_BENCH_CLIENT_PID" 2>/dev/null || true
        _BENCH_CLIENT_PID=""
        sleep 1
    fi

    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server "${IP_A_SERVER_ADDR}:${VPN_LISTEN_PORT}" \
        ${paths} \
        --auth-key "$_BENCH_PSK" \
        --scheduler "$BENCH_SCHEDULER" \
        --insecure \
        --log-level "$BENCH_LOG_LEVEL" >"$logfile" 2>&1 &
    _BENCH_CLIENT_PID=$!
    sleep 3

    if ! kill -0 "$_BENCH_CLIENT_PID" 2>/dev/null; then
        echo "ERROR: VPN client process died"
        return 1
    fi
    echo "VPN client running (PID $_BENCH_CLIENT_PID)"
}

bench_wait_tunnel() {
    local timeout="${1:-15}"
    local elapsed=0

    echo "Waiting for tunnel (max ${timeout}s)..."
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

bench_stop_vpn_client() {
    if [ -n "$_BENCH_CLIENT_PID" ]; then
        kill "$_BENCH_CLIENT_PID" 2>/dev/null || true
        wait "$_BENCH_CLIENT_PID" 2>/dev/null || true
        _BENCH_CLIENT_PID=""
        sleep 1
    fi
}

bench_stop_vpn() {
    bench_stop_vpn_client
    if [ -n "$_BENCH_SERVER_PID" ]; then
        kill "$_BENCH_SERVER_PID" 2>/dev/null || true
        wait "$_BENCH_SERVER_PID" 2>/dev/null || true
        _BENCH_SERVER_PID=""
        sleep 1
    fi
}

bench_cleanup() {
    echo ""
    echo "Cleaning up..."

    # Kill VPN processes
    [ -n "$_BENCH_CLIENT_PID" ] && kill "$_BENCH_CLIENT_PID" 2>/dev/null || true
    [ -n "$_BENCH_SERVER_PID" ] && kill "$_BENCH_SERVER_PID" 2>/dev/null || true
    _BENCH_CLIENT_PID=""
    _BENCH_SERVER_PID=""

    # Kill stale iperf3 inside benchmark netns only (avoid killing unrelated iperf3)
    ip netns exec "$NS_SERVER" pkill -f "iperf3" 2>/dev/null || true
    ip netns exec "$NS_CLIENT" pkill -f "iperf3" 2>/dev/null || true
    sleep 1

    # Remove tc rules + veth pairs for every possible path slot
    local i
    for (( i=0; i<BENCH_MAX_PATHS; i++ )); do
        local vc vs
        vc="$(bench_path_veth_client "$i")"
        vs="$(bench_path_veth_server "$i")"
        ip netns exec "$NS_CLIENT" tc qdisc del dev "$vc" root 2>/dev/null || true
        ip netns exec "$NS_SERVER" tc qdisc del dev "$vs" root 2>/dev/null || true
        ip link del "$vc" 2>/dev/null || true
    done

    # Remove namespaces
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true

    # Remove temp dir
    [ -n "$_BENCH_WORK_DIR" ] && rm -rf "$_BENCH_WORK_DIR"
}
