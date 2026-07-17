#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_8paths_dellink_test.sh — E2E test for RTM_DELLINK at the full 8-path
# budget. Exists to catch failover-storm / path_id grant-accounting
# regressions at MQVPN_MAX_PATHS = 8 that the 2-path run_dellink_test
# cannot trigger.
#
# Topology (8-path multipath):
#   vpn-client                   vpn-server
#     veth-a0 ─────────────────── veth-a1       Path 0 (10.100.0.0/24)
#     veth-b0 ─────────────────── veth-b1       Path 1 (10.110.0.0/24)
#     veth-c0 ─────────────────── veth-c1       Path 2 (10.120.0.0/24)
#     veth-d0 ─────────────────── veth-d1       Path 3 (10.130.0.0/24)
#     veth-e0 ─────────────────── veth-e1       Path 4 (10.140.0.0/24)
#     veth-f0 ─────────────────── veth-f1       Path 5 (10.150.0.0/24)
#     veth-g0 ─────────────────── veth-g1       Path 6 (10.160.0.0/24)
#     veth-h0 ─────────────────── veth-h1       Path 7 (10.170.0.0/24)
#
# Test steps:
#   1. Precondition: bring up 8-path tunnel; capture each path's path_id.
#   2. Drop slot 2 (veth-c0); verify exactly 1 of the original 8 path_ids
#      is closed/closing/removed, n_paths is {7,8}, tunnel still passes
#      traffic on a survivor.
#   3. Recreate slot 2 veth; verify n_paths recovers to 8 and traffic flows.
#
# Identifying the dropped slot by *path_id* (not by paths[] array index)
# matters because xquic may prune a closed entry, which would otherwise
# shift the array indices and break index-based assertions.
#
# Usage: sudo ./run_8paths_dellink_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

set -e

source "$(dirname "$0")/sanitizer_check.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
LOG_LEVEL="info"

while [ $# -gt 0 ]; do
    case "$1" in
        --log-level) LOG_LEVEL="$2"; shift 2 ;;
        *) [ -z "$MQVPN" ] && MQVPN="$1"; shift ;;
    esac
done

MQVPN="${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    echo "Build first: mkdir build && cd build && cmake .. && make"
    exit 1
fi

for dep in nc jq; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        echo "error: $dep not found (apt install $dep)"
        exit 1
    fi
done
if ! nc -h 2>&1 | grep -qi "openbsd"; then
    echo "error: requires OpenBSD netcat (apt install netcat-openbsd)"
    exit 1
fi

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

NS_SERVER="vpn-server-8p"
NS_CLIENT="vpn-client-8p"
N_PATHS=8
DROP_SLOT=2
SERVER_ADDR="10.100.0.1"
TUNNEL_IP="10.0.0.1"
CTRL_PORT=9091

# Path tables (slot 0..7)
VETH_C=(veth-a0 veth-b0 veth-c0 veth-d0 veth-e0 veth-f0 veth-g0 veth-h0)
VETH_S=(veth-a1 veth-b1 veth-c1 veth-d1 veth-e1 veth-f1 veth-g1 veth-h1)
OCTETS=(100 110 120 130 140 150 160 170)

client_ip()  { echo "10.${OCTETS[$1]}.0.2"; }
server_ip()  { echo "10.${OCTETS[$1]}.0.1"; }

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0

cleanup() {
    echo ""
    echo "Cleaning up..."
    stop_and_check_sanitizer "$CLIENT_PID" "client" "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    sleep 1
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    local i
    for (( i=0; i<N_PATHS; i++ )); do
        ip link del "${VETH_C[$i]}" 2>/dev/null || true
    done
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

# Clean leftovers from a previous crashed run
ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
for (( i=0; i<N_PATHS; i++ )); do
    ip link del "${VETH_C[$i]}" 2>/dev/null || true
done

# Generate PSK + cert
PSK=$("$MQVPN" --genkey 2>/dev/null)
echo "Generated PSK: ${PSK:0:8}..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-8paths-dellink" 2>/dev/null

# ─── Setup: 8-path netns topology ────────────────────────────────────────
echo "=== Setting up network namespaces (N=$N_PATHS) ==="
ip netns add "$NS_SERVER"
ip netns add "$NS_CLIENT"

for (( i=0; i<N_PATHS; i++ )); do
    ip link add "${VETH_C[$i]}" type veth peer name "${VETH_S[$i]}"
    ip link set "${VETH_C[$i]}" netns "$NS_CLIENT"
    ip link set "${VETH_S[$i]}" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$(client_ip "$i")/24" dev "${VETH_C[$i]}"
    ip netns exec "$NS_SERVER" ip addr add "$(server_ip "$i")/24" dev "${VETH_S[$i]}"
    ip netns exec "$NS_CLIENT" ip link set "${VETH_C[$i]}" up
    ip netns exec "$NS_SERVER" ip link set "${VETH_S[$i]}" up
done

ip netns exec "$NS_CLIENT" ip link set lo up
ip netns exec "$NS_SERVER" ip link set lo up
ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null
# Loose rp_filter so multiple /32 routes to SERVER_ADDR via different paths
# survive on hosts with strict default.
ip netns exec "$NS_CLIENT" sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
ip netns exec "$NS_SERVER" sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null

# Server address on loopback so it remains reachable when any single veth dies
ip netns exec "$NS_SERVER" ip addr add "${SERVER_ADDR}/32" dev lo

# Per-path host route for SERVER_ADDR via each path's gateway
for (( i=1; i<N_PATHS; i++ )); do
    ip netns exec "$NS_CLIENT" ip route add "${SERVER_ADDR}/32" \
        via "$(server_ip "$i")" dev "${VETH_C[$i]}" metric "$((100 + i))"
done

# Verify L3 on every path
for (( i=0; i<N_PATHS; i++ )); do
    if ! ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$(server_ip "$i")" >/dev/null 2>&1; then
        echo "FAIL: path $i (${VETH_C[$i]}) failed L3 verify"
        exit 1
    fi
done
echo "OK: netns topology created with $N_PATHS paths"

# ─── Start VPN server + client ───────────────────────────────────────────
echo "=== Starting VPN server ==="
ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server \
    --listen "0.0.0.0:4433" \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --control-port "$CTRL_PORT" \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "=== FAIL: Server process died ==="
    cat "${WORK_DIR}/server.log"
    exit 1
fi
echo "Server running (PID $SERVER_PID)"

echo "=== Starting VPN client (${N_PATHS}-path) ==="
paths_arg=""
for (( i=0; i<N_PATHS; i++ )); do
    paths_arg="${paths_arg} --path ${VETH_C[$i]}"
done

ip netns exec "$NS_CLIENT" "$MQVPN" \
    --mode client \
    --server "${SERVER_ADDR}:4433" \
    ${paths_arg} \
    --auth-key "$PSK" \
    --insecure \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "=== FAIL: Client process died ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "Client running (PID $CLIENT_PID)"

# Wait for tunnel (path 0 + handshake)
echo "Waiting for tunnel..."
ELAPSED=0
while [ "$ELAPSED" -lt 20 ]; do
    if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
if [ "$ELAPSED" -ge 20 ]; then
    echo "=== FAIL: Tunnel not reachable after 20s ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: tunnel up (${ELAPSED}s)"

# ── Helpers ─────────────────────────────────────────────────────────────
query_status() {
    ip netns exec "$NS_SERVER" bash -c \
        "echo '{\"cmd\":\"get_status\"}' | timeout 3 nc 127.0.0.1 $CTRL_PORT" 2>/dev/null
}

wait_for_n_paths() {
    local target="$1" timeout="${2:-30}" elapsed=0 n=0 resp
    while [ "$elapsed" -lt "$timeout" ]; do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "$n"; return 2
        fi
        resp=$(query_status)
        n=$(echo "$resp" | jq -r '.clients[0].n_paths // 0' 2>/dev/null || echo 0)
        if [ "$n" -ge "$target" ]; then
            echo "$n"; return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "$n"; return 1
}

count_closed_or_removed() {
    local s="$1" pid c=0 label
    for pid in $ORIGINAL_PIDS; do
        label=$(echo "$s" | jq -r --argjson pid "$pid" \
            '(.clients[0].paths[] | select(.path_id == $pid) | .state_label) // "removed"' 2>/dev/null)
        if [ "$label" = "closed" ] || [ "$label" = "closing" ] || [ "$label" = "removed" ]; then
            c=$((c + 1))
        fi
    done
    echo "$c"
}

# ─── Phase 1: precondition + path_id capture ─────────────────────────────
echo ""
echo "=== Phase 1: $N_PATHS paths active ==="
n=$(wait_for_n_paths "$N_PATHS" 30) && rc=0 || rc=$?
if [ "$rc" -ne 0 ] || [ "$n" -ne "$N_PATHS" ]; then
    echo "=== FAIL: did not converge to n_paths=$N_PATHS (got $n, rc=$rc) ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
status_p1=$(query_status)
n_active=$(echo "$status_p1" | jq -r \
    '[.clients[0].paths[] | select(.state_label == "active")] | length' 2>/dev/null || echo 0)
if [ "$n_active" -ne "$N_PATHS" ]; then
    echo "=== FAIL: Phase 1 has $n_active active (expected $N_PATHS) ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
ORIGINAL_PIDS=$(echo "$status_p1" | jq -r '.clients[0].paths[].path_id' | sort -n)
n_pids=$(echo "$ORIGINAL_PIDS" | wc -l)
if [ "$n_pids" -ne "$N_PATHS" ]; then
    echo "=== FAIL: Phase 1 returned $n_pids path_ids, expected $N_PATHS ==="
    exit 1
fi
echo "OK: n_paths=$N_PATHS active=$n_active path_ids=$(echo "$ORIGINAL_PIDS" | tr '\n' ',' | sed 's/,$//')"

# ─── Phase 2: dellink ─────────────────────────────────────────────────────
echo ""
echo "=== Phase 2: drop slot $DROP_SLOT (${VETH_C[$DROP_SLOT]}) ==="
ip netns exec "$NS_CLIENT" ip link del "${VETH_C[$DROP_SLOT]}"

# Wait up to 20s for xquic PTO + dellink netlink handler
ELAPSED=0
n_closed=0
while [ "$ELAPSED" -lt 20 ]; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "=== FAIL: server died during Phase 2 ==="
        exit 1
    fi
    status_p2=$(query_status)
    n_closed=$(count_closed_or_removed "$status_p2")
    if [ "$n_closed" -ge 1 ]; then
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

status_p2=$(query_status)
n=$(echo "$status_p2" | jq -r '.clients[0].n_paths // 0' 2>/dev/null || echo 0)
n_closed=$(count_closed_or_removed "$status_p2")

if [ "$n" -lt $((N_PATHS - 1)) ] || [ "$n" -gt "$N_PATHS" ]; then
    echo "=== FAIL: n_paths=$n outside expected {$((N_PATHS - 1)), $N_PATHS} ==="
    echo "$status_p2" | jq . || echo "$status_p2"
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: n_paths=$n in expected {$((N_PATHS - 1)), $N_PATHS} after dellink"

if [ "$n_closed" -ne 1 ]; then
    echo "=== FAIL: $n_closed paths closed/removed (expected 1 — possible storm) ==="
    echo "$status_p2" | jq . || echo "$status_p2"
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: exactly 1 of the original $N_PATHS path_ids closed/removed"

if ! ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "=== FAIL: tunnel ping broken after dellink ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "=== Phase 2: PASS ==="

# ─── Phase 3: re-add ─────────────────────────────────────────────────────
echo ""
echo "=== Phase 3: recreate slot $DROP_SLOT ==="
vc="${VETH_C[$DROP_SLOT]}"
vs="${VETH_S[$DROP_SLOT]}"
ip link add "$vc" type veth peer name "$vs"
ip link set "$vc" netns "$NS_CLIENT"
ip link set "$vs" netns "$NS_SERVER"
ip netns exec "$NS_CLIENT" ip addr add "$(client_ip "$DROP_SLOT")/24" dev "$vc"
ip netns exec "$NS_SERVER" ip addr add "$(server_ip "$DROP_SLOT")/24" dev "$vs"
ip netns exec "$NS_CLIENT" ip link set "$vc" up
ip netns exec "$NS_SERVER" ip link set "$vs" up
ip netns exec "$NS_CLIENT" ip route replace "${SERVER_ADDR}/32" \
    via "$(server_ip "$DROP_SLOT")" dev "$vc" metric "$((100 + DROP_SLOT))" 2>/dev/null || true

n=$(wait_for_n_paths "$N_PATHS" 30) && rc=0 || rc=$?
if [ "$rc" -eq 2 ]; then
    echo "=== FAIL: server died during Phase 3 ==="
    exit 1
fi
if [ "$n" -ne "$N_PATHS" ]; then
    echo "=== FAIL: n_paths=$n (expected $N_PATHS after re-add) ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: n_paths recovered to $N_PATHS"

if ! ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "=== FAIL: tunnel ping broken after re-add ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "=== Phase 3: PASS ==="

echo ""
echo "=== All 8-path dellink tests PASSED ==="
