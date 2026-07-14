#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_g_p16_paths_blocked_emission_test.sh — E2E test for the
# PR7 (receive auto-grant) + PR8 (G-P16 PATHS_BLOCKED send-side)
# closed loop, exercised via a deterministic 4-path startup scenario
# (Option E: low init_max_path_id).
#
# Background
# ----------
# xquic Stage 1 reject in xqc_path_create:
#   if (path_id > conn->remote_settings.init_max_path_id
#       && path_id > conn->local_max_path_id) { reject + G-P16 fire }
#
# This is an AND condition: the effective accept-cap is
#   max(remote_init_max_path_id, local_max_path_id).
# To trigger G-P16 deterministically in a mqvpn-only scenario, BOTH
# endpoints must advertise init_max_path_id = 2. With both = 2:
#   - path_id 0,1,2 → accept
#   - path_id 3     → 3 > 2 && 3 > 2 → Stage 1 reject → G-P16 fires
#
# 2 is the only value that works within MQVPN_MAX_PATHS=4: it lets
# the first 3 paths succeed and traps the 4th at startup, no carrier
# flap timing required.
#
# The closed loop being validated:
#   1. mqvpn client adds path_id 3 → xquic Stage 1 reject
#   2. xquic G-P16 send-side emits PATHS_BLOCKED toward server
#      (log marker: "|PATHS_BLOCKED sent|")
#   3. xquic server PR7 auto-grant observes PATHS_BLOCKED and emits
#      MAX_PATH_ID grant (mqvpn-server enables this via
#      conn_settings.max_path_id_grant_max_value = 64 since PR8).
#      Log marker: "|MAX_PATH_ID auto-grant|new_local_max:..."
#   4. Client recv processes MAX_PATH_ID; tunnel remains alive on
#      paths 0..2 and (eventually) path 3 succeeds on retry.
#
# Topology (4 paths, 2 netns):
#   vpn-client                   vpn-server
#     veth-a0 ─────────────────── veth-a1       Path A (10.10.0.0/24)
#     veth-b0 ─────────────────── veth-b1       Path B (10.20.0.0/24)
#     veth-c0 ─────────────────── veth-c1       Path C (10.30.0.0/24)
#     veth-d0 ─────────────────── veth-d1       Path D (10.40.0.0/24)
#
# Usage: sudo ./run_g_p16_paths_blocked_emission_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

set -e

source "$(dirname "$0")/sanitizer_check.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
# debug required: mqvpn INFO -> xquic WARN per project_log_level_xquic_mapping.md,
# so xquic XQC_LOG_INFO markers ("|PATHS_BLOCKED sent|", "|MAX_PATH_ID auto-grant|")
# are filtered out unless mqvpn runs at debug. Per-packet log flood cliff (5x
# Windows perf hit) does not apply under Linux netns CI.
LOG_LEVEL="debug"

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

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

# Unique names so this test runs alongside other e2e tests
NS_SERVER="vpn-server-gp16"
NS_CLIENT="vpn-client-gp16"
VETH_A0="veth-a0-gp16"
VETH_A1="veth-a1-gp16"
VETH_B0="veth-b0-gp16"
VETH_B1="veth-b1-gp16"
VETH_C0="veth-c0-gp16"
VETH_C1="veth-c1-gp16"
VETH_D0="veth-d0-gp16"
VETH_D1="veth-d1-gp16"

IP_A_CLIENT="10.10.0.2/24"; IP_A_SERVER="10.10.0.1/24"
IP_B_CLIENT="10.20.0.2/24"; IP_B_SERVER="10.20.0.1/24"
IP_C_CLIENT="10.30.0.2/24"; IP_C_SERVER="10.30.0.1/24"
IP_D_CLIENT="10.40.0.2/24"; IP_D_SERVER="10.40.0.1/24"
SERVER_ADDR="10.10.0.1"
TUNNEL_IP="10.0.0.1"

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0

cleanup() {
    echo ""
    echo "Cleaning up..."
    stop_and_check_sanitizer "$CLIENT_PID" "client" \
        "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" \
        "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    sleep 1
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true
    ip link del "$VETH_C0" 2>/dev/null || true
    ip link del "$VETH_D0" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

# Clean leftovers
ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip link del "$VETH_A0" 2>/dev/null || true
ip link del "$VETH_B0" 2>/dev/null || true
ip link del "$VETH_C0" 2>/dev/null || true
ip link del "$VETH_D0" 2>/dev/null || true

wait_for_log() {
    local log_file="$1" pattern="$2" timeout="${3:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if grep -qE "$pattern" "$log_file" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# ─── Setup ───
PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-gp16-paths-blocked-test" 2>/dev/null

ip netns add "$NS_SERVER"
ip netns add "$NS_CLIENT"

# Create 4 veth pairs
add_veth() {
    local v0="$1" v1="$2" ipc="$3" ips="$4"
    ip link add "$v0" type veth peer name "$v1"
    ip link set "$v0" netns "$NS_CLIENT"
    ip link set "$v1" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$ipc" dev "$v0"
    ip netns exec "$NS_SERVER" ip addr add "$ips" dev "$v1"
    ip netns exec "$NS_CLIENT" ip link set "$v0" up
    ip netns exec "$NS_SERVER" ip link set "$v1" up
}

add_veth "$VETH_A0" "$VETH_A1" "$IP_A_CLIENT" "$IP_A_SERVER"
add_veth "$VETH_B0" "$VETH_B1" "$IP_B_CLIENT" "$IP_B_SERVER"
add_veth "$VETH_C0" "$VETH_C1" "$IP_C_CLIENT" "$IP_C_SERVER"
add_veth "$VETH_D0" "$VETH_D1" "$IP_D_CLIENT" "$IP_D_SERVER"

ip netns exec "$NS_CLIENT" ip link set lo up
ip netns exec "$NS_SERVER" ip link set lo up

ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$NS_SERVER" ip addr add "${SERVER_ADDR}/32" dev lo

# Non-primary paths reach the server via their own subnet → server lo.
# Path A is the primary (server bind/connect addr), so no extra route needed.
ip netns exec "$NS_CLIENT" ip route add 10.10.0.0/24 via 10.20.0.1 dev "$VETH_B0" metric 200
ip netns exec "$NS_CLIENT" ip route add 10.10.0.0/24 via 10.30.0.1 dev "$VETH_C0" metric 300
ip netns exec "$NS_CLIENT" ip route add 10.10.0.0/24 via 10.40.0.1 dev "$VETH_D0" metric 400

ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$SERVER_ADDR" >/dev/null
ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.20.0.1 >/dev/null
ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.30.0.1 >/dev/null
ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.40.0.1 >/dev/null

# ─── Server (init_max_path_id=2: caps Stage 1 at path_id 2) ───
ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server \
    --listen "0.0.0.0:4433" \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --scheduler wlb \
    --init-max-path-id 2 \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "server died"
    cat "${WORK_DIR}/server.log"
    exit 1
fi

# ─── Client (4 paths, init_max_path_id=2: path_id 3 trips G-P16) ───
ip netns exec "$NS_CLIENT" "$MQVPN" \
    --mode client \
    --server "${SERVER_ADDR}:4433" \
    --path "$VETH_A0" --path "$VETH_B0" --path "$VETH_C0" --path "$VETH_D0" \
    --auth-key "$PSK" \
    --insecure \
    --scheduler wlb \
    --init-max-path-id 2 \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "client died"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# Wait for tunnel up on the primary path
ELAPSED=0
while [ "$ELAPSED" -lt 15 ]; do
    if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
if [ "$ELAPSED" -ge 15 ]; then
    echo "=== FAIL: Tunnel not reachable after 15s ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: tunnel up (${ELAPSED}s)"

# Wait for the closed-loop markers to settle. We don't strictly require
# all 4 paths to be ACTIVE — what we want is:
#   - path_id 3 attempted on the client (Stage 1 reject)
#   - PATHS_BLOCKED emitted (A1)
#   - MAX_PATH_ID auto-grant emitted on server (A2)
# Give the engines ~12s to round-trip these.
echo "Waiting up to 12s for PATHS_BLOCKED closed loop..."
wait_for_log "${WORK_DIR}/client.log" '\|PATHS_BLOCKED sent\|' 12 || true
wait_for_log "${WORK_DIR}/server.log" '\|MAX_PATH_ID auto-grant\|' 5 || true
sleep 2  # final settle

# =================================================================
#  Assertions — the closed loop
# =================================================================

echo ""
echo "=== Assertions ==="
PASS=0
FAIL=0

# A1 (hard) — G-P16 client-side PATHS_BLOCKED emission. The exact
# substring is load-bearing per xquic L5e Task 1.4 log wording at
# src/transport/xqc_multipath.c:224.
if grep -q '|PATHS_BLOCKED sent|' "${WORK_DIR}/client.log"; then
    echo "A1 PASS: G-P16 PATHS_BLOCKED sent (client emit)"
    PASS=$((PASS + 1))
else
    echo "A1 FAIL: '|PATHS_BLOCKED sent|' not found in client.log"
    echo "  (Expected: client tries path_id 3 with init_max_path_id=2 cap"
    echo "   → Stage 1 reject → PATHS_BLOCKED emit.)"
    echo "--- last 80 lines of client.log ---"
    tail -n 80 "${WORK_DIR}/client.log" || true
    FAIL=$((FAIL + 1))
fi

# A2 (hard) — server-side MAX_PATH_ID auto-grant (PR7 receive-side
# closed-loop counterpart). mqvpn-server enables this in PR8 via
# conn_settings.max_path_id_grant_max_value = 64 (mqvpn_server.c).
# Log wording at xqc_frame.c:2440:
#   "|MAX_PATH_ID auto-grant|new_local_max:%ui|"
if grep -q '|MAX_PATH_ID auto-grant|' "${WORK_DIR}/server.log"; then
    echo "A2 PASS: server PR7 MAX_PATH_ID auto-grant fired"
    PASS=$((PASS + 1))
else
    echo "A2 FAIL: '|MAX_PATH_ID auto-grant|' not in server.log"
    echo "  (PR7 auto-grant should fire after client PATHS_BLOCKED.)"
    echo "--- last 80 lines of server.log ---"
    tail -n 80 "${WORK_DIR}/server.log" || true
    FAIL=$((FAIL + 1))
fi

# A3 (hard) — tunnel must stay alive throughout the closed loop.
# Auto-grant closes the loop; even if path_id 3 stays PENDING, paths
# 0..2 carry the data plane and the tunnel ping must succeed.
if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "A3 PASS: tunnel still reachable after auto-grant"
    PASS=$((PASS + 1))
else
    echo "A3 FAIL: tunnel ping failed after closed-loop sequence"
    echo "--- last 60 lines of client.log ---"
    tail -n 60 "${WORK_DIR}/client.log" || true
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=== Summary: PASS=${PASS} FAIL=${FAIL} ==="

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
echo "=== G-P16 PATHS_BLOCKED emission test PASSED ==="
