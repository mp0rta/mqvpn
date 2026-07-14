#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_g_p10_proactive_cid_test.sh — G-P10 (proactive per-path CID issuance).
#
# Validates that after handshake completes the server proactively issues
# NEW_CONNECTION_ID for every UNUSED path_id (draft-21 §3.2.1 ¶1 RECOMMENDED),
# not just path_id=0. The client log should show MP NEW_CID frames received
# for path_id 0 AND >=1 within ~2 seconds of handshake.
#
# Topology: standard dual-path veth (-gp10 suffix). 2-path topology supports
# all 3 schedulers (minrtt / wlb / backup_fec — the last requires >=2 paths).
#
# Usage: sudo ./run_g_p10_proactive_cid_test.sh [mqvpn-binary] [--log-level LEVEL]
#   Override schedulers via env: SCHEDULERS_LIST="minrtt wlb" ./run_...

set -e

source "$(dirname "$0")/sanitizer_check.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
LOG_LEVEL="debug"   # need DEBUG: new_conn_id frame log is XQC_LOG_DEBUG

while [ $# -gt 0 ]; do
    case "$1" in
        --log-level) LOG_LEVEL="$2"; shift 2 ;;
        *) [ -z "$MQVPN" ] && MQVPN="$1"; shift ;;
    esac
done

MQVPN="${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}"
[ -f "$MQVPN" ] || { echo "error: mqvpn binary not found at $MQVPN"; exit 1; }
MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

SCHEDULERS_LIST="${SCHEDULERS_LIST:-minrtt wlb backup_fec}"

NS_SERVER="vpn-server-gp10"
NS_CLIENT="vpn-client-gp10"
VETH_A0="veth-a0-gp10"
VETH_A1="veth-a1-gp10"
VETH_B0="veth-b0-gp10"
VETH_B1="veth-b1-gp10"

IP_A_CLIENT="10.110.0.2/24"
IP_A_SERVER="10.110.0.1/24"
IP_B_CLIENT="10.210.0.2/24"
IP_B_SERVER="10.210.0.1/24"
SERVER_ADDR="10.110.0.1"
TUNNEL_IP="10.0.0.1"

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0
PASS=0
FAIL=0

cleanup_processes() {
    stop_and_check_sanitizer "$CLIENT_PID" "client" "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    SERVER_PID=""
    CLIENT_PID=""
    sleep 1
}

teardown_topology() {
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    cleanup_processes
    teardown_topology
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

teardown_topology

PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-gp10-test" 2>/dev/null

setup_topology() {
    ip netns add "$NS_SERVER"
    ip netns add "$NS_CLIENT"
    ip link add "$VETH_A0" type veth peer name "$VETH_A1"
    ip link set "$VETH_A0" netns "$NS_CLIENT"
    ip link set "$VETH_A1" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0"
    ip netns exec "$NS_SERVER" ip addr add "$IP_A_SERVER" dev "$VETH_A1"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
    ip netns exec "$NS_SERVER" ip link set "$VETH_A1" up
    ip link add "$VETH_B0" type veth peer name "$VETH_B1"
    ip link set "$VETH_B0" netns "$NS_CLIENT"
    ip link set "$VETH_B1" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$IP_B_CLIENT" dev "$VETH_B0"
    ip netns exec "$NS_SERVER" ip addr add "$IP_B_SERVER" dev "$VETH_B1"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" up
    ip netns exec "$NS_SERVER" ip link set "$VETH_B1" up
    ip netns exec "$NS_CLIENT" ip link set lo up
    ip netns exec "$NS_SERVER" ip link set lo up
    ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null
    ip netns exec "$NS_SERVER" ip addr add "${SERVER_ADDR}/32" dev lo
    ip netns exec "$NS_CLIENT" ip route add 10.110.0.0/24 via 10.210.0.1 dev "$VETH_B0" metric 200
    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$SERVER_ADDR" >/dev/null
    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 10.210.0.1 >/dev/null
}

start_server() {
    local sched="$1"
    ip netns exec "$NS_SERVER" "$MQVPN" \
        --mode server \
        --listen "0.0.0.0:4433" \
        --subnet 10.0.0.0/24 \
        --cert "${WORK_DIR}/server.crt" \
        --key "${WORK_DIR}/server.key" \
        --auth-key "$PSK" \
        --scheduler "$sched" \
        --log-level "$LOG_LEVEL" > "${WORK_DIR}/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
    kill -0 "$SERVER_PID" 2>/dev/null
}

start_client() {
    local sched="$1"
    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server "${SERVER_ADDR}:4433" \
        --path "$VETH_A0" --path "$VETH_B0" \
        --auth-key "$PSK" \
        --insecure \
        --scheduler "$sched" \
        --log-level "$LOG_LEVEL" > "${WORK_DIR}/client.log" 2>&1 &
    CLIENT_PID=$!
    sleep 3
    kill -0 "$CLIENT_PID" 2>/dev/null
}

wait_tunnel() {
    local timeout="${1:-30}" elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

run_one_scheduler() {
    local sched="$1"
    if ! start_server "$sched"; then
        echo "  FAIL: server did not start"
        cat "${WORK_DIR}/server.log"
        return 1
    fi
    if ! start_client "$sched"; then
        echo "  FAIL: client did not start"
        cat "${WORK_DIR}/client.log"
        return 1
    fi
    if ! wait_tunnel 30; then
        echo "  FAIL: tunnel not reachable within 30s"
        tail -40 "${WORK_DIR}/client.log"
        return 1
    fi

    # Allow ~2s for post-handshake proactive issuance + alt-path propagation.
    sleep 2

    # Server emits MP NEW_CID per UNUSED path_id (G-P10). The server-side
    # emission log in xqc_write_mp_new_conn_id_frame_to_packet
    # (xqc_packet_out.c:1799) format is:
    #   |path_id:N|cid:<cid>|sr_token:<token>|seq_num:M
    # path_id=0 is always issued (pre-G-P10 behaviour); G-P10 adds path_id>=1.
    # Note: the client-side receipt log "|new_conn_id|<cid>|sr_token:..."
    # does NOT carry path_id, so we must check server.log for emission.
    local count
    count=$(grep -cE '\|path_id:[1-9][0-9]*\|cid:[0-9a-f]+\|sr_token:' "${WORK_DIR}/server.log" || true)
    echo "  observed server emissions for path_id>=1: ${count}"

    if [ "$count" -lt 1 ]; then
        echo "  FAIL: no MP NEW_CID emission for path_id>=1 (G-P10 proactive issuance)"
        echo "  --- server.log (last 80 lines) ---"
        tail -80 "${WORK_DIR}/server.log"
        return 1
    fi
    return 0
}

for sched in $SCHEDULERS_LIST; do
    echo ""
    echo "=== Test: G-P10 proactive per-path CID issuance (scheduler=$sched) ==="
    setup_topology
    if run_one_scheduler "$sched"; then
        echo "  PASS: $sched"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $sched"
        FAIL=$((FAIL + 1))
    fi
    cleanup_processes
    teardown_topology
done

echo ""
echo "================================================="
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================="
[ "$FAIL" -eq 0 ]
