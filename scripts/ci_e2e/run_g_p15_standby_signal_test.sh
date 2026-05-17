#!/bin/bash
# run_g_p15_standby_signal_test.sh — G-P15 (mqvpn lifecycle -> xquic path-status glue).
#
# When mqvpn marks the secondary path as STANDBY (backup_fec scheduler), the
# client emits PATH_STATUS_BACKUP and the server's xqc_process_path_status_frame
# must log:
#   |path status:1|path_id:1|   (path_status=1 == STANDBY enum)
#
# This is wire-level proof of the glue; the parent backup_fec test only
# verifies the client-side log marker.
#
# Topology: standard dual-path veth (-gp15 suffix).
#
# Usage: sudo ./run_g_p15_standby_signal_test.sh [mqvpn-binary] [--log-level LEVEL]

set -e

source "$(dirname "$0")/sanitizer_check.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
LOG_LEVEL="debug"   # need DEBUG: '|path status:%ui|path_id:%ui|' is XQC_LOG_DEBUG

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

NS_SERVER="vpn-server-gp15"
NS_CLIENT="vpn-client-gp15"
VETH_A0="veth-a0-gp15"
VETH_A1="veth-a1-gp15"
VETH_B0="veth-b0-gp15"
VETH_B1="veth-b1-gp15"

IP_A_CLIENT="10.115.0.2/24"
IP_A_SERVER="10.115.0.1/24"
IP_B_CLIENT="10.215.0.2/24"
IP_B_SERVER="10.215.0.1/24"
SERVER_ADDR="10.115.0.1"
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

cleanup() {
    echo ""
    echo "Cleaning up..."
    cleanup_processes
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip link del "$VETH_A0" 2>/dev/null || true
ip link del "$VETH_B0" 2>/dev/null || true

PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-gp15-test" 2>/dev/null

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
ip netns exec "$NS_CLIENT" ip route add 10.115.0.0/24 via 10.215.0.1 dev "$VETH_B0" metric 200

ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server \
    --listen "0.0.0.0:4433" \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --scheduler backup_fec \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "  FAIL: server died"; cat "${WORK_DIR}/server.log"; FAIL=$((FAIL + 1))
else
    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server "${SERVER_ADDR}:4433" \
        --path "$VETH_A0" --path "$VETH_B0" \
        --auth-key "$PSK" \
        --insecure \
        --scheduler backup_fec \
        --log-level "$LOG_LEVEL" > "${WORK_DIR}/client.log" 2>&1 &
    CLIENT_PID=$!
    sleep 3

    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "  FAIL: client died"; cat "${WORK_DIR}/client.log"; FAIL=$((FAIL + 1))
    else
        TUNNEL_OK=0
        for i in $(seq 1 30); do
            if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
                TUNNEL_OK=1; break
            fi
            sleep 1
        done

        if [ "$TUNNEL_OK" -ne 1 ]; then
            echo "  FAIL: tunnel never reachable"
            tail -40 "${WORK_DIR}/client.log"
            FAIL=$((FAIL + 1))
        else
            echo "=== Test: G-P15 STANDBY signal wire-level ==="
            # Allow up to 5s for the demote-to-STANDBY flow to complete and
            # for PATH_STATUS_BACKUP to land + be logged.
            STANDBY_OK=0
            for i in $(seq 1 5); do
                # path_status=1 is STANDBY (xqc_app_path_status_t enum).
                # path_id should be 1 (secondary). Match defensively.
                if grep -qE "\|path status:1\|path_id:[1-9][0-9]*\|" "${WORK_DIR}/server.log"; then
                    STANDBY_OK=1; break
                fi
                sleep 1
            done

            if [ "$STANDBY_OK" -eq 1 ]; then
                echo "  PASS: server received PATH_STATUS_BACKUP (status=1) for secondary path"
                PASS=$((PASS + 1))
            else
                echo "  FAIL: PATH_STATUS_BACKUP not observed on server within 5s"
                echo "  --- server.log (last 80 lines) ---"
                tail -80 "${WORK_DIR}/server.log"
                FAIL=$((FAIL + 1))
            fi
        fi
    fi
fi

echo ""
echo "================================================="
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================="
[ "$FAIL" -eq 0 ]
