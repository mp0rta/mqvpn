#!/bin/bash
# run_backup_fec_test.sh — E2E smoke for the backup_fec scheduler.
#
# Verifies that both endpoints can establish a dual-path tunnel with
# Scheduler=backup_fec, and that a peer running wlb still interoperates
# (FEC negotiation downgrades silently). No loss is injected — FEC effect
# measurement is the responsibility of perf-weekly's ci_bench_backup_fec.sh.
#
# Topology (dual-path):
#   vpn-client                   vpn-server
#     veth-a0 ─────────────────── veth-a1       Path A (10.100.0.0/24)
#     veth-b0 ─────────────────── veth-b1       Path B (10.200.0.0/24)
#
# Test cases:
#   1. symmetric backup_fec — both sides on backup_fec, ping over tunnel
#   2. compatibility — client=backup_fec, server=wlb; ping still works
#
# Usage: sudo ./run_backup_fec_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

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

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

NS_SERVER="vpn-server-fec"
NS_CLIENT="vpn-client-fec"
VETH_A0="veth-a0-fec"
VETH_A1="veth-a1-fec"
VETH_B0="veth-b0-fec"
VETH_B1="veth-b1-fec"

IP_A_CLIENT="10.100.0.2/24"
IP_A_SERVER="10.100.0.1/24"
IP_B_CLIENT="10.200.0.2/24"
IP_B_SERVER="10.200.0.1/24"
SERVER_ADDR="10.100.0.1"
TUNNEL_IP="10.0.0.1"

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0
PASS=0
FAIL=0

cleanup_processes() {
    stop_and_check_sanitizer "$CLIENT_PID" "client" \
        "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" \
        "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
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

# Clean leftovers
ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip link del "$VETH_A0" 2>/dev/null || true
ip link del "$VETH_B0" 2>/dev/null || true

# Generate PSK + cert
PSK=$("$MQVPN" --genkey 2>/dev/null)
echo "Generated PSK: ${PSK:0:8}..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-backup-fec-test" 2>/dev/null

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
    ip netns exec "$NS_CLIENT" ip route add 10.100.0.0/24 via 10.200.0.1 dev "$VETH_B0" metric 200

    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$SERVER_ADDR" >/dev/null
    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 10.200.0.1 >/dev/null
}

teardown_topology() {
    cleanup_processes
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true
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
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "  server died"
        cat "${WORK_DIR}/server.log"
        return 1
    fi
}

start_client() {
    local sched="$1"
    # Force at least info level so the "path[N] activated: ... state=STANDBY"
    # log line emitted at LOG_I in mqvpn_client.c (tick_check_all_validations)
    # is captured. Without this, --log-level warn/error would silently fail
    # the STANDBY assertion below even on a correctly built binary.
    local client_log_level="$LOG_LEVEL"
    case "$client_log_level" in
        warn|error) client_log_level="info" ;;
    esac
    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server "${SERVER_ADDR}:4433" \
        --path "$VETH_A0" --path "$VETH_B0" \
        --auth-key "$PSK" \
        --insecure \
        --scheduler "$sched" \
        --log-level "$client_log_level" > "${WORK_DIR}/client.log" 2>&1 &
    CLIENT_PID=$!
    sleep 3
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "  client died"
        cat "${WORK_DIR}/client.log"
        return 1
    fi
}

wait_tunnel() {
    local timeout="${1:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

run_test() {
    local name="$1"
    local server_sched="$2"
    local client_sched="$3"
    local expect_standby="$4"  # "yes" if client must mark secondary as STANDBY

    echo ""
    echo "=== Test: $name ==="

    setup_topology
    if ! start_server "$server_sched"; then
        FAIL=$((FAIL + 1))
        teardown_topology
        return
    fi
    if ! start_client "$client_sched"; then
        FAIL=$((FAIL + 1))
        teardown_topology
        return
    fi

    if ! wait_tunnel 15; then
        echo "  FAIL: tunnel not reachable within 15s"
        echo "  --- client.log ---"
        cat "${WORK_DIR}/client.log"
        FAIL=$((FAIL + 1))
        teardown_topology
        return
    fi

    if ! ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
        echo "  FAIL: ping failed"
        FAIL=$((FAIL + 1))
        teardown_topology
        return
    fi

    # Catch a regression where backup_fec stops creating the secondary path
    # as STANDBY (e.g. someone changes the path_status arg back to 0).
    # Without this, ping-only check would still pass via Path A even if
    # FEC repair traffic never gets a STANDBY destination.
    #
    # PR4 changed the log marker: pre-PR4 client_activate_path emitted
    # "path[%d] created ... app_path_status=STANDBY" (xquic-side app status).
    # PR4 moved this into tick_check_all_validations which emits
    # "path[%d] activated: path_id=N iface=X state=STANDBY"
    # (internal lifecycle name). Grep the new marker.
    if [ "$expect_standby" = "yes" ]; then
        if ! grep -qE "path\[[0-9]+\] activated.*state=STANDBY" \
                "${WORK_DIR}/client.log"; then
            echo "  FAIL: secondary path not created as STANDBY"
            echo "  --- client.log (last 30 lines) ---"
            tail -30 "${WORK_DIR}/client.log"
            FAIL=$((FAIL + 1))
            teardown_topology
            return
        fi
    fi

    echo "  PASS: $name"
    PASS=$((PASS + 1))
    teardown_topology
}

run_test "symmetric backup_fec"           backup_fec backup_fec yes
run_test "compat: client=fec, server=wlb" wlb        backup_fec yes

echo ""
echo "================================================="
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================="
[ "$FAIL" -eq 0 ]
