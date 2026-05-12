#!/bin/bash
# run_carrier_flap_test.sh — E2E test for carrier-flap recovery (ip link
# set down/up without ip addr del/add).
#
# Distinct from run_dellink_test.sh: that exercises RTM_DELLINK (interface
# fully destroyed and recreated, RTM_NEWADDR follows). This exercises
# carrier-only flaps that emit RTM_NEWLINK with IFF_UP / IFF_RUNNING
# toggling but DO NOT emit RTM_NEWADDR — the failure mode protected by
# the 3s recover_dropped_paths_cb timer (platform_linux.c).
#
# Why this needs its own test: if the one-shot try_readd_removed_path()
# driven by the single RTM_NEWLINK fails (e.g. xqc_conn_create_path
# transient error during the carrier transient), there is no further
# netlink event to retry on — only the 3s timer keeps the slot
# recoverable.
#
# Topology (dual-path multipath):
#   vpn-client                   vpn-server
#     veth-a0 ─────────────────── veth-a1       Path A (10.100.0.0/24)
#     veth-b0 ─────────────────── veth-b1       Path B (10.200.0.0/24)
#
# Test steps:
#   1. Establish dual-path VPN tunnel
#   2. ip link set veth-a0 down (carrier loss) -> verify Path B handles traffic
#   3. ip link set veth-a0 up (carrier restore) -> verify Path A re-added
#      (via either netlink-triggered try_readd OR 3s recovery timer)
#
# Usage: sudo ./run_carrier_flap_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

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

# Unique names so this test runs alongside other e2e tests
NS_SERVER="vpn-server-cf"
NS_CLIENT="vpn-client-cf"
VETH_A0="veth-a0-cf"
VETH_A1="veth-a1-cf"
VETH_B0="veth-b0-cf"
VETH_B1="veth-b1-cf"

IP_A_CLIENT="10.100.0.2/24"
IP_A_SERVER="10.100.0.1/24"
IP_B_CLIENT="10.200.0.2/24"
IP_B_SERVER="10.200.0.1/24"
SERVER_ADDR="10.100.0.1"
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
    -days 365 -nodes -subj "/CN=mqvpn-carrier-flap-test" 2>/dev/null

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

ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$SERVER_ADDR" >/dev/null
ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.200.0.1 >/dev/null

# ─── Server ───
ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server \
    --listen "0.0.0.0:4433" \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --scheduler wlb \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "server died"
    cat "${WORK_DIR}/server.log"
    exit 1
fi

# ─── Client ───
ip netns exec "$NS_CLIENT" "$MQVPN" \
    --mode client \
    --server "${SERVER_ADDR}:4433" \
    --path "$VETH_A0" --path "$VETH_B0" \
    --auth-key "$PSK" \
    --insecure \
    --scheduler wlb \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "client died"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# Wait for tunnel up
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

echo "Waiting for dual-path activation..."
if ! wait_for_log "${WORK_DIR}/client.log" "path.*activated|state=ACTIVE" 15; then
    echo "=== FAIL: Secondary path not activated within 15s ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: dual-path active"

# =================================================================
#  Test 1: peer-side link down → carrier lost, surviving path continues
# =================================================================
#
# Take the SERVER-side end of the veth pair down — this causes the
# client-side veth to lose carrier (operstate IF_OPER_LOWERLAYERDOWN)
# while admin IFF_UP stays 1. That's what `is_carrier_loss()` in
# platform_linux.c gates on (it ignores admin-down events to avoid
# treating intentional `ip link set down` as a transient flap).
#
# Doing `ip link set <local> down` would clear IFF_UP and be filtered
# out by the carrier-loss gate — that's by design, so test the
# real-world case.

echo ""
echo "=== Test 1: Carrier loss (peer-side ip link set down) — Path B survives ==="

ip netns exec "$NS_SERVER" ip link set "$VETH_A1" down

# After RTM_NEWLINK with operstate=LOWERLAYERDOWN, handle_rtm_newlink
# should call remove_path_by_index → public APIs
# (on_platform_path_dropped + on_platform_fd_closed). Log marker:
#   "netlink: interface veth-a0-cf carrier lost, closing path"
if ! wait_for_log "${WORK_DIR}/client.log" "netlink: interface ${VETH_A0}.*closing path" 15; then
    echo "=== FAIL: Carrier-loss event not handled ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: carrier-loss event handled"

sleep 2

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "OK: tunnel ping works on surviving Path B"
else
    echo "=== FAIL: Tunnel ping failed after carrier loss ==="
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# =================================================================
#  Test 2: peer-side link up → carrier restored, path re-added
#  (via netlink event OR 3s recovery timer)
# =================================================================

echo ""
echo "=== Test 2: Carrier restore (peer-side ip link set up) — path re-added ==="

ip netns exec "$NS_SERVER" ip link set "$VETH_A1" up
# Client-side veth-a0-cf was never admin-downed, so this restores carrier.

# Allow up to 20s — the recovery timer fires every 3s, so even if the
# RTM_NEWLINK-driven try_readd_removed_path() fails synchronously, the
# timer will succeed on a later tick. The whole point of this test is
# that recovery DOES happen even when the netlink event sequence is
# minimal (carrier-only, no addr add/del).
if ! wait_for_log "${WORK_DIR}/client.log" "path .* re-added|timer re-added path" 20; then
    echo "=== FAIL: Path re-addition not detected within 20s ==="
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: path re-added"

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "OK: tunnel ping works after carrier restore"
else
    echo "=== FAIL: Tunnel ping failed after carrier restore ==="
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

echo ""
echo "=== All carrier-flap tests PASSED ==="
