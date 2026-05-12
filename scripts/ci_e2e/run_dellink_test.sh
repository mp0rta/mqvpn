#!/bin/bash
# run_dellink_test.sh — E2E test for RTM_DELLINK path removal/re-addition
#
# Verifies that when a network interface is removed (ip link del / USB unplug),
# the VPN immediately cleans up the dead path, and when the interface reappears,
# the path is automatically re-added with a fresh socket.
#
# Topology (dual-path multipath):
#   vpn-client                   vpn-server
#     veth-a0 ─────────────────── veth-a1       Path A (10.100.0.0/24)
#     10.100.0.2/24               10.100.0.1/24
#     veth-b0 ─────────────────── veth-b1       Path B (10.200.0.0/24)
#     10.200.0.2/24               10.200.0.1/24
#
# Test steps:
#   1. Establish dual-path VPN tunnel
#   2. ip link del Path A → verify surviving Path B handles traffic
#   3. ip link add Path A back → verify path re-added and tunnel works
#
# Usage: sudo ./run_dellink_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

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

# Namespace and veth names
NS_SERVER="vpn-server-dl"
NS_CLIENT="vpn-client-dl"
VETH_A0="veth-a0"
VETH_A1="veth-a1"
VETH_B0="veth-b0"
VETH_B1="veth-b1"

# IP addressing
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
    stop_and_check_sanitizer "$CLIENT_PID" "client" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" || SANITIZER_FAIL=1
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

# Generate PSK + cert
PSK=$("$MQVPN" --genkey 2>/dev/null)
echo "Generated PSK: ${PSK:0:8}..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-dellink-test" 2>/dev/null

wait_for_log() {
    local file="$1" pattern="$2" timeout="${3:-15}" elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if grep -qiE "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# =================================================================
#  Setup: dual-path netns topology
# =================================================================

echo "=== Setting up network namespaces ==="
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
ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Server address on loopback (survives veth-a1 destruction)
ip netns exec "$NS_SERVER" ip addr add "${SERVER_ADDR}/32" dev lo

# Backup route so server is reachable from Path B too
ip netns exec "$NS_CLIENT" ip route add 10.100.0.0/24 via 10.200.0.1 dev "$VETH_B0" metric 200

# Verify connectivity
ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$SERVER_ADDR" >/dev/null
ip netns exec "$NS_CLIENT" ping -c 1 -W 1 10.200.0.1 >/dev/null
echo "OK: netns topology created"

# =================================================================
#  Start VPN server + client
# =================================================================

echo "=== Starting VPN server ==="
ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server \
    --listen "0.0.0.0:4433" \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "=== FAIL: Server process died ==="
    cat "${WORK_DIR}/server.log"
    exit 1
fi
echo "Server running (PID $SERVER_PID)"

echo "=== Starting VPN client (dual-path) ==="
ip netns exec "$NS_CLIENT" "$MQVPN" \
    --mode client \
    --server "${SERVER_ADDR}:4433" \
    --path "$VETH_A0" --path "$VETH_B0" \
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

# Wait for tunnel + dual-path activation
echo "Waiting for tunnel..."
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
if ! wait_for_log "${WORK_DIR}/client.log" "path.*1.*activated" 15; then
    echo "=== FAIL: Secondary path not activated within 15s ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: dual-path active"

# =================================================================
#  Test 1: ip link del → surviving path continues
# =================================================================

echo ""
echo "=== Test 1: Interface removal — surviving path continues ==="

ip netns exec "$NS_CLIENT" ip link del "$VETH_A0"

if ! wait_for_log "${WORK_DIR}/client.log" "netlink: interface ${VETH_A0}.*closing path" 20; then
    echo "WARNING: Path A closure not detected in log within 20s"
fi
sleep 2

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "OK: tunnel ping works on surviving Path B"
else
    echo "=== FAIL: Tunnel ping failed after Path A removal ==="
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    exit 1
fi

if grep -qiE "interface.*removed|netlink.*removed" "${WORK_DIR}/client.log" 2>/dev/null; then
    echo "OK: RTM_DELLINK handler fired"
else
    echo "=== FAIL: RTM_DELLINK not detected in client log ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "=== Test 1: PASS ==="

# =================================================================
#  Test 2: ip link add → path re-added
# =================================================================

echo ""
echo "=== Test 2: Interface re-creation — path re-added ==="

# Re-create veth pair (both ends were destroyed by ip link del)
ip link add "$VETH_A0" type veth peer name "$VETH_A1"
ip link set "$VETH_A0" netns "$NS_CLIENT"
ip link set "$VETH_A1" netns "$NS_SERVER"
ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0"
ip netns exec "$NS_SERVER" ip addr add "$IP_A_SERVER" dev "$VETH_A1"
ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
ip netns exec "$NS_SERVER" ip link set "$VETH_A1" up

# Re-add backup route
ip netns exec "$NS_CLIENT" ip route replace 10.100.0.0/24 via 10.200.0.1 dev "$VETH_B0" metric 200 2>/dev/null || true

if ! wait_for_log "${WORK_DIR}/client.log" "re-appear|re-added|re.add" 15; then
    echo "=== FAIL: Path re-addition not detected within 15s ==="
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "OK: tunnel ping works after Path A re-added"
else
    echo "=== FAIL: Tunnel ping failed after Path A re-addition ==="
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    exit 1
fi
echo "=== Test 2: PASS ==="

echo ""
echo "=== All RTM_DELLINK tests PASSED ==="
