#!/bin/bash
# run_ipv6_multipath_test.sh — IPv6 + Multipath E2E test
#
# Verifies that mqvpn can carry IPv6 packets over multipath QUIC,
# including failover and path recovery.
#
# Topology:
#   mp6-client                          mp6-server
#     veth-a0-6 ──────────────── veth-a1-6   (Path A: 192.168.1.0/24)
#     veth-b0-6 ──────────────── veth-b1-6   (Path B: 192.168.2.0/24)
#
# Tunnel overlay:
#   IPv4: 10.0.0.0/24    (server .1, client .2)
#   IPv6: fd00:a6::/112  (server ::1, client ::2)
#
# Usage: sudo ./scripts/run_ipv6_multipath_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
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

# Generate PSK
PSK=$("$MQVPN" --genkey 2>/dev/null)
echo "Generated PSK: ${PSK}"

# Generate self-signed cert
echo "Generating self-signed certificate..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-mp6-test" 2>/dev/null

SUBNET="10.0.0.0/24"
SUBNET6="fd00:a6::/112"

NS_S="mp6-server"
NS_C="mp6-client"

SERVER_PID=""
CLIENT_PID=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    sleep 1
    ip netns del "$NS_S" 2>/dev/null || true
    ip netns del "$NS_C" 2>/dev/null || true
    ip link del veth-a0-6 2>/dev/null || true
    ip link del veth-b0-6 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Clean any leftover namespaces from previous runs
ip netns del "$NS_S" 2>/dev/null || true
ip netns del "$NS_C" 2>/dev/null || true
ip link del veth-a0-6 2>/dev/null || true
ip link del veth-b0-6 2>/dev/null || true

echo "=== Setting up network namespaces (2 paths) ==="
ip netns add "$NS_S"
ip netns add "$NS_C"

# Path A: veth pair (subnet 192.168.1.0/24)
ip link add veth-a0-6 type veth peer name veth-a1-6
ip link set veth-a0-6 netns "$NS_C"
ip link set veth-a1-6 netns "$NS_S"
ip netns exec "$NS_C" ip addr add 192.168.1.1/24 dev veth-a0-6
ip netns exec "$NS_S" ip addr add 192.168.1.2/24 dev veth-a1-6
ip netns exec "$NS_C" ip link set veth-a0-6 up
ip netns exec "$NS_S" ip link set veth-a1-6 up

# Path B: second veth pair (subnet 192.168.2.0/24)
ip link add veth-b0-6 type veth peer name veth-b1-6
ip link set veth-b0-6 netns "$NS_C"
ip link set veth-b1-6 netns "$NS_S"
ip netns exec "$NS_C" ip addr add 192.168.2.1/24 dev veth-b0-6
ip netns exec "$NS_S" ip addr add 192.168.2.2/24 dev veth-b1-6
ip netns exec "$NS_C" ip link set veth-b0-6 up
ip netns exec "$NS_S" ip link set veth-b1-6 up

# Loopback
ip netns exec "$NS_C" ip link set lo up
ip netns exec "$NS_S" ip link set lo up

# Enable IP forwarding and IPv6
ip netns exec "$NS_S" sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$NS_S" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip netns exec "$NS_C" sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
ip netns exec "$NS_S" sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true

# Verify underlay connectivity
echo "=== Verifying underlay connectivity ==="
ip netns exec "$NS_C" ping -c 1 -W 1 192.168.1.2 >/dev/null
echo "OK: Path A (192.168.1.x) working"
ip netns exec "$NS_C" ping -c 1 -W 1 192.168.2.2 >/dev/null
echo "OK: Path B (192.168.2.x) working"

echo "=== Starting VPN server (multipath + dual-stack) ==="
ip netns exec "$NS_S" "$MQVPN" \
    --mode server \
    --listen 0.0.0.0:4433 \
    --subnet "$SUBNET" \
    --subnet6 "$SUBNET6" \
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

echo "=== Starting VPN client (2 paths: veth-a0-6, veth-b0-6) ==="
ip netns exec "$NS_C" "$MQVPN" \
    --mode client \
    --server 192.168.1.2:4433 \
    --path veth-a0-6 --path veth-b0-6 \
    --auth-key "$PSK" \
    --insecure \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
sleep 4

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "=== FAIL: Client process died ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "Client running (PID $CLIENT_PID)"

# Show TUN devices
echo ""
echo "=== TUN devices ==="
echo "--- Server ---"
ip netns exec "$NS_S" ip addr show dev mqvpn0 2>/dev/null || echo "(server TUN not found)"
echo "--- Client ---"
ip netns exec "$NS_C" ip addr show dev mqvpn0 2>/dev/null || echo "(client TUN not found)"

# ==========================================================================
# Test 1: IPv4 ping (regression)
# ==========================================================================
echo ""
echo "=== Test 1: IPv4 ping through multipath tunnel ==="
if ip netns exec "$NS_C" ping -c 3 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "=== Test 1 (IPv4 ping): PASS ==="
else
    echo "=== Test 1 (IPv4 ping): FAIL ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# ==========================================================================
# Test 2: IPv6 ping through multipath tunnel
# ==========================================================================
echo ""
echo "=== Test 2: IPv6 ping through multipath tunnel (fd00:a6::1) ==="
if ip netns exec "$NS_C" ping -6 -c 3 -W 2 fd00:a6::1; then
    echo ""
    echo "=== Test 2 (IPv6 ping): PASS ==="
else
    echo ""
    echo "=== Test 2 (IPv6 ping): FAIL ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# ==========================================================================
# Test 3: Verify IPv6 routes and addresses
# ==========================================================================
echo ""
echo "=== Test 3: Verify IPv6 routes and addresses ==="
FAIL=0

if ip netns exec "$NS_C" ip -6 route show | grep -q "::/1 dev mqvpn0"; then
    echo "OK: IPv6 route ::/1 via mqvpn0"
else
    echo "FAIL: IPv6 route ::/1 not found"
    FAIL=1
fi

if ip netns exec "$NS_C" ip -6 route show | grep -q "8000::/1 dev mqvpn0"; then
    echo "OK: IPv6 route 8000::/1 via mqvpn0"
else
    echo "FAIL: IPv6 route 8000::/1 not found"
    FAIL=1
fi

if ip netns exec "$NS_C" ip -6 addr show dev mqvpn0 | grep -q "fd00:a6::2"; then
    echo "OK: Client TUN has IPv6 address fd00:a6::2"
else
    echo "FAIL: Client TUN missing IPv6 address"
    FAIL=1
fi

if ip netns exec "$NS_S" ip -6 addr show dev mqvpn0 | grep -q "fd00:a6::1"; then
    echo "OK: Server TUN has IPv6 address fd00:a6::1"
else
    echo "FAIL: Server TUN missing IPv6 address"
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "=== Test 3 (IPv6 routes): FAIL ==="
    exit 1
fi
echo ""
echo "=== Test 3 (IPv6 routes): PASS ==="

# ==========================================================================
# Test 4: IPv6 failover — bring down Path A, verify IPv6 continues on Path B
# ==========================================================================
echo ""
echo "=== Test 4: IPv6 failover (Path A down) ==="

echo "[$(date +%T)] Bringing DOWN Path A (veth-a0-6)..."
ip netns exec "$NS_C" ip link set veth-a0-6 down

# Wait for QUIC to detect path loss
sleep 3

echo "[$(date +%T)] Pinging IPv6 through tunnel (Path B only)..."
PING_OK=0
PING_TOTAL=10
for i in $(seq 1 $PING_TOTAL); do
    if ip netns exec "$NS_C" ping -6 -c 1 -W 2 fd00:a6::1 >/dev/null 2>&1; then
        PING_OK=$((PING_OK + 1))
    fi
done
echo "[$(date +%T)] IPv6 ping result: ${PING_OK}/${PING_TOTAL} succeeded"

if [ "$PING_OK" -ge 8 ]; then
    echo ""
    echo "=== Test 4 (IPv6 failover): PASS ==="
else
    echo ""
    echo "=== Test 4 (IPv6 failover): FAIL (${PING_OK}/${PING_TOTAL} < 8) ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# Also verify IPv4 still works on Path B
echo ""
echo "--- IPv4 check during failover ---"
if ip netns exec "$NS_C" ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "OK: IPv4 also working on Path B"
else
    echo "WARN: IPv4 ping failed during failover (non-fatal)"
fi

# ==========================================================================
# Test 5: Path recovery — bring Path A back up, verify IPv4 + IPv6
# ==========================================================================
echo ""
echo "=== Test 5: Path recovery (bring Path A back up) ==="

echo "[$(date +%T)] Bringing UP Path A (veth-a0-6)..."
ip netns exec "$NS_C" ip link set veth-a0-6 up
ip netns exec "$NS_C" ip addr add 192.168.1.1/24 dev veth-a0-6 2>/dev/null || true

echo "[$(date +%T)] Waiting for path re-creation..."
RECOVERY_PASS=0
for attempt in $(seq 1 4); do
    sleep 5
    V4_OK=0
    V6_OK=0
    if ip netns exec "$NS_C" ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
        V4_OK=1
    fi
    if ip netns exec "$NS_C" ping -6 -c 1 -W 2 fd00:a6::1 >/dev/null 2>&1; then
        V6_OK=1
    fi
    echo "[$(date +%T)] Attempt $attempt: IPv4=$V4_OK IPv6=$V6_OK"
    if [ "$V4_OK" -eq 1 ] && [ "$V6_OK" -eq 1 ]; then
        RECOVERY_PASS=1
        break
    fi
done

if [ "$RECOVERY_PASS" -eq 1 ]; then
    echo ""
    echo "=== Test 5 (Recovery): PASS ==="
else
    echo ""
    echo "=== Test 5 (Recovery): FAIL ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# ==========================================================================
# Summary
# ==========================================================================
echo ""
echo "=========================================="
echo "  Test Summary"
echo "=========================================="
echo "  Test 1 (IPv4 ping):      PASS"
echo "  Test 2 (IPv6 ping):      PASS"
echo "  Test 3 (IPv6 routes):    PASS"
echo "  Test 4 (IPv6 failover):  PASS (${PING_OK}/${PING_TOTAL})"
echo "  Test 5 (Recovery):       PASS"
echo "=========================================="
echo ""
echo "=== All IPv6 multipath tests PASSED ==="
