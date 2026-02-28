#!/bin/bash
# run_ipv6_full_multipath_test.sh — Full IPv6 (underlay + data plane) multipath E2E test
#
# Verifies that mqvpn works with IPv6 QUIC transport AND IPv6 tunnel data plane
# over multipath QUIC, including failover.
#
# Topology:
#   mp6f-client                              mp6f-server
#     veth-a0-6f ──────────────── veth-a1-6f   (Path A: fd00:a::1/64 ↔ fd00:a::2/64)
#     veth-b0-6f ──────────────── veth-b1-6f   (Path B: fd00:b::1/64 ↔ fd00:b::2/64)
#
#   Server VPN address: fd00:ff::1/128 on lo (reachable from both paths)
#   Client per-device routes to fd00:ff::1 via veth-a0-6f and veth-b0-6f
#
# Tunnel overlay:
#   IPv4: 10.0.0.0/24     (server .1, client .2)
#   IPv6: fd00:b6::/112   (server ::1, client ::2)
#
# Usage: sudo ./scripts/run_ipv6_full_multipath_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

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
    -days 365 -nodes -subj "/CN=mqvpn-mp6f-test" 2>/dev/null

SUBNET="10.0.0.0/24"
SUBNET6="fd00:b6::/112"

NS_S="mp6f-server"
NS_C="mp6f-client"

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
    ip link del veth-a0-6f 2>/dev/null || true
    ip link del veth-b0-6f 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Clean any leftover namespaces from previous runs
ip netns del "$NS_S" 2>/dev/null || true
ip netns del "$NS_C" 2>/dev/null || true
ip link del veth-a0-6f 2>/dev/null || true
ip link del veth-b0-6f 2>/dev/null || true

echo "=== Setting up network namespaces (2 IPv6 paths) ==="
ip netns add "$NS_S"
ip netns add "$NS_C"

# Path A: veth pair (IPv6 underlay fd00:a::/64)
ip link add veth-a0-6f type veth peer name veth-a1-6f
ip link set veth-a0-6f netns "$NS_C"
ip link set veth-a1-6f netns "$NS_S"
ip netns exec "$NS_C" ip link set veth-a0-6f up
ip netns exec "$NS_S" ip link set veth-a1-6f up

# Disable DAD for fast address assignment
ip netns exec "$NS_C" sysctl -w net.ipv6.conf.veth-a0-6f.accept_dad=0 >/dev/null
ip netns exec "$NS_S" sysctl -w net.ipv6.conf.veth-a1-6f.accept_dad=0 >/dev/null

ip netns exec "$NS_C" ip addr add fd00:a::1/64 dev veth-a0-6f nodad
ip netns exec "$NS_S" ip addr add fd00:a::2/64 dev veth-a1-6f nodad

# Path B: second veth pair (IPv6 underlay fd00:b::/64)
ip link add veth-b0-6f type veth peer name veth-b1-6f
ip link set veth-b0-6f netns "$NS_C"
ip link set veth-b1-6f netns "$NS_S"
ip netns exec "$NS_C" ip link set veth-b0-6f up
ip netns exec "$NS_S" ip link set veth-b1-6f up

ip netns exec "$NS_C" sysctl -w net.ipv6.conf.veth-b0-6f.accept_dad=0 >/dev/null
ip netns exec "$NS_S" sysctl -w net.ipv6.conf.veth-b1-6f.accept_dad=0 >/dev/null

ip netns exec "$NS_C" ip addr add fd00:b::1/64 dev veth-b0-6f nodad
ip netns exec "$NS_S" ip addr add fd00:b::2/64 dev veth-b1-6f nodad

# Loopback
ip netns exec "$NS_C" ip link set lo up
ip netns exec "$NS_S" ip link set lo up

# Enable IPv6 forwarding
ip netns exec "$NS_S" sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$NS_S" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
ip netns exec "$NS_C" sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
ip netns exec "$NS_S" sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true

# Server VPN address on loopback — reachable from both paths.
# IPv6 + SO_BINDTODEVICE requires a route to the server address on each
# bound device. Using a loopback address with per-device routes solves this.
ip netns exec "$NS_S" sysctl -w net.ipv6.conf.lo.accept_dad=0 >/dev/null
ip netns exec "$NS_S" ip -6 addr add fd00:ff::1/128 dev lo nodad

# Server-side routes: return traffic reaches fd00:ff::1 via loopback (already there),
# and each veth can reach the client-side subnets (already there via connected routes).

# Client per-device routes so SO_BINDTODEVICE sockets can reach fd00:ff::1
ip netns exec "$NS_C" ip -6 route add fd00:ff::1/128 via fd00:a::2 dev veth-a0-6f metric 100
ip netns exec "$NS_C" ip -6 route add fd00:ff::1/128 via fd00:b::2 dev veth-b0-6f metric 200

# Server-side return routes to client via both paths
ip netns exec "$NS_S" ip -6 route add fd00:a::1/128 dev veth-a1-6f metric 100
ip netns exec "$NS_S" ip -6 route add fd00:b::1/128 dev veth-b1-6f metric 100

sleep 1

# Verify underlay connectivity
echo "=== Verifying underlay connectivity ==="
ip netns exec "$NS_C" ping -6 -c 1 -W 2 fd00:a::2 >/dev/null
echo "OK: Path A (fd00:a::x) working"
ip netns exec "$NS_C" ping -6 -c 1 -W 2 fd00:b::2 >/dev/null
echo "OK: Path B (fd00:b::x) working"
ip netns exec "$NS_C" ping -6 -c 1 -W 2 fd00:ff::1 >/dev/null
echo "OK: Server VPN address (fd00:ff::1) reachable"

echo "=== Starting VPN server (IPv6 listen + multipath + dual-stack tunnel) ==="
ip netns exec "$NS_S" "$MQVPN" \
    --mode server \
    --listen "[fd00:ff::1]:4433" \
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

echo "=== Starting VPN client (IPv6 server + 2 paths) ==="
ip netns exec "$NS_C" "$MQVPN" \
    --mode client \
    --server "[fd00:ff::1]:4433" \
    --path veth-a0-6f --path veth-b0-6f \
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
# Test 1: IPv4 ping through IPv6 multipath tunnel
# ==========================================================================
echo ""
echo "=== Test 1: IPv4 ping through IPv6 multipath tunnel ==="
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
# Test 2: IPv6 ping through IPv6 multipath tunnel
# ==========================================================================
echo ""
echo "=== Test 2: IPv6 tunnel ping through IPv6 multipath transport (fd00:b6::1) ==="
if ip netns exec "$NS_C" ping -6 -c 3 -W 2 fd00:b6::1; then
    echo ""
    echo "=== Test 2 (IPv6 tunnel ping): PASS ==="
else
    echo ""
    echo "=== Test 2 (IPv6 tunnel ping): FAIL ==="
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
echo "=== Test 3: Verify IPv6 tunnel routes and addresses ==="
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

if ip netns exec "$NS_C" ip -6 addr show dev mqvpn0 | grep -q "fd00:b6::2"; then
    echo "OK: Client TUN has IPv6 address fd00:b6::2"
else
    echo "FAIL: Client TUN missing IPv6 address"
    FAIL=1
fi

if ip netns exec "$NS_S" ip -6 addr show dev mqvpn0 | grep -q "fd00:b6::1"; then
    echo "OK: Server TUN has IPv6 address fd00:b6::1"
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
# Test 4: IPv6 failover — bring down Path A, verify IPv6 tunnel continues
# ==========================================================================
echo ""
echo "=== Test 4: IPv6 failover (Path A down) ==="

echo "[$(date +%T)] Bringing DOWN Path A (veth-a0-6f)..."
ip netns exec "$NS_C" ip link set veth-a0-6f down

sleep 3

echo "[$(date +%T)] Pinging IPv6 tunnel (Path B only)..."
PING_OK=0
PING_TOTAL=10
for i in $(seq 1 $PING_TOTAL); do
    if ip netns exec "$NS_C" ping -6 -c 1 -W 2 fd00:b6::1 >/dev/null 2>&1; then
        PING_OK=$((PING_OK + 1))
    fi
done
echo "[$(date +%T)] IPv6 tunnel ping: ${PING_OK}/${PING_TOTAL} succeeded"

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

# Also check IPv4 tunnel works on Path B
echo ""
echo "--- IPv4 tunnel check during failover ---"
if ip netns exec "$NS_C" ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "OK: IPv4 tunnel also working on Path B"
else
    echo "WARN: IPv4 tunnel ping failed during failover (non-fatal)"
fi

# ==========================================================================
# Test 5: Path recovery
# ==========================================================================
echo ""
echo "=== Test 5: Path recovery (bring Path A back up) ==="

echo "[$(date +%T)] Bringing UP Path A (veth-a0-6f)..."
ip netns exec "$NS_C" ip link set veth-a0-6f up
ip netns exec "$NS_C" sysctl -w net.ipv6.conf.veth-a0-6f.accept_dad=0 >/dev/null
ip netns exec "$NS_C" ip addr add fd00:a::1/64 dev veth-a0-6f nodad 2>/dev/null || true
ip netns exec "$NS_C" ip -6 route add fd00:ff::1/128 via fd00:a::2 dev veth-a0-6f metric 100 2>/dev/null || true

echo "[$(date +%T)] Waiting for path re-creation..."
RECOVERY_PASS=0
for attempt in $(seq 1 4); do
    sleep 5
    V4_OK=0
    V6_OK=0
    if ip netns exec "$NS_C" ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
        V4_OK=1
    fi
    if ip netns exec "$NS_C" ping -6 -c 1 -W 2 fd00:b6::1 >/dev/null 2>&1; then
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
echo "  Test Summary (IPv6 underlay + tunnel + multipath)"
echo "=========================================="
echo "  Test 1 (IPv4 tunnel ping):   PASS"
echo "  Test 2 (IPv6 tunnel ping):   PASS"
echo "  Test 3 (IPv6 routes):        PASS"
echo "  Test 4 (IPv6 failover):      PASS (${PING_OK}/${PING_TOTAL})"
echo "  Test 5 (Recovery):           PASS"
echo "=========================================="
echo ""
echo "=== All IPv6 full-stack multipath tests PASSED ==="
