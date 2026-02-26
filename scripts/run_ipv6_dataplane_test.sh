#!/bin/bash
# run_ipv6_dataplane_test.sh — IPv6 data plane (dual-stack TUN) E2E test
#
# Verifies that mqvpn can carry both IPv4 and IPv6 packets through the tunnel
# when --subnet6 is configured.
#
# Topology:
#   vpn-client-dp              vpn-server-dp               vpn-external-dp
#     veth-c ──────────────── veth-s
#     192.168.50.1/24         192.168.50.2/24
#                              veth-wan-s ─────────────── veth-wan-e
#                              172.16.0.1/24              172.16.0.2/24
#
# Tunnel overlay:
#   IPv4: 10.0.0.0/24  (client .2, server .1)
#   IPv6: fd00:abcd::/112 (client ::2, server ::1)
#
# Usage: sudo ./scripts/run_ipv6_dataplane_test.sh [path-to-mqvpn-binary]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="${1:-${SCRIPT_DIR}/../build/mqvpn}"

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
    -days 365 -nodes -subj "/CN=mqvpn-dp-test" 2>/dev/null

SUBNET="10.0.0.0/24"
SUBNET6="fd00:abcd::/112"
IPTABLES_COMMENT="mqvpn-dp-test:$$"

NS_S="vpn-server-dp"
NS_C="vpn-client-dp"
NS_E="vpn-external-dp"

SERVER_PID=""
CLIENT_PID=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    sleep 1
    # Remove iptables rules from server namespace (best-effort)
    ip netns exec "$NS_S" iptables -t nat -D POSTROUTING -s "$SUBNET" -o veth-wan-s -j MASQUERADE \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec "$NS_S" iptables -D FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec "$NS_S" iptables -D FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    # Remove namespaces
    ip netns del "$NS_S" 2>/dev/null || true
    ip netns del "$NS_C" 2>/dev/null || true
    ip netns del "$NS_E" 2>/dev/null || true
    ip link del veth-c-dp 2>/dev/null || true
    ip link del veth-wan-sdp 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Clean any leftover namespaces from previous runs
ip netns del "$NS_S" 2>/dev/null || true
ip netns del "$NS_C" 2>/dev/null || true
ip netns del "$NS_E" 2>/dev/null || true
ip link del veth-c-dp 2>/dev/null || true
ip link del veth-wan-sdp 2>/dev/null || true

echo "=== Setting up network namespaces (IPv4 underlay) ==="
ip netns add "$NS_S"
ip netns add "$NS_C"
ip netns add "$NS_E"

# veth pair 1: client <-> server (IPv4 underlay)
ip link add veth-c-dp type veth peer name veth-s-dp
ip link set veth-c-dp netns "$NS_C"
ip link set veth-s-dp netns "$NS_S"

ip netns exec "$NS_C" ip addr add 192.168.50.1/24 dev veth-c-dp
ip netns exec "$NS_S" ip addr add 192.168.50.2/24 dev veth-s-dp
ip netns exec "$NS_C" ip link set veth-c-dp up
ip netns exec "$NS_S" ip link set veth-s-dp up
ip netns exec "$NS_C" ip link set lo up
ip netns exec "$NS_S" ip link set lo up

# veth pair 2: server <-> external (IPv4 WAN side)
ip link add veth-wan-sdp type veth peer name veth-wan-edp
ip link set veth-wan-sdp netns "$NS_S"
ip link set veth-wan-edp netns "$NS_E"

ip netns exec "$NS_S" ip addr add 172.16.0.1/24 dev veth-wan-sdp
ip netns exec "$NS_E" ip addr add 172.16.0.2/24 dev veth-wan-edp
ip netns exec "$NS_S" ip link set veth-wan-sdp up
ip netns exec "$NS_E" ip link set veth-wan-edp up
ip netns exec "$NS_E" ip link set lo up

# Routing
ip netns exec "$NS_S" ip route add default via 172.16.0.2 dev veth-wan-sdp
ip netns exec "$NS_C" ip route add default via 192.168.50.2 dev veth-c-dp

# Enable IP forwarding in server namespace
ip netns exec "$NS_S" sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$NS_S" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

# Enable IPv6 in client namespace (may be disabled by default)
ip netns exec "$NS_C" sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
ip netns exec "$NS_S" sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true

# Set up NAT in server namespace
echo "=== Setting up NAT rules in server namespace ==="
ip netns exec "$NS_S" iptables -t nat -A POSTROUTING -s "$SUBNET" -o veth-wan-sdp -j MASQUERADE \
    -m comment --comment "$IPTABLES_COMMENT"
ip netns exec "$NS_S" iptables -I FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
    -m comment --comment "$IPTABLES_COMMENT"
ip netns exec "$NS_S" iptables -I FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
    -m comment --comment "$IPTABLES_COMMENT"

# Verify underlay connectivity
echo "=== Verifying underlay connectivity ==="
ip netns exec "$NS_C" ping -c 1 -W 2 192.168.50.2 >/dev/null
echo "OK: client -> server underlay (IPv4)"
ip netns exec "$NS_S" ping -c 1 -W 1 172.16.0.2 >/dev/null
echo "OK: server -> external WAN"

echo "=== Starting VPN server (with --subnet6) ==="
ip netns exec "$NS_S" "$MQVPN" \
    --mode server \
    --listen "192.168.50.2:4433" \
    --subnet "$SUBNET" \
    --subnet6 "$SUBNET6" \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --log-level debug > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "=== FAIL: Server process died ==="
    cat "${WORK_DIR}/server.log"
    exit 1
fi
echo "Server running (PID $SERVER_PID)"

echo "=== Starting VPN client ==="
ip netns exec "$NS_C" "$MQVPN" \
    --mode client \
    --server "192.168.50.2:4433" \
    --auth-key "$PSK" \
    --insecure \
    --no-reconnect \
    --log-level debug > "${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3

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

echo ""
echo "=== Routes in client namespace ==="
echo "--- IPv4 ---"
ip netns exec "$NS_C" ip route show 2>/dev/null
echo "--- IPv6 ---"
ip netns exec "$NS_C" ip -6 route show 2>/dev/null

# ---- Test 1: IPv4 through tunnel (regression) ----
echo ""
echo "=== Test 1: IPv4 ping through tunnel ==="
if ip netns exec "$NS_C" ping -c 3 -W 2 172.16.0.2; then
    echo ""
    echo "=== Test 1 (IPv4 through tunnel): PASS ==="
else
    echo ""
    echo "=== Test 1 (IPv4 through tunnel): FAIL ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# ---- Test 2: IPv6 through tunnel ----
echo ""
echo "=== Test 2: IPv6 ping through tunnel (fd00:abcd::1) ==="
# Ping the server's tunnel IPv6 address
if ip netns exec "$NS_C" ping -6 -c 3 -W 2 fd00:abcd::1; then
    echo ""
    echo "=== Test 2 (IPv6 through tunnel): PASS ==="
else
    echo ""
    echo "=== Test 2 (IPv6 through tunnel): FAIL ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# ---- Test 3: Verify routes ----
echo ""
echo "=== Test 3: Verify IPv4 and IPv6 routes ==="
FAIL=0

# Check IPv4 catch-all routes
if ip netns exec "$NS_C" ip route show | grep -q "0.0.0.0/1 dev mqvpn0"; then
    echo "OK: IPv4 route 0.0.0.0/1 via mqvpn0"
else
    echo "FAIL: IPv4 route 0.0.0.0/1 not found"
    FAIL=1
fi
if ip netns exec "$NS_C" ip route show | grep -q "128.0.0.0/1 dev mqvpn0"; then
    echo "OK: IPv4 route 128.0.0.0/1 via mqvpn0"
else
    echo "FAIL: IPv4 route 128.0.0.0/1 not found"
    FAIL=1
fi

# Check IPv6 catch-all routes
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

# Check TUN has IPv6 address
if ip netns exec "$NS_C" ip -6 addr show dev mqvpn0 | grep -q "fd00:abcd::2"; then
    echo "OK: Client TUN has IPv6 address fd00:abcd::2"
else
    echo "FAIL: Client TUN missing IPv6 address"
    FAIL=1
fi

if ip netns exec "$NS_S" ip -6 addr show dev mqvpn0 | grep -q "fd00:abcd::1"; then
    echo "OK: Server TUN has IPv6 address fd00:abcd::1"
else
    echo "FAIL: Server TUN missing IPv6 address"
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "=== Test 3 (Routes): FAIL ==="
    exit 1
fi
echo ""
echo "=== Test 3 (Routes): PASS ==="

# ---- Test 4: Verify ADDRESS_ASSIGN in logs ----
echo ""
echo "=== Test 4: Verify ADDRESS_ASSIGN capsules ==="
FAIL=0

if grep -q "ADDRESS_ASSIGN.*10.0.0.2" "${WORK_DIR}/server.log"; then
    echo "OK: Server sent IPv4 ADDRESS_ASSIGN"
else
    echo "FAIL: Server IPv4 ADDRESS_ASSIGN not found in log"
    FAIL=1
fi

if grep -q "ADDRESS_ASSIGN.*fd00:abcd::2" "${WORK_DIR}/server.log"; then
    echo "OK: Server sent IPv6 ADDRESS_ASSIGN"
else
    echo "FAIL: Server IPv6 ADDRESS_ASSIGN not found in log"
    FAIL=1
fi

if grep -q "ADDRESS_ASSIGN.*10.0.0.2" "${WORK_DIR}/client.log"; then
    echo "OK: Client received IPv4 ADDRESS_ASSIGN"
else
    echo "FAIL: Client IPv4 ADDRESS_ASSIGN not found in log"
    FAIL=1
fi

if grep -q "ADDRESS_ASSIGN.*fd00:abcd::2" "${WORK_DIR}/client.log"; then
    echo "OK: Client received IPv6 ADDRESS_ASSIGN"
else
    echo "FAIL: Client IPv6 ADDRESS_ASSIGN not found in log"
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "=== Test 4 (ADDRESS_ASSIGN): FAIL ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo ""
echo "=== Test 4 (ADDRESS_ASSIGN): PASS ==="

echo ""
echo "=== All IPv6 data plane tests PASSED ==="
