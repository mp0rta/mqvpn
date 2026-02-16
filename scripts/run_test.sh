#!/bin/bash
# run_test.sh — Quick smoke test using network namespaces
#
# Creates two netns (vpn-client, vpn-server), runs mpvpn server and client,
# and verifies connectivity with ping.
#
# Usage: sudo ./run_test.sh [path-to-mpvpn-binary]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MPVPN="${1:-${SCRIPT_DIR}/../build/mpvpn}"

if [ ! -f "$MPVPN" ]; then
    echo "error: mpvpn binary not found at $MPVPN"
    echo "Build first: mkdir build && cd build && cmake .. && make"
    exit 1
fi

MPVPN="$(realpath "$MPVPN")"
WORK_DIR="$(mktemp -d)"

# Generate self-signed cert
echo "Generating self-signed certificate..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mpvpn-test" 2>/dev/null

cleanup() {
    echo ""
    echo "Cleaning up..."
    kill "$SERVER_PID" 2>/dev/null || true
    kill "$CLIENT_PID" 2>/dev/null || true
    sleep 1
    ip netns del vpn-server 2>/dev/null || true
    ip netns del vpn-client 2>/dev/null || true
    ip link del veth-c 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Clean any leftover namespaces from previous runs
ip netns del vpn-server 2>/dev/null || true
ip netns del vpn-client 2>/dev/null || true
ip link del veth-c 2>/dev/null || true

echo "=== Setting up network namespaces ==="
ip netns add vpn-server
ip netns add vpn-client

ip link add veth-c type veth peer name veth-s
ip link set veth-c netns vpn-client
ip link set veth-s netns vpn-server

ip netns exec vpn-client ip addr add 192.168.100.1/24 dev veth-c
ip netns exec vpn-server ip addr add 192.168.100.2/24 dev veth-s
ip netns exec vpn-client ip link set veth-c up
ip netns exec vpn-server ip link set veth-s up
ip netns exec vpn-client ip link set lo up
ip netns exec vpn-server ip link set lo up

# Enable IP forwarding in server namespace
ip netns exec vpn-server sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Verify underlay connectivity
echo "=== Verifying underlay connectivity ==="
ip netns exec vpn-client ping -c 1 -W 1 192.168.100.2 >/dev/null
echo "OK: underlay veth pair working"

echo "=== Starting VPN server ==="
ip netns exec vpn-server "$MPVPN" \
    --mode server \
    --listen 192.168.100.2:4433 \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --log-level debug &
SERVER_PID=$!
sleep 2

# Check server is still running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "=== FAIL: Server process died ==="
    wait "$SERVER_PID" 2>/dev/null || true
    exit 1
fi
echo "Server running (PID $SERVER_PID)"

echo "=== Starting VPN client ==="
ip netns exec vpn-client "$MPVPN" \
    --mode client \
    --server 192.168.100.2:4433 \
    --insecure \
    --log-level debug &
CLIENT_PID=$!
sleep 3

# Check client is still running
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "=== FAIL: Client process died ==="
    wait "$CLIENT_PID" 2>/dev/null || true
    exit 1
fi
echo "Client running (PID $CLIENT_PID)"

# Show TUN devices
echo ""
echo "=== TUN devices ==="
ip netns exec vpn-server ip addr show dev mpvpn0 2>/dev/null || echo "(server TUN not found)"
ip netns exec vpn-client ip addr show dev mpvpn0 2>/dev/null || echo "(client TUN not found)"

echo ""
echo "=== Routes in client namespace ==="
ip netns exec vpn-client ip route show 2>/dev/null

echo ""
echo "=== Testing connectivity ==="
if ip netns exec vpn-client ping -c 3 -W 2 10.0.0.1; then
    echo ""
    echo "=== PASS: VPN tunnel is working ==="
else
    echo ""
    echo "=== FAIL: Could not ping through VPN tunnel ==="
    exit 1
fi
