#!/bin/bash
# run_test.sh — Quick smoke test using network namespaces
#
# Creates two netns (vpn-client, vpn-server), runs mqvpn server and client,
# and verifies connectivity with ping.
#
# Usage: sudo ./run_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

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
    -days 365 -nodes -subj "/CN=mqvpn-test" 2>/dev/null

CLIENT_STRICT_PID=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    kill "$CLIENT_STRICT_PID" 2>/dev/null || true
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
ip netns exec vpn-server "$MQVPN" \
    --mode server \
    --listen 192.168.100.2:4433 \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

# Check server is still running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "=== FAIL: Server process died ==="
    cat "${WORK_DIR}/server.log"
    exit 1
fi
echo "Server running (PID $SERVER_PID)"

echo "=== Starting VPN client ==="
ip netns exec vpn-client "$MQVPN" \
    --mode client \
    --server 192.168.100.2:4433 \
    --auth-key "$PSK" \
    --insecure \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3

# Check client is still running
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
ip netns exec vpn-server ip addr show dev mqvpn0 2>/dev/null || echo "(server TUN not found)"
ip netns exec vpn-client ip addr show dev mqvpn0 2>/dev/null || echo "(client TUN not found)"

echo ""
echo "=== Routes in client namespace ==="
ip netns exec vpn-client ip route show 2>/dev/null

echo ""
echo "=== Test 1: Connectivity (--insecure) ==="
if ip netns exec vpn-client ping -c 3 -W 2 10.0.0.1; then
    echo ""
    echo "=== PASS: VPN tunnel is working ==="
else
    echo ""
    echo "=== FAIL: Could not ping through VPN tunnel ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# Stop client for next test
kill "$CLIENT_PID" 2>/dev/null || true
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""
sleep 2

echo ""
echo "=== Test 2: Self-signed cert rejected without --insecure ==="
ip netns exec vpn-client "$MQVPN" \
    --mode client \
    --server 192.168.100.2:4433 \
    --auth-key "$PSK" \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/client_strict.log" 2>&1 &
CLIENT_STRICT_PID=$!

# Wait for connection attempt — client should fail and exit
sleep 5

if kill -0 "$CLIENT_STRICT_PID" 2>/dev/null; then
    # Still running — check if tunnel came up (it shouldn't)
    if ip netns exec vpn-client ip addr show dev mqvpn0 >/dev/null 2>&1; then
        echo "=== FAIL: Self-signed cert was accepted without --insecure ==="
        kill "$CLIENT_STRICT_PID" 2>/dev/null || true
        wait "$CLIENT_STRICT_PID" 2>/dev/null || true
        echo ""
        echo "--- Server log ---"
        cat "${WORK_DIR}/server.log"
        echo ""
        echo "--- Client strict log ---"
        cat "${WORK_DIR}/client_strict.log"
        exit 1
    else
        echo "OK: Client running but no tunnel (cert rejected)"
        kill "$CLIENT_STRICT_PID" 2>/dev/null || true
        wait "$CLIENT_STRICT_PID" 2>/dev/null || true
    fi
else
    wait "$CLIENT_STRICT_PID" 2>/dev/null || true
    echo "OK: Client exited (self-signed cert rejected)"
fi

if grep -q "certificate verification failed\|cert.*fail\|TLS.*fail" "${WORK_DIR}/client_strict.log" 2>/dev/null; then
    echo "OK: Certificate rejection message found in log"
fi
echo "=== PASS: Self-signed cert correctly rejected without --insecure ==="
