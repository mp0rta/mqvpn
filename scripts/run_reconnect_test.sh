#!/bin/bash
# run_reconnect_test.sh — Automatic reconnection E2E test
#
# Verifies that the client automatically reconnects after the server
# is killed and restarted.
#
# Topology (same as run_nat_test.sh):
#   vpn-client                vpn-server                  vpn-external
#     veth-c ──────────────── veth-s
#     192.168.100.1/24        192.168.100.2/24
#                              veth-wan-s ─────────────── veth-wan-e
#                              172.16.0.1/24              172.16.0.2/24
#
# Test steps:
#   1. Connect client to server, verify tunnel ping
#   2. Kill server, wait for client to detect disconnect
#   3. Restart server, wait for client to reconnect
#   4. Verify tunnel ping works again
#
# Usage: sudo ./scripts/run_reconnect_test.sh [path-to-mqvpn-binary]

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
    -days 365 -nodes -subj "/CN=mqvpn-reconn-test" 2>/dev/null

SUBNET="10.0.0.0/24"
IPTABLES_COMMENT="mqvpn-reconn-test:$$"
NS_SVR="vpn-server-rc"
NS_CLI="vpn-client-rc"
NS_EXT="vpn-external-rc"

SERVER_PID=""
CLIENT_PID=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    sleep 1
    # Remove iptables rules from server namespace (best-effort)
    ip netns exec "$NS_SVR" iptables -t nat -D POSTROUTING -s "$SUBNET" -o veth-wan-s -j MASQUERADE \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec "$NS_SVR" iptables -D FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec "$NS_SVR" iptables -D FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    # Remove namespaces
    ip netns del "$NS_SVR" 2>/dev/null || true
    ip netns del "$NS_CLI" 2>/dev/null || true
    ip netns del "$NS_EXT" 2>/dev/null || true
    ip link del veth-c 2>/dev/null || true
    ip link del veth-wan-s 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Clean any leftover namespaces from previous runs
ip netns del "$NS_SVR" 2>/dev/null || true
ip netns del "$NS_CLI" 2>/dev/null || true
ip netns del "$NS_EXT" 2>/dev/null || true
ip link del veth-c 2>/dev/null || true
ip link del veth-wan-s 2>/dev/null || true

echo "=== Setting up network namespaces ==="
ip netns add "$NS_SVR"
ip netns add "$NS_CLI"
ip netns add "$NS_EXT"

# veth pair 1: client <-> server (underlay)
ip link add veth-c type veth peer name veth-s
ip link set veth-c netns "$NS_CLI"
ip link set veth-s netns "$NS_SVR"

ip netns exec "$NS_CLI" ip addr add 192.168.100.1/24 dev veth-c
ip netns exec "$NS_SVR" ip addr add 192.168.100.2/24 dev veth-s
ip netns exec "$NS_CLI" ip link set veth-c up
ip netns exec "$NS_SVR" ip link set veth-s up
ip netns exec "$NS_CLI" ip link set lo up
ip netns exec "$NS_SVR" ip link set lo up

# veth pair 2: server <-> external (WAN side)
ip link add veth-wan-s type veth peer name veth-wan-e
ip link set veth-wan-s netns "$NS_SVR"
ip link set veth-wan-e netns "$NS_EXT"

ip netns exec "$NS_SVR" ip addr add 172.16.0.1/24 dev veth-wan-s
ip netns exec "$NS_EXT" ip addr add 172.16.0.2/24 dev veth-wan-e
ip netns exec "$NS_SVR" ip link set veth-wan-s up
ip netns exec "$NS_EXT" ip link set veth-wan-e up
ip netns exec "$NS_EXT" ip link set lo up

# Routing
ip netns exec "$NS_SVR" ip route add default via 172.16.0.2 dev veth-wan-s
ip netns exec "$NS_CLI" ip route add default via 192.168.100.2 dev veth-c

# Enable IP forwarding in server namespace
ip netns exec "$NS_SVR" sysctl -w net.ipv4.ip_forward=1 >/dev/null

setup_nat() {
    ip netns exec "$NS_SVR" iptables -t nat -A POSTROUTING -s "$SUBNET" -o veth-wan-s -j MASQUERADE \
        -m comment --comment "$IPTABLES_COMMENT"
    ip netns exec "$NS_SVR" iptables -I FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT"
    ip netns exec "$NS_SVR" iptables -I FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT"
}

cleanup_nat() {
    ip netns exec "$NS_SVR" iptables -t nat -D POSTROUTING -s "$SUBNET" -o veth-wan-s -j MASQUERADE \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec "$NS_SVR" iptables -D FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec "$NS_SVR" iptables -D FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
}

start_server() {
    local log_suffix="${1:-}"
    ip netns exec "$NS_SVR" "$MQVPN" \
        --mode server \
        --listen 192.168.100.2:4433 \
        --subnet "$SUBNET" \
        --cert "${WORK_DIR}/server.crt" \
        --key "${WORK_DIR}/server.key" \
        --auth-key "$PSK" \
        --log-level debug > "${WORK_DIR}/server${log_suffix}.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: Server process died"
        cat "${WORK_DIR}/server${log_suffix}.log"
        exit 1
    fi
    echo "Server running (PID $SERVER_PID)"
}

# ---- Phase 1: Initial connection ----

echo "=== Setting up NAT rules ==="
setup_nat

echo "=== Verifying underlay connectivity ==="
ip netns exec "$NS_CLI" ping -c 1 -W 1 192.168.100.2 >/dev/null
echo "OK: client -> server underlay"

echo "=== Starting VPN server ==="
start_server ""

echo "=== Starting VPN client (reconnect enabled) ==="
ip netns exec "$NS_CLI" "$MQVPN" \
    --mode client \
    --server 192.168.100.2:4433 \
    --auth-key "$PSK" \
    --insecure \
    --log-level debug > "${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "=== FAIL: Client process died ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "Client running (PID $CLIENT_PID)"

echo ""
echo "=== Test 1: Initial tunnel ping ==="
if ip netns exec "$NS_CLI" ping -c 3 -W 2 172.16.0.2; then
    echo ""
    echo "=== Test 1 (Initial tunnel ping): PASS ==="
else
    echo ""
    echo "=== Test 1 (Initial tunnel ping): FAIL ==="
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# ---- Phase 2: Kill server ----

echo ""
echo "=== Test 2: Kill server, verify client stays alive ==="
echo "Killing server (PID $SERVER_PID)..."
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
cleanup_nat

echo "Waiting for client to detect disconnect..."
sleep 5

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "=== Test 2 (Client stays alive): FAIL — client exited ==="
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: client still running (waiting to reconnect)"

# Verify client log shows reconnection attempt
if grep -q "reconnecting in" "${WORK_DIR}/client.log"; then
    echo "OK: client log shows reconnection scheduling"
else
    echo "WARN: no 'reconnecting in' found in client log yet"
fi
echo ""
echo "=== Test 2 (Client stays alive): PASS ==="

# ---- Phase 3: Restart server, verify reconnection ----

echo ""
echo "=== Test 3: Restart server, verify reconnection ==="
setup_nat

echo "Restarting VPN server..."
start_server "_2"

echo "Waiting for client to reconnect..."
# Reconnect interval is 5s base, first attempt should happen quickly
# Wait up to 15s for reconnection
RECONN_OK=0
for i in $(seq 1 15); do
    if ip netns exec "$NS_CLI" ping -c 1 -W 1 172.16.0.2 >/dev/null 2>&1; then
        RECONN_OK=1
        echo "Tunnel restored after ~${i}s"
        break
    fi
    sleep 1
done

if [ "$RECONN_OK" -eq 0 ]; then
    echo "=== Test 3 (Reconnection): FAIL — tunnel not restored after 15s ==="
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    echo ""
    echo "--- Server log (restart) ---"
    cat "${WORK_DIR}/server_2.log"
    exit 1
fi

echo ""
echo "=== Test 3 (Reconnection): PASS ==="

# ---- Phase 4: Full tunnel verification after reconnect ----

echo ""
echo "=== Test 4: Sustained ping after reconnection ==="
if ip netns exec "$NS_CLI" ping -c 5 -W 2 172.16.0.2; then
    echo ""
    echo "=== Test 4 (Sustained ping): PASS ==="
else
    echo ""
    echo "=== Test 4 (Sustained ping): FAIL ==="
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

echo ""
echo "=== All reconnection tests PASSED ==="
