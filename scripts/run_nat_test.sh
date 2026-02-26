#!/bin/bash
# run_nat_test.sh — NAT/WAN E2E test using network namespaces
#
# Creates three netns (vpn-client, vpn-server, vpn-external) with two veth
# pairs, runs mqvpn server and client, and verifies NAT connectivity.
#
# Topology:
#   vpn-client                vpn-server                  vpn-external
#     veth-c ──────────────── veth-s
#     192.168.100.1/24        192.168.100.2/24
#                              veth-wan-s ─────────────── veth-wan-e
#                              172.16.0.1/24              172.16.0.2/24
#
# Usage: sudo ./scripts/run_nat_test.sh [path-to-mqvpn-binary]

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
    -days 365 -nodes -subj "/CN=mqvpn-nat-test" 2>/dev/null

SUBNET="10.0.0.0/24"
IPTABLES_COMMENT="mqvpn-nat-test:$$"

SERVER_PID=""
CLIENT_PID=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    sleep 1
    # Remove iptables rules from server namespace (best-effort)
    ip netns exec vpn-server iptables -t nat -D POSTROUTING -s "$SUBNET" -o veth-wan-s -j MASQUERADE \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec vpn-server iptables -D FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec vpn-server iptables -D FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    # Remove namespaces
    ip netns del vpn-server 2>/dev/null || true
    ip netns del vpn-client 2>/dev/null || true
    ip netns del vpn-external 2>/dev/null || true
    ip link del veth-c 2>/dev/null || true
    ip link del veth-wan-s 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Clean any leftover namespaces from previous runs
ip netns del vpn-server 2>/dev/null || true
ip netns del vpn-client 2>/dev/null || true
ip netns del vpn-external 2>/dev/null || true
ip link del veth-c 2>/dev/null || true
ip link del veth-wan-s 2>/dev/null || true

echo "=== Setting up network namespaces ==="
ip netns add vpn-server
ip netns add vpn-client
ip netns add vpn-external

# veth pair 1: client <-> server (underlay)
ip link add veth-c type veth peer name veth-s
ip link set veth-c netns vpn-client
ip link set veth-s netns vpn-server

ip netns exec vpn-client ip addr add 192.168.100.1/24 dev veth-c
ip netns exec vpn-server ip addr add 192.168.100.2/24 dev veth-s
ip netns exec vpn-client ip link set veth-c up
ip netns exec vpn-server ip link set veth-s up
ip netns exec vpn-client ip link set lo up
ip netns exec vpn-server ip link set lo up

# veth pair 2: server <-> external (WAN side)
ip link add veth-wan-s type veth peer name veth-wan-e
ip link set veth-wan-s netns vpn-server
ip link set veth-wan-e netns vpn-external

ip netns exec vpn-server ip addr add 172.16.0.1/24 dev veth-wan-s
ip netns exec vpn-external ip addr add 172.16.0.2/24 dev veth-wan-e
ip netns exec vpn-server ip link set veth-wan-s up
ip netns exec vpn-external ip link set veth-wan-e up
ip netns exec vpn-external ip link set lo up

# Routing
# server: default route via WAN so that `ip route get 8.8.8.8` returns veth-wan-s
ip netns exec vpn-server ip route add default via 172.16.0.2 dev veth-wan-s
# client: default route via server (underlay)
ip netns exec vpn-client ip route add default via 192.168.100.2 dev veth-c

# Enable IP forwarding in server namespace
ip netns exec vpn-server sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Set up NAT in server namespace (same rules as start_server.sh)
echo "=== Setting up NAT rules in server namespace ==="
ip netns exec vpn-server iptables -t nat -A POSTROUTING -s "$SUBNET" -o veth-wan-s -j MASQUERADE \
    -m comment --comment "$IPTABLES_COMMENT"
ip netns exec vpn-server iptables -I FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
    -m comment --comment "$IPTABLES_COMMENT"
ip netns exec vpn-server iptables -I FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
    -m comment --comment "$IPTABLES_COMMENT"

# Verify underlay connectivity
echo "=== Verifying underlay connectivity ==="
ip netns exec vpn-client ping -c 1 -W 1 192.168.100.2 >/dev/null
echo "OK: client -> server underlay"
ip netns exec vpn-server ping -c 1 -W 1 172.16.0.2 >/dev/null
echo "OK: server -> external WAN"

echo "=== Starting VPN server ==="
ip netns exec vpn-server "$MQVPN" \
    --mode server \
    --listen 192.168.100.2:4433 \
    --subnet "$SUBNET" \
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
ip netns exec vpn-client "$MQVPN" \
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

# Show TUN devices and routes
echo ""
echo "=== TUN devices ==="
ip netns exec vpn-server ip addr show dev mqvpn0 2>/dev/null || echo "(server TUN not found)"
ip netns exec vpn-client ip addr show dev mqvpn0 2>/dev/null || echo "(client TUN not found)"

echo ""
echo "=== Routes in client namespace ==="
ip netns exec vpn-client ip route show 2>/dev/null

echo ""
echo "=== Test 1: Ping through NAT ==="
if ip netns exec vpn-client ping -c 3 -W 2 172.16.0.2; then
    echo ""
    echo "=== Test 1 (Ping through NAT): PASS ==="
else
    echo ""
    echo "=== Test 1 (Ping through NAT): FAIL ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

echo ""
echo "=== Test 2: iptables rules ==="
FAIL=0

# Check MASQUERADE rule exists and has packet count > 0
MASQ_PKTS=$(ip netns exec vpn-server iptables -t nat -L POSTROUTING -v -n 2>/dev/null \
    | grep "$IPTABLES_COMMENT" | awk '{print $1}')
if [ -z "$MASQ_PKTS" ]; then
    echo "FAIL: MASQUERADE rule not found"
    FAIL=1
elif [ "$MASQ_PKTS" -eq 0 ] 2>/dev/null; then
    echo "FAIL: MASQUERADE rule has 0 packets"
    FAIL=1
else
    echo "OK: MASQUERADE rule present (${MASQ_PKTS} packets)"
fi

# Check FORWARD rules exist and have packet count > 0
FWD_LINES=$(ip netns exec vpn-server iptables -L FORWARD -v -n 2>/dev/null \
    | grep "$IPTABLES_COMMENT")
FWD_COUNT=$(echo "$FWD_LINES" | wc -l)
if [ "$FWD_COUNT" -lt 2 ]; then
    echo "FAIL: Expected 2 FORWARD rules, found $FWD_COUNT"
    FAIL=1
else
    FWD_PKTS_TOTAL=0
    while IFS= read -r line; do
        pkts=$(echo "$line" | awk '{print $1}')
        FWD_PKTS_TOTAL=$((FWD_PKTS_TOTAL + pkts))
    done <<< "$FWD_LINES"
    if [ "$FWD_PKTS_TOTAL" -eq 0 ]; then
        echo "FAIL: FORWARD rules have 0 total packets"
        FAIL=1
    else
        echo "OK: FORWARD rules present (${FWD_PKTS_TOTAL} total packets)"
    fi
fi

if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "=== Test 2 (iptables rules): FAIL ==="
    echo ""
    echo "--- iptables nat ---"
    ip netns exec vpn-server iptables -t nat -L -v -n 2>/dev/null
    echo ""
    echo "--- iptables filter ---"
    ip netns exec vpn-server iptables -L -v -n 2>/dev/null
    exit 1
fi
echo ""
echo "=== Test 2 (iptables rules): PASS ==="
