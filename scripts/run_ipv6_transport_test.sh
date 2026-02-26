#!/bin/bash
# run_ipv6_transport_test.sh — IPv6 transport (underlay) E2E test
#
# Verifies that mqvpn can use IPv6 for the QUIC underlay while keeping
# the IPv4 data plane intact.  Uses network namespaces with an IPv6
# underlay between client and server, plus an IPv4 WAN segment behind
# the server.
#
# Topology:
#   vpn-client                vpn-server                  vpn-external
#     veth-c ──────────────── veth-s
#     fd00::1/64              fd00::2/64
#                              veth-wan-s ─────────────── veth-wan-e
#                              172.16.0.1/24              172.16.0.2/24
#
# Usage: sudo ./scripts/run_ipv6_transport_test.sh [path-to-mqvpn-binary]

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
    -days 365 -nodes -subj "/CN=mqvpn-ipv6-test" 2>/dev/null

SUBNET="10.0.0.0/24"
IPTABLES_COMMENT="mqvpn-ipv6-test:$$"

SERVER_PID=""
CLIENT_PID=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    sleep 1
    # Remove iptables rules from server namespace (best-effort)
    ip netns exec vpn-server6 iptables -t nat -D POSTROUTING -s "$SUBNET" -o veth-wan-s -j MASQUERADE \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec vpn-server6 iptables -D FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec vpn-server6 iptables -D FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    # Remove namespaces
    ip netns del vpn-server6 2>/dev/null || true
    ip netns del vpn-client6 2>/dev/null || true
    ip netns del vpn-external6 2>/dev/null || true
    ip link del veth-c6 2>/dev/null || true
    ip link del veth-wan-s6 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Clean any leftover namespaces from previous runs
ip netns del vpn-server6 2>/dev/null || true
ip netns del vpn-client6 2>/dev/null || true
ip netns del vpn-external6 2>/dev/null || true
ip link del veth-c6 2>/dev/null || true
ip link del veth-wan-s6 2>/dev/null || true

echo "=== Setting up network namespaces (IPv6 underlay) ==="
ip netns add vpn-server6
ip netns add vpn-client6
ip netns add vpn-external6

# veth pair 1: client <-> server (IPv6 underlay)
ip link add veth-c6 type veth peer name veth-s6
ip link set veth-c6 netns vpn-client6
ip link set veth-s6 netns vpn-server6

# Bring up interfaces and disable DAD before adding addresses
ip netns exec vpn-client6 ip link set veth-c6 up
ip netns exec vpn-server6 ip link set veth-s6 up
ip netns exec vpn-client6 ip link set lo up
ip netns exec vpn-server6 ip link set lo up

ip netns exec vpn-client6 sysctl -w net.ipv6.conf.veth-c6.accept_dad=0 >/dev/null
ip netns exec vpn-server6 sysctl -w net.ipv6.conf.veth-s6.accept_dad=0 >/dev/null

ip netns exec vpn-client6 ip addr add fd00::1/64 dev veth-c6 nodad
ip netns exec vpn-server6 ip addr add fd00::2/64 dev veth-s6 nodad

# veth pair 2: server <-> external (IPv4 WAN side)
ip link add veth-wan-s6 type veth peer name veth-wan-e6
ip link set veth-wan-s6 netns vpn-server6
ip link set veth-wan-e6 netns vpn-external6

ip netns exec vpn-server6 ip addr add 172.16.0.1/24 dev veth-wan-s6
ip netns exec vpn-external6 ip addr add 172.16.0.2/24 dev veth-wan-e6
ip netns exec vpn-server6 ip link set veth-wan-s6 up
ip netns exec vpn-external6 ip link set veth-wan-e6 up
ip netns exec vpn-external6 ip link set lo up

# Routing
# server: IPv4 default route via WAN
ip netns exec vpn-server6 ip route add default via 172.16.0.2 dev veth-wan-s6
# client: IPv6 default route via server (underlay)
ip netns exec vpn-client6 ip -6 route add default via fd00::2 dev veth-c6

# Enable IP forwarding in server namespace (both v4 and v6)
ip netns exec vpn-server6 sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec vpn-server6 sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

# Set up NAT in server namespace (IPv4 data plane masquerade)
echo "=== Setting up NAT rules in server namespace ==="
ip netns exec vpn-server6 iptables -t nat -A POSTROUTING -s "$SUBNET" -o veth-wan-s6 -j MASQUERADE \
    -m comment --comment "$IPTABLES_COMMENT"
ip netns exec vpn-server6 iptables -I FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
    -m comment --comment "$IPTABLES_COMMENT"
ip netns exec vpn-server6 iptables -I FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
    -m comment --comment "$IPTABLES_COMMENT"

# Wait for IPv6 neighbor discovery
sleep 1

# Verify underlay connectivity
echo "=== Verifying underlay connectivity ==="
ip netns exec vpn-client6 ping -6 -c 1 -W 2 fd00::2 >/dev/null
echo "OK: client -> server underlay (IPv6)"
ip netns exec vpn-server6 ping -c 1 -W 1 172.16.0.2 >/dev/null
echo "OK: server -> external WAN (IPv4)"

echo "=== Starting VPN server (listening on [fd00::2]:4433) ==="
ip netns exec vpn-server6 "$MQVPN" \
    --mode server \
    --listen "[fd00::2]:4433" \
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

echo "=== Starting VPN client (connecting to [fd00::2]:4433) ==="
ip netns exec vpn-client6 "$MQVPN" \
    --mode client \
    --server "[fd00::2]:4433" \
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

# Show TUN devices and routes
echo ""
echo "=== TUN devices ==="
ip netns exec vpn-server6 ip addr show dev mqvpn0 2>/dev/null || echo "(server TUN not found)"
ip netns exec vpn-client6 ip addr show dev mqvpn0 2>/dev/null || echo "(client TUN not found)"

echo ""
echo "=== Routes in client namespace ==="
ip netns exec vpn-client6 ip route show 2>/dev/null
echo ""
ip netns exec vpn-client6 ip -6 route show 2>/dev/null

echo ""
echo "=== Test 1: Ping through IPv6 QUIC tunnel to IPv4 WAN ==="
if ip netns exec vpn-client6 ping -c 3 -W 2 172.16.0.2; then
    echo ""
    echo "=== Test 1 (Ping through IPv6 tunnel): PASS ==="
else
    echo ""
    echo "=== Test 1 (Ping through IPv6 tunnel): FAIL ==="
    echo ""
    echo "--- Server log ---"
    cat "${WORK_DIR}/server.log"
    echo ""
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

echo ""
echo "=== Test 2: iptables NAT rules ==="
FAIL=0

# Check MASQUERADE rule exists and has packet count > 0
MASQ_PKTS=$(ip netns exec vpn-server6 iptables -t nat -L POSTROUTING -v -n 2>/dev/null \
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
FWD_LINES=$(ip netns exec vpn-server6 iptables -L FORWARD -v -n 2>/dev/null \
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
    ip netns exec vpn-server6 iptables -t nat -L -v -n 2>/dev/null
    echo ""
    echo "--- iptables filter ---"
    ip netns exec vpn-server6 iptables -L -v -n 2>/dev/null
    exit 1
fi
echo ""
echo "=== Test 2 (iptables rules): PASS ==="

echo ""
echo "=== All IPv6 transport tests PASSED ==="
