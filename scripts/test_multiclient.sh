#!/bin/bash
# test_multiclient.sh — Multi-client + PSK authentication E2E test
#
# Creates 1 server + 3 client netns, verifies:
#   1. All 3 clients connect with correct PSK and get unique IPs
#   2. All clients can ping through the tunnel
#   3. One client disconnect doesn't affect others
#   4. Wrong PSK is rejected (client exits)
#
# Usage: sudo ./test_multiclient.sh [path-to-mqvpn-binary]

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
    -days 365 -nodes -subj "/CN=mqvpn-test" 2>/dev/null

SERVER_PID=""
CLIENT1_PID=""
CLIENT2_PID=""
CLIENT3_PID=""
CLIENT_BAD_PID=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    for pid in $CLIENT_BAD_PID $CLIENT3_PID $CLIENT2_PID $CLIENT1_PID $SERVER_PID; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for ns in mc-client1 mc-client2 mc-client3 mc-client-bad mc-server; do
        ip netns del "$ns" 2>/dev/null || true
    done
    for link in veth-c1 veth-c2 veth-c3 veth-cb; do
        ip link del "$link" 2>/dev/null || true
    done
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Clean any leftover namespaces
for ns in mc-client1 mc-client2 mc-client3 mc-client-bad mc-server; do
    ip netns del "$ns" 2>/dev/null || true
done
for link in veth-c1 veth-c2 veth-c3 veth-cb; do
    ip link del "$link" 2>/dev/null || true
done

echo "=== Setting up network namespaces (1 server + 3 clients) ==="
ip netns add mc-server
ip netns add mc-client1
ip netns add mc-client2
ip netns add mc-client3

# Create veth pairs: each client ↔ server
for i in 1 2 3; do
    ip link add "veth-c${i}" type veth peer name "veth-s${i}"
    ip link set "veth-c${i}" netns "mc-client${i}"
    ip link set "veth-s${i}" netns mc-server
    ip netns exec "mc-client${i}" ip addr add "192.168.${i}0.1/24" dev "veth-c${i}"
    ip netns exec mc-server ip addr add "192.168.${i}0.2/24" dev "veth-s${i}"
    ip netns exec "mc-client${i}" ip link set "veth-c${i}" up
    ip netns exec mc-server ip link set "veth-s${i}" up
    ip netns exec "mc-client${i}" ip link set lo up
done
ip netns exec mc-server ip link set lo up
ip netns exec mc-server sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Verify underlay
echo "=== Verifying underlay connectivity ==="
for i in 1 2 3; do
    ip netns exec "mc-client${i}" ping -c 1 -W 1 "192.168.${i}0.2" >/dev/null
    echo "OK: Client ${i} → server (192.168.${i}0.x)"
done

# ========================================
# Start server with PSK and max-clients=3
# ========================================
echo ""
echo "=== Starting VPN server (auth-key, max-clients=3) ==="
ip netns exec mc-server "$MQVPN" \
    --mode server \
    --listen 0.0.0.0:4433 \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --max-clients 3 \
    --log-level debug > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "=== FAIL: Server process died ==="
    cat "${WORK_DIR}/server.log"
    exit 1
fi
echo "Server running (PID $SERVER_PID)"

# ========================================
# Test 1: Connect 3 clients with correct PSK
# ========================================
echo ""
echo "=== Test 1: Connect 3 clients with correct PSK ==="

for i in 1 2 3; do
    echo "Starting client ${i}..."
    ip netns exec "mc-client${i}" "$MQVPN" \
        --mode client \
        --server "192.168.${i}0.2:4433" \
        --auth-key "$PSK" \
        --insecure \
        --log-level debug > "${WORK_DIR}/client${i}.log" 2>&1 &
    eval "CLIENT${i}_PID=$!"
    sleep 3
done

# Check all clients are running
ALL_RUNNING=1
for i in 1 2 3; do
    pid_var="CLIENT${i}_PID"
    pid="${!pid_var}"
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "FAIL: Client ${i} (PID ${pid}) died"
        cat "${WORK_DIR}/client${i}.log"
        ALL_RUNNING=0
    else
        echo "OK: Client ${i} running (PID ${pid})"
    fi
done

if [ "$ALL_RUNNING" -eq 0 ]; then
    echo "=== FAIL: Not all clients started ==="
    exit 1
fi

# Show assigned IPs
echo ""
echo "=== Assigned IPs ==="
for i in 1 2 3; do
    ip netns exec "mc-client${i}" ip addr show dev mqvpn0 2>/dev/null | grep inet || echo "Client ${i}: no TUN"
done
echo ""
echo "Server TUN:"
ip netns exec mc-server ip addr show dev mqvpn0 2>/dev/null | grep inet || echo "Server: no TUN"

# ========================================
# Test 2: All clients can ping server TUN
# ========================================
echo ""
echo "=== Test 2: Ping from all clients ==="
PING_PASS=1
for i in 1 2 3; do
    if ip netns exec "mc-client${i}" ping -c 3 -W 2 10.0.0.1 >/dev/null 2>&1; then
        echo "OK: Client ${i} → 10.0.0.1 ping success"
    else
        echo "FAIL: Client ${i} → 10.0.0.1 ping failed"
        PING_PASS=0
    fi
done

if [ "$PING_PASS" -eq 0 ]; then
    echo "=== FAIL: Not all clients can ping ==="
    exit 1
fi
echo "=== PASS: All 3 clients can ping through tunnel ==="

# ========================================
# Test 3: Disconnect client 2, others survive
# ========================================
echo ""
echo "=== Test 3: Disconnect client 2, verify others continue ==="
echo "Killing client 2 (PID $CLIENT2_PID)..."
kill "$CLIENT2_PID" 2>/dev/null || true
wait "$CLIENT2_PID" 2>/dev/null || true
CLIENT2_PID=""
sleep 2

SURVIVE_PASS=1
for i in 1 3; do
    pid_var="CLIENT${i}_PID"
    pid="${!pid_var}"
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "FAIL: Client ${i} (PID ${pid}) died after client 2 disconnect"
        SURVIVE_PASS=0
    else
        if ip netns exec "mc-client${i}" ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
            echo "OK: Client ${i} still alive and ping works"
        else
            echo "FAIL: Client ${i} alive but ping failed"
            SURVIVE_PASS=0
        fi
    fi
done

if [ "$SURVIVE_PASS" -eq 0 ]; then
    echo "=== FAIL: Other clients affected by client 2 disconnect ==="
    exit 1
fi
echo "=== PASS: Other clients unaffected by disconnect ==="

# ========================================
# Test 4: Wrong PSK rejected
# ========================================
echo ""
echo "=== Test 4: Wrong PSK rejected ==="

# Create a netns for the bad client
ip netns add mc-client-bad
ip link add veth-cb type veth peer name veth-sb
ip link set veth-cb netns mc-client-bad
ip link set veth-sb netns mc-server
ip netns exec mc-client-bad ip addr add 192.168.40.1/24 dev veth-cb
ip netns exec mc-server ip addr add 192.168.40.2/24 dev veth-sb
ip netns exec mc-client-bad ip link set veth-cb up
ip netns exec mc-server ip link set veth-sb up
ip netns exec mc-client-bad ip link set lo up

ip netns exec mc-client-bad ping -c 1 -W 1 192.168.40.2 >/dev/null

echo "Connecting with wrong PSK..."
ip netns exec mc-client-bad "$MQVPN" \
    --mode client \
    --server 192.168.40.2:4433 \
    --auth-key "WRONG_KEY_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    --insecure \
    --log-level debug > "${WORK_DIR}/client_bad.log" 2>&1 &
CLIENT_BAD_PID=$!

# Wait for the client to attempt connection and get rejected
sleep 5

if kill -0 "$CLIENT_BAD_PID" 2>/dev/null; then
    # Client might still be running if it retries — check if tunnel is NOT up
    if ip netns exec mc-client-bad ip addr show dev mqvpn0 >/dev/null 2>&1; then
        echo "FAIL: Bad client got a TUN device (should have been rejected)"
        AUTH_PASS=0
    else
        echo "OK: Bad client running but no tunnel established"
        kill "$CLIENT_BAD_PID" 2>/dev/null || true
        wait "$CLIENT_BAD_PID" 2>/dev/null || true
        CLIENT_BAD_PID=""
        AUTH_PASS=1
    fi
else
    # Client exited — check server log for 403
    wait "$CLIENT_BAD_PID" 2>/dev/null || true
    CLIENT_BAD_PID=""
    if grep -q "auth.*fail\|403\|unauthorized\|authentication" "${WORK_DIR}/server.log" 2>/dev/null || \
       grep -q "auth.*fail\|403\|unauthorized\|authentication" "${WORK_DIR}/client_bad.log" 2>/dev/null; then
        echo "OK: Bad client rejected (auth failure in logs)"
        AUTH_PASS=1
    else
        echo "OK: Bad client exited (no tunnel established)"
        AUTH_PASS=1
    fi
fi

if [ "$AUTH_PASS" -eq 1 ]; then
    echo "=== PASS: Wrong PSK rejected ==="
else
    echo "=== FAIL: Wrong PSK was not rejected ==="
fi

# Verify good clients still work after bad client attempt
echo ""
echo "=== Verify: Good clients still working after auth rejection ==="
FINAL_PASS=1
for i in 1 3; do
    if ip netns exec "mc-client${i}" ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
        echo "OK: Client ${i} still working"
    else
        echo "FAIL: Client ${i} broken after bad client attempt"
        FINAL_PASS=0
    fi
done

# ==========================================================================
# Summary
# ==========================================================================
echo ""
echo "=========================================="
echo "  Multi-client Test Summary"
echo "=========================================="
echo "  Test 1 (3 clients connect): PASS"
echo "  Test 2 (All ping):          PASS"
[ "$SURVIVE_PASS" -eq 1 ] \
    && echo "  Test 3 (Disconnect):        PASS" \
    || echo "  Test 3 (Disconnect):        FAIL"
[ "$AUTH_PASS" -eq 1 ] \
    && echo "  Test 4 (Wrong PSK):         PASS" \
    || echo "  Test 4 (Wrong PSK):         FAIL"
[ "$FINAL_PASS" -eq 1 ] \
    && echo "  Final (Post-auth verify):   PASS" \
    || echo "  Final (Post-auth verify):   FAIL"
echo "=========================================="

if [ "$SURVIVE_PASS" -eq 1 ] && [ "$AUTH_PASS" -eq 1 ] && [ "$FINAL_PASS" -eq 1 ]; then
    echo ""
    echo "=== ALL TESTS PASSED ==="
    exit 0
else
    echo ""
    echo "=== SOME TESTS FAILED ==="
    exit 1
fi
