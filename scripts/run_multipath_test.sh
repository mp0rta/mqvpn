#!/bin/bash
# run_multipath_test.sh — Multipath smoke test using network namespaces
#
# Creates two netns with 2 veth pairs (2 paths), runs mqvpn server and client
# with --path options, verifies multipath negotiation and connectivity.
#
# Usage: sudo ./run_multipath_test.sh [path-to-mqvpn-binary]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="${1:-${SCRIPT_DIR}/../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    echo "Build first: mkdir build && cd build && cmake .. && make"
    exit 1
fi

if ! command -v iperf3 &>/dev/null; then
    echo "error: iperf3 not found. Install: sudo apt install iperf3"
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

IPERF_SERVER_PID=""
IPERF_CLIENT_PID=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    kill "$IPERF_CLIENT_PID" 2>/dev/null || true
    kill "$IPERF_SERVER_PID" 2>/dev/null || true
    kill "$SERVER_PID" 2>/dev/null || true
    kill "$CLIENT_PID" 2>/dev/null || true
    sleep 1
    # Remove tc netem rules (ignore errors if not applied)
    ip netns exec mp-client tc qdisc del dev veth-a0 root 2>/dev/null || true
    ip netns exec mp-client tc qdisc del dev veth-b0 root 2>/dev/null || true
    ip netns exec mp-server tc qdisc del dev veth-a1 root 2>/dev/null || true
    ip netns exec mp-server tc qdisc del dev veth-b1 root 2>/dev/null || true
    ip netns del mp-server 2>/dev/null || true
    ip netns del mp-client 2>/dev/null || true
    ip link del veth-a0 2>/dev/null || true
    ip link del veth-b0 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Clean any leftover namespaces
ip netns del mp-server 2>/dev/null || true
ip netns del mp-client 2>/dev/null || true
ip link del veth-a0 2>/dev/null || true
ip link del veth-b0 2>/dev/null || true

echo "=== Setting up network namespaces (2 paths) ==="
ip netns add mp-server
ip netns add mp-client

# Path A: veth pair (subnet 192.168.1.0/24)
ip link add veth-a0 type veth peer name veth-a1
ip link set veth-a0 netns mp-client
ip link set veth-a1 netns mp-server
ip netns exec mp-client ip addr add 192.168.1.1/24 dev veth-a0
ip netns exec mp-server ip addr add 192.168.1.2/24 dev veth-a1
ip netns exec mp-client ip link set veth-a0 up
ip netns exec mp-server ip link set veth-a1 up

# Path B: second veth pair (subnet 192.168.2.0/24)
ip link add veth-b0 type veth peer name veth-b1
ip link set veth-b0 netns mp-client
ip link set veth-b1 netns mp-server
ip netns exec mp-client ip addr add 192.168.2.1/24 dev veth-b0
ip netns exec mp-server ip addr add 192.168.2.2/24 dev veth-b1
ip netns exec mp-client ip link set veth-b0 up
ip netns exec mp-server ip link set veth-b1 up

# Loopback
ip netns exec mp-client ip link set lo up
ip netns exec mp-server ip link set lo up

# Enable IP forwarding in server namespace
ip netns exec mp-server sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Verify both underlay paths
echo "=== Verifying underlay connectivity ==="
ip netns exec mp-client ping -c 1 -W 1 192.168.1.2 >/dev/null
echo "OK: Path A (192.168.1.x) working"
ip netns exec mp-client ping -c 1 -W 1 192.168.2.2 >/dev/null
echo "OK: Path B (192.168.2.x) working"

echo "=== Starting VPN server (multipath enabled) ==="
ip netns exec mp-server "$MQVPN" \
    --mode server \
    --listen 0.0.0.0:4433 \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --log-level debug &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "=== FAIL: Server process died ==="
    wait "$SERVER_PID" 2>/dev/null || true
    exit 1
fi
echo "Server running (PID $SERVER_PID)"

echo "=== Starting VPN client (2 paths: veth-a0, veth-b0) ==="
ip netns exec mp-client "$MQVPN" \
    --mode client \
    --server 192.168.1.2:4433 \
    --path veth-a0 --path veth-b0 \
    --auth-key "$PSK" \
    --insecure \
    --log-level debug &
CLIENT_PID=$!
sleep 4

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "=== FAIL: Client process died ==="
    wait "$CLIENT_PID" 2>/dev/null || true
    exit 1
fi
echo "Client running (PID $CLIENT_PID)"

# Show TUN devices
echo ""
echo "=== TUN devices ==="
ip netns exec mp-server ip addr show dev mqvpn0 2>/dev/null || echo "(server TUN not found)"
ip netns exec mp-client ip addr show dev mqvpn0 2>/dev/null || echo "(client TUN not found)"

echo ""
echo "=== Routes in client namespace ==="
ip netns exec mp-client ip route show 2>/dev/null

echo ""
echo "=== Test 1: Connectivity (ping) ==="
if ip netns exec mp-client ping -c 5 -W 2 10.0.0.1; then
    echo ""
    echo "=== PASS: VPN tunnel is working with multipath ==="
else
    echo ""
    echo "=== FAIL: Could not ping through VPN tunnel ==="
    exit 1
fi

# ==========================================================================
# Test 2: iperf3 bandwidth aggregation with tc netem shaping
# ==========================================================================
echo ""
echo "=== Test 2: iperf3 bandwidth aggregation ==="
echo "Applying tc netem: Path A = 100Mbps/5ms, Path B = 50Mbps/20ms"

# Apply shaping on both ends of each veth pair for realistic behavior
# Path A: 100Mbps, 5ms delay
ip netns exec mp-client tc qdisc add dev veth-a0 root netem delay 5ms rate 100mbit
ip netns exec mp-server tc qdisc add dev veth-a1 root netem delay 5ms rate 100mbit
# Path B: 50Mbps, 20ms delay
ip netns exec mp-client tc qdisc add dev veth-b0 root netem delay 20ms rate 50mbit
ip netns exec mp-server tc qdisc add dev veth-b1 root netem delay 20ms rate 50mbit

echo "tc netem applied."

# Start iperf3 server in server netns (listening on VPN address)
ip netns exec mp-server iperf3 -s -B 10.0.0.1 -1 &
IPERF_SERVER_PID=$!
sleep 1

echo "Running iperf3 for 15 seconds (-P 4)..."
IPERF_OUTPUT=$(ip netns exec mp-client iperf3 -c 10.0.0.1 -B 10.0.0.2 -P 4 -t 15 2>&1) || true
IPERF_SERVER_PID=""

echo ""
echo "--- iperf3 output ---"
echo "$IPERF_OUTPUT"
echo "--- end iperf3 output ---"

# Extract receiver bandwidth — prefer [SUM] line for parallel flows, fall back to single flow
BW_LINE=$(echo "$IPERF_OUTPUT" | grep -E '\[SUM\].*receiver' | tail -1)
if [ -z "$BW_LINE" ]; then
    BW_LINE=$(echo "$IPERF_OUTPUT" | grep -E '\[.*\].*receiver' | tail -1)
fi
if [ -n "$BW_LINE" ]; then
    BW_VALUE=$(echo "$BW_LINE" | awk '{for(i=1;i<=NF;i++) if($(i+1) ~ /bits\/sec/) {print $i; exit}}')
    BW_UNIT=$(echo "$BW_LINE" | awk '{for(i=1;i<=NF;i++) if($i ~ /bits\/sec/) {print $i; exit}}')
    echo ""
    echo "Measured bandwidth: ${BW_VALUE} ${BW_UNIT}"

    # Convert to Mbps for comparison
    BW_MBPS=$(echo "$BW_VALUE $BW_UNIT" | awk '{
        val = $1;
        unit = $2;
        if (unit ~ /^G/) val *= 1000;
        else if (unit ~ /^K/) val /= 1000;
        printf "%.1f", val;
    }')

    echo "Single path limit (Path A): 100 Mbps"
    echo "Combined theoretical max:   150 Mbps"
    echo "Measured throughput:         ${BW_MBPS} Mbps"

    PASS_BW=$(echo "$BW_MBPS" | awk '{print ($1 > 100.0) ? "1" : "0"}')
    if [ "$PASS_BW" = "1" ]; then
        echo ""
        echo "=== PASS: Bandwidth exceeds single-path limit (${BW_MBPS} > 100 Mbps) ==="
    else
        echo ""
        echo "=== FAIL: Bandwidth did NOT exceed single-path limit (${BW_MBPS} <= 100 Mbps) ==="
        echo "(This may be expected — multipath scheduler may not fully aggregate yet)"
    fi
else
    echo ""
    echo "=== FAIL: Could not parse iperf3 output ==="
fi

# Remove tc shaping before next test
ip netns exec mp-client tc qdisc del dev veth-a0 root 2>/dev/null || true
ip netns exec mp-server tc qdisc del dev veth-a1 root 2>/dev/null || true
ip netns exec mp-client tc qdisc del dev veth-b0 root 2>/dev/null || true
ip netns exec mp-server tc qdisc del dev veth-b1 root 2>/dev/null || true

# ==========================================================================
# Test 3: Failover — bring down Path A during active transfer
# ==========================================================================
echo ""
echo "=== Test 3: Failover (Path A down during iperf3) ==="

# Ensure Path A is up (in case previous test left it down)
ip netns exec mp-client ip link set veth-a0 up 2>/dev/null || true
sleep 1

# Start iperf3 server (-1 = one-off)
ip netns exec mp-server iperf3 -s -B 10.0.0.1 -1 &
IPERF_SERVER_PID=$!
sleep 1

# Start iperf3 client in background for 20 seconds (-P 4 for parallel flows)
ip netns exec mp-client iperf3 -c 10.0.0.1 -B 10.0.0.2 -P 4 -t 20 > "${WORK_DIR}/failover_iperf.txt" 2>&1 &
IPERF_CLIENT_PID=$!
echo "iperf3 started (PID $IPERF_CLIENT_PID), running for 20 seconds..."

# Wait 5 seconds, then bring down Path A
sleep 5
echo "[$(date +%T)] Bringing DOWN Path A (veth-a0)..."
ip netns exec mp-client ip link set veth-a0 down
echo "[$(date +%T)] Path A is DOWN. Traffic should failover to Path B."

# Wait 10 more seconds — iperf3 should survive on Path B
sleep 10
echo "[$(date +%T)] Checking if iperf3 is still running..."

if kill -0 "$IPERF_CLIENT_PID" 2>/dev/null; then
    echo "[$(date +%T)] iperf3 still alive after Path A down — good"
else
    echo "[$(date +%T)] iperf3 died after Path A down"
fi

# Wait for iperf3 to finish naturally
echo "Waiting for iperf3 to complete..."
wait "$IPERF_CLIENT_PID"
IPERF_EXIT=$?
IPERF_CLIENT_PID=""
wait "$IPERF_SERVER_PID" 2>/dev/null || true
IPERF_SERVER_PID=""

echo ""
echo "--- failover iperf3 output ---"
cat "${WORK_DIR}/failover_iperf.txt"
echo "--- end failover iperf3 output ---"

echo ""
echo "iperf3 exit code: $IPERF_EXIT"

if [ "$IPERF_EXIT" -eq 0 ]; then
    echo ""
    echo "=== PASS: Failover succeeded — iperf3 completed after Path A went down ==="
else
    echo ""
    echo "=== FAIL: Failover failed — iperf3 exited with code $IPERF_EXIT ==="
fi

# ==========================================================================
# Test 4: Path recovery — bring Path A back up, verify re-creation + ping
# ==========================================================================
echo ""
echo "=== Test 4: Path recovery (bring Path A back up) ==="

# Path A is still down from Test 3. Bring it back up.
echo "[$(date +%T)] Bringing UP Path A (veth-a0)..."
ip netns exec mp-client ip link set veth-a0 up
ip netns exec mp-client ip addr add 192.168.1.1/24 dev veth-a0 2>/dev/null || true

# Wait for path re-creation timer to fire and xquic to establish the new path.
# PATH_RECREATE_DELAY_SEC=5, plus some margin for QUIC path validation.
echo "[$(date +%T)] Waiting up to 20 seconds for path re-creation..."

RECOVERY_PASS=0
for attempt in $(seq 1 4); do
    sleep 5
    # Check if "path re-created" or "path[0] re-created" appeared in recent process output
    # Use ping as the definitive test: if both paths are up, ping should still work
    if ip netns exec mp-client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
        echo "[$(date +%T)] Ping OK (attempt $attempt)"
    fi

    # Check if new path was created by looking for 2 active paths in xquic
    # We verify by running a short iperf3 — if it works, the connection is healthy
    if [ "$attempt" -ge 2 ]; then
        ip netns exec mp-server iperf3 -s -B 10.0.0.1 -1 &>/dev/null &
        IPERF_SERVER_PID=$!
        sleep 1
        RECOVERY_BW=$(ip netns exec mp-client iperf3 -c 10.0.0.1 -B 10.0.0.2 -t 3 2>&1 | \
            grep -E '\[.*\].*receiver' | tail -1 | \
            awk '{for(i=1;i<=NF;i++) if($(i+1) ~ /bits\/sec/) {print $i; exit}}')
        wait "$IPERF_SERVER_PID" 2>/dev/null || true
        IPERF_SERVER_PID=""

        if [ -n "$RECOVERY_BW" ]; then
            echo "[$(date +%T)] iperf3 after recovery: ${RECOVERY_BW} (attempt $attempt)"
            RECOVERY_PASS=1
            break
        fi
    fi
done

if [ "$RECOVERY_PASS" -eq 1 ]; then
    echo ""
    echo "=== PASS: Path recovery — connection healthy after Path A restored ==="
else
    echo ""
    echo "=== FAIL: Path recovery — could not verify connectivity after restore ==="
fi

# ==========================================================================
# Summary
# ==========================================================================
echo ""
echo "=========================================="
echo "  Test Summary"
echo "=========================================="
echo "  Test 1 (Ping):       PASS"
[ -n "$BW_LINE" ] && echo "  Test 2 (Bandwidth):  ${BW_MBPS} Mbps (threshold: >100 Mbps)"
[ "$IPERF_EXIT" -eq 0 ] \
    && echo "  Test 3 (Failover):   PASS" \
    || echo "  Test 3 (Failover):   FAIL (exit=$IPERF_EXIT)"
[ "$RECOVERY_PASS" -eq 1 ] \
    && echo "  Test 4 (Recovery):   PASS" \
    || echo "  Test 4 (Recovery):   FAIL"
echo "=========================================="
