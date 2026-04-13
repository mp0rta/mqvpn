#!/bin/bash
# ci_stress_multi_client.sh — 60-simultaneous-client stress test
#
# Validates that the VPN server can handle 60 concurrent clients without
# resource leaks or stability issues. Uses a bridge topology: one server
# netns with a Linux bridge, and 60 client netns each connected via veth
# to the bridge. All on the same L2/L3 subnet — no default-ns routing needed.
#
# Topology:
#   ci-stress-server (10.50.0.1/24 on br0)
#          |
#         br0 (bridge)
#        / | \
#     veth veth ... veth
#       |    |        |
#   ci-stress-c1   ci-stress-c2  ...  ci-stress-c60
#   (10.50.0.2)    (10.50.0.3)        (10.50.0.61)
#
# Output: ci_stress_results/multi_client_<timestamp>.json
#
# Usage: sudo ./ci_stress_multi_client.sh [path/to/mqvpn]
#
# Requires root (network namespaces).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/ci_stress_env.sh"

# Override MQVPN if passed as argument
if [ "${1:-}" != "" ]; then
    MQVPN="$1"
fi

NUM_CLIENTS=60

# Subnet addressing (all on 10.50.0.0/24)
SERVER_NS="ci-stress-server"
BRIDGE_NAME="br0"
SERVER_IP="10.50.0.1"

# ── Custom cleanup ──

multi_client_cleanup() {
    echo ""
    echo "Cleaning up multi-client topology..."

    ci_stress_monitor_stop

    # Stop all client processes
    for pid in "${CLIENT_PIDS[@]}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done

    # Stop server
    if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi

    sleep 1

    # Delete client namespaces and veths
    for i in $(seq 1 "$NUM_CLIENTS"); do
        ip netns del "ci-stress-c${i}" 2>/dev/null || true
        ip link del "ci-s-c${i}a" 2>/dev/null || true
    done

    # Delete server namespace (bridge + veths cleaned up with it)
    ip netns del "$SERVER_NS" 2>/dev/null || true

    # Clean up work dir
    [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR" || true
}

trap multi_client_cleanup EXIT

# Initialize arrays
CLIENT_PIDS=()
SERVER_PID=""
WORK_DIR=""

# ── Pre-flight ──

ci_stress_check_deps
ci_stress_cleanup_stale

# Also clean any stale multi-client state
for i in $(seq 1 "$NUM_CLIENTS"); do
    ip netns del "ci-stress-c${i}" 2>/dev/null || true
    ip link del "ci-s-c${i}a" 2>/dev/null || true
done
ip netns del "$SERVER_NS" 2>/dev/null || true

echo "================================================================"
echo "  mqvpn Multi-Client Stress Test (CI)"
echo "  Binary:    $MQVPN"
echo "  Clients:   $NUM_CLIENTS"
echo "  Commit:    ${CI_STRESS_COMMIT:0:12}"
echo "  Date:      $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"
echo ""

# ── Create server netns with bridge ──

echo "Creating server namespace with bridge..."

ip netns add "$SERVER_NS"
ip netns exec "$SERVER_NS" ip link set lo up
ip netns exec "$SERVER_NS" ip link add "$BRIDGE_NAME" type bridge
ip netns exec "$SERVER_NS" ip addr add "${SERVER_IP}/24" dev "$BRIDGE_NAME"
ip netns exec "$SERVER_NS" ip link set "$BRIDGE_NAME" up

echo "OK: server netns created (${SERVER_IP} on ${BRIDGE_NAME})"

# ── Generate TLS cert + PSK ──

WORK_DIR="$(mktemp -d)"

PSK=$("$MQVPN" --genkey 2>/dev/null)

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=ci-stress-multi" 2>/dev/null

# ── Start VPN server in server netns ──

echo "Starting VPN server..."

ip netns exec "$SERVER_NS" "$MQVPN" \
    --mode server \
    --listen "0.0.0.0:${VPN_LISTEN_PORT}" \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --log-level "$CI_STRESS_LOG_LEVEL" &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: VPN server died"
    exit 1
fi
echo "VPN server running (PID $SERVER_PID)"

# ── Start server RSS/fd monitor ──

SERVER_MONITOR_LOG="${CI_STRESS_RESULTS}/multi_client_server_monitor.log"
ci_stress_monitor_start "$SERVER_PID" "$SERVER_MONITOR_LOG"

# ── Create 60 client netns + veths bridged to server ──

echo ""
echo "Creating ${NUM_CLIENTS} client namespaces..."

for i in $(seq 1 "$NUM_CLIENTS"); do
    client_ns="ci-stress-c${i}"
    veth_client="ci-s-c${i}a"   # inside client netns
    veth_bridge="ci-s-c${i}b"   # inside server netns, attached to bridge
    client_ip="10.50.0.$((i + 1))"

    ip netns add "$client_ns"

    # Create veth pair in server netns, move one end to client netns
    ip netns exec "$SERVER_NS" ip link add "$veth_bridge" type veth peer name "$veth_client"
    ip netns exec "$SERVER_NS" ip link set "$veth_client" netns "$client_ns"

    # Attach bridge end to br0
    ip netns exec "$SERVER_NS" ip link set "$veth_bridge" master "$BRIDGE_NAME"
    ip netns exec "$SERVER_NS" ip link set "$veth_bridge" up

    # Configure client end
    ip netns exec "$client_ns" ip addr add "${client_ip}/24" dev "$veth_client"
    ip netns exec "$client_ns" ip link set "$veth_client" up
    ip netns exec "$client_ns" ip link set lo up

    if [ $((i % 10)) -eq 0 ]; then
        echo "  created ${i}/${NUM_CLIENTS} client namespaces"
    fi
done

echo "OK: ${NUM_CLIENTS} client namespaces created"

# ── Verify basic connectivity ──

echo "Verifying connectivity (client 1 -> server)..."
if ! ip netns exec "ci-stress-c1" ping -c 1 -W 5 "$SERVER_IP" >/dev/null; then
    echo "DEBUG: client 1 routes:"
    ip netns exec "ci-stress-c1" ip route
    echo "DEBUG: server ns bridge:"
    ip netns exec "$SERVER_NS" bridge link
    echo "ERROR: client 1 cannot reach server"
    exit 1
fi
echo "OK: routing works"

# ── Start 60 VPN clients ──

echo ""
echo "Starting ${NUM_CLIENTS} VPN clients..."

CLIENT_PIDS=()
for i in $(seq 1 "$NUM_CLIENTS"); do
    client_ns="ci-stress-c${i}"
    veth_client="ci-s-c${i}a"

    ip netns exec "$client_ns" "$MQVPN" \
        --mode client \
        --server "${SERVER_IP}:${VPN_LISTEN_PORT}" \
        --path "$veth_client" \
        --auth-key "$PSK" \
        --insecure \
        --log-level "$CI_STRESS_LOG_LEVEL" &
    CLIENT_PIDS+=($!)

    if [ $((i % 10)) -eq 0 ]; then
        echo "  started ${i}/${NUM_CLIENTS} clients"
    fi
done

# Brief pause to let clients begin connecting
sleep 3

# ── Wait for all tunnels (with timeout) ──

echo ""
echo "Waiting for tunnels to come up (timeout 60s)..."

TUNNEL_TIMEOUT=60
clients_connected=0
clients_failed=0
connected_indices=()

for i in $(seq 1 "$NUM_CLIENTS"); do
    client_ns="ci-stress-c${i}"
    pid="${CLIENT_PIDS[$((i - 1))]}"

    # Check if client process is still alive
    if ! kill -0 "$pid" 2>/dev/null; then
        clients_failed=$((clients_failed + 1))
        continue
    fi

    # Try pinging tunnel server from this client
    tunnel_ok=0
    elapsed=0
    while [ "$elapsed" -lt "$TUNNEL_TIMEOUT" ]; do
        if ip netns exec "$client_ns" ping -c 1 -W 1 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
            tunnel_ok=1
            break
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    if [ "$tunnel_ok" -eq 1 ]; then
        clients_connected=$((clients_connected + 1))
        connected_indices+=("$i")
    else
        clients_failed=$((clients_failed + 1))
    fi

    if [ $((i % 10)) -eq 0 ]; then
        echo "  checked ${i}/${NUM_CLIENTS}: connected=${clients_connected} failed=${clients_failed}"
    fi
done

echo ""
echo "=== Connection Summary ==="
echo "  Connected: ${clients_connected}/${NUM_CLIENTS}"
echo "  Failed:    ${clients_failed}/${NUM_CLIENTS}"

# ── Stabilization period (monitor resources under load) ──

echo ""
echo "Stabilizing for 30s (monitoring resources)..."
sleep 30
ci_stress_check_resources "$SERVER_MONITOR_LOG" "server (during stabilization)" || true

# ── Verify: ping from each connected client through tunnel ──

echo ""
echo "Verifying tunnel connectivity for connected clients..."

verify_ok=0
verify_fail=0

for i in "${connected_indices[@]}"; do
    client_ns="ci-stress-c${i}"
    if ip netns exec "$client_ns" ping -c 1 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
        verify_ok=$((verify_ok + 1))
    else
        verify_fail=$((verify_fail + 1))
    fi
done

echo "  Verification: ok=${verify_ok} fail=${verify_fail} (of ${#connected_indices[@]} connected)"

# ── Stop all clients ──

echo ""
echo "Stopping ${NUM_CLIENTS} clients..."

for i in $(seq 1 "$NUM_CLIENTS"); do
    pid="${CLIENT_PIDS[$((i - 1))]}"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
    fi
done

# Wait for all client processes to exit
for i in $(seq 1 "$NUM_CLIENTS"); do
    pid="${CLIENT_PIDS[$((i - 1))]}"
    wait "$pid" 2>/dev/null || true
done

echo "OK: all clients stopped"

# ── Stop monitors and server ──

ci_stress_monitor_stop

echo "Stopping VPN server..."
if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
fi
echo "OK: server stopped"

# ── Check server resources ──

echo ""
echo "=== Resource Check ==="

resource_status="pass"
if ! ci_stress_check_resources "$SERVER_MONITOR_LOG" "server"; then
    resource_status="fail"
fi

# ── Extract server RSS from monitor log ──

read -r server_rss_initial server_rss_final server_rss_max <<< "$(python3 -c "
lines = open('${SERVER_MONITOR_LOG}').read().strip().split('\n')
samples = []
for line in lines:
    parts = line.split()
    if len(parts) >= 2:
        samples.append(int(parts[1]))
if samples:
    print(samples[0], samples[-1], max(samples))
else:
    print(0, 0, 0)
")"

# ── Determine overall status ──

if [ "$resource_status" = "fail" ]; then
    overall_status="fail"
elif [ "$clients_connected" -lt $((NUM_CLIENTS / 2)) ]; then
    # Less than half connected = fail
    overall_status="fail"
else
    overall_status="pass"
fi

# ── Output summary JSON ──

timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
output_file="${CI_STRESS_RESULTS}/multi_client_$(date +%s).json"

python3 -c "
import json, sys

result = {
    'test': 'multi_client',
    'commit': '${CI_STRESS_COMMIT}',
    'timestamp': '${timestamp}',
    'num_clients': ${NUM_CLIENTS},
    'clients_connected': ${clients_connected},
    'clients_failed': ${clients_failed},
    'server_rss_initial_kb': ${server_rss_initial},
    'server_rss_final_kb': ${server_rss_final},
    'server_rss_max_kb': ${server_rss_max},
    'status': '${overall_status}'
}

with open('${output_file}', 'w') as f:
    json.dump(result, f, indent=2)
    f.write('\n')

json.dump(result, sys.stdout, indent=2)
print()
"

echo ""
echo "Results written to: ${output_file}"

if [ "$overall_status" = "fail" ]; then
    echo "RESULT: FAIL"
    exit 1
else
    echo "RESULT: PASS"
    exit 0
fi
