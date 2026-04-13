#!/bin/bash
# ci_stress_failover.sh — 100-cycle path fault/recover stress test
#
# Runs 100 fault/recover cycles alternating Path A and Path B while continuous
# iperf3 traffic flows over the VPN tunnel. Odd cycles fault Path A (surviving
# path = B, 80Mbps), even cycles fault Path B (surviving path = A, 300Mbps).
# Each cycle: bring path down (2s), bring it back up (3s), verify tunnel alive.
# Monitors RSS/fd for both VPN processes to detect resource leaks.
#
# Flow:
#   1. Setup dual-path netns with netem (Path A = 300Mbps/10ms, Path B = 80Mbps/30ms)
#   2. Start VPN server (wlb) + multipath client
#   3. Start long-running iperf3 transfer (-t 3600)
#   4. Loop 100 times: alternate fault Path A / Path B -> wait -> recover -> verify
#   5. Check for resource leaks after all cycles complete
#   6. Output summary JSON to ci_stress_results/failover_storm_<timestamp>.json
#
# Output: ci_stress_results/failover_storm_<timestamp>.json
#
# Usage: sudo ./ci_stress_failover.sh [path-to-mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/ci_stress_env.sh"

MQVPN="${1:-${MQVPN}}"

NUM_CYCLES=100
SCHEDULER="wlb"

trap ci_stress_cleanup EXIT

ci_stress_check_deps

echo "================================================================"
echo "  mqvpn Failover Storm Stress Test (CI)"
echo "  Binary:    $MQVPN"
echo "  Scheduler: $SCHEDULER"
echo "  Cycles:    $NUM_CYCLES"
echo "  Commit:    ${CI_STRESS_COMMIT:0:12}"
echo "  Date:      $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# ── Setup netns + netem ──

ci_stress_setup_netns
ci_stress_apply_netem

# ── Start VPN ──

ci_stress_start_server "$SCHEDULER"
ci_stress_start_client "--path $VETH_A0 --path $VETH_B0" "$SCHEDULER"
ci_stress_wait_tunnel 30

# ── iperf3 server (persistent, no -1) ──

ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" &>/dev/null &
IPERF_SERVER_PID=$!
sleep 1

# ── iperf3 client (long-running, enough for all cycles) ──

echo "Starting iperf3 for 3600s (-P 4, background)..."
ip netns exec "$NS_CLIENT" iperf3 \
    -c "$TUNNEL_SERVER_IP" -t 3600 \
    -P 4 &>/dev/null &
IPERF_CLIENT_PID=$!
sleep 2

# ── Start RSS/fd monitors ──

SERVER_MON_LOG="$(mktemp)"
CLIENT_MON_LOG="$(mktemp)"

ci_stress_monitor_start "$_CS_SERVER_PID" "$SERVER_MON_LOG"
echo "Monitoring VPN server (PID $_CS_SERVER_PID) -> $SERVER_MON_LOG"

ci_stress_monitor_start "$_CS_CLIENT_PID" "$CLIENT_MON_LOG"
echo "Monitoring VPN client (PID $_CS_CLIENT_PID) -> $CLIENT_MON_LOG"

# ── Fault/Recover loop ──

CYCLES_OK=0
CYCLES_FAILED=0

echo ""
echo "Starting $NUM_CYCLES fault/recover cycles..."

for ((i = 1; i <= NUM_CYCLES; i++)); do
    # Alternate: odd cycles fault Path A, even cycles fault Path B
    if (( i % 2 == 1 )); then
        FAULT_VETH_C="$VETH_A0"
        FAULT_VETH_S="$VETH_A1"
        FAULT_IP_C="$IP_A_CLIENT"
        FAULT_IP_S="$IP_A_SERVER"
        FAULT_NETEM="$NETEM_A"
        FAULT_LABEL="A"
    else
        FAULT_VETH_C="$VETH_B0"
        FAULT_VETH_S="$VETH_B1"
        FAULT_IP_C="$IP_B_CLIENT"
        FAULT_IP_S="$IP_B_SERVER"
        FAULT_NETEM="$NETEM_B"
        FAULT_LABEL="B"
    fi

    # (a) Let traffic flow
    sleep 3

    # (b) FAULT: bring down the selected path on both ends
    ip netns exec "$NS_CLIENT" ip link set "$FAULT_VETH_C" down
    ip netns exec "$NS_SERVER" ip link set "$FAULT_VETH_S" down

    # (c) Traffic on surviving path only
    sleep 2

    # (d) RECOVER: bring up, re-add IPs (lost when link went down), re-apply netem
    ip netns exec "$NS_CLIENT" ip link set "$FAULT_VETH_C" up
    ip netns exec "$NS_SERVER" ip link set "$FAULT_VETH_S" up
    ip netns exec "$NS_CLIENT" ip addr add "$FAULT_IP_C" dev "$FAULT_VETH_C" 2>/dev/null || true
    ip netns exec "$NS_SERVER" ip addr add "$FAULT_IP_S" dev "$FAULT_VETH_S" 2>/dev/null || true
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$FAULT_VETH_C" root netem ${FAULT_NETEM} 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc add dev "$FAULT_VETH_S" root netem ${FAULT_NETEM} 2>/dev/null || true

    # (e) Let traffic recover (10s: QUIC path revalidation takes ~10-15s)
    sleep 10

    # (f) Verify: iperf3 client still alive + tunnel ping
    CYCLE_OK=true

    if ! kill -0 "$IPERF_CLIENT_PID" 2>/dev/null; then
        echo "  [cycle $i Path $FAULT_LABEL] FAIL: iperf3 client died"
        CYCLE_OK=false
    fi

    if ! ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
        echo "  [cycle $i Path $FAULT_LABEL] FAIL: tunnel ping failed"
        CYCLE_OK=false
    fi

    # (g) Record result
    if [ "$CYCLE_OK" = true ]; then
        CYCLES_OK=$((CYCLES_OK + 1))
    else
        CYCLES_FAILED=$((CYCLES_FAILED + 1))
    fi

    # (h) Progress every 10 cycles
    if (( i % 10 == 0 )); then
        echo "  [cycle $i/$NUM_CYCLES] ok=$CYCLES_OK failed=$CYCLES_FAILED"
    fi
done

echo ""
echo "All $NUM_CYCLES cycles complete: ok=$CYCLES_OK failed=$CYCLES_FAILED"

# ── Kill iperf3 ──

kill "$IPERF_CLIENT_PID" 2>/dev/null || true
wait "$IPERF_CLIENT_PID" 2>/dev/null || true
kill "$IPERF_SERVER_PID" 2>/dev/null || true
wait "$IPERF_SERVER_PID" 2>/dev/null || true

# ── Stop monitors and check resources ──

ci_stress_monitor_stop

echo ""
echo "── Resource Check ──"

RESOURCE_FAILED=0

ci_stress_check_resources "$SERVER_MON_LOG" "server" || RESOURCE_FAILED=1
ci_stress_check_resources "$CLIENT_MON_LOG" "client" || RESOURCE_FAILED=1

# ── Stop VPN (ASan leak detection runs on process exit) ──

echo ""
echo "Stopping VPN..."
ci_stress_stop_vpn

echo ""
echo "── Sanitizer Check ──"
ci_stress_check_sanitizer || RESOURCE_FAILED=1

# ── Parse monitor logs for summary stats ──

RESOURCE_STATS=$(python3 -c "
import sys

def parse_log(path, label):
    try:
        lines = open(path).read().strip().split('\n')
        samples = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                samples.append((int(parts[0]), int(parts[1]), int(parts[2])))
        if not samples:
            return {'initial_kb': 0, 'final_kb': 0, 'max_kb': 0}
        return {
            'initial_kb': samples[0][1],
            'final_kb': samples[-1][1],
            'max_kb': max(s[1] for s in samples),
        }
    except Exception:
        return {'initial_kb': 0, 'final_kb': 0, 'max_kb': 0}

server = parse_log('${SERVER_MON_LOG}', 'server')
client = parse_log('${CLIENT_MON_LOG}', 'client')

print(f\"{server['initial_kb']} {server['final_kb']} {server['max_kb']}\")
print(f\"{client['initial_kb']} {client['final_kb']} {client['max_kb']}\")
")

SERVER_RSS_INITIAL=$(echo "$RESOURCE_STATS" | sed -n '1p' | awk '{print $1}')
SERVER_RSS_FINAL=$(echo "$RESOURCE_STATS" | sed -n '1p' | awk '{print $2}')
SERVER_RSS_MAX=$(echo "$RESOURCE_STATS" | sed -n '1p' | awk '{print $3}')
CLIENT_RSS_INITIAL=$(echo "$RESOURCE_STATS" | sed -n '2p' | awk '{print $1}')
CLIENT_RSS_FINAL=$(echo "$RESOURCE_STATS" | sed -n '2p' | awk '{print $2}')
CLIENT_RSS_MAX=$(echo "$RESOURCE_STATS" | sed -n '2p' | awk '{print $3}')

# ── Determine status ──

if [ "$CYCLES_FAILED" -gt $((NUM_CYCLES / 10)) ] || [ "$RESOURCE_FAILED" -ne 0 ]; then
    STATUS="fail"
else
    STATUS="pass"
fi

echo ""
echo "── Summary ──"
echo "  Cycles:             $NUM_CYCLES (ok=$CYCLES_OK failed=$CYCLES_FAILED)"
echo "  Server RSS (KB):    initial=${SERVER_RSS_INITIAL} final=${SERVER_RSS_FINAL} max=${SERVER_RSS_MAX}"
echo "  Client RSS (KB):    initial=${CLIENT_RSS_INITIAL} final=${CLIENT_RSS_FINAL} max=${CLIENT_RSS_MAX}"
echo "  Status:             ${STATUS}"

# ── Generate JSON output ──

TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${CI_STRESS_RESULTS}/failover_storm_$(date +%Y%m%d_%H%M%S).json"

python3 -c "
import json

result = {
    'test': 'failover_storm',
    'commit': '${CI_STRESS_COMMIT}',
    'timestamp': '${TIMESTAMP}',
    'num_cycles': ${NUM_CYCLES},
    'cycles_ok': ${CYCLES_OK},
    'cycles_failed': ${CYCLES_FAILED},
    'server_rss': {
        'initial_kb': ${SERVER_RSS_INITIAL},
        'final_kb': ${SERVER_RSS_FINAL},
        'max_kb': ${SERVER_RSS_MAX}
    },
    'client_rss': {
        'initial_kb': ${CLIENT_RSS_INITIAL},
        'final_kb': ${CLIENT_RSS_FINAL},
        'max_kb': ${CLIENT_RSS_MAX}
    },
    'status': '${STATUS}'
}

with open('${OUTPUT_FILE}', 'w') as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
"

# ── Cleanup temp files ──

rm -f "$SERVER_MON_LOG" "$CLIENT_MON_LOG"

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"

if [ "$STATUS" = "fail" ]; then
    exit 1
fi
