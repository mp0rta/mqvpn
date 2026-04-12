#!/bin/bash
# ci_stress_long_running.sh — 1-hour continuous transfer stress test
#
# Runs a 1-hour iperf3 transfer over a multipath VPN tunnel while monitoring
# RSS and fd count of both server and client processes. Detects memory leaks
# (RSS growth >50%) and fd leaks during sustained load.
#
# Flow:
#   1. Setup dual-path netns with netem (Path A = 300Mbps/10ms, Path B = 80Mbps/30ms)
#   2. Start VPN server (wlb) + multipath client
#   3. Run 1-hour iperf3 transfer (TCP, -P 4)
#   4. Monitor RSS/fd for both VPN processes every 10s
#   5. Check for resource leaks after transfer completes
#   6. Stop VPN (ASan leak detection runs on process exit)
#   7. Output summary JSON to ci_stress_results/long_running_<timestamp>.json
#
# Output: ci_stress_results/long_running_<timestamp>.json
#
# Usage: sudo ./ci_stress_long_running.sh [path-to-mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/ci_stress_env.sh"

MQVPN="${1:-${MQVPN}}"

DURATION=3600
IPERF_PARALLEL=4
SCHEDULER="wlb"

trap ci_stress_cleanup EXIT

ci_stress_check_deps

echo "================================================================"
echo "  mqvpn Long-Running Stress Test (CI)"
echo "  Binary:    $MQVPN"
echo "  Scheduler: $SCHEDULER"
echo "  Duration:  ${DURATION}s (1 hour)"
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

# ── iperf3 server ──

ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" &>/dev/null &
IPERF_SERVER_PID=$!
sleep 1

# ── iperf3 client (background, JSON output) ──

IPERF_JSON="$(mktemp)"
echo "Starting iperf3 for ${DURATION}s (-P ${IPERF_PARALLEL}, JSON)..."
ip netns exec "$NS_CLIENT" iperf3 \
    -c "$TUNNEL_SERVER_IP" -t "$DURATION" \
    -P "$IPERF_PARALLEL" --json \
    > "$IPERF_JSON" 2>&1 &
IPERF_CLIENT_PID=$!

# ── Start RSS/fd monitors ──

SERVER_MON_LOG="$(mktemp)"
CLIENT_MON_LOG="$(mktemp)"

ci_stress_monitor_start "$_CS_SERVER_PID" "$SERVER_MON_LOG"
echo "Monitoring VPN server (PID $_CS_SERVER_PID) -> $SERVER_MON_LOG"

ci_stress_monitor_start "$_CS_CLIENT_PID" "$CLIENT_MON_LOG"
echo "Monitoring VPN client (PID $_CS_CLIENT_PID) -> $CLIENT_MON_LOG"

# ── Wait for iperf3 to complete ──

echo "Waiting for iperf3 to complete (${DURATION}s)..."
wait "$IPERF_CLIENT_PID" || true
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
echo "Stopping VPN (ASan checks run on exit)..."
ci_stress_stop_vpn

# ── Parse iperf3 JSON for throughput ──

THROUGHPUT_MBPS=$(python3 -c "
import json, sys

try:
    with open('${IPERF_JSON}') as f:
        raw = json.load(f)
    end = raw.get('end', {})
    sum_sent = end.get('sum_sent', {})
    bps = sum_sent.get('bits_per_second', 0)
    print(f'{bps / 1e6:.1f}')
except Exception as e:
    print('0.0', file=sys.stderr)
    print('0.0')
")

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

if [ "$RESOURCE_FAILED" -eq 0 ]; then
    STATUS="pass"
else
    STATUS="fail"
fi

echo ""
echo "── Summary ──"
echo "  Throughput:         ${THROUGHPUT_MBPS} Mbps"
echo "  Server RSS (KB):    initial=${SERVER_RSS_INITIAL} final=${SERVER_RSS_FINAL} max=${SERVER_RSS_MAX}"
echo "  Client RSS (KB):    initial=${CLIENT_RSS_INITIAL} final=${CLIENT_RSS_FINAL} max=${CLIENT_RSS_MAX}"
echo "  Status:             ${STATUS}"

# ── Generate JSON output ──

TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${CI_STRESS_RESULTS}/long_running_$(date +%Y%m%d_%H%M%S).json"

python3 -c "
import json

result = {
    'test': 'long_running',
    'commit': '${CI_STRESS_COMMIT}',
    'timestamp': '${TIMESTAMP}',
    'duration_sec': ${DURATION},
    'throughput_mbps': ${THROUGHPUT_MBPS},
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

rm -f "$IPERF_JSON" "$SERVER_MON_LOG" "$CLIENT_MON_LOG"

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"

if [ "$STATUS" = "fail" ]; then
    exit 1
fi
