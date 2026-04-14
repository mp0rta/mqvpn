#!/bin/bash
# bench_failover.sh — Netns failover benchmark (TTF + TTR)
#
# Runs a 75-second iperf3 transfer over multipath VPN, injects a path
# failure at t=20s, recovers at t=40s, and measures:
#   TTF: time from fault to surviving path reaching 50% capacity
#   TTR: time from recovery to 80% of pre-fault throughput
#   Degraded: average during fault (t=20-40)
#   Post-recover: last 10s (t=65-75, after path revalidation)
#
# Both client and server sides of the faulted path are brought down.
# On recovery: link up + IP re-add + netem re-apply on both ends.
#
# Output: bench_results/failover_netns_<timestamp>.json
#
# Usage: sudo ./bench_failover.sh [-s scheduler] [-p a|b] [-P streams] [-l loglevel] [mqvpn-binary]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/bench_env_setup.sh"

FAULT_PATH="${FAULT_PATH:-a}"
IPERF_PARALLEL="${IPERF_PARALLEL:-4}"

while getopts "s:p:P:l:" opt; do
    case "$opt" in
        s) BENCH_SCHEDULER="$OPTARG" ;;
        p) FAULT_PATH="$OPTARG" ;;
        P) IPERF_PARALLEL="$OPTARG" ;;
        l) BENCH_LOG_LEVEL="$OPTARG" ;;
        *) echo "Usage: $0 [-s scheduler] [-p a|b] [-P streams] [-l loglevel] [mqvpn-binary]"; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

case "$FAULT_PATH" in
    a|A)
        FAULT_PATH_LABEL="A"
        FAULT_IF_CLIENT="$VETH_A0"
        FAULT_IF_SERVER="$VETH_A1"
        FAULT_IP_CLIENT="$IP_A_CLIENT"
        FAULT_IP_SERVER="$IP_A_SERVER"
        FAULT_NETEM="delay 10ms rate 300mbit"
        ;;
    b|B)
        FAULT_PATH_LABEL="B"
        FAULT_IF_CLIENT="$VETH_B0"
        FAULT_IF_SERVER="$VETH_B1"
        FAULT_IP_CLIENT="$IP_B_CLIENT"
        FAULT_IP_SERVER="$IP_B_SERVER"
        FAULT_NETEM="delay 30ms rate 80mbit"
        ;;
    *)
        echo "error: invalid fault path '$FAULT_PATH' (expected a or b)"
        exit 1
        ;;
esac

MQVPN="${1:-${MQVPN}}"
DURATION=75
INTERVAL=0.5
FAULT_INJECT_SEC=20
FAULT_RECOVER_SEC=40
IPERF_SERVER_PID=""

# Stale cleanup
pkill -f "mqvpn.*bench" 2>/dev/null || true
ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip link del "$VETH_A0" 2>/dev/null || true
ip link del "$VETH_B0" 2>/dev/null || true

trap bench_cleanup EXIT

bench_check_deps

echo "================================================================"
echo "  mqvpn Failover Benchmark (TTF + TTR)"
echo "  Binary:    $MQVPN"
echo "  Scheduler: $BENCH_SCHEDULER"
echo "  FaultPath: ${FAULT_PATH_LABEL}"
echo "  Streams:   ${IPERF_PARALLEL}"
echo "  Duration:  ${DURATION}s"
echo "  LogLevel:  ${BENCH_LOG_LEVEL}"
echo "  Date:      $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# --- Setup ---
bench_setup_netns
bench_apply_netem
bench_start_vpn_server
bench_start_vpn_client "--path $VETH_A0 --path $VETH_B0"
bench_wait_tunnel 15

# --- iperf3 server ---
ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" -1 &>/dev/null &
IPERF_SERVER_PID=$!
sleep 1

# --- iperf3 client (background, JSON output) ---
IPERF_JSON="$(mktemp)"
echo "Starting iperf3 for ${DURATION}s (interval=${INTERVAL}s, -P ${IPERF_PARALLEL}, JSON)..."
ip netns exec "$NS_CLIENT" iperf3 \
    -c "$TUNNEL_SERVER_IP" -t "$DURATION" \
    -P "$IPERF_PARALLEL" \
    --interval "$INTERVAL" --json \
    > "$IPERF_JSON" 2>&1 &
IPERF_CLIENT_PID=$!

# --- Fault injection at t=20s ---
sleep "$FAULT_INJECT_SEC"
echo "[$(date +%T)] FAULT INJECT: Path ${FAULT_PATH_LABEL} down (both ends)"
ip netns exec "$NS_CLIENT" ip link set "$FAULT_IF_CLIENT" down
ip netns exec "$NS_SERVER" ip link set "$FAULT_IF_SERVER" down

# --- Fault recovery at t=40s ---
WAIT_RECOVER=$((FAULT_RECOVER_SEC - FAULT_INJECT_SEC))
sleep "$WAIT_RECOVER"
echo "[$(date +%T)] FAULT RECOVER: Path ${FAULT_PATH_LABEL} up (both ends)"
ip netns exec "$NS_CLIENT" ip link set "$FAULT_IF_CLIENT" up
ip netns exec "$NS_SERVER" ip link set "$FAULT_IF_SERVER" up
ip netns exec "$NS_CLIENT" ip addr add "$FAULT_IP_CLIENT" dev "$FAULT_IF_CLIENT" 2>/dev/null || true
ip netns exec "$NS_SERVER" ip addr add "$FAULT_IP_SERVER" dev "$FAULT_IF_SERVER" 2>/dev/null || true
ip netns exec "$NS_CLIENT" tc qdisc add dev "$FAULT_IF_CLIENT" root netem ${FAULT_NETEM} 2>/dev/null || true
ip netns exec "$NS_SERVER" tc qdisc add dev "$FAULT_IF_SERVER" root netem ${FAULT_NETEM} 2>/dev/null || true

# --- Wait for iperf3 to finish ---
echo "Waiting for iperf3 to complete..."
wait "$IPERF_CLIENT_PID" || true
wait "$IPERF_SERVER_PID" 2>/dev/null || true
IPERF_SERVER_PID=""

# --- Parse iperf3 JSON ---
TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${RESULTS_DIR}/failover_netns_$(date +%Y%m%d_%H%M%S).json"

python3 -c "
import json, sys

with open('${IPERF_JSON}') as f:
    raw = json.load(f)

intervals = []
for iv in raw.get('intervals', []):
    s = iv['sum']
    intervals.append({
        'time_sec': round(s['end'], 2),
        'mbps': round(s['bits_per_second'] / 1e6, 1)
    })

fault_inject = ${FAULT_INJECT_SEC}
fault_recover = ${FAULT_RECOVER_SEC}
duration = ${DURATION}

# Pre-fault average (both paths active)
pre_fault = [iv['mbps'] for iv in intervals if iv['time_sec'] <= fault_inject]
pre_fault_avg = sum(pre_fault) / len(pre_fault) if pre_fault else 0

# Degraded average (during fault, surviving path only)
degraded = [iv['mbps'] for iv in intervals
            if iv['time_sec'] > fault_inject and iv['time_sec'] <= fault_recover]
degraded_avg = sum(degraded) / len(degraded) if degraded else 0

# TTF: time from fault to surviving path reaching 50% capacity
surviving_path_mbps = 80 if '${FAULT_PATH_LABEL}' == 'A' else 300
ttf_threshold = surviving_path_mbps * 0.5
ttf = None
for iv in intervals:
    if iv['time_sec'] > fault_inject and iv['mbps'] >= ttf_threshold:
        ttf = round(iv['time_sec'] - fault_inject, 2)
        break

# TTR: time from recovery to 80% of pre-fault (path revalidation)
ttr_threshold = pre_fault_avg * 0.8
ttr = None
for iv in intervals:
    if iv['time_sec'] > fault_recover and iv['mbps'] >= ttr_threshold:
        ttr = round(iv['time_sec'] - fault_recover, 2)
        break

# Post-recover average (last 10s)
post_recover = [iv['mbps'] for iv in intervals if iv['time_sec'] > duration - 10]
post_recover_avg = sum(post_recover) / len(post_recover) if post_recover else 0

result = {
    'test': 'failover',
    'env': 'netns',
    'scheduler': '${BENCH_SCHEDULER}',
    'fault_path': '${FAULT_PATH_LABEL}',
    'iperf_parallel_streams': ${IPERF_PARALLEL},
    'timestamp': '${TIMESTAMP}',
    'netem': {
        'path_a': {'one_way_delay_ms': 10, 'rtt_ms': 20, 'rate_mbit': 300},
        'path_b': {'one_way_delay_ms': 30, 'rtt_ms': 60, 'rate_mbit': 80}
    },
    'duration_sec': ${DURATION},
    'fault_inject_sec': fault_inject,
    'fault_recover_sec': fault_recover,
    'intervals': intervals,
    'pre_fault_avg_mbps': round(pre_fault_avg, 1),
    'degraded_avg_mbps': round(degraded_avg, 1),
    'ttf_sec': ttf,
    'ttr_sec': ttr,
    'post_recover_avg_mbps': round(post_recover_avg, 1)
}

with open('${OUTPUT_FILE}', 'w') as f:
    json.dump(result, f, indent=2)

print(f'Pre-fault avg:     {pre_fault_avg:.1f} Mbps')
print(f'Degraded avg:      {degraded_avg:.1f} Mbps')
print(f'TTF:               {ttf} sec')
print(f'TTR:               {ttr} sec')
print(f'Post-recover avg:  {post_recover_avg:.1f} Mbps')
"

rm -f "$IPERF_JSON"

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"
