#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# bench_aggregate.sh — Netns bandwidth aggregation N-sweep
#
# Measures throughput for single-path vs multipath across varying
# parallel stream counts: [1, 2, 4, 8, 16, 32].
#
# Output: bench_results/aggregate_netns_<timestamp>.json
#
# Usage: sudo ./bench_aggregate.sh [-s scheduler] [-p streams] [path-to-mqvpn-binary]
#   -s  Scheduler: wlb or minrtt (default: wlb)
#   -p  Comma-separated parallel stream counts (default: 1,2,4,8,16,32,64)
#       Example: -p 64  or  -p 1,4,16,64

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/bench_env_setup.sh"

IPERF_DURATION=10
STREAM_COUNTS=(1 2 4 8 16 32 64)
IPERF_SERVER_PID=""

while getopts "s:p:" opt; do
    case "$opt" in
        s) BENCH_SCHEDULER="$OPTARG" ;;
        p) IFS=',' read -ra STREAM_COUNTS <<< "$OPTARG" ;;
        *) echo "Usage: $0 [-s scheduler] [-p streams] [mqvpn-binary]"; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

MQVPN="${1:-${MQVPN}}"

trap bench_cleanup EXIT

bench_check_deps

echo "================================================================"
echo "  mqvpn Bandwidth Aggregation Benchmark (netns)"
echo "  Binary:    $MQVPN"
echo "  Scheduler: $BENCH_SCHEDULER"
echo "  Streams:   ${STREAM_COUNTS[*]}"
echo "  Date:      $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# --- Setup ---
bench_setup_netns
bench_apply_netem
bench_start_vpn_server

# --- Collect results ---
# Store results as lines of "streams single_mbps multi_mbps"
RESULTS_TMP="$(mktemp)"

for N in "${STREAM_COUNTS[@]}"; do
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Streams: $N"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # --- Single-path measurement ---
    echo "  [1/2] single-path (Path A only)..."
    bench_start_vpn_client "--path $VETH_A0"
    bench_wait_tunnel 15

    ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" -1 &>/dev/null &
    IPERF_SERVER_PID=$!
    sleep 1

    SINGLE_JSON="$(mktemp)"
    ip netns exec "$NS_CLIENT" iperf3 \
        -c "$TUNNEL_SERVER_IP" -t "$IPERF_DURATION" \
        -P "$N" --json \
        > "$SINGLE_JSON" 2>&1 || true

    wait "$IPERF_SERVER_PID" 2>/dev/null || true
    IPERF_SERVER_PID=""

    SINGLE_MBPS=$(python3 -c "
import json, sys
try:
    with open('${SINGLE_JSON}') as f:
        data = json.load(f)
    end = data.get('end', {})
    if 'sum_received' in end:
        print(f\"{end['sum_received']['bits_per_second'] / 1e6:.1f}\")
    else:
        print('0.0')
except Exception:
    print('0.0')
")
    rm -f "$SINGLE_JSON"
    echo "        single-path: ${SINGLE_MBPS} Mbps"

    bench_stop_vpn_client
    sleep 3

    # --- Multipath measurement ---
    echo "  [2/2] multipath (Path A + Path B)..."
    bench_start_vpn_client "--path $VETH_A0 --path $VETH_B0"
    bench_wait_tunnel 15

    ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" -1 &>/dev/null &
    IPERF_SERVER_PID=$!
    sleep 1

    MULTI_JSON="$(mktemp)"
    ip netns exec "$NS_CLIENT" iperf3 \
        -c "$TUNNEL_SERVER_IP" -t "$IPERF_DURATION" \
        -P "$N" --json \
        > "$MULTI_JSON" 2>&1 || true

    wait "$IPERF_SERVER_PID" 2>/dev/null || true
    IPERF_SERVER_PID=""

    MULTI_MBPS=$(python3 -c "
import json, sys
try:
    with open('${MULTI_JSON}') as f:
        data = json.load(f)
    end = data.get('end', {})
    if 'sum_received' in end:
        print(f\"{end['sum_received']['bits_per_second'] / 1e6:.1f}\")
    else:
        print('0.0')
except Exception:
    print('0.0')
")
    rm -f "$MULTI_JSON"
    echo "        multipath:   ${MULTI_MBPS} Mbps"

    echo "$N $SINGLE_MBPS $MULTI_MBPS" >> "$RESULTS_TMP"

    bench_stop_vpn_client
    sleep 3
done

# --- Generate output JSON ---
TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${RESULTS_DIR}/aggregate_netns_$(date +%Y%m%d_%H%M%S).json"

python3 -c "
import json

results = []
with open('${RESULTS_TMP}') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) == 3:
            results.append({
                'streams': int(parts[0]),
                'single_path_mbps': float(parts[1]),
                'multipath_mbps': float(parts[2])
            })

output = {
    'test': 'aggregate',
    'env': 'netns',
    'scheduler': '${BENCH_SCHEDULER}',
    'timestamp': '${TIMESTAMP}',
    'netem': {
        'path_a': {'one_way_delay_ms': 10, 'rtt_ms': 20, 'rate_mbit': 300},
        'path_b': {'one_way_delay_ms': 30, 'rtt_ms': 60, 'rate_mbit': 80}
    },
    'theoretical_max_mbps': 380,
    'results': results
}

with open('${OUTPUT_FILE}', 'w') as f:
    json.dump(output, f, indent=2)

print()
print('Results summary:')
print(f\"{'Streams':>8}  {'Single':>10}  {'Multi':>10}  {'Gain':>8}\")
for r in results:
    gain = (r['multipath_mbps'] / r['single_path_mbps'] - 1) * 100 if r['single_path_mbps'] > 0 else 0
    print(f\"{r['streams']:>8}  {r['single_path_mbps']:>8.1f} M  {r['multipath_mbps']:>8.1f} M  {gain:>+7.1f}%\")
"

rm -f "$RESULTS_TMP"

# Sanity check: fail if all results are zero (iperf3 silently failed)
ZERO_COUNT=$(python3 -c "
import json
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
zeros = sum(1 for r in data['results'] if r['single_path_mbps'] == 0.0 and r['multipath_mbps'] == 0.0)
print(zeros)
")
if [ "$ZERO_COUNT" -eq "${#STREAM_COUNTS[@]}" ]; then
    echo "ERROR: all benchmark results are 0.0 — iperf3 likely failed"
    exit 1
fi

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"
