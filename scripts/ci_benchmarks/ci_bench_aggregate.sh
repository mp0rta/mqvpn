#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# ci_bench_aggregate.sh — CI bandwidth aggregation benchmark
#
# Measures throughput for single-path vs multipath across varying
# parallel stream counts for both WLB and MinRTT schedulers.
#
# Netem: Path A = 300 Mbps / 10 ms, Path B = 80 Mbps / 30 ms
# Theoretical max = 380 Mbps
#
# Output: ci_bench_results/aggregate_<timestamp>.json
#
# Usage: sudo ./ci_bench_aggregate.sh [path-to-mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQVPN="${1:-${MQVPN}}"
IPERF_DURATION=10
STREAM_COUNTS=(1 4 16 64)
SCHEDULERS=(wlb minrtt)

trap ci_bench_cleanup EXIT

ci_bench_check_deps

echo "================================================================"
echo "  mqvpn Bandwidth Aggregation Benchmark (CI)"
echo "  Binary:     $MQVPN"
echo "  Schedulers: ${SCHEDULERS[*]}"
echo "  Streams:    ${STREAM_COUNTS[*]}"
echo "  Duration:   ${IPERF_DURATION}s per iperf3 run"
echo "  Commit:     $CI_BENCH_COMMIT"
echo "  Date:       $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# --- Setup netns and netem ---
ci_bench_setup_netns
ci_bench_apply_netem "delay 10ms rate 300mbit" "delay 30ms rate 80mbit"

# --- Collect results per scheduler ---
# Format: scheduler streams single_mbps multi_mbps
RESULTS_TMP="$(mktemp)"

for SCHED in "${SCHEDULERS[@]}"; do
    echo ""
    echo "================================================================"
    echo "  Scheduler: $SCHED"
    echo "================================================================"

    ci_bench_start_server "$SCHED"

    for N in "${STREAM_COUNTS[@]}"; do
        echo ""
        echo "--------------------------------------------"
        echo "  [$SCHED] Streams: $N"
        echo "--------------------------------------------"

        # --- Single-path measurement (Path A only) ---
        echo "  [1/2] single-path (Path A only)..."
        ci_bench_start_client "--path $VETH_A0" "$SCHED"
        ci_bench_wait_tunnel 15

        SINGLE_JSON="$(ci_bench_run_iperf TCP DL "$IPERF_DURATION" "$N")"
        SINGLE_MBPS="$(ci_bench_parse_throughput "$SINGLE_JSON")"
        rm -f "$SINGLE_JSON"
        echo "        single-path: ${SINGLE_MBPS} Mbps"

        ci_bench_stop_client
        sleep 2

        # --- Multipath measurement (Path A + Path B) ---
        echo "  [2/2] multipath (Path A + Path B)..."
        ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "$SCHED"
        ci_bench_wait_tunnel 15

        MULTI_JSON="$(ci_bench_run_iperf TCP DL "$IPERF_DURATION" "$N")"
        MULTI_MBPS="$(ci_bench_parse_throughput "$MULTI_JSON")"
        rm -f "$MULTI_JSON"
        echo "        multipath:   ${MULTI_MBPS} Mbps"

        echo "$SCHED $N $SINGLE_MBPS $MULTI_MBPS" >> "$RESULTS_TMP"

        ci_bench_stop_client
        sleep 2
    done

    # Stop VPN (server + client) before switching scheduler
    ci_bench_stop_vpn
    sleep 2
done

# --- Generate output JSON ---
TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${CI_BENCH_RESULTS}/aggregate_$(date +%Y%m%d_%H%M%S).json"

python3 -c "
import json

wlb_results = []
minrtt_results = []

with open('${RESULTS_TMP}') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) != 4:
            continue
        sched, streams, single, multi = parts
        single_f = float(single)
        multi_f = float(multi)
        gain = ((multi_f / single_f) - 1.0) * 100.0 if single_f > 0 else 0.0

        entry = {
            'streams': int(streams),
            'single_path_mbps': single_f,
            'multipath_mbps': multi_f,
            'gain_pct': round(gain, 1)
        }

        if sched == 'wlb':
            wlb_results.append(entry)
        elif sched == 'minrtt':
            minrtt_results.append(entry)

output = {
    'test': 'aggregate',
    'commit': '${CI_BENCH_COMMIT}',
    'timestamp': '${TIMESTAMP}',
    'netem': {
        'path_a': {'one_way_delay_ms': 10, 'rtt_ms': 20, 'rate_mbit': 300},
        'path_b': {'one_way_delay_ms': 30, 'rtt_ms': 60, 'rate_mbit': 80}
    },
    'theoretical_max_mbps': 380,
    'results': {
        'wlb': wlb_results,
        'minrtt': minrtt_results
    }
}

with open('${OUTPUT_FILE}', 'w') as f:
    json.dump(output, f, indent=2)

print()
print('Results summary:')
for sched_name, sched_data in [('wlb', wlb_results), ('minrtt', minrtt_results)]:
    print(f'  [{sched_name}]')
    print(f\"  {'Streams':>8}  {'Single':>10}  {'Multi':>10}  {'Gain':>8}\")
    for r in sched_data:
        print(f\"  {r['streams']:>8}  {r['single_path_mbps']:>8.1f} M  {r['multipath_mbps']:>8.1f} M  {r['gain_pct']:>+7.1f}%\")
    print()
"

rm -f "$RESULTS_TMP"

# --- Sanity check ---
ci_bench_sanity_check "$OUTPUT_FILE" "aggregate benchmark"

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"
