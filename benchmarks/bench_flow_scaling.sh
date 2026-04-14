#!/bin/bash
# ci_bench_flow_scaling.sh — CI flow scaling benchmark
#
# Tests WLB vs MinRTT with varying parallel stream counts on asymmetric paths.
#
# Netem: Path A = 100 Mbps / 5 ms OWD (10 ms RTT)
#        Path B =  50 Mbps / 20 ms OWD (40 ms RTT)
# Theoretical max = 150 Mbps
#
# Stream counts: 1 4 8 16 32 64
#
# For each stream count, for each scheduler (wlb, minrtt):
#   - Start server+client with multipath, run iperf3 TCP DL for 15s with -P $N
#   - Parse throughput
#
# Between schedulers: stop VPN, restart.
# Between stream counts within same scheduler: just restart client.
#
# Output: ci_bench_results/flow_scaling_<timestamp>.json
#
# Usage: sudo ./ci_bench_flow_scaling.sh [path-to-mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQVPN="${1:-${MQVPN}}"

IPERF_DURATION=15
STREAM_COUNTS=(1 4 8 16 32 64)
SCHEDULERS=(wlb minrtt)

NETEM_A="delay 5ms rate 100mbit"
NETEM_B="delay 20ms rate 50mbit"

trap ci_bench_cleanup EXIT

ci_bench_check_deps

echo "================================================================"
echo "  mqvpn Flow Scaling Benchmark (CI)"
echo "  Binary:     $MQVPN"
echo "  Schedulers: ${SCHEDULERS[*]}"
echo "  Streams:    ${STREAM_COUNTS[*]}"
echo "  Duration:   ${IPERF_DURATION}s per iperf3 run"
echo "  Netem A:    ${NETEM_A}"
echo "  Netem B:    ${NETEM_B}"
echo "  Commit:     $CI_BENCH_COMMIT"
echo "  Date:       $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# --- Setup netns and netem ---
ci_bench_setup_netns
ci_bench_apply_netem "$NETEM_A" "$NETEM_B"

# --- Collect results per scheduler ---
# Format: scheduler streams mbps
RESULTS_TMP="$(mktemp)"

for SCHED in "${SCHEDULERS[@]}"; do
    echo ""
    echo "================================================================"
    echo "  Scheduler: $SCHED"
    echo "================================================================"

    if ! ci_bench_start_server "$SCHED"; then
        echo "  SKIP: VPN server failed for $SCHED"
        for N in "${STREAM_COUNTS[@]}"; do
            echo "$SCHED $N 0.0" >> "$RESULTS_TMP"
        done
        continue
    fi

    for N in "${STREAM_COUNTS[@]}"; do
        echo ""
        echo "--------------------------------------------"
        echo "  [$SCHED] Streams: $N"
        echo "--------------------------------------------"

        if ! ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "$SCHED"; then
            echo "    SKIP: VPN client failed"
            echo "$SCHED $N 0.0" >> "$RESULTS_TMP"
            ci_bench_stop_client
            continue
        fi
        if ! ci_bench_wait_tunnel 15; then
            echo "    SKIP: tunnel not ready"
            echo "$SCHED $N 0.0" >> "$RESULTS_TMP"
            ci_bench_stop_client
            continue
        fi

        IPERF_JSON="$(ci_bench_run_iperf TCP DL "$IPERF_DURATION" "$N")"
        MBPS="$(ci_bench_parse_throughput "$IPERF_JSON")"
        rm -f "$IPERF_JSON"
        echo "        throughput: ${MBPS} Mbps"

        echo "$SCHED $N $MBPS" >> "$RESULTS_TMP"

        ci_bench_stop_client
        sleep 2
    done

    # Stop VPN (server + client) before switching scheduler
    ci_bench_stop_vpn
    sleep 2
done

# --- Generate output JSON ---
TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${CI_BENCH_RESULTS}/flow_scaling_$(date +%Y%m%d_%H%M%S).json"

python3 <<PYEOF
import json

wlb_results = []
minrtt_results = []

with open('${RESULTS_TMP}') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) != 3:
            continue
        sched, streams, mbps = parts

        entry = {
            'streams': int(streams),
            'mbps': float(mbps)
        }

        if sched == 'wlb':
            wlb_results.append(entry)
        elif sched == 'minrtt':
            minrtt_results.append(entry)

output = {
    'test': 'flow_scaling',
    'commit': '${CI_BENCH_COMMIT}',
    'timestamp': '${TIMESTAMP}',
    'netem': {
        'path_a': {'one_way_delay_ms': 5, 'rtt_ms': 10, 'rate_mbit': 100},
        'path_b': {'one_way_delay_ms': 20, 'rtt_ms': 40, 'rate_mbit': 50}
    },
    'results': {
        'wlb': wlb_results,
        'minrtt': minrtt_results
    }
}

with open('${OUTPUT_FILE}', 'w') as f:
    json.dump(output, f, indent=2)

print(json.dumps(output, indent=2))
PYEOF

rm -f "$RESULTS_TMP"

# --- Sanity check ---
ci_bench_sanity_check "$OUTPUT_FILE" "flow_scaling benchmark"

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"
