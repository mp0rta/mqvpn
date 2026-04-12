#!/bin/bash
# ci_bench_udp_scheduler.sh — UDP scheduler comparison benchmark
#
# Measures UDP metrics (throughput, jitter, loss%) for WLB vs MinRTT
# across 4 network scenarios with varying path characteristics.
#
# Scenarios:
#   1. Equal paths          — symmetric 50 Mbit / 10 ms
#   2. Asymmetric bandwidth — 100 Mbit vs 50 Mbit
#   3. Asymmetric jitter    — clean vs 8 ms jitter
#   4. Lossy path           — clean vs 1% loss
#
# Output: ci_bench_results/udp_scheduler_<timestamp>.json
#
# Usage: sudo ./ci_bench_udp_scheduler.sh [path-to-mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQVPN="${1:-${MQVPN}}"

DURATION=15
PARALLEL=4
SCHEDULERS="wlb minrtt"

# ── Scenario definitions ──
# Each scenario: name, netem_a, netem_b, target_bw

SCENARIO_NAMES=(
    "equal_paths"
    "asymmetric_bandwidth"
    "asymmetric_jitter"
    "lossy_path"
)

SCENARIO_NETEM_A=(
    "delay 10ms rate 50mbit"
    "delay 5ms rate 100mbit"
    "delay 10ms rate 50mbit"
    "delay 10ms rate 50mbit"
)

SCENARIO_NETEM_B=(
    "delay 10ms rate 50mbit"
    "delay 20ms rate 50mbit"
    "delay 10ms 8ms rate 50mbit"
    "delay 10ms rate 50mbit loss 1%"
)

SCENARIO_TARGET_BW=(
    "120M"
    "180M"
    "120M"
    "120M"
)

NUM_SCENARIOS=${#SCENARIO_NAMES[@]}

# ── UDP metrics parser ──
# Extracts throughput (Mbps), jitter_ms, lost_percent from iperf3 UDP JSON.
# Prints three lines: mbps, jitter_ms, lost_pct

ci_bench_parse_udp() {
    local json_file="$1"
    python3 -c "
import json
try:
    with open('${json_file}') as f:
        data = json.load(f)
    end = data.get('end', {})
    s = end.get('sum', {})
    mbps = s.get('bits_per_second', 0) / 1e6
    jitter = s.get('jitter_ms', 0)
    lost = s.get('lost_percent', 0)
    print(f'{mbps:.1f}')
    print(f'{jitter:.3f}')
    print(f'{lost:.2f}')
except Exception:
    print('0.0')
    print('0.000')
    print('0.00')
"
}

# ── Preflight ──

ci_bench_check_deps

trap ci_bench_cleanup EXIT

echo "================================================================"
echo "  mqvpn UDP Scheduler Benchmark (CI)"
echo "  Binary:     $MQVPN"
echo "  Schedulers: $SCHEDULERS"
echo "  Duration:   ${DURATION}s per run"
echo "  Parallel:   ${PARALLEL} streams"
echo "  Scenarios:  ${NUM_SCENARIOS}"
echo "  Commit:     ${CI_BENCH_COMMIT:0:12}"
echo "  Date:       $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# ── Associative arrays for results ──

declare -A R_MBPS
declare -A R_JITTER
declare -A R_LOST

# ── Run scenarios ──

for (( i=0; i<NUM_SCENARIOS; i++ )); do
    SCENARIO="${SCENARIO_NAMES[$i]}"
    NETEM_A="${SCENARIO_NETEM_A[$i]}"
    NETEM_B="${SCENARIO_NETEM_B[$i]}"
    TARGET_BW="${SCENARIO_TARGET_BW[$i]}"

    echo ""
    echo "========================================"
    echo "  Scenario $((i+1))/${NUM_SCENARIOS}: ${SCENARIO}"
    echo "  Path A: ${NETEM_A}"
    echo "  Path B: ${NETEM_B}"
    echo "  Target BW: ${TARGET_BW}"
    echo "========================================"

    for SCHED in $SCHEDULERS; do
        echo ""
        echo "--- ${SCENARIO} / ${SCHED} ---"

        # Setup fresh netns + netem
        ci_bench_setup_netns
        ci_bench_apply_netem "$NETEM_A" "$NETEM_B"

        # Start VPN
        ci_bench_start_server "$SCHED"
        ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "$SCHED"
        ci_bench_wait_tunnel 15

        # Run UDP DL iperf3
        IPERF_JSON=$(ci_bench_run_iperf UDP DL "$DURATION" "$PARALLEL" "$TARGET_BW")

        # Parse UDP metrics
        PARSE_RESULT=$(ci_bench_parse_udp "$IPERF_JSON")
        MBPS=$(echo "$PARSE_RESULT" | sed -n '1p')
        JITTER=$(echo "$PARSE_RESULT" | sed -n '2p')
        LOST=$(echo "$PARSE_RESULT" | sed -n '3p')
        rm -f "$IPERF_JSON"

        echo "    Throughput:  ${MBPS} Mbps"
        echo "    Jitter:      ${JITTER} ms"
        echo "    Loss:        ${LOST}%"

        R_MBPS[${SCENARIO}_${SCHED}]="$MBPS"
        R_JITTER[${SCENARIO}_${SCHED}]="$JITTER"
        R_LOST[${SCENARIO}_${SCHED}]="$LOST"

        # Tear down for next run
        ci_bench_stop_vpn
        ci_bench_cleanup_stale
    done
done

# ── Generate JSON output ──

echo ""
echo "Generating JSON output..."

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
OUTPUT_FILE="${CI_BENCH_RESULTS}/udp_scheduler_$(date -u '+%Y%m%d_%H%M%S').json"

python3 <<PYEOF
import json

scenarios = []

scenario_defs = [
    ("equal_paths",          "${SCENARIO_NETEM_A[0]}", "${SCENARIO_NETEM_B[0]}", "${SCENARIO_TARGET_BW[0]}"),
    ("asymmetric_bandwidth", "${SCENARIO_NETEM_A[1]}", "${SCENARIO_NETEM_B[1]}", "${SCENARIO_TARGET_BW[1]}"),
    ("asymmetric_jitter",    "${SCENARIO_NETEM_A[2]}", "${SCENARIO_NETEM_B[2]}", "${SCENARIO_TARGET_BW[2]}"),
    ("lossy_path",           "${SCENARIO_NETEM_A[3]}", "${SCENARIO_NETEM_B[3]}", "${SCENARIO_TARGET_BW[3]}"),
]

results_data = {
$(for (( i=0; i<NUM_SCENARIOS; i++ )); do
    S="${SCENARIO_NAMES[$i]}"
    for SCHED in $SCHEDULERS; do
        echo "    '${S}_${SCHED}_mbps': ${R_MBPS[${S}_${SCHED}]},"
        echo "    '${S}_${SCHED}_jitter': ${R_JITTER[${S}_${SCHED}]},"
        echo "    '${S}_${SCHED}_lost': ${R_LOST[${S}_${SCHED}]},"
    done
done)
}

for name, netem_a, netem_b, target_bw in scenario_defs:
    scenarios.append({
        "name": name,
        "netem_a": netem_a,
        "netem_b": netem_b,
        "target_bw": target_bw,
        "wlb": {
            "mbps": results_data[f"{name}_wlb_mbps"],
            "jitter_ms": results_data[f"{name}_wlb_jitter"],
            "lost_pct": results_data[f"{name}_wlb_lost"],
        },
        "minrtt": {
            "mbps": results_data[f"{name}_minrtt_mbps"],
            "jitter_ms": results_data[f"{name}_minrtt_jitter"],
            "lost_pct": results_data[f"{name}_minrtt_lost"],
        },
    })

result = {
    "test": "udp_scheduler",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "${TIMESTAMP}",
    "scenarios": scenarios,
}

with open("${OUTPUT_FILE}", "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
PYEOF

# ── Sanity check ──

ci_bench_sanity_check "$OUTPUT_FILE" "udp_scheduler benchmark"

echo ""
echo "================================================================"
echo "  UDP Scheduler Benchmark DONE"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"
