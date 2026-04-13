#!/bin/bash
# ci_bench_multipath_scheduler.sh — Multipath scheduler comparison (WLB vs MinRTT)
#
# Compares WLB vs MinRTT across 8 network scenarios with varied netem parameters.
# Each scenario applies tc netem on both ends of each veth pair (RTT = 2x delay).
#
# Scenarios:
#   1. Equal paths           — 2 x 50Mbps / 10ms
#   2. Asymmetric bandwidth  — 100Mbps/5ms + 50Mbps/20ms
#   3. High jitter           — 2 x 50Mbps / 10ms +/- 5ms
#   4. Asymmetric jitter     — 50Mbps/10ms (stable) + 50Mbps/10ms +/- 8ms (jittery)
#   5. Lossy path            — 50Mbps/10ms + 50Mbps/10ms/1% loss
#   6. Realistic mixed       — 100Mbps/5ms + 50Mbps/20ms +/- 5ms/0.5% loss
#   7. Mobile dual-LTE       — 50Mbps/30ms +/- 10ms/0.5% + 30Mbps/50ms +/- 15ms/1%
#   8. Mobile Wi-Fi + LTE    — 80Mbps/5ms +/- 2ms + 30Mbps/40ms +/- 12ms/0.5%
#
# Output: ci_bench_results/multipath_scheduler_<timestamp>.json
#
# Usage: sudo ./ci_bench_multipath_scheduler.sh [path-to-mqvpn-binary]

set -euo pipefail

source "$(dirname "$0")/ci_bench_env.sh"

MQVPN="${1:-${MQVPN}}"

DURATION=15
PARALLEL=4

# ── Preflight ──

ci_bench_check_deps

trap ci_bench_cleanup EXIT

# ── Scenario definitions ──
# Each scenario: name, netem_a, netem_b

SCENARIO_NAMES=(
    "equal_paths"
    "asymmetric_bandwidth"
    "high_jitter"
    "asymmetric_jitter"
    "lossy_path"
    "realistic_mixed"
    "mobile_dual_lte"
    "mobile_wifi_lte"
)

declare -A NETEM_A
declare -A NETEM_B

NETEM_A["equal_paths"]="delay 10ms rate 50mbit"
NETEM_B["equal_paths"]="delay 10ms rate 50mbit"

NETEM_A["asymmetric_bandwidth"]="delay 5ms rate 100mbit"
NETEM_B["asymmetric_bandwidth"]="delay 20ms rate 50mbit"

NETEM_A["high_jitter"]="delay 10ms 5ms rate 50mbit"
NETEM_B["high_jitter"]="delay 10ms 5ms rate 50mbit"

NETEM_A["asymmetric_jitter"]="delay 10ms rate 50mbit"
NETEM_B["asymmetric_jitter"]="delay 10ms 8ms rate 50mbit"

NETEM_A["lossy_path"]="delay 10ms rate 50mbit"
NETEM_B["lossy_path"]="delay 10ms rate 50mbit loss 1%"

NETEM_A["realistic_mixed"]="delay 5ms rate 100mbit"
NETEM_B["realistic_mixed"]="delay 20ms 5ms rate 50mbit loss 0.5%"

NETEM_A["mobile_dual_lte"]="delay 30ms 10ms rate 50mbit loss 0.5%"
NETEM_B["mobile_dual_lte"]="delay 50ms 15ms rate 30mbit loss 1%"

NETEM_A["mobile_wifi_lte"]="delay 5ms 2ms rate 80mbit"
NETEM_B["mobile_wifi_lte"]="delay 40ms 12ms rate 30mbit loss 0.5%"

# Result storage
declare -A RESULT_MBPS

# ── Setup ──

ci_bench_setup_netns

echo ""
echo "================================================================"
echo "  CI Multipath Scheduler Benchmark (WLB vs MinRTT)"
echo "  Binary:    $MQVPN"
echo "  Duration:  ${DURATION}s per test"
echo "  Parallel:  ${PARALLEL} streams"
echo "  Commit:    ${CI_BENCH_COMMIT}"
echo "  Date:      $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"
echo ""

# ── Run scenarios ──

total=${#SCENARIO_NAMES[@]}
idx=0

for scenario in "${SCENARIO_NAMES[@]}"; do
    idx=$((idx + 1))
    netem_a="${NETEM_A[$scenario]}"
    netem_b="${NETEM_B[$scenario]}"

    echo ""
    echo "==> ${idx}/${total}  ${scenario}"
    echo "    Path A: ${netem_a}"
    echo "    Path B: ${netem_b}"

    ci_bench_setup_netns
    ci_bench_apply_netem "$netem_a" "$netem_b"

    # Single-path baseline (Path A only)
    echo ""
    echo "    [single] Starting VPN..."

    if ! ci_bench_start_server "wlb"; then
        echo "    SKIP: server failed for single"
        RESULT_MBPS["${scenario}_single"]="0.0"
        ci_bench_stop_vpn
        ci_bench_cleanup_stale
    elif ! ci_bench_start_client "--path $VETH_A0" "wlb"; then
        echo "    SKIP: client failed for single"
        RESULT_MBPS["${scenario}_single"]="0.0"
        ci_bench_stop_vpn
        ci_bench_cleanup_stale
    elif ! ci_bench_wait_tunnel; then
        echo "    SKIP: tunnel failed for single"
        RESULT_MBPS["${scenario}_single"]="0.0"
        ci_bench_stop_vpn
        ci_bench_cleanup_stale
    else
        iperf_json=$(ci_bench_run_iperf TCP DL "$DURATION" "$PARALLEL")
        mbps=$(ci_bench_parse_throughput "$iperf_json")
        rm -f "$iperf_json"
        RESULT_MBPS["${scenario}_single"]="$mbps"
        echo "    [single] ${mbps} Mbps"
        ci_bench_stop_vpn
        ci_bench_cleanup_stale
    fi

    # Multipath (WLB + MinRTT)
    for sched in wlb minrtt; do
        echo ""
        echo "    [${sched}] Starting VPN..."

        ci_bench_setup_netns
        ci_bench_apply_netem "$netem_a" "$netem_b"

        if ! ci_bench_start_server "$sched"; then
            echo "    SKIP: server failed for ${sched}"
            RESULT_MBPS["${scenario}_${sched}"]="0.0"
            ci_bench_stop_vpn
            continue
        fi

        if ! ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "$sched"; then
            echo "    SKIP: client failed for ${sched}"
            RESULT_MBPS["${scenario}_${sched}"]="0.0"
            ci_bench_stop_vpn
            continue
        fi

        if ! ci_bench_wait_tunnel; then
            echo "    SKIP: tunnel failed for ${sched}"
            RESULT_MBPS["${scenario}_${sched}"]="0.0"
            ci_bench_stop_vpn
            continue
        fi

        iperf_json=$(ci_bench_run_iperf TCP DL "$DURATION" "$PARALLEL")
        mbps=$(ci_bench_parse_throughput "$iperf_json")
        rm -f "$iperf_json"

        RESULT_MBPS["${scenario}_${sched}"]="$mbps"
        echo "    [${sched}] ${mbps} Mbps"

        ci_bench_stop_vpn
    done

    ci_bench_cleanup
    echo ""
done

# ── Generate JSON output ──

echo ""
echo "Generating JSON output..."

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
OUTPUT_FILE="${CI_BENCH_RESULTS}/multipath_scheduler_$(date -u '+%Y%m%d_%H%M%S').json"
mkdir -p "$CI_BENCH_RESULTS"

# Build scenario JSON fragments
SCENARIOS_JSON=""
for scenario in "${SCENARIO_NAMES[@]}"; do
    single_val="${RESULT_MBPS[${scenario}_single]:-0.0}"
    wlb_val="${RESULT_MBPS[${scenario}_wlb]:-0.0}"
    minrtt_val="${RESULT_MBPS[${scenario}_minrtt]:-0.0}"
    netem_a="${NETEM_A[$scenario]}"
    netem_b="${NETEM_B[$scenario]}"

    if [ -n "$SCENARIOS_JSON" ]; then
        SCENARIOS_JSON="${SCENARIOS_JSON},"
    fi
    SCENARIOS_JSON="${SCENARIOS_JSON}{\"name\":\"${scenario}\",\"netem_a\":\"${netem_a}\",\"netem_b\":\"${netem_b}\",\"single_mbps\":${single_val},\"wlb_mbps\":${wlb_val},\"minrtt_mbps\":${minrtt_val}}"
done

python3 <<PYEOF
import json

raw = json.loads('[${SCENARIOS_JSON}]')

result = {
    "test": "multipath_scheduler",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "${TIMESTAMP}",
    "scenarios": []
}

for s in raw:
    result["scenarios"].append({
        "name": s["name"],
        "netem_a": s["netem_a"],
        "netem_b": s["netem_b"],
        "single_mbps": s["single_mbps"],
        "wlb_mbps": s["wlb_mbps"],
        "minrtt_mbps": s["minrtt_mbps"]
    })

with open("${OUTPUT_FILE}", "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
PYEOF

echo ""
echo "Results written to: ${OUTPUT_FILE}"

# ── Sanity check ──

ci_bench_sanity_check "$OUTPUT_FILE" "multipath_scheduler"

echo ""
echo "================================================================"
echo "  Multipath Scheduler Benchmark DONE"
echo "================================================================"
