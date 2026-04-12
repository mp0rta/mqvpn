#!/bin/bash
# ci_bench_ntn.sh — NTN (Non-Terrestrial Network) satellite link benchmark
#
# Tests multipath scheduler performance across LTE/WiFi + satellite scenarios.
# Models LEO/GEO satellite link characteristics based on 3GPP NTN specs
# and real-world Starlink measurements.
#
# Netem is applied on both ends of each veth pair, so RTT = 2 x one-way delay.
#
# Scenarios:
#   1. LTE + LEO (Starlink-like)  — typical smartphone dual connectivity
#   2. LTE + LEO (high orbit)     — worst-case LEO, higher RTT/loss
#   3. LTE + GEO                  — extreme RTT asymmetry
#   4. WiFi + LEO                 — home/office + satellite backup
#   5. Dual-LEO                   — satellite-only (maritime/aviation)
#
# For each scenario, both WLB and MinRTT schedulers are tested.
#
# Output: ci_bench_results/ntn_<timestamp>.json
#
# Usage: sudo ./ci_bench_ntn.sh [path-to-mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQVPN="${1:-${MQVPN}}"

DURATION=15
PARALLEL=4
TUNNEL_TIMEOUT=30  # longer for high-RTT satellite paths (GEO RTT ~600ms)

# ── Preflight ──

ci_bench_check_deps

trap ci_bench_cleanup EXIT

# ── Scenario definitions ──
# Each scenario: name, description, netem_a, netem_b

SCENARIO_NAMES=(
    "lte_leo_starlink"
    "lte_leo_high_orbit"
    "lte_geo"
    "wifi_leo"
    "dual_leo"
)

SCENARIO_DESCS=(
    "LTE + LEO (Starlink-like)"
    "LTE + LEO (high orbit)"
    "LTE + GEO"
    "WiFi + LEO"
    "Dual-LEO"
)

SCENARIO_NETEM_A=(
    "delay 15ms 3ms rate 50mbit loss 0.2%"
    "delay 15ms 3ms rate 50mbit loss 0.2%"
    "delay 15ms 3ms rate 50mbit loss 0.2%"
    "delay 3ms 1ms rate 80mbit"
    "delay 25ms 8ms rate 100mbit loss 0.5%"
)

SCENARIO_NETEM_B=(
    "delay 25ms 8ms rate 100mbit loss 0.5%"
    "delay 40ms 12ms rate 80mbit loss 0.8%"
    "delay 300ms 5ms rate 20mbit loss 0.2%"
    "delay 25ms 8ms rate 100mbit loss 0.5%"
    "delay 35ms 10ms rate 80mbit loss 0.8%"
)

NUM_SCENARIOS=${#SCENARIO_NAMES[@]}

echo "================================================================"
echo "  mqvpn NTN (Non-Terrestrial Network) Benchmark (CI)"
echo "  Binary:     $MQVPN"
echo "  Scenarios:  ${NUM_SCENARIOS}"
echo "  Schedulers: wlb, minrtt"
echo "  iperf3:     -P ${PARALLEL} -t ${DURATION}"
echo "  Commit:     ${CI_BENCH_COMMIT:0:12}"
echo "  Date:       $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# ── Per-scenario results ──

declare -A RESULT_WLB
declare -A RESULT_MINRTT

for ((i = 0; i < NUM_SCENARIOS; i++)); do
    name="${SCENARIO_NAMES[$i]}"
    desc="${SCENARIO_DESCS[$i]}"
    netem_a="${SCENARIO_NETEM_A[$i]}"
    netem_b="${SCENARIO_NETEM_B[$i]}"

    echo ""
    echo "──────────────────────────────────────────────────────────────"
    echo "  [$((i + 1))/${NUM_SCENARIOS}] ${desc}"
    echo "  Path A: ${netem_a}"
    echo "  Path B: ${netem_b}"
    echo "──────────────────────────────────────────────────────────────"

    for sched in wlb minrtt; do
        echo ""
        echo "  => Scheduler: ${sched}"

        # Full setup for each scenario+scheduler
        ci_bench_setup_netns
        ci_bench_apply_netem "${netem_a}" "${netem_b}"

        # Start VPN
        if ! ci_bench_start_server "$sched"; then
            echo "    SKIP: VPN server failed for ${sched}"
            [ "$sched" = "wlb" ] && RESULT_WLB[$name]="0.0"
            [ "$sched" = "minrtt" ] && RESULT_MINRTT[$name]="0.0"
            ci_bench_stop_vpn
            ci_bench_cleanup_stale
            continue
        fi

        if ! ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "$sched"; then
            echo "    SKIP: VPN client failed for ${sched}"
            [ "$sched" = "wlb" ] && RESULT_WLB[$name]="0.0"
            [ "$sched" = "minrtt" ] && RESULT_MINRTT[$name]="0.0"
            ci_bench_stop_vpn
            ci_bench_cleanup_stale
            continue
        fi

        if ! ci_bench_wait_tunnel "$TUNNEL_TIMEOUT"; then
            echo "    SKIP: tunnel not established for ${sched}"
            [ "$sched" = "wlb" ] && RESULT_WLB[$name]="0.0"
            [ "$sched" = "minrtt" ] && RESULT_MINRTT[$name]="0.0"
            ci_bench_stop_vpn
            ci_bench_cleanup_stale
            continue
        fi

        # Run iperf3 TCP DL
        iperf_json=$(ci_bench_run_iperf TCP DL "$DURATION" "$PARALLEL")
        mbps=$(ci_bench_parse_throughput "$iperf_json")
        rm -f "$iperf_json"

        echo "    Throughput: ${mbps} Mbps"

        if [ "$sched" = "wlb" ]; then
            RESULT_WLB[$name]="$mbps"
        else
            RESULT_MINRTT[$name]="$mbps"
        fi

        # Stop VPN between schedulers
        ci_bench_stop_vpn

        # Full cleanup between runs
        ci_bench_cleanup_stale
    done
done

# ── Generate JSON output ──

echo ""
echo "Generating JSON output..."

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
OUTPUT_FILE="${CI_BENCH_RESULTS}/ntn_$(date -u '+%Y%m%d_%H%M%S').json"

python3 <<PYEOF
import json

scenarios = []

names = ${NUM_SCENARIOS}
scenario_names = $(printf '%s\n' "${SCENARIO_NAMES[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin]))")
scenario_descs = $(printf '%s\n' "${SCENARIO_DESCS[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin]))")
scenario_netem_a = $(printf '%s\n' "${SCENARIO_NETEM_A[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin]))")
scenario_netem_b = $(printf '%s\n' "${SCENARIO_NETEM_B[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin]))")

wlb_results = {
$(for ((i = 0; i < NUM_SCENARIOS; i++)); do
    name="${SCENARIO_NAMES[$i]}"
    echo "    \"${name}\": ${RESULT_WLB[$name]:-0.0},"
done)
}

minrtt_results = {
$(for ((i = 0; i < NUM_SCENARIOS; i++)); do
    name="${SCENARIO_NAMES[$i]}"
    echo "    \"${name}\": ${RESULT_MINRTT[$name]:-0.0},"
done)
}

for i in range(len(scenario_names)):
    name = scenario_names[i]
    scenarios.append({
        "name": name,
        "description": scenario_descs[i],
        "netem_a": scenario_netem_a[i],
        "netem_b": scenario_netem_b[i],
        "wlb_mbps": wlb_results.get(name, 0.0),
        "minrtt_mbps": minrtt_results.get(name, 0.0),
    })

result = {
    "test": "ntn",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "${TIMESTAMP}",
    "scenarios": scenarios,
}

with open("${OUTPUT_FILE}", "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
PYEOF

# ── Sanity check ──

ci_bench_sanity_check "$OUTPUT_FILE" "NTN benchmark"

# ── Summary ──

echo ""
echo "================================================================"
echo "  NTN Benchmark Results"
echo "================================================================"
echo ""
printf "  %-22s | %10s | %10s\n" "Scenario" "WLB (Mbps)" "MinRTT (Mbps)"
echo "  ───────────────────────┼────────────┼──────────────"
for ((i = 0; i < NUM_SCENARIOS; i++)); do
    name="${SCENARIO_NAMES[$i]}"
    printf "  %-22s | %10s | %10s\n" \
        "$name" "${RESULT_WLB[$name]:-N/A}" "${RESULT_MINRTT[$name]:-N/A}"
done
echo "  ───────────────────────┴────────────┴──────────────"

echo ""
echo "Result: ${OUTPUT_FILE}"
echo ""
echo "================================================================"
echo "  NTN Benchmark DONE"
echo "================================================================"
