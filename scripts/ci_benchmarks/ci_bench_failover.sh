#!/bin/bash
# ci_bench_failover.sh — CI dual-path failover benchmark (TTF + TTR)
#
# Tests both Path A and Path B fault/recovery in a single 100s run.
#
# For each scheduler:
#   1. Setup netns with netem: Path A = 300Mbps/10ms, Path B = 80Mbps/30ms
#   2. Start VPN server + multipath client
#   3. Run 100s iperf3 transfer (TCP, -P 4)
#   4. Cycle 1 — Path A fault:
#      t=20:  inject fault on Path A (ip link set down on both ends)
#      t=40:  recover Path A (ip link set up + IP re-add + netem re-apply)
#   5. Cycle 2 — Path B fault:
#      t=55:  inject fault on Path B (ip link set down on both ends)
#      t=75:  recover Path B (ip link set up + IP re-add + netem re-apply)
#   6. Parse iperf3 JSON intervals to calculate TTF, TTR, and phase averages
#
# Timeline:
#   t=0-20:   pre-fault         (A+B active)
#   t=20-40:  degraded-A        (Path B only, surviving=80Mbps)
#   t=40-55:  Path A recovery   (A+B active)
#   t=55-75:  degraded-B        (Path A only, surviving=300Mbps)
#   t=75-90:  Path B recovery   (A+B active)
#   t=90-100: post-recover      (A+B active)
#
# Metrics per fault cycle:
#   TTF (Time-To-Fallback): seconds from fault injection until throughput
#       reaches 50% of surviving path capacity
#   TTR (Time-To-Recovery): seconds from fault recovery until throughput
#       reaches 80% of pre-fault average
#
# Output: ci_bench_results/failover_<timestamp>.json
#
# Usage: sudo ./ci_bench_failover.sh [path-to-mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQVPN="${1:-${MQVPN}}"

DURATION=100
INTERVAL=0.5
IPERF_PARALLEL=4
SCHEDULERS="wlb minrtt"

# Fault timing
FAULT_A_INJECT_SEC=20
FAULT_A_RECOVER_SEC=40
FAULT_B_INJECT_SEC=55
FAULT_B_RECOVER_SEC=75

TTF_DEFINITION="seconds from fault injection until throughput reaches 50% of surviving path capacity (fallback detection)"
TTR_DEFINITION="seconds from fault recovery until throughput reaches 80% of pre-fault average (full recovery)"

trap ci_bench_cleanup EXIT

ci_bench_check_deps

echo "================================================================"
echo "  mqvpn Dual-Path Failover Benchmark (CI)"
echo "  Binary:     $MQVPN"
echo "  Schedulers: $SCHEDULERS"
echo "  Duration:   ${DURATION}s (Path A fault t=${FAULT_A_INJECT_SEC}-${FAULT_A_RECOVER_SEC}, Path B fault t=${FAULT_B_INJECT_SEC}-${FAULT_B_RECOVER_SEC})"
echo "  Commit:     ${CI_BENCH_COMMIT:0:12}"
echo "  Date:       $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# ── Collect results for each scheduler ──

declare -A RESULT_A_PRE_FAULT
declare -A RESULT_A_DEGRADED
declare -A RESULT_A_TTF
declare -A RESULT_A_TTR
declare -A RESULT_B_PRE_FAULT
declare -A RESULT_B_DEGRADED
declare -A RESULT_B_TTF
declare -A RESULT_B_TTR
declare -A RESULT_POST_RECOVER

for SCHED in $SCHEDULERS; do
    echo ""
    echo "────────────────────────────────────────"
    echo "  Scheduler: $SCHED"
    echo "────────────────────────────────────────"

    # --- Setup netns + netem ---
    ci_bench_setup_netns
    ci_bench_apply_netem

    # --- Start VPN ---
    ci_bench_start_server "$SCHED"
    ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "$SCHED"
    ci_bench_wait_tunnel 15

    # --- iperf3 server (-1 = single client, exits after transfer) ---
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

    # --- Cycle 1: Path A fault injection at t=20s ---
    (
        sleep "$FAULT_A_INJECT_SEC"
        echo "[$(date +%T)] FAULT INJECT ($SCHED): bringing down Path A"
        ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" down
        ip netns exec "$NS_SERVER" ip link set "$VETH_A1" down
    ) &
    FAULT_A_INJECT_PID=$!

    # --- Cycle 1: Path A recovery at t=40s ---
    (
        sleep "$FAULT_A_RECOVER_SEC"
        echo "[$(date +%T)] FAULT RECOVER ($SCHED): bringing up Path A"
        ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
        ip netns exec "$NS_SERVER" ip link set "$VETH_A1" up
        # Re-add IPs lost when link went down
        ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0" 2>/dev/null || true
        ip netns exec "$NS_SERVER" ip addr add "$IP_A_SERVER" dev "$VETH_A1" 2>/dev/null || true
        # Re-apply netem on restored interfaces
        ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_A0" root netem delay 10ms rate 300mbit 2>/dev/null || true
        ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_A1" root netem delay 10ms rate 300mbit 2>/dev/null || true
    ) &
    FAULT_A_RECOVER_PID=$!

    # --- Cycle 2: Path B fault injection at t=55s ---
    (
        sleep "$FAULT_B_INJECT_SEC"
        echo "[$(date +%T)] FAULT INJECT ($SCHED): bringing down Path B"
        ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" down
        ip netns exec "$NS_SERVER" ip link set "$VETH_B1" down
    ) &
    FAULT_B_INJECT_PID=$!

    # --- Cycle 2: Path B recovery at t=75s ---
    (
        sleep "$FAULT_B_RECOVER_SEC"
        echo "[$(date +%T)] FAULT RECOVER ($SCHED): bringing up Path B"
        ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" up
        ip netns exec "$NS_SERVER" ip link set "$VETH_B1" up
        # Re-add IPs lost when link went down
        ip netns exec "$NS_CLIENT" ip addr add "$IP_B_CLIENT" dev "$VETH_B0" 2>/dev/null || true
        ip netns exec "$NS_SERVER" ip addr add "$IP_B_SERVER" dev "$VETH_B1" 2>/dev/null || true
        # Re-apply netem on restored interfaces
        ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_B0" root netem delay 30ms rate 80mbit 2>/dev/null || true
        ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_B1" root netem delay 30ms rate 80mbit 2>/dev/null || true
    ) &
    FAULT_B_RECOVER_PID=$!

    # --- Wait for iperf3 to finish ---
    echo "Waiting for iperf3 to complete..."
    wait "$IPERF_CLIENT_PID" || true
    kill "$IPERF_SERVER_PID" 2>/dev/null || true
    wait "$IPERF_SERVER_PID" 2>/dev/null || true
    wait "$FAULT_A_INJECT_PID" 2>/dev/null || true
    wait "$FAULT_A_RECOVER_PID" 2>/dev/null || true
    wait "$FAULT_B_INJECT_PID" 2>/dev/null || true
    wait "$FAULT_B_RECOVER_PID" 2>/dev/null || true

    # --- Parse iperf3 JSON ---
    PARSE_RESULT=$(python3 -c "
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

fault_a_inject = ${FAULT_A_INJECT_SEC}
fault_a_recover = ${FAULT_A_RECOVER_SEC}
fault_b_inject = ${FAULT_B_INJECT_SEC}
fault_b_recover = ${FAULT_B_RECOVER_SEC}
duration = ${DURATION}

# ── Cycle 1: Path A fault ──

# Pre-fault A average (t<=20, both paths active)
pre_fault_a = [iv['mbps'] for iv in intervals if iv['time_sec'] <= fault_a_inject]
pre_fault_a_avg = sum(pre_fault_a) / len(pre_fault_a) if pre_fault_a else 0

# Degraded A average (20<t<=40, Path B only)
degraded_a = [iv['mbps'] for iv in intervals
              if iv['time_sec'] > fault_a_inject and iv['time_sec'] <= fault_a_recover]
degraded_a_avg = sum(degraded_a) / len(degraded_a) if degraded_a else 0

# TTF A: time from fault A injection until throughput >= 50% of surviving Path B (80*0.5=40)
# Bounded to degraded-A window (20<t<=40) to avoid false match after recovery
surviving_a_mbps = 80  # Path B rate
ttf_a_threshold = surviving_a_mbps * 0.5
ttf_a = None
for iv in intervals:
    if iv['time_sec'] > fault_a_inject and iv['time_sec'] <= fault_a_recover and iv['mbps'] >= ttf_a_threshold:
        ttf_a = round(iv['time_sec'] - fault_a_inject, 2)
        break

# TTR A: time from fault A recovery until throughput >= 80% of pre-fault A average
# Bounded to recovery-A window (40<t<=55) to avoid contamination by Path B fault
ttr_a_threshold = pre_fault_a_avg * 0.8
ttr_a = None
for iv in intervals:
    if iv['time_sec'] > fault_a_recover and iv['time_sec'] <= fault_b_inject and iv['mbps'] >= ttr_a_threshold:
        ttr_a = round(iv['time_sec'] - fault_a_recover, 2)
        break

# ── Cycle 2: Path B fault ──

# Pre-fault B average (40<t<=55, after A recovery, before B fault)
pre_fault_b = [iv['mbps'] for iv in intervals
               if iv['time_sec'] > fault_a_recover and iv['time_sec'] <= fault_b_inject]
pre_fault_b_avg = sum(pre_fault_b) / len(pre_fault_b) if pre_fault_b else 0

# Degraded B average (55<t<=75, Path A only)
degraded_b = [iv['mbps'] for iv in intervals
              if iv['time_sec'] > fault_b_inject and iv['time_sec'] <= fault_b_recover]
degraded_b_avg = sum(degraded_b) / len(degraded_b) if degraded_b else 0

# TTF B: time from fault B injection until throughput >= 50% of surviving Path A (300*0.5=150)
# Bounded to degraded-B window (55<t<=75)
surviving_b_mbps = 300  # Path A rate
ttf_b_threshold = surviving_b_mbps * 0.5
ttf_b = None
for iv in intervals:
    if iv['time_sec'] > fault_b_inject and iv['time_sec'] <= fault_b_recover and iv['mbps'] >= ttf_b_threshold:
        ttf_b = round(iv['time_sec'] - fault_b_inject, 2)
        break

# TTR B: time from fault B recovery until throughput >= 80% of pre-fault B average
# Bounded to recovery-B window (75<t<=90)
ttr_b_threshold = pre_fault_b_avg * 0.8
ttr_b = None
for iv in intervals:
    if iv['time_sec'] > fault_b_recover and iv['time_sec'] <= 90 and iv['mbps'] >= ttr_b_threshold:
        ttr_b = round(iv['time_sec'] - fault_b_recover, 2)
        break

# Post-recover average (t>90, both paths active again)
post_recover = [iv['mbps'] for iv in intervals if iv['time_sec'] > 90]
post_recover_avg = sum(post_recover) / len(post_recover) if post_recover else 0

print(f'{pre_fault_a_avg:.1f}')
print(f'{degraded_a_avg:.1f}')
print(f'{ttf_a}')
print(f'{ttr_a}')
print(f'{pre_fault_b_avg:.1f}')
print(f'{degraded_b_avg:.1f}')
print(f'{ttf_b}')
print(f'{ttr_b}')
print(f'{post_recover_avg:.1f}')
")

    PRE_FAULT_A=$(echo "$PARSE_RESULT" | sed -n '1p')
    DEGRADED_A=$(echo "$PARSE_RESULT" | sed -n '2p')
    TTF_A=$(echo "$PARSE_RESULT" | sed -n '3p')
    TTR_A=$(echo "$PARSE_RESULT" | sed -n '4p')
    PRE_FAULT_B=$(echo "$PARSE_RESULT" | sed -n '5p')
    DEGRADED_B=$(echo "$PARSE_RESULT" | sed -n '6p')
    TTF_B=$(echo "$PARSE_RESULT" | sed -n '7p')
    TTR_B=$(echo "$PARSE_RESULT" | sed -n '8p')
    POST_RECOVER=$(echo "$PARSE_RESULT" | sed -n '9p')

    echo "  ── Path A fault (t=${FAULT_A_INJECT_SEC}-${FAULT_A_RECOVER_SEC}) ──"
    echo "  Pre-fault avg:     ${PRE_FAULT_A} Mbps"
    echo "  Degraded avg:      ${DEGRADED_A} Mbps"
    echo "  TTF:               ${TTF_A} sec"
    echo "  TTR:               ${TTR_A} sec"
    echo "  ── Path B fault (t=${FAULT_B_INJECT_SEC}-${FAULT_B_RECOVER_SEC}) ──"
    echo "  Pre-fault avg:     ${PRE_FAULT_B} Mbps"
    echo "  Degraded avg:      ${DEGRADED_B} Mbps"
    echo "  TTF:               ${TTF_B} sec"
    echo "  TTR:               ${TTR_B} sec"
    echo "  ── Post-recover (t>90) ──"
    echo "  Post-recover avg:  ${POST_RECOVER} Mbps"

    RESULT_A_PRE_FAULT[$SCHED]="$PRE_FAULT_A"
    RESULT_A_DEGRADED[$SCHED]="$DEGRADED_A"
    RESULT_A_TTF[$SCHED]="$TTF_A"
    RESULT_A_TTR[$SCHED]="$TTR_A"
    RESULT_B_PRE_FAULT[$SCHED]="$PRE_FAULT_B"
    RESULT_B_DEGRADED[$SCHED]="$DEGRADED_B"
    RESULT_B_TTF[$SCHED]="$TTF_B"
    RESULT_B_TTR[$SCHED]="$TTR_B"
    RESULT_POST_RECOVER[$SCHED]="$POST_RECOVER"

    rm -f "$IPERF_JSON"

    # --- Stop VPN before next scheduler ---
    ci_bench_stop_vpn

    # --- Tear down netns (will be recreated for next scheduler) ---
    ci_bench_cleanup_stale
done

# ── Generate combined JSON output ──

TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${CI_BENCH_RESULTS}/failover_$(date +%Y%m%d_%H%M%S).json"

# Convert "None" to json null
a_ttf_wlb="${RESULT_A_TTF[wlb]}"
a_ttr_wlb="${RESULT_A_TTR[wlb]}"
b_ttf_wlb="${RESULT_B_TTF[wlb]}"
b_ttr_wlb="${RESULT_B_TTR[wlb]}"
a_ttf_minrtt="${RESULT_A_TTF[minrtt]}"
a_ttr_minrtt="${RESULT_A_TTR[minrtt]}"
b_ttf_minrtt="${RESULT_B_TTF[minrtt]}"
b_ttr_minrtt="${RESULT_B_TTR[minrtt]}"

[ "$a_ttf_wlb" = "None" ] && a_ttf_wlb="None"
[ "$a_ttr_wlb" = "None" ] && a_ttr_wlb="None"
[ "$b_ttf_wlb" = "None" ] && b_ttf_wlb="None"
[ "$b_ttr_wlb" = "None" ] && b_ttr_wlb="None"
[ "$a_ttf_minrtt" = "None" ] && a_ttf_minrtt="None"
[ "$a_ttr_minrtt" = "None" ] && a_ttr_minrtt="None"
[ "$b_ttf_minrtt" = "None" ] && b_ttf_minrtt="None"
[ "$b_ttr_minrtt" = "None" ] && b_ttr_minrtt="None"

python3 -c "
import json

result = {
    'test': 'failover',
    'commit': '${CI_BENCH_COMMIT}',
    'timestamp': '${TIMESTAMP}',
    'netem': {
        'path_a': {'one_way_delay_ms': 10, 'rtt_ms': 20, 'rate_mbit': 300},
        'path_b': {'one_way_delay_ms': 30, 'rtt_ms': 60, 'rate_mbit': 80}
    },
    'results': {
        'wlb': {
            'fault_a': {
                'pre_fault_avg_mbps': ${RESULT_A_PRE_FAULT[wlb]},
                'degraded_avg_mbps': ${RESULT_A_DEGRADED[wlb]},
                'ttf_sec': ${a_ttf_wlb},
                'ttr_sec': ${a_ttr_wlb}
            },
            'fault_b': {
                'pre_fault_avg_mbps': ${RESULT_B_PRE_FAULT[wlb]},
                'degraded_avg_mbps': ${RESULT_B_DEGRADED[wlb]},
                'ttf_sec': ${b_ttf_wlb},
                'ttr_sec': ${b_ttr_wlb}
            },
            'post_recover_avg_mbps': ${RESULT_POST_RECOVER[wlb]}
        },
        'minrtt': {
            'fault_a': {
                'pre_fault_avg_mbps': ${RESULT_A_PRE_FAULT[minrtt]},
                'degraded_avg_mbps': ${RESULT_A_DEGRADED[minrtt]},
                'ttf_sec': ${a_ttf_minrtt},
                'ttr_sec': ${a_ttr_minrtt}
            },
            'fault_b': {
                'pre_fault_avg_mbps': ${RESULT_B_PRE_FAULT[minrtt]},
                'degraded_avg_mbps': ${RESULT_B_DEGRADED[minrtt]},
                'ttf_sec': ${b_ttf_minrtt},
                'ttr_sec': ${b_ttr_minrtt}
            },
            'post_recover_avg_mbps': ${RESULT_POST_RECOVER[minrtt]}
        }
    },
    'ttf_definition': '${TTF_DEFINITION}',
    'ttr_definition': '${TTR_DEFINITION}'
}

with open('${OUTPUT_FILE}', 'w') as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
"

ci_bench_sanity_check "$OUTPUT_FILE" "failover benchmark"

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"
