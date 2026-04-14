#!/bin/bash
# ci_bench_udp_sweep.sh — UDP rate sweep benchmark
#
# Sweeps UDP send rate from 200-380 Mbps to find the saturation point
# (where loss exceeds 5%) for single-path, WLB, and MinRTT.
#
# Netem: Path A = 300Mbps/10ms, Path B = 80Mbps/30ms
# Payload: 1100B bulk (-l 1100), single stream
# Direction: DL (server→client)
#
# Output: ci_bench_results/udp_sweep_<timestamp>.json
#
# Usage: sudo ./ci_bench_udp_sweep.sh [path-to-mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQVPN="${1:-${MQVPN}}"

DURATION=15
PACKET_SIZE=1100
LOSS_THRESHOLD=5.0

SWEEP_RATES=(200 210 220 230 240 250 260 270 280 290 300 310 320 330 340 350 360 370 380)

CONDITIONS=("single" "wlb" "minrtt")

trap 'rm -f "$RESULTS_TMP"; ci_bench_cleanup' EXIT

ci_bench_check_deps

echo "================================================================"
echo "  mqvpn UDP Rate Sweep Benchmark (CI)"
echo "  Binary:     $MQVPN"
echo "  Sweep:      ${SWEEP_RATES[0]}-${SWEEP_RATES[-1]} Mbps (${#SWEEP_RATES[@]} points)"
echo "  Conditions: ${CONDITIONS[*]}"
echo "  Payload:    ${PACKET_SIZE}B, DL, single stream"
echo "  Commit:     ${CI_BENCH_COMMIT:0:12}"
echo "  Date:       $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# ── Results file (append lines: condition rate mbps loss jitter) ──

RESULTS_TMP="$(mktemp)"

# ── Run sweep for each condition ──

for cond in "${CONDITIONS[@]}"; do
    echo ""
    echo "════════════════════════════════════════"
    echo "  Condition: ${cond}"
    echo "════════════════════════════════════════"

    ci_bench_setup_netns
    ci_bench_apply_netem

    # Start VPN
    if [ "$cond" = "single" ]; then
        ci_bench_start_server "wlb"
        ci_bench_start_client "--path $VETH_A0" "wlb"
    else
        ci_bench_start_server "$cond"
        ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "$cond"
    fi
    ci_bench_wait_tunnel 15

    for rate in "${SWEEP_RATES[@]}"; do
        # iperf3 server (one-shot)
        ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" -1 &>/dev/null &
        IPERF_SRV_PID=$!
        sleep 1

        # iperf3 client: UDP DL with specific packet size
        IPERF_JSON="$(mktemp)"
        ip netns exec "$NS_CLIENT" iperf3 \
            -c "$TUNNEL_SERVER_IP" -u -b "${rate}M" -l "$PACKET_SIZE" \
            -t "$DURATION" -R --json \
            > "$IPERF_JSON" 2>&1 || true

        wait "$IPERF_SRV_PID" 2>/dev/null || true

        # Parse UDP metrics
        PARSE=$(python3 -c "
import json
try:
    with open('${IPERF_JSON}') as f:
        data = json.load(f)
    end = data.get('end', {})
    s = end.get('sum', {})
    mbps = s.get('bits_per_second', 0) / 1e6
    jitter = s.get('jitter_ms', 0)
    lost = s.get('lost_percent', 0)
    print(f'{mbps:.1f} {lost:.2f} {jitter:.3f}')
except Exception:
    print('0.0 0.00 0.000')
")
        MBPS=$(echo "$PARSE" | awk '{print $1}')
        LOST=$(echo "$PARSE" | awk '{print $2}')
        JITTER=$(echo "$PARSE" | awk '{print $3}')

        echo "    ${rate}M → ${MBPS} Mbps, loss=${LOST}%, jitter=${JITTER}ms"
        echo "${cond} ${rate} ${MBPS} ${LOST} ${JITTER}" >> "$RESULTS_TMP"

        rm -f "$IPERF_JSON"
    done

    ci_bench_stop_vpn
    ci_bench_cleanup_stale
done

# ── Generate JSON output ──

echo ""
echo "Generating JSON output..."

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
OUTPUT_FILE="${CI_BENCH_RESULTS}/udp_sweep_$(date -u '+%Y%m%d_%H%M%S').json"

python3 <<PYEOF
import json

sweep_rates = [$(IFS=,; echo "${SWEEP_RATES[*]}")]
loss_threshold = ${LOSS_THRESHOLD}

results = {}
with open('${RESULTS_TMP}') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) != 5:
            continue
        cond, rate, mbps, lost, jitter = parts
        if cond not in results:
            results[cond] = []
        results[cond].append({
            'rate': int(rate),
            'throughput': float(mbps),
            'loss_pct': float(lost),
            'jitter_ms': float(jitter),
        })

def find_saturation(points):
    """Last rate before loss first exceeds threshold. None if first point exceeds."""
    sat = None
    for p in sorted(points, key=lambda x: x['rate']):
        if p['loss_pct'] < loss_threshold:
            sat = p['rate']
        else:
            break
    return sat

output = {
    'test': 'udp_sweep',
    'commit': '${CI_BENCH_COMMIT}',
    'timestamp': '${TIMESTAMP}',
    'netem': {
        'path_a': {'delay_ms': 10, 'rate_mbit': 300},
        'path_b': {'delay_ms': 30, 'rate_mbit': 80},
    },
    'theoretical_max_mbps': 380,
    'packet_size_bytes': ${PACKET_SIZE},
    'sweep_rates_mbps': sweep_rates,
    'results': {},
}

for cond in ['single', 'wlb', 'minrtt']:
    pts = results.get(cond, [])
    output['results'][cond] = {
        'saturation_mbps': find_saturation(pts),
        'points': sorted(pts, key=lambda x: x['rate']),
    }

with open('${OUTPUT_FILE}', 'w') as f:
    json.dump(output, f, indent=2)

print(json.dumps(output, indent=2))
PYEOF

rm -f "$RESULTS_TMP"

ci_bench_sanity_check "$OUTPUT_FILE" "udp_sweep benchmark"

# ── Summary ──

echo ""
echo "================================================================"
echo "  UDP Rate Sweep Results"
echo "================================================================"

python3 -c "
import json
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
for cond in ['single', 'wlb', 'minrtt']:
    r = data['results'][cond]
    sat = r['saturation_mbps']
    sat_str = f'{sat} Mbps' if sat else 'N/A'
    print(f'  {cond:8s}: saturation = {sat_str}')
"

echo ""
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"
