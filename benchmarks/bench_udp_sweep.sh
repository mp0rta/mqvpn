#!/bin/bash
# bench_udp_sweep.sh — UDP rate sweep benchmark (netns)
#
# Sweeps UDP send rate for single-path vs multipath (wlb / minrtt)
# across two packet sizes (1100B bulk, 160B VoIP).
# Measures throughput, loss rate, and jitter at each rate point.
#
# Output: bench_results/udp_sweep_netns_<timestamp>.json
#
# Usage: sudo ./bench_udp_sweep.sh [-L] [-d SEC] [mqvpn-binary]
#   -L       Add lossy-path test (1% loss on Path B, WLB multipath sweep)
#   -d SEC   iperf3 duration per rate point (default: 15)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/bench_env_setup.sh"

IPERF_DURATION=15
LOSSY_TEST=0
IPERF_SERVER_PID=""

# Packet sizes:
#   "bulk"  = 1100B — fits within typical TUN MTU (1182).
#             1100 + 8 (UDP) + 20 (IP) = 1128 < 1182 TUN MTU.
#   "voip"  =  160B — G.711 20ms frame size.
# Rate sweeps per packet size
RATES_1100=(10 25 50 75 100 125 150 175 200 250 300 350 380)
RATES_160=(1 5 10 20 30 50 75 100 150 200)
PKT_SIZES=(1100 160)

while getopts "Ld:" opt; do
    case "$opt" in
        L) LOSSY_TEST=1 ;;
        d) IPERF_DURATION="$OPTARG" ;;
        *) echo "Usage: $0 [-L] [-d SEC] [mqvpn-binary]"; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

MQVPN="${1:-${MQVPN}}"

trap bench_cleanup EXIT

bench_check_deps

echo "================================================================"
echo "  mqvpn UDP Rate Sweep Benchmark (netns)"
echo "  Binary:    $MQVPN"
echo "  Duration:  ${IPERF_DURATION}s per rate point"
echo "  Lossy:     $([ "$LOSSY_TEST" -eq 1 ] && echo 'yes' || echo 'no')"
echo "  Date:      $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# --- Setup ---
bench_setup_netns
bench_apply_netem
bench_start_vpn_server

# --- Temp directory for sweep data ---
SWEEP_DIR="$(mktemp -d)"
MANIFEST="${SWEEP_DIR}/manifest.txt"
: > "$MANIFEST"

# --- Helpers ---
get_rates_for_pkt() {
    local pkt_size=$1
    if [ "$pkt_size" -eq 1100 ]; then
        echo "${RATES_1100[@]}"
    else
        echo "${RATES_160[@]}"
    fi
}

# Run a single UDP iperf3 measurement and append results to tmp file
run_udp_point() {
    local rate=$1
    local pkt_size=$2
    local results_file=$3

    ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" -1 &>/dev/null &
    IPERF_SERVER_PID=$!
    sleep 1

    local iperf_json
    iperf_json="$(mktemp)"
    ip netns exec "$NS_CLIENT" iperf3 \
        -u -c "$TUNNEL_SERVER_IP" \
        -b "${rate}M" -l "$pkt_size" \
        -t "$IPERF_DURATION" --json \
        > "$iperf_json" 2>/dev/null || true

    wait "$IPERF_SERVER_PID" 2>/dev/null || true
    IPERF_SERVER_PID=""

    # Extract UDP metrics (receiver-side stats from server report)
    python3 -c "
import json, sys
try:
    with open('${iperf_json}') as f:
        data = json.load(f)
    if 'error' in data:
        print('0.00 0.0000 0.0000')
        print(f'  iperf3: {data[\"error\"]}', file=sys.stderr)
    else:
        end = data.get('end', {})
        s = end.get('sum', {})
        tput = s.get('bits_per_second', 0) / 1e6
        lost = s.get('lost_percent', 0)
        jitter = s.get('jitter_ms', 0)
        print(f'{tput:.2f} {lost:.4f} {jitter:.4f}')
except Exception as e:
    print('0.00 0.0000 0.0000')
    print(f'  parse error: {e}', file=sys.stderr)
" >> "$results_file"

    rm -f "$iperf_json"
    sleep 2
}

# Run a full rate sweep for one condition
run_sweep() {
    local condition=$1
    local scheduler=$2
    local pkt_size=$3
    local results_file=$4

    local rates
    rates=($(get_rates_for_pkt "$pkt_size"))

    echo ""
    echo "  -- ${condition} / ${scheduler} / ${pkt_size}B --"

    for rate in "${rates[@]}"; do
        printf "    %4d Mbps ... " "$rate"
        echo -n "${rate} " >> "$results_file"
        run_udp_point "$rate" "$pkt_size" "$results_file"

        # Read back the last line to show progress
        local last
        last=$(tail -1 "$results_file")
        local tput lost jitter
        read -r _ tput lost jitter <<< "$last"
        printf "tput=%s Mbps  loss=%s%%  jitter=%s ms\n" "$tput" "$lost" "$jitter"
    done
}

# Register a sweep: writes condition:scheduler:pkt_size:filepath to manifest
register_sweep() {
    local condition=$1
    local scheduler=$2
    local pkt_size=$3
    local filepath=$4
    echo "${condition}:${scheduler}:${pkt_size}:${filepath}" >> "$MANIFEST"
}

# --- Main sweep loop ---
for pkt_size in "${PKT_SIZES[@]}"; do
    echo ""
    echo "================================================================"
    echo "  Packet size: ${pkt_size} bytes"
    echo "================================================================"

    # 1) Single-path (Path A only) — WLB scheduler
    TMP_SINGLE="${SWEEP_DIR}/single_path_wlb_${pkt_size}.dat"
    : > "$TMP_SINGLE"

    bench_start_vpn_client "--path $VETH_A0"
    bench_wait_tunnel 15
    run_sweep "single_path" "wlb" "$pkt_size" "$TMP_SINGLE"
    bench_stop_vpn_client
    register_sweep "single_path" "wlb" "$pkt_size" "$TMP_SINGLE"
    sleep 3

    # 2) Multipath WLB (Path A + B)
    TMP_WLB="${SWEEP_DIR}/multipath_wlb_${pkt_size}.dat"
    : > "$TMP_WLB"

    bench_start_vpn_client "--path $VETH_A0 --path $VETH_B0"
    bench_wait_tunnel 15
    run_sweep "multipath" "wlb" "$pkt_size" "$TMP_WLB"
    bench_stop_vpn_client
    register_sweep "multipath" "wlb" "$pkt_size" "$TMP_WLB"
    sleep 3

    # 3) Switch to MinRTT scheduler
    bench_stop_vpn
    sleep 2
    BENCH_SCHEDULER=minrtt
    bench_start_vpn_server

    TMP_MINRTT="${SWEEP_DIR}/multipath_minrtt_${pkt_size}.dat"
    : > "$TMP_MINRTT"

    bench_start_vpn_client "--path $VETH_A0 --path $VETH_B0"
    bench_wait_tunnel 15
    run_sweep "multipath" "minrtt" "$pkt_size" "$TMP_MINRTT"
    bench_stop_vpn_client
    register_sweep "multipath" "minrtt" "$pkt_size" "$TMP_MINRTT"
    sleep 3

    # 4) Switch back to WLB for next iteration (or lossy test)
    bench_stop_vpn
    sleep 2
    BENCH_SCHEDULER=wlb
    bench_start_vpn_server

    # 5) Optional: lossy-path test
    if [ "$LOSSY_TEST" -eq 1 ]; then
        echo ""
        echo "  -- Adding 1% loss to Path B for lossy test --"
        bench_apply_netem "delay 10ms rate 300mbit" "delay 30ms rate 80mbit loss 1%"

        TMP_LOSSY="${SWEEP_DIR}/multipath_lossy_wlb_${pkt_size}.dat"
        : > "$TMP_LOSSY"

        bench_start_vpn_client "--path $VETH_A0 --path $VETH_B0"
        bench_wait_tunnel 15
        run_sweep "multipath_lossy" "wlb" "$pkt_size" "$TMP_LOSSY"
        bench_stop_vpn_client
        register_sweep "multipath_lossy" "wlb" "$pkt_size" "$TMP_LOSSY"
        sleep 3

        # Restore normal netem
        bench_apply_netem
    fi
done

# --- Generate output JSON ---
TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${RESULTS_DIR}/udp_sweep_netns_$(date +%Y%m%d_%H%M%S).json"

python3 - "$OUTPUT_FILE" "$TIMESTAMP" "$MANIFEST" <<'PYEOF'
import json, sys

output_file = sys.argv[1]
timestamp = sys.argv[2]
manifest_file = sys.argv[3]

output = {
    'test': 'udp_sweep',
    'env': 'netns',
    'timestamp': timestamp,
    'netem': {
        'path_a': {'delay_ms': 10, 'rate_mbit': 300},
        'path_b': {'delay_ms': 30, 'rate_mbit': 80}
    },
    'theoretical_max_mbps': 380,
    'sweeps': []
}

with open(manifest_file) as mf:
    for line in mf:
        line = line.strip()
        if not line:
            continue
        condition, scheduler, pkt_str, filepath = line.split(':', 3)
        results = []
        with open(filepath) as f:
            for row in f:
                parts = row.strip().split()
                if len(parts) == 4:
                    results.append({
                        'target_mbps': int(parts[0]),
                        'throughput_mbps': float(parts[1]),
                        'lost_percent': float(parts[2]),
                        'jitter_ms': float(parts[3])
                    })
        output['sweeps'].append({
            'condition': condition,
            'scheduler': scheduler,
            'packet_size': int(pkt_str),
            'results': results
        })

# Sort sweeps for consistent ordering
cond_order = {'single_path': 0, 'multipath': 1, 'multipath_lossy': 2}
sched_order = {'wlb': 0, 'minrtt': 1}
output['sweeps'].sort(key=lambda s: (
    s['packet_size'],
    cond_order.get(s['condition'], 9),
    sched_order.get(s['scheduler'], 9)
))

with open(output_file, 'w') as f:
    json.dump(output, f, indent=2)

# Summary table
print()
print('Results summary:')
for sw in output['sweeps']:
    print(f"\n  {sw['condition']} / {sw['scheduler']} / {sw['packet_size']}B:")
    print(f"  {'Rate':>8}  {'Tput':>10}  {'Loss':>8}  {'Jitter':>8}")
    for r in sw['results']:
        print(f"  {r['target_mbps']:>6} M  {r['throughput_mbps']:>8.1f} M  "
              f"{r['lost_percent']:>6.2f}%  {r['jitter_ms']:>6.2f}ms")
PYEOF

# Clean up temp files
rm -rf "$SWEEP_DIR"

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"
