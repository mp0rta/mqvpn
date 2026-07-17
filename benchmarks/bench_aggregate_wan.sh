#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# bench_aggregate_wan.sh — WAN/EC2 bandwidth aggregation N-sweep
#
# Same structure as bench_aggregate.sh but uses real NICs instead of netns.
# Server is assumed to be running on EC2 — this script runs client-side only.
#
# Output: bench_results/aggregate_wan_<timestamp>.json
#
# Usage: sudo ./bench_aggregate_wan.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="${MQVPN:-${SCRIPT_DIR}/../build/mqvpn}"
RESULTS_DIR="${RESULTS_DIR:-${SCRIPT_DIR}/../bench_results}"

# --- Configuration (override via env vars) ---
SERVER_ADDR="${SERVER_ADDR:-<ec2-ip>:443}"
AUTH_KEY="${AUTH_KEY:-<psk>}"
NIC_A="${NIC_A:-enp4s0}"
NIC_B="${NIC_B:-enp5s0}"
NETEM_A="${NETEM_A:-delay 5ms rate 300mbit}"
NETEM_B="${NETEM_B:-delay 15ms rate 80mbit}"
SCHEDULER="${SCHEDULER:-wlb}"

IPERF_DURATION=10
STREAM_COUNTS=(1 2 4 8 16 32 64)
TUNNEL_SERVER_IP="10.0.0.1"

CLIENT_PID=""

# --- Validation ---
if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    exit 1
fi
MQVPN="$(realpath "$MQVPN")"
mkdir -p "$RESULTS_DIR"

if ! command -v iperf3 &>/dev/null; then
    echo "error: iperf3 not found"
    exit 1
fi

if [[ "$SERVER_ADDR" == *"<ec2-ip>"* ]]; then
    echo "error: Set SERVER_ADDR env var (e.g. SERVER_ADDR=1.2.3.4:443)"
    exit 1
fi
if [[ "$AUTH_KEY" == *"<psk>"* ]]; then
    echo "error: Set AUTH_KEY env var"
    exit 1
fi

# --- Save/restore tc ---
restore_tc() {
    tc qdisc del dev "$NIC_A" root 2>/dev/null || true
    tc qdisc del dev "$NIC_B" root 2>/dev/null || true
}

stop_client() {
    if [ -n "$CLIENT_PID" ] && kill -0 "$CLIENT_PID" 2>/dev/null; then
        kill "$CLIENT_PID" 2>/dev/null || true
        wait "$CLIENT_PID" 2>/dev/null || true
        CLIENT_PID=""
        sleep 1
    fi
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    stop_client
    restore_tc
}
trap cleanup EXIT

echo "================================================================"
echo "  mqvpn Bandwidth Aggregation Benchmark (WAN)"
echo "  Server:  $SERVER_ADDR"
echo "  NIC A:   $NIC_A ($NETEM_A)"
echo "  NIC B:   $NIC_B ($NETEM_B)"
echo "  Sched:   $SCHEDULER"
echo "  Streams: ${STREAM_COUNTS[*]}"
echo "  Date:    $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# --- Apply netem ---
restore_tc
echo "Applying tc netem..."
tc qdisc add dev "$NIC_A" root netem ${NETEM_A}
tc qdisc add dev "$NIC_B" root netem ${NETEM_B}

wait_tunnel() {
    local elapsed=0
    while [ "$elapsed" -lt 15 ]; do
        if ping -c 1 -W 1 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
            echo "OK: tunnel up (${elapsed}s)"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "ERROR: tunnel not reachable"
    return 1
}

start_client() {
    local paths="$1"
    stop_client

    "$MQVPN" \
        --mode client \
        --server "$SERVER_ADDR" \
        ${paths} \
        --auth-key "$AUTH_KEY" \
        --scheduler "$SCHEDULER" \
        --log-level info &
    CLIENT_PID=$!
    sleep 4

    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "ERROR: VPN client process died"
        return 1
    fi
}

# --- Parse netem params ---
DELAY_A=$(echo "$NETEM_A" | grep -oP '\d+(?=ms)' | head -1)
RATE_A=$(echo "$NETEM_A" | grep -oP '\d+(?=mbit)' | head -1)
DELAY_B=$(echo "$NETEM_B" | grep -oP '\d+(?=ms)' | head -1)
RATE_B=$(echo "$NETEM_B" | grep -oP '\d+(?=mbit)' | head -1)

# --- Collect results ---
RESULTS_TMP="$(mktemp)"

for N in "${STREAM_COUNTS[@]}"; do
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Streams: $N"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # --- Single-path ---
    echo "  [1/2] single-path ($NIC_A only)..."
    start_client "--path $NIC_A"
    wait_tunnel

    SINGLE_JSON="$(mktemp)"
    iperf3 -c "$TUNNEL_SERVER_IP" -t "$IPERF_DURATION" \
        -P "$N" --json \
        > "$SINGLE_JSON" 2>&1 || true

    SINGLE_MBPS=$(python3 -c "
import json
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

    stop_client
    sleep 3

    # --- Multipath ---
    echo "  [2/2] multipath ($NIC_A + $NIC_B)..."
    start_client "--path $NIC_A --path $NIC_B"
    wait_tunnel

    MULTI_JSON="$(mktemp)"
    iperf3 -c "$TUNNEL_SERVER_IP" -t "$IPERF_DURATION" \
        -P "$N" --json \
        > "$MULTI_JSON" 2>&1 || true

    MULTI_MBPS=$(python3 -c "
import json
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

    stop_client
    sleep 3
done

# --- Generate output JSON ---
TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${RESULTS_DIR}/aggregate_wan_$(date +%Y%m%d_%H%M%S).json"

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

theoretical_max = ${RATE_A:-300} + ${RATE_B:-80}

output = {
    'test': 'aggregate',
    'env': 'wan',
    'scheduler': '${SCHEDULER}',
    'timestamp': '${TIMESTAMP}',
    'server': '${SERVER_ADDR}',
    'netem': {
        'path_a': {'delay_ms': ${DELAY_A:-5}, 'rate_mbit': ${RATE_A:-300}},
        'path_b': {'delay_ms': ${DELAY_B:-15}, 'rate_mbit': ${RATE_B:-80}}
    },
    'theoretical_max_mbps': theoretical_max,
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

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"
