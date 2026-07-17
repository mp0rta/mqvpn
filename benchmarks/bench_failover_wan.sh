#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# bench_failover_wan.sh — WAN/EC2 failover TTR measurement
#
# Same structure as bench_failover.sh but uses real NICs instead of netns.
# Server is assumed to be running on EC2 — this script runs client-side only.
#
# Fault injection uses tc loss 100% instead of link down.
# Existing tc qdiscs are saved and restored on exit.
#
# Output: bench_results/failover_wan_<timestamp>.json
#
# Usage: sudo ./bench_failover_wan.sh

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

DURATION=60
INTERVAL=0.5
FAULT_INJECT_SEC=20
FAULT_RECOVER_SEC=40
TUNNEL_SERVER_IP="10.0.0.1"

CLIENT_PID=""
IPERF_SERVER_PID=""
SAVED_TC_A=""
SAVED_TC_B=""

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
save_tc() {
    SAVED_TC_A="$(tc qdisc show dev "$NIC_A" 2>/dev/null || true)"
    SAVED_TC_B="$(tc qdisc show dev "$NIC_B" 2>/dev/null || true)"
}

restore_tc() {
    tc qdisc del dev "$NIC_A" root 2>/dev/null || true
    tc qdisc del dev "$NIC_B" root 2>/dev/null || true
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    CLIENT_PID=""
    restore_tc
}
trap cleanup EXIT

echo "================================================================"
echo "  mqvpn Failover TTR Benchmark (WAN)"
echo "  Server:  $SERVER_ADDR"
echo "  NIC A:   $NIC_A ($NETEM_A)"
echo "  NIC B:   $NIC_B ($NETEM_B)"
echo "  Sched:   $SCHEDULER"
echo "  Date:    $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# --- Save existing tc and apply netem ---
save_tc
restore_tc

echo "Applying tc netem..."
tc qdisc add dev "$NIC_A" root netem ${NETEM_A}
tc qdisc add dev "$NIC_B" root netem ${NETEM_B}

# --- Start VPN client ---
echo "Starting mqvpn client..."
"$MQVPN" \
    --mode client \
    --server "$SERVER_ADDR" \
    --path "$NIC_A" --path "$NIC_B" \
    --auth-key "$AUTH_KEY" \
    --scheduler "$SCHEDULER" \
    --log-level info &
CLIENT_PID=$!
sleep 4

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "ERROR: VPN client process died"
    exit 1
fi

# --- Wait for tunnel ---
echo "Waiting for tunnel..."
ELAPSED=0
while [ "$ELAPSED" -lt 15 ]; do
    if ping -c 1 -W 1 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
        echo "OK: tunnel up (${ELAPSED}s)"
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
if [ "$ELAPSED" -ge 15 ]; then
    echo "ERROR: tunnel not reachable"
    exit 1
fi

# --- iperf3 (JSON output) ---
IPERF_JSON="$(mktemp)"
echo "Starting iperf3 for ${DURATION}s (interval=${INTERVAL}s, JSON)..."
iperf3 -c "$TUNNEL_SERVER_IP" -t "$DURATION" \
    --interval "$INTERVAL" --json \
    > "$IPERF_JSON" 2>&1 &
IPERF_CLIENT_PID=$!

# --- Fault injection at t=20s (tc loss 100% on Path A) ---
sleep "$FAULT_INJECT_SEC"
echo "[$(date +%T)] FAULT INJECT: adding 100% loss to $NIC_A"
tc qdisc change dev "$NIC_A" root netem ${NETEM_A} loss 100%

# --- Fault recovery at t=40s ---
WAIT_RECOVER=$((FAULT_RECOVER_SEC - FAULT_INJECT_SEC))
sleep "$WAIT_RECOVER"
echo "[$(date +%T)] FAULT RECOVER: restoring $NIC_A netem"
tc qdisc change dev "$NIC_A" root netem ${NETEM_A}

# --- Wait for iperf3 ---
echo "Waiting for iperf3 to complete..."
wait "$IPERF_CLIENT_PID" || true

# --- Parse netem params for JSON ---
# Extract delay_ms and rate_mbit from NETEM strings
DELAY_A=$(echo "$NETEM_A" | grep -oP '\d+(?=ms)' | head -1)
RATE_A=$(echo "$NETEM_A" | grep -oP '\d+(?=mbit)' | head -1)
DELAY_B=$(echo "$NETEM_B" | grep -oP '\d+(?=ms)' | head -1)
RATE_B=$(echo "$NETEM_B" | grep -oP '\d+(?=mbit)' | head -1)

# --- Generate output JSON ---
TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${RESULTS_DIR}/failover_wan_$(date +%Y%m%d_%H%M%S).json"

python3 -c "
import json

with open('${IPERF_JSON}') as f:
    raw = json.load(f)

intervals = []
for iv in raw.get('intervals', []):
    s = iv['sum']
    intervals.append({
        'time_sec': round(s['end'], 2),
        'mbps': round(s['bits_per_second'] / 1e6, 1)
    })

fault_inject = ${FAULT_INJECT_SEC}
fault_recover = ${FAULT_RECOVER_SEC}

pre_fault = [iv['mbps'] for iv in intervals if iv['time_sec'] <= fault_inject]
pre_fault_avg = sum(pre_fault) / len(pre_fault) if pre_fault else 0

threshold = pre_fault_avg * 0.9
ttr = None
for iv in intervals:
    if iv['time_sec'] > fault_inject and iv['mbps'] >= threshold:
        ttr = round(iv['time_sec'] - fault_inject, 2)
        break

post_recover = [iv['mbps'] for iv in intervals if iv['time_sec'] > fault_recover + 2]
post_recover_avg = sum(post_recover) / len(post_recover) if post_recover else 0

result = {
    'test': 'failover',
    'env': 'wan',
    'scheduler': '${SCHEDULER}',
    'timestamp': '${TIMESTAMP}',
    'server': '${SERVER_ADDR}',
    'netem': {
        'path_a': {'delay_ms': ${DELAY_A:-5}, 'rate_mbit': ${RATE_A:-300}},
        'path_b': {'delay_ms': ${DELAY_B:-15}, 'rate_mbit': ${RATE_B:-80}}
    },
    'duration_sec': ${DURATION},
    'fault_inject_sec': fault_inject,
    'fault_recover_sec': fault_recover,
    'intervals': intervals,
    'pre_fault_avg_mbps': round(pre_fault_avg, 1),
    'ttr_sec': ttr,
    'post_recover_avg_mbps': round(post_recover_avg, 1)
}

with open('${OUTPUT_FILE}', 'w') as f:
    json.dump(result, f, indent=2)

print(f'Pre-fault avg:     {pre_fault_avg:.1f} Mbps')
print(f'TTR:               {ttr} sec')
print(f'Post-recover avg:  {post_recover_avg:.1f} Mbps')
"

rm -f "$IPERF_JSON"

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"
