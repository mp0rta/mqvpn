#!/bin/bash
# ci_stress_reconnect.sh — 500-cycle connect/disconnect stress test
#
# Validates that the VPN server survives many client reconnections without
# resource leaks (RSS growth, fd leaks). Each cycle: start client, wait for
# tunnel, verify connectivity, stop client.
#
# Usage:
#   sudo ./ci_stress_reconnect.sh [path/to/mqvpn]
#
# Requires root (network namespaces).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/ci_stress_env.sh"

# Override MQVPN if passed as argument
if [ "${1:-}" != "" ]; then
    MQVPN="$1"
fi

TOTAL_CYCLES=500
TUNNEL_TIMEOUT=15
PROGRESS_INTERVAL=50

trap ci_stress_cleanup EXIT

# ── Pre-flight ──

ci_stress_check_deps

# ── Setup ──

echo "=== ci_stress_reconnect: ${TOTAL_CYCLES}-cycle connect/disconnect ==="
echo ""

ci_stress_setup_netns
ci_stress_apply_netem

# ── Start VPN server ──

ci_stress_start_server wlb

SERVER_MONITOR_LOG="${CI_STRESS_RESULTS}/reconnect_server_monitor.log"
ci_stress_monitor_start "$_CS_SERVER_PID" "$SERVER_MONITOR_LOG"

# ── Reconnect loop ──

cycles_ok=0
cycles_failed=0
total_cycle_ns=0

echo ""
echo "Starting ${TOTAL_CYCLES}-cycle reconnect loop..."
echo ""

IP_B_SERVER_ADDR="10.200.0.1"

for i in $(seq 1 "$TOTAL_CYCLES"); do
    cycle_start=$(date +%s%N)

    # Rotate path config: A only, B only, A+B multipath
    case $((i % 3)) in
        0) paths="--path $VETH_A0"; server_addr="${IP_A_SERVER_ADDR}" ;;
        1) paths="--path $VETH_B0"; server_addr="${IP_B_SERVER_ADDR}" ;;
        2) paths="--path $VETH_A0 --path $VETH_B0"; server_addr="${IP_A_SERVER_ADDR}" ;;
    esac

    # Start client
    if ! ci_stress_start_client "$paths" wlb "$server_addr" 2>/dev/null; then
        cycles_failed=$((cycles_failed + 1))
        ci_stress_stop_client
        cycle_end=$(date +%s%N)
        total_cycle_ns=$((total_cycle_ns + cycle_end - cycle_start))
        continue
    fi

    # Wait for tunnel
    if ! ci_stress_wait_tunnel "$TUNNEL_TIMEOUT" 2>/dev/null; then
        cycles_failed=$((cycles_failed + 1))
        ci_stress_stop_client
        cycle_end=$(date +%s%N)
        total_cycle_ns=$((total_cycle_ns + cycle_end - cycle_start))
        continue
    fi

    # Verify connectivity through tunnel
    if ! ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
        cycles_failed=$((cycles_failed + 1))
        ci_stress_stop_client
        cycle_end=$(date +%s%N)
        total_cycle_ns=$((total_cycle_ns + cycle_end - cycle_start))
        continue
    fi

    # Stop client
    ci_stress_stop_client

    cycle_end=$(date +%s%N)
    cycle_ns=$((cycle_end - cycle_start))
    total_cycle_ns=$((total_cycle_ns + cycle_ns))
    cycles_ok=$((cycles_ok + 1))

    # Progress report
    if [ $((i % PROGRESS_INTERVAL)) -eq 0 ]; then
        avg_ms=$((total_cycle_ns / i / 1000000))
        echo "[${i}/${TOTAL_CYCLES}] ok=${cycles_ok} fail=${cycles_failed} avg=${avg_ms}ms/cycle"
    fi
done

echo ""
echo "Reconnect loop complete."

# ── Stop monitors and server ──

ci_stress_monitor_stop
ci_stress_stop_vpn

# ── Resource check ──

echo ""
echo "=== Resource check ==="

resource_status="pass"
if ! ci_stress_check_resources "$SERVER_MONITOR_LOG" "server"; then
    resource_status="fail"
fi

echo ""
echo "=== Sanitizer check ==="
if ! ci_stress_check_sanitizer; then
    resource_status="fail"
fi

# ── Extract server RSS from monitor log ──

read -r server_rss_initial server_rss_final server_rss_max <<< "$(python3 -c "
lines = open('${SERVER_MONITOR_LOG}').read().strip().split('\n')
samples = []
for line in lines:
    parts = line.split()
    if len(parts) >= 2:
        samples.append(int(parts[1]))
if samples:
    print(samples[0], samples[-1], max(samples))
else:
    print(0, 0, 0)
")"

# ── Compute average cycle time ──

completed=$((cycles_ok + cycles_failed))
if [ "$completed" -gt 0 ]; then
    avg_cycle_sec=$(python3 -c "print(f'{${total_cycle_ns} / ${completed} / 1e9:.3f}')")
else
    avg_cycle_sec="0.000"
fi

# ── Determine overall status ──

if [ "$resource_status" = "fail" ]; then
    overall_status="fail"
elif [ "$cycles_failed" -gt $((TOTAL_CYCLES / 10)) ]; then
    # More than 10% failures
    overall_status="fail"
else
    overall_status="pass"
fi

# ── Output summary JSON ──

timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
output_file="${CI_STRESS_RESULTS}/reconnect_$(date +%s).json"

python3 -c "
import json, sys

result = {
    'test': 'reconnect',
    'commit': '${CI_STRESS_COMMIT}',
    'timestamp': '${timestamp}',
    'cycles_total': ${TOTAL_CYCLES},
    'cycles_ok': ${cycles_ok},
    'cycles_failed': ${cycles_failed},
    'avg_cycle_sec': float('${avg_cycle_sec}'),
    'server_rss_initial_kb': ${server_rss_initial},
    'server_rss_final_kb': ${server_rss_final},
    'server_rss_max_kb': ${server_rss_max},
    'status': '${overall_status}'
}

with open('${output_file}', 'w') as f:
    json.dump(result, f, indent=2)
    f.write('\n')

json.dump(result, sys.stdout, indent=2)
print()
"

echo ""
echo "Results written to: ${output_file}"

if [ "$overall_status" = "fail" ]; then
    echo "RESULT: FAIL"
    exit 1
else
    echo "RESULT: PASS"
    exit 0
fi
