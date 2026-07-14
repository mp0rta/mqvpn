#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# ci_bench_raw_throughput.sh — Raw throughput benchmark (no netem)
#
# Measures VPN overhead by comparing direct veth throughput against VPN throughput.
# No tc netem is applied — veth pairs run at native kernel speed.
#
# Tests (per direction):
#   1. Direct (no VPN)        — baseline veth throughput via iperf3 across netns
#   2. Single-path VPN        — 1 path (ci-a0 only)
#   3. Multipath VPN (MinRTT) — 2 paths
#   4. Multipath VPN (WLB)    — 2 paths
#
# Output: ci_bench_results/raw_throughput_<timestamp>.json
#
# Usage: sudo ./ci_bench_raw_throughput.sh [--full] [path-to-mqvpn-binary]
#   --full: run both DL and UL (default: DL only)

set -euo pipefail

source "$(dirname "$0")/ci_bench_env.sh"

FULL_MODE=0
if [ "${1:-}" = "--full" ]; then
    FULL_MODE=1
    shift
fi

MQVPN="${1:-${MQVPN}}"

DURATION=10
PARALLEL=4
DIRECTIONS=("DL")
[ "$FULL_MODE" -eq 1 ] && DIRECTIONS=("DL" "UL")

# ── Preflight ──

ci_bench_check_deps

trap ci_bench_cleanup EXIT

# ── Setup ──

ci_bench_setup_netns

DIR_LABEL=$(IFS='+'; echo "${DIRECTIONS[*]}")
echo ""
echo "================================================================"
echo "  CI Raw Throughput Benchmark (TCP ${DIR_LABEL}, no netem)"
echo "  Binary:    $MQVPN"
echo "  Duration:  ${DURATION}s"
echo "  Parallel:  ${PARALLEL} streams"
echo "  Commit:    ${CI_BENCH_COMMIT}"
echo "  Date:      $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# Collect results per direction
declare -A R_DIRECT R_SINGLE R_MINRTT R_WLB

for DIR in "${DIRECTIONS[@]}"; do
    echo ""
    echo "================================================================"
    echo "  Direction: $DIR"
    echo "================================================================"

    IPERF_R_FLAG=""
    [ "$DIR" = "DL" ] && IPERF_R_FLAG="-R"

    # ── Direct (no VPN) ──
    echo ""
    echo "==> Direct (no VPN) — baseline"

    ip netns exec "$NS_SERVER" iperf3 -s -B "$IP_A_SERVER_ADDR" -1 &>/dev/null &
    _direct_srv=$!
    sleep 1

    direct_json="$(mktemp)"
    ip netns exec "$NS_CLIENT" iperf3 \
        -c "$IP_A_SERVER_ADDR" \
        -t "$DURATION" -P "$PARALLEL" $IPERF_R_FLAG --json > "$direct_json" 2>&1 || true
    wait "$_direct_srv" 2>/dev/null || true

    R_DIRECT[$DIR]=$(ci_bench_parse_throughput "$direct_json")
    rm -f "$direct_json"
    echo "    Direct:  ${R_DIRECT[$DIR]} Mbps"

    # ── Single-path VPN ──
    echo ""
    echo "==> Single-path VPN"

    ci_bench_start_server "wlb"
    ci_bench_start_client "--path $VETH_A0" "wlb"
    ci_bench_wait_tunnel

    sp_json=$(ci_bench_run_iperf TCP "$DIR" "$DURATION" "$PARALLEL")
    R_SINGLE[$DIR]=$(ci_bench_parse_throughput "$sp_json")
    rm -f "$sp_json"
    echo "    Single-path:  ${R_SINGLE[$DIR]} Mbps"

    ci_bench_stop_vpn

    # ── Multipath MinRTT ──
    echo ""
    echo "==> Multipath VPN — MinRTT"

    ci_bench_start_server "minrtt"
    ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "minrtt"
    ci_bench_wait_tunnel

    mr_json=$(ci_bench_run_iperf TCP "$DIR" "$DURATION" "$PARALLEL")
    R_MINRTT[$DIR]=$(ci_bench_parse_throughput "$mr_json")
    rm -f "$mr_json"
    echo "    Multipath MinRTT:  ${R_MINRTT[$DIR]} Mbps"

    ci_bench_stop_vpn

    # ── Multipath WLB ──
    echo ""
    echo "==> Multipath VPN — WLB"

    ci_bench_start_server "wlb"
    ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "wlb"
    ci_bench_wait_tunnel

    wlb_json=$(ci_bench_run_iperf TCP "$DIR" "$DURATION" "$PARALLEL")
    R_WLB[$DIR]=$(ci_bench_parse_throughput "$wlb_json")
    rm -f "$wlb_json"
    echo "    Multipath WLB:  ${R_WLB[$DIR]} Mbps"

    ci_bench_stop_vpn
done

# ── Generate JSON output ──

echo ""
echo "Generating JSON output..."

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
OUTPUT_FILE="${CI_BENCH_RESULTS}/raw_throughput_$(date -u '+%Y%m%d_%H%M%S').json"

python3 <<PYEOF
import json

def overhead(baseline, measured):
    if baseline > 0 and measured > 0:
        return round((1 - measured / baseline) * 100, 1)
    return None

directions = {}
$(for DIR in "${DIRECTIONS[@]}"; do
cat <<INNER
directions["${DIR}"] = {
    "direct_mbps": float("${R_DIRECT[$DIR]}"),
    "single_path_mbps": float("${R_SINGLE[$DIR]}"),
    "multipath_minrtt_mbps": float("${R_MINRTT[$DIR]}"),
    "multipath_wlb_mbps": float("${R_WLB[$DIR]}"),
}
INNER
done)

results = {}
overhead_pct = {}
for d, v in directions.items():
    results[d] = v
    overhead_pct[d] = {
        "single_path": overhead(v["direct_mbps"], v["single_path_mbps"]),
        "multipath_minrtt": overhead(v["direct_mbps"], v["multipath_minrtt_mbps"]),
        "multipath_wlb": overhead(v["direct_mbps"], v["multipath_wlb_mbps"]),
    }

output = {
    "test": "raw_throughput",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "${TIMESTAMP}",
    "protocol": "tcp",
    "directions": list(directions.keys()),
    "duration_sec": ${DURATION},
    "parallel_streams": ${PARALLEL},
    "results": results,
    "overhead_pct": overhead_pct,
}

with open("${OUTPUT_FILE}", "w") as f:
    json.dump(output, f, indent=2)

print(json.dumps(output, indent=2))
PYEOF

echo ""
echo "Results written to: ${OUTPUT_FILE}"

# ── Sanity check ──

ci_bench_sanity_check "$OUTPUT_FILE" "raw_throughput"

echo ""
echo "================================================================"
echo "  Raw Throughput Benchmark DONE"
echo "================================================================"
