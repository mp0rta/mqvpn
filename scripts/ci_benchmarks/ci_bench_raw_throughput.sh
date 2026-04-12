#!/bin/bash
# ci_bench_raw_throughput.sh — Raw throughput benchmark (TCP DL only, no netem)
#
# Measures VPN overhead by comparing direct veth throughput against VPN throughput.
# No tc netem is applied — veth pairs run at native kernel speed.
#
# Tests:
#   1. Direct (no VPN)        — baseline veth throughput via iperf3 across netns
#   2. Single-path VPN        — 1 path (ci-a0 only)
#   3. Multipath VPN (MinRTT) — 2 paths
#   4. Multipath VPN (WLB)    — 2 paths
#
# Output: ci_bench_results/raw_throughput_<timestamp>.json
#
# Usage: sudo ./ci_bench_raw_throughput.sh [path-to-mqvpn-binary]

set -euo pipefail

source "$(dirname "$0")/ci_bench_env.sh"

MQVPN="${1:-${MQVPN}}"

DURATION=10
PARALLEL=4

# ── Preflight ──

ci_bench_check_deps

trap ci_bench_cleanup EXIT

# ── Setup ──

ci_bench_setup_netns

echo ""
echo "================================================================"
echo "  CI Raw Throughput Benchmark (TCP DL, no netem)"
echo "  Binary:    $MQVPN"
echo "  Duration:  ${DURATION}s"
echo "  Parallel:  ${PARALLEL} streams"
echo "  Commit:    ${CI_BENCH_COMMIT}"
echo "  Date:      $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"
echo ""

# ── 1/4  Direct (no VPN) — baseline veth throughput ──

echo "==> 1/4  Direct (no VPN) — baseline veth throughput"

# For the direct test we run iperf3 manually across the veth IPs (no tunnel).
# Server in server-ns, client in client-ns, DL = server -> client (-R).
ip netns exec "$NS_SERVER" iperf3 -s -B "$IP_A_SERVER_ADDR" -1 &>/dev/null &
_direct_iperf_srv=$!
sleep 1

direct_json="$(mktemp)"
ip netns exec "$NS_CLIENT" iperf3 \
    -c "$IP_A_SERVER_ADDR" \
    -t "$DURATION" -P "$PARALLEL" -R --json > "$direct_json" 2>&1 || true

wait "$_direct_iperf_srv" 2>/dev/null || true

direct_mbps=$(ci_bench_parse_throughput "$direct_json")
rm -f "$direct_json"
echo "    Direct:  ${direct_mbps} Mbps"

# ── 2/4  Single-path VPN ──

echo ""
echo "==> 2/4  Single-path VPN (1 path, WLB)"

ci_bench_start_server "wlb"
ci_bench_start_client "--path $VETH_A0" "wlb"
ci_bench_wait_tunnel

sp_json=$(ci_bench_run_iperf TCP DL "$DURATION" "$PARALLEL")
single_path_mbps=$(ci_bench_parse_throughput "$sp_json")
rm -f "$sp_json"
echo "    Single-path:  ${single_path_mbps} Mbps"

ci_bench_stop_vpn

# ── 3/4  Multipath VPN (MinRTT) ──

echo ""
echo "==> 3/4  Multipath VPN — MinRTT (2 paths)"

ci_bench_start_server "minrtt"
ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "minrtt"
ci_bench_wait_tunnel

mp_minrtt_json=$(ci_bench_run_iperf TCP DL "$DURATION" "$PARALLEL")
multipath_minrtt_mbps=$(ci_bench_parse_throughput "$mp_minrtt_json")
rm -f "$mp_minrtt_json"
echo "    Multipath MinRTT:  ${multipath_minrtt_mbps} Mbps"

ci_bench_stop_vpn

# ── 4/4  Multipath VPN (WLB) ──

echo ""
echo "==> 4/4  Multipath VPN — WLB (2 paths)"

ci_bench_start_server "wlb"
ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "wlb"
ci_bench_wait_tunnel

mp_wlb_json=$(ci_bench_run_iperf TCP DL "$DURATION" "$PARALLEL")
multipath_wlb_mbps=$(ci_bench_parse_throughput "$mp_wlb_json")
rm -f "$mp_wlb_json"
echo "    Multipath WLB:  ${multipath_wlb_mbps} Mbps"

ci_bench_stop_vpn

# ── Generate JSON output ──

echo ""
echo "Generating JSON output..."

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
OUTPUT_FILE="${CI_BENCH_RESULTS}/raw_throughput_$(date -u '+%Y%m%d_%H%M%S').json"

python3 <<PYEOF
import json

direct = float("${direct_mbps}")
single = float("${single_path_mbps}")
minrtt = float("${multipath_minrtt_mbps}")
wlb    = float("${multipath_wlb_mbps}")

def overhead(baseline, measured):
    if baseline > 0 and measured > 0:
        return round((1 - measured / baseline) * 100, 1)
    return None

result = {
    "test": "raw_throughput",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "${TIMESTAMP}",
    "protocol": "tcp",
    "direction": "dl",
    "duration_sec": ${DURATION},
    "parallel_streams": ${PARALLEL},
    "results": {
        "direct_mbps": direct,
        "single_path_mbps": single,
        "multipath_minrtt_mbps": minrtt,
        "multipath_wlb_mbps": wlb
    },
    "overhead_pct": {
        "single_path": overhead(direct, single),
        "multipath_minrtt": overhead(direct, minrtt),
        "multipath_wlb": overhead(direct, wlb)
    }
}

with open("${OUTPUT_FILE}", "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
PYEOF

echo ""
echo "Results written to: ${OUTPUT_FILE}"

# ── Sanity check ──

ci_bench_sanity_check "$OUTPUT_FILE" "raw_throughput"

echo ""
echo "================================================================"
echo "  Raw Throughput Benchmark DONE"
echo "================================================================"
