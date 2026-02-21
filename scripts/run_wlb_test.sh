#!/bin/bash
# run_wlb_test.sh — WLB scheduler non-regression test
#
# Verifies WLB scheduler matches MinRTT throughput (no regression) while
# providing flow-affinity benefits.  Both schedulers aggregate bandwidth
# across paths; WLB's advantage is flow-level pinning (less TCP reordering).
#
# Two scenarios: equal paths (2 × 50Mbps) and asymmetric paths (100 + 50Mbps).
# Pass criteria: WLB >= 0.9× MinRTT (no significant throughput regression).
#
# Usage: sudo ./run_wlb_test.sh [path-to-mqvpn-binary]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="${1:-${SCRIPT_DIR}/../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    echo "Build first: cd build && cmake .. && make -j"
    exit 1
fi

if ! command -v iperf3 &>/dev/null; then
    echo "error: iperf3 not found. Install: sudo apt install iperf3"
    exit 1
fi

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

IPERF_DURATION=15
IPERF_PARALLEL=4
TUNNEL_WAIT=5

# Result storage
declare -A RESULTS

SERVER_PID=""
CLIENT_PID=""
IPERF_SERVER_PID=""

# ================================================================
#  Setup / Cleanup
# ================================================================

generate_cert() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
        -days 365 -nodes -subj "/CN=mqvpn-wlb-test" 2>/dev/null
}

setup_netns() {
    # Clean leftovers
    ip netns del wlb-server 2>/dev/null || true
    ip netns del wlb-client 2>/dev/null || true
    ip link del wlb-a0 2>/dev/null || true
    ip link del wlb-b0 2>/dev/null || true

    ip netns add wlb-server
    ip netns add wlb-client

    # Path A: 192.168.10.0/24
    ip link add wlb-a0 type veth peer name wlb-a1
    ip link set wlb-a0 netns wlb-client
    ip link set wlb-a1 netns wlb-server
    ip netns exec wlb-client ip addr add 192.168.10.1/24 dev wlb-a0
    ip netns exec wlb-server ip addr add 192.168.10.2/24 dev wlb-a1
    ip netns exec wlb-client ip link set wlb-a0 up
    ip netns exec wlb-server ip link set wlb-a1 up

    # Path B: 192.168.20.0/24
    ip link add wlb-b0 type veth peer name wlb-b1
    ip link set wlb-b0 netns wlb-client
    ip link set wlb-b1 netns wlb-server
    ip netns exec wlb-client ip addr add 192.168.20.1/24 dev wlb-b0
    ip netns exec wlb-server ip addr add 192.168.20.2/24 dev wlb-b1
    ip netns exec wlb-client ip link set wlb-b0 up
    ip netns exec wlb-server ip link set wlb-b1 up

    # Loopback
    ip netns exec wlb-client ip link set lo up
    ip netns exec wlb-server ip link set lo up

    # IP forwarding
    ip netns exec wlb-server sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # Verify
    ip netns exec wlb-client ping -c 1 -W 1 192.168.10.2 >/dev/null
    ip netns exec wlb-client ping -c 1 -W 1 192.168.20.2 >/dev/null
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$IPERF_SERVER_PID" ] && kill "$IPERF_SERVER_PID" 2>/dev/null || true
    kill_vpn
    clear_tc
    ip netns del wlb-server 2>/dev/null || true
    ip netns del wlb-client 2>/dev/null || true
    ip link del wlb-a0 2>/dev/null || true
    ip link del wlb-b0 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# ================================================================
#  tc netem helpers
# ================================================================

apply_tc() {
    local rate_a="$1" delay_a="$2" rate_b="$3" delay_b="$4"

    clear_tc

    # Apply on both ends for realistic behavior
    ip netns exec wlb-client tc qdisc add dev wlb-a0 root netem delay "${delay_a}" rate "${rate_a}"
    ip netns exec wlb-server tc qdisc add dev wlb-a1 root netem delay "${delay_a}" rate "${rate_a}"
    ip netns exec wlb-client tc qdisc add dev wlb-b0 root netem delay "${delay_b}" rate "${rate_b}"
    ip netns exec wlb-server tc qdisc add dev wlb-b1 root netem delay "${delay_b}" rate "${rate_b}"
}

clear_tc() {
    ip netns exec wlb-client tc qdisc del dev wlb-a0 root 2>/dev/null || true
    ip netns exec wlb-server tc qdisc del dev wlb-a1 root 2>/dev/null || true
    ip netns exec wlb-client tc qdisc del dev wlb-b0 root 2>/dev/null || true
    ip netns exec wlb-server tc qdisc del dev wlb-b1 root 2>/dev/null || true
}

# ================================================================
#  VPN start / stop
# ================================================================

run_vpn() {
    local scheduler="$1"

    ip netns exec wlb-server "$MQVPN" \
        --mode server \
        --listen 0.0.0.0:4433 \
        --subnet 10.0.0.0/24 \
        --cert "${WORK_DIR}/server.crt" \
        --key "${WORK_DIR}/server.key" \
        --scheduler "$scheduler" \
        --log-level info &
    SERVER_PID=$!
    sleep 2

    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "  ERROR: Server process died"
        return 1
    fi

    ip netns exec wlb-client "$MQVPN" \
        --mode client \
        --server 192.168.10.2:4433 \
        --path wlb-a0 --path wlb-b0 \
        --insecure \
        --scheduler "$scheduler" \
        --log-level info &
    CLIENT_PID=$!
    sleep "$TUNNEL_WAIT"

    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "  ERROR: Client process died"
        return 1
    fi

    # Verify tunnel is up
    if ! ip netns exec wlb-client ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
        echo "  ERROR: Tunnel not established (ping failed)"
        return 1
    fi

    return 0
}

kill_vpn() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    CLIENT_PID=""
    SERVER_PID=""
    sleep 1
    # Wait for TUN device to be released
    sleep 1
}

# ================================================================
#  iperf3 runner — returns Mbps as string
# ================================================================

run_iperf() {
    # Start iperf3 server in server netns
    ip netns exec wlb-server iperf3 -s -B 10.0.0.1 -1 &>/dev/null &
    IPERF_SERVER_PID=$!
    sleep 1

    # Run iperf3 client with parallel flows
    local output
    output=$(ip netns exec wlb-client iperf3 \
        -c 10.0.0.1 -B 10.0.0.2 \
        -P "$IPERF_PARALLEL" -t "$IPERF_DURATION" 2>&1) || true

    wait "$IPERF_SERVER_PID" 2>/dev/null || true
    IPERF_SERVER_PID=""

    # Extract receiver bandwidth from [SUM] line
    local bw_line bw_value bw_unit bw_mbps
    bw_line=$(echo "$output" | grep -E '\[SUM\].*receiver' | tail -1)
    if [ -z "$bw_line" ]; then
        # Single flow fallback (no SUM line)
        bw_line=$(echo "$output" | grep -E '\[.*\].*receiver' | tail -1)
    fi

    if [ -n "$bw_line" ]; then
        bw_mbps=$(echo "$bw_line" | awk '{
            for (i = 1; i <= NF; i++) {
                if ($(i+1) ~ /bits\/sec/) {
                    val = $i;
                    unit = $(i+1);
                    if (unit ~ /^G/) val *= 1000;
                    else if (unit ~ /^K/) val /= 1000;
                    printf "%.1f", val;
                    exit;
                }
            }
        }')
        echo "$bw_mbps"
    else
        echo "0.0"
    fi
}

# ================================================================
#  Test scenarios
# ================================================================

run_scenario() {
    local name="$1" rate_a="$2" delay_a="$3" rate_b="$4" delay_b="$5" pass_ratio="$6"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $name"
    echo "  Path A: ${rate_a} / ${delay_a}    Path B: ${rate_b} / ${delay_b}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    apply_tc "$rate_a" "$delay_a" "$rate_b" "$delay_b"

    # --- MinRTT run ---
    echo ""
    echo "  [1/2] Running with MinRTT scheduler..."
    if ! run_vpn "minrtt"; then
        echo "  SKIP: VPN setup failed for MinRTT"
        RESULTS["${name}_minrtt"]="ERROR"
        RESULTS["${name}_wlb"]="SKIP"
        kill_vpn
        clear_tc
        return
    fi

    local bw_minrtt
    bw_minrtt=$(run_iperf)
    echo "  MinRTT: ${bw_minrtt} Mbps"
    kill_vpn

    # --- WLB run ---
    echo ""
    echo "  [2/2] Running with WLB scheduler..."
    if ! run_vpn "wlb"; then
        echo "  SKIP: VPN setup failed for WLB"
        RESULTS["${name}_minrtt"]="$bw_minrtt"
        RESULTS["${name}_wlb"]="ERROR"
        kill_vpn
        clear_tc
        return
    fi

    local bw_wlb
    bw_wlb=$(run_iperf)
    echo "  WLB:    ${bw_wlb} Mbps"
    kill_vpn

    clear_tc

    # Store results
    RESULTS["${name}_minrtt"]="$bw_minrtt"
    RESULTS["${name}_wlb"]="$bw_wlb"

    # Compute ratio
    local ratio verdict
    ratio=$(awk "BEGIN { if ($bw_minrtt > 0) printf \"%.2f\", $bw_wlb / $bw_minrtt; else print \"0.00\" }")
    RESULTS["${name}_ratio"]="$ratio"

    local pass
    pass=$(awk "BEGIN { print ($ratio >= $pass_ratio) ? 1 : 0 }")
    if [ "$pass" = "1" ]; then
        verdict="PASS (>=${pass_ratio}x)"
    else
        verdict="FAIL (<${pass_ratio}x)"
    fi
    RESULTS["${name}_verdict"]="$verdict"
    echo ""
    echo "  Ratio: ${ratio}x → $verdict"
}

# ================================================================
#  Main
# ================================================================

echo "=========================================="
echo "  mqvpn WLB Scheduler Test"
echo "  Binary: $MQVPN"
echo "  iperf3: -P ${IPERF_PARALLEL} -t ${IPERF_DURATION}"
echo "=========================================="

echo ""
echo "Setting up network namespaces..."
setup_netns
echo "OK: 2 veth pairs created"

echo ""
echo "Generating TLS certificate..."
generate_cert
echo "OK"

# Scenario 1: Equal paths
# WLB should match MinRTT (both aggregate).  Pass = no regression (>= 0.9x).
run_scenario \
    "equal" \
    "50mbit" "10ms" \
    "50mbit" "10ms" \
    "0.9"

# Scenario 2: Asymmetric paths
# WLB should match MinRTT (both aggregate).  Pass = no regression (>= 0.9x).
run_scenario \
    "asymmetric" \
    "100mbit" "5ms" \
    "50mbit" "20ms" \
    "0.9"

# ================================================================
#  Summary
# ================================================================

echo ""
echo ""
echo "=========================================="
echo "  WLB Scheduler Test Results"
echo "=========================================="
echo ""
echo "  Scenario 1: Equal paths (2 x 50Mbps / 10ms)  [pass >= 0.9x]"
echo "    MinRTT:  ${RESULTS[equal_minrtt]:-N/A} Mbps"
echo "    WLB:     ${RESULTS[equal_wlb]:-N/A} Mbps"
echo "    Ratio:   ${RESULTS[equal_ratio]:-N/A}x  ${RESULTS[equal_verdict]:-N/A}"
echo ""
echo "  Scenario 2: Asymmetric (100Mbps/5ms + 50Mbps/20ms)  [pass >= 0.9x]"
echo "    MinRTT:  ${RESULTS[asymmetric_minrtt]:-N/A} Mbps"
echo "    WLB:     ${RESULTS[asymmetric_wlb]:-N/A} Mbps"
echo "    Ratio:   ${RESULTS[asymmetric_ratio]:-N/A}x  ${RESULTS[asymmetric_verdict]:-N/A}"
echo ""
echo "=========================================="

# Exit code based on results
FAIL=0
for key in equal_verdict asymmetric_verdict; do
    v="${RESULTS[$key]:-}"
    if [[ "$v" == *FAIL* ]] || [[ "$v" == *ERROR* ]]; then
        FAIL=1
    fi
done

if [ "$FAIL" -eq 0 ]; then
    echo "  Overall: PASS"
else
    echo "  Overall: FAIL (see details above)"
fi
echo "=========================================="
exit $FAIL
