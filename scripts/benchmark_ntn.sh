#!/bin/bash
# benchmark_ntn.sh — NTN (Non-Terrestrial Network) multipath scheduler benchmark
#
# Tests MinRTT vs WLB across LTE + satellite NTN scenarios.
# Models LEO/GEO satellite link characteristics based on 3GPP NTN specs
# and real-world Starlink measurements.
#
# NTN characteristics (from literature):
#   LEO (500-2000km): RTT 20-80ms, jitter 6-15ms (handover spikes 30-140ms),
#                     DL 30-150Mbps, UL 10-20Mbps, loss 0.2-1%
#   GEO (35786km):    RTT 500-600ms, jitter small, DL 5-30Mbps, loss ~0.2%
#
# Scenarios:
#   1. LTE + LEO (Starlink-like)     — typical smartphone dual connectivity
#   2. LTE + LEO (high orbit)        — worst-case LEO, higher RTT
#   3. LTE + GEO                     — extreme RTT asymmetry
#   4. Wi-Fi + LEO                   — home/office + satellite backup
#   5. Dual LEO                      — satellite-only (maritime/aviation)
#   6. LTE + LEO handover stress     — simulates frequent satellite handovers
#
# References:
#   - 3GPP NTN Overview: https://www.3gpp.org/technologies/ntn-overview
#   - Starlink latency: https://starlink.com/public-files/StarlinkLatency.pdf
#   - MPQUIC in ITSN: https://ieeexplore.ieee.org/document/10520815/
#
# Usage: sudo ./benchmark_ntn.sh [path-to-mqvpn-binary]

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
TUNNEL_WAIT=6      # longer wait for high-RTT paths to establish

declare -A R_BW
declare -A R_RETR

SERVER_PID=""
CLIENT_PID=""
IPERF_SERVER_PID=""

SCENARIOS=()

# ================================================================
#  Setup / Cleanup
# ================================================================

generate_cert() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
        -days 365 -nodes -subj "/CN=mqvpn-ntn-bench" 2>/dev/null
}

setup_netns() {
    ip netns del ntn-server 2>/dev/null || true
    ip netns del ntn-client 2>/dev/null || true
    ip link del ntn-a0 2>/dev/null || true
    ip link del ntn-b0 2>/dev/null || true

    ip netns add ntn-server
    ip netns add ntn-client

    # Path A (terrestrial): 192.168.10.0/24
    ip link add ntn-a0 type veth peer name ntn-a1
    ip link set ntn-a0 netns ntn-client
    ip link set ntn-a1 netns ntn-server
    ip netns exec ntn-client ip addr add 192.168.10.1/24 dev ntn-a0
    ip netns exec ntn-server ip addr add 192.168.10.2/24 dev ntn-a1
    ip netns exec ntn-client ip link set ntn-a0 up
    ip netns exec ntn-server ip link set ntn-a1 up

    # Path B (satellite): 192.168.20.0/24
    ip link add ntn-b0 type veth peer name ntn-b1
    ip link set ntn-b0 netns ntn-client
    ip link set ntn-b1 netns ntn-server
    ip netns exec ntn-client ip addr add 192.168.20.1/24 dev ntn-b0
    ip netns exec ntn-server ip addr add 192.168.20.2/24 dev ntn-b1
    ip netns exec ntn-client ip link set ntn-b0 up
    ip netns exec ntn-server ip link set ntn-b1 up

    ip netns exec ntn-client ip link set lo up
    ip netns exec ntn-server ip link set lo up
    ip netns exec ntn-server sysctl -w net.ipv4.ip_forward=1 >/dev/null

    ip netns exec ntn-client ping -c 1 -W 1 192.168.10.2 >/dev/null
    ip netns exec ntn-client ping -c 1 -W 1 192.168.20.2 >/dev/null
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$IPERF_SERVER_PID" ] && kill "$IPERF_SERVER_PID" 2>/dev/null || true
    kill_vpn
    clear_tc
    ip netns del ntn-server 2>/dev/null || true
    ip netns del ntn-client 2>/dev/null || true
    ip link del ntn-a0 2>/dev/null || true
    ip link del ntn-b0 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# ================================================================
#  tc netem helpers
# ================================================================

apply_tc_full() {
    local rate_a="$1" netem_a="$2" rate_b="$3" netem_b="$4"

    clear_tc

    ip netns exec ntn-client tc qdisc add dev ntn-a0 root netem ${netem_a} rate "${rate_a}"
    ip netns exec ntn-server tc qdisc add dev ntn-a1 root netem ${netem_a} rate "${rate_a}"
    ip netns exec ntn-client tc qdisc add dev ntn-b0 root netem ${netem_b} rate "${rate_b}"
    ip netns exec ntn-server tc qdisc add dev ntn-b1 root netem ${netem_b} rate "${rate_b}"
}

clear_tc() {
    ip netns exec ntn-client tc qdisc del dev ntn-a0 root 2>/dev/null || true
    ip netns exec ntn-server tc qdisc del dev ntn-a1 root 2>/dev/null || true
    ip netns exec ntn-client tc qdisc del dev ntn-b0 root 2>/dev/null || true
    ip netns exec ntn-server tc qdisc del dev ntn-b1 root 2>/dev/null || true
}

# ================================================================
#  VPN start / stop
# ================================================================

run_vpn() {
    local scheduler="$1"

    ip netns exec ntn-server "$MQVPN" \
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
        echo "    ERROR: Server process died"
        return 1
    fi

    ip netns exec ntn-client "$MQVPN" \
        --mode client \
        --server 192.168.10.2:4433 \
        --path ntn-a0 --path ntn-b0 \
        --insecure \
        --scheduler "$scheduler" \
        --log-level info &
    CLIENT_PID=$!
    sleep "$TUNNEL_WAIT"

    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "    ERROR: Client process died"
        return 1
    fi

    if ! ip netns exec ntn-client ping -c 2 -W 3 10.0.0.1 >/dev/null 2>&1; then
        echo "    ERROR: Tunnel not established (ping failed)"
        return 1
    fi

    return 0
}

kill_vpn() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    CLIENT_PID=""
    SERVER_PID=""
    sleep 2
}

# ================================================================
#  iperf3 runner — returns "bw_mbps retransmissions"
# ================================================================

run_iperf() {
    ip netns exec ntn-server iperf3 -s -B 10.0.0.1 -1 &>/dev/null &
    IPERF_SERVER_PID=$!
    sleep 1

    local output
    output=$(ip netns exec ntn-client iperf3 \
        -c 10.0.0.1 -B 10.0.0.2 \
        -P "$IPERF_PARALLEL" -t "$IPERF_DURATION" 2>&1) || true

    wait "$IPERF_SERVER_PID" 2>/dev/null || true
    IPERF_SERVER_PID=""

    local bw_line bw_mbps
    bw_line=$(echo "$output" | grep -E '\[SUM\].*receiver' | tail -1)
    if [ -z "$bw_line" ]; then
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
    else
        bw_mbps="0.0"
    fi

    local retr_line retrans
    retr_line=$(echo "$output" | grep -E '\[SUM\].*sender' | tail -1)
    if [ -z "$retr_line" ]; then
        retr_line=$(echo "$output" | grep -E '\[.*\].*sender' | tail -1)
    fi

    if [ -n "$retr_line" ]; then
        retrans=$(echo "$retr_line" | awk '{
            for (i = 1; i <= NF; i++) {
                if ($i ~ /bits\/sec/) { print $(i+1); exit }
            }
        }')
        if ! [[ "$retrans" =~ ^[0-9]+$ ]]; then
            retrans="-"
        fi
    else
        retrans="-"
    fi

    echo "${bw_mbps} ${retrans}"
}

# ================================================================
#  Scenario runner
# ================================================================

run_scenario() {
    local name="$1" label="$2" rate_a="$3" netem_a="$4" rate_b="$5" netem_b="$6"

    SCENARIOS+=("$name")

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  [$name] $label"
    echo "  Path A: ${rate_a} / ${netem_a}"
    echo "  Path B: ${rate_b} / ${netem_b}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    apply_tc_full "$rate_a" "$netem_a" "$rate_b" "$netem_b"

    for sched in minrtt wlb; do
        local step
        [ "$sched" = "minrtt" ] && step="1/2" || step="2/2"

        echo ""
        echo "    [${step}] ${sched}..."
        if ! run_vpn "$sched"; then
            echo "    SKIP: VPN setup failed for ${sched}"
            R_BW["${name}_${sched}"]="ERR"
            R_RETR["${name}_${sched}"]="-"
            kill_vpn
            continue
        fi

        local result bw retr
        result=$(run_iperf)
        bw=$(echo "$result" | awk '{print $1}')
        retr=$(echo "$result" | awk '{print $2}')

        R_BW["${name}_${sched}"]="$bw"
        R_RETR["${name}_${sched}"]="$retr"

        printf "    %-7s  %7s Mbps  Retr: %s\n" "$sched" "$bw" "$retr"
        kill_vpn
    done

    clear_tc
}

# ================================================================
#  Main
# ================================================================

echo "================================================================"
echo "  mqvpn NTN (Non-Terrestrial Network) Benchmark"
echo "  Binary:  $MQVPN"
echo "  iperf3:  -P ${IPERF_PARALLEL} -t ${IPERF_DURATION}"
echo "  Date:    $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

echo ""
echo "Setting up network namespaces..."
setup_netns
echo "OK: 2 veth pairs created"

echo ""
echo "Generating TLS certificate..."
generate_cert
echo "OK"

# ---- Scenario 1: LTE + LEO (Starlink-like) ----
# Typical smartphone dual connectivity.
# LEO: RTT ~50ms, jitter ±15ms, DL ~30Mbps, loss 0.5%
# Ref: Starlink median latency 38-50ms, jitter avg 6.7ms
run_scenario "lte_leo" \
    "LTE + LEO satellite (Starlink-like)" \
    "50mbit" "delay 25ms 5ms distribution normal loss 0.3%" \
    "30mbit" "delay 50ms 15ms distribution normal loss 0.5%"

# ---- Scenario 2: LTE + LEO (high orbit / worst case) ----
# LEO at higher altitude or low elevation angle.
# RTT 80ms, larger jitter, higher loss.
run_scenario "lte_leo_high" \
    "LTE + LEO high orbit (worst case)" \
    "50mbit" "delay 25ms 5ms distribution normal loss 0.3%" \
    "20mbit" "delay 80ms 20ms distribution normal loss 1%"

# ---- Scenario 3: LTE + GEO ----
# Extreme RTT asymmetry: LTE 25ms vs GEO 300ms (one-way).
# GEO: low bandwidth, stable but very high latency.
# Ref: 3GPP PDB 1100ms for GEO, typical RTT 500-600ms
run_scenario "lte_geo" \
    "LTE + GEO satellite (extreme RTT asymmetry)" \
    "50mbit" "delay 25ms 5ms distribution normal loss 0.3%" \
    "10mbit" "delay 300ms 10ms distribution normal loss 0.2%"

# ---- Scenario 4: Wi-Fi + LEO ----
# Home/office with satellite backup link.
# Wi-Fi: fast + low latency. LEO: moderate latency.
run_scenario "wifi_leo" \
    "Wi-Fi + LEO satellite (home + backup)" \
    "80mbit" "delay 5ms 2ms distribution normal" \
    "30mbit" "delay 50ms 15ms distribution normal loss 0.5%"

# ---- Scenario 5: Dual LEO (satellite only) ----
# Maritime / aviation: no terrestrial, two satellite paths.
# Both paths have high RTT, jitter, and loss.
run_scenario "dual_leo" \
    "Dual LEO (maritime/aviation, no terrestrial)" \
    "30mbit" "delay 40ms 10ms distribution normal loss 0.5%" \
    "30mbit" "delay 60ms 20ms distribution normal loss 0.8%"

# ---- Scenario 6: LTE + LEO handover stress ----
# Simulates frequent satellite handovers via high jitter.
# Real Starlink: 15s cycle, 30-140ms spikes at boundaries.
# Modeled as very high jitter (±30ms) + elevated loss.
run_scenario "lte_leo_handover" \
    "LTE + LEO handover stress (high jitter)" \
    "50mbit" "delay 25ms 5ms distribution normal loss 0.3%" \
    "30mbit" "delay 50ms 30ms distribution normal loss 1.5%"

# ================================================================
#  Summary
# ================================================================

echo ""
echo ""
echo "================================================================"
echo "  NTN Benchmark Results"
echo "================================================================"
echo ""
printf "  %-18s │ %10s %7s │ %10s %7s │ %s\n" \
    "Scenario" "MinRTT" "Retr" "WLB" "Retr" "Ratio"
echo "  ───────────────────┼────────────────────┼────────────────────┼───────"

for name in "${SCENARIOS[@]}"; do
    bw_m="${R_BW[${name}_minrtt]:-N/A}"
    bw_w="${R_BW[${name}_wlb]:-N/A}"
    re_m="${R_RETR[${name}_minrtt]:-N/A}"
    re_w="${R_RETR[${name}_wlb]:-N/A}"

    ratio="-"
    if [[ "$bw_m" =~ ^[0-9] ]] && [[ "$bw_w" =~ ^[0-9] ]]; then
        ratio=$(awk "BEGIN { if ($bw_m > 0) printf \"%.2fx\", $bw_w / $bw_m; else print \"-\" }")
    fi

    printf "  %-18s │ %7s Mbps %5s │ %7s Mbps %5s │ %s\n" \
        "$name" "$bw_m" "$re_m" "$bw_w" "$re_w" "$ratio"
done

echo "  ───────────────────┴────────────────────┴────────────────────┴───────"
echo ""

# NTN-specific notes
echo "  Notes:"
echo "  - LEO handover spikes (30-140ms/15s cycle) are approximated"
echo "    via high jitter; real handovers are periodic, not random."
echo "  - GEO RTT modeled as 300ms one-way (600ms round-trip)."
echo "  - UL/DL asymmetry not modeled (tc netem is symmetric)."
echo ""
echo "================================================================"
