#!/bin/bash
# benchmark_flow_scaling.sh — WLB flow-scaling benchmark
#
# Tests how WLB performance scales with the number of concurrent flows.
# Runs MinRTT vs WLB with -P 32 and -P 64 across key scenarios.
#
# Hypothesis: WLB's flow-affinity scheduling improves with more flows
# because WRR granularity increases (1 flow = smaller % of total traffic).
#
# Scenarios (subset of full benchmark — focus on where WLB struggled):
#   1. Equal paths           — 2 × 50Mbps / 10ms
#   2. Asymmetric bandwidth  — 100Mbps/5ms + 50Mbps/20ms
#   3. Asymmetric jitter     — 50Mbps/10ms (stable) + 50Mbps/10ms±8ms (jittery)
#   4. Lossy path            — 50Mbps/10ms + 50Mbps/10ms/1% loss
#   5. Realistic mixed       — 100Mbps/5ms + 50Mbps/20ms±5ms/0.5% loss
#   6. Mobile Wi-Fi + LTE    — 80Mbps/5ms±2ms + 30Mbps/40ms±12ms/0.5%
#
# Usage: sudo ./benchmark_flow_scaling.sh [path-to-mqvpn-binary]

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

# Generate PSK
PSK=$("$MQVPN" --genkey 2>/dev/null)

IPERF_DURATION=15
PARALLEL_COUNTS=(32 64)
TUNNEL_WAIT=5

# Result storage — indexed by "scenario_scheduler_P" keys
declare -A R_BW      # throughput Mbps
declare -A R_RETR    # retransmissions

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
        -days 365 -nodes -subj "/CN=mqvpn-flowscale" 2>/dev/null
}

setup_netns() {
    ip netns del fs-server 2>/dev/null || true
    ip netns del fs-client 2>/dev/null || true
    ip link del fs-a0 2>/dev/null || true
    ip link del fs-b0 2>/dev/null || true

    ip netns add fs-server
    ip netns add fs-client

    # Path A: 192.168.10.0/24
    ip link add fs-a0 type veth peer name fs-a1
    ip link set fs-a0 netns fs-client
    ip link set fs-a1 netns fs-server
    ip netns exec fs-client ip addr add 192.168.10.1/24 dev fs-a0
    ip netns exec fs-server ip addr add 192.168.10.2/24 dev fs-a1
    ip netns exec fs-client ip link set fs-a0 up
    ip netns exec fs-server ip link set fs-a1 up

    # Path B: 192.168.20.0/24
    ip link add fs-b0 type veth peer name fs-b1
    ip link set fs-b0 netns fs-client
    ip link set fs-b1 netns fs-server
    ip netns exec fs-client ip addr add 192.168.20.1/24 dev fs-b0
    ip netns exec fs-server ip addr add 192.168.20.2/24 dev fs-b1
    ip netns exec fs-client ip link set fs-b0 up
    ip netns exec fs-server ip link set fs-b1 up

    # Loopback
    ip netns exec fs-client ip link set lo up
    ip netns exec fs-server ip link set lo up

    # IP forwarding
    ip netns exec fs-server sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # Verify
    ip netns exec fs-client ping -c 1 -W 1 192.168.10.2 >/dev/null
    ip netns exec fs-client ping -c 1 -W 1 192.168.20.2 >/dev/null
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$IPERF_SERVER_PID" ] && kill "$IPERF_SERVER_PID" 2>/dev/null || true
    kill_vpn
    clear_tc
    ip netns del fs-server 2>/dev/null || true
    ip netns del fs-client 2>/dev/null || true
    ip link del fs-a0 2>/dev/null || true
    ip link del fs-b0 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# ================================================================
#  tc netem helpers
# ================================================================

apply_tc_full() {
    local rate_a="$1" netem_a="$2" rate_b="$3" netem_b="$4"

    clear_tc

    ip netns exec fs-client tc qdisc add dev fs-a0 root netem ${netem_a} rate "${rate_a}"
    ip netns exec fs-server tc qdisc add dev fs-a1 root netem ${netem_a} rate "${rate_a}"
    ip netns exec fs-client tc qdisc add dev fs-b0 root netem ${netem_b} rate "${rate_b}"
    ip netns exec fs-server tc qdisc add dev fs-b1 root netem ${netem_b} rate "${rate_b}"
}

clear_tc() {
    ip netns exec fs-client tc qdisc del dev fs-a0 root 2>/dev/null || true
    ip netns exec fs-server tc qdisc del dev fs-a1 root 2>/dev/null || true
    ip netns exec fs-client tc qdisc del dev fs-b0 root 2>/dev/null || true
    ip netns exec fs-server tc qdisc del dev fs-b1 root 2>/dev/null || true
}

# ================================================================
#  VPN start / stop
# ================================================================

run_vpn() {
    local scheduler="$1"

    ip netns exec fs-server "$MQVPN" \
        --mode server \
        --listen 0.0.0.0:4433 \
        --subnet 10.0.0.0/24 \
        --cert "${WORK_DIR}/server.crt" \
        --key "${WORK_DIR}/server.key" \
        --auth-key "$PSK" \
        --scheduler "$scheduler" \
        --log-level info &
    SERVER_PID=$!
    sleep 2

    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "    ERROR: Server process died"
        return 1
    fi

    ip netns exec fs-client "$MQVPN" \
        --mode client \
        --server 192.168.10.2:4433 \
        --path fs-a0 --path fs-b0 \
        --auth-key "$PSK" \
        --insecure \
        --scheduler "$scheduler" \
        --log-level info &
    CLIENT_PID=$!
    sleep "$TUNNEL_WAIT"

    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "    ERROR: Client process died"
        return 1
    fi

    if ! ip netns exec fs-client ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
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
#  iperf3 runner
# ================================================================

run_iperf() {
    local parallel="$1"

    ip netns exec fs-server iperf3 -s -B 10.0.0.1 -1 &>/dev/null &
    IPERF_SERVER_PID=$!
    sleep 1

    local output
    output=$(ip netns exec fs-client iperf3 \
        -c 10.0.0.1 -B 10.0.0.2 \
        -P "$parallel" -t "$IPERF_DURATION" 2>&1) || true

    wait "$IPERF_SERVER_PID" 2>/dev/null || true
    IPERF_SERVER_PID=""

    # Extract receiver bandwidth from [SUM] line
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

    # Extract retransmissions from [SUM] sender line
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
#  Scenario runner — runs all (scheduler × parallel) combinations
# ================================================================

run_scenario() {
    local name="$1" label="$2" rate_a="$3" netem_a="$4" rate_b="$5" netem_b="$6"

    # Track unique scenario names (only once)
    local found=0
    for s in "${SCENARIOS[@]}"; do [ "$s" = "$name" ] && found=1; done
    [ "$found" -eq 0 ] && SCENARIOS+=("$name")

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  [$name] $label"
    echo "  Path A: ${rate_a} / ${netem_a}"
    echo "  Path B: ${rate_b} / ${netem_b}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    apply_tc_full "$rate_a" "$netem_a" "$rate_b" "$netem_b"

    local total=${#PARALLEL_COUNTS[@]}
    total=$((total * 2))
    local step=0

    for P in "${PARALLEL_COUNTS[@]}"; do
        for sched in minrtt wlb; do
            step=$((step + 1))
            echo ""
            echo "    [${step}/${total}] ${sched} / P=${P}..."

            if ! run_vpn "$sched"; then
                echo "    SKIP: VPN setup failed for ${sched} P=${P}"
                R_BW["${name}_${sched}_${P}"]="ERR"
                R_RETR["${name}_${sched}_${P}"]="-"
                kill_vpn
                continue
            fi

            local result bw retr
            result=$(run_iperf "$P")
            bw=$(echo "$result" | awk '{print $1}')
            retr=$(echo "$result" | awk '{print $2}')

            R_BW["${name}_${sched}_${P}"]="$bw"
            R_RETR["${name}_${sched}_${P}"]="$retr"

            printf "    %-7s P=%-3d  %7s Mbps  Retr: %s\n" "$sched" "$P" "$bw" "$retr"
            kill_vpn
        done
    done

    clear_tc
}

# ================================================================
#  Main
# ================================================================

echo "================================================================"
echo "  mqvpn Flow-Scaling Benchmark (WLB vs MinRTT)"
echo "  Binary:    $MQVPN"
echo "  Parallel:  ${PARALLEL_COUNTS[*]}"
echo "  Duration:  ${IPERF_DURATION}s per run"
echo "  Date:      $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

echo ""
echo "Setting up network namespaces..."
setup_netns
echo "OK: 2 veth pairs created"

echo ""
echo "Generating TLS certificate..."
generate_cert
echo "OK"

# ---- Scenarios ----

run_scenario "equal" \
    "Equal paths (baseline)" \
    "50mbit" "delay 10ms" \
    "50mbit" "delay 10ms"

run_scenario "asym_bw" \
    "Asymmetric bandwidth" \
    "100mbit" "delay 5ms" \
    "50mbit"  "delay 20ms"

run_scenario "asym_jitter" \
    "Asymmetric jitter (Path B jittery)" \
    "50mbit" "delay 10ms" \
    "50mbit" "delay 10ms 8ms distribution normal"

run_scenario "loss" \
    "Lossy path (Path B 1% loss)" \
    "50mbit" "delay 10ms" \
    "50mbit" "delay 10ms loss 1%"

run_scenario "realistic" \
    "Realistic mixed (asymmetric + jitter + loss)" \
    "100mbit" "delay 5ms" \
    "50mbit"  "delay 20ms 5ms distribution normal loss 0.5%"

run_scenario "mobile_wifi_lte" \
    "Mobile Wi-Fi + LTE (typical smartphone)" \
    "80mbit" "delay 5ms 2ms distribution normal" \
    "30mbit" "delay 40ms 12ms distribution normal loss 0.5%"

# ================================================================
#  Summary
# ================================================================

echo ""
echo ""
echo "================================================================"
echo "  Flow-Scaling Benchmark Results"
echo "================================================================"

for P in "${PARALLEL_COUNTS[@]}"; do
    echo ""
    echo "  ── P = ${P} parallel flows ──────────────────────────────────"
    echo ""
    printf "  %-16s │ %10s %7s │ %10s %7s │ %s\n" \
        "Scenario" "MinRTT" "Retr" "WLB" "Retr" "Ratio"
    echo "  ─────────────────┼────────────────────┼────────────────────┼───────"

    for name in "${SCENARIOS[@]}"; do
        bw_m="${R_BW[${name}_minrtt_${P}]:-N/A}"
        bw_w="${R_BW[${name}_wlb_${P}]:-N/A}"
        re_m="${R_RETR[${name}_minrtt_${P}]:-N/A}"
        re_w="${R_RETR[${name}_wlb_${P}]:-N/A}"

        ratio="-"
        if [[ "$bw_m" =~ ^[0-9] ]] && [[ "$bw_w" =~ ^[0-9] ]]; then
            ratio=$(awk "BEGIN { if ($bw_m > 0) printf \"%.2fx\", $bw_w / $bw_m; else print \"-\" }")
        fi

        printf "  %-16s │ %7s Mbps %5s │ %7s Mbps %5s │ %s\n" \
            "$name" "$bw_m" "$re_m" "$bw_w" "$re_w" "$ratio"
    done

    echo "  ─────────────────┴────────────────────┴────────────────────┴───────"
done

echo ""
echo "================================================================"
