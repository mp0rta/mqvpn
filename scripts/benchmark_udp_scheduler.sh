#!/bin/bash
# benchmark_udp_scheduler.sh — UDP multipath scheduler benchmark
#
# Measures UDP-specific metrics (throughput, jitter, loss%) for MinRTT vs WLB.
# UDP packets use per-packet WRR (no flow pinning) under WLB, so bandwidth
# aggregation should be better than TCP in most scenarios.
#
# Target bandwidth is set to ~1.2× combined link capacity to mildly
# oversubscribe without flooding the TUN queue (which masks scheduler
# differences).
#
# Scenarios:
#   1. Equal paths           — 2 × 50Mbps / 10ms
#   2. Asymmetric bandwidth  — 100Mbps/5ms + 50Mbps/20ms
#   3. Asymmetric jitter     — 50Mbps/10ms + 50Mbps/10ms±8ms
#   4. Lossy path            — 50Mbps/10ms + 50Mbps/10ms/1% loss
#   5. Realistic mixed       — 100Mbps/5ms + 50Mbps/20ms±5ms/0.5% loss
#   6. Mobile Wi-Fi + LTE    — 80Mbps/5ms±2ms + 30Mbps/40ms±12ms/0.5%
#   7. VoIP simulation       — 2 × 50Mbps/10ms, 100Kbps/160B packets
#
# Usage: sudo ./benchmark_udp_scheduler.sh [path-to-mqvpn-binary]

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
IPERF_PARALLEL=4
TUNNEL_WAIT=5

# Per-stream UDP target bandwidth (-b).  Total = value × IPERF_PARALLEL.
# Set to ~1.2× combined link capacity / P to mildly oversubscribe
# without flooding the TUN queue (which masks scheduler differences).
#   100Mbps links → 30M × 4 = 120M (1.2×)
#   150Mbps links → 45M × 4 = 180M (1.2×)
#   110Mbps links → 33M × 4 = 132M (1.2×)

# Result storage
declare -A R_BW        # throughput Mbps
declare -A R_JITTER    # jitter ms
declare -A R_LOSS      # loss %

SERVER_PID=""
CLIENT_PID=""
IPERF_SERVER_PID=""

SCENARIOS=()

# ================================================================
#  Setup / Cleanup (identical to TCP benchmark)
# ================================================================

generate_cert() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
        -days 365 -nodes -subj "/CN=mqvpn-bench" 2>/dev/null
}

setup_netns() {
    ip netns del bench-server 2>/dev/null || true
    ip netns del bench-client 2>/dev/null || true
    ip link del bench-a0 2>/dev/null || true
    ip link del bench-b0 2>/dev/null || true

    ip netns add bench-server
    ip netns add bench-client

    # Path A: 192.168.10.0/24
    ip link add bench-a0 type veth peer name bench-a1
    ip link set bench-a0 netns bench-client
    ip link set bench-a1 netns bench-server
    ip netns exec bench-client ip addr add 192.168.10.1/24 dev bench-a0
    ip netns exec bench-server ip addr add 192.168.10.2/24 dev bench-a1
    ip netns exec bench-client ip link set bench-a0 up
    ip netns exec bench-server ip link set bench-a1 up

    # Path B: 192.168.20.0/24
    ip link add bench-b0 type veth peer name bench-b1
    ip link set bench-b0 netns bench-client
    ip link set bench-b1 netns bench-server
    ip netns exec bench-client ip addr add 192.168.20.1/24 dev bench-b0
    ip netns exec bench-server ip addr add 192.168.20.2/24 dev bench-b1
    ip netns exec bench-client ip link set bench-b0 up
    ip netns exec bench-server ip link set bench-b1 up

    # Loopback
    ip netns exec bench-client ip link set lo up
    ip netns exec bench-server ip link set lo up

    # IP forwarding
    ip netns exec bench-server sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # Verify
    ip netns exec bench-client ping -c 1 -W 1 192.168.10.2 >/dev/null
    ip netns exec bench-client ping -c 1 -W 1 192.168.20.2 >/dev/null
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$IPERF_SERVER_PID" ] && kill "$IPERF_SERVER_PID" 2>/dev/null || true
    kill_vpn
    clear_tc
    ip netns del bench-server 2>/dev/null || true
    ip netns del bench-client 2>/dev/null || true
    ip link del bench-a0 2>/dev/null || true
    ip link del bench-b0 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# ================================================================
#  tc netem helpers
# ================================================================

apply_tc_full() {
    local rate_a="$1" netem_a="$2" rate_b="$3" netem_b="$4"

    clear_tc

    ip netns exec bench-client tc qdisc add dev bench-a0 root netem ${netem_a} rate "${rate_a}"
    ip netns exec bench-server tc qdisc add dev bench-a1 root netem ${netem_a} rate "${rate_a}"
    ip netns exec bench-client tc qdisc add dev bench-b0 root netem ${netem_b} rate "${rate_b}"
    ip netns exec bench-server tc qdisc add dev bench-b1 root netem ${netem_b} rate "${rate_b}"
}

clear_tc() {
    ip netns exec bench-client tc qdisc del dev bench-a0 root 2>/dev/null || true
    ip netns exec bench-server tc qdisc del dev bench-a1 root 2>/dev/null || true
    ip netns exec bench-client tc qdisc del dev bench-b0 root 2>/dev/null || true
    ip netns exec bench-server tc qdisc del dev bench-b1 root 2>/dev/null || true
}

# ================================================================
#  VPN start / stop
# ================================================================

run_vpn() {
    local scheduler="$1"

    ip netns exec bench-server "$MQVPN" \
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

    ip netns exec bench-client "$MQVPN" \
        --mode client \
        --server 192.168.10.2:4433 \
        --path bench-a0 --path bench-b0 \
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

    if ! ip netns exec bench-client ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
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
#  iperf3 UDP runner — returns "bw_mbps jitter_ms loss_pct"
# ================================================================

# run_iperf_udp <target_bw> [pkt_len]
#   target_bw: iperf3 -b value (per-stream; total = value × IPERF_PARALLEL)
#   pkt_len:   iperf3 -l value (default: not set, iperf3 default 1460)
run_iperf_udp() {
    local target_bw="$1"
    local pkt_len="$2"

    ip netns exec bench-server iperf3 -s -B 10.0.0.1 -1 &>/dev/null &
    IPERF_SERVER_PID=$!
    sleep 1

    local len_args=""
    if [ -n "$pkt_len" ]; then
        len_args="-l $pkt_len"
    fi

    local output
    output=$(ip netns exec bench-client iperf3 \
        -c 10.0.0.1 -B 10.0.0.2 \
        -u -b "$target_bw" $len_args \
        -P "$IPERF_PARALLEL" -t "$IPERF_DURATION" 2>&1) || true

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

    # Extract jitter and loss from receiver summary line
    # iperf3 UDP format: "... X.XX ms  Y/Z (P%)"
    local jitter_ms="0.000" loss_pct="0.00"

    # Use individual stream receiver lines for jitter/loss (SUM line may omit them)
    local detail_line
    detail_line=$(echo "$output" | grep -E '\[  [0-9]+\].*receiver' | head -1)
    if [ -z "$detail_line" ]; then
        detail_line="$bw_line"
    fi

    if [ -n "$detail_line" ]; then
        # Jitter: number followed by "ms" before the loss fraction
        jitter_ms=$(echo "$detail_line" | awk '{
            for (i = 1; i <= NF; i++) {
                if ($i == "ms") { printf "%.3f", $(i-1); exit }
            }
        }')
        if [ -z "$jitter_ms" ]; then
            jitter_ms="-"
        fi

        # Loss: "(X%)" pattern
        loss_pct=$(echo "$detail_line" | grep -oP '\([\d.e+-]+%\)' | tr -d '()%' | head -1)
        if [ -z "$loss_pct" ]; then
            loss_pct="-"
        fi
    fi

    echo "${bw_mbps} ${jitter_ms} ${loss_pct}"
}

# ================================================================
#  Scenario runner
# ================================================================

# run_scenario <name> <label> <rate_a> <netem_a> <rate_b> <netem_b> <udp_bw> [pkt_len]
run_scenario() {
    local name="$1" label="$2" rate_a="$3" netem_a="$4" rate_b="$5" netem_b="$6"
    local udp_bw="$7" pkt_len="$8"

    SCENARIOS+=("$name")

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  [$name] $label"
    echo "  Path A: ${rate_a} / ${netem_a}"
    echo "  Path B: ${rate_b} / ${netem_b}"
    echo "  UDP target: ${udp_bw}${pkt_len:+ pkt_len=${pkt_len}}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    apply_tc_full "$rate_a" "$netem_a" "$rate_b" "$netem_b"

    local scheds=(minrtt wlb)
    local total_s=${#scheds[@]}
    local si=0
    for sched in "${scheds[@]}"; do
        si=$((si + 1))
        local step="${si}/${total_s}"

        echo ""
        echo "    [${step}] ${sched}..."
        if ! run_vpn "$sched"; then
            echo "    SKIP: VPN setup failed for ${sched}"
            R_BW["${name}_${sched}"]="ERR"
            R_JITTER["${name}_${sched}"]="-"
            R_LOSS["${name}_${sched}"]="-"
            kill_vpn
            continue
        fi

        local result bw jitter loss
        result=$(run_iperf_udp "$udp_bw" "$pkt_len")
        bw=$(echo "$result" | awk '{print $1}')
        jitter=$(echo "$result" | awk '{print $2}')
        loss=$(echo "$result" | awk '{print $3}')

        R_BW["${name}_${sched}"]="$bw"
        R_JITTER["${name}_${sched}"]="$jitter"
        R_LOSS["${name}_${sched}"]="$loss"

        printf "    %-7s  %7s Mbps  Jitter: %s ms  Loss: %s%%\n" \
            "$sched" "$bw" "$jitter" "$loss"
        kill_vpn
    done

    clear_tc
}

# ================================================================
#  Main
# ================================================================

echo "================================================================"
echo "  mqvpn UDP Multipath Scheduler Benchmark"
echo "  Binary:  $MQVPN"
echo "  iperf3:  -u -P ${IPERF_PARALLEL} -t ${IPERF_DURATION}"
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

# ---- Scenarios ----

# Per-stream -b targets: total = value × P4
#   100Mbps capacity → 30M/stream (120M total, 1.2×)
#   150Mbps capacity → 45M/stream (180M total, 1.2×)
#   110Mbps capacity → 33M/stream (132M total, 1.2×)

run_scenario "equal" \
    "Equal paths (baseline, 2×50=100Mbps)" \
    "50mbit" "delay 10ms" \
    "50mbit" "delay 10ms" \
    "30M"

run_scenario "asym_bw" \
    "Asymmetric bandwidth (100+50=150Mbps)" \
    "100mbit" "delay 5ms" \
    "50mbit"  "delay 20ms" \
    "45M"

run_scenario "asym_jitter" \
    "Asymmetric jitter (Path B jittery, 2×50=100Mbps)" \
    "50mbit" "delay 10ms" \
    "50mbit" "delay 10ms 8ms distribution normal" \
    "30M"

run_scenario "loss" \
    "Lossy path (Path B 1% loss, 2×50=100Mbps)" \
    "50mbit" "delay 10ms" \
    "50mbit" "delay 10ms loss 1%" \
    "30M"

run_scenario "realistic" \
    "Realistic mixed (100+50=150Mbps, jitter+loss)" \
    "100mbit" "delay 5ms" \
    "50mbit"  "delay 20ms 5ms distribution normal loss 0.5%" \
    "45M"

run_scenario "mobile_wifi_lte" \
    "Mobile Wi-Fi + LTE (80+30=110Mbps)" \
    "80mbit" "delay 5ms 2ms distribution normal" \
    "30mbit" "delay 40ms 12ms distribution normal loss 0.5%" \
    "33M"

run_scenario "voip" \
    "VoIP simulation (G.711, 100Kbps/160B packets)" \
    "50mbit" "delay 10ms" \
    "50mbit" "delay 10ms" \
    "100K" "160"

# ================================================================
#  Summary
# ================================================================

echo ""
echo ""
echo "================================================================"
echo "  UDP Benchmark Results"
echo "================================================================"
echo ""
printf "  %-14s │ %10s %7s %7s │ %10s %7s %7s │ %s\n" \
    "Scenario" "MinRTT" "Jitter" "Loss" "WLB" "Jitter" "Loss" "Ratio"
echo "  ───────────────┼───────────────────────────┼───────────────────────────┼───────"

for name in "${SCENARIOS[@]}"; do
    bw_m="${R_BW[${name}_minrtt]:-N/A}"
    bw_w="${R_BW[${name}_wlb]:-N/A}"
    ji_m="${R_JITTER[${name}_minrtt]:-N/A}"
    ji_w="${R_JITTER[${name}_wlb]:-N/A}"
    lo_m="${R_LOSS[${name}_minrtt]:-N/A}"
    lo_w="${R_LOSS[${name}_wlb]:-N/A}"

    ratio="-"
    if [[ "$bw_m" =~ ^[0-9] ]] && [[ "$bw_w" =~ ^[0-9] ]]; then
        ratio=$(awk "BEGIN { if ($bw_m > 0) printf \"%.2fx\", $bw_w / $bw_m; else print \"-\" }")
    fi

    printf "  %-14s │ %7s Mbps %5s %5s%% │ %7s Mbps %5s %5s%% │ %s\n" \
        "$name" "$bw_m" "$ji_m" "$lo_m" "$bw_w" "$ji_w" "$lo_w" "$ratio"
done

echo "  ───────────────┴───────────────────────────┴───────────────────────────┴───────"
echo ""
echo "================================================================"
