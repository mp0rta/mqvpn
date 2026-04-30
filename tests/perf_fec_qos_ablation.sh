#!/bin/bash
# perf_fec_qos_ablation.sh — FEC QoS ablation matrix.
#
# Compares HIGH (FEC off) vs NORMAL (FEC on) DATAGRAM QoS across 4 netem
# profiles and writes results as CSV + a markdown summary.
#
# REQUIRES:
#   - root (netem on netns)
#   - build with -DMQVPN_DEBUG_QOS_OVERRIDE=ON -DXQC_ENABLE_FEC=ON -DXQC_ENABLE_XOR=ON
#   - iperf3
#   - netem (sch_netem kernel module; modprobe sch_netem if missing)
#
# Run:
#   sudo bash tests/perf_fec_qos_ablation.sh [path/to/mqvpn]
#
# Output:
#   - CSV to stdout
#   - markdown table at $RESULTS (default /tmp/mqvpn-fec-grid-results.md;
#     override with the RESULTS env var to write elsewhere)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

# Probe netem availability — fail fast if the kernel module is missing,
# otherwise the loss/delay cells will silently behave like no_loss.
if ! tc qdisc add dev lo root netem loss 0% 2>/dev/null; then
    echo "ERROR: 'tc qdisc … netem' not available. Load sch_netem (modprobe sch_netem) or check tc/iproute2 install." >&2
    exit 2
fi
tc qdisc del dev lo root 2>/dev/null || true

MQVPN="${1:-${MQVPN}}"
LOG_DIR="$(mktemp -d)"
ALL_WORK_DIRS=()
RESULTS="${RESULTS:-/tmp/mqvpn-fec-grid-results.md}"
trap 'bench_cleanup; for d in "${ALL_WORK_DIRS[@]}"; do rm -rf "$d"; done; rm -rf "$LOG_DIR"' EXIT

QOS_LEVELS=("high" "normal")
declare -A NETEM_PROFILES=(
    [no_loss]=""
    [loss_5]="loss 5%"
    [loss_5_burst]="loss 5% 25%"
    [ntn_like]="loss 1% delay 50ms 10ms"
)

run_one_cell() {
    local qos="$1"
    local profile="$2"
    local netem="$3"

    bench_setup_netns
    if [[ -n "$netem" ]]; then
        ip netns exec "$NS_CLIENT" tc qdisc add dev veth-a0 root netem $netem || true
    fi

    BENCH_SCHEDULER="backup_fec"
    export MQVPN_DGRAM_QOS_OVERRIDE="$qos"
    local server_log="${LOG_DIR}/${qos}_${profile}_server.log"
    local client_log="${LOG_DIR}/${qos}_${profile}_client.log"

    # Generate PSK and TLS cert for this cell (matches bench_start_vpn_server
    # flow which always regenerates into a fresh _BENCH_WORK_DIR).
    _BENCH_WORK_DIR="$(mktemp -d)"
    ALL_WORK_DIRS+=("$_BENCH_WORK_DIR")
    _BENCH_PSK=$("$MQVPN" --genkey 2>/dev/null)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${_BENCH_WORK_DIR}/server.key" -out "${_BENCH_WORK_DIR}/server.crt" \
        -days 365 -nodes -subj "/CN=mqvpn-bench" 2>/dev/null

    # Start server inside the server netns.
    # Flags deliberately mirror bench_start_vpn_server (bench_env_setup.sh L143-151).
    ip netns exec "$NS_SERVER" "$MQVPN" \
        --mode server \
        --listen "0.0.0.0:${VPN_LISTEN_PORT}" \
        --subnet 10.0.0.0/24 \
        --cert "${_BENCH_WORK_DIR}/server.crt" \
        --key  "${_BENCH_WORK_DIR}/server.key" \
        --auth-key "$_BENCH_PSK" \
        --scheduler "$BENCH_SCHEDULER" \
        --log-level "$BENCH_LOG_LEVEL" \
        >"$server_log" 2>&1 &
    _BENCH_SERVER_PID=$!
    sleep 1

    bench_start_vpn_client "--path veth-a0 --path veth-b0" "$client_log"
    sleep 2

    local sent=1000
    local recv
    recv=$(ip netns exec "$NS_CLIENT" \
        timeout 5 ping -c "$sent" -i 0.001 "$TUNNEL_SERVER_IP" 2>/dev/null \
        | grep -oE '[0-9]+ received' | awk '{print $1}' || true)
    recv=${recv:-0}
    local loss_pct
    loss_pct=$(awk -v r="$recv" -v s="$sent" 'BEGIN{ printf "%.2f", (s-r)*100.0/s }')

    local iperf_pidfile="${LOG_DIR}/iperf3.pid"
    ip netns exec "$NS_SERVER" iperf3 -s -D --pidfile "$iperf_pidfile" >/dev/null 2>&1 || true
    sleep 1
    if [[ ! -f "$iperf_pidfile" ]] || ! kill -0 "$(cat "$iperf_pidfile" 2>/dev/null)" 2>/dev/null; then
        echo "  WARN: iperf3 server failed to start in cell ${qos}/${profile}" >&2
    fi
    local tput_mbps
    tput_mbps=$(ip netns exec "$NS_CLIENT" \
        iperf3 -c "$TUNNEL_SERVER_IP" -t 5 -J 2>/dev/null \
        | grep -oE '"bits_per_second":\s*[0-9.]+' | tail -1 \
        | grep -oE '[0-9.]+' | awk '{ printf "%.2f", $1/1000000 }' || true)
    tput_mbps=${tput_mbps:-0}
    kill "$(cat "$iperf_pidfile" 2>/dev/null)" 2>/dev/null || true

    # Trigger graceful close so the server flushes svr_log_conn_stats
    if [[ -n "$_BENCH_CLIENT_PID" ]]; then
        kill -TERM "$_BENCH_CLIENT_PID" 2>/dev/null || true
        wait "$_BENCH_CLIENT_PID" 2>/dev/null || true
    fi
    sleep 2

    local fec_send fec_recover
    fec_send=$(grep -oE 'fec_send=[0-9]+' "$server_log" | tail -1 | cut -d= -f2 || true)
    fec_send=${fec_send:-0}
    fec_recover=$(grep -oE 'fec_recover=[0-9]+' "$server_log" | tail -1 | cut -d= -f2 || true)
    fec_recover=${fec_recover:-0}

    local cpu_user cpu_sys
    read -r cpu_user cpu_sys < <(top -bn1 | awk '/^%Cpu/ { print $2, $4; exit }')
    cpu_user=${cpu_user:-0}
    cpu_sys=${cpu_sys:-0}

    echo "${qos},${profile},${loss_pct},${tput_mbps},${fec_send:-0},${fec_recover:-0},${cpu_user:-0},${cpu_sys:-0}"

    bench_cleanup
    unset MQVPN_DGRAM_QOS_OVERRIDE
}

echo "qos,netem,inner_udp_loss_pct,inner_tcp_throughput_mbps,fec_send,fec_recover,cpu_user_pct,cpu_sys_pct"
for qos in "${QOS_LEVELS[@]}"; do
    for profile in "${!NETEM_PROFILES[@]}"; do
        run_one_cell "$qos" "$profile" "${NETEM_PROFILES[$profile]}"
    done
done | tee "${LOG_DIR}/results.csv"

mkdir -p "$(dirname "$RESULTS")"
{
    echo "# PR1 FEC QoS ablation results"
    echo ""
    echo "**Run date:** $(date -u +%Y-%m-%d)"
    echo "**Build:** \`-DMQVPN_DEBUG_QOS_OVERRIDE=ON -DXQC_ENABLE_FEC=ON -DXQC_ENABLE_XOR=ON\`"
    echo ""
    echo "| QoS | netem | UDP loss % | TCP Mbps | fec_send | fec_recover | CPU u/s |"
    echo "|---|---|---|---|---|---|---|"
    # Filter out helper-stdout noise that the outer `tee` captured alongside
    # the per-cell echo lines. Only rows whose qos column matches the matrix
    # values and that have all 8 fields are real data.
    awk -F, 'NF==8 && $1 ~ /^(high|normal)$/ { printf "| %s | %s | %s | %s | %s | %s | %s/%s |\n", $1,$2,$3,$4,$5,$6,$7,$8 }' \
        "${LOG_DIR}/results.csv"
    echo ""
    echo "## Expected observations"
    echo ""
    echo "- \`loss_5_burst\` row: \`UDP loss %\` for \`normal\` < \`high\` — confirms FEC recovery."
    echo "- \`no_loss\` row: \`TCP Mbps\` for \`normal\` ≈ \`high\` — no priority side-effect regression."
} > "$RESULTS"

echo ""
echo "Results written to $RESULTS"
