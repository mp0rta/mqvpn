#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# bench_hybrid_scheduler.sh — Hybrid TCP-lane on/off × scheduler benchmark.
#
# Measures mqvpn v0.9.0 hybrid mode (TCP STREAM lane: client-side lwIP
# termination ↔ server-side egress relay) against the plain CONNECT-IP tunnel
# (raw IP over DATAGRAM), for the MinRTT and WLB multipath schedulers, over a
# symmetric 2-path link, sweeping the iperf3 parallel-stream count P.
#
# Topology (built on benchmarks/bench_env_setup.sh — the same env the hybrid
# e2e test test_e2e_hybrid_h2.sh uses, so the STREAM lane actually engages):
#   - iperf3 target is 10.222.0.1, a /32 loopback alias in the SERVER netns.
#     It is OUTSIDE the tunnel subnet (10.0.0.0/24), outside every client
#     on-link path subnet, and is not the VPN transport address — the four
#     conditions the classifier + egress ACL require for a TCP flow to be
#     laned to STREAM (see classifier.c: tunnel-subnet destinations stay RAW).
#     The client's full-tunnel default route (installed by mqvpn) sends it
#     through the TUN either way.
#   - hybrid ON:  [Hybrid] Enabled=true, Tcp=stream, EgressAllow=10.222.0.0/24
#     → client terminates TCP, relays over STREAM; server connect()s to
#       10.222.0.1. EgressAllow punches 10.222.0.1 through the default RFC1918
#       deny.
#   - hybrid OFF: no --config → TCP tunneled as raw IP (DATAGRAM). Same target,
#     reached via the server's ip_forward to its own lo. Only the lane differs
#     between the two arms — a clean A/B.
#
# Per cell we verify, not assume (both via the server control API, on demand —
# NOT the client [STATUS] log, whose lanes line only ticks every 30s
# (STATUS_INTERVAL_SEC) and so never fires within a short bench run):
#   - STREAM lane engaged (hybrid ON): get_stats `tcp_flows_total` > 0 (the
#     server opened ≥1 egress TCP flow; cumulative, survives flow close),
#     else status=NO_LANE.
#   - both paths carried load: get_status per-path bytes_tx+bytes_rx; the
#     lighter path <5% of the total → status=1PATH.
# Only VPN_FAIL / ZERO_BW / NO_LANE reps are excluded from the mean; 1PATH and
# NO_PATHDATA carry a valid throughput and are counted but flagged (minrtt
# legitimately single-paths a single flow at low P — that is a finding, not a
# failure).
#
# Output: bench_results/hybrid_mode/hybrid_mode_<epoch>.csv + stdout summary.
#
# Usage: sudo [MQVPN=/path/to/mqvpn] ./bench_hybrid_scheduler.sh
# Env:   REPEAT=3 PVALUES="1 2 4 8 16" SCHEDULERS="minrtt wlb"
#        NETEM="delay 25ms rate 100mbit limit 2000" DURATION=15 CTRL_PORT=9097
#
# ── Design notes (empirically validated) ────────────────────────────────────
# Two earlier attempts failed the "did the lane actually engage" check; both
# are load-bearing to avoid re-introducing:
#   1. The out-of-tunnel target (Topology above) is mandatory: an in-subnet
#      target would silently benchmark RAW under a "hybrid on" label.
#   2. Lane engagement MUST be read from the server control API
#      (tcp_flows_total), NOT the client [STATUS] log: that log's lanes line
#      only ticks every STATUS_INTERVAL_SEC=30, so a <30s bench run emits none
#      and the grep reads a false 0. get_stats is on-demand and cumulative.
# Verified by smoke: hybrid off ⇒ flows=0, RAW, both paths; hybrid on ⇒
# flows>0, both paths ~equal (STREAM lane striping). The margin varies with P
# (smoke: ~+13% at P=4) because the RAW baseline's single-flow reorder penalty
# grows as fewer flows spread the load — see the gain% caveat in the summary.
set -u

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bench_env_setup.sh"

REPEAT="${REPEAT:-3}"
PVALUES="${PVALUES:-1 2 4 8 16}"
SCHEDULERS="${SCHEDULERS:-minrtt wlb}"
# limit 2000 ≈ 5×BDP (BDP at 100mbit/50ms ≈ 420 pkts): deep enough not to
# tail-drop the aggregate in steady state, shallow enough to avoid the
# bufferbloat that would make the two arms' CC fill it differently. Paired
# with iperf's -O warmup below.
NETEM="${NETEM:-delay 25ms rate 100mbit limit 2000}"
DURATION="${DURATION:-15}"
CTRL_PORT="${CTRL_PORT:-9097}"
TARGET="10.222.0.1"

if [ "$(id -u)" -ne 0 ]; then echo "error: needs root (netns/tc). sudo." >&2; exit 1; fi
# bench_check_test_deps validates MQVPN + realpaths it, and checks each tool
# (incl. that nc is the OpenBSD build the control-API protocol needs).
bench_check_test_deps iperf3 python3 nc jq openssl tc || exit 1

RESULTS_DIR="${RESULTS_DIR:-${BENCH_DIR}/../bench_results/hybrid_mode}"
mkdir -p "$RESULTS_DIR"
CSV="${RESULTS_DIR}/hybrid_mode_$(date +%s).csv"
echo "scheduler,hybrid,P,rep,bw_mbps,path_lo_bytes,path_hi_bytes,tcp_flows_total,status" >"$CSV"

WORK="$(mktemp -d)"
INI_ON="${WORK}/hybrid_on.ini"
cat >"$INI_ON" <<EOF
[Hybrid]
Enabled = true
Tcp = stream
EgressAllow = 10.222.0.0/24
EOF

declare -A R_BW R_SP

trap 'bench_cleanup; rm -rf "$WORK"' EXIT

# ── helpers ─────────────────────────────────────────────────────────────────

# run_iperf_p <target> <duration> <P> — echo receiver Mbps ("0.0" on failure).
# Client stderr → /dev/null so a warning line can't corrupt the JSON parse.
run_iperf_p() {
    local target="$1" duration="$2" P="$3" json ipid
    json="$(mktemp)"
    ip netns exec "$NS_SERVER" iperf3 -s -B "$target" -1 &>/dev/null &
    ipid=$!
    sleep 1
    # -O 3: omit the first 3s so the reported average is steady-state, not the
    # CC ramp — the two arms (inner-TCP CUBIC vs split-TCP/QUIC-CC) ramp
    # differently, and without this the transient would leak into gain%.
    ip netns exec "$NS_CLIENT" timeout $((duration + 20)) \
        iperf3 -c "$target" -t "$duration" -O 3 -P "$P" --json >"$json" 2>/dev/null || true
    kill "$ipid" 2>/dev/null || true; wait "$ipid" 2>/dev/null || true
    python3 -c "
import json
try:
    e=json.load(open('$json')).get('end',{})
    print(f\"{e['sum_received']['bits_per_second']/1e6:.1f}\" if 'sum_received' in e else '0.0')
except Exception: print('0.0')"
    rm -f "$json"
}

# server_tcp_flows_total <ctrl_port> — cumulative count of egress TCP flows the
# server opened (get_stats). >0 proves the STREAM lane carried TCP; on demand,
# survives flow close. (pkts_lane_tcp is a CLIENT-side classify counter — always
# 0 in the server's stats — so it is deliberately not used as the gate.)
# Must be queried while the server is still alive.
server_tcp_flows_total() {
    bench_query_control "$1" get_stats | python3 -c "
import sys, json
try: print(json.load(sys.stdin).get('tcp_flows_total',0))
except Exception: print(0)"
}

# perpath_bytes <ctrl_port> — server-side per-path load (tx+rx), ascending, as
# "lo hi"; empty string if unavailable / <2 paths. Query while server alive.
perpath_bytes() {
    bench_query_control "$1" get_status | python3 -c "
import sys, json
try:
    ps=json.load(sys.stdin)['clients'][0]['paths']
    L=sorted(p.get('bytes_tx',0)+p.get('bytes_rx',0) for p in ps)
    print(f'{L[0]} {L[-1]}' if len(L)>=2 else '')
except Exception: print('')"
}

# _stats <list> — "mean min max n" in one pass ("- - - 0" when empty).
_stats() {
    awk '{for(i=1;i<=NF;i++){v=$i;s+=v;n++; if(n==1||v<mn)mn=v; if(n==1||v>mx)mx=v}}
         END{ if(!n){print "- - - 0";exit}
              printf "%.1f %.1f %.1f %d", s/n, mn, mx, n }' <<<"$1"
}

# ── one cell (all reps) ─────────────────────────────────────────────────────

# run_cell <scheduler> <hybrid:on|off> <P>
run_cell() {
    local sched="$1" hybrid="$2" P="$3"
    local key="${sched}_${hybrid}_P${P}"
    BENCH_SCHEDULER="$sched"
    local cfg=""; [ "$hybrid" = "on" ] && cfg="--config $INI_ON"

    local rep
    for rep in $(seq 1 "$REPEAT"); do
        printf "    %-6s hybrid=%-3s P=%-2s rep %d/%d ... " \
            "$sched" "$hybrid" "$P" "$rep" "$REPEAT"

        # Server log kept for failure autopsy; client log is unneeded (the lane
        # signal comes from the server API, not the client's 30s [STATUS] line).
        local slog; slog="$(mktemp)"
        if ! bench_start_vpn_server "--control-port $CTRL_PORT $cfg" "$slog" >/dev/null 2>&1 \
           || ! bench_start_vpn_client "--path $(bench_path_veth_client 0) --path $(bench_path_veth_client 1) $cfg" /dev/null >/dev/null 2>&1 \
           || ! bench_wait_tunnel 25 >/dev/null 2>&1; then
            echo "VPN_FAIL"; { echo "      ── server log tail ──"; tail -5 "$slog"; } >&2
            echo "${sched},${hybrid},${P},${rep},,,,,VPN_FAIL" >>"$CSV"
            bench_stop_vpn >/dev/null 2>&1; rm -f "$slog"; continue
        fi
        bench_wait_for_n_paths 2 20 "$CTRL_PORT" >/dev/null 2>&1 || true

        local bw; bw="$(run_iperf_p "$TARGET" "$DURATION" "$P")"
        # Query server counters while it is still alive.
        local flows_total; flows_total="$(server_tcp_flows_total "$CTRL_PORT")"
        local plo phi; read -r plo phi <<<"$(perpath_bytes "$CTRL_PORT")"
        bench_stop_vpn >/dev/null 2>&1; rm -f "$slog"

        # Status precedence: ZERO_BW > NO_LANE > NO_PATHDATA > 1PATH > OK.
        # NO_LANE (hybrid on but the server opened no egress TCP flow) means the
        # "on" run actually rode RAW → excluded from the mean.
        local status="OK"
        if ! awk -v b="$bw" 'BEGIN{exit !(b+0>0)}'; then
            status="ZERO_BW"
        elif [ "$hybrid" = "on" ] && [ "${flows_total:-0}" = "0" ]; then
            status="NO_LANE"
        elif [ -z "${plo:-}" ] || [ -z "${phi:-}" ]; then
            status="NO_PATHDATA"
        elif awk -v a="$plo" -v b="$phi" 'BEGIN{t=a+b; exit !(t>0 && a<0.05*t)}'; then
            status="1PATH"
        fi

        echo "${sched},${hybrid},${P},${rep},${bw},${plo:-},${phi:-},${flows_total},${status}" >>"$CSV"
        case "$status" in
            OK|1PATH|NO_PATHDATA) R_BW["$key"]="${R_BW[$key]:-} ${bw}" ;;
        esac
        [ "$status" = "1PATH" ] && R_SP["$key"]=$(( ${R_SP[$key]:-0} + 1 ))

        printf "%6s Mbps  path=%s/%s  flows=%s  [%s]\n" \
            "$bw" "${plo:-–}" "${phi:-–}" "${flows_total:-0}" "$status"
    done
}

# ── main ────────────────────────────────────────────────────────────────────

echo "================================================================"
echo "  mqvpn Hybrid TCP-lane × Scheduler Benchmark"
echo "  Binary:   $MQVPN  ($("$MQVPN" --version 2>/dev/null))"
echo "  Link:     ${NETEM} per leg, symmetric, 2 paths (RTT ≈ 2×delay)"
echo "  Target:   ${TARGET} (out-of-tunnel egress, STREAM-lane eligible)"
echo "  iperf3:   TCP uplink -P {${PVALUES// /,}} -t ${DURATION}s, ${REPEAT} reps"
echo "  Sched:    ${SCHEDULERS}"
echo "  CSV:      $CSV"
echo "  Date:     $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

bench_setup_netns_n 2
bench_add_server_host_routes 2
ip netns exec "$NS_SERVER" ip addr add "${TARGET}/32" dev lo
bench_apply_netem "$NETEM" "$NETEM"

for sched in $SCHEDULERS; do
    for hybrid in off on; do
        echo ""
        echo "━━━ scheduler=${sched}  hybrid=${hybrid} ━━━"
        for P in $PVALUES; do
            run_cell "$sched" "$hybrid" "$P"
        done
    done
done

# ── summary ─────────────────────────────────────────────────────────────────

echo ""; echo ""
echo "================================================================"
echo "  Results — receiver throughput (Mbps), mean of valid reps"
echo "================================================================"
echo ""
printf "  %-6s │ %-2s │ %-22s │ %-22s │ %-5s │ %s\n" \
    "sched" "P" "hyb=off  mean(min-max) n" "hyb=on   mean(min-max) n" "gain" "sp o/n"
echo "  ───────┼────┼────────────────────────┼────────────────────────┼───────┼──────"
for sched in $SCHEDULERS; do
    for P in $PVALUES; do
        read -r om onl oh no <<<"$(_stats "${R_BW[${sched}_off_P${P}]:-}")"
        read -r nm onn nh nn <<<"$(_stats "${R_BW[${sched}_on_P${P}]:-}")"
        gain="-"
        if [[ "$om" =~ ^[0-9] ]] && [[ "$nm" =~ ^[0-9] ]]; then
            gain=$(awk "BEGIN{ if($om>0) printf \"%+.0f%%\", ($nm/$om-1)*100; else print \"-\" }")
        fi
        printf "  %-6s │ %-2s │ %6s (%5s-%5s) %d │ %6s (%5s-%5s) %d │ %-5s │ %d/%d\n" \
            "$sched" "$P" "$om" "$onl" "$oh" "$no" "$nm" "$onn" "$nh" "$nn" "$gain" \
            "${R_SP[${sched}_off_P${P}]:-0}" "${R_SP[${sched}_on_P${P}]:-0}"
    done
    echo "  ───────┼────┼────────────────────────┼────────────────────────┼───────┼──────"
done
echo ""
echo "  n = valid reps of ${REPEAT} (VPN_FAIL / ZERO_BW / NO_LANE excluded; see CSV)."
echo "  sp o/n = reps that used a single path (off/on), counted not excluded —"
echo "     expected for minrtt at low P: a single flow does not stripe across paths."
echo "  gain% is the intended hybrid A/B, NOT pure lane efficiency: the RAW (off)"
echo "     baseline also pays the datagram packet-reorder penalty (a single TCP"
echo "     flow striped across two 25ms legs backs off on reorder), which the"
echo "     in-order STREAM lane avoids — so gain% widens as fewer flows spread load."
echo "  Scope: TCP uplink (client→server) only; iperf -O 3 warmup (steady-state)."
echo "  CSV: $CSV"
echo "================================================================"
