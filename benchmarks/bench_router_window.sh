#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# bench_router_window.sh — lwIP receive-window sweep on the ROUTER topology.
#
# WHY THIS EXISTS (do not fold it into sweep_single_path.sh):
# docs/hybrid_h2_memory_budget.md §5a retired the "shrinking TCP_WND costs
# goodput" caveat, but explicitly scoped the retirement to a topology where the
# inner TCP connection terminates ON THE SAME DEVICE that runs lwIP — an iOS app
# talking to its own Network Extension, µs-scale, no real BDP to fill. Every
# existing sweep inherits that shape: bench_env_setup.sh runs iperf3 inside
# NS_CLIENT, i.e. the same netns as the lwIP terminator, reaching it over the
# TUN. The WAN legs were the swept variable; the inner hop never was.
#
# On a router (the OpenMPTCProuter integration) that assumption does not hold:
# the inner TCP peer is a DIFFERENT MACHINE on the LAN, so the lwIP window has
# to cover a real LAN bandwidth-delay product. This script builds that shape —
#
#   [bench-lan]  iperf3 client, 192.168.50.2
#        | veth-lan0/1  (+ netem: the LAN hop under test)
#   [bench-client]  = the ROUTER: ip_forward + MASQUERADE into the tunnel,
#        |            mqvpn client, lwIP TCP lane terminates the inner TCP here
#        | veth-a0/b0 (+ netem: the two WAN legs)
#   [bench-server]  mqvpn server + iperf3 target 10.222.0.1 (OUT of tunnel)
#
# — and sweeps MQVPN_LWIP_RCV_SCALE so the window can be sized from measurement
# instead of from the iOS result.
#
# Usage:
#   sudo -E benchmarks/bench_router_window.sh
# Env:
#   SCALES     window scales to compare, first = reference   (default "5 4 3")
#   LAN_NETEM  LAN hop profiles, ';'-separated tc netem args
#              (default "delay 0.5ms rate 1000mbit limit 5000;delay 4ms rate 1000mbit limit 5000")
#   REPEAT     reps per cell (default 3)
#   DURATION   iperf3 seconds per rep (default 15)
#   PVALUES    parallel inner streams (default "1 8")
#   BUILD_DIR  where per-scale builds are staged (default build-winsweep)
#   XQUIC_BUILD_DIR  prebuilt xquic (default third_party/xquic/build)
#
# TWO TRAPS INHERITED FROM bench_hybrid_scheduler.sh — both silently produce a
# "hybrid on" number that actually measured RAW:
#   1. The iperf3 target MUST be out-of-tunnel (10.222.0.1, a /32 on the server's
#      lo, reached via [Hybrid] EgressAllow). A tunnel-subnet target is forced to
#      RAW by the classifier.
#   2. Lane engagement is proven by the SERVER control API's get_stats
#      tcp_flows_total, NOT by the client's [STATUS] log line — that ticks every
#      30 s, so a short run emits none and a grep reads a false 0.
set -uo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$BENCH_DIR/.." && pwd)"

SCALES="${SCALES:-5 4 3}"
LAN_NETEM="${LAN_NETEM:-delay 0.5ms rate 1000mbit limit 5000;delay 4ms rate 1000mbit limit 5000}"
REPEAT="${REPEAT:-3}"
DURATION="${DURATION:-15}"
PVALUES="${PVALUES:-1 8}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-winsweep}"
XQUIC_BUILD_DIR="${XQUIC_BUILD_DIR:-$ROOT/third_party/xquic/build}"
CTRL_PORT="${CTRL_PORT:-9098}"
TARGET="10.222.0.1"

NS_LAN="bench-lan"
LAN_VETH_L="veth-lan0"   # in NS_LAN
LAN_VETH_R="veth-lan1"   # in NS_CLIENT (router side)
LAN_IP_CLIENT="192.168.50.2"
LAN_IP_ROUTER="192.168.50.1"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: needs root for netns (run under sudo -E)" >&2; exit 1
fi

OUT="${RESULTS_DIR:-$ROOT/ci_sweep_results/router-window-$(date +%m%d-%H%M%S)}"
mkdir -p "$OUT"
CSV="$OUT/router_window.csv"
echo "scale,lan_profile,P,rep,bw_mbps,tcp_flows_total,status" >"$CSV"
echo "output: $OUT"

# ── build one mqvpn per scale ───────────────────────────────────────────────
# Separate build dirs, not a rebuild in place: a stale object from the previous
# scale would silently mix two window sizes into one binary.
for s in $SCALES; do
    bdir="$BUILD_DIR/s$s"
    if [ ! -x "$bdir/mqvpn" ]; then
        echo "=== building scale $s -> $bdir ==="
        cmake -S "$ROOT" -B "$bdir" -DCMAKE_BUILD_TYPE=Release \
            -DMQVPN_ENABLE_HYBRID_TCP_LANE=ON \
            -DXQUIC_BUILD_DIR="$XQUIC_BUILD_DIR" \
            -DCMAKE_C_FLAGS="-DMQVPN_LWIP_RCV_SCALE=$s" >"$OUT/build-s$s.log" 2>&1 \
          && cmake --build "$bdir" -j"$(nproc)" >>"$OUT/build-s$s.log" 2>&1 \
          || { echo "BUILD FAILED for scale $s — see $OUT/build-s$s.log"; exit 1; }
    fi
    # Prove the binary really carries this scale rather than the default: the
    # whole sweep is meaningless if the -D silently failed to reach lwipopts.h.
    got=$(cc -E -dM -DMQVPN_LWIP_RCV_SCALE=$s -I"$ROOT/src" -I"$ROOT/src/hybrid" \
              -I"$ROOT/src/hybrid/lwip_port" -I"$ROOT/third_party/lwip/src/include" \
              -include "$ROOT/src/hybrid/lwip_port/lwipopts.h" -x c /dev/null \
          | awk '/^#define MQVPN_LWIP_RCV_SCALE /{print $3}')
    [ "$got" = "$s" ] || { echo "scale pin mismatch: wanted $s got '$got'"; exit 1; }
    echo "scale $s: TCP_WND = $(( 65535 << s )) B"
done

source "$BENCH_DIR/bench_env_setup.sh"

WORK="$(mktemp -d)"
INI="$WORK/hybrid.ini"
cat >"$INI" <<EOF
[Hybrid]
Enabled = true
Tcp = stream
EgressAllow = 10.222.0.0/24
EOF

lan_teardown() {
    ip netns del "$NS_LAN" 2>/dev/null || true
}
trap 'lan_teardown; bench_cleanup; rm -rf "$WORK"' EXIT

# ── LAN leg: the whole point of this script ─────────────────────────────────
# Must run AFTER the tunnel is up: the MASQUERADE rule and the forward route
# both reference the TUN device mqvpn creates at connect time.
lan_setup() {
    local netem="$1" tun
    lan_teardown
    ip netns add "$NS_LAN"
    ip link add "$LAN_VETH_L" type veth peer name "$LAN_VETH_R"
    ip link set "$LAN_VETH_L" netns "$NS_LAN"
    ip link set "$LAN_VETH_R" netns "$NS_CLIENT"
    ip netns exec "$NS_LAN" ip addr add "$LAN_IP_CLIENT/24" dev "$LAN_VETH_L"
    ip netns exec "$NS_LAN" ip link set "$LAN_VETH_L" up
    ip netns exec "$NS_LAN" ip link set lo up
    ip netns exec "$NS_LAN" ip route add default via "$LAN_IP_ROUTER"
    ip netns exec "$NS_CLIENT" ip addr add "$LAN_IP_ROUTER/24" dev "$LAN_VETH_R"
    ip netns exec "$NS_CLIENT" ip link set "$LAN_VETH_R" up

    # netem on the ROUTER side of the LAN pair shapes router->LAN (the
    # download direction the iperf3 receiver measures).
    # shellcheck disable=SC2086
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$LAN_VETH_R" root netem $netem
    # shellcheck disable=SC2086
    ip netns exec "$NS_LAN" tc qdisc add dev "$LAN_VETH_L" root netem $netem

    ip netns exec "$NS_CLIENT" sysctl -qw net.ipv4.ip_forward=1
    tun="$(ip netns exec "$NS_CLIENT" ip -o link show \
           | awk -F': ' '/mqvpn|tun/{print $2; exit}')"
    [ -n "$tun" ] || { echo "  ERROR: no TUN in $NS_CLIENT"; return 1; }
    # MASQUERADE rather than a return route on the server: it is what a real
    # router does, and it keeps the server side identical to every other bench
    # (packets enter the tunnel with the client's assigned tunnel IP, so the
    # classifier sees exactly the source it sees without a LAN leg).
    ip netns exec "$NS_CLIENT" iptables -t nat -A POSTROUTING -o "$tun" \
        -s "192.168.50.0/24" -j MASQUERADE || return 1
    echo "  LAN leg up via $tun (netem: $netem)"
}

# run_iperf_lan <P> — receiver Mbps measured FROM THE LAN NETNS ("0.0" on error)
run_iperf_lan() {
    local P="$1" json ipid
    json="$(mktemp)"
    ip netns exec "$NS_SERVER" iperf3 -s -B "$TARGET" -1 &>/dev/null &
    ipid=$!
    sleep 1
    # -O 3 drops the CC ramp; the arms ramp differently per window size and the
    # transient would otherwise leak straight into the comparison.
    ip netns exec "$NS_LAN" timeout $((DURATION + 20)) \
        iperf3 -c "$TARGET" -t "$DURATION" -O 3 -P "$P" --json >"$json" 2>/dev/null || true
    kill "$ipid" 2>/dev/null || true; wait "$ipid" 2>/dev/null || true
    python3 -c "
import json
try:
    e=json.load(open('$json')).get('end',{})
    print(f\"{e['sum_received']['bits_per_second']/1e6:.1f}\" if 'sum_received' in e else '0.0')
except Exception: print('0.0')"
    rm -f "$json"
}

server_flows() {
    bench_query_control "$CTRL_PORT" get_stats | python3 -c "
import sys, json
try: print(json.load(sys.stdin).get('tcp_flows_total',0))
except Exception: print(0)"
}

# ── sweep ───────────────────────────────────────────────────────────────────
lan_idx=0
IFS=';' read -ra LAN_PROFILES <<<"$LAN_NETEM"
for netem in "${LAN_PROFILES[@]}"; do
    lan_idx=$((lan_idx + 1))
    for s in $SCALES; do
        echo "=== scale $s | LAN '$netem' ($(date '+%H:%M:%S')) ==="
        # Consumed by the sourced harness (bench_start_vpn_{server,client} read
        # $MQVPN at call time), which is why shellcheck cannot see the use.
        # shellcheck disable=SC2034
        MQVPN="$BUILD_DIR/s$s/mqvpn"
        bench_cleanup >/dev/null 2>&1 || true
        bench_setup_netns >/dev/null || { echo "  netns setup failed"; continue; }
        bench_apply_netem >/dev/null 2>&1 || true
        bench_add_server_host_routes 2 >/dev/null 2>&1 || true
        bench_start_vpn_server "--control-port $CTRL_PORT --config $INI" \
            "$OUT/server-s$s-l$lan_idx.log" >/dev/null || { echo "  server failed"; continue; }
        bench_start_vpn_client "--path $VETH_A0 --path $VETH_B0 --config $INI" \
            "$OUT/client-s$s-l$lan_idx.log" >/dev/null || { echo "  client failed"; continue; }
        bench_wait_tunnel 20 >/dev/null || { echo "  tunnel not up"; continue; }
        lan_setup "$netem" || { echo "  LAN setup failed"; continue; }

        for P in $PVALUES; do
            for rep in $(seq 1 "$REPEAT"); do
                before=$(server_flows)
                bw=$(run_iperf_lan "$P")
                after=$(server_flows)
                delta=$((after - before))
                status=OK
                # Trap 2: a nonzero bw with delta==0 means the traffic went RAW,
                # not through the lane — that row must NOT be averaged in.
                [ "$delta" -gt 0 ] || status=NO_LANE
                [ "$bw" = "0.0" ] && status=ZERO_BW
                echo "$s,$lan_idx,$P,$rep,$bw,$delta,$status" >>"$CSV"
                echo "  scale=$s lan=$lan_idx P=$P rep=$rep  ${bw} Mbps  flows=$delta  $status"
            done
        done
        bench_cleanup >/dev/null 2>&1 || true
        lan_teardown
    done
done

echo
echo "=== summary (OK rows only; first scale in SCALES is the reference) ==="
python3 - "$CSV" "$SCALES" <<'PY'
import csv, sys, statistics as st
rows=[r for r in csv.DictReader(open(sys.argv[1])) if r['status']=='OK']
scales=sys.argv[2].split(); ref=scales[0]
agg={}
for r in rows:
    agg.setdefault((r['scale'],r['lan_profile'],r['P']),[]).append(float(r['bw_mbps']))
if not agg:
    print("NO OK ROWS — every cell failed the lane gate; check the logs."); sys.exit(1)
print(f"{'lan':>4} {'P':>3} " + " ".join(f"{'s'+s:>10}" for s in scales) + "   worst vs ref")
worst=0.0
for lan in sorted({k[1] for k in agg}):
    for P in sorted({k[2] for k in agg}, key=int):
        base=agg.get((ref,lan,P))
        cells=[]
        for s in scales:
            v=agg.get((s,lan,P))
            cells.append(f"{st.mean(v):10.1f}" if v else f"{'-':>10}")
        d=""
        if base:
            for s in scales[1:]:
                v=agg.get((s,lan,P))
                if v:
                    pct=(st.mean(v)-st.mean(base))/st.mean(base)*100
                    worst=min(worst,pct); d+=f" s{s}:{pct:+.1f}%"
        print(f"{lan:>4} {P:>3} " + " ".join(cells) + "  " + d)
print(f"\nworst cell vs reference: {worst:+.1f}%   (gate: -5%)")
print("PASS" if worst > -5.0 else "FAIL")
PY
echo "csv: $CSV"
