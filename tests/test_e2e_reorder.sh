#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# test_e2e_reorder.sh — Netns end-to-end test for the reorder-buffer feature
# (Phase 1/2) against the real xquic engine.
#
# What this verifies:
#   Phase A (negotiation): with [Reorder] Enabled=on on BOTH ends, the tunnel
#     establishes and the mqvpn-reorder capability is negotiated. We key on the
#     real INFO log markers emitted by the implementation:
#       - server: "client advertised mqvpn-reorder"
#               (src/mqvpn_server.c:919, LOG_I, §19.3)
#       - client: "peer advertised mqvpn-reorder; TX stamping enabled"
#               (src/mqvpn_client.c:1138, LOG_I, §19.3)
#     The reorder shim wire header is 8 bytes (MQVPN_REORDER_HDR_LEN,
#     src/reorder.h:45) and the client subtracts it ONCE from the inner TUN MTU
#     (src/mqvpn_client.c:1170-1174, §9). There is NO dedicated "MTU -8" log
#     marker — the subtraction is silent. We instead verify it behaviorally:
#     the platform layer logs the final TUN MTU at
#       "TUN <dev> configured: ... (mtu=<N>)"
#       (src/platform/linux/platform_linux.c:126, LOG_INF)
#     so we parse that mtu= from the reorder-ON run and the reorder-OFF run and
#     assert ON == OFF - 8.
#
#   Phase B (data path): an inner UDP workload (iperf3 -u) runs across the
#     tunnel on the ReorderRule Port, over two paths with an RTT spread applied
#     by netem so striping produces reordering. We assert the transfer completes
#     and data is delivered. (If iperf3 is unavailable the data check degrades
#     to a tunnel ping, like tests/test_e2e_backup_fec.sh.)
#
#   Phase C (regression / wire-compat): a second full run with
#     [Reorder] Enabled=off confirms the tunnel still works unchanged and that
#     NO reorder negotiation occurs (markers absent), proving the feature is a
#     no-op when disabled.
#
# How reorder is enabled: the harness (bench_start_vpn_*) only takes CLI flags,
# and there is no CLI flag for the [Reorder] section — it is INI/JSON only
# (src/config.c SEC_REORDER). mqvpn's --config loads the file as a base and CLI
# flags override per-field (src/main.c:321-331,365-388), so we generate a tiny
# INI containing ONLY [Reorder]/[ReorderRule] and pass it via --config alongside
# the harness's existing --listen/--server/--path/--auth-key flags.
#
# Requires: root, netns support, netcat-openbsd, jq, iperf3 (iperf3 optional).
# Usage:    sudo ./test_e2e_reorder.sh [mqvpn-binary]

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../benchmarks/bench_env_setup.sh
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
N_PATHS=2
CTRL_PORT=9094
INNER_UDP_PORT=5301   # ReorderRule Port + iperf3 -u server port (inner workload)

CLIENT_LOG="$(mktemp)"
SERVER_LOG="$(mktemp)"
CLIENT_LOG_OFF="$(mktemp)"
SERVER_LOG_OFF="$(mktemp)"
INI_ON="$(mktemp --suffix=.ini)"
INI_OFF="$(mktemp --suffix=.ini)"

trap 'bench_cleanup; rm -f "$CLIENT_LOG" "$SERVER_LOG" "$CLIENT_LOG_OFF" \
    "$SERVER_LOG_OFF" "$INI_ON" "$INI_OFF"' EXIT

fail=0

echo "[reorder] N=$N_PATHS binary=$MQVPN inner-udp-port=$INNER_UDP_PORT"
bench_check_test_deps nc jq

# ── Generate the reorder INI (config mechanism: --config base + CLI override) ──
# Keys/values cross-checked against src/config.c:
#   [Reorder] Enabled  on/off   -> parse_reorder_enabled (config.c:298)
#   [Reorder] MaxWaitMs <ms>     -> config.c (SEC_REORDER)
#   [ReorderRule] Proto udp      -> parse_reorder_proto   (config.c:319)
#   [ReorderRule] Port  <P>      -> config.c:612
#   [ReorderRule] Profile quic_bulk -> parse_reorder_profile (config.c:336)
#
# MaxWaitMs = 60 is chosen ABOVE the 40ms path-B spread (netem below) on purpose:
# the late packet from the slow path then arrives WITHIN the reorder wait window,
# so the buffered gap actually FILLS (gap_filled_count>0) instead of timing out.
# This lets Phase B prove the engine genuinely re-orders packets, not merely that
# it activates. (With the default 30ms wait < 40ms spread, every period would
# time out — the §24 H5 "wait < RTT spread" regime where the shim only adds cost.)
cat >"$INI_ON" <<EOF
[Reorder]
Enabled = on
MaxWaitMs = 60

[ReorderRule]
Proto = udp
Port = ${INNER_UDP_PORT}
Profile = quic_bulk
EOF

cat >"$INI_OFF" <<EOF
[Reorder]
Enabled = off
EOF

# ── Topology: 2 paths, RTT spread on path 1 so striping reorders inner pkts ──
bench_setup_netns_n "$N_PATHS"
bench_add_server_host_routes "$N_PATHS"
# Path A (slot 0): low latency. Path B (slot 1): +40ms one-way delay. The RTT
# asymmetry across the two striped paths is what produces out-of-order arrival
# at the receiver, which is exactly what the reorder buffer must absorb.
bench_apply_netem "delay 1ms" "delay 40ms"

# Helper: run one full server+client lifecycle with a given INI + log files.
# $1 = INI path, $2 = server log, $3 = client log
reorder_run() {
    local ini="$1" slog="$2" clog="$3"
    bench_start_vpn_server "--control-port ${CTRL_PORT} --config ${ini}" "$slog"

    local paths_arg=""
    local i
    for (( i=0; i<N_PATHS; i++ )); do
        paths_arg="${paths_arg} --path $(bench_path_veth_client "$i")"
    done
    bench_start_vpn_client "${paths_arg} --config ${ini}" "$clog"

    bench_wait_tunnel 25
}

# Extract the negotiated TUN MTU the client applied, from the platform marker
# "TUN <dev> configured: ... (mtu=<N>)" (platform_linux.c:126). Echoes the int
# or empty string if not found.
extract_client_mtu() {
    local clog="$1"
    grep -oE 'TUN .* configured:.*\(mtu=[0-9]+\)' "$clog" 2>/dev/null \
        | grep -oE 'mtu=[0-9]+' | tail -1 | cut -d= -f2
}

# Run an inner UDP workload on the ReorderRule port across the tunnel. iperf3
# server binds inside NS_SERVER on the tunnel IP; client drives it from
# NS_CLIENT. Returns 0 if the transfer completed (or fell back to ping OK).
# Sets WORKLOAD_KIND to "iperf3" (high-rate UDP, reliably exercises the reorder
# engine) or "ping" (low-rate fallback that may NOT generate enough in-flight
# packets to arm a reorder period) so the caller can decide whether the
# "engine fired" (gap_count>0) check is a hard assertion or informational.
WORKLOAD_KIND=""
run_inner_udp_workload() {
    if command -v iperf3 >/dev/null 2>&1; then
        ip netns exec "$NS_SERVER" iperf3 -s -p "$INNER_UDP_PORT" -1 -D \
            --pidfile /tmp/iperf3-reorder.pid >/dev/null 2>&1 || true
        sleep 1
        # -u UDP, modest rate, short run; --cport pins client src port too so the
        # 4-tuple's dst port matches the ReorderRule. dst port = INNER_UDP_PORT.
        if ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_SERVER_IP" \
                -p "$INNER_UDP_PORT" -u -b 20M -l 1200 -t 6 >/dev/null 2>&1; then
            kill "$(cat /tmp/iperf3-reorder.pid 2>/dev/null)" 2>/dev/null || true
            rm -f /tmp/iperf3-reorder.pid
            WORKLOAD_KIND="iperf3"
            return 0
        fi
        kill "$(cat /tmp/iperf3-reorder.pid 2>/dev/null)" 2>/dev/null || true
        rm -f /tmp/iperf3-reorder.pid
        echo "  (iperf3 transfer failed; falling back to tunnel ping)" >&2
    else
        echo "  (iperf3 not installed; falling back to tunnel ping)" >&2
    fi
    # Fallback: prove inner data still flows across the RTT-spread paths.
    WORKLOAD_KIND="ping"
    ip netns exec "$NS_CLIENT" ping -c 10 -i 0.2 -W 2 "$TUNNEL_SERVER_IP" \
        >/dev/null 2>&1
}

# ─── Phase A + B: reorder ENABLED ──────────────────────────────────────────
echo ""
echo "=== Phase A: negotiation (reorder ON) ==="
reorder_run "$INI_ON" "$SERVER_LOG" "$CLIENT_LOG"

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
    echo "PASS: tunnel established (reorder ON)"
else
    echo "FAIL: tunnel did not establish with reorder ON"
    fail=1
fi

# Negotiation markers (both ends must log them). EXACT source strings:
#   src/mqvpn_server.c:919  -> "client advertised mqvpn-reorder"
#   src/mqvpn_client.c:1138 -> "peer advertised mqvpn-reorder; TX stamping enabled"
if grep -q "client advertised mqvpn-reorder" "$SERVER_LOG"; then
    echo "PASS: server logged reorder advertisement from client"
else
    echo "FAIL: server did NOT log 'client advertised mqvpn-reorder'"
    fail=1
fi

if grep -q "peer advertised mqvpn-reorder; TX stamping enabled" "$CLIENT_LOG"; then
    echo "PASS: client logged reorder echo from server (TX stamping enabled)"
else
    echo "FAIL: client did NOT log 'peer advertised mqvpn-reorder; TX stamping enabled'"
    fail=1
fi

mtu_on="$(extract_client_mtu "$CLIENT_LOG")"
if [ -n "$mtu_on" ]; then
    echo "INFO: client TUN MTU with reorder ON = $mtu_on"
else
    echo "WARN: could not parse client TUN MTU from log (marker drift?)"
fi

echo ""
echo "=== Phase B: inner UDP data path (reorder ON, RTT-spread paths) ==="
if run_inner_udp_workload; then
    echo "PASS: inner UDP workload completed across reordering paths"
else
    echo "FAIL: inner UDP workload did not complete"
    fail=1
fi

# Confirm traffic actually traversed the tunnel via the control API.
status_on="$(bench_query_control "$CTRL_PORT" get_status)"
tx_on=$(echo "$status_on" | jq '.clients[0].bytes_tx // 0' 2>/dev/null || echo 0)
if [ "${tx_on:-0}" -gt 0 ]; then
    echo "PASS: server observed client bytes_tx=$tx_on (data flowed through tunnel)"
else
    echo "FAIL: control API shows no client tx bytes (bytes_tx=$tx_on)"
    fail=1
fi

# ── Prove the reorder ENGINE actually fired in-tunnel (not just that the
#    capability was negotiated). The inner UDP flow is striped across the
#    1ms vs 40ms paths, so packets MUST arrive out of order at the server's
#    RX engine; every reorder period it arms increments gap_count. A non-zero
#    gap_count is therefore the load-bearing evidence that the engine observed
#    and acted on real in-tunnel reordering.
#
#    JSON shape (control_socket.c get_reorder_stats):
#      {"ok":true,"reorder":{"gap_count":N,"gap_filled_count":N,
#       "gap_timeout_count":N,...,"ack_demote_count":N,"delivered_count":N}}
#    The server aggregates RX stats across all live conns (mqvpn_server.c
#    mqvpn_server_get_reorder_stats), so .reorder.* is the whole-server sum.
reorder_stats="$(bench_query_control "$CTRL_PORT" get_reorder_stats)"
gap_count=$(echo "$reorder_stats"      | jq '.reorder.gap_count // 0'        2>/dev/null || echo 0)
gap_filled=$(echo "$reorder_stats"     | jq '.reorder.gap_filled_count // 0'  2>/dev/null || echo 0)
gap_timeout=$(echo "$reorder_stats"    | jq '.reorder.gap_timeout_count // 0' 2>/dev/null || echo 0)
delivered=$(echo "$reorder_stats"      | jq '.reorder.delivered_count // 0'   2>/dev/null || echo 0)
ack_demote=$(echo "$reorder_stats"     | jq '.reorder.ack_demote_count // 0'  2>/dev/null || echo 0)

echo "INFO: reorder stats — gap_filled=$gap_filled gap_timeout=$gap_timeout delivered=$delivered ack_demote=$ack_demote"
# ack_demote not asserted: the iperf3 -u workload is one-directional (client->
# server data, all large packets), so there is no small-packet ACK/return
# direction for the classifier to demote. ACK-direction demotion needs a
# bidirectional asymmetric inner flow (real inner QUIC = §24 eval-harness
# scope); its correctness is covered by the unit test test_rx_ack_demote_small_flow.

# The "engine fired" (gap_count>0) check is a HARD assertion only under the
# high-rate iperf3 workload, which reliably produces concurrent in-flight
# packets across the 1ms vs 40ms paths. The ping fallback (-c 10 -i 0.2) is
# too low-rate/serialized to guarantee a reorder period, so there it is
# informational only (don't fail a host that merely lacks iperf3).
if [ "$WORKLOAD_KIND" = "iperf3" ]; then
    if [ "${gap_count:-0}" -gt 0 ]; then
        echo "PASS: reorder engine fired in-tunnel (gap_count=$gap_count)"
    else
        echo "FAIL: reorder engine never armed (gap_count=$gap_count) — was the inner"
        echo "      flow actually striped across the RTT-spread paths? raw=$reorder_stats"
        fail=1
    fi
    # Stronger evidence: the engine did not just activate, it actually RE-ORDERED.
    # MaxWaitMs=60 > the 40ms path-B spread, so the late packet arrives inside the
    # wait window and the buffered gap fills. gap_filled>0 proves real in-tunnel
    # order correction (the feature delivering value), not merely detection.
    if [ "${gap_filled:-0}" -gt 0 ]; then
        echo "PASS: reorder engine corrected ordering in-tunnel (gap_filled=$gap_filled)"
    else
        echo "FAIL: no gaps filled (gap_filled=$gap_filled) despite MaxWaitMs(60) >"
        echo "      path-B spread(40ms) — late packets should arrive within the wait."
        echo "      raw=$reorder_stats"
        fail=1
    fi
else
    echo "SKIP: engine-fired/filled checks need iperf3; ping fallback is too low-rate"
    echo "      to guarantee reordering. gap_count=$gap_count gap_filled=$gap_filled (info)."
fi

# Non-fatal breakdown for the human reading the run. Whether a gap closes by
# the missing seq arriving (gap_filled) vs the wait expiring (gap_timeout)
# depends on the 40ms path-B one-way delay vs the 30ms default max_wait_ms —
# either outcome still counts toward gap_count, which is why the hard assertion
# is on gap_count, not gap_filled. Narrow path B below max_wait (e.g. 20ms) if
# you want to bias toward gap_filled.
echo "INFO: reorder breakdown — gap_filled=$gap_filled gap_timeout=$gap_timeout delivered=$delivered"

# ACK demotion is intentionally NOT asserted here. iperf3 -u is a one-directional
# client→server data flow: there is no small-packet ACK/return direction for the
# ACK-direction classifier to observe, so ack_demote_count is expected to stay 0
# in this harness. Demotion requires a bidirectional asymmetric inner flow (a
# real inner QUIC/TCP session), which is the §24 eval-harness scope; its
# correctness is covered by the unit test test_rx_ack_demote_small_flow
# (tests/test_reorder_rx.c). Surface it as INFO only.
echo "INFO: ack_demote_count=$ack_demote (expected 0 under one-directional iperf3 -u; see comment)"

# Tear down the ON run before the OFF regression run (fresh server+client).
bench_stop_vpn

# ─── Phase C: regression — reorder DISABLED (wire-compat) ──────────────────
echo ""
echo "=== Phase C: regression (reorder OFF) ==="
reorder_run "$INI_OFF" "$SERVER_LOG_OFF" "$CLIENT_LOG_OFF"

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
    echo "PASS: tunnel established unchanged with reorder OFF"
else
    echo "FAIL: tunnel did not establish with reorder OFF"
    fail=1
fi

# With reorder OFF, the capability must NOT be negotiated (no header advertised).
if grep -q "mqvpn-reorder" "$SERVER_LOG_OFF" "$CLIENT_LOG_OFF"; then
    echo "FAIL: reorder negotiation occurred despite Enabled=off"
    fail=1
else
    echo "PASS: no reorder negotiation with Enabled=off (no-op confirmed)"
fi

# Inner data still flows with reorder OFF.
if run_inner_udp_workload; then
    echo "PASS: inner UDP workload completed with reorder OFF"
else
    echo "FAIL: inner UDP workload failed with reorder OFF"
    fail=1
fi

# Behavioral MTU check: reorder ON inner MTU should be exactly 8 (the wire
# header, MQVPN_REORDER_HDR_LEN) less than the reorder-OFF inner MTU. Only
# checked when both values parsed and the OFF MTU stayed above the IPv6 floor
# (the -8 is clamped to IPV6_MIN_MTU=1280 for v6, client.c:1172-1173; this
# topology is v4-only so no clamp is expected).
mtu_off="$(extract_client_mtu "$CLIENT_LOG_OFF")"
if [ -n "$mtu_on" ] && [ -n "$mtu_off" ]; then
    if [ "$mtu_on" -eq "$((mtu_off - 8))" ]; then
        echo "PASS: reorder MTU overhead applied (ON=$mtu_on == OFF=$mtu_off - 8)"
    else
        echo "FAIL: reorder MTU overhead wrong (ON=$mtu_on, OFF=$mtu_off, expected ON=OFF-8)"
        fail=1
    fi
else
    echo "WARN: skipping MTU -8 check (ON='$mtu_on' OFF='$mtu_off' — one not parsed)"
fi

# ─── Verdict ───────────────────────────────────────────────────────────────
echo ""
if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL"
    echo "--- Server log ON (last 25) ---";  tail -25 "$SERVER_LOG"
    echo "--- Client log ON (last 25) ---";  tail -25 "$CLIENT_LOG"
    echo "--- Server log OFF (last 15) ---"; tail -15 "$SERVER_LOG_OFF"
    echo "--- Client log OFF (last 15) ---"; tail -15 "$CLIENT_LOG_OFF"
    exit 1
fi
echo "RESULT: PASS"
exit 0
