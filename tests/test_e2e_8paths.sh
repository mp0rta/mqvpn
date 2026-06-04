#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# test_e2e_8paths.sh — Verify 8 paths handshake + control API JSON shape
# against the real xquic engine through netns isolation.
#
# Phase 1 (handshake): all 8 paths reach state_label=="active" and tunnel ping
# works.
# Phase 2 (control API): get_status JSON is valid, n_paths reflects all 8,
# and at least one path reports srtt_ms>0 (proves traffic flowed). Per-field
# coverage and size bound are covered by tests/test_control_response_bound.c
# at the unit level.
#
# rev2: consolidated from test_e2e_8paths_handshake.sh +
#       test_e2e_control_api_8paths.sh; relies on shared helpers in
#       bench_env_setup.sh.
#
# Requires: root, netns support, netcat-openbsd, jq
# Usage: sudo ./test_e2e_8paths.sh [mqvpn-binary]

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../benchmarks/bench_env_setup.sh
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
N_PATHS=8
CTRL_PORT=9091
CLIENT_LOG="$(mktemp)"
SERVER_LOG="$(mktemp)"

trap 'bench_cleanup; rm -f "$CLIENT_LOG" "$SERVER_LOG"' EXIT

echo "[8paths] N=$N_PATHS binary=$MQVPN"
bench_check_test_deps nc jq

bench_setup_netns_n "$N_PATHS"
bench_add_server_host_routes "$N_PATHS"

bench_start_vpn_server "--control-port $CTRL_PORT" "$SERVER_LOG"

paths_arg=""
for (( i=0; i<N_PATHS; i++ )); do
    paths_arg="${paths_arg} --path $(bench_path_veth_client "$i")"
done

bench_start_vpn_client "$paths_arg" "$CLIENT_LOG"
# bench_wait_tunnel only confirms path 0 + handshake (single ping to TUN
# server). 8-path validation is covered by the control API poll below.
bench_wait_tunnel 20

# ─── Phase 1: handshake ───────────────────────────────────────────────────
echo "Polling control API for n_paths == $N_PATHS..."
n=$(bench_wait_for_n_paths "$N_PATHS" 30 "$CTRL_PORT") && rc=0 || rc=$?
if [ "$rc" -eq 2 ]; then
    echo "FAIL: server died during Phase 1 poll (last seen n_paths=$n)" >&2
    tail -30 "$SERVER_LOG" >&2
    exit 1
fi
status_p1="$(bench_query_control "$CTRL_PORT" get_status)"

fail=0
if [ "$n" -ne "$N_PATHS" ]; then
    echo "FAIL: n_paths=$n (expected $N_PATHS)"
    fail=1
else
    echo "PASS: n_paths=$n"
fi

n_active=$(echo "$status_p1" | jq -r \
    '[.clients[0].paths[] | select(.state_label == "active")] | length' 2>/dev/null || echo 0)
if [ "$n_active" -lt "$N_PATHS" ]; then
    echo "FAIL: $n_active of $N_PATHS paths active (rest stuck at init/validating/closed)"
    fail=1
else
    echo "PASS: all $N_PATHS paths active"
fi

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
    echo "PASS: tunnel ping works"
else
    echo "FAIL: tunnel ping does not work"
    fail=1
fi

# ─── Phase 2: control API JSON shape ──────────────────────────────────────
# Push a few packets so srtt_ms / bytes_tx fields are populated per path.
ip netns exec "$NS_CLIENT" ping -c 10 -i 0.2 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1 || true
sleep 2
status_p2="$(bench_query_control "$CTRL_PORT" get_status)"

if ! echo "$status_p2" | jq -e . >/dev/null 2>&1; then
    echo "FAIL: get_status response is not valid JSON"
    fail=1
else
    echo "PASS: get_status response is valid JSON"
fi

nonzero_srtt=$(echo "$status_p2" | jq -r \
    '[.clients[0].paths[] | select(.srtt_ms > 0)] | length' 2>/dev/null || echo 0)
if [ "$nonzero_srtt" -lt 1 ]; then
    echo "FAIL: no path reports srtt_ms > 0 (traffic may not have flowed)"
    fail=1
else
    echo "PASS: $nonzero_srtt of $N_PATHS paths report srtt_ms > 0"
fi

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "--- Phase 1 status JSON ---"
    echo "$status_p1" | jq . 2>/dev/null || echo "$status_p1"
    echo "--- Phase 2 status JSON ---"
    echo "$status_p2" | jq . 2>/dev/null || echo "$status_p2"
    echo "--- Client log (last 30) ---"
    tail -30 "$CLIENT_LOG"
    echo "--- Server log (last 20) ---"
    tail -20 "$SERVER_LOG"
    exit 1
fi
exit 0
