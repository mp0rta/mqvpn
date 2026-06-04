#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# test_e2e_dellink_8paths.sh — Exercise the RTM_DELLINK / RTM_NEWLINK
# path-recycle loop with a fully-populated 8-path client, to catch
# regressions in failover-storm / path_id grant accounting at the new cap.
#
# Phase 1 (precondition): wait until 8 paths are established, capture their
# path_ids. If this never converges, bail — the bug isn't dellink.
# Phase 2 (graded): del veth-c0. Assert:
#   - n_paths ∈ {7, 8} (xquic may prune the closed slot immediately, or hold
#     it in the array until PATH_ABANDON is acked)
#   - exactly 1 of the captured path_ids is now closed/closing OR removed
#     from the array (other paths must remain untouched — catches storm)
#   - tunnel still passes traffic on a surviving path
# Phase 3 (graded): recreate the veth pair. n_paths returns to 8 and ping
# works again.
#
# rev3 changes vs rev2:
#   - Track slots by path_id captured at Phase 1, not by array index. xquic
#     may reorder or prune paths[] in the JSON output (review NEW-[1]).
#   - On server death during Phase 2 polling, skip subsequent assertions
#     instead of cascading 4 FAIL increments for one root cause (NEW-[2]).
#   - Drop redundant integer-regex guards; jq `// 0` is sufficient.
#
# Requires: root, netns support, netcat-openbsd, jq
# Usage: sudo ./test_e2e_dellink_8paths.sh [mqvpn-binary]

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../benchmarks/bench_env_setup.sh
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
N_PATHS=8
DROP_SLOT=2
CTRL_PORT=9091
CLIENT_LOG="$(mktemp)"
SERVER_LOG="$(mktemp)"

trap 'bench_cleanup; rm -f "$CLIENT_LOG" "$SERVER_LOG"' EXIT

echo "[8paths-dellink] N=$N_PATHS drop=slot$DROP_SLOT binary=$MQVPN"
bench_check_test_deps nc jq

bench_setup_netns_n "$N_PATHS"
bench_add_server_host_routes "$N_PATHS"

bench_start_vpn_server "--control-port $CTRL_PORT" "$SERVER_LOG"

paths_arg=""
for (( i=0; i<N_PATHS; i++ )); do
    paths_arg="${paths_arg} --path $(bench_path_veth_client "$i")"
done

bench_start_vpn_client "$paths_arg" "$CLIENT_LOG"
bench_wait_tunnel 20

PASS=0
FAIL=0

# ── Phase 1: precondition + capture path_ids ─────────────────────────────
n=$(bench_wait_for_n_paths "$N_PATHS" 30 "$CTRL_PORT") && rc=0 || rc=$?
if [ "$rc" -ne 0 ] || [ "$n" -ne "$N_PATHS" ]; then
    echo "ERROR: setup did not converge to n_paths=$N_PATHS (got $n, rc=$rc); aborting" >&2
    tail -40 "$CLIENT_LOG" >&2
    exit 1
fi

status_p1="$(bench_query_control "$CTRL_PORT" get_status)"
n_active=$(echo "$status_p1" | jq -r \
    '[.clients[0].paths[] | select(.state_label == "active")] | length' 2>/dev/null || echo 0)
if [ "$n_active" -ne "$N_PATHS" ]; then
    echo "ERROR: Phase 1 has $n_active active (expected $N_PATHS); aborting — handshake flaky, not a dellink regression" >&2
    exit 1
fi
ORIGINAL_PIDS=$(echo "$status_p1" | jq -r '.clients[0].paths[].path_id' | sort -n)
n_pids=$(echo "$ORIGINAL_PIDS" | wc -l)
if [ "$n_pids" -ne "$N_PATHS" ]; then
    echo "ERROR: Phase 1 returned $n_pids path_ids, expected $N_PATHS" >&2
    exit 1
fi
echo "Phase 1 (precondition): n_paths=$N_PATHS active=$n_active path_ids=$(echo "$ORIGINAL_PIDS" | tr '\n' ',' | sed 's/,$//')"

# ── Phase 2: dellink ─────────────────────────────────────────────────────
drop_veth="$(bench_path_veth_client "$DROP_SLOT")"
ip netns exec "$NS_CLIENT" ip link del "$drop_veth"

# Count Phase-1 path_ids now in {closed, closing, removed}. The dellink
# event should close exactly one path; if more close, it's a storm regression.
count_closed_or_removed() {
    local s="$1" pid c=0 label
    for pid in $ORIGINAL_PIDS; do
        label=$(echo "$s" | jq -r --argjson pid "$pid" \
            '(.clients[0].paths[] | select(.path_id == $pid) | .state_label) // "removed"' 2>/dev/null)
        if [ "$label" = "closed" ] || [ "$label" = "closing" ] || [ "$label" = "removed" ]; then
            c=$((c + 1))
        fi
    done
    echo "$c"
}

# Wait up to 20s for xquic PTO to register the close.
elapsed=0
server_died=0
n_closed=0
while [ "$elapsed" -lt 20 ]; do
    if ! kill -0 "$_BENCH_SERVER_PID" 2>/dev/null; then
        server_died=1
        break
    fi
    status_p2="$(bench_query_control "$CTRL_PORT" get_status)"
    n_closed=$(count_closed_or_removed "$status_p2")
    if [ "$n_closed" -ge 1 ]; then
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

if [ "$server_died" -eq 1 ]; then
    echo "FAIL: server died during Phase 2 poll — skipping remaining assertions" >&2
    FAIL=$((FAIL + 1))
else
    status_p2="$(bench_query_control "$CTRL_PORT" get_status)"
    n=$(echo "$status_p2" | jq -r '.clients[0].n_paths // 0' 2>/dev/null || echo 0)
    n_closed=$(count_closed_or_removed "$status_p2")

    if [ "$n" -ge $((N_PATHS - 1)) ] && [ "$n" -le "$N_PATHS" ]; then
        echo "PASS: n_paths=$n in expected {7, 8} after dellink"
        PASS=$((PASS + 1))
    else
        echo "FAIL: n_paths=$n outside expected {7, 8}"
        FAIL=$((FAIL + 1))
    fi

    if [ "$n_closed" -eq 1 ]; then
        echo "PASS: exactly 1 of the original $N_PATHS paths is closed/removed"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $n_closed paths closed/removed (expected 1 — possible storm)"
        FAIL=$((FAIL + 1))
    fi

    if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
        echo "PASS: tunnel ping survives after dellink"
        PASS=$((PASS + 1))
    else
        echo "FAIL: tunnel ping broken after dellink"
        FAIL=$((FAIL + 1))
    fi
fi

# ── Phase 3: re-add ──────────────────────────────────────────────────────
if [ "$server_died" -ne 1 ]; then
    vc="$(bench_path_veth_client "$DROP_SLOT")"
    vs="$(bench_path_veth_server "$DROP_SLOT")"
    ic="$(bench_path_client_ip "$DROP_SLOT")/24"
    is="$(bench_path_server_ip "$DROP_SLOT")/24"
    ip link add "$vc" type veth peer name "$vs"
    ip link set "$vc" netns "$NS_CLIENT"
    ip link set "$vs" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$ic" dev "$vc"
    ip netns exec "$NS_SERVER" ip addr add "$is" dev "$vs"
    ip netns exec "$NS_CLIENT" ip link set "$vc" up
    ip netns exec "$NS_SERVER" ip link set "$vs" up
    ip netns exec "$NS_CLIENT" ip route replace "${IP_A_SERVER_ADDR}/32" \
        via "$(bench_path_server_ip "$DROP_SLOT")" dev "$vc" \
        metric "$((100 + DROP_SLOT))" 2>/dev/null || true

    n=$(bench_wait_for_n_paths "$N_PATHS" 30 "$CTRL_PORT") && rc=0 || rc=$?
    if [ "$rc" -eq 2 ]; then
        echo "FAIL: server died during Phase 3 poll" >&2
        FAIL=$((FAIL + 1))
    elif [ "$n" -eq "$N_PATHS" ]; then
        echo "PASS: n_paths recovered to $N_PATHS after re-add"
        PASS=$((PASS + 1))
    else
        echo "FAIL: n_paths=$n (expected $N_PATHS after re-add)"
        FAIL=$((FAIL + 1))
    fi

    if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
        echo "PASS: tunnel ping works after re-add"
        PASS=$((PASS + 1))
    else
        echo "FAIL: tunnel ping broken after re-add"
        FAIL=$((FAIL + 1))
    fi
fi

echo "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    echo "--- Client log (last 40) ---"
    tail -40 "$CLIENT_LOG"
    echo "--- Server log (last 20) ---"
    tail -20 "$SERVER_LOG"
    exit 1
fi
exit 0
