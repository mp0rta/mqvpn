#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# test_e2e_wrong_psk.sh — E2E smoke test: wrong PSK must fail fast, not hang.
#
# Verifies:
#   1. A client connecting with the WRONG PSK observes the reason-agnostic
#      "CONNECT-IP request failed" marker within a few seconds (not a hang).
#      The exact reason (AUTH vs PROTOCOL) is intentionally NOT asserted: a
#      403 header and a stream RST can race, and whichever the peer sends
#      first is legitimate (spec §3.4: headers "usually but not guaranteed").
#   2. The correct PSK still establishes normally ("tunnel 200 OK" unchanged,
#      ping succeeds) — the fast-fail path must not regress the happy path.
#
# Requires: root (TUN + netns). Not added to CI; use perf-weekly.yml for
# automated bench coverage instead.
#
# Run manually:
#   sudo bash tests/test_e2e_wrong_psk.sh [path/to/mqvpn]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
# WARN-or-lower: the "CONNECT-IP request failed" marker is a LOG_W line —
# INFO/DEBUG works too (WARN is a strict superset at lower verbosity), but an
# ERROR-only level would suppress it and hang wait_for_log into a false
# failure. Keep this at "warn" deliberately (see cli_signal_connect_fail).
BENCH_LOG_LEVEL="${BENCH_LOG_LEVEL:-warn}"

PASS=0
FAIL=0
LOG_DIR="$(mktemp -d)"

trap 'bench_cleanup; rm -rf "$LOG_DIR"' EXIT

run_test() {
    local name="$1"
    shift
    echo ""
    echo "--- Test: $name ---"
    if "$@"; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name"
        FAIL=$((FAIL + 1))
    fi
}

# Parameterized wait_for_log (adapted from tests/test_e2e_dellink.sh). $1 =
# log file, $2 = grep -E pattern, $3 = timeout seconds (default 10).
wait_for_log() {
    local logfile="$1"
    local pattern="$2"
    local timeout="${3:-10}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if [ -f "$logfile" ] && grep -qE "$pattern" "$logfile" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

assert_ping() {
    local msg="${1:-tunnel reachable}"
    if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
        echo "  assert_ping OK: $msg"
        return 0
    else
        echo "  assert_ping FAIL: $msg"
        return 1
    fi
}

# --- Test 1: wrong PSK fails fast (reason-agnostic marker, not a hang) ---

test_wrong_psk_fails_fast() {
    local client_log="${LOG_DIR}/wrong_psk_client.log"
    bench_setup_netns
    BENCH_SCHEDULER="wlb"
    bench_start_vpn_server

    # Deliberately do NOT use bench_start_vpn_client (it always feeds the
    # correct $_BENCH_PSK) — launch the client directly with a wrong key.
    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server "${IP_A_SERVER_ADDR}:${VPN_LISTEN_PORT}" \
        --path veth-a0 \
        --auth-key "wrong-psk-deliberately-incorrect" \
        --scheduler "$BENCH_SCHEDULER" \
        --insecure \
        --log-level "$BENCH_LOG_LEVEL" >"$client_log" 2>&1 &
    _BENCH_CLIENT_PID=$!

    if wait_for_log "$client_log" "CONNECT-IP request failed" 10; then
        echo "  OK: client reported CONNECT-IP request failed (fast-fail, not a hang)"
    else
        echo "  FAIL: client never reported the failure marker within 10s"
        echo "  --- last 20 lines of client log ---"
        tail -20 "$client_log"
        return 1
    fi

    # Must NOT have established a tunnel with the wrong PSK.
    if grep -q "tunnel 200 OK" "$client_log"; then
        echo "  FAIL: tunnel established despite wrong PSK"
        return 1
    fi

    kill "$_BENCH_CLIENT_PID" 2>/dev/null || true
    wait "$_BENCH_CLIENT_PID" 2>/dev/null || true
    _BENCH_CLIENT_PID=""
    return 0
}

# --- Test 2: correct PSK still establishes normally (no regression) ---

test_correct_psk_still_connects() {
    local client_log="${LOG_DIR}/correct_psk_client.log"
    bench_cleanup
    bench_setup_netns
    BENCH_SCHEDULER="wlb"
    bench_start_vpn_server
    bench_start_vpn_client "--path veth-a0" "$client_log"

    sleep 2
    assert_ping "correct PSK ping" || return 1

    if ! grep -q "tunnel 200 OK" "$client_log"; then
        echo "  FAIL: 'tunnel 200 OK' marker missing — happy-path log wording regressed"
        return 1
    fi

    return 0
}

run_test "wrong PSK fails fast" test_wrong_psk_fails_fast
run_test "correct PSK still connects" test_correct_psk_still_connects

echo ""
echo "================================================="
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================="
[ "$FAIL" -eq 0 ]
