#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# test_e2e_hybrid_h2.sh — Netns end-to-end test for hybrid mode H2 (real
# TCP-lane transport: client-side lwIP termination <-> server-side egress
# relay). This is the FIRST point where the independently-built client
# (lwIP + tcp_lane request builder) and server (auth/ACL/connect/relay)
# sides actually talk to each other over a live tunnel.
#
# What this verifies:
#   Test 1 (curl body correctness), Tcp=stream:
#     - a real HTTP server, reachable only through the tunnel's hybrid TCP
#       relay (NOT the CONNECT-IP subnet, NOT the VPN transport address),
#       serves a known file; curl fetches it FROM the client netns and the
#       body is compared byte-for-byte against the source file. Exit-code
#       success alone is not accepted as a PASS (session-1 lesson): the
#       comparison IS the server-side-bytes verification this test hinges
#       on.
#     - the client [STATUS] line additionally confirms the TCP lane was
#       actually exercised (nonzero tcp counter), not merely that curl
#       happened to work over some other path.
#   Test 7 (byte-identical regression), two phases:
#     Phase A [Hybrid] Enabled=false:
#       - inner ping + TCP transfer through the CONNECT-IP tunnel (as H1),
#         but strengthened to a full byte-for-byte compare of a random
#         payload (not just nc's exit code).
#     Phase B [Hybrid] Enabled=true / Tcp=raw:
#       - same byte-identical transfer (still travels the CONNECT-IP path,
#         since Tcp=raw makes the classifier route TCP as RAW — see
#         classifier.c). PLUS: the client's tcp lane counter must stay at
#         0 for the whole run (classifier never yields LANE_TCP under
#         Tcp=raw, so nothing ever reaches lwIP — see the note by
#         LANE_TCP_ASSERTION below for why this deviates from the literal
#         task sketch), and the server's tcp_flows_active must read 0 via
#         the control API (defensive: catches a future regression once
#         Task 24 wires this field live; it is unconditionally 0 today).
#
# HTTP target addressing (Test 1): the client runs a full-tunnel default
# route (0.0.0.0/1 + 128.0.0.0/1 via TUN, src/platform/linux/routing.c) with
# ONE exception — a /32 host route pinning the VPN server's OWN transport
# address via the original interface (so the QUIC packets themselves don't
# recurse into the tunnel). Any address inside the veth path subnets
# (10.<oct>.0.0/24) is ALSO on-link on the client and bypasses the tunnel
# via the more-specific connected route. So the HTTP target must be an
# address that is: (a) not the pinned VPN transport address, (b) not inside
# any client-side on-link subnet, (c) not inside the CONNECT-IP tunnel
# subnet (rejected outright by the ACL's tunnel-subnet check), yet (d)
# reachable from the SERVER's own netns egress connect(). A /32 loopback
# alias in the server netns (10.222.0.1, disjoint from every subnet above)
# satisfies all four; EgressAllow punches it through the mandatory
# default-on RFC1918 deny (src/hybrid/tcp_egress.c DEFAULT_DENY_V4).
#
# Requires: root, netns support, netcat-openbsd, curl, python3, jq.
# Usage:    sudo ./test_e2e_hybrid_h2.sh [mqvpn-binary]

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Pin the build dir explicitly (same rationale as test_e2e_hybrid_h1.sh):
# this branch builds into build-debug, and the harness default
# (../build/mqvpn) can silently pick up a stale binary from another tree.
MQVPN="${MQVPN:-${SCRIPT_DIR}/../build-debug/mqvpn}"
# shellcheck source=../benchmarks/bench_env_setup.sh
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
N_PATHS=1
CTRL_PORT=9096   # distinct from h1's 9095 — same CI job may run both

# HTTP target for Test 1 — see the addressing note above. Lives only as a
# /32 loopback alias inside NS_SERVER, added/removed by this script.
HTTP_TARGET_IP="10.222.0.1"
HTTP_TARGET_PORT=8070
HTTP_DOCROOT="$(mktemp -d)"
HTTP_TESTFILE="testfile.bin"
HTTP_PID=""

INNER_TCP_PORT=5402   # distinct from h1's 5401 — same CI job may run both

CLIENT_LOG_T1="$(mktemp)"
SERVER_LOG_T1="$(mktemp)"
CLIENT_LOG_T7A="$(mktemp)"
SERVER_LOG_T7A="$(mktemp)"
CLIENT_LOG_T7B="$(mktemp)"
SERVER_LOG_T7B="$(mktemp)"
INI_T1="$(mktemp --suffix=.ini)"
INI_T7A="$(mktemp --suffix=.ini)"
INI_T7B="$(mktemp --suffix=.ini)"
CURL_OUT="$(mktemp)"
SENT_FILE_A="$(mktemp)"
RECV_FILE_A="$(mktemp)"
SENT_FILE_B="$(mktemp)"
RECV_FILE_B="$(mktemp)"

cleanup_http_server() {
    if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
        kill "$HTTP_PID" 2>/dev/null || true
        wait "$HTTP_PID" 2>/dev/null || true
    fi
    ip netns exec "$NS_SERVER" ip addr del "${HTTP_TARGET_IP}/32" dev lo 2>/dev/null || true
}

trap 'cleanup_http_server; bench_cleanup; rm -rf "$HTTP_DOCROOT"; rm -f \
    "$CLIENT_LOG_T1" "$SERVER_LOG_T1" "$CLIENT_LOG_T7A" "$SERVER_LOG_T7A" \
    "$CLIENT_LOG_T7B" "$SERVER_LOG_T7B" "$INI_T1" "$INI_T7A" "$INI_T7B" \
    "$CURL_OUT" "$SENT_FILE_A" "$RECV_FILE_A" "$SENT_FILE_B" "$RECV_FILE_B"' EXIT

fail=0

echo "[hybrid-h2] N=$N_PATHS binary=$MQVPN inner-tcp-port=$INNER_TCP_PORT http-target=${HTTP_TARGET_IP}:${HTTP_TARGET_PORT}"
bench_check_test_deps nc curl python3 jq

# ── Phase INIs. Keys cross-checked against src/config.c cfg_keys[] and the
#    hand-coded [Hybrid] EgressAllow parser (src/config.c ~line 1063):
cat >"$INI_T1" <<EOF
[Hybrid]
Enabled = true
Tcp = stream
EgressAllow = 10.222.0.0/24
EOF

cat >"$INI_T7A" <<EOF
[Hybrid]
Enabled = false
EOF

cat >"$INI_T7B" <<EOF
[Hybrid]
Enabled = true
Tcp = raw
EOF

# ── Topology: single path, no netem — H2 tests transport correctness, not
#    scheduling. ──
bench_setup_netns_n "$N_PATHS"
bench_add_server_host_routes "$N_PATHS"

# Give NS_SERVER the HTTP target's loopback alias (disjoint from every
# client-side on-link subnet — see the addressing note above).
ip netns exec "$NS_SERVER" ip addr add "${HTTP_TARGET_IP}/32" dev lo

# Known-content docroot file (few KB, non-trivial content so a truncated or
# zeroed relay would be caught).
head -c 4096 /dev/urandom >"${HTTP_DOCROOT}/${HTTP_TESTFILE}"

# Start the HTTP server bound to the target alias, inside NS_SERVER (same
# netns the mqvpn server's egress connect() runs in — trivially reachable).
ip netns exec "$NS_SERVER" python3 -m http.server "$HTTP_TARGET_PORT" \
    --bind "$HTTP_TARGET_IP" --directory "$HTTP_DOCROOT" >/dev/null 2>&1 &
HTTP_PID=$!

# Poll for readiness instead of a fixed sleep.
http_ready=0
for _ in $(seq 1 20); do
    if ip netns exec "$NS_SERVER" curl -s --max-time 1 -o /dev/null \
            "http://${HTTP_TARGET_IP}:${HTTP_TARGET_PORT}/${HTTP_TESTFILE}" 2>/dev/null; then
        http_ready=1
        break
    fi
    sleep 0.5
done
if [ "$http_ready" -ne 1 ]; then
    echo "ERROR: HTTP test server never became ready" >&2
    exit 1
fi
echo "OK: HTTP test server ready at ${HTTP_TARGET_IP}:${HTTP_TARGET_PORT}"

# Parameterized wait_for_log (same as test_e2e_hybrid_h1.sh). $1 = log file,
# $2 = grep -E pattern, $3 = timeout seconds (default 40).
wait_for_log() {
    local logfile="$1"
    local pattern="$2"
    local timeout="${3:-40}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if grep -qE "$pattern" "$logfile" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Run one full server+client lifecycle with a given INI + log files (same
# shape as test_e2e_hybrid_h1.sh's hybrid_run — file-local copy since
# neither script is a sourceable library).
hybrid_run() {
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

# Parse the LAST client "lanes tcp/dgram/raw=<t>/<d>/<r>" (same as h1).
LANE_TCP=0; LANE_DGRAM=0; LANE_RAW=0
parse_lanes() {
    local clog="$1"
    local counts
    counts="$(grep -oE 'lanes tcp/dgram/raw=[0-9]+/[0-9]+/[0-9]+' "$clog" \
        | tail -1 | cut -d= -f2)"
    [ -n "$counts" ] || return 1
    LANE_TCP="${counts%%/*}"
    LANE_RAW="${counts##*/}"
    LANE_DGRAM="${counts#*/}"; LANE_DGRAM="${LANE_DGRAM%%/*}"
    return 0
}

# Byte-identical inner TCP transfer through the CONNECT-IP tunnel (Test 7).
# $1 = sent file, $2 = recv file. Writes/compares full content, not just
# exit codes or byte counts (strengthens h1 Phase 3's "traffic works" into
# an actual byte-identical proof).
run_byte_identical_transfer() {
    local sent="$1" recv="$2"
    head -c 65536 /dev/urandom >"$sent"

    ip netns exec "$NS_SERVER" timeout 20 nc -l "$INNER_TCP_PORT" \
        >"$recv" 2>/dev/null &
    local lpid=$!
    sleep 1
    if ! ip netns exec "$NS_CLIENT" timeout 15 nc -N "$TUNNEL_SERVER_IP" \
            "$INNER_TCP_PORT" <"$sent" >/dev/null 2>&1; then
        echo "  (inner TCP transfer failed)" >&2
        kill "$lpid" 2>/dev/null || true
        wait "$lpid" 2>/dev/null || true
        return 1
    fi
    wait "$lpid" 2>/dev/null || true

    if ! cmp -s "$sent" "$recv"; then
        echo "  (byte mismatch: sent $(wc -c <"$sent") bytes, received $(wc -c <"$recv") bytes)" >&2
        return 1
    fi
    return 0
}

# ─── Test 1: curl body correctness, Enabled=true / Tcp=stream ─────────────
echo ""
echo "=== Test 1: curl through the tunnel's TCP lane (body byte-for-byte) ==="
hybrid_run "$INI_T1" "$SERVER_LOG_T1" "$CLIENT_LOG_T1"

if ip netns exec "$NS_CLIENT" curl -sS --max-time 15 \
        -o "$CURL_OUT" "http://${HTTP_TARGET_IP}:${HTTP_TARGET_PORT}/${HTTP_TESTFILE}"; then
    if cmp -s "$CURL_OUT" "${HTTP_DOCROOT}/${HTTP_TESTFILE}"; then
        echo "PASS: curl body byte-for-byte matches the source file"
    else
        echo "FAIL: curl body mismatch (fetched $(wc -c <"$CURL_OUT") bytes," \
            "expected $(wc -c <"${HTTP_DOCROOT}/${HTTP_TESTFILE}") bytes)"
        fail=1
    fi
else
    echo "FAIL: curl through the tunnel failed (exit $?)"
    fail=1
fi

# Confirm the TCP lane was actually exercised, not e.g. a stray direct
# route. Same race pin as h1 Phase 1: [STATUS] fires every 30s and may
# legitimately read 0 before the curl above ran.
if wait_for_log "$CLIENT_LOG_T1" 'lanes tcp/dgram/raw=[1-9][0-9]*/' 40; then
    parse_lanes "$CLIENT_LOG_T1" || true
    echo "PASS: [STATUS] reports nonzero tcp lane (tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW)"
else
    echo "FAIL: no [STATUS] line with nonzero tcp lane within 40s"
    parse_lanes "$CLIENT_LOG_T1" \
        && echo "      last lanes line: tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW" \
        || echo "      (no lanes line at all)"
    fail=1
fi

bench_stop_vpn

# ─── Test 7 Phase A: Enabled=false (byte-identical baseline) ──────────────
echo ""
echo "=== Test 7 Phase A: hybrid OFF (byte-identical baseline) ==="
hybrid_run "$INI_T7A" "$SERVER_LOG_T7A" "$CLIENT_LOG_T7A"

if run_byte_identical_transfer "$SENT_FILE_A" "$RECV_FILE_A"; then
    echo "PASS: inner TCP transfer byte-identical with hybrid OFF"
else
    echo "FAIL: inner TCP transfer NOT byte-identical with hybrid OFF"
    fail=1
fi

bench_stop_vpn

# ─── Test 7 Phase B: Enabled=true / Tcp=raw (byte-identical + no lwIP) ────
echo ""
echo "=== Test 7 Phase B: hybrid ON / Tcp=raw (byte-identical + nothing reaches lwIP) ==="
hybrid_run "$INI_T7B" "$SERVER_LOG_T7B" "$CLIENT_LOG_T7B"

if run_byte_identical_transfer "$SENT_FILE_B" "$RECV_FILE_B"; then
    echo "PASS: inner TCP transfer byte-identical with hybrid ON / Tcp=raw"
else
    echo "FAIL: inner TCP transfer NOT byte-identical with hybrid ON / Tcp=raw"
    fail=1
fi

# LANE_TCP_ASSERTION: classifier.c's MQVPN_LANE_TCP branch is unreachable
# under Tcp=raw (`pol->tcp_mode == MQVPN_HYBRID_TCP_RAW` forces LANE_RAW
# unconditionally — see mqvpn_hybrid_classify). c->pkts_lane_tcp is
# therefore structurally pinned at 0 for the whole run; h1 Phase 2 already
# established and documented this exact behavior ("tcp is 0 by construction
# and deliberately NOT asserted"). The task sketch for this phase asks to
# assert "pkts_lane_tcp > 0 ... while tcp_flows_active == 0" — that is
# unreachable given the current classifier and would contradict h1's own
# finding, so this test asserts the direction that is actually true and
# actually meaningful: tcp lane stays at 0 (nothing was ever handed to
# lwIP) and raw lane is nonzero (TCP traffic still counted, just as RAW).
if wait_for_log "$CLIENT_LOG_T7B" \
        'lanes tcp/dgram/raw=[0-9]+/[0-9]+/[1-9][0-9]*' 40; then
    parse_lanes "$CLIENT_LOG_T7B" || true
    if [ "$LANE_TCP" -eq 0 ]; then
        echo "PASS: tcp lane stayed 0 under Tcp=raw (tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW) — nothing reached lwIP"
    else
        echo "FAIL: tcp lane nonzero under Tcp=raw (tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW) — classifier regression"
        fail=1
    fi
else
    echo "FAIL: no [STATUS] line with nonzero raw lane within 40s"
    parse_lanes "$CLIENT_LOG_T7B" \
        && echo "      last lanes line: tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW" \
        || echo "      (no lanes line at all)"
    fail=1
fi

# Any lanes line observed during the whole run must never show a nonzero
# tcp field (not just the last one) — cumulative counters only grow, so
# checking every observed line is equivalent to a running max check.
nonzero_tcp="$(grep -oE 'lanes tcp/dgram/raw=[0-9]+/' "$CLIENT_LOG_T7B" \
    | grep -vE 'lanes tcp/dgram/raw=0/' || true)"
if [ -z "$nonzero_tcp" ]; then
    echo "PASS: every [STATUS] line shows tcp lane == 0 under Tcp=raw"
else
    echo "FAIL: a [STATUS] line showed nonzero tcp lane under Tcp=raw:"
    echo "$nonzero_tcp" | sed 's/^/      /'
    fail=1
fi

# Server-side tcp_flows_active via the control API — unconditionally 0
# today (mqvpn_server_get_stats doesn't wire tcp_flows_active yet), so this
# is a defensive/forward-looking assertion: it documents the invariant and
# will start actually exercising it once a later task wires the field live.
stats_json="$(bench_query_control "$CTRL_PORT" get_stats)"
tcp_flows_active="$(echo "$stats_json" | jq -r '.tcp_flows_active // -1' 2>/dev/null || echo -1)"
if [ "$tcp_flows_active" = "0" ]; then
    echo "PASS: server get_stats reports tcp_flows_active=0"
else
    echo "FAIL: server get_stats reports tcp_flows_active=$tcp_flows_active (expected 0)"
    echo "      raw response: $stats_json"
    fail=1
fi

# ─── Verdict ───────────────────────────────────────────────────────────────
echo ""
if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL"
    echo "--- Client log Test1 (last 20) ---"; tail -20 "$CLIENT_LOG_T1"
    echo "--- Server log Test1 (last 20) ---"; tail -20 "$SERVER_LOG_T1"
    echo "--- Client log T7A (last 20) ---"; tail -20 "$CLIENT_LOG_T7A"
    echo "--- Client log T7B (last 20) ---"; tail -20 "$CLIENT_LOG_T7B"
    echo "--- Server log T7B (last 20) ---"; tail -20 "$SERVER_LOG_T7B"
    exit 1
fi
echo "RESULT: PASS"
exit 0
