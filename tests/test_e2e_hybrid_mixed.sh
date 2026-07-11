#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# test_e2e_hybrid_mixed.sh — Netns end-to-end test for the client-lane /
# server-egress BUILD-GATE SPLIT (MQVPN_HYBRID_TCP_LANE_BUILD vs
# MQVPN_HYBRID_TCP_EGRESS_BUILD, CMakeLists.txt). This pins the mixed shape
# LANE=ON / EGRESS=OFF: a lane-capable client talking to an egress-less
# server. What this verifies:
#   - the egress-less server answers every connect-tcp request with an
#     explicit 501 (svr_masque_send_501, src/mqvpn_server.c — the ONLY
#     connect-tcp responder left once MQVPN_HYBRID_TCP_EGRESS_ENABLED is
#     compiled out; svr_tcp_egress_on_request is unreachable dead code in
#     this build);
#   - the lane client tears the flow down cleanly on that rejection (inner
#     RST of both the pcb and the H3 request via
#     mqvpn_tcp_lane_on_stream_rejected -> tcp_lane_teardown_flow,
#     src/hybrid/tcp_lane.c) and the tunnel stays healthy afterward — no
#     hang, no connection-wide fallout, ping and RAW-lane TCP keep working;
#   - RAW mode (Tcp=raw) still passes end to end, since it never touches the
#     lane/egress code paths at all;
#   - server stats keys (tcp_flows_total, tcp_flows_rejected) read 0 via the
#     control API. The server DOES have real backing counters for these keys
#     (tcp_egress_flows_total_opened / tcp_egress_flows_rejected_cap in
#     mqvpn_server_t, surfaced by mqvpn_server_get_stats — both in
#     src/mqvpn_server.c) — but both the fields and the get_stats block that
#     surfaces them are #ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED'd out of this
#     build; mqvpn_server_get_stats memsets the out struct and
#     control_socket.c prints the JSON keys unconditionally, so the keys are
#     present and read exactly 0. That the server-side fields EXIST when
#     EGRESS is compiled in is precisely what makes the negative control's
#     assertion-5 flip work (a BOTH-ON binary moves them off 0).
#
# WHY THIS IS PINNED STRUCTURALLY, NOT BY STATUS-LINE VALUE: the literal
# HTTP status code the server sends back is observable NOWHERE at the
# client. cli_connect_tcp_on_headers (src/mqvpn_client.c) parses the
# response status only to branch on "2xx or not" — it never logs or stores
# the number — and the server never logs its outgoing status either. So a
# test that tried to assert "the status was literally 501, not 503" would
# have nothing in either log to grep. Instead this test pins the STRUCTURAL
# fact that guarantees it's 501: this build compiles out the whole egress
# module (MQVPN_HYBRID_TCP_EGRESS_ENABLED undefined), which removes
# svr_tcp_egress_on_request entirely and leaves svr_masque_send_501 as the
# only code path that can answer a connect-tcp CONNECT stream at all — a
# 503 (the OTHER rejection status this codebase can emit, from the
# TcpMaxGlobalFlows cap in svr_tcp_egress_on_request) is not merely
# unobserved here, it is UNREACHABLE in this binary. The runtime
# discriminators this script asserts instead are the pair
# tcp_flows_total == 0 AND tcp_flows_rejected == 0 on the SERVER's own
# get_stats: tcp_flows_rejected is incremented only on the 503-cap path
# inside svr_tcp_egress_on_request (grep src/hybrid/tcp_egress.c), which
# cannot execute in this binary, so both counters staying at 0 together is
# only possible if no egress code ran at all — i.e. every connect-tcp
# request really did fall through to svr_masque_send_501.
#
# The OTHER, EXECUTABLE half of this structural pin — asserting the egress
# object file / symbols are actually absent from the linked server binary
# (e.g. `nm`/`ar` on svr_tcp_egress_on_request) — deliberately does NOT live
# in this script. That check belongs in the build-gate CI job next to the
# CMake option itself; this script stays purely behavioral so the exact
# same script can be pointed at a negative-control BOTH-ON binary (LANE=ON
# EGRESS=ON) and is expected to pass Phase 2 the same way while Phase 1's
# assertions would legitimately need to flip (out of scope here — that
# binary gets its own coverage in test_e2e_hybrid_h2.sh).
#
# Requires: root, netns support, netcat-openbsd, jq, ss.
# Usage:    sudo ./test_e2e_hybrid_mixed.sh [mqvpn-binary]

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Pin the build dir explicitly (same rationale as test_e2e_hybrid_h1.sh /
# test_e2e_hybrid_h2.sh): the harness default (../build/mqvpn) can silently
# pick up a stale binary from a different build tree. This script's default
# is the LANE=ON/EGRESS=OFF build tree specifically (build-egoff) — the
# mixed shape under test — not build-debug. $1 / $MQVPN still override.
MQVPN="${MQVPN:-${SCRIPT_DIR}/../build-egoff/mqvpn}"
# shellcheck source=../benchmarks/bench_env_setup.sh
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
N_PATHS=1
# Distinct from h1 (9095), h2 (9096) AND the benchmark family's shared
# default 9097 (sweep_reorder.sh / sweep_single_path.sh /
# bench_hybrid_scheduler.sh) — the same CI job or dev box may run any of
# them back to back.
CTRL_PORT=9098

# EXTERNAL egress target, same addressing rationale as
# test_e2e_hybrid_h2.sh's HTTP_TARGET_IP (see that file's header note): a
# /32 loopback alias inside NS_SERVER, disjoint from every client-side
# on-link subnet and from the CONNECT-IP tunnel subnet, reachable only via
# the server's own egress connect() (which, in this binary, never runs —
# the request never gets past header parsing).
EXTERNAL_TARGET_IP="10.222.0.1"
EXTERNAL_TARGET_PORT=8090

INNER_TCP_PORT=5403   # distinct from h1's 5401 and h2's 5402

CLIENT_LOG_P1="$(mktemp)"
SERVER_LOG_P1="$(mktemp)"
CLIENT_LOG_P2="$(mktemp)"
SERVER_LOG_P2="$(mktemp)"
INI_P1="$(mktemp --suffix=.ini)"
INI_P2="$(mktemp --suffix=.ini)"
SENT_FILE="$(mktemp)"
RECV_FILE="$(mktemp)"

# Cleanup only drops the /32 alias — no persistent listener exists to reap (see the external-target note below).
cleanup_external_target() {
    ip netns exec "$NS_SERVER" ip addr del "${EXTERNAL_TARGET_IP}/32" dev lo 2>/dev/null || true
}

trap 'cleanup_external_target; bench_cleanup; rm -f "$CLIENT_LOG_P1" "$SERVER_LOG_P1" \
    "$CLIENT_LOG_P2" "$SERVER_LOG_P2" "$INI_P1" "$INI_P2" "$SENT_FILE" "$RECV_FILE"' EXIT

fail=0

echo "[hybrid-mixed] N=$N_PATHS binary=$MQVPN inner-tcp-port=$INNER_TCP_PORT external-target=${EXTERNAL_TARGET_IP}:${EXTERNAL_TARGET_PORT}"
bench_check_test_deps nc jq ss

# ── Phase INIs. Keys cross-checked against src/config.c cfg_keys[] (same as
#    h1/h2). EgressAllow is parsed unconditionally by BOTH client and server
#    config loaders regardless of which hybrid build gates are compiled in
#    (src/config.c ~line 1063, ~line 1140) — it is completely INERT on this
#    egress-OFF server (there is no egress ACL code left to consult it), but
#    it must still be present: this exact INI is meant to also serve as the
#    negative-control input against a BOTH-ON binary (see the header note
#    above), and without EgressAllow punching a hole in the default-deny
#    (src/hybrid/tcp_egress.c DEFAULT_DENY_V4) that control run would 403
#    the target instead of actually exercising the lane — making the
#    control blind to what it's supposed to prove. Value copied verbatim
#    from test_e2e_hybrid_h2.sh Test 1's INI_T1.
cat >"$INI_P1" <<EOF
[Hybrid]
Enabled = true
Tcp = stream
EgressAllow = 10.222.0.0/24
EOF

cat >"$INI_P2" <<EOF
[Hybrid]
Enabled = true
Tcp = raw
EgressAllow = 10.222.0.0/24
EOF

# ── Topology: single path, no netem — this test pins a build-gate shape,
#    not scheduling. ──
bench_setup_netns_n "$N_PATHS"
bench_add_server_host_routes "$N_PATHS"

# External target: only the /32 loopback alias in NS_SERVER is persistent.
# There is deliberately NO long-lived listener on it — the one-shot `nc -l`
# embedded in run_external_byte_identical_transfer is the single listener
# for the target port, started and reaped inside each transfer attempt
# (mirrors h2, which likewise never runs a second listener on a port its
# transfer already binds — two listeners on the same IP:port would
# EADDRINUSE the second bind and turn a healthy binary into a false FAIL).
# That embedded listener serves both phases: in Phase 1 it simply never
# receives a connection (the 501'd lane flow dies client-side), and in a
# BOTH-ON negative-control run it is exactly what the relayed bytes reach.
ip netns exec "$NS_SERVER" ip addr add "${EXTERNAL_TARGET_IP}/32" dev lo

# Parameterized wait_for_log (same as h1/h2). $1 = log file, $2 = grep -E
# pattern, $3 = timeout seconds (default 40).
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

# Listener readiness gate for the one-shot `nc -l`s in the transfer helpers
# (h2's wait_for_listening_port shape): poll up to ~10s until listener $3
# is alive AND bound on port $2 inside netns $1. A dead or never-bound
# listener would make Phase 1's "transfer FAILED" assertion pass for the
# wrong reason (see the external-target note), so readiness failure is a
# HARNESS error — environment, not product — and aborts the whole run
# instead of being scored as an assertion result.
wait_listener_ready() {
    local ns="$1" port="$2" lpid="$3"
    local i
    for (( i=0; i<20; i++ )); do
        if ! kill -0 "$lpid" 2>/dev/null; then
            break
        fi
        if ip netns exec "$ns" ss -ltn 2>/dev/null | grep -q ":${port} "; then
            # The bind ss just saw must be OUR listener's: if $lpid died in
            # the meantime, the bound socket belongs to a stale
            # port-squatter and our nc lost an EADDRINUSE race — returning
            # 0 here would let the transfer talk to the squatter and make
            # Phase 1's assertion 1 pass for an environmental reason.
            kill -0 "$lpid" 2>/dev/null || break
            return 0
        fi
        sleep 0.5
    done
    echo "ERROR: test listener (pid $lpid) failed to start on port ${port} in ${ns} — environment, not product" >&2
    exit 1
}

# Run one full server+client lifecycle with a given INI + log files (same
# shape as h1/h2's hybrid_run).
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

# Parse the LAST client "lanes tcp/dgram/raw=<t>/<d>/<r>" (same as h1/h2).
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

# Parse the LAST client "flows act/tot/rej=<a>/<t>/<r>" (same as h2).
FLOWS_ACT=0; FLOWS_TOT=0; FLOWS_REJ=0
parse_flows() {
    local clog="$1"
    local counts
    counts="$(grep -oE 'flows act/tot/rej=[0-9]+/[0-9]+/[0-9]+' "$clog" \
        | tail -1 | cut -d= -f2)"
    [ -n "$counts" ] || return 1
    FLOWS_ACT="${counts%%/*}"
    FLOWS_REJ="${counts##*/}"
    FLOWS_TOT="${counts#*/}"; FLOWS_TOT="${FLOWS_TOT%%/*}"
    return 0
}

# Byte-identical inner TCP transfer through the CONNECT-IP tunnel to
# $TUNNEL_SERVER_IP (same helper shape as h1/h2's run_byte_identical_transfer,
# file-local copy since none of these scripts are sourceable libraries).
# $1 = sent file, $2 = recv file.
run_tunnel_byte_identical_transfer() {
    local sent="$1" recv="$2"
    head -c 65536 /dev/urandom >"$sent"

    ip netns exec "$NS_SERVER" timeout 20 nc -l "$INNER_TCP_PORT" \
        >"$recv" 2>/dev/null &
    local lpid=$!
    wait_listener_ready "$NS_SERVER" "$INNER_TCP_PORT" "$lpid"
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

# Byte-identical TCP transfer to the EXTERNAL target (h2 Test 1 shape, minus
# curl: this test only needs raw byte delivery, not HTTP framing). $1 = sent
# file — caller must pre-fill it with a NON-EMPTY payload (two empty files
# would `cmp` equal and false-PASS); $2 = recv file. The embedded one-shot
# `nc -l` is the target's only listener, and Phase 1 expects the transfer
# to FAIL while Phase 2 expects it to PASS — see the external-target note
# above for both.
run_external_byte_identical_transfer() {
    local sent="$1" recv="$2"
    [ -s "$sent" ] || { echo "ERROR: empty sent-payload file — harness bug" >&2; exit 1; }

    ip netns exec "$NS_SERVER" timeout 20 nc -l "$EXTERNAL_TARGET_IP" "$EXTERNAL_TARGET_PORT" \
        >"$recv" 2>/dev/null &
    local lpid=$!
    wait_listener_ready "$NS_SERVER" "$EXTERNAL_TARGET_PORT" "$lpid"
    if ! ip netns exec "$NS_CLIENT" timeout 15 nc -N "$EXTERNAL_TARGET_IP" \
            "$EXTERNAL_TARGET_PORT" <"$sent" >/dev/null 2>&1; then
        echo "  (external TCP transfer failed)" >&2
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

# ─── Phase 1: Enabled=true / Tcp=stream against an egress-less server ─────
echo ""
echo "=== Phase 1: LANE=ON client, EGRESS=OFF server, Tcp=stream (expect 501 + inner RST) ==="
hybrid_run "$INI_P1" "$SERVER_LOG_P1" "$CLIENT_LOG_P1"

# 1) The transfer must FAIL — attempt an external-target TCP flow and
#    byte-compare received-vs-sent. cli_connect_tcp_on_headers
#    (src/mqvpn_client.c) routes any non-2xx status (501 here) to
#    mqvpn_tcp_lane_on_stream_rejected, which RSTs the flow before any
#    payload byte can cross — so the receiver gets 0 bytes (nc's exit code
#    alone is NOT trusted, same lesson as h1/h2: it can read 0 even when
#    nothing was ever delivered).
head -c 65536 /dev/urandom >"$SENT_FILE"
if run_external_byte_identical_transfer "$SENT_FILE" "$RECV_FILE"; then
    echo "FAIL: external TCP transfer unexpectedly succeeded byte-identical (egress-less server should 501-reject)"
    fail=1
else
    recv_bytes="$(wc -c <"$RECV_FILE" 2>/dev/null || echo 0)"
    sent_bytes="$(wc -c <"$SENT_FILE")"
    if [ "$recv_bytes" != "$sent_bytes" ]; then
        echo "PASS: external TCP transfer failed as expected (sent ${sent_bytes} bytes, received ${recv_bytes} bytes)"
    else
        echo "FAIL: byte counts matched despite a reported transfer failure — inconclusive rejection"
        fail=1
    fi
fi

# 2) [STATUS] tcp lane field must go NONZERO: lane classification is purely
#    client-side (mqvpn_hybrid_classify -> tun_decide_lane) and fires the
#    moment a packet is handed to lwIP, before the connect-tcp request's
#    response (and therefore the eventual rejection) is even known — see
#    the [STATUS] printf in src/platform/linux/platform_linux.c (~line 311)
#    for the exact log line and test_e2e_hybrid_h2.sh's LANE_TCP_ASSERTION
#    commentary for why this counts independently of outcome.
#    Race pin: same as h1/h2 — [STATUS] fires every 30s
#    (STATUS_INTERVAL_SEC) and a tick can legitimately land before the
#    transfer above ran, so wait up to 40s (one interval + slack) for a
#    tick that DEMANDS a nonzero field.
if wait_for_log "$CLIENT_LOG_P1" 'lanes tcp/dgram/raw=[1-9][0-9]*/' 40; then
    parse_lanes "$CLIENT_LOG_P1" || true
    echo "PASS: [STATUS] reports nonzero tcp lane despite the rejection (tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW)"
else
    echo "FAIL: no [STATUS] line with nonzero tcp lane within 40s"
    parse_lanes "$CLIENT_LOG_P1" \
        && echo "      last lanes line: tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW" \
        || echo "      (no lanes line at all)"
    fail=1
fi

# 3) [STATUS] flows tot field must be >= 1: lane->stats.flows_total
#    (src/hybrid/tcp_lane.c ~line 344) increments at flow creation, BEFORE
#    the connect-tcp response is known, so it counts the attempted flow
#    even though it is doomed to be 501-rejected.
if wait_for_log "$CLIENT_LOG_P1" 'flows act/tot/rej=[0-9]+/[1-9][0-9]*/' 40; then
    parse_flows "$CLIENT_LOG_P1" || true
    echo "PASS: [STATUS] reports nonzero tcp_flows_total (act=$FLOWS_ACT tot=$FLOWS_TOT rej=$FLOWS_REJ)"
else
    echo "FAIL: no [STATUS] line with nonzero tcp_flows_total within 40s"
    parse_flows "$CLIENT_LOG_P1" \
        && echo "      last flows line: act=$FLOWS_ACT tot=$FLOWS_TOT rej=$FLOWS_REJ" \
        || echo "      (no flows line at all)"
    fail=1
fi

# 4) The client process must still be alive: the rejection is a per-flow
#    teardown (tcp_lane_teardown_flow), not a connection-wide error — a
#    regression here (e.g. a wrongly-propagated -1 from cb_request_read)
#    would kill the whole H3/QUIC connection and take the client down with
#    it. _BENCH_CLIENT_PID is bench_env_setup.sh's internal handle to the
#    just-started client process (referenced directly by other e2e scripts,
#    e.g. tests/test_e2e_backup_fec.sh).
if [ -n "$_BENCH_CLIENT_PID" ] && kill -0 "$_BENCH_CLIENT_PID" 2>/dev/null; then
    echo "PASS: client process still alive after the connect-tcp rejection"
else
    echo "FAIL: client process is not alive after the connect-tcp rejection"
    fail=1
fi

# 5)+6) Server-side stats via the control API: an egress-less server has no
#    egress module at all, so both counters must read exactly 0 — not "0
#    because nothing happened yet" but "0 because there is no code path
#    left that could increment them" (see the header's structural-pin
#    reasoning). `// -1` distinguishes "key present and zero" from "key
#    absent" (a contract violation, e.g. a build that dropped the field
#    from the JSON entirely) — a bare `-1` result must fail distinctly from
#    a `0` result, not be conflated with it.
stats_json_p1="$(bench_query_control "$CTRL_PORT" get_stats)"
srv_tot_p1="$(echo "$stats_json_p1" | jq -r '.tcp_flows_total // -1' 2>/dev/null || echo -1)"
if [ "$srv_tot_p1" = "0" ]; then
    echo "PASS: server get_stats reports tcp_flows_total=0 (egress module absent)"
elif [ "$srv_tot_p1" = "-1" ]; then
    echo "FAIL: server get_stats is missing the tcp_flows_total key entirely (contract violation)"
    echo "      raw response: $stats_json_p1"
    fail=1
else
    echo "FAIL: server get_stats reports tcp_flows_total=$srv_tot_p1 (expected 0)"
    echo "      raw response: $stats_json_p1"
    fail=1
fi

srv_rej_p1="$(echo "$stats_json_p1" | jq -r '.tcp_flows_rejected // -1' 2>/dev/null || echo -1)"
if [ "$srv_rej_p1" = "0" ]; then
    echo "PASS: server get_stats reports tcp_flows_rejected=0 (503-cap path unreachable in this binary)"
elif [ "$srv_rej_p1" = "-1" ]; then
    echo "FAIL: server get_stats is missing the tcp_flows_rejected key entirely (contract violation)"
    echo "      raw response: $stats_json_p1"
    fail=1
else
    echo "FAIL: server get_stats reports tcp_flows_rejected=$srv_rej_p1 (expected 0)"
    echo "      raw response: $stats_json_p1"
    fail=1
fi

# 7) Same-instance liveness BEFORE teardown: prove the tunnel itself is
#    still fully healthy after the rejection, not merely that the process
#    didn't crash. Target $TUNNEL_SERVER_IP (the CONNECT-IP tunnel
#    subnet), NOT another external-target probe: the classifier keeps
#    tunnel-subnet TCP on the RAW lane unconditionally by design
#    (client_tunnel_subnet in classifier.h, same exclusion h1 Phase 1
#    pins), so this traffic never re-enters the lane/egress path we just
#    proved broken — it is a clean, independent liveness signal. An
#    external-target probe would instead RST forever here (Tcp=stream
#    routes it back into the same 501-rejecting lane every time), which is
#    exactly the failure mode assertion (1) above already covers — reusing
#    it here would prove nothing new about tunnel health.
if ip netns exec "$NS_CLIENT" ping -c 5 -i 0.2 -W 2 "$TUNNEL_SERVER_IP" \
        >/dev/null 2>&1; then
    echo "PASS: tunnel ping to ${TUNNEL_SERVER_IP} succeeds after the connect-tcp rejection"
else
    echo "FAIL: tunnel ping to ${TUNNEL_SERVER_IP} failed after the connect-tcp rejection"
    fail=1
fi

if run_tunnel_byte_identical_transfer "$SENT_FILE" "$RECV_FILE"; then
    echo "PASS: tunnel-subnet TCP transfer byte-identical after the connect-tcp rejection"
else
    echo "FAIL: tunnel-subnet TCP transfer NOT byte-identical after the connect-tcp rejection"
    fail=1
fi

cleanup_external_target
bench_stop_vpn

# ─── Phase 2: fresh pair, Tcp=raw — RAW mode never touches lane/egress ────
echo ""
echo "=== Phase 2: fresh server+client, Tcp=raw (RAW mode bypasses lane/egress entirely) ==="
# Re-add the /32 alias only (see the external-target note).
ip netns exec "$NS_SERVER" ip addr add "${EXTERNAL_TARGET_IP}/32" dev lo
hybrid_run "$INI_P2" "$SERVER_LOG_P2" "$CLIENT_LOG_P2"

head -c 65536 /dev/urandom >"$SENT_FILE"
if run_external_byte_identical_transfer "$SENT_FILE" "$RECV_FILE"; then
    echo "PASS: external TCP transfer byte-identical under Tcp=raw (never reaches the lane/egress code at all)"
else
    echo "FAIL: external TCP transfer NOT byte-identical under Tcp=raw"
    fail=1
fi

cleanup_external_target
bench_stop_vpn

# ─── Verdict ───────────────────────────────────────────────────────────────
echo ""
if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL"
    echo "--- Client log P1 (last 20) ---"; tail -20 "$CLIENT_LOG_P1"
    echo "--- Server log P1 (last 10) ---"; tail -10 "$SERVER_LOG_P1"
    echo "--- Client log P2 (last 20) ---"; tail -20 "$CLIENT_LOG_P2"
    echo "--- Server log P2 (last 10) ---"; tail -10 "$SERVER_LOG_P2"
    exit 1
fi
echo "RESULT: PASS"
exit 0
