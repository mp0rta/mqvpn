#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# test_e2e_hybrid_h1.sh — Netns end-to-end test for the hybrid-mode ingress
# classifier + per-lane counters (written at the H1 stage; assertions kept
# current with the H2 TCP-lane transport).
#
# What this verifies (per phase, fresh server+client each; every phase's
# TCP transfer compares the received bytes byte-for-byte against what was
# sent — exit codes alone can mask a transport that delivers nothing):
#   Phase 1 [Hybrid] Enabled=true / Tcp=stream:
#     - tunnel establishes and traffic works (ping + byte-identical TCP
#       transfer).
#     - the client [STATUS] line (platform_linux.c, fires every 30s in
#       ESTABLISHED; ends with "lanes tcp/dgram/raw=<n>/<n>/<n>") reports
#       tcp == 0 and a NONZERO raw count: this phase's TCP probe targets
#       the tunnel subnet (TUNNEL_SERVER_IP), and the classifier keeps
#       tunnel-subnet TCP on the RAW lane BY DESIGN (client_tunnel_subnet
#       in classifier.h — the server's connect-tcp egress ACL denies the
#       tunnel subnet unconditionally, so laning it could only ever RST).
#       This phase is the e2e pin of that exclusion; the actual TCP-lane
#       transport with an out-of-subnet target is test_e2e_hybrid_h2.sh
#       Test 1's job.
#   Phase 2 [Hybrid] Enabled=true / Tcp=raw:
#     - traffic works; NONZERO raw count (TCP now classifies as RAW by
#       policy). tcp is 0 by construction and deliberately NOT asserted.
#   Phase 3 [Hybrid] Enabled=false:
#     - traffic works; the lanes line reads exactly 0/0/0 (classifier is
#       skipped entirely when hybrid is disabled — the default).
#
# TIMING / RACE PIN: the [STATUS] timer is armed at TUN-up with a
# compile-time 30s interval (STATUS_INTERVAL_SEC — do NOT patch it). A
# [STATUS] line can legitimately fire BEFORE the phase's traffic ran and
# report 0, so phases 1-2 wait (40s timeout, covering one full interval
# plus slack) for a pattern that DEMANDS a nonzero field; counters are
# cumulative, so once nonzero they stay nonzero.
#
# How hybrid is enabled: no CLI flag — [Hybrid] is INI/JSON only
# (src/config.c SEC_HYBRID). Like tests/test_e2e_reorder.sh, we generate a
# tiny INI containing ONLY [Hybrid] and pass it via --config alongside the
# harness's --listen/--server/--path/--auth-key flags (CLI overrides
# per-field, so the INI adds only the hybrid section).
#
# Requires: root, netns support, netcat-openbsd.
# Usage:    sudo ./test_e2e_hybrid_h1.sh [mqvpn-binary]

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Pin the build dir explicitly: this branch builds into build-debug, and the
# harness default (../build/mqvpn) can silently pick up a STALE binary from a
# different build tree (past e2e lesson). $1 / $MQVPN still override.
MQVPN="${MQVPN:-${SCRIPT_DIR}/../build-debug/mqvpn}"
# shellcheck source=../benchmarks/bench_env_setup.sh
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
N_PATHS=1
CTRL_PORT=9095
INNER_TCP_PORT=5401   # inner TCP listener port (server netns, tunnel IP)

CLIENT_LOG_P1="$(mktemp)"
SERVER_LOG_P1="$(mktemp)"
CLIENT_LOG_P2="$(mktemp)"
SERVER_LOG_P2="$(mktemp)"
CLIENT_LOG_P3="$(mktemp)"
SERVER_LOG_P3="$(mktemp)"
INI_P1="$(mktemp --suffix=.ini)"
INI_P2="$(mktemp --suffix=.ini)"
INI_P3="$(mktemp --suffix=.ini)"
SENT_FILE="$(mktemp)"
RECV_FILE="$(mktemp)"

trap 'bench_cleanup; rm -f "$CLIENT_LOG_P1" "$SERVER_LOG_P1" "$CLIENT_LOG_P2" \
    "$SERVER_LOG_P2" "$CLIENT_LOG_P3" "$SERVER_LOG_P3" \
    "$INI_P1" "$INI_P2" "$INI_P3" "$SENT_FILE" "$RECV_FILE"' EXIT

fail=0

echo "[hybrid-h1] N=$N_PATHS binary=$MQVPN inner-tcp-port=$INNER_TCP_PORT"
bench_check_test_deps nc

# ── Phase INIs. Keys cross-checked against src/config.c cfg_keys[]:
#    [Hybrid] Enabled true|false -> CFG_BOOL (parse_bool: true/yes/1)
#    [Hybrid] Tcp stream|raw|auto -> parse_hybrid_tcp_mode
cat >"$INI_P1" <<EOF
[Hybrid]
Enabled = true
Tcp = stream
EOF

cat >"$INI_P2" <<EOF
[Hybrid]
Enabled = true
Tcp = raw
EOF

cat >"$INI_P3" <<EOF
[Hybrid]
Enabled = false
EOF

# ── Topology: single path, no netem — H1 asserts counters, not scheduling ──
bench_setup_netns_n "$N_PATHS"
bench_add_server_host_routes "$N_PATHS"

# Parameterized wait_for_log (adapted from tests/test_e2e_dellink.sh, which
# greps a hardcoded global log — here each phase has its own log file).
# $1 = log file, $2 = grep -E pattern, $3 = timeout seconds (default 40).
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

# Run one full server+client lifecycle with a given INI + log files.
# $1 = INI path, $2 = server log, $3 = client log
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

# Traffic: ping (ICMP -> RAW lane) + one inner TCP transfer through the
# tunnel via netcat-openbsd (already a hard dep for the control API).
# Listener binds inside NS_SERVER; client pushes a 64KB random payload and
# closes on EOF (-N). The receiver's bytes are compared byte-for-byte
# against the payload — nc's exit code alone can read 0 even when nothing
# was delivered (the sender can't tell), which once masked a Phase 1
# transport failure entirely.
run_inner_traffic() {
    if ! ip netns exec "$NS_CLIENT" ping -c 5 -i 0.2 -W 2 "$TUNNEL_SERVER_IP" \
            >/dev/null 2>&1; then
        echo "  (tunnel ping failed)" >&2
        return 1
    fi

    head -c 65536 /dev/urandom >"$SENT_FILE"
    ip netns exec "$NS_SERVER" timeout 20 nc -l "$INNER_TCP_PORT" \
        >"$RECV_FILE" 2>/dev/null &
    local lpid=$!
    sleep 1
    if ! ip netns exec "$NS_CLIENT" timeout 15 nc -N "$TUNNEL_SERVER_IP" \
            "$INNER_TCP_PORT" <"$SENT_FILE" >/dev/null 2>&1; then
        echo "  (inner TCP transfer failed)" >&2
        kill "$lpid" 2>/dev/null || true
        wait "$lpid" 2>/dev/null || true
        return 1
    fi
    wait "$lpid" 2>/dev/null || true

    if ! cmp -s "$SENT_FILE" "$RECV_FILE"; then
        echo "  (byte mismatch: sent $(wc -c <"$SENT_FILE") bytes, received $(wc -c <"$RECV_FILE") bytes)" >&2
        return 1
    fi
    return 0
}

# Parse the LAST client "lanes tcp/dgram/raw=<t>/<d>/<r>" into LANE_TCP /
# LANE_DGRAM / LANE_RAW (counters are cumulative, so last = max). Returns 1
# if no lanes line found.
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

# ─── Phase 1: Enabled=true / Tcp=stream ────────────────────────────────────
echo ""
echo "=== Phase 1: hybrid ON, Tcp=stream (tunnel-subnet TCP stays RAW) ==="
hybrid_run "$INI_P1" "$SERVER_LOG_P1" "$CLIENT_LOG_P1"

if run_inner_traffic; then
    echo "PASS: inner traffic byte-identical with hybrid ON / Tcp=stream"
else
    echo "FAIL: inner traffic failed with hybrid ON / Tcp=stream"
    fail=1
fi

# RACE PIN: demand a NONZERO raw field — an early [STATUS] tick may
# legitimately report 0 before the traffic above ran. The TCP probe targets
# the tunnel subnet, which the classifier keeps on the RAW lane by design
# (see the header), so under Tcp=stream this phase expects tcp == 0 with
# every packet (ping AND the TCP transfer) counted raw.
if wait_for_log "$CLIENT_LOG_P1" \
        'lanes tcp/dgram/raw=[0-9]+/[0-9]+/[1-9][0-9]*' 40; then
    parse_lanes "$CLIENT_LOG_P1" || true
    echo "PASS: [STATUS] reports nonzero raw lane (tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW)"
    if [ "$LANE_TCP" -eq 0 ]; then
        echo "PASS: tcp lane == 0 (tunnel-subnet TCP excluded from the lane)"
    else
        echo "FAIL: tcp lane nonzero for tunnel-subnet-only TCP (tcp=$LANE_TCP)"
        fail=1
    fi
else
    echo "FAIL: no [STATUS] line with nonzero raw lane within 40s"
    parse_lanes "$CLIENT_LOG_P1" \
        && echo "      last lanes line: tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW" \
        || echo "      (no lanes line at all)"
    fail=1
fi

bench_stop_vpn

# ─── Phase 2: Enabled=true / Tcp=raw ───────────────────────────────────────
echo ""
echo "=== Phase 2: hybrid ON, Tcp=raw (TCP counts as raw) ==="
hybrid_run "$INI_P2" "$SERVER_LOG_P2" "$CLIENT_LOG_P2"

if run_inner_traffic; then
    echo "PASS: traffic works with hybrid ON / Tcp=raw"
else
    echo "FAIL: traffic failed with hybrid ON / Tcp=raw"
    fail=1
fi

# NONZERO third (raw) field; tcp is 0 by construction and NOT asserted.
if wait_for_log "$CLIENT_LOG_P2" \
        'lanes tcp/dgram/raw=[0-9]+/[0-9]+/[1-9][0-9]*' 40; then
    parse_lanes "$CLIENT_LOG_P2" || true
    echo "PASS: [STATUS] reports nonzero raw lane (tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW)"
else
    echo "FAIL: no [STATUS] line with nonzero raw lane within 40s"
    parse_lanes "$CLIENT_LOG_P2" \
        && echo "      last lanes line: tcp=$LANE_TCP dgram=$LANE_DGRAM raw=$LANE_RAW" \
        || echo "      (no lanes line at all)"
    fail=1
fi

bench_stop_vpn

# ─── Phase 3: Enabled=false (default no-op) ────────────────────────────────
echo ""
echo "=== Phase 3: hybrid OFF (counters must stay 0/0/0) ==="
hybrid_run "$INI_P3" "$SERVER_LOG_P3" "$CLIENT_LOG_P3"

if run_inner_traffic; then
    echo "PASS: traffic works with hybrid OFF"
else
    echo "FAIL: traffic failed with hybrid OFF"
    fail=1
fi

# Any lanes line will do (counters can only ever be 0 here), then assert
# every observed lanes line reads exactly 0/0/0.
if wait_for_log "$CLIENT_LOG_P3" 'lanes tcp/dgram/raw=' 40; then
    nonzero="$(grep -E 'lanes tcp/dgram/raw=' "$CLIENT_LOG_P3" \
        | grep -vE 'lanes tcp/dgram/raw=0/0/0' || true)"
    if [ -z "$nonzero" ]; then
        echo "PASS: all [STATUS] lanes lines read 0/0/0 with hybrid disabled"
    else
        echo "FAIL: nonzero lane counters despite Enabled=false:"
        echo "$nonzero" | sed 's/^/      /'
        fail=1
    fi
else
    echo "FAIL: no [STATUS] lanes line within 40s with hybrid OFF"
    fail=1
fi

# ─── Verdict ───────────────────────────────────────────────────────────────
echo ""
if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL"
    echo "--- Client log P1 (last 20) ---"; tail -20 "$CLIENT_LOG_P1"
    echo "--- Client log P2 (last 20) ---"; tail -20 "$CLIENT_LOG_P2"
    echo "--- Client log P3 (last 20) ---"; tail -20 "$CLIENT_LOG_P3"
    echo "--- Server log P1 (last 10) ---"; tail -10 "$SERVER_LOG_P1"
    exit 1
fi
echo "RESULT: PASS"
exit 0
