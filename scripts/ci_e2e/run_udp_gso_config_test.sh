#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_udp_gso_config_test.sh — E2E test for the [Advanced] UdpGso and
# UdpGro config keys. Filename kept as `udp_gso` on purpose even though
# it now covers both offload knobs: .github/workflows/ci.yml:385 and
# several bench-script comments reference this path, and a rename would
# spread diff noise for no functional gain.
#
# `udp_gso` (Linux TX UDP GSO / batched-send registration, see
# src/udp_offload.{c,h} and the wiring in mqvpn_client.c / mqvpn_server.c's
# init_xquic_engine()) and `udp_gro` (Linux RX UDP GRO / recvmsg-based
# coalesced-datagram splitting, see mqvpn_udp_gro_enable() called from the
# client's path-registration loop and the server's svr_create_udp_socket() in
# src/platform/linux/platform_linux.c) both have NO CLI flag — the
# [Advanced] section of the INI config file is their only input surface
# (src/config.c's CFG_BOOL(SEC_ADVANCED, "UdpGso", "udp_gso", udp_gso) /
# CFG_BOOL(SEC_ADVANCED, "UdpGro", "udp_gro", udp_gro); both default to 1 in
# src/config.c's mqvpn_config_defaults(). udp_gso additionally has a
# library-side default in src/mqvpn_config.c because it crosses the public
# ABI — udp_gro deliberately has no library-side presence at all, so do not
# go looking for one there). This
# mirrors run_reinjection_test.sh's rationale comment for the same reason
# ([Multipath] Reinjection is also config-file-only).
#
# G13 note — log wording is an observable invariant, pinned here for
# UdpGso and extended to UdpGro in the same spirit: this script greps
# both endpoints' startup logs for two disjoint literal prefixes:
#     LOG_I(c, "udp-gso: %s", c->gso_available ? "GSO enabled"
#                                               : "GSO unavailable, using sendmmsg");
#     LOG_I(s, "udp-gso: %s", s->gso_available ? "GSO enabled"
#                                               : "GSO unavailable, using sendmmsg");
#     LOG_INF("udp-gro: enabled on path[%d]", i);      /* client, per path */
#     LOG_INF("udp-gro: unavailable on path[%d] (%s); ...", i, ...);
#     LOG_INF("udp-gro: enabled");                     /* server */
#     LOG_INF("udp-gro: unavailable (%s); ...", ...);
# Changing either wording, or moving/removing any of these call sites,
# silently breaks the corresponding assertions below (presence in the arm
# where that knob is on, absence in the arm where it is forced off) the
# same way the "reconnecting in" / "stuck in PENDING" wordings are pinned
# invariants elsewhere in this suite (see sanitizer_check.sh and
# AGENTS.md's e2e log marker note). If you reword either, update the
# matching grep pattern in this file (search "udp-gso:" / "udp-gro:") in
# the same change. Two teardown telemetry lines use further, disjoint
# prefixes that never match either grep above:
#     LOG_INF("udp-rx: receives=%llu datagrams=%llu gro_config=%d", ...);
#     LOG_I(c, "udp-tx: sends=%llu datagrams=%llu gso_config=%d", ...);
#     LOG_I(s, "udp-tx: sends=%llu datagrams=%llu gso_config=%d", ...);
# Both are emitted unconditionally — on the enabled and the disabled path
# alike — so a knob's state shows up in the *_config field value rather
# than in the line's presence, and neither can serve as an enablement
# marker. They are asserted by check_teardown_line below, which runs after
# the endpoints have been reaped (the lines do not exist before teardown:
# udp-rx comes from platform_linux.c's `cleanup:` labels, udp-tx from
# mqvpn_client_destroy / mqvpn_server_destroy). run_udp_gso_bench.sh
# parses the same two lines into its result table.
#
# Race-freedom rationale (why asserting log-ABSENCE right after tunnel-up
# is safe, not a best-effort poll): both LOG_I("udp-gso: ...") call sites
# run inside init_xquic_engine(), synchronously before xqc_engine_create()
# — i.e. strictly before the engine exists, and therefore strictly before
# any handshake can begin. The udp-gro markers run even earlier in the
# startup sequence: the client's fires per path inside the socket
# registration loop, strictly before mqvpn_client_connect() is called;
# the server's fires inside svr_create_udp_socket(), strictly before
# event_base_dispatch() is reached. "Tunnel is up" (first successful
# tunnel ping) can only happen after a completed handshake, which
# happens-after engine creation and after the event loop starts running —
# both of which happen-after every point above where a marker would have
# been emitted had its knob been on. So by the time the tunnel-ping check
# below passes, there is no remaining window where either marker could
# still be about to appear — checking the log files at that point is
# equivalent to checking them at any later time.
#
# Arms (single client/server pair per arm; fresh netns + fresh PSK/cert
# each time via bench_env_setup.sh). Each arm asserts BOTH markers'
# present/absent state — checking only the knob under test would let a
# regression in the OTHER knob's wiring pass silently:
#   A. default (UdpGso=true, UdpGro=true) — no --config / -C. The
#      "udp-gso: " line (either "GSO enabled" or "GSO unavailable, using
#      sendmmsg" — both prove the batch send path was registered; the
#      choice between them depends on the CI runner's kernel, which this
#      test does not pin) and the "udp-gro: " line (either "enabled" or
#      "unavailable...", same kernel-dependence caveat) MUST both be
#      present in BOTH the client and server logs.
#   B. UdpGso=false (-C), UdpGro stays default true — a minimal INI
#      containing ONLY [Advanced] / UdpGso = false is passed via -C to
#      BOTH endpoints, same flags as Arm A otherwise. The "udp-gso: " line
#      MUST be ABSENT from both logs (proves the escape hatch cleanly
#      restores the legacy per-packet xqc_engine_create() registration
#      with no GSO callback wired in at all — not merely "GSO available
#      but declined"); the "udp-gro: " line MUST still be PRESENT (UdpGro
#      is untouched by this arm).
#   C. UdpGro=false (-C), UdpGso stays default true — a minimal INI
#      containing ONLY [Advanced] / UdpGro = false is passed via -C to
#      BOTH endpoints. The "udp-gro: " line MUST be ABSENT from both logs
#      (proves the escape hatch cleanly restores the legacy
#      one-datagram-per-recvmsg() path with no GRO sockopt set at all);
#      the "udp-gso: " line MUST still be PRESENT (UdpGso is untouched by
#      this arm).
#
# All arms verify tunnel connectivity (ping through the tunnel) after
# the marker checks, same idiom as every other 2-path e2e script in this
# directory (see run_dellink_test.sh / run_reconnect_test.sh).
#
# REQUIRES: root (netns + TUN), openssl (cert generation via
# bench_env_setup.sh's bench_start_vpn_server).
#
# Run manually:
#   sudo bash scripts/ci_e2e/run_udp_gso_config_test.sh [path/to/mqvpn]
#
# Exit code: 0 if all arms pass and no sanitizer error fired, 1 otherwise.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/sanitizer_check.sh"
source "${SCRIPT_DIR}/../../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}}"
LOG_DIR="$(mktemp -d)"
SANITIZER_FAIL=0

# Named-function trap (same shape as run_reinjection_test.sh /
# run_control_api_test.sh): preserve logs on failure, reap netns/procs via
# bench_cleanup, and fail the whole run if a sanitizer error fired in any
# arm even though that arm's own functional check passed.
cleanup() {
    local _rc=$?
    bench_cleanup
    # Preserve logs on ANY failure mode, not just a nonzero $_rc: a run that
    # returns 0 (every arm's own functional check passed) can still have
    # SANITIZER_FAIL set from a check that only fires after the arm itself
    # reported success — deleting the logs before that check is even
    # consulted would defeat the "Logs preserved at: ..." message below for
    # exactly the failure mode it exists to cover.
    if (( _rc != 0 || SANITIZER_FAIL != 0 )); then
        echo "Logs preserved at: $LOG_DIR" >&2
    else
        rm -rf "$LOG_DIR"
    fi
    if (( SANITIZER_FAIL != 0 )); then
        echo "FAIL: sanitizer errors detected" >&2
        exit 1
    fi
}
trap cleanup EXIT
echo "Logs: $LOG_DIR"

# --- Preflight ---

if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: must run as root (sudo)" >&2
    exit 2
fi

# bench_check_test_deps (benchmarks/bench_env_setup.sh:101-118): verifies
# $MQVPN exists and resolves it to a realpath; verifies each named dep is
# on PATH. openssl is the only external dep this script needs (used
# transitively by bench_start_vpn_server for cert generation).
bench_check_test_deps openssl

PASS=0
FAIL=0

# --- run_test wrapper (copied from run_reinjection_test.sh / run_control_api_test.sh) ---

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

# --- Client launcher with extra-flags support ---
#
# bench_start_vpn_client (benchmarks/bench_env_setup.sh:312-340) only takes
# a --path list, not arbitrary extra flags, so -C can't go through it. This
# mirrors run_reinjection_test.sh's start_client_with_auth_key /
# run_control_api_test.sh's client launcher: SAME flag set as
# bench_start_vpn_client's body (including --scheduler "$BENCH_SCHEDULER",
# previously missing here — a real flag-set gap, not just parity in name),
# plus an extra_flags passthrough.
start_client() {
    local extra_flags="$1"
    local client_log="$2"

    if [ -n "$_BENCH_CLIENT_PID" ] && kill -0 "$_BENCH_CLIENT_PID" 2>/dev/null; then
        kill "$_BENCH_CLIENT_PID" 2>/dev/null || true
        wait "$_BENCH_CLIENT_PID" 2>/dev/null || true
        _BENCH_CLIENT_PID=""
    fi

    # shellcheck disable=SC2086  # extra_flags is intentionally word-split
    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server "${IP_A_SERVER_ADDR}:${VPN_LISTEN_PORT}" \
        --path "$VETH_A0" --path "$VETH_B0" \
        --auth-key "$_BENCH_PSK" \
        --scheduler "$BENCH_SCHEDULER" \
        --insecure \
        --log-level "$BENCH_LOG_LEVEL" \
        $extra_flags \
        >"$client_log" 2>&1 &
    _BENCH_CLIENT_PID=$!
    sleep 2

    if ! kill -0 "$_BENCH_CLIENT_PID" 2>/dev/null; then
        echo "  ERROR: client process died; tail of $client_log:" >&2
        tail -30 "$client_log" >&2
        return 1
    fi
    return 0
}

# End-of-arm teardown: sanitizer-check both endpoints (same idiom as
# run_reinjection_test.sh's finish_scenario / run_backup_fec_test.sh's
# cleanup_processes) and clear the PID vars so the next arm's bench_cleanup
# doesn't try to re-kill an already-reaped process. A sanitizer failure is
# recorded in the global SANITIZER_FAIL (checked once at final script
# exit) rather than flipping this arm's own PASS/FAIL.
finish_arm() {
    local desc="$1" server_log="$2" client_log="$3"
    stop_and_check_sanitizer "$_BENCH_CLIENT_PID" "${desc} client" "$client_log" \
        || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$_BENCH_SERVER_PID" "${desc} server" "$server_log" \
        || SANITIZER_FAIL=1
    _BENCH_CLIENT_PID=""
    _BENCH_SERVER_PID=""
}

# check_marker <marker> <expect_present:0|1> <server_log> <client_log>
#
# Shared present/absent assertion for a single log-line prefix, factored
# out of run_arm so both the "udp-gso: " and "udp-gro: " checks share one
# implementation. Grep the log FILES directly (no writer | grep -q
# pipeline — G19: a pipefail'd writer|grep -q can SIGPIPE-fail the writer
# even on a successful match). Ends on an explicit `return 0`, never a
# bare `[ cond ] && action` — a sourced/shared function that falls through
# to a false condition would return 1 and could abort a caller's `set -e`.
check_marker() {
    local marker="$1" expect_present="$2" server_log="$3" client_log="$4"
    local server_hits client_hits
    server_hits=$(grep -c "$marker" "$server_log" 2>/dev/null || true)
    client_hits=$(grep -c "$marker" "$client_log" 2>/dev/null || true)
    server_hits="${server_hits:-0}"
    client_hits="${client_hits:-0}"

    if [ "$expect_present" -eq 1 ]; then
        if [ "$server_hits" -eq 0 ] || [ "$client_hits" -eq 0 ]; then
            echo "  FAIL: '$marker' marker missing (server_hits=$server_hits client_hits=$client_hits)"
            echo "  --- server log tail ---"
            tail -30 "$server_log"
            echo "  --- client log tail ---"
            tail -30 "$client_log"
            return 1
        fi
        echo "  OK: '$marker' marker present on both ends:"
        grep "$marker" "$server_log" | sed 's/^/    server: /'
        grep "$marker" "$client_log" | sed 's/^/    client: /'
    else
        if [ "$server_hits" -ne 0 ] || [ "$client_hits" -ne 0 ]; then
            echo "  FAIL: '$marker' marker unexpectedly present (server_hits=$server_hits client_hits=$client_hits)"
            echo "  --- server log hits ---"
            grep "$marker" "$server_log" || true
            echo "  --- client log hits ---"
            grep "$marker" "$client_log" || true
            return 1
        fi
        echo "  OK: '$marker' marker absent on both ends (server_hits=0 client_hits=0)"
    fi
    return 0
}

# check_teardown_line <prefix> <expected_field> <server_log> <client_log>
#
# Assertion for the unconditional teardown telemetry lines ("udp-rx: " /
# "udp-tx: "). Unlike check_marker's presence/absence contract, these lines
# are emitted whatever the knob's state, so the knob is verified through a
# field value carried ON the line (e.g. "gso_config=0") — presence alone
# would prove nothing. Both endpoints must emit it.
#
# MUST be called only after finish_arm has reaped both endpoints: the
# lines are written during process teardown, so grepping any earlier races
# a line that does not exist yet. Greps the FILES directly and closes with
# `tail -1` (reads to EOF) rather than a `grep -q`-style early-exit reader
# — G19: under pipefail an early-exiting reader SIGPIPEs the writer and
# turns a successful match into a spurious failure.
check_teardown_line() {
    local prefix="$1" field="$2" server_log="$3" client_log="$4"
    local rc=0 log line
    for log in "$server_log" "$client_log"; do
        line="$(grep "$prefix" "$log" 2>/dev/null | tail -1 || true)"
        if [ -z "$line" ]; then
            echo "  FAIL: '$prefix' teardown line missing from $log"
            rc=1
            continue
        fi
        case "$line" in
            *"$field"*)
                echo "  OK: $(basename "$log"): $line"
                ;;
            *)
                echo "  FAIL: '$prefix' line does not carry '$field' in $log:"
                echo "    $line"
                rc=1
                ;;
        esac
    done
    return $rc
}

# --- Shared arm body ---
#
# arm_id: short tag for log filenames.
# expect_gso: 1 = "udp-gso: " must be present in both logs, 0 = absent.
#             Also asserted verbatim as "gso_config=<expect_gso>" on the
#             "udp-tx: " teardown line, which pins that the config value
#             actually reached the send path rather than only the startup
#             registration branch.
# expect_gro: 1 = "udp-gro: " must be present in both logs, 0 = absent.
#             Likewise asserted as "gro_config=<expect_gro>" on "udp-rx: ".
# extra_flags: appended to BOTH the server and client command lines
#              (e.g. "-C <ini>" for Arm B/C; empty for Arm A).
run_arm() {
    local arm_id="$1" expect_gso="$2" expect_gro="$3" extra_flags="$4"
    local server_log="${LOG_DIR}/${arm_id}_server.log"
    local client_log="${LOG_DIR}/${arm_id}_client.log"

    bench_cleanup
    bench_setup_netns

    # bench_start_vpn_server (benchmarks/bench_env_setup.sh:276-310): rolls
    # a fresh PSK + self-signed cert into $_BENCH_PSK / $_BENCH_WORK_DIR,
    # then launches the server with $extra_flags appended raw. start_client
    # (above) reads the SAME $_BENCH_PSK immediately after — no re-roll
    # race, since neither this function nor its callees invoke
    # bench_start_vpn_server a second time per arm (contrast
    # run_reinjection_test.sh's start_server_with_flags, which restarts
    # deliberately to reuse a freshly-rolled PSK across a custom flag set;
    # not needed here since one bench_start_vpn_server call already
    # supports arbitrary extra flags).
    # shellcheck disable=SC2086  # extra_flags is intentionally word-split
    if ! bench_start_vpn_server "$extra_flags" "$server_log"; then
        echo "  FAIL: server did not start; tail of $server_log:"
        tail -30 "$server_log" 2>/dev/null
        return 1
    fi

    if ! start_client "$extra_flags" "$client_log"; then
        return 1
    fi

    # bench_wait_tunnel (benchmarks/bench_env_setup.sh:342-358): polls
    # ping to $TUNNEL_SERVER_IP from $NS_CLIENT up to the given timeout.
    if ! bench_wait_tunnel 15; then
        echo "  --- server log ---"
        cat "$server_log"
        echo "  --- client log ---"
        cat "$client_log"
        return 1
    fi

    # udp-gso: / udp-gro: marker checks. Race-freedom argument is in the
    # file header: every marker's LOG call site runs before the point
    # where a handshake could begin, so tunnel-up (just verified above)
    # happens-after the point either marker would have appeared. Fail the
    # arm if either marker doesn't match its arm's expectation — checking
    # only one would let a regression in the other knob's wiring through.
    if ! check_marker "udp-gso: " "$expect_gso" "$server_log" "$client_log"; then
        return 1
    fi
    if ! check_marker "udp-gro: " "$expect_gro" "$server_log" "$client_log"; then
        return 1
    fi

    # Tunnel connectivity, same idiom as run_dellink_test.sh /
    # run_reconnect_test.sh: a few pings through the tunnel address.
    if ! ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_SERVER_IP"; then
        echo "  FAIL: tunnel ping failed"
        echo "  --- server log ---"
        cat "$server_log"
        echo "  --- client log ---"
        cat "$client_log"
        return 1
    fi
    echo "  OK: tunnel connectivity verified"

    finish_arm "$arm_id" "$server_log" "$client_log"

    # Teardown telemetry, checked only now: both endpoints have been reaped
    # above, and these lines are written on the way out (see the header's
    # G13 note). Each carries its knob's configured value, so this catches a
    # config value that reached the startup registration but not the data
    # path — the "udp-gso: "/"udp-gro: " marker checks above cannot.
    if ! check_teardown_line "udp-tx: " "gso_config=${expect_gso}" \
        "$server_log" "$client_log"; then
        return 1
    fi
    if ! check_teardown_line "udp-rx: " "gro_config=${expect_gro}" \
        "$server_log" "$client_log"; then
        return 1
    fi
    return 0
}

# --- Arm A: default (UdpGso, UdpGro unset -> both true) ---

test_arm_default() {
    run_arm "default" 1 1 ""
}

# --- Arm B: UdpGso = false via -C (UdpGro stays default true) ---

test_arm_disabled() {
    # Minimal INI containing ONLY [Advanced] / UdpGso = false — mirrors
    # tests/test_config.c's test_advanced_udp_gso fixture
    # ("[Advanced]\nUdpGso = false\n") exactly. main.c loads this file via
    # mqvpn_config_load() before applying CLI overrides per-field (see
    # main.c's "CLI overrides config file values" comment); since udp_gso
    # has no CLI flag, this INI section is the value's only source, and
    # every other value falls back to mqvpn_config_defaults() + this run's
    # flags — an INI with only [Advanced] is valid on its own
    # (parse_section / SEC_ADVANCED in src/config.c never requires
    # sibling sections).
    local ini="${LOG_DIR}/udp_gso_false.ini"
    cat >"$ini" <<EOF
[Advanced]
UdpGso = false
EOF
    run_arm "disabled" 0 1 "-C $ini"
}

# --- Arm C: UdpGro = false via -C (UdpGso stays default true) ---

test_arm_gro_disabled() {
    # Minimal INI containing ONLY [Advanced] / UdpGro = false — mirrors
    # tests/test_config.c's test_advanced_udp_gro fixture
    # ("[Advanced]\nUdpGro = false\n") exactly, same rationale as Arm B's
    # comment above (udp_gro also has no CLI flag).
    local ini="${LOG_DIR}/udp_gro_false.ini"
    cat >"$ini" <<EOF
[Advanced]
UdpGro = false
EOF
    run_arm "gro_disabled" 1 0 "-C $ini"
}

# --- Main runner ---

echo ""
echo "================================================================"
echo " UdpGso / UdpGro config-key E2E"
echo " Binary: $MQVPN"
echo "================================================================"

run_test "Arm A — default (UdpGso, UdpGro unset, true): both markers present" test_arm_default
run_test "Arm B — UdpGso = false via -C: gso marker absent, gro present"      test_arm_disabled
run_test "Arm C — UdpGro = false via -C: gro marker absent, gso present"      test_arm_gro_disabled

echo ""
echo "================================================================"
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================================"

if (( FAIL > 0 )); then
    exit 1
fi
exit 0
