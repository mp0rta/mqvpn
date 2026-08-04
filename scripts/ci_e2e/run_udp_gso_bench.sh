#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_udp_gso_bench.sh — UdpGso / UdpGro A/B/C/D benchmark: throughput,
# CPU cost, receive-side counters, and latency
#
# Measures the win (or lack of one) from `udp_gso` (Linux TX UDP GSO /
# batched-send registration — see src/udp_offload.{c,h}, wired in
# init_xquic_engine() in mqvpn_client.c / mqvpn_server.c) and `udp_gro`
# (Linux RX UDP GRO / recvmsg-based coalesced-datagram splitting — see
# mqvpn_udp_gro_enable(), wired in the client's path-registration loop and
# the server's svr_create_udp_socket() in src/platform/linux/platform_linux.c) on
# the SAME binary, so every comparison is purely a runtime UdpGso/UdpGro
# toggle and never a rebuild artifact (G20 — see mqvpn-dev-gates skill:
# compiler/flag drift between arms has produced false conclusions before).
# The binary path and its sha256 are recorded in the output header for
# that reason.
#
# Arms (single client/server pair, same 2-path netns topology as
# run_udp_gso_config_test.sh, fresh netns/PSK/cert every run) — four
# arms, the full 2x2 of the two independent knobs:
#   A. "default"   — no --config / -C. udp_gso and udp_gro both default to
#      true in src/config.c's mqvpn_config_defaults(). (udp_gso also has a
#      library-side default in src/mqvpn_config.c because it crosses the
#      public ABI; udp_gro is platform-only and has none — do not look for
#      one there.)
#   B. "disabled"  — [Advanced]/UdpGso=false via -C <ini>, udp_gro stays
#      default true. INI content mirrors run_udp_gso_config_test.sh's
#      Arm B exactly (== tests/test_config.c's test_advanced_udp_gso
#      fixture).
#   C. "gro_off"   — [Advanced]/UdpGro=false via -C <ini>, udp_gso stays
#      default true. Mirrors run_udp_gso_config_test.sh's Arm C exactly
#      (== tests/test_config.c's test_advanced_udp_gro fixture).
#   D. "both_off"  — [Advanced]/UdpGso=false AND UdpGro=false via -C
#      <ini> — the true pre-#167 baseline (neither offload wired at all).
# All four arms pass -C to BOTH endpoints (empty extra_flags for arm A).
# Per run we also grep both endpoints' logs for the "udp-gso: " AND
# "udp-gro: " markers (pinned wording, see mqvpn_client.c:2843 /
# mqvpn_server.c:1880, platform_linux.c's mqvpn_udp_gro_enable() call
# sites, and run_udp_gso_config_test.sh's header comment) so the printed
# table proves which code path actually ran in each row for BOTH knobs,
# not just which flags were passed.
#
# Per run:
#   - iperf3 TCP, client (NS_CLIENT) -> server (NS_SERVER) upload, no -R.
#     This is the same direction/idiom as bench_aggregate.sh /
#     run_throughput_floor_test.sh (iperf3 -c ... -t DURATION -P STREAMS
#     --json, parsed via python3 for end.sum_received / end.sum). Upload
#     (not -R/download) is deliberate: it drives data from the CLIENT's TUN
#     out through the CLIENT's outer UDP TX path (what UdpGso batches) and
#     back in through the SERVER's outer UDP RX path (what UdpGro
#     coalesces) — the same direction exercises both knobs' receive side.
#   - CPU: both mqvpn processes (client + server, PIDs tracked by
#     bench_env_setup.sh as $_BENCH_CLIENT_PID / $_BENCH_SERVER_PID) are
#     sampled for the same window as the iperf3 transfer.
#     No bench sibling in this repo uses pidstat (grepped; all CPU/RSS
#     sampling in this tree is /proc-based, e.g.
#     scripts/ci_stress/ci_stress_env.sh:290-312's RSS monitor), so this
#     script prefers pidstat when present (verified empirically against the
#     real /usr/bin/pidstat on a dev box — see comment above
#     proc_cpu_ticks() below for exactly what was checked) and falls back
#     to a plain /proc/[pid]/stat utime+stime delta otherwise. Either
#     method reports whole-process CPU (all threads aggregated), confirmed
#     empirically with a 2-thread pthread busy-loop test process reading
#     ~200% from both methods — not just the main thread.
#   - Transmit-side counters (per run, printed as a separate detail table —
#     see the "Transmit-side detail" section below): the "udp-tx: sends=N
#     datagrams=M gso_config=X" teardown telemetry line from BOTH endpoint
#     logs, parsed under the same reaped-first / "NA" rules as the
#     receive-side line below. datagrams/sends is the achieved batching
#     factor, and the only runtime evidence that UdpGso did anything: the
#     startup "udp-gso: " marker reports a kernel capability probe, so it
#     reads identically whether every burst formed a 32-datagram GSO run or
#     every datagram took a syscall of its own.
#   - Receive-side counters (per run, printed as a separate detail table —
#     see the "Receive-side detail" section below): the "udp-rx:
#     receives=N datagrams=M gro_config=X" teardown telemetry line from
#     BOTH endpoint logs (parsed only after the process has been reaped —
#     it is written at teardown, so it does not exist while the process is
#     alive; a missing line means the arm failed before carrying traffic,
#     recorded as "NA" fields, not treated as a parse error);
#     Udp: InErrors / RcvbufErrors from /proc/net/snmp in each namespace,
#     sampled before and after the traffic window and reported as a
#     before/after delta column (bulk UDP through netns can legitimately
#     drop in any arm — this is diagnostic context for the maintainer's
#     reading of the throughput number, never a pass/fail gate); and the
#     effective SO_RCVBUF per endpoint (`ss -uln -m` in the namespace,
#     max "rb" value seen) — the client requests 7 MiB
#     (src/mqvpn_client.c's SOCKET_BUF_SIZE) and the server 1 MiB
#     (src/platform/linux/platform_linux.c), both unchecked, and Linux
#     clamps to rmem_max unless SO_RCVBUFFORCE succeeds, so the effective
#     value can be far smaller than the source suggests.
#   - Latency under load (arms "default" and "gro_off" ONLY — the kernel
#     only coalesces packets that arrive in the same NAPI poll and
#     gro_flush_timeout is 0 by default, so on an idle tunnel GRO and
#     non-GRO are identical by construction and a low-rate arm would
#     compare nothing; only these two arms isolate the UdpGro toggle under
#     real load): `ping` runs concurrently with the iperf3
#     window and its `rtt min/avg/max/mdev` summary is recorded, compacted
#     into one slash-delimited token (min/avg/max/mdev, no spaces) for the
#     row format — the raw ping output is preserved at
#     ${LOG_DIR}/ping_<tag>.txt for the exact original line. Reported, not
#     gated: whether any latency delta is acceptable is the maintainer's
#     call, not this script's.
#   - N runs per arm (default 3), medians reported (throughput/CPU only —
#     the receive-side/latency numbers are diagnostic and printed per-run,
#     not medianed). Arms ALTERNATE (default, disabled, gro_off, both_off,
#     default, disabled, gro_off, both_off, ...) rather than running all of
#     one arm then all of the next, to spread any monotonic drift (thermal
#     throttling, netns/cert-gen warmup, etc.) evenly across all four arms
#     instead of biasing whichever pair runs last.
#
# Output: a compact per-run table + per-arm medians + a receive-side detail
# table, echoed to stdout AND appended to a file under ci_sweep_results/
# (gitignored, transient — see AGENTS.md: ci_sweep_results/ is transient,
# bench_results/ is the curated archive; this script deliberately does NOT
# write bench_results/).
#
# REQUIRES: root (netns + TUN), iperf3, python3, openssl (cert generation
# via bench_env_setup.sh's bench_start_vpn_server), ping. pidstat (sysstat)
# is OPTIONAL — auto-detected, falls back to /proc if absent.
#
# This is a local maintainer tool, NOT wired into CI (no ci.yml/stress.yml
# reference). It is not a throughput/CPU pass/fail gate — a completed
# comparison always prints its table regardless of the numbers — but it
# DOES exit nonzero (after printing the table) if: a sanitizer error fired
# in any run, EITHER the "udp-gso: " or "udp-gro: " marker didn't match
# the expected present/absent state for its arm in any run (a
# silently-void A/B produced a plausible-looking table once already — see
# MARKER_FAIL below), or every run failed and there is nothing to report.
#
# --- Optional shaped mode (UDP_GSO_BENCH_NETEM=1) ---
# An unshaped netns never blocks a send: cwnd/pacing never bites, so
# write_mmsg_ex is only ever called with vlen==1 and GSO measures as
# neutral (or worse, due to per-call cmsg overhead with nothing to
# amortize it over). Real links block: with RTT + a rate cap, cwnd/pacing
# queues datagrams and ACK-clocked bursts hand write_mmsg_ex real vlen>1
# batches, which is the only regime GSO can show a win in. Setting
# UDP_GSO_BENCH_NETEM=1 applies tc netem (delay NETEM_DELAY, rate
# NETEM_RATE — same profile on both paths, both directions) via
# bench_env_setup.sh's bench_apply_netem, following the same shape/ordering
# precedent as run_throughput_floor_test.sh:187-191 and
# bench_env_setup.sh:254-274's bench_apply_netem itself. A single
# invocation is either fully shaped or fully unshaped — never mixed, so
# the printed table stays a single-condition comparison (the unshaped
# numbers already exist from prior runs). With the link saturated by
# iperf3, CPU is no longer pinned near 100%; the meaningful comparison
# becomes CPU% at equal throughput between arms, not raw throughput.
#
# Usage:
#   sudo bash scripts/ci_e2e/run_udp_gso_bench.sh [path/to/mqvpn] [duration_s] [runs]
# Defaults: path/to/mqvpn = build/mqvpn (repo-relative), duration_s = 10,
#           runs = 3 (per arm; 4*runs total launches, alternating over the
#           four arms).
# Env override: IPERF_STREAMS (default 4) — iperf3 -P parallel stream count.
# Env override: UDP_GSO_BENCH_NETEM (default 0) — set to 1 to shape both
#           paths with tc netem instead of running on the bare netns.
# Env override: NETEM_DELAY (default 20ms), NETEM_RATE (default 300mbit) —
#           only consulted when UDP_GSO_BENCH_NETEM=1.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/sanitizer_check.sh"
source "${SCRIPT_DIR}/../../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}}"
DURATION="${2:-10}"
RUNS="${3:-3}"
IPERF_STREAMS="${IPERF_STREAMS:-4}"
UDP_GSO_BENCH_NETEM="${UDP_GSO_BENCH_NETEM:-0}"
NETEM_DELAY="${NETEM_DELAY:-20ms}"
NETEM_RATE="${NETEM_RATE:-300mbit}"

if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: must run as root (sudo)" >&2
    exit 2
fi

if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -lt 1 ]; then
    echo "ERROR: duration_s must be a positive integer, got '$DURATION'" >&2
    exit 2
fi
if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || [ "$RUNS" -lt 1 ]; then
    echo "ERROR: runs must be a positive integer, got '$RUNS'" >&2
    exit 2
fi
if [[ "$UDP_GSO_BENCH_NETEM" != "0" && "$UDP_GSO_BENCH_NETEM" != "1" ]]; then
    echo "ERROR: UDP_GSO_BENCH_NETEM must be 0 or 1, got '$UDP_GSO_BENCH_NETEM'" >&2
    exit 2
fi

# Same profile on both paths, both directions (see the shaped-mode header
# comment above) — bench_apply_netem takes one "netem args" string per path
# and this script deliberately does not offer per-path asymmetry, unlike
# BENCH_ENV_NETEM's profile table (benchmarks/bench_env_setup.sh) which sweep
# scripts use for asymmetric Path A/B scenarios; that is out of scope here.
NETEM_PROFILE="delay ${NETEM_DELAY} rate ${NETEM_RATE}"

# bench_check_test_deps (benchmarks/bench_env_setup.sh:101-118): verifies
# $MQVPN exists and resolves it to a realpath (mutates the global $MQVPN —
# no separate existence check needed here), and verifies each named dep is
# on PATH.
bench_check_test_deps iperf3 python3 openssl ping

HAVE_PIDSTAT=0
if command -v pidstat >/dev/null 2>&1; then
    HAVE_PIDSTAT=1
fi
CLK_TCK="$(getconf CLK_TCK)"

LOG_DIR="$(mktemp -d)"
RAW_RESULTS="$(mktemp)"
SANITIZER_FAIL=0
# Set to 1 by check_offload_marker() (called from run_one()) when EITHER
# the "udp-gso: " or "udp-gro: " marker doesn't match the arm's expected
# present/absent state. A mismatch means the A/B/C/D comparison ran with
# the wrong code path for that knob in at least one run — the printed
# table would otherwise look like a normal, trustworthy comparison while
# silently comparing apples to apples (or worse). Checked once at exit,
# same shape as SANITIZER_FAIL below.
MARKER_FAIL=0

OUT_DIR="${SCRIPT_DIR}/../../ci_sweep_results"
mkdir -p "$OUT_DIR"
RESULT_FILE="${OUT_DIR}/udp_gso_bench_$(date +%Y%m%d_%H%M%S).txt"
: > "$RESULT_FILE"

# Dual stdout+file echo, with no pipe involved (G19 — a writer|grep -q /
# writer|head pipeline can SIGPIPE-fail the writer under pipefail even on a
# successful match; this sidesteps the whole class by never piping).
log_line() {
    printf '%s\n' "$1"
    printf '%s\n' "$1" >> "$RESULT_FILE"
}

# Named-function trap (same shape as run_udp_gso_config_test.sh): preserve
# logs on failure, reap netns/procs via bench_cleanup, fail the whole run
# if a sanitizer error fired in any arm even though that arm's own
# functional steps (tunnel-up, iperf3) completed.
cleanup() {
    local _rc=$?
    bench_cleanup
    # Preserve logs on ANY failure mode, not just a nonzero $_rc: a run that
    # returns 0 (every arm's own functional check passed) can still have
    # MARKER_FAIL or SANITIZER_FAIL set from a check that only fires after
    # the arm itself reported success — deleting the logs before those
    # checks are even consulted would defeat the "Logs preserved at: ..."
    # message below for exactly the failure modes it exists to cover.
    if (( _rc != 0 || MARKER_FAIL != 0 || SANITIZER_FAIL != 0 )); then
        echo "Logs preserved at: $LOG_DIR" >&2
    else
        rm -rf "$LOG_DIR"
    fi
    rm -f "$RAW_RESULTS"
    if (( MARKER_FAIL != 0 )); then
        echo "FAIL: udp-gso/udp-gro marker mismatch detected in one or more runs (see FAIL lines above)" >&2
        exit 1
    fi
    if (( SANITIZER_FAIL != 0 )); then
        echo "FAIL: sanitizer errors detected" >&2
        exit 1
    fi
}
trap cleanup EXIT
echo "Logs: $LOG_DIR"

# --- G20 header facts: binary identity (path is $MQVPN itself, resolved to
#     a realpath by bench_check_test_deps above; never touched again after
#     this point — every one of the 4*RUNS launches below execs this exact
#     same file) ---
BIN_SHA256="$(sha256sum "$MQVPN" | awk '{print $1}')"
KERNEL="$(uname -r)"
RUN_DATE="$(date -Iseconds)"

# --- Per-arm INIs. All three -C variants mirror
#     run_udp_gso_config_test.sh's Arm B/C fixtures exactly (== the
#     tests/test_config.c test_advanced_udp_gso / test_advanced_udp_gro
#     fixtures). Created once, reused for every run of their arm. ---
DISABLED_INI="${LOG_DIR}/udp_gso_false.ini"
cat >"$DISABLED_INI" <<EOF
[Advanced]
UdpGso = false
EOF

GRO_OFF_INI="${LOG_DIR}/udp_gro_false.ini"
cat >"$GRO_OFF_INI" <<EOF
[Advanced]
UdpGro = false
EOF

# both_off is the true pre-#167 baseline: neither offload wired at all.
BOTH_OFF_INI="${LOG_DIR}/udp_both_off.ini"
cat >"$BOTH_OFF_INI" <<EOF
[Advanced]
UdpGso = false
UdpGro = false
EOF

# --- Arm alternation sequence (drift reduction): default, disabled,
#     gro_off, both_off, default, disabled, gro_off, both_off, ... for
#     RUNS iterations of each — extended from the original two-arm
#     alternation to all four arms, so drift is spread evenly across all
#     of them rather than biasing whichever pair runs last. ---
ARM_SEQUENCE=()
for (( i = 0; i < RUNS; i++ )); do
    ARM_SEQUENCE+=("default" "disabled" "gro_off" "both_off")
done

log_line "================================================================"
log_line " UdpGso / UdpGro A/B/C/D bench (throughput + CPU + receive-side)"
log_line " Binary:   $MQVPN"
log_line " SHA256:   $BIN_SHA256"
log_line " Kernel:   $KERNEL"
log_line " Date:     $RUN_DATE"
log_line " Duration: ${DURATION}s per run, iperf3 TCP -P ${IPERF_STREAMS}, ${RUNS} runs/arm"
log_line " CPU tool: $([ "$HAVE_PIDSTAT" -eq 1 ] && echo "pidstat" || echo "/proc/[pid]/stat fallback (pidstat not found)")"
if [ "$UDP_GSO_BENCH_NETEM" -eq 1 ]; then
    log_line " Netem:    ON  (both paths, both directions: ${NETEM_PROFILE})"
    log_line " NOTE:     shaped mode: compare CPU% at equal tput; expect GSO/GRO arms lower"
else
    log_line " Netem:    OFF (unshaped netns — set UDP_GSO_BENCH_NETEM=1 to shape)"
fi
log_line " Arm order (alternating): ${ARM_SEQUENCE[*]}"
log_line "================================================================"

# --- Client launcher with extra-flags support ---
#
# bench_start_vpn_client (benchmarks/bench_env_setup.sh:312-340) only takes
# a --path list, not arbitrary extra flags, so -C can't go through it. Same
# shape as run_udp_gso_config_test.sh's start_client (scripts/ci_e2e/
# run_udp_gso_config_test.sh's start_client): SAME flag set as
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

# End-of-run teardown: sanitizer-check both endpoints (same idiom as
# run_udp_gso_config_test.sh's finish_arm) and clear the PID vars so the
# next run's bench_cleanup doesn't try to re-kill an already-reaped
# process. A sanitizer failure is recorded in the global SANITIZER_FAIL
# (checked once at final script exit) rather than flipping this run's own
# pass/fail — this is a bench tool, a slow/degraded run still has data
# worth reporting.
finish_run() {
    local desc="$1" server_log="$2" client_log="$3"
    stop_and_check_sanitizer "$_BENCH_CLIENT_PID" "${desc} client" "$client_log" \
        || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$_BENCH_SERVER_PID" "${desc} server" "$server_log" \
        || SANITIZER_FAIL=1
    _BENCH_CLIENT_PID=""
    _BENCH_SERVER_PID=""
}

# --- CPU measurement helpers ---
#
# Verified empirically on the dev box preparing this script (real
# /usr/bin/pidstat from sysstat, not from memory — sysstat's column set
# has changed across versions historically, so this was checked live):
#   - `LC_ALL=C S_TIME_FORMAT=ISO pidstat -p PID 1 N`'s "Average:" line has
#     the shape `Average:  UID  PID  %usr  %system  %guest  %wait  %CPU
#     CPU(-)  Command` — %CPU is field 8 (awk $8). Confirmed against a
#     busy-loop test process (100.00 for a fully CPU-bound single thread).
#   - S_TIME_FORMAT=ISO avoids a real footgun: pidstat's default per-sample
#     timestamp is locale-dependent 12h "HH:MM:SS AM/PM" (adds an extra
#     field vs. 24h), which would shift every awk column index on the
#     *timestamped* lines. This script only ever parses the "Average:"
#     line, which has no timestamp field and is therefore immune to that
#     shift either way — S_TIME_FORMAT=ISO is set anyway so the raw
#     per-sample files left in $LOG_DIR are readable un-ambiguously if a
#     maintainer tails them by hand.
#   - Both pidstat and /proc/[pid]/stat aggregate ALL threads of a PID into
#     one figure, not just the main thread — confirmed with a 2-thread
#     pthread busy-loop process reading ~200.00% from both methods. (A
#     naive assumption that /proc/PID/stat is "just the main thread" would
#     have been wrong and would have undercounted a multi-threaded mqvpn.)
CLIENT_PIDSTAT_PID=""
CLIENT_PIDSTAT_OUT=""
CLIENT_T0=""
CLIENT_TS0=""
SERVER_PIDSTAT_PID=""
SERVER_PIDSTAT_OUT=""
SERVER_T0=""
SERVER_TS0=""

# Cumulative CPU ticks (utime+stime) for a PID, from /proc/[pid]/stat.
# proc(5): comm (field 2) is parenthesized and may itself contain ')', so
# this skips past the LAST ') ' rather than splitting on whitespace
# naively; the remainder's 0-indexed fields are state=0 ppid=1 ... utime=11
# stime=12 (verified against the documented /proc/[pid]/stat field order
# and against a live busy-loop process above).
# Echoes 0 and returns 1 if the pid is gone (process died mid-measurement)
# — callers must check the return status, not just trust a numeric 0.
proc_cpu_ticks() {
    local pid="$1" line rest
    line="$(cat "/proc/${pid}/stat" 2>/dev/null)"
    if [ -z "$line" ]; then
        echo 0
        return 1
    fi
    rest="${line##*) }"
    local -a f
    read -r -a f <<< "$rest"
    echo "$(( ${f[11]:-0} + ${f[12]:-0} ))"
}

cpu_start_client() {
    local pid="$1" tag="$2"
    if [ "$HAVE_PIDSTAT" -eq 1 ]; then
        CLIENT_PIDSTAT_OUT="${LOG_DIR}/pidstat_client_${tag}.out"
        ( LC_ALL=C S_TIME_FORMAT=ISO pidstat -p "$pid" 1 "$DURATION" \
            >"$CLIENT_PIDSTAT_OUT" 2>/dev/null ) &
        CLIENT_PIDSTAT_PID=$!
    else
        CLIENT_T0="$(proc_cpu_ticks "$pid")" || true
        CLIENT_TS0="$(date +%s%N)"
    fi
}

cpu_start_server() {
    local pid="$1" tag="$2"
    if [ "$HAVE_PIDSTAT" -eq 1 ]; then
        SERVER_PIDSTAT_OUT="${LOG_DIR}/pidstat_server_${tag}.out"
        ( LC_ALL=C S_TIME_FORMAT=ISO pidstat -p "$pid" 1 "$DURATION" \
            >"$SERVER_PIDSTAT_OUT" 2>/dev/null ) &
        SERVER_PIDSTAT_PID=$!
    else
        SERVER_T0="$(proc_cpu_ticks "$pid")" || true
        SERVER_TS0="$(date +%s%N)"
    fi
}

# Echoes a %CPU float. On any measurement failure this echoes "0.0" (so the
# printed table still has a well-formed number) but ALSO prints the actual
# observed failure to stderr first (G19: failure paths print actual
# values, not just a silently-plausible number).
cpu_finish_client() {
    local pid="$1"
    if [ "$HAVE_PIDSTAT" -eq 1 ]; then
        wait "$CLIENT_PIDSTAT_PID" 2>/dev/null || true
        local pct
        pct="$(awk '/^Average:/ {print $8}' "$CLIENT_PIDSTAT_OUT" 2>/dev/null)" || true
        if [ -z "$pct" ]; then
            echo "WARN: no pidstat Average line for client pid $pid; raw output:" >&2
            cat "$CLIENT_PIDSTAT_OUT" >&2 2>/dev/null || true
            echo "0.0"
            return
        fi
        echo "$pct"
    else
        local t1 ts1 rc=0
        t1="$(proc_cpu_ticks "$pid")" || rc=$?
        ts1="$(date +%s%N)"
        if [ "$rc" -ne 0 ]; then
            echo "WARN: /proc/${pid}/stat unreadable at measurement end (client pid $pid gone)" >&2
            echo "0.0"
            return
        fi
        python3 -c "
clk = ${CLK_TCK}
dticks = ${t1} - ${CLIENT_T0}
dns = ${ts1} - ${CLIENT_TS0}
pct = (100.0 * dticks / clk / (dns / 1e9)) if dns > 0 else 0.0
print(f'{max(pct, 0.0):.1f}')
"
    fi
}

cpu_finish_server() {
    local pid="$1"
    if [ "$HAVE_PIDSTAT" -eq 1 ]; then
        wait "$SERVER_PIDSTAT_PID" 2>/dev/null || true
        local pct
        pct="$(awk '/^Average:/ {print $8}' "$SERVER_PIDSTAT_OUT" 2>/dev/null)" || true
        if [ -z "$pct" ]; then
            echo "WARN: no pidstat Average line for server pid $pid; raw output:" >&2
            cat "$SERVER_PIDSTAT_OUT" >&2 2>/dev/null || true
            echo "0.0"
            return
        fi
        echo "$pct"
    else
        local t1 ts1 rc=0
        t1="$(proc_cpu_ticks "$pid")" || rc=$?
        ts1="$(date +%s%N)"
        if [ "$rc" -ne 0 ]; then
            echo "WARN: /proc/${pid}/stat unreadable at measurement end (server pid $pid gone)" >&2
            echo "0.0"
            return
        fi
        python3 -c "
clk = ${CLK_TCK}
dticks = ${t1} - ${SERVER_T0}
dns = ${ts1} - ${SERVER_TS0}
pct = (100.0 * dticks / clk / (dns / 1e9)) if dns > 0 else 0.0
print(f'{max(pct, 0.0):.1f}')
"
    fi
}

# --- Offload marker helpers (udp-gso: / udp-gro:) ---
#
# offload_marker_state <marker> <server_log> <client_log>
# Echoes "present" (marker found on both ends), "absent" (found on
# neither), or "MIXED(s=X,c=Y)" (found on only one end — should not
# happen but is reported, not silently coerced). Grep the log FILES
# directly (no writer | grep -q pipeline — G19: a pipefail'd
# writer|grep -q can SIGPIPE-fail the writer even on a successful match).
# Pure computation, no globals touched — safe to call via command
# substitution (unlike check_offload_marker below, which must NOT be
# called that way).
offload_marker_state() {
    local marker="$1" server_log="$2" client_log="$3"
    local server_hits client_hits
    server_hits=$(grep -c "$marker" "$server_log" 2>/dev/null || true)
    client_hits=$(grep -c "$marker" "$client_log" 2>/dev/null || true)
    server_hits="${server_hits:-0}"
    client_hits="${client_hits:-0}"
    if [ "$server_hits" -gt 0 ] && [ "$client_hits" -gt 0 ]; then
        echo "present"
    elif [ "$server_hits" -eq 0 ] && [ "$client_hits" -eq 0 ]; then
        echo "absent"
    else
        echo "MIXED(s=${server_hits},c=${client_hits})"
    fi
    return 0
}

# check_offload_marker <label> <state> <expect_present:0|1> <server_log> <client_log>
# Compares an already-computed marker state (from offload_marker_state)
# against its arm's expectation and sets the script-global MARKER_FAIL on
# mismatch. MUST be called directly, NOT via command substitution — a
# `x=$(check_offload_marker ...)` would run this in a subshell and the
# MARKER_FAIL=1 assignment would be lost when the subshell exits.
# A mismatch means this run's throughput/CPU/latency numbers were
# measured against the WRONG code path for that knob (e.g. the "disabled"
# arm actually ran with GSO registered) — a silently-void A/B produced a
# plausible-looking table once already. This is a hard failure, not a
# WARN: the run's row stays in the table (the state fields still report
# what was actually observed) but the script fails loudly at exit.
check_offload_marker() {
    local label="$1" state="$2" expect_present="$3" server_log="$4" client_log="$5"
    local expect_state="absent"
    if [ "$expect_present" -eq 1 ]; then
        expect_state="present"
    fi
    if [ "$state" != "$expect_state" ]; then
        echo "  FAIL: expected ${label} marker ${expect_state}, got ${state}" >&2
        echo "  --- server log tail ($server_log) ---" >&2
        tail -30 "$server_log" >&2 2>/dev/null
        echo "  --- client log tail ($client_log) ---" >&2
        tail -30 "$client_log" >&2 2>/dev/null
        MARKER_FAIL=1
    fi
    return 0
}

# --- Receive-side diagnostic helpers (Step 5: not a pass/fail gate) ---
#
# snmp_udp_counters <netns>
# Echoes "InErrors RcvbufErrors" (two space-separated integers) from
# /proc/net/snmp's Udp: section inside the given netns. Locates the two
# columns BY NAME from the Udp: header line (not a fixed index), so a
# kernel that reorders or adds Udp: columns doesn't silently misalign
# this. Echoes "0 0" if the netns/file/columns are unavailable —
# diagnostic-only data, never a pass/fail gate (see file header).
snmp_udp_counters() {
    local ns="$1" out
    out="$(ip netns exec "$ns" awk '
        $1 == "Udp:" && !hdr_done { for (i = 2; i <= NF; i++) col[$i] = i; hdr_done = 1; next }
        $1 == "Udp:" { print $col["InErrors"], $col["RcvbufErrors"]; exit }
    ' /proc/net/snmp 2>/dev/null)"
    if [ -z "$out" ]; then
        echo "0 0"
    else
        echo "$out"
    fi
}

# effective_rcvbuf <netns>
# Echoes the effective SO_RCVBUF (bytes, kernel-doubled "rb" value from
# `ss -uln -m`) of mqvpn's UDP socket(s) in the given netns — the max
# across all UDP sockets found, since a client with N paths opens N
# sockets that all request the same size. Diagnostic only: SO_RCVBUF is
# unchecked and Linux clamps to rmem_max unless SO_RCVBUFFORCE succeeds,
# so this can be far smaller than the source constant suggests (see file
# header). Echoes "NA" if no UDP socket / no skmem info is found.
effective_rcvbuf() {
    local ns="$1" max
    max="$(ip netns exec "$ns" ss -uln -m 2>/dev/null | awk '
        match($0, /rb[0-9]+/) {
            v = substr($0, RSTART + 2, RLENGTH - 2) + 0
            if (v > max) max = v
        }
        END { if (max > 0) print max; else print "NA" }
    ')"
    if [ -z "$max" ]; then
        max="NA"
    fi
    echo "$max"
}

# --- One arm/run: netns + server + client + marker checks + iperf3 + CPU
#     + receive-side counters + (default/gro_off only) latency ---
run_one() {
    local arm_label="$1" expect_gso="$2" expect_gro="$3" extra_flags="$4" run_idx="$5"
    local tag="${arm_label}_r${run_idx}"
    local server_log="${LOG_DIR}/${tag}_server.log"
    local client_log="${LOG_DIR}/${tag}_client.log"

    echo ""
    echo "--- ${arm_label} run ${run_idx}/${RUNS} ---"

    bench_cleanup
    bench_setup_netns

    # Shaped mode: apply tc netem to BOTH path veths, both directions (same
    # precedent as bench_apply_netem itself — benchmarks/bench_env_setup.sh:
    # 254-274 — and run_throughput_floor_test.sh:187-191), after
    # bench_setup_netns and before the server starts, so the shaping is in
    # place before any packet (including the handshake) crosses the netns.
    # bench_cleanup (called at the top of every run_one, and by the EXIT
    # trap) already runs `tc qdisc del ... root` for every path slot — see
    # bench_env_setup.sh:404-405 — so no separate per-arm teardown is needed
    # here; the qdisc this call adds is torn down by the very next
    # bench_cleanup, same as bench_setup_netns's veths are.
    if [ "$UDP_GSO_BENCH_NETEM" -eq 1 ]; then
        if ! bench_apply_netem "$NETEM_PROFILE" "$NETEM_PROFILE"; then
            echo "  FAIL: tc netem apply failed" >&2
            return 1
        fi
    fi

    # shellcheck disable=SC2086  # extra_flags is intentionally word-split
    if ! bench_start_vpn_server "$extra_flags" "$server_log"; then
        echo "  FAIL: server did not start; tail of $server_log:" >&2
        tail -30 "$server_log" >&2 2>/dev/null
        return 1
    fi

    if ! start_client "$extra_flags" "$client_log"; then
        return 1
    fi

    if ! bench_wait_tunnel 15; then
        echo "  FAIL: tunnel did not come up" >&2
        return 1
    fi

    # udp-gso: / udp-gro: marker checks. Wording pinned by
    # mqvpn_client.c:2843 / mqvpn_server.c:1880 (udp-gso) and
    # platform_linux.c's mqvpn_udp_gro_enable() call sites (udp-gro), and
    # by run_udp_gso_config_test.sh; keep all in sync if either ever
    # changes. check_offload_marker is called directly (not via `x=$(...)`)
    # so its MARKER_FAIL=1 assignment isn't lost in a subshell.
    local gso_state gro_state
    gso_state="$(offload_marker_state "udp-gso: " "$server_log" "$client_log")"
    gro_state="$(offload_marker_state "udp-gro: " "$server_log" "$client_log")"
    check_offload_marker "udp-gso" "$gso_state" "$expect_gso" "$server_log" "$client_log"
    check_offload_marker "udp-gro" "$gro_state" "$expect_gro" "$server_log" "$client_log"

    # Receive-side diagnostics captured while both endpoints' sockets are
    # still live (before finish_run below tears them down): effective
    # SO_RCVBUF, per-interface gro_flush_timeout, and a "before" SNMP
    # sample bracketing the traffic window that follows. None of this
    # gates the run (see file header) — it is reported alongside the
    # throughput/CPU numbers for the maintainer's own reading.
    local c_rcvbuf s_rcvbuf gro_flush_c gro_flush_s
    c_rcvbuf="$(effective_rcvbuf "$NS_CLIENT")"
    s_rcvbuf="$(effective_rcvbuf "$NS_SERVER")"
    gro_flush_c="$(ip netns exec "$NS_CLIENT" cat "/sys/class/net/${VETH_A0}/gro_flush_timeout" 2>/dev/null || true)"
    gro_flush_s="$(ip netns exec "$NS_SERVER" cat "/sys/class/net/${VETH_A1}/gro_flush_timeout" 2>/dev/null || true)"
    [ -z "$gro_flush_c" ] && gro_flush_c="NA"
    [ -z "$gro_flush_s" ] && gro_flush_s="NA"

    local c_inerr0 c_rberr0 s_inerr0 s_rberr0
    read -r c_inerr0 c_rberr0 <<< "$(snmp_udp_counters "$NS_CLIENT")"
    read -r s_inerr0 s_rberr0 <<< "$(snmp_udp_counters "$NS_SERVER")"

    # iperf3 TCP upload (client -> server, no -R): same idiom as
    # bench_aggregate.sh:68-76 / run_throughput_floor_test.sh's
    # run_iperf3_mbps, minus -R (see header comment for why upload, not
    # download, is the deliberate direction here).
    ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" -1 &>/dev/null &
    local iperf_srv_pid=$!
    sleep 1

    cpu_start_client "$_BENCH_CLIENT_PID" "$tag"
    cpu_start_server "$_BENCH_SERVER_PID" "$tag"

    # Latency under load — arms "default" and "gro_off" ONLY: these are
    # the two arms that isolate the UdpGro toggle (the other two arms
    # differ only in UdpGso, which does not affect delivery ordering/
    # timing on the receive side). See file header for why an idle-link
    # low-rate arm would measure nothing. ping_out's filename is unique
    # PER RUN (via $tag = "${arm_label}_r${run_idx}"), not per arm — RUNS
    # repeats of the same arm must not overwrite each other's output.
    local ping_out="" PING_PID=""
    if [ "$arm_label" = "default" ] || [ "$arm_label" = "gro_off" ]; then
        ping_out="${LOG_DIR}/ping_${tag}.txt"
        ip netns exec "$NS_CLIENT" ping -c "$((DURATION * 10))" -i 0.1 -W 1 \
            "$TUNNEL_SERVER_IP" >"$ping_out" 2>&1 &
        PING_PID=$!
    fi

    local iperf_json
    iperf_json="$(mktemp)"
    ip netns exec "$NS_CLIENT" iperf3 \
        -c "$TUNNEL_SERVER_IP" -t "$DURATION" -P "$IPERF_STREAMS" --json \
        >"$iperf_json" 2>/dev/null || true

    # Kill before wait: `iperf3 -s -1` exits only after it has served a
    # client, so if the tunnel died between bench_wait_tunnel and the client
    # above, the client fails (swallowed by `|| true`) and the one-shot
    # server would keep listening forever — wait would then hang with no
    # global timeout to rescue it. In the success path the server has
    # already exited and the kill is a no-op.
    kill "$iperf_srv_pid" 2>/dev/null || true
    wait "$iperf_srv_pid" 2>/dev/null || true

    # Reap the background ping BEFORE the result row is written: ping
    # emits its rtt summary only at exit, so parsing earlier is a race
    # that silently yields no line — and an unreaped ping outlives netns
    # teardown. Its own exit status is not the run's verdict.
    if [ -n "$PING_PID" ]; then
        wait "$PING_PID" 2>/dev/null || true
    fi

    local client_cpu server_cpu
    client_cpu="$(cpu_finish_client "$_BENCH_CLIENT_PID")"
    server_cpu="$(cpu_finish_server "$_BENCH_SERVER_PID")"

    local mbps
    mbps="$(python3 -c "
import json
try:
    with open('${iperf_json}') as f:
        data = json.load(f)
    end = data.get('end', {})
    if 'sum_received' in end:
        print(f\"{end['sum_received']['bits_per_second'] / 1e6:.1f}\")
    elif 'sum' in end:
        print(f\"{end['sum']['bits_per_second'] / 1e6:.1f}\")
    else:
        print('0.0')
except Exception:
    print('0.0')
")"
    rm -f "$iperf_json"

    # "After" SNMP sample + deltas. These counters are netns/kernel-level
    # cumulative totals unaffected by killing the mqvpn process below, so
    # sampling here (bracketing the actual traffic window) rather than
    # after finish_run gives the same, more precisely-scoped numbers.
    local c_inerr1 c_rberr1 s_inerr1 s_rberr1
    read -r c_inerr1 c_rberr1 <<< "$(snmp_udp_counters "$NS_CLIENT")"
    read -r s_inerr1 s_rberr1 <<< "$(snmp_udp_counters "$NS_SERVER")"
    local c_inerr_d=$(( c_inerr1 - c_inerr0 ))
    local c_rberr_d=$(( c_rberr1 - c_rberr0 ))
    local s_inerr_d=$(( s_inerr1 - s_inerr0 ))
    local s_rberr_d=$(( s_rberr1 - s_rberr0 ))

    # ping's own "rtt min/avg/max/mdev = a/b/c/d ms" summary line is only
    # written at exit (already reaped above). Field 4 of that line is
    # "a/b/c/d" with no embedded whitespace, so it fits the RAW_RESULTS
    # row as one token; the full original line (and every individual
    # sample) stays in $ping_out for anyone who wants it verbatim.
    local rtt="NA"
    if [ -n "$ping_out" ] && [ -f "$ping_out" ]; then
        rtt="$(awk '/^rtt/ {print $4}' "$ping_out" 2>/dev/null)"
        [ -z "$rtt" ] && rtt="NA"
    fi

    echo "  tput=${mbps}Mbps  client_cpu=${client_cpu}%  server_cpu=${server_cpu}%" \
         "  gso=${gso_state}  gro=${gro_state}  rtt=${rtt}"
    echo "  rcvbuf: client=${c_rcvbuf}B server=${s_rcvbuf}B" \
         "  gro_flush_timeout: client=${gro_flush_c} server=${gro_flush_s}" \
         "  snmp_delta(InErrors/RcvbufErrors): client=${c_inerr_d}/${c_rberr_d}" \
         "server=${s_inerr_d}/${s_rberr_d}"

    # Reap both endpoints BEFORE reading the udp-rx teardown telemetry
    # line: it is emitted from the `cleanup:` label in main(), i.e. only
    # after the process has fully exited — reading the log files any
    # earlier would race a line that does not exist yet.
    finish_run "$tag" "$server_log" "$client_log"

    # udp-rx: receives=N datagrams=M gro_config=X — emitted unconditionally
    # at teardown by BOTH endpoints (see platform_linux.c's two `cleanup:`
    # labels), including when UdpGro is off (gro_config=0). A missing line
    # means this arm failed before carrying traffic, not a parse error —
    # the two early startup-failure `return 1` paths above already cover
    # that case for the run's own pass/fail, so here it just becomes "NA"
    # data in an otherwise-successful-looking row.
    local c_rx c_receives c_datagrams c_gro_cfg
    local s_rx s_receives s_datagrams s_gro_cfg
    c_rx="$(grep "udp-rx: " "$client_log" 2>/dev/null | tail -1 || true)"
    s_rx="$(grep "udp-rx: " "$server_log" 2>/dev/null | tail -1 || true)"
    if [ -n "$c_rx" ]; then
        c_receives="$(echo "$c_rx" | sed -n 's/.*receives=\([0-9]*\).*/\1/p')"
        c_datagrams="$(echo "$c_rx" | sed -n 's/.*datagrams=\([0-9]*\).*/\1/p')"
        c_gro_cfg="$(echo "$c_rx" | sed -n 's/.*gro_config=\([0-9]*\).*/\1/p')"
    else
        c_receives="NA"; c_datagrams="NA"; c_gro_cfg="NA"
    fi
    if [ -n "$s_rx" ]; then
        s_receives="$(echo "$s_rx" | sed -n 's/.*receives=\([0-9]*\).*/\1/p')"
        s_datagrams="$(echo "$s_rx" | sed -n 's/.*datagrams=\([0-9]*\).*/\1/p')"
        s_gro_cfg="$(echo "$s_rx" | sed -n 's/.*gro_config=\([0-9]*\).*/\1/p')"
    else
        s_receives="NA"; s_datagrams="NA"; s_gro_cfg="NA"
    fi
    [ -z "$c_receives" ] && c_receives="NA"
    [ -z "$c_datagrams" ] && c_datagrams="NA"
    [ -z "$c_gro_cfg" ] && c_gro_cfg="NA"
    [ -z "$s_receives" ] && s_receives="NA"
    [ -z "$s_datagrams" ] && s_datagrams="NA"
    [ -z "$s_gro_cfg" ] && s_gro_cfg="NA"
    echo "  udp-rx: client receives=${c_receives} datagrams=${c_datagrams} gro_config=${c_gro_cfg}" \
         " server receives=${s_receives} datagrams=${s_datagrams} gro_config=${s_gro_cfg}"

    # udp-tx: sends=N datagrams=M gso_config=X — the transmit-side
    # counterpart, emitted unconditionally at teardown by BOTH endpoints
    # (mqvpn_client_destroy / mqvpn_server_destroy), including when UdpGso is
    # off (gso_config=0). datagrams/sends is the achieved batching factor:
    # 1.0 means every datagram cost its own syscall, a state the startup
    # "udp-gso: " marker cannot distinguish from a fully batched run because
    # it only reports the kernel capability probe. Same NA convention as the
    # udp-rx block above.
    local c_tx c_sends c_tx_dgrams c_gso_cfg
    local s_tx s_sends s_tx_dgrams s_gso_cfg
    c_tx="$(grep "udp-tx: " "$client_log" 2>/dev/null | tail -1 || true)"
    s_tx="$(grep "udp-tx: " "$server_log" 2>/dev/null | tail -1 || true)"
    if [ -n "$c_tx" ]; then
        c_sends="$(echo "$c_tx" | sed -n 's/.*sends=\([0-9]*\).*/\1/p')"
        c_tx_dgrams="$(echo "$c_tx" | sed -n 's/.*datagrams=\([0-9]*\).*/\1/p')"
        c_gso_cfg="$(echo "$c_tx" | sed -n 's/.*gso_config=\([0-9]*\).*/\1/p')"
    else
        c_sends="NA"; c_tx_dgrams="NA"; c_gso_cfg="NA"
    fi
    if [ -n "$s_tx" ]; then
        s_sends="$(echo "$s_tx" | sed -n 's/.*sends=\([0-9]*\).*/\1/p')"
        s_tx_dgrams="$(echo "$s_tx" | sed -n 's/.*datagrams=\([0-9]*\).*/\1/p')"
        s_gso_cfg="$(echo "$s_tx" | sed -n 's/.*gso_config=\([0-9]*\).*/\1/p')"
    else
        s_sends="NA"; s_tx_dgrams="NA"; s_gso_cfg="NA"
    fi
    [ -z "$c_sends" ] && c_sends="NA"
    [ -z "$c_tx_dgrams" ] && c_tx_dgrams="NA"
    [ -z "$c_gso_cfg" ] && c_gso_cfg="NA"
    [ -z "$s_sends" ] && s_sends="NA"
    [ -z "$s_tx_dgrams" ] && s_tx_dgrams="NA"
    [ -z "$s_gso_cfg" ] && s_gso_cfg="NA"
    echo "  udp-tx: client sends=${c_sends} datagrams=${c_tx_dgrams} gso_config=${c_gso_cfg}" \
         " server sends=${s_sends} datagrams=${s_tx_dgrams} gso_config=${s_gso_cfg}"

    # RAW_RESULTS row — every field is guaranteed whitespace-free (see
    # comments above) so the fixed-column-count parse in the Python table
    # generator below stays valid. Field order MUST match FIELD_NAMES in
    # the PYEOF block later in this script.
    printf '%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n' \
        "$arm_label" "$run_idx" "$mbps" "$client_cpu" "$server_cpu" \
        "$gso_state" "$gro_state" \
        "$c_receives" "$c_datagrams" "$c_gro_cfg" \
        "$s_receives" "$s_datagrams" "$s_gro_cfg" \
        "$c_sends" "$c_tx_dgrams" "$c_gso_cfg" \
        "$s_sends" "$s_tx_dgrams" "$s_gso_cfg" \
        "$c_inerr_d" "$c_rberr_d" "$s_inerr_d" "$s_rberr_d" \
        "$c_rcvbuf" "$s_rcvbuf" "$gro_flush_c" "$gro_flush_s" "$rtt" \
        >> "$RAW_RESULTS"

    return 0
}

# --- Main loop: alternate arms, RUNS launches per arm ---
#
# Four arms, not two: a two-way if/else here would silently only ever
# launch the two arms it happens to know about even if ARM_SEQUENCE above
# already lists four names — see the trailing *) branch, which turns an
# unrecognized arm into a hard error instead of a silent fall-through.
declare -A ARM_RUN_COUNT=( [default]=0 [disabled]=0 [gro_off]=0 [both_off]=0 )
for arm in "${ARM_SEQUENCE[@]}"; do
    ARM_RUN_COUNT[$arm]=$(( ARM_RUN_COUNT[$arm] + 1 ))
    run_idx="${ARM_RUN_COUNT[$arm]}"

    case "$arm" in
        default)
            expect_gso=1
            expect_gro=1
            extra_flags=""
            ;;
        disabled)
            expect_gso=0
            expect_gro=1
            extra_flags="-C $DISABLED_INI"
            ;;
        gro_off)
            expect_gso=1
            expect_gro=0
            extra_flags="-C $GRO_OFF_INI"
            ;;
        both_off)
            expect_gso=0
            expect_gro=0
            extra_flags="-C $BOTH_OFF_INI"
            ;;
        *)
            echo "ERROR: unknown arm '$arm' in ARM_SEQUENCE" >&2
            exit 2
            ;;
    esac

    if ! run_one "$arm" "$expect_gso" "$expect_gro" "$extra_flags" "$run_idx"; then
        echo "  WARN: run ${arm} #${run_idx} did not complete cleanly (see $LOG_DIR)" >&2
        # run_one returns early on setup failure, i.e. WITHOUT reaching its
        # finish_run — and finish_run is what sanitizer-checks both endpoints.
        # Without this, a run that died *because* of a sanitizer error would
        # be reported as a mere WARN and the script could still exit 0, which
        # contradicts the header's promise to fail on any sanitizer error.
        # stop_and_check_sanitizer returns 0 for an empty PID, so calling this
        # when an endpoint never started is a no-op.
        finish_run "${arm} #${run_idx} (failed run)" \
            "${LOG_DIR}/${arm}_r${run_idx}_server.log" \
            "${LOG_DIR}/${arm}_r${run_idx}_client.log"
    fi
    sleep 2
done

if [ ! -s "$RAW_RESULTS" ]; then
    echo "ERROR: no successful runs — nothing to report" >&2
    exit 1
fi

# --- Compact table + medians, echoed AND appended to $RESULT_FILE ---
python3 - "$RAW_RESULTS" "$RESULT_FILE" "$MQVPN" "$BIN_SHA256" "$KERNEL" "$RUN_DATE" \
    "$IPERF_STREAMS" "$DURATION" "$UDP_GSO_BENCH_NETEM" "$NETEM_DELAY" "$NETEM_RATE" \
    "${ARM_SEQUENCE[@]}" <<'PYEOF'
import sys
import statistics

argv = sys.argv[1:]
(raw_file, result_file, mqvpn, sha, kernel, run_date, streams, duration,
 netem_on, netem_delay, netem_rate) = argv[:11]
arm_seq = argv[11:]

# Field order MUST match the printf in run_one() (scripts/ci_e2e/
# run_udp_gso_bench.sh's RAW_RESULTS row) exactly — this list is the
# single source of truth for both sides, named rather than positional so
# an insert/reorder on one side is a visible mismatch, not a silent
# column transposition.
FIELD_NAMES = [
    "arm", "run", "mbps", "ccpu", "scpu",
    "gso", "gro",
    "c_receives", "c_datagrams", "c_gro_cfg",
    "s_receives", "s_datagrams", "s_gro_cfg",
    "c_sends", "c_tx_dgrams", "c_gso_cfg",
    "s_sends", "s_tx_dgrams", "s_gso_cfg",
    "c_inerr_d", "c_rberr_d", "s_inerr_d", "s_rberr_d",
    "c_rcvbuf", "s_rcvbuf",
    "gro_flush_c", "gro_flush_s",
    "rtt",
]

# Four arms — must stay in sync with ARM_SEQUENCE and the bash `case`
# above (same silent-drop hazard, restated there).
ARM_ORDER = ("default", "disabled", "gro_off", "both_off")


def _int_or_na(x):
    """Receive- and transmit-side counters are either an integer or the
    literal "NA" (arm failed before carrying traffic, or the sysfs/proc
    source was unavailable — see run_one()'s comments). Pass non-numeric
    values through unchanged rather than raising."""
    try:
        return int(x)
    except ValueError:
        return x


def _ratio(dgrams, sends):
    """Batching factor datagrams/sends as a short string, or "NA" when
    either operand is non-numeric ("NA" from a failed arm) or no send was
    ever made — which would otherwise divide by zero on an arm that died
    before carrying traffic."""
    if not isinstance(dgrams, int) or not isinstance(sends, int) or sends == 0:
        return "NA"
    return f"{dgrams / sends:.2f}"


rows = []
with open(raw_file) as f:
    for line in f:
        parts = line.split()
        if len(parts) != len(FIELD_NAMES):
            # Never drop a row silently: a short row means a helper emitted an
            # empty field, and the only symptom downstream would be a smaller
            # (n=...) in the medians.
            print("WARN: skipping malformed result row (%d fields, expected %d): %s"
                  % (len(parts), len(FIELD_NAMES), line.rstrip()), file=sys.stderr)
            continue
        r = dict(zip(FIELD_NAMES, parts))
        r["run"] = int(r["run"])
        r["mbps"] = float(r["mbps"])
        r["ccpu"] = float(r["ccpu"])
        r["scpu"] = float(r["scpu"])
        for k in ("c_receives", "c_datagrams", "c_gro_cfg",
                  "s_receives", "s_datagrams", "s_gro_cfg",
                  "c_sends", "c_tx_dgrams", "c_gso_cfg",
                  "s_sends", "s_tx_dgrams", "s_gso_cfg",
                  "c_inerr_d", "c_rberr_d", "s_inerr_d", "s_rberr_d",
                  "c_rcvbuf", "s_rcvbuf", "gro_flush_c", "gro_flush_s"):
            r[k] = _int_or_na(r[k])
        rows.append(r)

lines = []
lines.append("=" * 72)
lines.append("UdpGso / UdpGro A/B/C/D bench result")
lines.append(f"Binary:   {mqvpn}")
lines.append(f"SHA256:   {sha}")
lines.append(f"Kernel:   {kernel}")
lines.append(f"Date:     {run_date}")
lines.append(f"Duration: {duration}s per run, iperf3 TCP -P {streams}")
if netem_on == "1":
    lines.append(f"Netem:    ON  (both paths, both directions: delay {netem_delay} rate {netem_rate})")
    lines.append("NOTE:     shaped mode: compare CPU% at equal tput; expect GSO/GRO arms lower")
else:
    lines.append("Netem:    OFF (unshaped netns)")
lines.append(f"Arm order (alternating): {' '.join(arm_seq)}")
lines.append("=" * 72)
lines.append("")
lines.append(
    f"{'arm':<10}{'run':<5}{'tput(Mbps)':<12}{'client%':<10}{'server%':<10}"
    f"{'gso':<10}{'gro':<10}{'rtt(ms)':<20}"
)
for r in rows:
    lines.append(
        f"{r['arm']:<10}{r['run']:<5}{r['mbps']:<12.1f}"
        f"{r['ccpu']:<10.1f}{r['scpu']:<10.1f}"
        f"{r['gso']:<10}{r['gro']:<10}{r['rtt']:<20}"
    )

lines.append("")
lines.append("Medians (throughput/CPU only — receive-side counters and rtt are")
lines.append("per-run diagnostics, not medianed; see the detail table below):")
for arm in ARM_ORDER:
    vals = [r for r in rows if r["arm"] == arm]
    if not vals:
        lines.append(f"  {arm}: no data (all runs failed — see log dir)")
        continue
    med_mbps = statistics.median(v["mbps"] for v in vals)
    med_ccpu = statistics.median(v["ccpu"] for v in vals)
    med_scpu = statistics.median(v["scpu"] for v in vals)
    lines.append(
        f"  {arm:<10} tput={med_mbps:.1f}Mbps  "
        f"client_cpu={med_ccpu:.1f}%  server_cpu={med_scpu:.1f}%  (n={len(vals)})"
    )

lines.append("")
lines.append("Receive-side detail (diagnostic only — never a pass/fail gate; a")
lines.append('missing udp-rx counter ("NA") means the arm failed before carrying')
lines.append("traffic. datagrams > receives is the direct evidence the kernel")
lines.append("actually coalesced. *_inErrD/*_rbErrD are before/after deltas of")
lines.append("/proc/net/snmp's Udp: InErrors/RcvbufErrors, bulk UDP through netns")
lines.append("can legitimately drop in any arm. *_rcvbuf is the effective")
lines.append("SO_RCVBUF in bytes, possibly clamped well below the requested size.")
lines.append("*_flush is /sys/class/net/<path-A-veth>/gro_flush_timeout, sampled")
lines.append("once per run.)")
lines.append(
    f"{'arm':<10}{'run':<5}"
    f"{'c_recv':<9}{'c_dgram':<9}{'c_groC':<8}"
    f"{'s_recv':<9}{'s_dgram':<9}{'s_groC':<8}"
    f"{'c_inErrD':<10}{'c_rbErrD':<10}{'s_inErrD':<10}{'s_rbErrD':<10}"
    f"{'c_rcvbuf':<10}{'s_rcvbuf':<10}{'c_flush':<9}{'s_flush':<9}"
)
for r in rows:
    lines.append(
        f"{r['arm']:<10}{r['run']:<5}"
        f"{r['c_receives']!s:<9}{r['c_datagrams']!s:<9}{r['c_gro_cfg']!s:<8}"
        f"{r['s_receives']!s:<9}{r['s_datagrams']!s:<9}{r['s_gro_cfg']!s:<8}"
        f"{r['c_inerr_d']!s:<10}{r['c_rberr_d']!s:<10}{r['s_inerr_d']!s:<10}{r['s_rberr_d']!s:<10}"
        f"{r['c_rcvbuf']!s:<10}{r['s_rcvbuf']!s:<10}{r['gro_flush_c']!s:<9}{r['gro_flush_s']!s:<9}"
    )

lines.append("")
lines.append("Transmit-side detail (diagnostic only — never a pass/fail gate; a")
lines.append('missing udp-tx counter ("NA") means the arm failed before carrying')
lines.append("traffic. ratio = datagrams/sends is the achieved batching factor:")
lines.append("1.00 means every datagram cost its own send syscall, the state the")
lines.append('startup "udp-gso: GSO enabled" marker cannot distinguish from a')
lines.append("fully batched run because it only reports the kernel capability")
lines.append("probe. *_gsoC is the UdpGso value the endpoint actually ran with.)")
lines.append(
    f"{'arm':<10}{'run':<5}"
    f"{'c_sends':<10}{'c_dgram':<10}{'c_ratio':<9}{'c_gsoC':<8}"
    f"{'s_sends':<10}{'s_dgram':<10}{'s_ratio':<9}{'s_gsoC':<8}"
)
for r in rows:
    lines.append(
        f"{r['arm']:<10}{r['run']:<5}"
        f"{r['c_sends']!s:<10}{r['c_tx_dgrams']!s:<10}"
        f"{_ratio(r['c_tx_dgrams'], r['c_sends']):<9}{r['c_gso_cfg']!s:<8}"
        f"{r['s_sends']!s:<10}{r['s_tx_dgrams']!s:<10}"
        f"{_ratio(r['s_tx_dgrams'], r['s_sends']):<9}{r['s_gso_cfg']!s:<8}"
    )

text = "\n".join(lines)
print(text)
with open(result_file, "a") as f:
    f.write(text + "\n")
PYEOF

echo ""
echo "Result file: $RESULT_FILE"
exit 0
