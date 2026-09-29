#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# ci_stress_env.sh — Shared CI stress test environment setup
#
# Source this file from CI stress test scripts:
#   source "$(dirname "$0")/ci_stress_env.sh"
#
# Provides:
#   - Namespace/veth setup (same topology as ci_bench but different names)
#   - VPN server/client lifecycle
#   - RSS/fd monitoring (background loop)
#   - Resource leak detection
#   - Result helpers

set -euo pipefail

CI_STRESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MQVPN="${MQVPN:-${CI_STRESS_DIR}/../../build/mqvpn}"
CI_STRESS_RESULTS="${CI_STRESS_RESULTS:-${CI_STRESS_DIR}/../../ci_stress_results}"

# Git commit SHA for JSON output
CI_STRESS_COMMIT="${CI_STRESS_COMMIT:-$(git -C "$CI_STRESS_DIR" rev-parse HEAD 2>/dev/null || echo unknown)}"

# Namespace and veth names (different from ci-bench to avoid conflicts)
NS_SERVER="ci-stress-server"
NS_CLIENT="ci-stress-client"
VETH_A0="ci-s-a0"
VETH_A1="ci-s-a1"
VETH_B0="ci-s-b0"
VETH_B1="ci-s-b1"

# IP addressing
IP_A_CLIENT="10.100.0.2/24"
IP_A_SERVER="10.100.0.1/24"
IP_B_CLIENT="10.200.0.2/24"
IP_B_SERVER="10.200.0.1/24"
IP_A_SERVER_ADDR="10.100.0.1"
IP_A_SUBNET="10.100.0.0/24"
IP_B_SERVER_ADDR="10.200.0.1"
TUNNEL_SERVER_IP="10.0.0.1"
VPN_LISTEN_PORT="4433"
CI_STRESS_LOG_LEVEL="${CI_STRESS_LOG_LEVEL:-warn}"

# Optional log capture. When a caller sets these before ci_stress_start_server
# / ci_stress_start_client, that VPN process's stdout+stderr goes to the named
# file instead of being inherited. Only scripts that assert on log content opt
# in (ci_stress_failover.sh); the others keep today's inline console output.
CI_STRESS_SERVER_LOG="${CI_STRESS_SERVER_LOG:-}"
CI_STRESS_CLIENT_LOG="${CI_STRESS_CLIENT_LOG:-}"

# Default netem
NETEM_A="${NETEM_A:-delay 10ms rate 300mbit}"
NETEM_B="${NETEM_B:-delay 30ms rate 80mbit}"

# Process PIDs
_CS_SERVER_PID=""
_CS_CLIENT_PID=""
_CS_WORK_DIR=""
_CS_PSK=""
_CS_MONITOR_PIDS=()

# ── Dependency checks ──

ci_stress_check_deps() {
    if [ ! -f "$MQVPN" ]; then
        echo "error: mqvpn binary not found at $MQVPN"
        exit 1
    fi
    MQVPN="$(realpath "$MQVPN")"

    for cmd in iperf3 openssl python3 tc; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "error: $cmd not found"
            exit 1
        fi
    done

    mkdir -p "$CI_STRESS_RESULTS"
}

# ── Stale state cleanup ──

ci_stress_cleanup_stale() {
    pkill -f "mqvpn.*ci-stress" 2>/dev/null || true
    ip netns exec "$NS_SERVER" pkill -f "iperf3" 2>/dev/null || true
    ip netns exec "$NS_CLIENT" pkill -f "iperf3" 2>/dev/null || true
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true
}

# ── Path B route to the server ──

# The server (IP_A_SERVER_ADDR) lives on Path A's subnet, so Path B reaches it
# only through this via-route. Without it a SO_BINDTODEVICE socket on B still
# sends (the kernel assumes the destination is on-link and the veth peer
# answers the ARP), but the client's path re-add gate
# (src/platform/linux/route_check.c, RTM_F_FIB_MATCH) sees no FIB route and
# defers the re-add forever — B never comes back after its first fault.
# Same route as the ci_e2e dual-path suites. Any script that faults Path B
# must call this again on recovery.
#
# `replace`, not `add`: whether the route survived the fault depends on how
# the path was broken. An admin down flushes every route through the link,
# but a carrier loss (peer down) keeps them and only flags them linkdown --
# so `add` would succeed in one case and fail with EEXIST in the other.
# `replace` states the intent ("this route must exist now") for both, which
# is what lets callers drop the `|| true` that would otherwise hide a real
# failure such as a missing namespace.
ci_stress_add_path_b_route() {
    ip netns exec "$NS_CLIENT" ip route replace "$IP_A_SUBNET" via "$IP_B_SERVER_ADDR" \
        dev "$VETH_B0" metric 200
}

# ── Network namespace setup ──

ci_stress_setup_netns() {
    echo "Setting up network namespaces..."

    ci_stress_cleanup_stale

    ip netns add "$NS_SERVER"
    ip netns add "$NS_CLIENT"

    # Path A: 10.100.0.0/24
    ip link add "$VETH_A0" type veth peer name "$VETH_A1"
    ip link set "$VETH_A0" netns "$NS_CLIENT"
    ip link set "$VETH_A1" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0"
    ip netns exec "$NS_SERVER" ip addr add "$IP_A_SERVER" dev "$VETH_A1"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
    ip netns exec "$NS_SERVER" ip link set "$VETH_A1" up

    # Path B: 10.200.0.0/24
    ip link add "$VETH_B0" type veth peer name "$VETH_B1"
    ip link set "$VETH_B0" netns "$NS_CLIENT"
    ip link set "$VETH_B1" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$IP_B_CLIENT" dev "$VETH_B0"
    ip netns exec "$NS_SERVER" ip addr add "$IP_B_SERVER" dev "$VETH_B1"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" up
    ip netns exec "$NS_SERVER" ip link set "$VETH_B1" up

    # Loopback
    ip netns exec "$NS_CLIENT" ip link set lo up
    ip netns exec "$NS_SERVER" ip link set lo up

    # IP forwarding
    ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null

    ci_stress_add_path_b_route

    # Verify
    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$IP_A_SERVER_ADDR" >/dev/null
    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$IP_B_SERVER_ADDR" >/dev/null
    # The exact FIB query the re-add gate performs. A ping via B cannot tell
    # the difference (the on-link fallback also answers), this can: it fails
    # with "No route" when only the fallback would carry Path B.
    ip netns exec "$NS_CLIENT" ip route get "$IP_A_SERVER_ADDR" oif "$VETH_B0" fibmatch >/dev/null

    echo "OK: netns created"
}

# ── tc netem ──

ci_stress_apply_netem() {
    local netem_a="${1:-$NETEM_A}"
    local netem_b="${2:-$NETEM_B}"

    # Clear existing
    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_A0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_A1" root 2>/dev/null || true
    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_B0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_B1" root 2>/dev/null || true

    # Apply on both ends (RTT = 2 x delay)
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_A0" root netem ${netem_a}
    ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_A1" root netem ${netem_a}
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_B0" root netem ${netem_b}
    ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_B1" root netem ${netem_b}

    echo "OK: netem applied (A: ${netem_a}, B: ${netem_b})"
}

# ── VPN server ──

ci_stress_start_server() {
    local scheduler="${1:-wlb}"
    _CS_WORK_DIR="$(mktemp -d)"

    _CS_PSK=$("$MQVPN" --genkey 2>/dev/null)

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${_CS_WORK_DIR}/server.key" -out "${_CS_WORK_DIR}/server.crt" \
        -days 365 -nodes -subj "/CN=ci-stress" 2>/dev/null

    if [ -n "$CI_STRESS_SERVER_LOG" ]; then exec 3>>"$CI_STRESS_SERVER_LOG"; else exec 3>&1; fi
    ip netns exec "$NS_SERVER" "$MQVPN" \
        --mode server \
        --listen "0.0.0.0:${VPN_LISTEN_PORT}" \
        --subnet 10.0.0.0/24 \
        --cert "${_CS_WORK_DIR}/server.crt" \
        --key "${_CS_WORK_DIR}/server.key" \
        --auth-key "$_CS_PSK" \
        --scheduler "$scheduler" \
        --log-level "$CI_STRESS_LOG_LEVEL" >&3 2>&1 &
    _CS_SERVER_PID=$!
    exec 3>&-
    sleep 2

    if ! kill -0 "$_CS_SERVER_PID" 2>/dev/null; then
        echo "ERROR: VPN server died"
        return 1
    fi
    echo "VPN server running (PID $_CS_SERVER_PID, scheduler=$scheduler)"
}

# ── VPN client ──

ci_stress_start_client() {
    local paths="$1"
    local scheduler="${2:-wlb}"
    local server_addr="${3:-$IP_A_SERVER_ADDR}"

    # Kill previous client (capture exit code for sanitizer check)
    if [ -n "$_CS_CLIENT_PID" ] && kill -0 "$_CS_CLIENT_PID" 2>/dev/null; then
        kill "$_CS_CLIENT_PID" 2>/dev/null || true
        local _exit=0
        wait "$_CS_CLIENT_PID" 2>/dev/null || _exit=$?
        if [ "$_exit" -ne 0 ] && [ "$_exit" -ne 143 ]; then
            _CS_CLIENT_SANITIZER_FAIL=1
            echo "WARN: previous VPN client (PID $_CS_CLIENT_PID) exited with code $_exit"
        fi
        _CS_CLIENT_PID=""
        sleep 1
    fi

    if [ -n "$CI_STRESS_CLIENT_LOG" ]; then exec 3>>"$CI_STRESS_CLIENT_LOG"; else exec 3>&1; fi
    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server "${server_addr}:${VPN_LISTEN_PORT}" \
        ${paths} \
        --auth-key "$_CS_PSK" \
        --scheduler "$scheduler" \
        --insecure \
        --log-level "$CI_STRESS_LOG_LEVEL" >&3 2>&1 &
    _CS_CLIENT_PID=$!
    exec 3>&-
    sleep 3

    if ! kill -0 "$_CS_CLIENT_PID" 2>/dev/null; then
        echo "ERROR: VPN client died"
        return 1
    fi
    echo "VPN client running (PID $_CS_CLIENT_PID)"
}

# ── Tunnel wait ──

ci_stress_wait_tunnel() {
    local timeout="${1:-15}"
    local elapsed=0

    while [ "$elapsed" -lt "$timeout" ]; do
        if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
            echo "OK: tunnel up (${elapsed}s)"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "ERROR: tunnel not reachable after ${timeout}s"
    return 1
}

# ── Stop VPN ──

# Sanitizer failure flags (set to 1 if any VPN process exits with ASan/UBSan error)
_CS_CLIENT_SANITIZER_FAIL=0
_CS_SERVER_SANITIZER_FAIL=0

ci_stress_stop_client() {
    if [ -n "$_CS_CLIENT_PID" ] && kill -0 "$_CS_CLIENT_PID" 2>/dev/null; then
        kill "$_CS_CLIENT_PID" 2>/dev/null || true
        local _exit=0
        wait "$_CS_CLIENT_PID" 2>/dev/null || _exit=$?
        # exit 143 = SIGTERM (normal kill), anything else is ASan/UBSan
        if [ "$_exit" -ne 0 ] && [ "$_exit" -ne 143 ]; then
            _CS_CLIENT_SANITIZER_FAIL=1
            echo "WARN: VPN client (PID $_CS_CLIENT_PID) exited with code $_exit"
        fi
        _CS_CLIENT_PID=""
        sleep 1
    fi
}

ci_stress_stop_vpn() {
    ci_stress_stop_client
    if [ -n "$_CS_SERVER_PID" ] && kill -0 "$_CS_SERVER_PID" 2>/dev/null; then
        kill "$_CS_SERVER_PID" 2>/dev/null || true
        local _exit=0
        wait "$_CS_SERVER_PID" 2>/dev/null || _exit=$?
        if [ "$_exit" -ne 0 ] && [ "$_exit" -ne 143 ]; then
            _CS_SERVER_SANITIZER_FAIL=1
            echo "WARN: VPN server (PID $_CS_SERVER_PID) exited with code $_exit"
        fi
        _CS_SERVER_PID=""
        sleep 1
    fi
}

# Check if ASan/UBSan reported errors (accumulated across all stop_client/stop_vpn calls).
# Call after ci_stress_stop_vpn.
ci_stress_check_sanitizer() {
    local failed=0
    if [ "$_CS_SERVER_SANITIZER_FAIL" -ne 0 ]; then
        echo "  FAIL: VPN server reported ASan/UBSan error"
        failed=1
    fi
    if [ "$_CS_CLIENT_SANITIZER_FAIL" -ne 0 ]; then
        echo "  FAIL: VPN client reported ASan/UBSan error"
        failed=1
    fi
    if [ "$failed" -eq 0 ]; then
        echo "  OK: no sanitizer errors"
    fi
    return $failed
}

# ── Log assertions (for captured VPN logs) ──

# Wait until <pattern> (extended regex) appears in <log> after line
# <start_line>. Returns 0 on match, 1 on timeout.
#
# G19: deliberately awk, not `tail -n +N | grep -q`. These scripts run under
# `set -o pipefail`, where a grep that exits at its first match can SIGPIPE
# the writer and turn a match into a spurious timeout -- the exact hazard
# scripts/ci_e2e/e2e_lib.sh documents but does not have to handle, because no
# consumer of that library sets pipefail. awk reads to EOF and uses no pipe
# at all. The pattern travels through the environment so awk does not
# reprocess its backslashes the way -v would.
ci_stress_wait_log_after() {
    local log="$1" pattern="$2" start_line="$3" timeout="${4:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if CS_LOG_PAT="$pattern" awk -v start="$start_line" \
                'NR > start && $0 ~ ENVIRON["CS_LOG_PAT"] { found = 1 }
                 END { exit !found }' "$log" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Echo the last <max> log lines a failing step produced, indented, so the
# console explains the failure instead of only naming it.
ci_stress_dump_log_since() {
    local log="$1" start_line="$2" max="${3:-12}"
    echo "    ── log since the fault (last ${max} lines) ──"
    awk -v start="$start_line" 'NR > start' "$log" 2>/dev/null \
        | tail -n "$max" | sed 's/^/    /'
}

# ── RSS/fd monitoring ──

# Start background monitoring of a process's RSS and fd count.
# Usage: ci_stress_monitor_start PID LOGFILE
# LOGFILE format: timestamp_epoch rss_kb fd_count
ci_stress_monitor_start() {
    local pid="$1"
    local logfile="$2"

    : > "$logfile"

    (
        while kill -0 "$pid" 2>/dev/null; do
            local ts rss_kb fd_count
            ts=$(date +%s)
            rss_kb=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
            fd_count=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
            echo "$ts $rss_kb $fd_count" >> "$logfile"
            sleep 10
        done
    ) &
    _CS_MONITOR_PIDS+=($!)
}

# Stop all running monitors.
ci_stress_monitor_stop() {
    if [ ${#_CS_MONITOR_PIDS[@]} -eq 0 ]; then return 0; fi
    for mpid in "${_CS_MONITOR_PIDS[@]}"; do
        kill "$mpid" 2>/dev/null || true
        wait "$mpid" 2>/dev/null || true
    done
    _CS_MONITOR_PIDS=()
}

# True when the binary under test is an ASan build.
#
# ASan reserves a large shadow region and quarantines freed memory instead of
# returning it, so a sanitizer build's RSS climbs by hundreds of percent with
# nothing leaking -- which is why the growth check below is skipped for them.
# Leak coverage does not depend on it: LeakSanitizer still runs at exit and
# the fd check still applies.
#
# Detect it from the binary, not from ASAN_OPTIONS: that variable is a tuning
# knob rather than a marker, and a caller who simply did not export it turns a
# clean run red for the wrong reason. The variable is still honoured as a
# fallback for when the binary cannot be read.
ci_stress_is_asan_build() {
    [ -n "${ASAN_OPTIONS:-}" ] && return 0
    LC_ALL=C grep -qa "__asan_init" "$MQVPN" 2>/dev/null
}

# Check resource log for leaks.
# Fails if RSS grew >50% from initial or fd count increased.
# Usage: ci_stress_check_resources LOGFILE LABEL
ci_stress_check_resources() {
    local logfile="$1"
    local label="${2:-process}"
    local result=0

    if [ ! -s "$logfile" ]; then
        echo "WARN: $label monitor log is empty"
        return 0
    fi

    CS_ASAN="$(ci_stress_is_asan_build && echo 1 || echo 0)" python3 -c "
import sys

lines = open('${logfile}').read().strip().split('\n')
if len(lines) < 2:
    print('  $label: not enough data points ({} samples)'.format(len(lines)))
    sys.exit(0)

samples = []
for line in lines:
    parts = line.split()
    if len(parts) >= 3:
        samples.append((int(parts[0]), int(parts[1]), int(parts[2])))

if not samples:
    print('  $label: no valid samples')
    sys.exit(0)

initial_rss = samples[0][1]
final_rss = samples[-1][1]
initial_fd = samples[0][2]
final_fd = samples[-1][2]
max_rss = max(s[1] for s in samples)

print(f'  $label: RSS initial={initial_rss}KB final={final_rss}KB max={max_rss}KB ({len(samples)} samples)')
print(f'  $label: fd  initial={initial_fd} final={final_fd}')

import os
asan_enabled = os.environ.get('CS_ASAN') == '1'

failed = False

if initial_rss > 0:
    growth = (max_rss - initial_rss) / initial_rss
    if growth > 0.5:
        if asan_enabled:
            print(f'  SKIP: $label RSS grew {growth*100:.0f}% (ASan shadow memory, not a real leak)')
        else:
            print(f'  FAIL: $label RSS grew {growth*100:.0f}% (>{50}% threshold)')
            failed = True

if final_fd > initial_fd:
    print(f'  FAIL: $label fd count leaked ({initial_fd} -> {final_fd})')
    failed = True

if failed:
    sys.exit(1)
else:
    print(f'  OK: $label resources stable')
"
    result=$?
    return $result
}

# ── Cleanup ──

ci_stress_cleanup() {
    echo ""
    echo "Cleaning up..."

    ci_stress_monitor_stop

    [ -n "$_CS_CLIENT_PID" ] && kill "$_CS_CLIENT_PID" 2>/dev/null || true
    [ -n "$_CS_SERVER_PID" ] && kill "$_CS_SERVER_PID" 2>/dev/null || true
    _CS_CLIENT_PID=""
    _CS_SERVER_PID=""

    ip netns exec "$NS_SERVER" pkill -f "iperf3" 2>/dev/null || true
    ip netns exec "$NS_CLIENT" pkill -f "iperf3" 2>/dev/null || true
    sleep 1

    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_A0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_A1" root 2>/dev/null || true
    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_B0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_B1" root 2>/dev/null || true

    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true

    [ -n "$_CS_WORK_DIR" ] && rm -rf "$_CS_WORK_DIR" || true
}
