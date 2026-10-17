#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_tun_offload_config_test.sh — E2E test for the [Advanced] TunOffload and
# TunGro config keys (Linux TUN with IFF_VNET_HDR + TSO/USO reads, and the
# write-side TCP GRO, src/platform/linux/tun.c / tun_offload.c).
#
# Both keys have no CLI flag; the INI passed with -C is their only input, as
# for UdpGso / UdpGro (run_udp_gso_config_test.sh, whose shape this follows).
#
# G13 note: the arms assert on the TUN creation line in src/platform/linux/tun.c:
#     "TUN device %s created (fd=%d, offloads: csum tso4 tso6[ uso4 uso6][ gro])"
#     "TUN device %s created (fd=%d)"                   /* plain TUN */
# If you reword it, update the "offloads: csum tso4" and " gro)" patterns
# below in the same change. The line is logged before the tunnel can come up,
# so checking it after tunnel-up is race-free.
#
# Arms (fresh netns, PSK and cert each; -C goes to both endpoints):
#   A. default: offloads on and gro on, on both ends.
#   B. TunOffload = false: plain TUN on both ends (no offloads, so no gro).
#   C. TunGro = false: offloads on, gro off, on both ends.
# Each arm then pushes TCP both ways through the tunnel with iperf3, since
# TSO reads, GRO writes and their checksum handling only show up on TCP.
#
# REQUIRES: root (netns + TUN), openssl, iperf3, jq.
#
# Run manually:
#   sudo bash scripts/ci_e2e/run_tun_offload_config_test.sh [path/to/mqvpn]
#
# Exit code: 0 if all arms pass and no sanitizer error fired, 1 otherwise.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/sanitizer_check.sh"
source "${SCRIPT_DIR}/../../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}}"
LOG_DIR="$(mktemp -d)"
SANITIZER_FAIL=0
IPERF_SECONDS=3
MIN_MBPS=1

cleanup() {
    local _rc=$?
    bench_cleanup
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

if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: must run as root (sudo)" >&2
    exit 2
fi

bench_check_test_deps openssl iperf3 jq

PASS=0
FAIL=0

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

# Same flag set as bench_start_vpn_client, plus an extra_flags passthrough.
start_client() {
    local extra_flags="$1"
    local client_log="$2"

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

finish_arm() {
    local desc="$1" server_log="$2" client_log="$3"
    stop_and_check_sanitizer "$_BENCH_CLIENT_PID" "${desc} client" "$client_log" \
        || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$_BENCH_SERVER_PID" "${desc} server" "$server_log" \
        || SANITIZER_FAIL=1
    _BENCH_CLIENT_PID=""
    _BENCH_SERVER_PID=""
}

# check_marker <pattern> <expect_present:0|1> <server_log> <client_log>
# Greps the files directly (G19: no writer | grep -q under pipefail).
check_marker() {
    local pattern="$1" expect_present="$2" server_log="$3" client_log="$4"
    local server_hits client_hits
    server_hits=$(grep -c -- "$pattern" "$server_log" 2>/dev/null || true)
    client_hits=$(grep -c -- "$pattern" "$client_log" 2>/dev/null || true)
    server_hits="${server_hits:-0}"
    client_hits="${client_hits:-0}"

    if [ "$expect_present" -eq 1 ]; then
        if [ "$server_hits" -eq 0 ] || [ "$client_hits" -eq 0 ]; then
            echo "  FAIL: '$pattern' missing (server_hits=$server_hits client_hits=$client_hits)"
            grep "TUN device" "$server_log" "$client_log" || true
            return 1
        fi
        echo "  OK: '$pattern' present on both ends"
    else
        if [ "$server_hits" -ne 0 ] || [ "$client_hits" -ne 0 ]; then
            echo "  FAIL: '$pattern' unexpectedly present (server_hits=$server_hits client_hits=$client_hits)"
            grep "TUN device" "$server_log" "$client_log" || true
            return 1
        fi
        echo "  OK: '$pattern' absent on both ends"
    fi
    return 0
}

# iperf3_tcp <label> [-R]: one TCP run through the tunnel; fails below MIN_MBPS.
iperf3_tcp() {
    local label="$1" reverse="${2:-}"
    local json="${LOG_DIR}/iperf3_${label}.json" mbps

    ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" -1 >/dev/null 2>&1 &
    local srv_pid=$!
    sleep 1
    # shellcheck disable=SC2086  # reverse is empty or -R
    timeout $((IPERF_SECONDS + 15)) ip netns exec "$NS_CLIENT" iperf3 \
        -c "$TUNNEL_SERVER_IP" -t "$IPERF_SECONDS" $reverse --json \
        >"$json" 2>&1 || true
    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true

    mbps=$(jq -r '(.end.sum_received.bits_per_second // 0) / 1e6 | floor' "$json" 2>/dev/null || echo 0)
    mbps="${mbps:-0}"
    if [ "$mbps" -lt "$MIN_MBPS" ]; then
        echo "  FAIL: iperf3 $label ${mbps} Mbps (< ${MIN_MBPS}); output:"
        tail -20 "$json"
        return 1
    fi
    echo "  OK: iperf3 $label ${mbps} Mbps"
    return 0
}

# run_arm <arm_id> <expect_offload> <expect_gro> <extra_flags>
run_arm() {
    local arm_id="$1" expect_offload="$2" expect_gro="$3" extra_flags="$4"
    local server_log="${LOG_DIR}/${arm_id}_server.log"
    local client_log="${LOG_DIR}/${arm_id}_client.log"
    local rc=0

    bench_cleanup
    bench_setup_netns

    if ! bench_start_vpn_server "$extra_flags" "$server_log"; then
        echo "  FAIL: server did not start; tail of $server_log:"
        tail -30 "$server_log" 2>/dev/null
        return 1
    fi
    if ! start_client "$extra_flags" "$client_log"; then
        return 1
    fi
    if ! bench_wait_tunnel 15; then
        echo "  --- server log ---"
        cat "$server_log"
        echo "  --- client log ---"
        cat "$client_log"
        return 1
    fi

    check_marker "offloads: csum tso4" "$expect_offload" "$server_log" "$client_log" || rc=1
    check_marker " gro)" "$expect_gro" "$server_log" "$client_log" || rc=1
    if [ "$rc" -eq 0 ]; then
        iperf3_tcp "${arm_id}_ul" || rc=1
        iperf3_tcp "${arm_id}_dl" -R || rc=1
    fi

    finish_arm "$arm_id" "$server_log" "$client_log"
    return "$rc"
}

test_arm_default() {
    run_arm "default" 1 1 ""
}

test_arm_offload_off() {
    local ini="${LOG_DIR}/tun_offload_false.ini"
    printf '[Advanced]\nTunOffload = false\n' >"$ini"
    run_arm "offload_off" 0 0 "-C $ini"
}

test_arm_gro_off() {
    local ini="${LOG_DIR}/tun_gro_false.ini"
    printf '[Advanced]\nTunGro = false\n' >"$ini"
    run_arm "gro_off" 1 0 "-C $ini"
}

echo ""
echo "================================================================"
echo " TunOffload / TunGro config-key E2E"
echo " Binary: $MQVPN"
echo "================================================================"

run_test "Arm A — default: offloads + gro on both ends, TCP both ways" test_arm_default
run_test "Arm B — TunOffload = false: plain TUN, TCP both ways"         test_arm_offload_off
run_test "Arm C — TunGro = false: offloads without gro, TCP both ways"  test_arm_gro_off

echo ""
echo "================================================================"
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================================"

if (( FAIL > 0 )); then
    exit 1
fi
exit 0
