#!/bin/bash
# test_e2e_backup_fec.sh — E2E smoke test for backup_fec scheduler.
#
# Verifies:
#   1. mqvpn server + client both start with Scheduler=backup_fec, connection
#      establishes, ping succeeds.
#   2. Compatibility scenario: client=backup_fec / server=wlb still connects
#      (FEC negotiation just disables silently — see plan Open Items).
#
# Requires: root (TUN + netns). Not added to CI; use perf-weekly.yml for
# automated bench coverage instead.
#
# Run manually:
#   sudo bash tests/test_e2e_backup_fec.sh [path/to/mqvpn]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
BENCH_LOG_LEVEL="${BENCH_LOG_LEVEL:-info}"

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

# --- Test 1: symmetric backup_fec on both sides ---

test_symmetric_backup_fec() {
    local client_log="${LOG_DIR}/symmetric_client.log"
    bench_setup_netns
    BENCH_SCHEDULER="backup_fec"
    bench_start_vpn_server
    bench_start_vpn_client "--path veth-a0 --path veth-b0" "$client_log"

    sleep 2
    assert_ping "symmetric backup_fec ping" || return 1

    # Quick iperf3 sanity check (no loss injected — just confirms data flows)
    if command -v iperf3 >/dev/null; then
        ip netns exec "$NS_SERVER" iperf3 -s -D --pidfile /tmp/iperf3-fec.pid >/dev/null 2>&1 || true
        sleep 1
        if ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_SERVER_IP" -t 5 -R >/dev/null 2>&1; then
            echo "  iperf3 OK"
        else
            echo "  iperf3 failed (non-fatal — connection still verified by ping)"
        fi
        kill "$(cat /tmp/iperf3-fec.pid 2>/dev/null)" 2>/dev/null || true
    fi
    return 0
}

# --- Test 2: compatibility — client=backup_fec, server=wlb ---

test_compat_client_fec_server_wlb() {
    local client_log="${LOG_DIR}/compat_client.log"
    bench_cleanup
    bench_setup_netns

    BENCH_SCHEDULER="wlb"
    bench_start_vpn_server

    BENCH_SCHEDULER="backup_fec"
    bench_start_vpn_client "--path veth-a0 --path veth-b0" "$client_log"

    sleep 2
    assert_ping "compat (client=backup_fec, server=wlb) ping" || return 1
    return 0
}

# --- Test 3: backup_fec actually emits repair packets ---

test_backup_fec_emits_repairs() {
    local server_log="${LOG_DIR}/repair_server.log"
    bench_cleanup
    bench_setup_netns
    BENCH_SCHEDULER="backup_fec"

    # bench_start_vpn_server takes no log-path argument; it redirects to the
    # shell's stdout.  We call it to generate the PSK and TLS cert/key in
    # _BENCH_WORK_DIR, then kill the server it started and restart it with
    # explicit log capture so we can grep fec_send= afterwards.
    bench_start_vpn_server

    # Kill the server spawned by the helper and re-launch with log capture.
    kill "$_BENCH_SERVER_PID" 2>/dev/null || true
    wait "$_BENCH_SERVER_PID" 2>/dev/null || true

    ip netns exec "$NS_SERVER" "$MQVPN" \
        --mode server \
        --listen "0.0.0.0:${VPN_LISTEN_PORT}" \
        --subnet 10.0.0.0/24 \
        --cert "${_BENCH_WORK_DIR}/server.crt" \
        --key "${_BENCH_WORK_DIR}/server.key" \
        --auth-key "$_BENCH_PSK" \
        --scheduler "$BENCH_SCHEDULER" \
        --log-level "$BENCH_LOG_LEVEL" >"$server_log" 2>&1 &
    _BENCH_SERVER_PID=$!
    sleep 2

    if ! kill -0 "$_BENCH_SERVER_PID" 2>/dev/null; then
        echo "  FAIL: restarted server process died"
        return 1
    fi

    bench_start_vpn_client "--path veth-a0 --path veth-b0" "${LOG_DIR}/repair_client.log"

    sleep 2

    # Generate ~5s of UDP traffic through the tunnel to fill at least one FEC block
    if command -v iperf3 >/dev/null; then
        ip netns exec "$NS_SERVER" iperf3 -s -D --pidfile /tmp/iperf3-fec-repair.pid >/dev/null 2>&1 || true
        sleep 1
        ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_SERVER_IP" -u -b 50M -t 5 >/dev/null 2>&1 || true
        kill "$(cat /tmp/iperf3-fec-repair.pid 2>/dev/null)" 2>/dev/null || true
    else
        # Fallback: many pings to drive enough packets
        ip netns exec "$NS_CLIENT" ping -c 200 -i 0.02 "$TUNNEL_SERVER_IP" >/dev/null 2>&1 || true
    fi

    # Trigger graceful close on the client so the server flushes conn stats
    # (svr_log_conn_stats is only called from cb_h3_conn_close or the loss
    # checkpoint; see mqvpn_server.c:454 / 1032).
    if [[ -n "$_BENCH_CLIENT_PID" ]]; then
        kill -TERM "$_BENCH_CLIENT_PID" 2>/dev/null || true
        # Give xquic time to send CONNECTION_CLOSE and the server to log stats
        wait "$_BENCH_CLIENT_PID" 2>/dev/null || true
    fi

    sleep 2  # let the server's cb_h3_conn_close flush

    local fec_send
    fec_send=$(grep -oE 'fec_send=[0-9]+' "$server_log" | tail -1 | cut -d= -f2)
    if [[ -z "$fec_send" ]]; then
        echo "  FAIL: server log never emitted fec_send= line"
        echo "  --- last 20 lines of server log ---"
        tail -20 "$server_log"
        return 1
    fi
    if (( fec_send == 0 )); then
        echo "  FAIL: fec_send=0 — backup_fec did not emit any repair packets"
        echo "  --- relevant log lines ---"
        grep -E "fec_(send|recover|enable)" "$server_log" | tail -10
        return 1
    fi

    echo "  OK: fec_send=$fec_send (FEC repair packets observed)"
    return 0
}

run_test "symmetric backup_fec" test_symmetric_backup_fec
run_test "compat: client=backup_fec, server=wlb" test_compat_client_fec_server_wlb
run_test "backup_fec emits repair packets" test_backup_fec_emits_repairs

echo ""
echo "================================================="
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================="
[ "$FAIL" -eq 0 ]
