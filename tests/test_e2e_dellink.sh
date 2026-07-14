#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# test_e2e_dellink.sh — E2E test for RTM_DELLINK path removal/re-addition
#
# Tests that when a network interface is removed (ip link del), the VPN
# immediately cleans up the path, and when the interface reappears, the
# path is automatically re-added with a fresh socket.
#
# Requires: root, netns support, iperf3 not required
# Usage: sudo ./test_e2e_dellink.sh [mqvpn-binary]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
BENCH_LOG_LEVEL="${BENCH_LOG_LEVEL:-info}"

PASS=0
FAIL=0
TOTAL=2
CLIENT_LOG="$(mktemp)"

trap 'bench_cleanup; rm -f "$CLIENT_LOG"' EXIT

# --- Helpers ---

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

assert_log() {
    local pattern="$1"
    local msg="${2:-log matches $pattern}"
    if grep -qiE "$pattern" "$CLIENT_LOG" 2>/dev/null; then
        echo "  assert_log OK: $msg"
        return 0
    else
        echo "  assert_log FAIL: $msg (pattern: $pattern)"
        return 1
    fi
}

wait_for_log() {
    local pattern="$1"
    local timeout="${2:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if grep -qiE "$pattern" "$CLIENT_LOG" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# --- Setup ---

echo "================================================================"
echo "  mqvpn E2E Test: RTM_DELLINK Path Removal/Re-addition"
echo "  Binary:   $MQVPN"
echo "  LogLevel: $BENCH_LOG_LEVEL"
echo "  Date:     $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# Check binary exists (skip iperf3 check — this test only uses ping)
if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    echo "Build first: mkdir build && cd build && cmake .. && make -j"
    exit 1
fi
MQVPN="$(realpath "$MQVPN")"

bench_setup_netns
bench_apply_netem

# Make the server address (10.100.0.1) reachable from both paths.
# ip link del destroys the veth pair (both ends), so without this
# the server address would vanish when Path A is removed.
# This mirrors real-world topology where a VPN server has one public
# IP reachable from multiple interfaces (WiFi, LTE, etc.).
ip netns exec "$NS_SERVER" ip addr add "${IP_A_SERVER_ADDR}/32" dev lo
ip netns exec "$NS_CLIENT" ip route add 10.100.0.0/24 via 10.200.0.1 dev "$VETH_B0" metric 200

bench_start_vpn_server
bench_start_vpn_client "--path $VETH_A0 --path $VETH_B0" "$CLIENT_LOG"
bench_wait_tunnel 15

# Wait for secondary path activation (multipath negotiation is async)
echo "Waiting for dual-path activation..."
if ! wait_for_log "path.*1.*activated" 15; then
    echo "ERROR: secondary path not activated within 15s"
    exit 1
fi
echo "Dual-path active, starting tests..."

# =================================================================
# Test 1: Interface removal — surviving path continues
# =================================================================
test_1_dellink() {
    # Delete Path A veth (also removes server-side peer veth-a1)
    ip netns exec "$NS_CLIENT" ip link del "$VETH_A0"

    # Wait for xquic PTO-based path removal. PTO can take 10+ seconds
    # depending on connection activity and RTT.
    if ! wait_for_log "path.*removed.*veth-a0" 20; then
        echo "  WARNING: Path A closure not detected in log within 20s"
    fi
    sleep 2 # settle time for xquic scheduler to switch

    # Traffic should still flow on Path B
    assert_ping "Path B survives after Path A removal" || return 1

    # Check that our handler logged the removal
    assert_log "interface.*removed|removed.*path|RTM_DELLINK" \
               "RTM_DELLINK handler fired" || return 1
}

# =================================================================
# Test 2: Interface re-creation — path re-added
# =================================================================
test_2_readd() {
    # Re-create the veth pair (both ends were destroyed by ip link del)
    ip link add "$VETH_A0" type veth peer name "$VETH_A1"
    ip link set "$VETH_A0" netns "$NS_CLIENT"
    ip link set "$VETH_A1" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0"
    ip netns exec "$NS_SERVER" ip addr add "$IP_A_SERVER" dev "$VETH_A1"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
    ip netns exec "$NS_SERVER" ip link set "$VETH_A1" up
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_A0" root netem delay 10ms rate 300mbit 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_A1" root netem delay 10ms rate 300mbit 2>/dev/null || true

    # Re-add backup route via Path B (was removed when veth-a0 was deleted because
    # the kernel removed the /32 route pointing to 10.200.0.1 — veth-b0 was fine but
    # re-adding ensures it's present for Test 3)
    ip netns exec "$NS_CLIENT" ip route replace 10.100.0.0/24 via 10.200.0.1 dev "$VETH_B0" metric 200 2>/dev/null || true

    # Wait for path re-addition (RTM_NEWLINK + RTM_NEWADDR processing)
    if ! wait_for_log "re-appear|re-added|re.add" 15; then
        echo "  Timed out waiting for path re-addition"
        return 1
    fi

    # Verify tunnel still works (now dual-path again)
    assert_ping "tunnel working after Path A re-added" || return 1

    # Check log
    assert_log "re-appear|re-added|re.add" \
               "RTM_NEWLINK re-add handler fired" || return 1
}

# --- Run tests ---

run_test "1: Interface removal — surviving path continues" test_1_dellink
run_test "2: Interface re-creation — path re-added" test_2_readd

# --- Summary ---

echo ""
echo "================================================================"
echo "  Results: $PASS/$TOTAL passed, $FAIL failed"
echo "================================================================"

if [ "$FAIL" -gt 0 ]; then
    echo "Client log (last 30 lines):"
    tail -30 "$CLIENT_LOG"
fi

exit $((FAIL > 0 ? 1 : 0))
