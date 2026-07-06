#!/bin/bash
# run_route_gate_test.sh — E2E test for the FIB route-reachability gate
# on path re-add (route_check.c / platform_linux.c).
#
# Regression for the "addr present, route absent" blackhole: a link
# down/up on a path whose ONLY route to the server is a manually-added
# via-route (not the auto-restored on-link prefix) leaves the interface
# with a usable source address but no FIB route to the server. Without
# the gate, re-add fires anyway, SO_BINDTODEVICE sends the PATH_CHALLENGE
# into the kernel's assume-on-link ARP fallback, and the path is stuck in
# PENDING forever (see docs/impl-notes/2026-07-06-dellink-blackhole-
# verification.md for the mechanism). With the gate, re-add is deferred
# until the route actually reappears.
#
# Topology (dual-path multipath):
#   vpn-client-rg                 vpn-server-rg
#     veth-a0-rg ───────────────── veth-a1-rg    Path A (10.100.0.0/24, on-link)
#     veth-b0-rg ───────────────── veth-b1-rg    Path B (10.200.0.0/24)
#
# Path B reaches the server (10.100.0.1, on Path A's subnet) only via a
# manually-added route: `10.100.0.0/24 via 10.200.0.1 dev veth-b0-rg`.
#
# Test steps:
#   1. Establish dual-path VPN tunnel (both ACTIVE)
#   2. ip link set veth-b0-rg down (admin down) -> Path B dropped
#      (address is NOT flushed; only routes through the link are)
#   3. ip link set veth-b0-rg up -> kernel auto-restores the 10.200.0.0/24
#      on-link prefix route, but NOT the manual via-route to the server
#      -> "usable address, no route to server" is now true for veth-b0-rg
#   4. Assert (gate holds): for 15s, the route-gate WRN log appears, no
#      "path veth-b0-rg re-added" fires, and no "stuck in PENDING" fires
#   5. ip route add 10.100.0.0/24 via 10.200.0.1 dev veth-b0-rg metric 200
#      -> Assert (recovery): within 15s, path is re-added and returns to
#      ACTIVE/STANDBY
#   6. Path A must stay ACTIVE throughout (untouched by this test)
#
# Usage: sudo ./run_route_gate_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

set -e

source "$(dirname "$0")/sanitizer_check.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
LOG_LEVEL="info"

while [ $# -gt 0 ]; do
    case "$1" in
        --log-level) LOG_LEVEL="$2"; shift 2 ;;
        *) [ -z "$MQVPN" ] && MQVPN="$1"; shift ;;
    esac
done

MQVPN="${MQVPN:-${SCRIPT_DIR}/../../build-lib/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    echo "Build first: cd build-lib && cmake .. && make"
    exit 1
fi

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

# Unique names so this test runs alongside other e2e tests
NS_SERVER="vpn-server-rg"
NS_CLIENT="vpn-client-rg"
VETH_A0="veth-a0-rg"
VETH_A1="veth-a1-rg"
VETH_B0="veth-b0-rg"
VETH_B1="veth-b1-rg"

IP_A_CLIENT="10.100.0.2/24"
IP_A_SERVER="10.100.0.1/24"
IP_B_CLIENT="10.200.0.2/24"
IP_B_SERVER="10.200.0.1/24"
SERVER_ADDR="10.100.0.1"
TUNNEL_IP="10.0.0.1"

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0

cleanup() {
    echo ""
    echo "Cleaning up..."
    stop_and_check_sanitizer "$CLIENT_PID" "client" \
        "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" \
        "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    sleep 1
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

# Clean leftovers
ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip link del "$VETH_A0" 2>/dev/null || true
ip link del "$VETH_B0" 2>/dev/null || true

wait_for_log() {
    local log_file="$1" pattern="$2" timeout="${3:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if grep -qE "$pattern" "$log_file" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Like wait_for_log but only considers lines AFTER line number $3 —
# needed to distinguish the post-re-add activation from the initial
# connection-time activation of the same path.
wait_for_log_after() {
    local log_file="$1" pattern="$2" start_line="$3" timeout="${4:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if tail -n "+$((start_line + 1))" "$log_file" 2>/dev/null \
                | grep -qE "$pattern"; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# ─── Setup ───
PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-route-gate-test" 2>/dev/null

ip netns add "$NS_SERVER"
ip netns add "$NS_CLIENT"

ip link add "$VETH_A0" type veth peer name "$VETH_A1"
ip link set "$VETH_A0" netns "$NS_CLIENT"
ip link set "$VETH_A1" netns "$NS_SERVER"
ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0"
ip netns exec "$NS_SERVER" ip addr add "$IP_A_SERVER" dev "$VETH_A1"
ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
ip netns exec "$NS_SERVER" ip link set "$VETH_A1" up

ip link add "$VETH_B0" type veth peer name "$VETH_B1"
ip link set "$VETH_B0" netns "$NS_CLIENT"
ip link set "$VETH_B1" netns "$NS_SERVER"
ip netns exec "$NS_CLIENT" ip addr add "$IP_B_CLIENT" dev "$VETH_B0"
ip netns exec "$NS_SERVER" ip addr add "$IP_B_SERVER" dev "$VETH_B1"
ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" up
ip netns exec "$NS_SERVER" ip link set "$VETH_B1" up

ip netns exec "$NS_CLIENT" ip link set lo up
ip netns exec "$NS_SERVER" ip link set lo up

ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$NS_SERVER" ip addr add "${SERVER_ADDR}/32" dev lo
ip netns exec "$NS_CLIENT" ip route add 10.100.0.0/24 via 10.200.0.1 dev "$VETH_B0" metric 200

ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$SERVER_ADDR" >/dev/null
ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.200.0.1 >/dev/null

# ─── Server ───
ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server \
    --listen "0.0.0.0:4433" \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --scheduler wlb \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "server died"
    cat "${WORK_DIR}/server.log"
    exit 1
fi

# ─── Client ───
ip netns exec "$NS_CLIENT" "$MQVPN" \
    --mode client \
    --server "${SERVER_ADDR}:4433" \
    --path "$VETH_A0" --path "$VETH_B0" \
    --auth-key "$PSK" \
    --insecure \
    --scheduler wlb \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "client died"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# Wait for tunnel up
ELAPSED=0
while [ "$ELAPSED" -lt 15 ]; do
    if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
if [ "$ELAPSED" -ge 15 ]; then
    echo "=== FAIL: Tunnel not reachable after 15s ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: tunnel up (${ELAPSED}s)"

echo "Waiting for dual-path activation..."
if ! wait_for_log "${WORK_DIR}/client.log" \
        "activated:.*iface=${VETH_B0}|name=${VETH_B0}\].*-> (ACTIVE|STANDBY)" 15; then
    echo "=== FAIL: Secondary path not activated within 15s ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: dual-path active"

# =================================================================
#  Test 1: local admin down on Path B (route disappears, address stays)
# =================================================================
#
# `ip link set <iface> down` clears IFF_UP and flushes routes through
# the link (including our manually-added via-route to the server), but
# does NOT flush the address we configured. This is the fault this
# test exists to catch: on `up`, the kernel auto-restores the on-link
# prefix route but never the via-route, leaving "usable address, no
# route to server" — exactly the ANK on-link-fallback blackhole
# precondition described in route_check.c.

echo ""
echo "=== Test 1: Local admin down on Path B — route disappears ==="

ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" down

# Drop log (WRN): "netlink: interface veth-b0-rg admin down, closing path N"
if ! wait_for_log "${WORK_DIR}/client.log" \
        "netlink: interface ${VETH_B0} admin down, closing path" 10; then
    echo "=== FAIL: Path B not dropped on admin down ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: Path B dropped on admin down"

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "OK: tunnel ping works on surviving Path A"
else
    echo "=== FAIL: Tunnel ping failed while Path B is admin-down ==="
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# =================================================================
#  Test 2: admin up on Path B — address is back, route is NOT.
#          Assert the gate blocks re-add and never gets stuck.
# =================================================================

echo ""
echo "=== Test 2: Admin up on Path B (route missing) — gate must block re-add ==="

UP_MARK=$(wc -l <"${WORK_DIR}/client.log")

ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" up
# Address was never flushed — it is present immediately. The kernel
# restores 10.200.0.0/24 as an on-link prefix route (derived from the
# interface's own address) but the manually-added via-route to the
# server's /24 is gone and stays gone until we add it back below.

READD_PATTERN="path ${VETH_B0} re-added|timer re-added path ${VETH_B0}"
GATE_PATTERN="netlink: ${VETH_B0} has a usable address but no route to the server — re-add deferred until a route appears"

echo "Observing for 15s: gate log must appear, no re-add, no PENDING stuck..."
if ! wait_for_log_after "${WORK_DIR}/client.log" "$GATE_PATTERN" "$UP_MARK" 15; then
    echo "=== FAIL: route-gate WRN log did not appear within 15s ==="
    echo "--- Client log (post-up) ---"
    tail -n "+$((UP_MARK + 1))" "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: route-gate WRN log observed"

OBSERVE_MARK=$(wc -l <"${WORK_DIR}/client.log")
if sed -n "$((UP_MARK + 1)),${OBSERVE_MARK}p" "${WORK_DIR}/client.log" \
        | grep -qE "$READD_PATTERN"; then
    echo "=== FAIL: path re-added despite missing route to server (gate regressed) ==="
    echo "--- Client log (post-up) ---"
    sed -n "$((UP_MARK + 1)),${OBSERVE_MARK}p" "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: no re-add while route is missing (gate held)"

if sed -n "$((UP_MARK + 1)),${OBSERVE_MARK}p" "${WORK_DIR}/client.log" \
        | grep -qE "stuck in PENDING"; then
    echo "=== FAIL: path stuck in PENDING while route is missing (blackhole regressed) ==="
    echo "--- Client log (post-up) ---"
    sed -n "$((UP_MARK + 1)),${OBSERVE_MARK}p" "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: no PENDING-stuck warning while route is missing"

# =================================================================
#  Test 3: route restored -> gate opens, path re-added and reactivates
# =================================================================

echo ""
echo "=== Test 3: Route restored — path must re-add and return to ACTIVE ==="

ROUTE_MARK=$(wc -l <"${WORK_DIR}/client.log")

ip netns exec "$NS_CLIENT" ip route add 10.100.0.0/24 via 10.200.0.1 dev "$VETH_B0" metric 200
echo "OK: server route restored on ${VETH_B0}"

if ! wait_for_log_after "${WORK_DIR}/client.log" "$READD_PATTERN" "$ROUTE_MARK" 15; then
    echo "=== FAIL: Path re-addition not detected within 15s of route restore ==="
    echo "--- Client log (post-route-restore) ---"
    tail -n "+$((ROUTE_MARK + 1))" "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: path re-added after route restore"

READD_LINE=$(grep -nE "$READD_PATTERN" "${WORK_DIR}/client.log" | tail -1 | cut -d: -f1)

ACTIVATE_PATTERN="activated:.*iface=${VETH_B0}.*state=(ACTIVE|STANDBY)|name=${VETH_B0}\].*-> (ACTIVE|STANDBY)"
if wait_for_log_after "${WORK_DIR}/client.log" "$ACTIVATE_PATTERN" "$READD_LINE" 15; then
    echo "OK: re-added path returned to ACTIVE/STANDBY"
else
    echo "=== FAIL: re-added path did not return to ACTIVE within 15s ==="
    echo "--- Client log (post-route-restore) ---"
    tail -n "+$((ROUTE_MARK + 1))" "${WORK_DIR}/client.log"
    exit 1
fi

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "OK: tunnel ping works after route restore"
else
    echo "=== FAIL: Tunnel ping failed after route restore ==="
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# =================================================================
#  Test 4: Path A was never touched — must remain ACTIVE throughout
# =================================================================

if grep -qE "netlink: interface ${VETH_A0} .*, closing path" "${WORK_DIR}/client.log"; then
    echo "=== FAIL: Path A was unexpectedly dropped during this test ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: Path A stayed up throughout"

echo ""
echo "=== All route-gate tests PASSED ==="
