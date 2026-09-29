#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_readd_recycled_slot_test.sh — E2E test: a dropped path whose library
# slot was recycled by another path's re-add must still be re-added by the
# recovery timer.
#
# add_path reuses the first fully released library slot (CLOSED_FREE) for
# any new path, under a new handle, so once another path's re-add takes a
# dropped path's slot, that path's old handle is gone from
# mqvpn_client_get_paths(). The recovery timer used to retry only handles
# the library still listed as CLOSED: such a path came back only if a link
# or address event happened to fire after its route returned. A route
# appearing emits no event the client listens for — the case built here.
#
# Topology (three paths, configured in the order K, A, B):
#   vpn-client-rs                 vpn-server-rs
#     veth-k0-rs ───────────────── veth-k1-rs    Path K (10.100.0.0/24, on-link)
#     veth-a0-rs ───────────────── veth-a1-rs    Path A (10.200.0.0/24)
#     veth-b0-rs ───────────────── veth-b1-rs    Path B (10.210.0.0/24)
#
# The server (10.100.0.1) sits on K's subnet. K is library slot 0 and is
# never touched, so the connection never reconnects. A (slot 1) and B
# (slot 2) reach the server only through manually added routes, which a
# link down flushes and a link up does not restore (the route-gate
# precondition of run_route_gate_test.sh). IPv6 is disabled on A, so A's
# link-up raises no late link-local address event.
#
# Test steps:
#   1. Establish all three paths; record A's handle H_A from the DEBUG FSM
#      line "path[handle=H_A name=veth-a0-rs]".
#   2. A link down -> A's library slot drains to CLOSED_FREE.
#   3. B link down; B link up and B's route restored -> B is re-added, into
#      slot 1: the first CLOSED_FREE slot, A's old one.
#   4. Precondition: "[STATUS]   path1=veth-b0-rs" (the status lines list
#      the library slots in order) shows the recycling happened, so H_A is
#      gone from the path list. If it never shows, the run is invalid and
#      fails.
#   5. A link up without its route: the event path stops at the route gate
#      without logging. The recovery timer, which must now evaluate A, logs
#      the route-gate deferral for A.
#   6. A's route added (no link or address event) -> within 15s the timer
#      re-adds A under a new handle, and A returns to ACTIVE/STANDBY.
#
# Usage: sudo ./run_readd_recycled_slot_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]
#        --log-level applies to the server; the client always runs at debug
#        (the FSM transition lines carry the path handles).

set -e

source "$(dirname "$0")/sanitizer_check.sh"
# Shared wait helpers (wait_for_log / wait_for_log_after).
source "$(dirname "$0")/e2e_lib.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
LOG_LEVEL="info"

while [ $# -gt 0 ]; do
    case "$1" in
        --log-level) LOG_LEVEL="$2"; shift 2 ;;
        *) [ -z "$MQVPN" ] && MQVPN="$1"; shift ;;
    esac
done

MQVPN="${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    echo "Build first: mkdir build && cd build && cmake .. && make"
    exit 1
fi

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"
CLIENT_LOG="${WORK_DIR}/client.log"

# Unique names so this test runs alongside other e2e tests
NS_SERVER="vpn-server-rs"
NS_CLIENT="vpn-client-rs"
VETH_K0="veth-k0-rs"
VETH_K1="veth-k1-rs"
VETH_A0="veth-a0-rs"
VETH_A1="veth-a1-rs"
VETH_B0="veth-b0-rs"
VETH_B1="veth-b1-rs"

SERVER_ADDR="10.100.0.1"
TUNNEL_IP="10.0.0.1"

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0
H_A=""
H_A_NEW=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    stop_and_check_sanitizer "$CLIENT_PID" "client" "$CLIENT_LOG" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" \
        "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    sleep 1
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_K0" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

# The library slot 1 name of the most recent [STATUS] block.
observed_path1() {
    sed -nE 's/.*\[STATUS\]   path1=([^ ]+) .*/\1/p' "$CLIENT_LOG" | tail -n 1
}

fail() {
    echo "=== FAIL: $1 ==="
    echo "H_A=${H_A:-unknown} new A handle=${H_A_NEW:-none}" \
        "last [STATUS] path1=$(observed_path1)"
    echo "--- Client log: path lines ---"
    grep -nE "name=(${VETH_K0}|${VETH_A0}|${VETH_B0})\]|re-added|route to the server|closing path|\[STATUS\]" \
        "$CLIENT_LOG" || true
    echo "--- Client log: last 40 lines outside xquic ---"
    grep -v "\[xquic\]" "$CLIENT_LOG" | tail -n 40
    exit 1
}

# A's and B's routes to the server: the same prefix as K's on-link route at
# a higher metric, so unbound traffic keeps using K. Path sockets are bound
# to their interface and only see routes through it.
add_route_a() {
    ip netns exec "$NS_CLIENT" ip route add 10.100.0.0/24 via 10.200.0.1 dev "$VETH_A0" metric 200
}
add_route_b() {
    ip netns exec "$NS_CLIENT" ip route add 10.100.0.0/24 via 10.210.0.1 dev "$VETH_B0" metric 210
}

# wait_for_carrier <iface> <timeout_sec>: until the client-side link
# reports LOWER_UP.
wait_for_carrier() {
    local elapsed=0 link
    while [ "$elapsed" -lt "$2" ]; do
        link=$(ip netns exec "$NS_CLIENT" ip -o link show dev "$1")
        case "$link" in
            *LOWER_UP*) return 0 ;;
        esac
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Clean leftovers
ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip link del "$VETH_K0" 2>/dev/null || true
ip link del "$VETH_A0" 2>/dev/null || true
ip link del "$VETH_B0" 2>/dev/null || true

# ─── Setup ───
PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-recycled-slot-test" 2>/dev/null

ip netns add "$NS_SERVER"
ip netns add "$NS_CLIENT"

# add_veth <client-if> <server-if> <client-cidr> <server-cidr>
add_veth() {
    ip link add "$1" type veth peer name "$2"
    ip link set "$1" netns "$NS_CLIENT"
    ip link set "$2" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$3" dev "$1"
    ip netns exec "$NS_SERVER" ip addr add "$4" dev "$2"
}
add_veth "$VETH_K0" "$VETH_K1" 10.100.0.2/24 10.100.0.1/24
add_veth "$VETH_A0" "$VETH_A1" 10.200.0.2/24 10.200.0.1/24
add_veth "$VETH_B0" "$VETH_B1" 10.210.0.2/24 10.210.0.1/24

ip netns exec "$NS_CLIENT" sysctl -w "net.ipv6.conf.${VETH_A0}.disable_ipv6=1" >/dev/null
for ifc in "$VETH_K0" "$VETH_A0" "$VETH_B0" lo; do
    ip netns exec "$NS_CLIENT" ip link set "$ifc" up
done
for ifc in "$VETH_K1" "$VETH_A1" "$VETH_B1" lo; do
    ip netns exec "$NS_SERVER" ip link set "$ifc" up
done

ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null
# Loose rp_filter: replies from the server arrive on A and B, whose routes
# to it lose to K's on hosts with a strict default.
ip netns exec "$NS_CLIENT" sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
ip netns exec "$NS_SERVER" sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null

add_route_a
add_route_b

ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$SERVER_ADDR" >/dev/null
ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.200.0.1 >/dev/null
ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.210.0.1 >/dev/null

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
    --path "$VETH_K0" --path "$VETH_A0" --path "$VETH_B0" \
    --auth-key "$PSK" \
    --insecure \
    --scheduler wlb \
    --log-level debug >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 3
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "client died"
    cat "$CLIENT_LOG"
    exit 1
fi

# =================================================================
#  Step 1: all three paths up; record A's handle
# =================================================================

ELAPSED=0
while [ "$ELAPSED" -lt 15 ]; do
    if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
[ "$ELAPSED" -lt 15 ] || fail "tunnel not reachable after 15s"
echo "OK: tunnel up (${ELAPSED}s)"

for ifc in "$VETH_A0" "$VETH_B0"; do
    wait_for_log "$CLIENT_LOG" "name=${ifc}\].*-> (ACTIVE|STANDBY)" 15 ||
        fail "path ${ifc} not activated within 15s"
done
echo "OK: paths ${VETH_A0} and ${VETH_B0} active beside ${VETH_K0}"

H_A=$(sed -nE "s/.*path\[handle=([0-9]+) name=${VETH_A0}\].*/\1/p" "$CLIENT_LOG" | sed -n 1p)
[ -n "$H_A" ] || fail "no FSM line for ${VETH_A0} (client not at debug?)"
echo "OK: H_A=${H_A}"

# =================================================================
#  Step 2: A down -> A's library slot drains to CLOSED_FREE
# =================================================================

echo ""
echo "=== Step 2: ${VETH_A0} down — its library slot must reach CLOSED_FREE ==="
ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" down
wait_for_log "$CLIENT_LOG" \
    "path\[handle=${H_A} name=${VETH_A0}\] CLOSED_DROPPED -> CLOSED_FREE" 20 ||
    fail "${VETH_A0}'s slot did not reach CLOSED_FREE within 20s"
echo "OK: ${VETH_A0} dropped and its library slot freed"

# =================================================================
#  Step 3: B down, then up with its route -> B re-added into A's slot
# =================================================================

echo ""
echo "=== Step 3: ${VETH_B0} down/up — its re-add takes the first free slot ==="
B_MARK=$(wc -l <"$CLIENT_LOG")
ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" down
wait_for_log_after "$CLIENT_LOG" \
    "netlink: interface ${VETH_B0} admin down, closing path" "$B_MARK" 10 ||
    fail "${VETH_B0} not dropped on admin down"
ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" up
wait_for_carrier "$VETH_B0" 10 || fail "${VETH_B0} reported no carrier within 10s"
add_route_b
wait_for_log_after "$CLIENT_LOG" "path ${VETH_B0} re-added \(handle=" "$B_MARK" 20 ||
    fail "${VETH_B0} not re-added within 20s of its link-up"
echo "OK: ${VETH_B0} re-added"

# =================================================================
#  Step 4: precondition — slot 1 (A's old slot) now carries B
# =================================================================

echo ""
echo "=== Step 4: precondition — library slot 1 must now carry ${VETH_B0} ==="
wait_for_log_after "$CLIENT_LOG" "\[STATUS\]   path1=${VETH_B0} " "$B_MARK" 35 ||
    fail "invalid run: no [STATUS] line shows path1=${VETH_B0} within 35s, so A's slot was not recycled"
echo "OK: slot 1 recycled for ${VETH_B0}; H_A=${H_A} is no longer listed"

# =================================================================
#  Step 5: A up without its route -> the timer evaluates A and defers
# =================================================================

echo ""
echo "=== Step 5: ${VETH_A0} up, no route — the recovery timer must evaluate it ==="
A_UP_MARK=$(wc -l <"$CLIENT_LOG")
ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
wait_for_carrier "$VETH_A0" 10 || fail "${VETH_A0} reported no carrier within 10s"
# Let the kernel's delayed link notification (linkwatch) reach the client
# first, so every later re-add of A is the timer's.
sleep 2

GATE_PATTERN="netlink: ${VETH_A0} has a usable address but no route to the server — re-add deferred until a route appears"
wait_for_log_after "$CLIENT_LOG" "$GATE_PATTERN" "$A_UP_MARK" 10 ||
    fail "route-gate deferral for ${VETH_A0} not logged within 10s: the recovery timer never evaluated A"
echo "OK: the recovery timer evaluates ${VETH_A0} (route-gate deferral logged)"

if tail -n "+$((A_UP_MARK + 1))" "$CLIENT_LOG" | grep -qE "path ${VETH_A0} re-added"; then
    fail "${VETH_A0} re-added while it has no route to the server"
fi
echo "OK: no re-add of ${VETH_A0} while its route is missing"

# =================================================================
#  Step 6: A's route added (no netlink event) -> the timer re-adds A
# =================================================================

echo ""
echo "=== Step 6: route for ${VETH_A0} added — the timer must re-add it ==="
ROUTE_MARK=$(wc -l <"$CLIENT_LOG")
add_route_a
wait_for_log_after "$CLIENT_LOG" "timer re-added path ${VETH_A0}" "$ROUTE_MARK" 15 ||
    fail "${VETH_A0} not re-added by the recovery timer within 15s of its route"

H_A_NEW=$(tail -n "+$((ROUTE_MARK + 1))" "$CLIENT_LOG" |
    sed -nE "s/.*path ${VETH_A0} re-added \(handle=([0-9]+)\).*/\1/p" | sed -n 1p)
[ -n "$H_A_NEW" ] && [ "$H_A_NEW" != "$H_A" ] ||
    fail "${VETH_A0} re-added without a new handle"
echo "OK: ${VETH_A0} re-added by the timer (handle ${H_A} -> ${H_A_NEW})"

wait_for_log_after "$CLIENT_LOG" \
    "path\[handle=${H_A_NEW} name=${VETH_A0}\].*-> (ACTIVE|STANDBY)" "$ROUTE_MARK" 15 ||
    fail "re-added ${VETH_A0} did not return to ACTIVE/STANDBY within 15s"
echo "OK: ${VETH_A0} back to ACTIVE/STANDBY"

ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1 ||
    fail "tunnel ping failed after ${VETH_A0} returned"
echo "OK: tunnel ping works"

if grep -qE "netlink: interface ${VETH_K0} .*, closing path" "$CLIENT_LOG"; then
    fail "path ${VETH_K0} was dropped during the test"
fi
echo "OK: ${VETH_K0} stayed up throughout"

echo ""
echo "=== All recycled-slot re-add tests PASSED ==="
