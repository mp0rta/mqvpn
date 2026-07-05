#!/bin/bash
# run_admin_down_test.sh — E2E test for LOCAL admin down/up recovery
# (ip link set <local> down + ip addr flush → ip link set up + addr re-add).
#
# Testing principle: idle recovery.
#   No iperf/ping runs during the fault + recovery phases. Background
#   socket reads would drive the xquic engine and mask a missing tick()
#   wake-up (that masking hid a 13s recovery latency for months), so the
#   recovery-latency assertions below depend on the tunnel staying idle.
#
# Companion to run_carrier_flap_test.sh: that test takes the PEER (server)
# side of the veth pair down, so the client sees a carrier loss
# (operstate LOWERLAYERDOWN with IFF_UP still set) — the case
# is_carrier_loss() in platform_linux.c is designed to catch. This test
# instead admin-downs the CLIENT-side interface itself, which clears
# IFF_UP and is deliberately ignored by the carrier-loss gate.
#
# Regression test for the admin-down/up recovery contract. After
# `ip link set <iface> down` the kernel clears IFF_UP; the platform
# treats this as an immediate administrative path drop (PLATFORM_DROP)
# and logs "netlink: interface <iface> admin down, closing path <n>"
# at WRN level, rather than letting the path bleed out slowly through
# write errors.
#
# On the later `ip link set <iface> up` the interface has NO address yet
# (on a real box DHCP/NetworkManager re-adds it seconds later), so the
# re-add is gated on the interface regaining a usable address of the
# server's family: the platform waits for the RTM_NEWADDR instead of
# firing a re-add against an addressless interface. Once the address is
# restored the re-added path completes PATH_CHALLENGE validation within
# ~1s and returns to ACTIVE/STANDBY. This test deliberately re-adds the
# address only AFTER `link up` to exercise that addressless window — if
# the address were restored in the same instant as `link up`, the gate
# would be satisfied immediately and the delayed-address path would not
# be exercised.
#
# Topology (dual-path multipath):
#   vpn-client-ad                 vpn-server-ad
#     veth-a0-ad ───────────────── veth-a1-ad    Path A (10.100.0.0/24)
#     veth-b0-ad ───────────────── veth-b1-ad    Path B (10.200.0.0/24)
#
# Test steps:
#   1. Establish dual-path VPN tunnel
#   2. In the CLIENT netns: ip link set veth-a0-ad down + ip addr flush
#      -> verify Path A is dropped immediately (admin down)
#      -> verify Path B keeps carrying tunnel traffic
#   3. Hold the interface down ~12s (short version of the real down window)
#   4. ip link set veth-a0-ad up (WITHOUT re-adding the address yet —
#      mimics the DHCP/NetworkManager delay on a real system)
#      -> verify NO re-add fires during the addressless window
#         (negative half of the address-gate contract)
#   5. Re-add 10.100.0.2/24 a couple of seconds later
#      -> verify the re-added path becomes ACTIVE/STANDBY within 45s
#
# Usage: sudo ./run_admin_down_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]
#        (use --log-level debug: FSM transition logs are DEBUG level)

set -e

source "$(dirname "$0")/sanitizer_check.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
LOG_LEVEL="debug"

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

# Unique names so this test runs alongside other e2e tests
NS_SERVER="vpn-server-ad"
NS_CLIENT="vpn-client-ad"
VETH_A0="veth-a0-ad"
VETH_A1="veth-a1-ad"
VETH_B0="veth-b0-ad"
VETH_B1="veth-b1-ad"

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
    # Optional: preserve logs for post-mortem (set MQVPN_E2E_LOG_DIR)
    if [ -n "${MQVPN_E2E_LOG_DIR:-}" ]; then
        mkdir -p "$MQVPN_E2E_LOG_DIR"
        cp "${WORK_DIR}/client.log" \
            "${MQVPN_E2E_LOG_DIR}/admin-down-client.log" 2>/dev/null || true
        cp "${WORK_DIR}/server.log" \
            "${MQVPN_E2E_LOG_DIR}/admin-down-server.log" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

# Clean leftovers (only our -ad suffixed resources)
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
    -days 365 -nodes -subj "/CN=mqvpn-admin-down-test" 2>/dev/null

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
#  Test 1: local admin down (ip link set down + addr flush)
#          -> Path A dropped immediately, Path B survives
# =================================================================
#
# Admin down clears IFF_UP; the platform treats this as an immediate
# administrative drop and closes Path A right away (logged by
# remove_path_by_index at WRN level). Path B keeps carrying tunnel
# traffic. The addr flush mimics what NetworkManager/netplan does on a
# real box when an interface is admin-downed.

echo ""
echo "=== Test 1: Local admin down (ip link set down + addr flush) — Path B survives ==="

ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" down
ip netns exec "$NS_CLIENT" ip addr flush dev "$VETH_A0"
DOWN_TS=$(date +%s)

# Drop log (WRN): "netlink: interface veth-a0-ad admin down, closing path N"
if ! wait_for_log "${WORK_DIR}/client.log" \
        "netlink: interface ${VETH_A0} admin down, closing path" 10; then
    echo "=== FAIL: Path A not dropped on admin down ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: Path A dropped immediately on admin down"

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "OK: tunnel ping works on surviving Path B"
else
    echo "=== FAIL: Tunnel ping failed while Path A is admin-down ==="
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

# Hold the interface down ~12s total (the short version of the ~30s
# down window in the user report) to prove the drop is stable and
# quiet: the slot is CLOSED_DROPPED with no retry timer armed, so
# nothing should fire (no spurious re-adds) while the interface stays
# down.
NOW_TS=$(date +%s)
REMAIN=$((12 - (NOW_TS - DOWN_TS)))
if [ "$REMAIN" -gt 0 ]; then
    echo "Holding interface down for ${REMAIN}s more (drop must stay quiet)..."
    sleep "$REMAIN"
fi

# =================================================================
#  Test 2: admin up, then addr re-add -> path re-added, reactivates
# =================================================================
#
# `ip link set up` sets IFF_UP again, but the interface has NO address
# yet (on a real system DHCP/NetworkManager re-adds it seconds later;
# we mimic that by re-adding the address only after link-up). The
# re-add is gated on the interface regaining a usable address of the
# server's family, so nothing fires until the address is restored via
# RTM_NEWADDR. Once it is, the re-added path validates and returns to
# ACTIVE/STANDBY within a second or two.

echo ""
echo "=== Test 2: Admin up (ip link set up, addr re-added after) — path must reactivate ==="

UP_MARK=$(wc -l <"${WORK_DIR}/client.log")

ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
# NOTE: address deliberately NOT re-added yet — the re-add is gated on
# the interface regaining a usable address, so it will not fire until
# the RTM_NEWADDR below. This mimics the DHCP/NetworkManager delay.

READD_PATTERN="path ${VETH_A0} re-added|timer re-added path ${VETH_A0}|reactivated path ${VETH_A0}"

# Simulated DHCP/NetworkManager delay.
sleep 2

# ─── Negative half of the address-gate contract ───
# While the interface is up but still addressless, NO re-add may fire:
# the gate must hold until the address is restored.
PRE_ADDR_MARK=$(wc -l <"${WORK_DIR}/client.log")
if sed -n "$((UP_MARK + 1)),${PRE_ADDR_MARK}p" "${WORK_DIR}/client.log" \
        | grep -qE "$READD_PATTERN"; then
    echo "=== FAIL: path re-added during addressless window (address gate regressed) ==="
    echo "--- Client log (link-up .. pre-addr) ---"
    sed -n "$((UP_MARK + 1)),${PRE_ADDR_MARK}p" "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: no re-add during addressless window (address gate held)"

# Restore the address; the gate is now satisfied and the re-add fires.
ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0"
echo "OK: address ${IP_A_CLIENT} re-added on ${VETH_A0}"

# ─── Verification A: path re-added (only after the address is back) ───
if ! wait_for_log_after "${WORK_DIR}/client.log" "$READD_PATTERN" "$UP_MARK" 20; then
    echo "=== FAIL: Path re-addition not detected within 20s of addr restore ==="
    echo "--- Client log (post-up) ---"
    tail -n "+$((UP_MARK + 1))" "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: path re-added after address restore (verification A)"

# Record where the re-add happened so verification B only looks at
# activation lines AFTER it (the initial connect also logged
# "activated ... state=ACTIVE" for this iface).
READD_LINE=$(grep -nE "$READD_PATTERN" "${WORK_DIR}/client.log" | tail -1 | cut -d: -f1)

# ─── Verification B: re-added path returns to ACTIVE within 45s ───
# Markers (post-re-add only):
#   INFO : "path[N] activated: path_id=... iface=veth-a0-ad state=ACTIVE"
#   DEBUG: "path[handle=N name=veth-a0-ad] VALIDATING -> ACTIVE ..."
ACTIVATE_PATTERN="activated:.*iface=${VETH_A0}.*state=(ACTIVE|STANDBY)|name=${VETH_A0}\].*-> (ACTIVE|STANDBY)"
if wait_for_log_after "${WORK_DIR}/client.log" "$ACTIVATE_PATTERN" "$READD_LINE" 45; then
    echo "OK: re-added path returned to ACTIVE (verification B)"
else
    echo "=== FAIL: re-added path did not return to ACTIVE within 45s ==="
    echo "--- Client log (post-up) ---"
    tail -n "+$((UP_MARK + 1))" "${WORK_DIR}/client.log"
    exit 1
fi

# ─── Recovery-latency assertion: re-add -> ACTIVE within 5s ───
# Pins the "drive engine after netlink-driven path changes" fix: before
# that fix, the re-added path only reactivated when an unrelated timer
# happened to fire, taking ~13s here (and still passing under the loose
# 45s window above). The engine must now be driven immediately after
# the netlink-triggered re-add, so the real latency budget is tight.
ts_to_ms() {  # HH:MM:SS.mmm -> ms since midnight
    local h=${1%%:*} rest=${1#*:}
    local m=${rest%%:*} s_ms=${rest#*:}
    local s=${s_ms%%.*} ms=${s_ms#*.}
    echo $(( (10#$h*3600 + 10#$m*60 + 10#$s)*1000 + 10#$ms ))
}
READD_TS=$(sed -n "${READD_LINE}p" "${WORK_DIR}/client.log" | awk '{print $1}')
ACT_TS=$(tail -n "+$((READD_LINE + 1))" "${WORK_DIR}/client.log" \
    | grep -E "$ACTIVATE_PATTERN" | head -1 | awk '{print $1}')
LAT_MS=$(( $(ts_to_ms "$ACT_TS") - $(ts_to_ms "$READD_TS") ))
# midnight wrap: extremely unlikely in CI; treat negative as wrap and skip
if [ "$LAT_MS" -ge 0 ] && [ "$LAT_MS" -gt 5000 ]; then
    echo "=== FAIL: re-add -> ACTIVE took ${LAT_MS} ms (budget 5000 ms) ==="
    exit 1
fi
echo "OK: re-add -> ACTIVE in ${LAT_MS} ms"

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "OK: tunnel ping works after admin up"
else
    echo "=== FAIL: Tunnel ping failed after admin up ==="
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

echo ""
echo "=== All admin-down tests PASSED ==="
