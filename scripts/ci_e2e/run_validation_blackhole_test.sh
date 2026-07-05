#!/bin/bash
# run_validation_blackhole_test.sh — E2E test for PATH_CHALLENGE black-hole
# abandon + recovery.
#
# Companion to run_admin_down_test.sh (which exercises the admin-down/up
# drop + address-gated re-add contract). This test instead verifies what
# happens when a re-added path's validation traffic is silently dropped:
#
#   - A black-holed PATH_CHALLENGE must NOT wedge the path in VALIDATING
#     forever. xquic retransmits the challenge at PTO cadence and, after
#     3 attempts, abandons the path with a WARN containing
#     "G-P3 validation timeout". The mqvpn FSM then transitions the slot
#     VALIDATING -> CREATE_WAIT (reason=XQUIC_REMOVED) and schedules a
#     backoff retry.
#   - When the black hole is later removed, one of the backoff retries
#     re-validates the path and it returns to ACTIVE/STANDBY.
#
# The black hole is installed on the SERVER side (silently drop everything
# the server would send back out Path A's interface), so the client's
# PATH_CHALLENGE reaches the server but the PATH_RESPONSE never returns —
# exactly the asymmetric black hole a broken NAT / firewall produces.
#
# Implemented with `tc qdisc ... netem loss 100%`, not iptables OUTPUT
# DROP: iptables rejects the packet at the socket layer, so the server's
# sendto() gets EPERM and the server itself abandons the path on the
# write error — that's a loud failure, not the silent black hole this
# test needs. netem drops the packet after the socket write already
# succeeded, which is indistinguishable from the wire actually eating it.
#
# A fresh validation cycle on Path A is forced with a local
# down/up of the client interface WITHOUT flushing the address: the
# address persists, so the re-add fires promptly at link-up (its address
# gate is already satisfied) and the new path's PATH_CHALLENGE goes
# straight into the black hole.
#
# Topology (dual-path multipath):
#   vpn-client-vb                 vpn-server-vb
#     veth-a0-vb ───────────────── veth-a1-vb    Path A (10.100.0.0/24)
#     veth-b0-vb ───────────────── veth-b1-vb    Path B (10.200.0.0/24)
#
# Test steps:
#   1. Establish dual-path VPN tunnel (both paths up)
#   2. Black-hole server->client on Path A only
#      (tc qdisc add dev veth-a1-vb root netem loss 100% in the server netns)
#   3. Force a fresh validation on Path A: link down, sleep 2, link up
#      (address NOT flushed)
#   4. within 20s of link-up the client logs "G-P3 validation timeout"
#      AND an FSM "-> CREATE_WAIT" transition for veth-a0-vb
#   5. between link-up and the first G-P3 line, count PATH_CHALLENGE
#      packet-send lines (xquic "|<==|...|frame:...PATH_CHALLENGE"):
#      expect >= 3 (PTO retransmits)
#   6. Remove the black hole ~25s after link-up (within the retry budget)
#   7. Recovery: within 45s of removal the path returns to ACTIVE/STANDBY
#
# Usage: sudo ./run_validation_blackhole_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]
#        (use --log-level debug: FSM transitions and PATH_CHALLENGE sends
#         are only logged at debug)

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

if ! command -v tc >/dev/null 2>&1; then
    echo "error: tc (iproute2) not found (needed to install the netem black hole)"
    exit 1
fi

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

# Unique names so this test runs alongside other e2e tests
NS_SERVER="vpn-server-vb"
NS_CLIENT="vpn-client-vb"
VETH_A0="veth-a0-vb"
VETH_A1="veth-a1-vb"
VETH_B0="veth-b0-vb"
VETH_B1="veth-b1-vb"

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
    # Remove the black hole if still installed (netns teardown drops it
    # too, but be explicit and tolerant of it already being gone).
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_A1" root netem \
        2>/dev/null || true
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
            "${MQVPN_E2E_LOG_DIR}/blackhole-client.log" 2>/dev/null || true
        cp "${WORK_DIR}/server.log" \
            "${MQVPN_E2E_LOG_DIR}/blackhole-server.log" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

# Clean leftovers (only our -vb suffixed resources)
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
# needed to distinguish the post-re-add events from the initial
# connection-time events on the same path.
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
    -days 365 -nodes -subj "/CN=mqvpn-blackhole-test" 2>/dev/null

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
#  Black-hole Path A, then force a fresh validation cycle
# =================================================================
#
# Drop everything the SERVER would send back out Path A's interface.
# The client's PATH_CHALLENGE still reaches the server, but the
# PATH_RESPONSE never returns — an asymmetric validation black hole.

echo ""
echo "=== Installing black hole: drop server->client on Path A (${VETH_A1}) ==="
ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_A1" root netem loss 100%
echo "OK: black hole installed"

# Force a fresh validation cycle on Path A by bouncing the client
# interface. The address is deliberately NOT flushed, so the re-add
# fires promptly at link-up and the new PATH_CHALLENGE hits the black
# hole immediately.
echo ""
echo "=== Forcing fresh validation on Path A (link down/up, address kept) ==="
ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" down
sleep 2

# Mark the log just before link-up so all assertions look only at the
# fresh validation cycle, never the initial connection-time validation.
LINKUP_MARK=$(wc -l <"${WORK_DIR}/client.log")
ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
LINKUP_TS=$(date +%s)

# ─── Assertion 1: challenge abandoned, slot -> CREATE_WAIT ───
# xquic WARN: "|G-P3 validation timeout|path_id:N|attempts:M|"
# mqvpn DEBUG: "path[handle=N name=veth-a0-vb] VALIDATING -> CREATE_WAIT reason=XQUIC_REMOVED ..."
if ! wait_for_log_after "${WORK_DIR}/client.log" \
        "G-P3 validation timeout" "$LINKUP_MARK" 20; then
    echo "=== FAIL: black-holed PATH_CHALLENGE was not abandoned (no G-P3 timeout) ==="
    echo "--- Client log (post-link-up) ---"
    tail -n "+$((LINKUP_MARK + 1))" "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: black-holed challenge abandoned with G-P3 validation timeout"

# Locate the first G-P3 line: the CREATE_WAIT check is anchored there
# (only the abandon-driven transition may satisfy it), and assertion 2
# counts the challenge sends leading up to it.
GP3_REL=$(tail -n "+$((LINKUP_MARK + 1))" "${WORK_DIR}/client.log" \
    | grep -nE "G-P3 validation timeout" | head -1 | cut -d: -f1)
GP3_LINE=$((LINKUP_MARK + GP3_REL))

if ! wait_for_log_after "${WORK_DIR}/client.log" \
        "name=${VETH_A0}\].*-> CREATE_WAIT.*reason=XQUIC_REMOVED" "$GP3_LINE" 10; then
    echo "=== FAIL: no abandon-driven -> CREATE_WAIT (reason=XQUIC_REMOVED) for ${VETH_A0} ==="
    echo "--- Client log (post-link-up) ---"
    tail -n "+$((LINKUP_MARK + 1))" "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: FSM transitioned Path A to CREATE_WAIT (reason=XQUIC_REMOVED)"

# ─── Assertion 2: challenge retransmitted at PTO cadence ───
# Count PATH_CHALLENGE packet-SEND lines (xquic send marker "|<==|")
# between link-up and the first G-P3 line, so receive/loss lines that
# also mention PATH_CHALLENGE cannot inflate the count. Expect >= 3
# (the initial send plus PTO retransmits before the path is abandoned).
CHALLENGE_COUNT=$(sed -n "$((LINKUP_MARK + 1)),${GP3_LINE}p" \
    "${WORK_DIR}/client.log" \
    | grep -cE "\|<==\|.*frame:.*PATH_CHALLENGE" || true)
echo "Path A PATH_CHALLENGE sends before abandon: ${CHALLENGE_COUNT}"
if [ "${CHALLENGE_COUNT:-0}" -lt 3 ]; then
    echo "=== FAIL: expected >= 3 PATH_CHALLENGE retransmits, saw ${CHALLENGE_COUNT} ==="
    echo "--- Client log (post-link-up) ---"
    tail -n "+$((LINKUP_MARK + 1))" "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: PATH_CHALLENGE retransmitted at PTO cadence"

# Hold the black hole in place until ~25s after link-up so the slot has
# cycled through a couple of backoff retries (5s, 10s, ...) and is still
# within the retry budget, then remove it.
NOW_TS=$(date +%s)
REMAIN=$((25 - (NOW_TS - LINKUP_TS)))
if [ "$REMAIN" -gt 0 ]; then
    echo "Holding black hole ${REMAIN}s more (let a couple of retries burn)..."
    sleep "$REMAIN"
fi

echo ""
echo "=== Removing black hole on Path A ==="
REMOVAL_MARK=$(wc -l <"${WORK_DIR}/client.log")
ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_A1" root netem || true
echo "OK: black hole removed"

# ─── Assertion 3 (recovery): path returns after the black hole lifts ───
# A post-removal retry re-validates Path A: either the FSM logs
# "... -> (ACTIVE|STANDBY)" or the activation INFO
# "path[N] activated: ... iface=veth-a0-vb state=(ACTIVE|STANDBY)".
RECOVER_PATTERN="activated:.*iface=${VETH_A0}.*state=(ACTIVE|STANDBY)|name=${VETH_A0}\].*-> (ACTIVE|STANDBY)"
if wait_for_log_after "${WORK_DIR}/client.log" "$RECOVER_PATTERN" "$REMOVAL_MARK" 45; then
    echo "OK: Path A recovered to ACTIVE/STANDBY after black hole lifted"
else
    echo "=== FAIL: Path A did not recover within 45s of black-hole removal ==="
    echo "--- Client log (post-removal) ---"
    tail -n "+$((REMOVAL_MARK + 1))" "${WORK_DIR}/client.log"
    exit 1
fi

if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "OK: tunnel ping works after Path A recovery"
else
    echo "=== FAIL: Tunnel ping failed after Path A recovery ==="
    echo "--- Client log ---"
    cat "${WORK_DIR}/client.log"
    exit 1
fi

echo ""
echo "=== All validation black-hole tests PASSED ==="
