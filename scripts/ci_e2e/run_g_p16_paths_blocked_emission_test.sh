#!/bin/bash
# run_g_p16_paths_blocked_emission_test.sh — E2E test for the
# PR7 (receive auto-grant) + PR8 (G-P16 PATHS_BLOCKED send-side)
# closed loop, exercised via a carrier-flap stress scenario.
#
# Background
# ----------
# Per draft-21 §4.5, abandoned path_ids are NEVER recycled. mqvpn
# allocates the next unused path_id every time a path is added. The
# xquic default init_max_path_id is 8 (XQC_DEFAULT_INIT_MAX_PATH_ID),
# so after enough alternating carrier flaps the next requested
# path_id will exceed the cap and Stage 1 reject fires.
#
# The closed loop being validated:
#   1. mqvpn client adds path -> xquic Stage 1 reject (path_id > cap)
#   2. xquic G-P16 send-side emits PATHS_BLOCKED toward server
#      (log marker: "|PATHS_BLOCKED sent|")
#   3. xquic server PR7 auto-grant observes PATHS_BLOCKED and emits
#      MAX_PATH_ID grant (mqvpn-server enables this via
#      conn_settings.max_path_id_grant_max_value = 64 since PR8).
#      Log marker: "|MAX_PATH_ID auto-grant|new_local_max:..."
#   4. Client recv processes MAX_PATH_ID, next path creation
#      succeeds, tunnel stays alive.
#
# Topology (dual-path multipath; mirrors run_carrier_flap_test.sh):
#   vpn-client                   vpn-server
#     veth-a0 ─────────────────── veth-a1       Path A (10.100.0.0/24)
#     veth-b0 ─────────────────── veth-b1       Path B (10.200.0.0/24)
#
# Usage: sudo ./run_g_p16_paths_blocked_emission_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

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

MQVPN="${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    echo "Build first: mkdir build && cd build && cmake .. && make"
    exit 1
fi

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

# Unique names so this test runs alongside other e2e tests
NS_SERVER="vpn-server-gp16"
NS_CLIENT="vpn-client-gp16"
VETH_A0="veth-a0-gp16"
VETH_A1="veth-a1-gp16"
VETH_B0="veth-b0-gp16"
VETH_B1="veth-b1-gp16"

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

# ─── Setup ───
PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-gp16-paths-blocked-test" 2>/dev/null

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
if ! wait_for_log "${WORK_DIR}/client.log" "path.*activated|state=ACTIVE" 15; then
    echo "=== FAIL: Secondary path not activated within 15s ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: dual-path active"

# =================================================================
#  Stress loop: 8 alternating carrier flaps (server-side veth)
#
#  Each flap = path drop + path re-add, consuming one new path_id
#  (draft-21 §4.5: path_ids are never recycled). With xquic default
#  init_max_path_id = 8, by ~cycle 7-8 the next requested path_id
#  reaches the cap, triggering G-P16 PATHS_BLOCKED send-side.
#
#  We toggle the SERVER end of the veth pair (mirrors
#  run_carrier_flap_test.sh) so client-side observes the carrier
#  drop / restore path that is_carrier_loss() in platform_linux.c
#  gates on.
# =================================================================

echo ""
echo "=== Stress: 8 alternating carrier flaps to exhaust path_id space ==="

for cycle in $(seq 1 8); do
    if [ $((cycle % 2)) -eq 1 ]; then
        PATH_END="$VETH_A1"
        LABEL="A"
    else
        PATH_END="$VETH_B1"
        LABEL="B"
    fi
    echo "  cycle ${cycle}/8: flap ${LABEL} (${PATH_END})"
    ip netns exec "$NS_SERVER" ip link set "$PATH_END" down
    sleep 2
    ip netns exec "$NS_SERVER" ip link set "$PATH_END" up
    sleep 3
done

# Allow time for the final PATHS_BLOCKED emit + optional grant
# round-trip to settle into the log file.
sleep 5

# =================================================================
#  Assertions — the closed loop
# =================================================================

echo ""
echo "=== Assertions ==="
PASS=0
FAIL=0

# A1 (hard) — G-P16 client-side PATHS_BLOCKED emission. The exact
# substring is load-bearing per xquic L5e Task 1.4 log wording at
# src/transport/xqc_multipath.c:224.
if grep -q '|PATHS_BLOCKED sent|' "${WORK_DIR}/client.log"; then
    echo "A1 PASS: G-P16 PATHS_BLOCKED sent (client emit)"
    PASS=$((PASS + 1))
else
    echo "A1 FAIL: '|PATHS_BLOCKED sent|' not found in client.log"
    echo "  (This may indicate the 8 flaps did not exhaust the path_id"
    echo "   space, e.g. recovery timer did not re-add every dropped slot,"
    echo "   or the 3s/cycle pacing was too tight.)"
    FAIL=$((FAIL + 1))
fi

# A2 (hard) — server-side MAX_PATH_ID auto-grant (PR7 receive-side
# closed-loop counterpart). mqvpn-server enables this in PR8 via
# conn_settings.max_path_id_grant_max_value = 64 (mqvpn_server.c).
# Log wording at xqc_frame.c:2440:
#   "|MAX_PATH_ID auto-grant|new_local_max:%ui|"
if grep -q '|MAX_PATH_ID auto-grant|' "${WORK_DIR}/server.log"; then
    echo "A2 PASS: server PR7 MAX_PATH_ID auto-grant fired"
    PASS=$((PASS + 1))
else
    echo "A2 FAIL: '|MAX_PATH_ID auto-grant|' not in server.log"
    echo "  (PR7 auto-grant should fire after client PATHS_BLOCKED.)"
    FAIL=$((FAIL + 1))
fi

# A3 (hard) — tunnel must survive the entire flap storm.
if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "A3 PASS: tunnel still reachable after 8-flap stress"
    PASS=$((PASS + 1))
else
    echo "A3 FAIL: tunnel ping failed after 8-flap stress"
    echo "--- last 60 lines of client.log ---"
    tail -n 60 "${WORK_DIR}/client.log" || true
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=== Summary: PASS=${PASS} FAIL=${FAIL} ==="

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
echo "=== G-P16 PATHS_BLOCKED emission test PASSED ==="
