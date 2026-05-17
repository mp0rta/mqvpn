#!/bin/bash
# run_g_p14_path_abandon_altpath_test.sh -- DEFERRED to PR8.
#
# G-P14 (PATH_ABANDON via alt-path) cannot be exercised via netns link-down
# on Linux because RTM_DELLINK invokes drop_path() (silent local removal, no
# PATH_ABANDON wire frame), not remove_path(). This is intentional design --
# see memory/feedback_xquic_close_path.md and
# memory/feedback_path_lifecycle_per_platform.md (drop_path avoids blocking
# surviving paths during xquic orderly shutdown).
#
# Current PR7 coverage:
#   - helper logic: xquic-side unit tests
#     xqc_test_mp21_gp14_pick_alt_active_path[_single]
#   - call-site wiring: code review only
#   - wire emission: UNTESTED
#
# PR8 will add:
#   - xquic-side: call-site unit test using engine-equipped fixture so the
#     PATH_ABANDON write path is exercised end-to-end in unit scope.
#   - mqvpn-side: test-only mqvpn_client_test_remove_path() hook that maps
#     to remove_path() (not drop_path()), plus a netns e2e that observes
#     PATH_ABANDON on the alt-path veth.
#
# Until then this script intentionally short-circuits to SKIP so CI is not
# misled by a structurally-impossible failure. The original netns body is
# preserved (commented out) below for PR8 revival.
#
# Usage: sudo ./run_g_p14_path_abandon_altpath_test.sh [mqvpn-binary] [--log-level LEVEL]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""

while [ $# -gt 0 ]; do
    case "$1" in
        --log-level) shift 2 ;;
        *) [ -z "$MQVPN" ] && MQVPN="$1"; shift ;;
    esac
done

MQVPN="${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}"
[ -f "$MQVPN" ] || { echo "error: mqvpn binary not found at $MQVPN"; exit 1; }

echo "SKIP: G-P14 e2e deferred to PR8 (Linux drop_path design; see"
echo "      feedback_xquic_close_path.md). xquic-side helper unit tests"
echo "      xqc_test_mp21_gp14_pick_alt_active_path[_single] cover the"
echo "      selection logic in PR7 scope; call-site wiring + wire-level"
echo "      PATH_ABANDON emission will be tested in PR8."
exit 0

# ---------------------------------------------------------------------------
# Original test body retained for PR8 revival. Do NOT delete -- PR8 will add a
# test-only mqvpn_client_test_remove_path() hook and re-enable this scenario.
# ---------------------------------------------------------------------------
#
# source "$(dirname "$0")/sanitizer_check.sh"
#
# LOG_LEVEL="debug"   # need DEBUG: 'path abandon|path_id' is XQC_LOG_DEBUG
# WORK_DIR="$(mktemp -d)"
#
# NS_SERVER="vpn-server-gp14"
# NS_CLIENT="vpn-client-gp14"
# VETH_A0="veth-a0-gp14"
# VETH_A1="veth-a1-gp14"
# VETH_B0="veth-b0-gp14"
# VETH_B1="veth-b1-gp14"
#
# IP_A_CLIENT="10.114.0.2/24"
# IP_A_SERVER="10.114.0.1/24"
# IP_B_CLIENT="10.214.0.2/24"
# IP_B_SERVER="10.214.0.1/24"
# SERVER_ADDR="10.114.0.1"
# TUNNEL_IP="10.0.0.1"
#
# SERVER_PID=""
# CLIENT_PID=""
# SANITIZER_FAIL=0
# PASS=0
# FAIL=0
#
# cleanup_processes() {
#     stop_and_check_sanitizer "$CLIENT_PID" "client" "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
#     stop_and_check_sanitizer "$SERVER_PID" "server" "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
#     SERVER_PID=""
#     CLIENT_PID=""
#     sleep 1
# }
#
# cleanup() {
#     echo ""
#     echo "Cleaning up..."
#     cleanup_processes
#     ip netns del "$NS_SERVER" 2>/dev/null || true
#     ip netns del "$NS_CLIENT" 2>/dev/null || true
#     ip link del "$VETH_A0" 2>/dev/null || true
#     ip link del "$VETH_B0" 2>/dev/null || true
#     rm -rf "$WORK_DIR"
#     if [ "$SANITIZER_FAIL" -ne 0 ]; then
#         echo "FAIL: sanitizer errors detected"
#         exit 1
#     fi
# }
# trap cleanup EXIT
#
# ip netns del "$NS_SERVER" 2>/dev/null || true
# ip netns del "$NS_CLIENT" 2>/dev/null || true
# ip link del "$VETH_A0" 2>/dev/null || true
# ip link del "$VETH_B0" 2>/dev/null || true
#
# PSK=$("$MQVPN" --genkey 2>/dev/null)
# openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
#     -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
#     -days 365 -nodes -subj "/CN=mqvpn-gp14-test" 2>/dev/null
#
# ip netns add "$NS_SERVER"
# ip netns add "$NS_CLIENT"
# ip link add "$VETH_A0" type veth peer name "$VETH_A1"
# ip link set "$VETH_A0" netns "$NS_CLIENT"
# ip link set "$VETH_A1" netns "$NS_SERVER"
# ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0"
# ip netns exec "$NS_SERVER" ip addr add "$IP_A_SERVER" dev "$VETH_A1"
# ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
# ip netns exec "$NS_SERVER" ip link set "$VETH_A1" up
# ip link add "$VETH_B0" type veth peer name "$VETH_B1"
# ip link set "$VETH_B0" netns "$NS_CLIENT"
# ip link set "$VETH_B1" netns "$NS_SERVER"
# ip netns exec "$NS_CLIENT" ip addr add "$IP_B_CLIENT" dev "$VETH_B0"
# ip netns exec "$NS_SERVER" ip addr add "$IP_B_SERVER" dev "$VETH_B1"
# ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" up
# ip netns exec "$NS_SERVER" ip link set "$VETH_B1" up
# ip netns exec "$NS_CLIENT" ip link set lo up
# ip netns exec "$NS_SERVER" ip link set lo up
# ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null
# ip netns exec "$NS_SERVER" ip addr add "${SERVER_ADDR}/32" dev lo
# ip netns exec "$NS_CLIENT" ip route add 10.114.0.0/24 via 10.214.0.1 dev "$VETH_B0" metric 200
# ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$SERVER_ADDR" >/dev/null
# ip netns exec "$NS_CLIENT" ping -c 1 -W 1 10.214.0.1 >/dev/null
#
# ip netns exec "$NS_SERVER" "$MQVPN" \
#     --mode server \
#     --listen "0.0.0.0:4433" \
#     --subnet 10.0.0.0/24 \
#     --cert "${WORK_DIR}/server.crt" \
#     --key "${WORK_DIR}/server.key" \
#     --auth-key "$PSK" \
#     --scheduler min_srtt \
#     --log-level "$LOG_LEVEL" > "${WORK_DIR}/server.log" 2>&1 &
# SERVER_PID=$!
# sleep 2
# if ! kill -0 "$SERVER_PID" 2>/dev/null; then
#     echo "  FAIL: server died"; cat "${WORK_DIR}/server.log"; FAIL=$((FAIL + 1))
# else
#     ip netns exec "$NS_CLIENT" "$MQVPN" \
#         --mode client \
#         --server "${SERVER_ADDR}:4433" \
#         --path "$VETH_A0" --path "$VETH_B0" \
#         --auth-key "$PSK" \
#         --insecure \
#         --scheduler min_srtt \
#         --log-level "$LOG_LEVEL" > "${WORK_DIR}/client.log" 2>&1 &
#     CLIENT_PID=$!
#     sleep 3
#
#     if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
#         echo "  FAIL: client died"; cat "${WORK_DIR}/client.log"; FAIL=$((FAIL + 1))
#     else
#         # Wait for both paths established
#         TUNNEL_OK=0
#         for i in $(seq 1 30); do
#             if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
#                 TUNNEL_OK=1; break
#             fi
#             sleep 1
#         done
#
#         if [ "$TUNNEL_OK" -ne 1 ]; then
#             echo "  FAIL: tunnel never reachable"
#             tail -40 "${WORK_DIR}/client.log"
#             FAIL=$((FAIL + 1))
#         else
#             # Give path_id=1 a beat to be validated (STANDBY/AVAILABLE)
#             sleep 2
#
#             echo "=== Test: G-P14 PATH_ABANDON via alt-path ==="
#             echo "  Bringing veth-a0-gp14 down inside client netns..."
#             ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" down
#
#             # Wait up to 10s for server to log PATH_ABANDON receipt for path_id=0
#             ABANDON_OK=0
#             for i in $(seq 1 10); do
#                 if grep -qE "path abandon\|path_id:0\b" "${WORK_DIR}/server.log"; then
#                     ABANDON_OK=1; break
#                 fi
#                 sleep 1
#             done
#
#             if [ "$ABANDON_OK" -eq 1 ]; then
#                 echo "  PASS: server received PATH_ABANDON for path_id=0 via alt-path"
#                 PASS=$((PASS + 1))
#             else
#                 echo "  FAIL: PATH_ABANDON for path_id=0 not observed within 10s"
#                 echo "  --- server.log (last 80 lines) ---"
#                 tail -80 "${WORK_DIR}/server.log"
#                 FAIL=$((FAIL + 1))
#             fi
#         fi
#     fi
# fi
#
# echo ""
# echo "================================================="
# echo " Results: PASS=$PASS  FAIL=$FAIL"
# echo "================================================="
# [ "$FAIL" -eq 0 ]
