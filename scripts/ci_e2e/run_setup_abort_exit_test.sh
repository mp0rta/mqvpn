#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_setup_abort_exit_test.sh — a client whose tunnel setup aborts must exit
#
# cb_tunnel_config_ready()'s fail: path runs when the platform cannot build
# the tunnel the server just handed it — TUN creation, addressing, routes or
# the kill switch. It used to disconnect and stay in the event loop: no
# tunnel, no retry (mqvpn_client_disconnect() is a user disconnect, so
# cb_h3_conn_close's Reconnect branch is skipped) and no exit, so
# Restart=on-failure never fired. It now exits non-zero and lets the
# supervisor decide.
#
# The trigger here is TUN creation: --tun-name names a device that already
# exists in the client namespace, so TUNSETIFF fails with EINVAL. It fires
# after the handshake, inside the callback, on every kernel and libc — no
# missing binary, no timing. Test 1 is the control: an ordinary client on the
# same rig comes up and stays up.
#
# Runs in both e2e jobs, including the sanitizer one: the abort path reaches
# exit() for the first time, so that is where a leak on it would show. The
# aborting client is the one process in the suite whose exit status is the
# assertion, so it is kept away from stop_and_check_sanitizer (which reads any
# non-zero status as a sanitizer failure) and Test 2 checks the status and the
# sanitizer reports itself.
#
# Topology (same as run_test.sh):
#   vpn-client                vpn-server
#     veth-c ──────────────── veth-s
#     192.168.100.1/24        192.168.100.2/24
#
# Usage: sudo ./scripts/ci_e2e/run_setup_abort_exit_test.sh [path-to-mqvpn-binary]

set -e

source "$(dirname "$0")/sanitizer_check.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="${1:-${SCRIPT_DIR}/../../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    echo "Build first: mkdir build && cd build && cmake .. && make"
    exit 1
fi

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

# A device that already exists in the client namespace, for the client to
# collide with. A veth needs no module the rig is not already using.
BUSY_DEV="mqvpn-busy0"
EXIT_WAIT=20 # seconds the aborting client gets to exit on its own

SERVER_PID=""
CLIENT_PID=""
ABORT_PID=""
SANITIZER_FAIL=0

cleanup() {
    echo ""
    echo "Cleaning up..."
    # ABORT_PID is deliberately not passed to stop_and_check_sanitizer: it is
    # expected to have exited non-zero, which that helper reads as a sanitizer
    # failure. Test 2 asserts its status and scans its log instead.
    if [ -n "$ABORT_PID" ] && kill -0 "$ABORT_PID" 2>/dev/null; then
        kill -KILL "$ABORT_PID" 2>/dev/null || true
        wait "$ABORT_PID" 2>/dev/null || true
    fi
    stop_and_check_sanitizer "$CLIENT_PID" "client" "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    sleep 1
    ip netns del vpn-server 2>/dev/null || true
    ip netns del vpn-client 2>/dev/null || true
    ip link del veth-c 2>/dev/null || true
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

# Generate PSK
PSK=$("$MQVPN" --genkey 2>/dev/null)

# Generate self-signed cert
echo "Generating self-signed certificate..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-abort-test" 2>/dev/null

# Clean any leftover namespaces from previous runs
ip netns del vpn-server 2>/dev/null || true
ip netns del vpn-client 2>/dev/null || true
ip link del veth-c 2>/dev/null || true

echo "=== Setting up network namespaces ==="
ip netns add vpn-server
ip netns add vpn-client

ip link add veth-c type veth peer name veth-s
ip link set veth-c netns vpn-client
ip link set veth-s netns vpn-server

ip netns exec vpn-client ip addr add 192.168.100.1/24 dev veth-c
ip netns exec vpn-server ip addr add 192.168.100.2/24 dev veth-s
ip netns exec vpn-client ip link set veth-c up
ip netns exec vpn-server ip link set veth-s up
ip netns exec vpn-client ip link set lo up
ip netns exec vpn-server ip link set lo up

ip netns exec vpn-client ping -c 1 -W 1 192.168.100.2 >/dev/null
echo "OK: underlay veth pair working"

echo "=== Starting VPN server ==="
ip netns exec vpn-server "$MQVPN" \
    --mode server \
    --listen 192.168.100.2:4433 \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --log-level debug > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "=== FAIL: Server process died ==="
    cat "${WORK_DIR}/server.log"
    exit 1
fi
echo "Server running (PID $SERVER_PID)"

echo ""
echo "=== Test 1 (control): an ordinary client comes up and stays up ==="
ip netns exec vpn-client "$MQVPN" \
    --mode client \
    --server 192.168.100.2:4433 \
    --auth-key "$PSK" \
    --insecure \
    --log-level debug > "${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "=== Test 1 (control): FAIL — client exited ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi

if ! ip netns exec vpn-client ping -c 3 -W 2 10.0.0.1 >/dev/null; then
    echo "=== Test 1 (control): FAIL — no ping through the tunnel ==="
    cat "${WORK_DIR}/client.log"
    exit 1
fi
echo "OK: tunnel up, 10.0.0.1 answers, client still running"
echo "=== Test 1 (control): PASS ==="

stop_and_check_sanitizer "$CLIENT_PID" "client" "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
CLIENT_PID=""
sleep 1

echo ""
echo "=== Test 2: tunnel setup aborts -> the client exits non-zero ==="
ip netns exec vpn-client ip link add "$BUSY_DEV" type veth peer name "${BUSY_DEV}p"
echo "Created $BUSY_DEV in vpn-client; the client will ask for that TUN name"

ip netns exec vpn-client "$MQVPN" \
    --mode client \
    --server 192.168.100.2:4433 \
    --auth-key "$PSK" \
    --insecure \
    --tun-name "$BUSY_DEV" \
    --log-level debug > "${WORK_DIR}/abort.log" 2>&1 &
ABORT_PID=$!

gone=0
waited=0
while [ "$waited" -lt "$EXIT_WAIT" ]; do
    sleep 1
    waited=$((waited + 1))
    if ! kill -0 "$ABORT_PID" 2>/dev/null; then
        gone=1
        break
    fi
done

if [ "$gone" -ne 1 ]; then
    echo "=== Test 2: FAIL — client still running ${EXIT_WAIT}s after the abort ==="
    grep -E 'TUN create failed|\[INF\] state:' "${WORK_DIR}/abort.log" | tail -10
    exit 1
fi

# `wait` reports the client's exit status, which is the point of this test and
# non-zero when it passes — so it must not trip `set -e`.
ABORT_RC=0
wait "$ABORT_PID" 2>/dev/null || ABORT_RC=$?
ABORT_PID=""

# The abort has to be the one we arranged, and it has to happen in the
# tunnel-setup callback — not at argv parsing, and not before the handshake.
if ! grep -q "TUN create failed" "${WORK_DIR}/abort.log"; then
    echo "=== Test 2: FAIL — client exited, but not on the TUN create path ==="
    tail -20 "${WORK_DIR}/abort.log"
    exit 1
fi
if ! grep -qE 'state: AUTHENTICATING .* TUNNEL_READY' "${WORK_DIR}/abort.log"; then
    echo "=== Test 2: FAIL — client never reached TUNNEL_READY; the abort did"
    echo "    not come from cb_tunnel_config_ready ==="
    tail -20 "${WORK_DIR}/abort.log"
    exit 1
fi
if [ "$ABORT_RC" -ne 1 ]; then
    echo "=== Test 2: FAIL — aborted client exited ${ABORT_RC}, expected 1 ==="
    echo "    (0 means a supervisor cannot tell the start failed)"
    tail -20 "${WORK_DIR}/abort.log"
    exit 1
fi
if ! grep -q "exiting: tunnel setup failed" "${WORK_DIR}/abort.log"; then
    echo "=== Test 2: FAIL — exited 1 without the setup-failed line ==="
    tail -20 "${WORK_DIR}/abort.log"
    exit 1
fi
# ASan and UBSan also exit 1, and "exiting: tunnel setup failed" is printed
# before the process leaves main, so a sanitizer report lands *after* it in the
# same log: neither the status nor that line rules one out. Look for the
# reports themselves. This is the only e2e client whose status is asserted
# rather than handed to stop_and_check_sanitizer, so nothing else covers it.
SAN_RE='ERROR: (Address|Leak|Memory|Thread)Sanitizer|runtime error:|SUMMARY: (Address|Leak|Memory|Thread|Undefined)'
if grep -qE "$SAN_RE" "${WORK_DIR}/abort.log"; then
    echo "=== Test 2: FAIL — sanitizer diagnostic on the abort path ==="
    grep -nE "$SAN_RE" "${WORK_DIR}/abort.log" | head -5
    tail -40 "${WORK_DIR}/abort.log"
    exit 1
fi
_check_residence_warnings "abort client" "${WORK_DIR}/abort.log" || exit 1

echo "OK: exited ${ABORT_RC} after ${waited}s, on the fail: path, after TUNNEL_READY"
echo "=== Test 2: PASS ==="
