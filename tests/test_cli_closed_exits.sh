#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# test_cli_closed_exits.sh — a client that reaches CLOSED by itself must exit.
#
# CLOSED that no shutdown asked for means the connection ended and the library
# will not retry it (--no-reconnect here; a rejected certificate does the same).
# The client used to stay in its event loop on a dead client until signalled;
# a supervisor (systemd, the desktop GUI) then never saw the failure. It must
# exit non-zero and say why.
#
# Getting into CLOSED without root, a server or a TUN: --no-reconnect plus a
# server address nothing answers on; the handshake is abandoned and
# cb_h3_conn_close takes its no-retry branch.
#
# Usage: test_cli_closed_exits.sh [path-to-mqvpn-binary]

set -u

MQVPN="${1:-${MQVPN:-./mqvpn}}"
# Any UDP port on loopback that does not answer with QUIC will do. If something
# on a CI image does answer, the client never reaches CLOSED and the test fails
# below saying that — a wrong guess is loud, not a silently different scenario.
PORT="${MQVPN_TEST_DEAD_PORT:-39547}"
EXIT_WAIT=40 # seconds to wait for the failed handshake and the exit

if [ ! -x "$MQVPN" ]; then
    echo "FAIL: mqvpn binary not found or not executable: $MQVPN" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d)"
LOG="${WORK_DIR}/client.log"
PID=""

cleanup() {
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill -KILL "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

"$MQVPN" --mode client --server "127.0.0.1:${PORT}" --insecure --no-reconnect \
    --log-level info >"$LOG" 2>&1 &
PID=$!

for _ in $(seq 1 $((EXIT_WAIT * 2))); do
    sleep 0.5
    kill -0 "$PID" 2>/dev/null || break
done

if kill -0 "$PID" 2>/dev/null; then
    if grep -qE '\[INF\] state: .* CLOSED$' "$LOG"; then
        echo "FAIL: client reached CLOSED but is still running" >&2
    else
        echo "FAIL: client never reached CLOSED within ${EXIT_WAIT}s" >&2
        echo "       (is something answering UDP ${PORT}? set MQVPN_TEST_DEAD_PORT)" >&2
    fi
    tail -20 "$LOG" >&2
    exit 1
fi

wait "$PID" 2>/dev/null
status=$?
PID=""

# exit 1 with the line, not a crash (ASan/UBSan exit 1 too, without it)
if ! grep -q 'exiting: connection closed' "$LOG"; then
    echo "FAIL: client exited (status ${status}) without 'exiting: connection closed'" >&2
    tail -20 "$LOG" >&2
    exit 1
fi
if [ "$status" -ne 1 ]; then
    echo "FAIL: client exited with status ${status} at CLOSED, want 1" >&2
    tail -20 "$LOG" >&2
    exit 1
fi

echo "PASS: client exited by itself at CLOSED (exit ${status})"
exit 0
