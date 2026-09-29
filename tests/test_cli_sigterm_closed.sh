#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# test_cli_sigterm_closed.sh — SIGTERM must stop a client that is already CLOSED.
#
# on_signal() sets shutting_down and calls mqvpn_client_disconnect(), which
# returns early when the state is already CLOSED or IDLE. When the loop's only
# exit was the CLOSED state callback, a client that had reached CLOSED on its
# own kept ticking through every SIGTERM and needed SIGKILL — systemd waits out
# TimeoutStopSec, and Restart=on-failure never sees the process exit.
#
# Getting into CLOSED without root, a server or a TUN: --no-reconnect plus a
# server address nothing answers on. The handshake fails at xquic's 10 s
# init_idle_time_out and cb_h3_conn_close takes its no-retry branch.
#
# That the client then stays in its event loop is setup, not the property under
# test, and this test does not claim it is right: run_killswitch_test.sh's
# Test 3 says the opposite ("with --no-reconnect the client exits and cleanup
# runs") and passes only because it carries a branch for either outcome. If a
# --no-reconnect client is ever made to exit here, this scenario loses its way
# into CLOSED and fails saying so — it does not quietly stop testing anything.
# The asserted property is narrower and independent of that: whatever state the
# client is in, SIGTERM must end the process.
#
# Usage: test_cli_sigterm_closed.sh [path-to-mqvpn-binary]

set -u

MQVPN="${1:-${MQVPN:-./mqvpn}}"
# Any UDP port on loopback that does not answer with QUIC will do. If something
# on a CI image does answer, the client never reaches CLOSED and the test fails
# below saying that — a wrong guess is loud, not a silently different scenario.
PORT="${MQVPN_TEST_DEAD_PORT:-39547}"
CLOSED_WAIT=40 # seconds to wait for the failed handshake (init_idle_time_out=10s)
TERM_GRACE=5   # seconds SIGTERM gets before the process is declared hung

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

# Wait for the client to reach CLOSED ("… [INF] state: CONNECTING → CLOSED").
closed=0
for _ in $(seq 1 $((CLOSED_WAIT * 2))); do
    sleep 0.5
    if grep -qE '\[INF\] state: .* CLOSED$' "$LOG"; then
        closed=1
        break
    fi
    kill -0 "$PID" 2>/dev/null || break
done

if [ "$closed" -ne 1 ]; then
    if kill -0 "$PID" 2>/dev/null; then
        echo "FAIL: client never reached CLOSED within ${CLOSED_WAIT}s" >&2
        echo "       (is something answering UDP ${PORT}? set MQVPN_TEST_DEAD_PORT)" >&2
    else
        echo "FAIL: client exited before reaching CLOSED" >&2
    fi
    tail -20 "$LOG" >&2
    exit 1
fi

if ! kill -0 "$PID" 2>/dev/null; then
    wait "$PID" 2>/dev/null
    echo "FAIL: client exited on its own at CLOSED (status $?) — this scenario" >&2
    echo "       has no way left into a state the client stays in, so it cannot" >&2
    echo "       exercise SIGTERM. If that exit is deliberate, give this test a" >&2
    echo "       new way into CLOSED or drop it; do not let it pass empty." >&2
    tail -20 "$LOG" >&2
    exit 1
fi

kill -TERM "$PID" 2>/dev/null || true

gone=0
waited=0
for _ in $(seq 1 $((TERM_GRACE * 2))); do
    sleep 0.5
    waited=$((waited + 1))
    if ! kill -0 "$PID" 2>/dev/null; then
        gone=1
        break
    fi
done

if [ "$gone" -ne 1 ]; then
    echo "FAIL: client still running ${TERM_GRACE}s after SIGTERM (state CLOSED)" >&2
    if grep -q 'received signal, shutting down' "$LOG"; then
        echo "       the handler ran — the event loop was not broken" >&2
    else
        echo "       the handler did not run — the signal never arrived" >&2
    fi
    tail -20 "$LOG" >&2
    exit 1
fi

wait "$PID" 2>/dev/null
status=$?
PID=""

# The process is gone; make sure the signal is what ended it, not a crash that
# happened to land in the same window.
if ! grep -q 'received signal, shutting down' "$LOG"; then
    echo "FAIL: client is gone but the signal handler never ran (status ${status})" >&2
    tail -20 "$LOG" >&2
    exit 1
fi
if [ "$status" -ne 0 ]; then
    echo "FAIL: client crashed or exited non-zero after SIGTERM (status ${status})" >&2
    tail -20 "$LOG" >&2
    exit 1
fi

echo "PASS: SIGTERM stopped the CLOSED client in $((waited * 500))ms (exit ${status})"
exit 0
