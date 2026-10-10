#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# check_buf_limits_bridged.sh — the [Advanced] buffer limits are set on BOTH
# sides, and there are two CLI→library bridges: the shared client one
# (src/platform/client_config_bridge.c) and the server run loop's own block
# (linux_platform_run_server, src/platform/linux/platform_linux.c).
#
# tests/test_config_bridge.c covers the client bridge because it is a plain
# function. The server block sits inside a run loop that opens a TUN and binds
# a socket, so no unit test reaches it; this source gate stands in. Same shape
# as check_ndebug_guard.sh.

set -u

SRC_DIR="${1:-$(dirname "$0")/../src}"
BRIDGE_FN="mqvpn_config_set_buf_limits"
fail=0

for f in "$SRC_DIR/platform/client_config_bridge.c" \
         "$SRC_DIR/platform/linux/platform_linux.c"; do
    if [ ! -e "$f" ]; then
        echo "FAIL: $f not found (moved? update this gate)" >&2
        fail=1
        continue
    fi
    # A real call, not a comment: the name followed by '(' with a non-comment
    # line start. Comments in both files mention the function by name.
    if ! grep -qE "^[[:space:]]*${BRIDGE_FN}[[:space:]]*\(" "$f"; then
        echo "FAIL: $f does not call ${BRIDGE_FN}() — the [Advanced] buffer" >&2
        echo "      limits would reach only one side of the tunnel." >&2
        fail=1
    fi
done

# mqvpn_client.c and mqvpn_server.c each build their own
# mqvpn_conn_settings_input_t, both inside functions that create an xquic
# engine, and neither is reachable from a unit test.
for f in "$SRC_DIR/mqvpn_client.c" "$SRC_DIR/mqvpn_server.c"; do
    if [ ! -e "$f" ]; then
        echo "FAIL: $f not found (moved? update this gate)" >&2
        fail=1
        continue
    fi
    for field in h3_body_buf_per_stream blocked_buf_per_stream blocked_buf_per_conn \
                 max_recv_window; do
        if ! grep -qE "^[[:space:]]*\.${field}[[:space:]]*=" "$f"; then
            echo "FAIL: $f builds mqvpn_conn_settings_input_t without .${field} —" >&2
            echo "      that [Advanced] buffer limit would never leave the config." >&2
            fail=1
        fi
    done
done

# The four keys sit outside the is_server if/else in the builder. Assert the
# structural half: the builder assigns them after that if/else closes.
BUILDER="$SRC_DIR/mqvpn_conn_settings.c"
if [ -e "$BUILDER" ]; then
    rate_line=$(grep -n 'out->recv_rate_bytes_per_sec' "$BUILDER" | head -1 | cut -d: -f1)
    buf_line=$(grep -n 'out->max_body_buf_per_stream' "$BUILDER" | head -1 | cut -d: -f1)
    close_line=$(grep -n '^    }$' "$BUILDER" | awk -F: -v r="${rate_line:-0}" \
                 '$1 > r { print $1; exit }')
    if [ -z "${buf_line:-}" ] || [ -z "${close_line:-}" ]; then
        echo "FAIL: $BUILDER — cannot locate the buffer-limit assignment" >&2
        fail=1
    elif [ "$buf_line" -lt "$close_line" ]; then
        echo "FAIL: $BUILDER assigns max_body_buf_per_stream at line $buf_line," >&2
        echo "      inside the is_server branch that closes at $close_line." >&2
        echo "      These four are cross-cutting; only recv_rate is client-only." >&2
        fail=1
    fi
else
    echo "FAIL: $BUILDER not found (moved? update this gate)" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "OK: [Advanced] buffer limits bridged on both sides and set outside the"
    echo "    client/server split"
fi

exit "$fail"
