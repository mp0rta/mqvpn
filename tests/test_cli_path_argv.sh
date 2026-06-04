#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# test_cli_path_argv.sh — Verify mqvpn CLI --path overflow handling.
#
# Asserts that passing MQVPN_MAX_PATH_IFACES + 1 --path flags is rejected
# with the expected error and non-zero exit, without ever reaching the
# connection setup phase.

set -u

MQVPN="${1:-${MQVPN:-./mqvpn}}"

if [ ! -x "$MQVPN" ]; then
    echo "FAIL: mqvpn binary not found or not executable: $MQVPN" >&2
    exit 1
fi

# Discover the configured cap by asking for one too many. We mirror the
# expected message format from src/main.c:248. The cap value is the only
# number the binary will quote in this message.
out=$("$MQVPN" --mode client --server 127.0.0.1:443 --insecure \
    --path lo --path lo --path lo --path lo --path lo \
    --path lo --path lo --path lo --path lo 2>&1)
rc=$?

if [ "$rc" -eq 0 ]; then
    echo "FAIL: 9 --path args were accepted (expected non-zero exit)" >&2
    echo "$out" >&2
    exit 1
fi

if ! echo "$out" | grep -qE 'error: max [0-9]+ paths supported'; then
    echo "FAIL: expected 'error: max N paths supported' in stderr, got:" >&2
    echo "$out" >&2
    exit 1
fi

# Extract the cap and require it matches the build-time constant 8.
cap=$(echo "$out" | sed -nE 's/.*error: max ([0-9]+) paths supported.*/\1/p' | head -n1)
if [ "$cap" != "8" ]; then
    echo "FAIL: expected cap=8, got cap=$cap" >&2
    exit 1
fi

echo "PASS: 9 --path args rejected with 'max 8 paths supported'"
exit 0
