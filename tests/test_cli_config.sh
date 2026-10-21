#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors

# All cases fail before opening sockets or creating a TUN.
set -euo pipefail
MQVPN="$1"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

expect_error() {
    local message="$1"
    shift
    if "$MQVPN" "$@" >"$tmp/out" 2>&1; then
        echo "FAIL: invalid config was accepted" >&2
        exit 1
    fi
    if ! grep -Fq "$message" "$tmp/out"; then
        cat "$tmp/out" >&2
        echo "FAIL: expected $message" >&2
        exit 1
    fi
}

for address in '127.0.0.1:443oops' '127.0.0.1:4294967739' '[::1]:443oops'; do
    printf '[Server]\nAddress=%s\n' "$address" >"$tmp/client.ini"
    expect_error 'error: invalid address' --config "$tmp/client.ini"
    printf '[Interface]\nListen=%s\n[Auth]\nKey=test\n' "$address" >"$tmp/server.ini"
    expect_error 'error: invalid address' --config "$tmp/server.ini"
done

# The CLI address must reach address validation, even without an INI Address.
printf '[Interface]\nMTU=1400\n' >"$tmp/common.ini"
expect_error 'error: invalid address' --config "$tmp/common.ini" --server host:bad

printf -v name '%064d' 0
expect_error 'error: --user name exceeds 63 bytes' --mode server --user "$name:key"
echo 'PASS: strict endpoint parsing, CLI precedence and username length'
