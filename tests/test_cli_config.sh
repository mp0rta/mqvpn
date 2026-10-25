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

for address in '127.0.0.1:443oops' '127.0.0.1:70000' '127.0.0.1:4294967739' '[::1]:443oops'; do
    printf '[Server]\nAddress=%s\n' "$address" >"$tmp/client.ini"
    expect_error "error: invalid server address '$address': use HOST:PORT or [IPv6]:PORT, port 1-65535" \
        --config "$tmp/client.ini"
    printf '[Interface]\nListen=%s\n[Auth]\nKey=test\n' "$address" >"$tmp/server.ini"
    expect_error "error: invalid listen address '$address': use HOST:PORT or [IPv6]:PORT, port 1-65535" \
        --config "$tmp/server.ini"
done

# The CLI address must reach address validation, even without an INI Address.
printf '[Interface]\nMTU=1400\n' >"$tmp/common.ini"
expect_error "error: invalid server address 'host:bad'" --config "$tmp/common.ini" --server host:bad
expect_error "error: invalid listen address 'host:70000'" \
    --mode server --auth-key test --listen host:70000

printf -v name '%064d' 0
expect_error 'error: --user name exceeds 63 bytes' --mode server --user "$name:key"

# Invalid JSON users must explain the failure before startup, in either form.
for bad in '{"users":"x"}' \
           "{\"users\":[{\"name\":\"$name\",\"key\":\"k\"}]}" \
           "{\"users\":[\"$name:k\"]}"; do
    printf '%s' "$bad" >"$tmp/users.json"
    expect_error 'config: invalid "users"' --config "$tmp/users.json"
done

# UTF-16LE with a BOM must identify the file and tell the user how to save it.
printf '\377\376[\000S\000e\000r\000v\000e\000r\000]\000' >"$tmp/utf16.ini"
expect_error "$tmp/utf16.ini: contains a NUL byte at offset 3; save the file as UTF-8 (not UTF-16)" \
    --config "$tmp/utf16.ini"
echo 'PASS: endpoint, username and file encoding diagnostics'
