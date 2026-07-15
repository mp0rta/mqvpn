#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# check_ndebug_guard.sh — CI runs ctest on a Release (-DNDEBUG) build too,
# which silently no-ops assert(). Any tests/test_*.c file that relies on a
# bare assert(...) call must #undef NDEBUG before it, or its checks vanish
# under Release. This gate fails the build if one is missing that guard.

set -u

TESTS_DIR="${1:-$(dirname "$0")}"
fail=0

for f in "$TESTS_DIR"/test_*.c; do
    [ -e "$f" ] || continue
    # Bare assert(<non-empty-args>) call site, excluding _Static_assert(...)
    # and comment mentions of the empty-arg form "assert()".
    if grep -qE '\bassert\([^)]' "$f"; then
        if ! grep -q '#undef NDEBUG' "$f"; then
            echo "FAIL: $f uses assert() but is missing '#undef NDEBUG'" >&2
            fail=1
        fi
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "OK: all tests/test_*.c files using assert() guard against NDEBUG"
fi

exit "$fail"
