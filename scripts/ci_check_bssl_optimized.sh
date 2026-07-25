#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# Fail if BoringSSL was built without CMAKE_BUILD_TYPE=Release.
#
# BoringSSL's CMakeLists sets no default build type. With CMAKE_BUILD_TYPE
# empty, CMAKE_C_FLAGS_RELEASE never applies (so the library compiles at -O0
# with asserts live) and its `NOT CMAKE_BUILD_TYPE MATCHES "rel"` guard
# additionally defines BORINGSSL_DISPATCH_TEST, which instruments the AES/GCM
# dispatch entry points. Measured cost on the netns harness: ~21% VPN
# throughput, and ~7x on X25519 (pure C, no asm path).
#
# Both failure modes leave the same fingerprint: BORINGSSL_function_hit, the
# dispatch-test flag array, exists only in a non-"rel" build. Checking for it
# in the built archive catches the mistake wherever it comes from — a missing
# flag, or a stale cache restored from before the flag was added.
#
# Usage: ci_check_bssl_optimized.sh <boringssl-build-dir>
set -euo pipefail

BUILD_DIR="${1:?usage: ci_check_bssl_optimized.sh <boringssl-build-dir>}"

# Newer BoringSSL layouts place the archives at the build root; older ones use
# crypto/ + ssl/ subdirs (same probe order as CMakeLists.txt and build.sh).
if [ -f "$BUILD_DIR/crypto/libcrypto.a" ]; then
    ARCHIVE="$BUILD_DIR/crypto/libcrypto.a"
elif [ -f "$BUILD_DIR/libcrypto.a" ]; then
    ARCHIVE="$BUILD_DIR/libcrypto.a"
else
    echo "ERROR: libcrypto.a not found under $BUILD_DIR" >&2
    exit 1
fi

SYMS="$(mktemp)"
trap 'rm -f "$SYMS"' EXIT

# No `nm ... | grep -q`: grep would exit at the first match and leave nm
# writing into a closed pipe (SIGPIPE), which under `set -o pipefail` turns a
# successful check into a spurious failure.
nm "$ARCHIVE" > "$SYMS" 2>/dev/null || true

# An empty or unreadable symbol table would make the grep below pass
# vacuously — the exact way a canary check rots into a no-op.
if [ "$(wc -l < "$SYMS")" -lt 100 ]; then
    echo "ERROR: could not read symbols from $ARCHIVE — check cannot run" >&2
    exit 1
fi

if grep -q "BORINGSSL_function_hit" "$SYMS"; then
    echo "ERROR: $ARCHIVE was built without CMAKE_BUILD_TYPE=Release." >&2
    echo "       BORINGSSL_DISPATCH_TEST instrumentation is compiled in, which" >&2
    echo "       means the library is also unoptimized (-O0)." >&2
    echo "       Fix: pass -DCMAKE_BUILD_TYPE=Release to BoringSSL's cmake, and" >&2
    echo "       bump the BoringSSL/xquic cache keys if a CI cache is involved." >&2
    exit 1
fi

echo "OK: $ARCHIVE is an optimized BoringSSL build"
