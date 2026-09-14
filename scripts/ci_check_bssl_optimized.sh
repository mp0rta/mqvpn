#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# Fail if a BoringSSL build is not the fast configuration we ship: it must be
# an optimized (Release) build AND carry its assembly implementations.
#
# Check 1 — optimized build. BoringSSL's CMakeLists sets no default build
# type. With CMAKE_BUILD_TYPE empty, CMAKE_C_FLAGS_RELEASE never applies (so
# the library compiles at -O0 with asserts live) and its
# `NOT CMAKE_BUILD_TYPE MATCHES "rel"` guard additionally defines
# BORINGSSL_DISPATCH_TEST, which instruments the AES/GCM dispatch entry
# points. Measured cost on the netns harness: ~21% VPN throughput, and ~7x on
# X25519 (pure C, no asm path). Both failure modes leave the same
# fingerprint: BORINGSSL_function_hit, the dispatch-test flag array, exists
# only in a non-"rel" build.
#
# Check 2 — assembly present. Every per-packet primitive (AES-GCM, ChaCha20-
# Poly1305, header protection) is hand-written assembly selected at runtime;
# OPENSSL_NO_ASM, or a generator that cannot assemble BoringSSL's .S files,
# silently drops all of it and falls back to constant-time C (aes_nohw), at
# roughly 10-30x the per-byte cost. Check 1 does not see this: a NO_ASM
# build is still a Release build. BoringSSL exports the same entry points
# from both the x86_64 and the AArch64 assembly (aes_hw_set_encrypt_key,
# gcm_ghash_{clmul,v8}, ChaCha20_ctr32_{ssse3,neon}); Mach-O prefixes an
# underscore. 32-bit targets are not shipped and not covered.
#
# Checking the built archive catches the mistake wherever it comes from — a
# missing flag, a toolchain default, or a stale cache restored from before
# the flag was added.
#
# Usage: ci_check_bssl_optimized.sh <boringssl-build-dir>
#   NM=<tool>  symbol lister to use (default: nm). GNU nm reads any ELF64
#              archive via its generic target, so a foreign-arch archive
#              (e.g. the Android arm64 build on an x86_64 runner) normally
#              works; point NM at llvm-nm if a host nm cannot read it, and
#              on Windows (COFF .lib) use llvm-nm or a MinGW nm from bash.
set -euo pipefail

BUILD_DIR="${1:?usage: ci_check_bssl_optimized.sh <boringssl-build-dir>}"
NM="${NM:-nm}"

# Newer BoringSSL layouts place the archives at the build root; older ones use
# crypto/ + ssl/ subdirs (same probe order as CMakeLists.txt and build.sh).
# MSVC multi-config builds emit Release/crypto.lib instead.
ARCHIVE=""
for candidate in crypto/libcrypto.a libcrypto.a Release/crypto.lib crypto.lib; do
    if [ -f "$BUILD_DIR/$candidate" ]; then
        ARCHIVE="$BUILD_DIR/$candidate"
        break
    fi
done
if [ -z "$ARCHIVE" ]; then
    echo "ERROR: libcrypto.a / crypto.lib not found under $BUILD_DIR" >&2
    exit 1
fi

# Symbols go through a temp file, not a pipe: under pipefail a `grep -q`
# reader that exits on first match would SIGPIPE the writer and fail the
# pipeline spuriously.
SYMS="$(mktemp)"
trap 'rm -f "$SYMS"' EXIT
# A nonzero status is fatal even if partial output was produced: a member
# that failed to parse could be the one carrying the fingerprint we look for.
# Valid archives return 0 from GNU nm and llvm-nm, including when they warn
# about empty (other-arch) assembly members.
if ! "$NM" "$ARCHIVE" > "$SYMS" 2>/dev/null; then
    echo "ERROR: $NM failed on $ARCHIVE — check cannot run" >&2
    exit 1
fi
if [ "$(wc -l < "$SYMS")" -lt 100 ]; then
    echo "ERROR: could not read symbols from $ARCHIVE with $NM — check cannot run" >&2
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

# One representative entry point per primitive family. Each pattern matches
# the ELF name and the underscore-prefixed Mach-O name.
ASM_MISSING=0
for pattern in \
    'aes_hw_set_encrypt_key' \
    'gcm_ghash_(clmul|v8)' \
    'ChaCha20_ctr32_(ssse3|neon)'; do
    if ! grep -qE "[ _]${pattern}\$" "$SYMS"; then
        echo "ERROR: $ARCHIVE has no assembly symbol matching '${pattern}'" >&2
        ASM_MISSING=1
    fi
done
if [ "$ASM_MISSING" -ne 0 ]; then
    echo "       BoringSSL was built without its assembly implementations" >&2
    echo "       (OPENSSL_NO_ASM, or a generator that cannot assemble .S files):" >&2
    echo "       AES-GCM / ChaCha20-Poly1305 run as constant-time C, 10-30x slower." >&2
    echo "       Fix: drop -DOPENSSL_NO_ASM, make sure the toolchain can assemble" >&2
    echo "       BoringSSL's .S/.asm sources (NASM on Windows x86_64), and bump" >&2
    echo "       the BoringSSL/xquic cache keys if a CI cache is involved." >&2
    exit 1
fi

echo "OK: $ARCHIVE is an optimized BoringSSL build with assembly"
