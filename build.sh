#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

NPROC=$(nproc 2>/dev/null || echo 4)

# ---------- Options ----------

if [ "$1" = "--clean" ]; then
    echo "Cleaning all build directories..."
    rm -rf "$SCRIPT_DIR/build"
    rm -rf "$SCRIPT_DIR/third_party/xquic/build"
    rm -rf "$SCRIPT_DIR/third_party/xquic/third_party/boringssl/build"
    echo "Clean complete."
    shift
fi

# ---------- Dependency checks ----------

err=0
for cmd in cmake make cc git; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' not found. Please install it."
        err=1
    fi
done

# /opt/homebrew is Apple Silicon Homebrew's prefix (Intel-mac brew installs
# under /usr/local, already covered). -L: Homebrew's include/event2 is a
# symlink into the keg, which find will not descend into by default.
if ! find -L /usr/include /usr/local/include /opt/homebrew/include \
        -name "event.h" -path "*/event2/*" 2>/dev/null | head -1 | grep -q .; then
    echo "ERROR: libevent headers not found. Install: apt install libevent-dev (macOS: brew install libevent)"
    err=1
fi

if [ "$err" -ne 0 ]; then
    exit 1
fi

# ---------- 1. BoringSSL ----------

BSSL_DIR="$SCRIPT_DIR/third_party/xquic/third_party/boringssl"
BSSL_BUILD="$BSSL_DIR/build"

# BoringSSL is a submodule of the xquic fork, pinned to an exact commit.
# `git submodule update --init --recursive` (run after checkout) puts it here.
if [ ! -f "$BSSL_DIR/CMakeLists.txt" ]; then
    echo "ERROR: BoringSSL not found at $BSSL_DIR."
    echo "Run: git submodule update --init --recursive"
    exit 1
fi

echo "=== Building BoringSSL ==="
# Wipe the build dir if it was produced from a different BoringSSL pin — an
# incremental rebuild across a pin bump can leave the previous revision's
# archives in the other layout, and the ssl/-first probes below would link
# them (see scripts/bssl_build_guard.sh).
source "$SCRIPT_DIR/scripts/bssl_build_guard.sh"
bssl_guard_build_dir "$BSSL_DIR" "$BSSL_BUILD"
mkdir -p "$BSSL_BUILD"
# CMAKE_BUILD_TYPE is mandatory: BoringSSL's CMakeLists sets no default, so
# omitting it compiles the whole library at -O0 with asserts live, and its
# `NOT CMAKE_BUILD_TYPE MATCHES "rel"` guard additionally defines
# BORINGSSL_DISPATCH_TEST (CPU-dispatch test instrumentation). Measured cost
# of the omission: ~21% VPN throughput and ~7x on X25519.
if [ ! -f "$BSSL_BUILD/CMakeCache.txt" ]; then
    cmake -S "$BSSL_DIR" -B "$BSSL_BUILD" \
        -DBUILD_SHARED_LIBS=0 \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS="-fPIC" \
        -DCMAKE_CXX_FLAGS="-fPIC"
elif ! grep -qiE '^CMAKE_BUILD_TYPE:STRING=Rel' "$BSSL_BUILD/CMakeCache.txt"; then
    # A build dir configured before that flag existed would silently keep its
    # -O0 objects, since the configure above is skipped once a cache exists.
    # Any Rel* type is left alone — that is the same prefix BoringSSL's own
    # CMakeLists tests to decide whether the build is an optimized one.
    echo "BoringSSL build dir was configured without CMAKE_BUILD_TYPE=Release — reconfiguring"
    rm -rf "$BSSL_BUILD"
    mkdir -p "$BSSL_BUILD"
    cmake -S "$BSSL_DIR" -B "$BSSL_BUILD" \
        -DBUILD_SHARED_LIBS=0 \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS="-fPIC" \
        -DCMAKE_CXX_FLAGS="-fPIC"
fi
make -C "$BSSL_BUILD" -j"$NPROC" ssl crypto
bssl_stamp_build_dir "$BSSL_DIR" "$BSSL_BUILD"

# ---------- 2. xquic ----------

XQUIC_DIR="$SCRIPT_DIR/third_party/xquic"
XQUIC_BUILD="$XQUIC_DIR/build"

echo "=== Building xquic ==="
mkdir -p "$XQUIC_BUILD"
# Re-configure if cache is missing OR if required flags weren't enabled in a prior
# configure (older checkouts had this script without FEC/UNLIMITED flags).
NEED_CONFIGURE=0
if [ ! -f "$XQUIC_BUILD/CMakeCache.txt" ]; then
    NEED_CONFIGURE=1
elif ! grep -q "^XQC_ENABLE_FEC:BOOL=ON" "$XQUIC_BUILD/CMakeCache.txt" \
   || ! grep -q "^XQC_ENABLE_XOR:BOOL=ON" "$XQUIC_BUILD/CMakeCache.txt" \
   || ! grep -q "^XQC_ENABLE_UNLIMITED:BOOL=ON" "$XQUIC_BUILD/CMakeCache.txt"; then
    echo "  Existing xquic build lacks required flags — wiping and reconfiguring"
    rm -rf "$XQUIC_BUILD"
    mkdir -p "$XQUIC_BUILD"
    NEED_CONFIGURE=1
fi
if [ "$NEED_CONFIGURE" -eq 1 ]; then
    cmake -S "$XQUIC_DIR" -B "$XQUIC_BUILD" \
        -DCMAKE_BUILD_TYPE=Release \
        -DSSL_TYPE=boringssl \
        -DSSL_PATH="$BSSL_DIR" \
        -DXQC_ENABLE_BBR2=ON \
        -DXQC_ENABLE_UNLIMITED=ON \
        -DXQC_ENABLE_FEC=ON \
        -DXQC_ENABLE_XOR=ON
fi
make -C "$XQUIC_BUILD" -j"$NPROC"

# ---------- 3. mqvpn ----------

echo "=== Building mqvpn ==="
mkdir -p "$SCRIPT_DIR/build"
if [ ! -f "$SCRIPT_DIR/build/CMakeCache.txt" ]; then
    cmake -S "$SCRIPT_DIR" -B "$SCRIPT_DIR/build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DXQUIC_BUILD_DIR="$XQUIC_BUILD"
fi
make -C "$SCRIPT_DIR/build" -j"$NPROC"

# ---------- Done ----------

echo ""
echo "Build complete: $(pwd)/build/mqvpn"
