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

# Clone BoringSSL if not present (not a git submodule of xquic)
if [ ! -f "$BSSL_DIR/CMakeLists.txt" ]; then
    echo "=== Cloning BoringSSL ==="
    git clone https://github.com/google/boringssl.git "$BSSL_DIR"
fi

echo "=== Building BoringSSL ==="
mkdir -p "$BSSL_BUILD"
if [ ! -f "$BSSL_BUILD/CMakeCache.txt" ]; then
    cmake -S "$BSSL_DIR" -B "$BSSL_BUILD" \
        -DBUILD_SHARED_LIBS=0 \
        -DCMAKE_C_FLAGS="-fPIC" \
        -DCMAKE_CXX_FLAGS="-fPIC"
fi
make -C "$BSSL_BUILD" -j"$NPROC" ssl crypto

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
