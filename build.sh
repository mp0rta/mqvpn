#!/usr/bin/env bash
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
for cmd in cmake make cc; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' not found. Please install it."
        err=1
    fi
done

if ! find /usr/include /usr/local/include -name "event.h" -path "*/event2/*" 2>/dev/null | head -1 | grep -q .; then
    echo "ERROR: libevent headers not found. Install: apt install libevent-dev"
    err=1
fi

if [ "$err" -ne 0 ]; then
    exit 1
fi

# ---------- 1. BoringSSL ----------

BSSL_DIR="$SCRIPT_DIR/third_party/xquic/third_party/boringssl"
BSSL_BUILD="$BSSL_DIR/build"

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
if [ ! -f "$XQUIC_BUILD/CMakeCache.txt" ]; then
    cmake -S "$XQUIC_DIR" -B "$XQUIC_BUILD" \
        -DCMAKE_BUILD_TYPE=Release \
        -DSSL_TYPE=boringssl \
        -DSSL_PATH="$BSSL_DIR" \
        -DXQC_ENABLE_BBR2=ON
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
