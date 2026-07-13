#!/usr/bin/env bash
# Cross-build BoringSSL -> xquic (static) -> libmqvpn (static) for iOS arm64.
# Usage: ./ios/build-ios.sh [boringssl|xquic|mqvpn|all]   (default: all)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"   # repo root
PHASE="${1:-all}"

IOS_DEPLOYMENT_TARGET=15.0
IOS_ARCH=arm64
OUT_DIR="$SCRIPT_DIR/ios/build"
mkdir -p "$OUT_DIR"

IOS_CMAKE_FLAGS=(
    -DCMAKE_SYSTEM_NAME=iOS
    -DCMAKE_OSX_ARCHITECTURES=$IOS_ARCH
    -DCMAKE_OSX_SYSROOT=iphoneos
    -DCMAKE_OSX_DEPLOYMENT_TARGET=$IOS_DEPLOYMENT_TARGET
    -DCMAKE_BUILD_TYPE=Release
    -GNinja
)

BSSL_DIR="$SCRIPT_DIR/third_party/xquic/third_party/boringssl"
BSSL_BUILD="$BSSL_DIR/build-ios"

if [ "$PHASE" = "boringssl" ] || [ "$PHASE" = "all" ]; then
    if [ ! -f "$BSSL_DIR/CMakeLists.txt" ]; then
        echo "=== Cloning BoringSSL ==="
        git clone https://github.com/google/boringssl.git "$BSSL_DIR"
    fi
    echo "=== BoringSSL commit: $(git -C "$BSSL_DIR" rev-parse HEAD) ==="
    echo "=== Building BoringSSL (iOS) ==="
    # CMAKE_SYSTEM_NAME=iOS auto-enables CMAKE_MACOSX_BUNDLE, which makes
    # CMake require a BUNDLE DESTINATION for the `bssl` CLI executable
    # target's install() rule (configure-time error, unrelated to which
    # targets we actually build). We only need the static libs, so disable
    # bundling instead of patching upstream BoringSSL's CMakeLists.
    cmake -S "$BSSL_DIR" -B "$BSSL_BUILD" "${IOS_CMAKE_FLAGS[@]}" \
        -DCMAKE_MACOSX_BUNDLE=OFF
    cmake --build "$BSSL_BUILD" --target ssl crypto
fi

# Newer BoringSSL layouts place archives at the build root instead of
# ssl/ + crypto/ subdirs (the repo's own root CMake handles both) — probe
# once, use the resolved paths everywhere below.
resolve_bssl_libs() {
    if [ -f "$BSSL_BUILD/ssl/libssl.a" ]; then
        SSL_A="$BSSL_BUILD/ssl/libssl.a"; CRYPTO_A="$BSSL_BUILD/crypto/libcrypto.a"
    else
        SSL_A="$BSSL_BUILD/libssl.a"; CRYPTO_A="$BSSL_BUILD/libcrypto.a"
    fi
    [ -f "$SSL_A" ] || { echo "libssl.a not found under $BSSL_BUILD" >&2; exit 1; }
}

XQUIC_DIR="$SCRIPT_DIR/third_party/xquic"
XQUIC_BUILD="$XQUIC_DIR/build-ios"

if [ "$PHASE" = "xquic" ] || [ "$PHASE" = "all" ]; then
    echo "=== Building xquic (iOS, static) ==="
    resolve_bssl_libs
    # With SSL_INC_PATH + SSL_LIB_PATH both set, the fork's CMake skips its
    # own BoringSSL discovery entirely and uses these paths as-is.
    # FEC/XOR flags MUST match build.sh: the mqvpn core compiles FEC
    # references under XQC_ENABLE_FEC && XQC_ENABLE_XOR, and a FEC-OFF
    # libxquic-static.a would surface as an undefined symbol only at the
    # Xcode extension link, far from the cause.
    # The fork's CMakeLists.txt bakes -Wno-dangling-pointer into
    # CMAKE_C_FLAGS_OPTION unconditionally (not gated by compiler ID); that
    # flag is GCC-only and AppleClang rejects it as an unknown warning
    # option, which -Werror then promotes to a hard error. Seeding
    # CMAKE_C_FLAGS with -Wno-unknown-warning-option here (appended before
    # the fork's own flags, so it's already active when they're parsed)
    # downgrades that rejection to a no-op without touching the fork tree.
    cmake -S "$XQUIC_DIR" -B "$XQUIC_BUILD" "${IOS_CMAKE_FLAGS[@]}" \
        -DCMAKE_C_FLAGS=-Wno-unknown-warning-option \
        -DSSL_TYPE=boringssl \
        -DSSL_PATH="$BSSL_DIR" \
        -DSSL_INC_PATH="$BSSL_DIR/include" \
        -DSSL_LIB_PATH="$SSL_A;$CRYPTO_A" \
        -DXQC_ENABLE_BBR2=ON \
        -DXQC_ENABLE_UNLIMITED=ON \
        -DXQC_ENABLE_FEC=ON \
        -DXQC_ENABLE_XOR=ON \
        -DXQC_ENABLE_TESTING=OFF
    cmake --build "$XQUIC_BUILD" --target xquic-static
fi

MQVPN_BUILD="$SCRIPT_DIR/build-ios"

if [ "$PHASE" = "mqvpn" ] || [ "$PHASE" = "all" ]; then
    echo "=== Building libmqvpn (iOS, static) — clean build for ABI consistency ==="
    # Clean only the mqvpn object/build dir (NOT BoringSSL/xquic, which have
    # their own dirs) so every mqvpn TU is compiled in one pass against a
    # single reorder.h; a mixed-object archive with disagreeing struct layouts
    # is then not producible.
    rm -rf "$MQVPN_BUILD"
    # ANDROID_CROSS_COMPILE=ON is the existing "skip libevent + CLI" switch;
    # it builds exactly the sans-I/O static core (mqvpn_lib) and nothing else.
    # BORINGSSL_BUILD_DIR must point at the iOS build — the root CMake default
    # is the host build dir and would resolve wrong/absent SSL libs.
    # Hybrid TCP lane is default-ON since v0.11.0 but the PoC does not link
    # lwip_core; keep the iOS core lane-free until the SDK phase stages lwIP.
    cmake -S "$SCRIPT_DIR" -B "$MQVPN_BUILD" "${IOS_CMAKE_FLAGS[@]}" \
        -DANDROID_CROSS_COMPILE=ON \
        -DMQVPN_ENABLE_HYBRID_TCP_LANE=OFF \
        -DXQUIC_BUILD_DIR="$XQUIC_BUILD" \
        -DBORINGSSL_BUILD_DIR="$BSSL_BUILD"
    cmake --build "$MQVPN_BUILD" --target mqvpn_lib

    echo "=== Staging artifacts to $OUT_DIR ==="
    resolve_bssl_libs
    cp "$MQVPN_BUILD/libmqvpn.a" "$OUT_DIR/"
    cp "$XQUIC_BUILD/libxquic-static.a" "$OUT_DIR/"
    cp "$SSL_A" "$CRYPTO_A" "$OUT_DIR/"
    echo "=== Done ==="
    lipo -info "$OUT_DIR"/*.a
fi
