#!/usr/bin/env bash
#
# build_android.sh — Cross-compile libmqvpn + xquic + BoringSSL for Android
#
# Produces prebuilt static libraries per ABI:
#   android/sdk-native/prebuilt/{ABI}/libmqvpn.a
#   android/sdk-native/prebuilt/{ABI}/libxquic.a
#   android/sdk-native/prebuilt/{ABI}/libssl.a
#   android/sdk-native/prebuilt/{ABI}/libcrypto.a
#
# Usage:
#   scripts/build_android.sh [--abi arm64-v8a] [--ndk /path/to/ndk]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
NDK_ROOT="${ANDROID_NDK:-${HOME}/android-ndk-r27d}"
ABIS="arm64-v8a armeabi-v7a x86_64"
API_LEVEL=26
JOBS=$(nproc 2>/dev/null || echo 4)

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --abi) ABIS="$2"; shift 2 ;;
        --ndk) NDK_ROOT="$2"; shift 2 ;;
        --api) API_LEVEL="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

NDK_CMAKE="${NDK_ROOT}/build/cmake/android.toolchain.cmake"
if [[ ! -f "$NDK_CMAKE" ]]; then
    echo "ERROR: NDK toolchain not found at: $NDK_CMAKE"
    echo "Set ANDROID_NDK or use --ndk /path/to/ndk"
    exit 1
fi

# Use Ninja if available, else Unix Makefiles
if command -v ninja &>/dev/null; then
    CMAKE_GEN="Ninja"
else
    CMAKE_GEN="Unix Makefiles"
fi

XQUIC_DIR="${PROJECT_ROOT}/third_party/xquic"
BORINGSSL_DIR="${XQUIC_DIR}/third_party/boringssl"
PREBUILT_BASE="${PROJECT_ROOT}/android/sdk-native/prebuilt"

echo "=== Android cross-compile ==="
echo "NDK: $NDK_ROOT"
echo "ABIs: $ABIS"
echo "API: $API_LEVEL"
echo "Generator: ${CMAKE_GEN}"
echo ""

for ABI in $ABIS; do
    echo "━━━ Building for $ABI ━━━"
    BUILD_DIR="${PROJECT_ROOT}/build-android/${ABI}"
    PREBUILT_DIR="${PREBUILT_BASE}/${ABI}"
    mkdir -p "$BUILD_DIR" "$PREBUILT_DIR"

    # ── 1. BoringSSL ──
    BSSL_BUILD="${BUILD_DIR}/boringssl"
    if [[ ! -f "${BSSL_BUILD}/libssl.a" ]] && [[ ! -f "${BSSL_BUILD}/ssl/libssl.a" ]]; then
        echo "  [1/3] Building BoringSSL..."
        mkdir -p "$BSSL_BUILD"
        cmake -S "$BORINGSSL_DIR" -B "$BSSL_BUILD" \
            -DCMAKE_TOOLCHAIN_FILE="$NDK_CMAKE" \
            -DANDROID_ABI="$ABI" \
            -DANDROID_NATIVE_API_LEVEL="$API_LEVEL" \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=OFF \
            -G "$CMAKE_GEN" \
            > /dev/null 2>&1
        cmake --build "$BSSL_BUILD" --target ssl --target crypto -j"$JOBS" > /dev/null 2>&1
    else
        echo "  [1/3] BoringSSL (cached)"
    fi
    # Output location varies by generator (ssl/libssl.a vs libssl.a)
    for lib in ssl crypto; do
        src="${BSSL_BUILD}/${lib}/lib${lib}.a"
        [[ -f "$src" ]] || src="${BSSL_BUILD}/lib${lib}.a"
        cp "$src" "$PREBUILT_DIR/"
    done

    # ── 2. xquic ──
    XQC_BUILD="${BUILD_DIR}/xquic"
    if [[ ! -f "${XQC_BUILD}/libxquic-static.a" ]]; then
        echo "  [2/3] Building xquic..."
        mkdir -p "$XQC_BUILD"
        # Flags aligned with xquic/xqc_build.sh Android config
        # -Wno-unknown-warning-option: xquic uses GCC-only -Wno-dangling-pointer
        cmake -S "$XQUIC_DIR" -B "$XQC_BUILD" \
            -DCMAKE_TOOLCHAIN_FILE="$NDK_CMAKE" \
            -DANDROID_ABI="$ABI" \
            -DANDROID_NATIVE_API_LEVEL="$API_LEVEL" \
            -DCMAKE_BUILD_TYPE=MinSizeRel \
            -DCMAKE_C_FLAGS="-Wno-unknown-warning-option" \
            -DSSL_TYPE=boringssl \
            -DSSL_PATH="$BSSL_BUILD" \
            -DSSL_INC_PATH="${BORINGSSL_DIR}/include" \
            -DXQC_ENABLE_BBR2=ON \
            -DXQC_ENABLE_TH3=ON \
            -DXQC_ENABLE_TESTING=OFF \
            -DXQC_BUILD_SAMPLE=OFF \
            -DXQC_ONLY_ERROR_LOG=ON \
            -DXQC_COMPAT_GENERATE_SR_PKT=ON \
            -DXQC_NO_PID_PACKET_PROCESS=1 \
            -DBUILD_SHARED_LIBS=OFF \
            -G "$CMAKE_GEN" \
            > /dev/null 2>&1
        cmake --build "$XQC_BUILD" --target xquic-static -j"$JOBS" > /dev/null 2>&1
    else
        echo "  [2/3] xquic (cached)"
    fi
    cp "$XQC_BUILD/libxquic-static.a" "$PREBUILT_DIR/libxquic.a"

    # ── 3. libmqvpn ──
    MQ_BUILD="${BUILD_DIR}/mqvpn"
    echo "  [3/3] Building libmqvpn..."
    mkdir -p "$MQ_BUILD"
    cmake -S "$PROJECT_ROOT" -B "$MQ_BUILD" \
        -DCMAKE_TOOLCHAIN_FILE="$NDK_CMAKE" \
        -DANDROID_ABI="$ABI" \
        -DANDROID_NATIVE_API_LEVEL="$API_LEVEL" \
        -DCMAKE_BUILD_TYPE=Release \
        -DXQUIC_BUILD_DIR="$XQC_BUILD" \
        -DBORINGSSL_BUILD_DIR="$BSSL_BUILD" \
        -DANDROID_CROSS_COMPILE=ON \
        -G "$CMAKE_GEN" \
        > /dev/null 2>&1
    cmake --build "$MQ_BUILD" --target mqvpn_lib -j"$JOBS" > /dev/null 2>&1

    if [[ -f "${MQ_BUILD}/libmqvpn.a" ]]; then
        cp "$MQ_BUILD/libmqvpn.a" "$PREBUILT_DIR/"
    else
        echo "  WARNING: libmqvpn.a not found for $ABI"
    fi

    echo "  → ${PREBUILT_DIR}/"
    ls -la "$PREBUILT_DIR/"
    echo ""
done

echo "=== Done ==="
echo "Prebuilt libraries:"
find "$PREBUILT_BASE" -name "*.a" | sort
echo ""
echo "Next: cd android && ./gradlew assembleDebug"
