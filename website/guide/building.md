# Building

## Linux

### Requirements

- CMake 3.22+
- GCC or Clang (C11)
- libevent 2.x

### Quick Build

```bash
./build.sh            # builds BoringSSL, xquic, and mqvpn
./build.sh --clean    # full rebuild
```

### Manual Build Steps

#### 1. Build BoringSSL

```bash
cd third_party/xquic/third_party/boringssl
mkdir -p build && cd build
cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make -j$(nproc) ssl crypto
cd ../../../../..
```

#### 2. Build xquic

```bash
cd third_party/xquic
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DSSL_TYPE=boringssl \
      -DSSL_PATH=../third_party/boringssl \
      -DXQC_ENABLE_BBR2=ON ..
make -j$(nproc)
cd ../../..
```

#### 3. Build mqvpn

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DXQUIC_BUILD_DIR=../third_party/xquic/build ..
make -j$(nproc)
```

### Testing

```bash
cd build && ctest --output-on-failure       # C library unit tests
sudo scripts/ci_e2e/run_test.sh             # E2E (netns, requires root)
sudo scripts/run_multipath_test.sh          # multipath failover
cd android && ./gradlew test                # Android SDK unit tests
```

## Windows (MSVC x64)

::: info
Only the client is supported on Windows. The server is Linux-only.
:::

### Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Visual Studio 2022 Build Tools | C/C++ compiler (MSVC) | `winget install Microsoft.VisualStudio.2022.BuildTools` (select C++ workload) |
| CMake >= 3.10 | Build system | `winget install Kitware.CMake` |
| Go | Required by BoringSSL | `winget install GoLang.Go` |
| NASM | Required by BoringSSL (assembly) | `winget install NASM.NASM` |
| Perl (Strawberry Perl) | Required by BoringSSL | `winget install StrawberryPerl.StrawberryPerl` |
| vcpkg | Install libevent | `git clone https://github.com/microsoft/vcpkg && .\vcpkg\bootstrap-vcpkg.bat` |
| Git | Source checkout | `winget install Git.Git` |

### Wintun

The TUN device is provided by [Wintun](https://www.wintun.net/). The `wintun.dll` is loaded at runtime, so it is not required at build time. Place `wintun.dll` next to the executable or in your PATH before running mqvpn.

### Build Steps

Run all commands from a Developer Command Prompt for VS 2022:

```batch
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
```

#### 1. Install libevent

```batch
vcpkg install libevent:x64-windows-static
```

#### 2. Build BoringSSL

```batch
cd third_party\xquic\third_party
git clone https://github.com/google/boringssl.git
cd boringssl
git checkout 9c95ec797c65fde9e8ddffc3888f0b8c1460fe4c

mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 -DBUILD_SHARED_LIBS=0 ..
cmake --build . --target ssl --config Release
cmake --build . --target crypto --config Release
```

#### 3. Build xquic

```batch
cd third_party\xquic
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DSSL_TYPE=boringssl ^
  -DSSL_PATH=%cd%\..\..\xquic\third_party\boringssl ^
  -DXQC_ENABLE_BBR2=ON ..
cmake --build . --config Release
```

#### 4. Build mqvpn

Replace `VCPKG_ROOT` with the path to your vcpkg clone.

```batch
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DXQUIC_BUILD_DIR=..\third_party\xquic\build\Release ^
  -DBORINGSSL_BUILD_DIR=..\third_party\xquic\third_party\boringssl\build\Release ^
  -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake ^
  -DVCPKG_TARGET_TRIPLET=x64-windows-static ..
cmake --build . --config Release
```

The binary is at `build\Release\mqvpn.exe`.

## Android

```bash
scripts/build_android.sh --abi arm64-v8a    # cross-compile C libs
cd android && ./gradlew assembleDebug       # build SDK + demo app
```

### Module Structure

```
android/
├── sdk-native/    # JNI bridge → libmqvpn_jni.so
├── sdk-runtime/   # MqvpnPoller (tick-loop)
├── sdk-network/   # NetworkMonitor, PathBinder
├── sdk-core/      # MqvpnVpnService, MqvpnManager, TunnelBridge
└── app/           # Demo app (Jetpack Compose)
```

See [Getting Started](./getting-started) to test your build.
