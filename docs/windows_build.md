# Windows Build Guide (MSVC x64)

How to build the mqvpn client on Windows using MSVC.

> **Note:** Only the client is supported on Windows. The server is Linux-only.

## Prerequisites

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

## Build Steps

Run all commands from a Developer Command Prompt for VS 2022, or source `vcvars64.bat` first:

```
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
```

### 1. Install libevent

```
vcpkg install libevent:x64-windows-static
```

### 2. Build BoringSSL

```
cd third_party\xquic\third_party
git clone https://github.com/google/boringssl.git
cd boringssl
git checkout 9c95ec797c65fde9e8ddffc3888f0b8c1460fe4c

mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 -DBUILD_SHARED_LIBS=0 ..
cmake --build . --target ssl --config Release
cmake --build . --target crypto --config Release
```

### 3. Build xquic

```
cd third_party\xquic
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DSSL_TYPE=boringssl ^
  -DSSL_PATH=%cd%\..\..\xquic\third_party\boringssl ^
  -DXQC_ENABLE_BBR2=ON ..
cmake --build . --config Release
```

### 4. Build mqvpn

Replace `VCPKG_ROOT` with the path to your vcpkg clone.

```
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DXQUIC_BUILD_DIR=..\third_party\xquic\build\Release ^
  -DBORINGSSL_BUILD_DIR=..\third_party\xquic\third_party\boringssl\build\Release ^
  -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake ^
  -DVCPKG_TARGET_TRIPLET=x64-windows-static ..
cmake --build . --config Release
```

On success, the binary is at `build\Release\mqvpn.exe`.

## Usage Examples

Single path:

```
mqvpn.exe --mode client --server 203.0.113.1:443 --auth-key <key>
```

Multipath (multiple NICs):

```
mqvpn.exe --mode client --server 203.0.113.1:443 --auth-key <key> ^
  --path "Ethernet" --path "Ethernet 3" --scheduler wlb
```
