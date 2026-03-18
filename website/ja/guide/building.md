# ビルド

## Linux

### 必要なもの

- CMake 3.22+
- GCC または Clang（C11）
- libevent 2.x

### クイックビルド

```bash
./build.sh            # BoringSSL、xquic、mqvpn をビルド
./build.sh --clean    # フルリビルド
```

### 手動ビルド手順

#### 1. BoringSSL のビルド

```bash
cd third_party/xquic/third_party/boringssl
mkdir -p build && cd build
cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make -j$(nproc) ssl crypto
cd ../../../../..
```

#### 2. xquic のビルド

```bash
cd third_party/xquic
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DSSL_TYPE=boringssl \
      -DSSL_PATH=../third_party/boringssl \
      -DXQC_ENABLE_BBR2=ON ..
make -j$(nproc)
cd ../../..
```

#### 3. mqvpn のビルド

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DXQUIC_BUILD_DIR=../third_party/xquic/build ..
make -j$(nproc)
```

### テスト

```bash
cd build && ctest --output-on-failure       # C ライブラリユニットテスト
sudo scripts/ci_e2e/run_test.sh             # E2E（netns、root 権限必要）
sudo scripts/run_multipath_test.sh          # マルチパスフェイルオーバー
cd android && ./gradlew test                # Android SDK ユニットテスト
```

## Windows (MSVC x64)

::: info
Windows ではクライアントのみサポートされています。サーバーは Linux 専用です。
:::

### 前提条件

| ツール | 用途 | インストール |
|--------|------|-------------|
| Visual Studio 2022 Build Tools | C/C++ コンパイラ (MSVC) | `winget install Microsoft.VisualStudio.2022.BuildTools`（C++ ワークロードを選択） |
| CMake >= 3.10 | ビルドシステム | `winget install Kitware.CMake` |
| Go | BoringSSL に必要 | `winget install GoLang.Go` |
| NASM | BoringSSL に必要（アセンブリ） | `winget install NASM.NASM` |
| Perl (Strawberry Perl) | BoringSSL に必要 | `winget install StrawberryPerl.StrawberryPerl` |
| vcpkg | libevent のインストール | `git clone https://github.com/microsoft/vcpkg && .\vcpkg\bootstrap-vcpkg.bat` |
| Git | ソース取得 | `winget install Git.Git` |

### Wintun

TUN デバイスは [Wintun](https://www.wintun.net/) によって提供されます。`wintun.dll` は実行時にロードされるため、ビルド時には不要です。mqvpn を実行する前に、`wintun.dll` を実行ファイルと同じディレクトリか PATH に配置してください。

### ビルド手順

すべてのコマンドは Developer Command Prompt for VS 2022 から実行してください：

```batch
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
```

#### 1. libevent のインストール

```batch
vcpkg install libevent:x64-windows-static
```

#### 2. BoringSSL のビルド

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

#### 3. xquic のビルド

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

#### 4. mqvpn のビルド

`VCPKG_ROOT` を vcpkg のクローン先パスに置き換えてください。

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

バイナリは `build\Release\mqvpn.exe` に生成されます。

## Android

```bash
scripts/build_android.sh --abi arm64-v8a    # C ライブラリのクロスコンパイル
cd android && ./gradlew assembleDebug       # SDK + デモアプリのビルド
```

### モジュール構成

```
android/
├── sdk-native/    # JNI ブリッジ → libmqvpn_jni.so
├── sdk-runtime/   # MqvpnPoller（tick ループ）
├── sdk-network/   # NetworkMonitor、PathBinder
├── sdk-core/      # MqvpnVpnService、MqvpnManager、TunnelBridge
└── app/           # デモアプリ（Jetpack Compose）
```

ビルドのテストは[はじめに](./getting-started)を参照してください。
