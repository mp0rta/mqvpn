#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# Stage license texts as APK assets/ before the Gradle build. AGP
# auto-includes src/main/assets/ in the produced APK. Required by
# Apache-2.0 §4(a) since the APK statically links xquic, BoringSSL, and
# lwIP (BSD-3-Clause requires the same notice retention).
#
# Shared by release.yml and android-repro.yml so the reproducibility gate
# compares the same payload the release actually ships.
set -euo pipefail
cd "$(dirname "$0")/.."

ASSETS=android/app/src/main/assets
mkdir -p "$ASSETS/third-party"
cp LICENSE                                         "$ASSETS/LICENSE"
cp NOTICE                                          "$ASSETS/NOTICE"
cp third_party/xquic/LICENSE                       "$ASSETS/third-party/xquic.txt"
cp third_party/xquic/third_party/boringssl/LICENSE "$ASSETS/third-party/boringssl.txt"
cp third_party/lwip/LICENSE                        "$ASSETS/third-party/lwip.txt"
