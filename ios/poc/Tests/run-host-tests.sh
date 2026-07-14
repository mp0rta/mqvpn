#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# Host-compile the pure Foundation logic + assertions and run on macOS. Mirrors
# the clock_shim_host_test.c precedent (logic tests need no simulator). The
# file that carries top-level test statements MUST be named main.swift.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SHARED="$DIR/../Shared"
APP="$DIR/../App"
OUT="$(mktemp -d)/hosttests"
swiftc -o "$OUT" \
    "$SHARED/ReorderSettings.swift" \
    "$DIR/main.swift"
"$OUT"
