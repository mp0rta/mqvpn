#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# Compile the Foundation-only logic + PureCases.swift and run on Linux or macOS.
# Later tasks append their pure source files to PURE_SOURCES.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SHARED="$DIR/../Shared"
APP="$DIR/../App"
PURE_SOURCES=(
    "$SHARED/ServerAddressField.swift"
    "$SHARED/TunnelPolicies.swift"
    "$SHARED/ProviderMessage.swift"
    "$SHARED/SampleRing.swift"
    "$SHARED/TunnelSessionCoordinator.swift"
    "$APP/BandwidthHistory.swift"
    "$APP/ReorderHistory.swift"
    "$APP/ChartGeometry.swift"
    "$APP/Derive.swift"
    "$APP/ReorderIngest.swift"
    "$APP/SettingsCore.swift"
)
if command -v swiftc >/dev/null 2>&1; then
    SWIFTC=(swiftc)
else
    SWIFTC=(env MISE_EXPERIMENTAL=true mise exec swift@6.4.1 -- swiftc)
fi
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT
"${SWIFTC[@]}" -parse-as-library -o "$TMPD/puretests" \
    ${PURE_SOURCES[@]+"${PURE_SOURCES[@]}"} \
    "$DIR/PureCases.swift" "$DIR/pure_main.swift"
"$TMPD/puretests"
