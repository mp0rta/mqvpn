#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# insert_spdx.sh — prepend SPDX-License-Identifier and Copyright lines to
# all first-party C, Kotlin, and shell source files that don't already have them.
#
# Idempotent: files already carrying an SPDX line are skipped.
# Run from repository root.

set -euo pipefail

SPDX_LINE='SPDX-License-Identifier: Apache-2.0'
COPYRIGHT_LINE='Copyright (c) 2026 mp0rta and mqvpn contributors'

# C / C++ / header files: first-party only (not third_party/), all under
# src/, include/, tests/, and android/sdk-native/src/main/jni/.
C_FILES=$(git ls-files \
  | grep -E '\.(c|h)$' \
  | grep -v '^third_party/' \
  | grep -E '^(src/|include/|tests/|android/sdk-native/src/main/jni/)')

# Kotlin files: all first-party under android/.
KT_FILES=$(git ls-files | grep -E '^android/.*\.kt$')

# Shell scripts: all first-party (not third_party/). The header must land BELOW
# the shebang, so these use a separate insertion path from the C/Kotlin loops.
SH_FILES=$(git ls-files | grep -E '\.sh$' | grep -v '^third_party/')

inserted_count=0
skipped_count=0

for f in $C_FILES; do
  if grep -q "$SPDX_LINE" "$f"; then
    skipped_count=$((skipped_count + 1))
    continue
  fi
  # Insert 3 lines at the top: SPDX, Copyright, blank line.
  sed -i "1i // $SPDX_LINE\n// $COPYRIGHT_LINE\n" "$f"
  inserted_count=$((inserted_count + 1))
done

for f in $KT_FILES; do
  if grep -q "$SPDX_LINE" "$f"; then
    skipped_count=$((skipped_count + 1))
    continue
  fi
  sed -i "1i // $SPDX_LINE\n// $COPYRIGHT_LINE\n" "$f"
  inserted_count=$((inserted_count + 1))
done

for f in $SH_FILES; do
  if grep -q "$SPDX_LINE" "$f"; then
    skipped_count=$((skipped_count + 1))
    continue
  fi
  # Insert the two comment lines right after the shebang (or at the top if a
  # shell file has none), keeping `#!` on line 1. Uses perl so this path is
  # portable to BSD/macOS sed as well as GNU.
  SPDX="$SPDX_LINE" COPYRIGHT="$COPYRIGHT_LINE" perl -0777 -i -pe '
    my $h = "# $ENV{SPDX}\n# $ENV{COPYRIGHT}\n";
    s/\A(\#\![^\n]*\n)/$1.$h/e or $_ = $h.$_;
  ' "$f"
  inserted_count=$((inserted_count + 1))
done

echo "Inserted headers in $inserted_count files; skipped $skipped_count files already carrying SPDX."
