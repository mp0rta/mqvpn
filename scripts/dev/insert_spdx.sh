#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and contributors
#
# insert_spdx.sh — prepend SPDX-License-Identifier and Copyright lines to
# all first-party C and Kotlin source files that don't already have them.
#
# Idempotent: files already carrying an SPDX line are skipped.
# Run from repository root.

set -euo pipefail

SPDX_LINE='SPDX-License-Identifier: Apache-2.0'
COPYRIGHT_LINE='Copyright (c) 2026 mp0rta and contributors'

# C / C++ / header files: first-party only (not third_party/), all under
# src/, include/, tests/, and android/sdk-native/src/main/jni/.
C_FILES=$(git ls-files \
  | grep -E '\.(c|h)$' \
  | grep -v '^third_party/' \
  | grep -E '^(src/|include/|tests/|android/sdk-native/src/main/jni/)')

# Kotlin files: all first-party under android/.
KT_FILES=$(git ls-files | grep -E '^android/.*\.kt$')

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

echo "Inserted headers in $inserted_count files; skipped $skipped_count files already carrying SPDX."
