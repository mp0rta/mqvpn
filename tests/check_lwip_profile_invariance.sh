#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# G-hy1: default-profile effective values must stay byte-identical to the
# pre-profile constants; the mobile profile must actually select.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
dump() {
  cc -E -dM $1 -I"$ROOT/src" -I"$ROOT/src/hybrid" -I"$ROOT/src/hybrid/lwip_port" \
     -I"$ROOT/third_party/lwip/src/include" \
     -include "$ROOT/src/hybrid/lwip_port/lwipopts.h" -x c /dev/null
}

# Read the whole dump with awk rather than piping it into `grep -q`: grep -q
# exits the moment it matches, and under `set -o pipefail` a writer that is
# still filling the pipe then fails the pipeline, so the check reports a
# missing macro that is in fact present. That is what made this test fail
# intermittently on macOS — twice on the same commit, naming a different
# macro each time. Comparing values (not the exact line the preprocessor
# printed) also stops the check depending on how a toolchain spaces -dM.
macro_value() {  # $1 = dump, $2 = macro name
  printf '%s\n' "$1" | awk -v name="$2" '
    $1 == "#define" && $2 == name {
      $1 = ""; $2 = ""; sub(/^[ \t]+/, ""); gsub(/[ \t]+/, " "); print; found = 1
    }
    END { if (!found) print "<undefined>" }'
}

D="$(dump "")"
fail=0
while IFS='|' read -r name want; do
  [ -n "$name" ] || continue
  got="$(macro_value "$D" "$name")"
  if [ "$got" != "$want" ]; then
    echo "FAIL: default profile: $name is '$got', expected '$want'"
    fail=1
  fi
done <<'PINS'
TCP_RCV_SCALE|5
MEMP_NUM_TCP_PCB|512
MEMP_NUM_TCP_SEG|2048
PBUF_POOL_SIZE|256
TCP_SND_BUF|(2 * 1024 * 1024)
PINS

if [ "$fail" -ne 0 ]; then
  # Tell a real profile regression apart from a toolchain difference without
  # needing another CI round.
  echo "--- compiler:"
  cc --version 2>&1 | head -2
  echo "--- pinned macros as the preprocessor emitted them:"
  printf '%s\n' "$D" | grep -E \
    '^#define[[:space:]]+(TCP_RCV_SCALE|MEMP_NUM_TCP_PCB|MEMP_NUM_TCP_SEG|PBUF_POOL_SIZE|TCP_SND_BUF)[[:space:]]' \
    || echo "  (none matched — lwipopts.h may not have been included)"
  exit 1
fi

M="$(dump "-DMQVPN_LWIP_MOBILE_PROFILE")"
mobile="$(macro_value "$M" TCP_RCV_SCALE)"
[ "$mobile" = "MQVPN_LWIP_MOBILE_RCV_SCALE" ] \
  || { echo "FAIL: mobile profile not selected (TCP_RCV_SCALE is '$mobile')"; exit 1; }
echo "PASS: profile invariance"
