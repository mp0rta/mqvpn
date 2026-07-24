#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# G-hy1: each lwIP build profile must select the pool/window constants it is
# documented to select. The pcb pool is what bounds the honored
# hybrid.TcpMaxFlows (tcp_lane.c clamps to MEMP_NUM_TCP_PCB / 2), so a silent
# change here silently changes the configurable flow ceiling:
#   desktop/router 8192 -> 4096 | Android 512 -> 256 | iOS 128 -> 64
# __ANDROID__ is a toolchain predefine, simulated here with -D for a
# preprocess-only dump.
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

WATCHED='MQVPN_LWIP_RCV_SCALE|TCP_RCV_SCALE|MQVPN_LWIP_TCP_PCB_POOL|MQVPN_LWIP_TCP_SEG_POOL|MEMP_NUM_TCP_PCB|MEMP_NUM_TCP_SEG|PBUF_POOL_SIZE|TCP_SND_BUF'

# check <profile-label> <extra-cflags>; pins on stdin as "NAME|value" lines.
check() {
  local label="$1" flags="$2" out fail=0 name want got
  out="$(dump "$flags")"
  while IFS='|' read -r name want; do
    [ -n "$name" ] || continue
    got="$(macro_value "$out" "$name")"
    if [ "$got" != "$want" ]; then
      echo "FAIL: ${label} profile: $name is '$got', expected '$want'"
      fail=1
    fi
  done
  if [ "$fail" -ne 0 ]; then
    # Tell a real profile regression apart from a toolchain difference without
    # needing another CI round.
    echo "--- compiler:"
    cc --version 2>&1 | head -2
    echo "--- watched macros as the preprocessor emitted them (${label}):"
    printf '%s\n' "$out" \
      | grep -E "^#define[[:space:]]+(${WATCHED})[[:space:]]" \
      || echo "  (none matched — lwipopts.h may not have been included)"
    exit 1
  fi
}

check "desktop/router" "" <<'PINS'
MQVPN_LWIP_RCV_SCALE|3
TCP_RCV_SCALE|MQVPN_LWIP_RCV_SCALE
MQVPN_LWIP_TCP_PCB_POOL|8192
MQVPN_LWIP_TCP_SEG_POOL|8192
MEMP_NUM_TCP_PCB|MQVPN_LWIP_TCP_PCB_POOL
MEMP_NUM_TCP_SEG|MQVPN_LWIP_TCP_SEG_POOL
PBUF_POOL_SIZE|64
TCP_SND_BUF|(2 * 1024 * 1024)
PINS

# Android keeps the pre-v0.14 pools (flow ceiling 256) but the desktop windows.
check "Android" "-D__ANDROID__" <<'PINS'
MQVPN_LWIP_RCV_SCALE|3
TCP_RCV_SCALE|MQVPN_LWIP_RCV_SCALE
MQVPN_LWIP_TCP_PCB_POOL|512
MQVPN_LWIP_TCP_SEG_POOL|2048
MEMP_NUM_TCP_PCB|MQVPN_LWIP_TCP_PCB_POOL
MEMP_NUM_TCP_SEG|MQVPN_LWIP_TCP_SEG_POOL
PBUF_POOL_SIZE|64
TCP_SND_BUF|(2 * 1024 * 1024)
PINS

# The iOS profile must win over __ANDROID__ if both are ever set.
# MQVPN_LWIP_IOS_RCV_SCALE is pinned to its CONCRETE default (2), not just the
# symbolic TCP_RCV_SCALE indirection: with only the symbolic pin, bumping the
# default scale would pass every check in the tree while silently doubling the
# iOS windows and PBUF ladder against the NE memory ceiling.
check "iOS" "-DMQVPN_LWIP_IOS_PROFILE" <<'PINS'
TCP_RCV_SCALE|MQVPN_LWIP_IOS_RCV_SCALE
MQVPN_LWIP_IOS_RCV_SCALE|2
MQVPN_LWIP_TCP_PCB_POOL|128
MQVPN_LWIP_TCP_SEG_POOL|512
PBUF_POOL_SIZE|32
TCP_SND_BUF|(65536 << MQVPN_LWIP_IOS_RCV_SCALE)
PINS
check "iOS over Android" "-DMQVPN_LWIP_IOS_PROFILE -D__ANDROID__" <<'PINS'
MQVPN_LWIP_TCP_PCB_POOL|128
MQVPN_LWIP_TCP_SEG_POOL|512
PINS

echo "PASS: profile invariance"
