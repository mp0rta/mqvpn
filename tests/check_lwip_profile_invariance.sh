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

# check <profile-label> <extra-cflags> <<PINS
check() {
  local label="$1" flags="$2" out
  out="$(dump "$flags")"
  while IFS= read -r pin; do
    [ -n "$pin" ] || continue
    echo "$out" | grep -Fqx "$pin" \
      || { echo "FAIL: ${label} profile lost: ${pin}"; exit 1; }
  done
}

check "desktop/router" "" <<'PINS'
#define TCP_RCV_SCALE 5
#define MQVPN_LWIP_TCP_PCB_POOL 8192
#define MQVPN_LWIP_TCP_SEG_POOL 8192
#define PBUF_POOL_SIZE 256
#define TCP_SND_BUF (2 * 1024 * 1024)
#define MEMP_NUM_TCP_PCB MQVPN_LWIP_TCP_PCB_POOL
#define MEMP_NUM_TCP_SEG MQVPN_LWIP_TCP_SEG_POOL
PINS

# Android keeps the pre-v0.14 pools (flow ceiling 256) but the desktop windows.
check "Android" "-D__ANDROID__" <<'PINS'
#define TCP_RCV_SCALE 5
#define MQVPN_LWIP_TCP_PCB_POOL 512
#define MQVPN_LWIP_TCP_SEG_POOL 2048
#define PBUF_POOL_SIZE 256
#define TCP_SND_BUF (2 * 1024 * 1024)
#define MEMP_NUM_TCP_PCB MQVPN_LWIP_TCP_PCB_POOL
#define MEMP_NUM_TCP_SEG MQVPN_LWIP_TCP_SEG_POOL
PINS

# The iOS profile must win over __ANDROID__ if both are ever set.
check "iOS" "-DMQVPN_LWIP_IOS_PROFILE" <<'PINS'
#define TCP_RCV_SCALE MQVPN_LWIP_IOS_RCV_SCALE
#define MQVPN_LWIP_TCP_PCB_POOL 128
#define MQVPN_LWIP_TCP_SEG_POOL 512
PINS
check "iOS over Android" "-DMQVPN_LWIP_IOS_PROFILE -D__ANDROID__" <<'PINS'
#define MQVPN_LWIP_TCP_PCB_POOL 128
PINS

echo "PASS: profile invariance"
