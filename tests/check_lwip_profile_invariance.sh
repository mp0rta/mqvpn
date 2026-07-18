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
D="$(dump "")"
while IFS= read -r pin; do
  echo "$D" | grep -Fqx "$pin" || { echo "FAIL: default profile lost: ${pin}"; exit 1; }
done <<'PINS'
#define TCP_RCV_SCALE 5
#define MEMP_NUM_TCP_PCB 512
#define MEMP_NUM_TCP_SEG 2048
#define PBUF_POOL_SIZE 256
#define TCP_SND_BUF (2 * 1024 * 1024)
PINS
M="$(dump "-DMQVPN_LWIP_MOBILE_PROFILE")"
echo "$M" | grep -Fq '#define TCP_RCV_SCALE MQVPN_LWIP_MOBILE_RCV_SCALE' \
  || { echo "FAIL: mobile profile not selected"; exit 1; }
echo "PASS: profile invariance"
