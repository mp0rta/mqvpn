#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# build_picoquic.sh — Clone + build stock picoquic to obtain the picoquicdemo
# binary used as the inner HTTP/3 workload generator for the reorder parameter
# sweep (benchmarks/sweep_reorder.sh). picoquic is NOT vendored as a submodule —
# the clone tree at third_party/picoquic/ is gitignored. Output:
#   <repo>/third_party/picoquic/**/picoquicdemo
#
# Usage: scripts/ci_interop/build_picoquic.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="${REPO_ROOT}/third_party/picoquic"
PICOQUIC_URL="https://github.com/private-octopus/picoquic.git"
# Pin for reproducibility. Replace with a concrete SHA verified to build
# picoquicdemo WITH BBR before running the sweep. If the pinned SHA lacks BBR,
# bump the pin — BBR is a hard comparability invariant for the sweep, do NOT fall
# back to another congestion-control algorithm.
PICOQUIC_PIN="${PICOQUIC_PIN:-master}"

command -v cmake >/dev/null || { echo "cmake required" >&2; exit 1; }
command -v git   >/dev/null || { echo "git required"   >&2; exit 1; }

if [ ! -d "${DEST}/.git" ]; then
    git clone "${PICOQUIC_URL}" "${DEST}"
fi
git -C "${DEST}" fetch --tags origin
git -C "${DEST}" checkout "${PICOQUIC_PIN}"

# picoquic ships a build helper that fetches/builds its picotls dependency;
# prefer it, fall back to a manual cmake of the picoquicdemo target.
if [ -x "${DEST}/ci/build_picoquic.sh" ]; then
    ( cd "${DEST}" && ./ci/build_picoquic.sh )
else
    ( cd "${DEST}" \
        && git submodule update --init --recursive \
        && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
        && cmake --build build -j"$(nproc)" --target picoquicdemo )
fi

BIN="$(find "${DEST}" -name picoquicdemo -type f -perm -u+x | head -1)"
[ -n "${BIN}" ] || { echo "picoquicdemo not built" >&2; exit 1; }
echo "picoquicdemo: ${BIN}"
echo "--- usage banner (confirm the BBR congestion-control flag + scenario syntax) ---"
"${BIN}" 2>&1 | head -40 || true
