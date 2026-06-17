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
# Pinned for reproducibility: picoquic e652e454 (v1.1.50.0), verified to build
# picoquicdemo with BBR (-G bbr; -h lists bbr among the supported CCs and it is
# the build default). BBR is a hard comparability invariant for the sweep — if a
# future bump drops it, do NOT fall back to another congestion-control algorithm.
PICOQUIC_PIN="${PICOQUIC_PIN:-e652e454b40ff94d7a0372d537fdf176d55b61f1}"

command -v cmake >/dev/null || { echo "cmake required" >&2; exit 1; }
command -v git   >/dev/null || { echo "git required"   >&2; exit 1; }

if [ ! -d "${DEST}/.git" ]; then
    git clone "${PICOQUIC_URL}" "${DEST}"
fi
git -C "${DEST}" fetch --tags origin
git -C "${DEST}" checkout "${PICOQUIC_PIN}"

# picoquic depends on picotls being BUILT as a sibling (../picotls); its CMake
# FindPTLS looks for the libpicotls-* libraries there. picoquic ships
# ci/build_picotls.sh which clones h2o/picotls into ../picotls and builds it.
# Build picotls first (skip if already built), then build the picoquicdemo target.
PICOTLS_DIR="${REPO_ROOT}/third_party/picotls"
if [ ! -f "${PICOTLS_DIR}/libpicotls-core.a" ]; then
    ( cd "${DEST}" && ./ci/build_picotls.sh )
fi
( cd "${DEST}" \
    && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j"$(nproc)" --target picoquicdemo )

BIN="$(find "${DEST}" -name picoquicdemo -type f -perm -u+x | head -1)"
[ -n "${BIN}" ] || { echo "picoquicdemo not built" >&2; exit 1; }
echo "picoquicdemo: ${BIN}"
echo "--- usage banner (confirm the BBR congestion-control flag + scenario syntax) ---"
"${BIN}" 2>&1 | head -40 || true
