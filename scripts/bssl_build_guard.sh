#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# BoringSSL build-dir provenance guard — source this, do not execute it.
#
# BoringSSL moved its archive layout between the revisions this repo has
# pinned: older builds put them at <build>/ssl/libssl.a + <build>/crypto/,
# newer ones at the build root. Every consumer therefore probes both layouts,
# preferring ssl/. That probe order turns an INCREMENTAL pin bump into a trap:
# the new build writes root-layout archives, nothing deletes the old-layout
# ones, and the probe silently picks the stale pair — a link failure at best,
# at worst a "successful" build shipping the previous BoringSSL revision
# (i.e. a security bump that never actually landed).
#
# The fix is provenance, not probe order (reordering just mirrors the trap for
# the opposite migration): each build dir carries a stamp naming the submodule
# commit it was built from, and consumers wipe or reject a dir whose stamp
# does not match the current pin. A dir with no stamp has unknown provenance
# and is treated as stale — including pre-stamp build dirs, which pay one
# forced rebuild. CI caches are keyed by the pin, so a restored cache either
# matches or was already unusable.
#
# Usage (all three take <bssl_src_dir> <bssl_build_dir>):
#   bssl_guard_build_dir   before configuring/skip-checking: wipe on mismatch
#   bssl_stamp_build_dir   after a successful build: record provenance
#   bssl_verify_build_dir  consume-only paths (no rebuild available): fail
#                          loudly on mismatch instead of wiping

bssl_stamp_file() { echo "$2/.mqvpn-boringssl-commit"; }

bssl_guard_build_dir() {
    local src="$1" bdir="$2" want have
    want="$(git -C "$src" rev-parse HEAD)" || return 1
    if [ -d "$bdir" ]; then
        have="$(cat "$(bssl_stamp_file "$src" "$bdir")" 2>/dev/null || true)"
        if [ "$have" != "$want" ]; then
            echo "BoringSSL build dir is stale (built from '${have:-unknown}', pin is $want) — wiping $bdir"
            rm -rf "$bdir"
        fi
    fi
}

bssl_stamp_build_dir() {
    local src="$1" bdir="$2"
    git -C "$src" rev-parse HEAD > "$(bssl_stamp_file "$src" "$bdir")"
}

bssl_verify_build_dir() {
    local src="$1" bdir="$2" want have
    want="$(git -C "$src" rev-parse HEAD)" || return 1
    have="$(cat "$(bssl_stamp_file "$src" "$bdir")" 2>/dev/null || true)"
    if [ "$have" != "$want" ]; then
        echo "ERROR: BoringSSL build dir $bdir is stale or unstamped" >&2
        echo "       (built from '${have:-unknown}', pin is $want)." >&2
        echo "       Re-run the BoringSSL build phase for this target." >&2
        return 1
    fi
}
