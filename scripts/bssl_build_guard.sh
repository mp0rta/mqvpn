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
# Trees without git metadata: the pin is read with `git rev-parse`, which has
# nothing to read when the source tree was extracted from an archive rather
# than cloned — a release tarball, or the deliberately .git-less copies
# .github/workflows/android-repro.yml builds from (`tar --exclude=.git`, so
# that repo metadata cannot leak into a reproducibility comparison). Every
# consumer runs under `set -e`, so an unguarded `git` failure there aborts the
# whole build. "Cannot determine the pin" is therefore handled explicitly
# below, and always in the direction that cannot ship a stale archive: guard
# wipes, stamp records nothing, verify skips. CI itself always has git
# metadata (actions/checkout), so the loud consume-only failure this guard
# exists for is unaffected.
#
# Usage (all three take <bssl_src_dir> <bssl_build_dir>):
#   bssl_guard_build_dir   before configuring/skip-checking: wipe on mismatch
#   bssl_stamp_build_dir   after a successful build: record provenance
#   bssl_verify_build_dir  consume-only paths (no rebuild available): fail
#                          loudly on mismatch instead of wiping

bssl_stamp_file() { echo "$2/.mqvpn-boringssl-commit"; }

# Echoes the pinned commit, or nothing when it cannot be determined (no git
# metadata, git not installed). Never fails: callers decide what "unknown"
# means for them, and none of them may abort the build over it.
bssl_pin_commit() { git -C "$1" rev-parse HEAD 2>/dev/null || true; }

bssl_guard_build_dir() {
    local src="$1" bdir="$2" want have
    want="$(bssl_pin_commit "$src")"
    [ -d "$bdir" ] || return 0
    if [ -z "$want" ]; then
        # Unknown pin: provenance cannot be established, so the dir cannot be
        # trusted. Wiping costs a rebuild; keeping it risks linking archives
        # from another revision, which is the failure this guard exists to
        # prevent.
        echo "BoringSSL pin is undeterminable in $src (no git metadata) — wiping $bdir"
        rm -rf "$bdir"
        return 0
    fi
    have="$(cat "$(bssl_stamp_file "$src" "$bdir")" 2>/dev/null || true)"
    if [ "$have" != "$want" ]; then
        echo "BoringSSL build dir is stale (built from '${have:-unknown}', pin is $want) — wiping $bdir"
        rm -rf "$bdir"
    fi
}

bssl_stamp_build_dir() {
    local src="$1" bdir="$2" want
    want="$(bssl_pin_commit "$src")"
    if [ -z "$want" ]; then
        # Leave no stamp rather than an empty one: an empty stamp reads as a
        # real recorded provenance that matches nothing, which would make a
        # later verify report "stale" for a dir that is simply unattributable.
        rm -f "$(bssl_stamp_file "$src" "$bdir")"
        return 0
    fi
    printf '%s\n' "$want" > "$(bssl_stamp_file "$src" "$bdir")"
}

bssl_verify_build_dir() {
    local src="$1" bdir="$2" want have
    want="$(bssl_pin_commit "$src")"
    if [ -z "$want" ]; then
        echo "WARNING: BoringSSL pin is undeterminable in $src (no git metadata);" >&2
        echo "         skipping the provenance check for $bdir." >&2
        return 0
    fi
    have="$(cat "$(bssl_stamp_file "$src" "$bdir")" 2>/dev/null || true)"
    if [ "$have" != "$want" ]; then
        echo "ERROR: BoringSSL build dir $bdir is stale or unstamped" >&2
        echo "       (built from '${have:-unknown}', pin is $want)." >&2
        echo "       Re-run the BoringSSL build phase for this target." >&2
        return 1
    fi
}
