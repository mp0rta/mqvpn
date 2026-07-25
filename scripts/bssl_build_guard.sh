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
# The fix is provenance: each build dir carries a stamp naming the source it
# was built from, and consumers wipe or reject a dir whose stamp does not
# match the current source. A dir with no stamp has unknown provenance and is
# treated as stale — including pre-stamp build dirs, which pay one forced
# rebuild.
#
# Provenance is a digest of the source CONTENT, not the submodule commit id.
# Reading the commit (`git -C <src> rev-parse HEAD`) was the obvious choice and
# is wrong twice over:
#
#   - It is unreadable in a tree that was copied rather than cloned. A
#     submodule's .git is a gitlink FILE pointing into the superproject's .git,
#     so `tar --exclude=.git` drops both — which is exactly what
#     .github/workflows/android-repro.yml does on purpose (repo metadata must
#     not leak into a reproducibility byte-comparison), and what a release
#     tarball looks like. Every consumer runs the guard bare under `set -e`, so
#     a git failure there aborted the whole build.
#   - It answers the wrong question even when it works. `rev-parse HEAD` names
#     the COMMITTED revision, so a locally modified BoringSSL working tree — a
#     hand-applied patch, a half-finished submodule update — stamps archives
#     with a commit they were not built from. That is the same "the bump never
#     actually landed" failure this guard exists to prevent, arriving through a
#     different door.
#
# A content digest has neither hole: it is computable in any tree and it
# changes when the source changes, committed or not. Cost is ~0.3 s over
# BoringSSL's ~400 MB / ~9.7k files, against a multi-minute build.
#
# The digest deliberately covers file paths and contents only — no mtimes,
# ownership or permission bits, which differ between a runner checkout and a
# container extraction of the same source (android-repro varies both by
# design). File modes are therefore invisible to it; content is what decides
# what the compiler produces here.
#
# Usage (all three take <bssl_src_dir> <bssl_build_dir>):
#   bssl_guard_build_dir   before configuring/skip-checking: wipe on mismatch
#   bssl_stamp_build_dir   after a successful build: record provenance
#   bssl_verify_build_dir  consume-only paths (no rebuild available): fail
#                          loudly on mismatch instead of wiping

# Renamed with the mechanism: the stamp holds a content digest now, not a
# commit id. Old stamps read as unstamped, i.e. stale — the same one forced
# rebuild a pre-stamp build dir already pays.
bssl_stamp_file() { echo "$2/.mqvpn-boringssl-provenance"; }

# sha256sum is coreutils; macOS ships shasum instead. Echoed as a command
# STRING because it must be usable both as an xargs command and inline, and
# shell functions cannot be either (xargs execs, it does not go through bash).
bssl_hash_cmd() {
    if command -v sha256sum > /dev/null 2>&1; then
        echo "sha256sum"
    else
        echo "shasum -a 256"
    fi
}

# Digest of the source tree's paths + contents. Echoes the digest, or nothing
# (plus an explanation on stderr) when the tree is missing or empty — which
# means the submodule was never checked out, and every consumer is about to
# fail at cmake anyway.
#
# Our own build output is excluded, and that exclusion is load-bearing rather
# than an optimisation: two of the three consumers put the build dir INSIDE the
# source dir (build.sh -> boringssl/build, ios/build-ios.sh -> boringssl/
# build-ios; only scripts/build_android.sh builds out of tree). A digest that
# walked into them would be self-invalidating, because the stamp file itself
# lives in the build dir — bssl_stamp_build_dir would record a digest that
# stopped being true the instant it was written, so bssl_verify_build_dir
# always failed (a hard error on the iOS path) and bssl_guard_build_dir always
# wiped (a silent full BoringSSL rebuild on every build.sh run). Excluding the
# build dirs also stops two sibling ones on the same machine from invalidating
# each other.
#
# The two paths are named EXACTLY, and both halves of that matter. `-name
# build` would also prune BoringSSL's real source dir at util/build/, and a
# `./build*` wildcard would prune anything upstream might add at the top level
# under that prefix (a build-support/, say). Either way the guard would go on
# reporting a match across a pin bump that only touched the dropped files —
# i.e. exactly the "the bump never actually landed" failure it exists to
# prevent, so the exclusion is kept as narrow as the consumers require. A
# consumer that adds a third in-tree build dir must add it here; it will
# announce itself loudly (verify fails, guard wipes every run) rather than
# silently widening what provenance covers.
#
# GNU-only spellings are avoided on purpose: this also runs on macOS via
# ios/build-ios.sh, where find(1) has no -printf and tar(1) has no --sort
# (-path and -prune are in POSIX find, so the exclusion above is portable).
# `-name .git -prune` matches the submodule's gitlink FILE as well as a
# standalone clone's .git directory. xargs may split a 9.7k-file list across
# several invocations; per-file lines keep the order xargs received them, so
# the outer digest is stable either way.
bssl_source_digest() {
    local src="$1" list hasher
    hasher="$(bssl_hash_cmd)"
    if [ ! -d "$src" ]; then
        echo "bssl_source_digest: $src does not exist" >&2
        return 1
    fi
    list="$(cd "$src" && find . -name .git -prune \
        -o \( -type d \( -path './build' -o -path './build-ios' \) -prune \) \
        -o -type f -print | LC_ALL=C sort)"
    if [ -z "$list" ]; then
        echo "bssl_source_digest: $src has no files (submodule not checked out?)" >&2
        return 1
    fi
    # shellcheck disable=SC2086  # hasher may carry arguments ("shasum -a 256")
    printf '%s\n' "$list" | (cd "$src" && xargs $hasher) | $hasher | cut -d' ' -f1
}

bssl_guard_build_dir() {
    local src="$1" bdir="$2" want have
    [ -d "$bdir" ] || return 0
    want="$(bssl_source_digest "$src")" || return 1
    have="$(head -n 1 "$(bssl_stamp_file "$src" "$bdir")" 2> /dev/null || true)"
    if [ "$have" != "$want" ]; then
        echo "BoringSSL build dir is stale (built from '${have:-unknown}', source is $want) — wiping $bdir"
        rm -rf "$bdir"
    fi
}

bssl_stamp_build_dir() {
    local src="$1" bdir="$2" want commit
    want="$(bssl_source_digest "$src")" || return 1
    # Line 1 is the digest and the only line ever compared. The commit, when
    # the tree still has the metadata to name one, rides along as a comment so
    # a human reading the stamp can tell which revision this was — it is
    # informational precisely because it can be a lie about a dirty tree.
    commit="$(git -C "$src" rev-parse HEAD 2> /dev/null || true)"
    # if/fi, not `[ -n "$commit" ] && printf`: the latter is the last command
    # of the group when there is no commit, so the function would return 1 and
    # abort every caller (they all run it bare under `set -e`).
    {
        printf '%s\n' "$want"
        if [ -n "$commit" ]; then
            printf '# commit %s\n' "$commit"
        fi
    } > "$(bssl_stamp_file "$src" "$bdir")"
}

bssl_verify_build_dir() {
    local src="$1" bdir="$2" want have
    want="$(bssl_source_digest "$src")" || return 1
    have="$(head -n 1 "$(bssl_stamp_file "$src" "$bdir")" 2> /dev/null || true)"
    if [ "$have" != "$want" ]; then
        echo "ERROR: BoringSSL build dir $bdir is stale or unstamped" >&2
        echo "       (built from '${have:-unknown}', source is $want)." >&2
        echo "       Re-run the BoringSSL build phase for this target." >&2
        return 1
    fi
}
