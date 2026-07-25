#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# scripts/bssl_build_guard.sh behaviour.
#
# Two halves. First, the provenance contract itself (stamp, keep, wipe, loud
# reject). Second, the two properties that made provenance content-derived
# rather than `git rev-parse HEAD`:
#
#   - a tree with no git metadata must still work. A submodule's .git is a
#     gitlink FILE, so `tar --exclude=.git` drops it; that is what
#     android-repro.yml builds from and what a release tarball looks like. The
#     commit-based guard aborted there ("fatal: not a git repository") and took
#     the whole build with it.
#   - a MODIFIED source tree must invalidate the build dir. The commit-based
#     guard could not see this at all: rev-parse reports the committed
#     revision, so archives built from a patched tree were stamped as if they
#     came from the clean pin.
#
# Throwaway trees in a temp dir — no submodules, no network, no BoringSSL
# build. Functions are called the way the consumers call them (sourced, under
# `set -e`), because there "returns nonzero" and "aborts the build" are the
# same event and only the second is observable to a user.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/bssl_build_guard.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

ok() { printf 'PASS: %s\n' "$1"; }
bad() {
    printf 'FAIL: %s\n' "$1"
    fail=1
}

# A minimal "BoringSSL source tree": a couple of files in a subdir.
make_src() {
    local d="$WORK/$1"
    mkdir -p "$d/crypto"
    echo "int ssl(void);" > "$d/ssl.h"
    echo "int crypto(void);" > "$d/crypto/crypto.h"
    echo "$d"
}

make_build_dir() {
    local d="$WORK/$1"
    mkdir -p "$d"
    echo "archive" > "$d/libssl.a"
    echo "$d"
}

# Run a guard call exactly as a consumer does. Echoes the exit status; output
# lands in $WORK/out.
run_guarded() {
    (
        set -euo pipefail
        # shellcheck source=/dev/null
        source "$GUARD"
        "$@"
    ) > "$WORK/out" 2>&1
    echo $?
}

stamp_of() { head -n 1 "$1/.mqvpn-boringssl-provenance" 2> /dev/null || true; }

# ── 1. provenance contract ────────────────────────────────────────────────
src="$(make_src src1)"
bdir="$(make_build_dir build1)"

rc="$(run_guarded bssl_stamp_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ] || [ -z "$(stamp_of "$bdir")" ]; then
    bad "stamp did not record provenance (rc=$rc)"
    sed 's/^/      /' "$WORK/out"
else
    ok "stamp records provenance"
fi

rc="$(run_guarded bssl_guard_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ] || [ ! -f "$bdir/libssl.a" ]; then
    bad "guard wiped a build dir that matches its source (rc=$rc)"
else
    ok "guard keeps a build dir that matches its source"
fi

rc="$(run_guarded bssl_verify_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ]; then
    bad "verify rejected a matching stamp (rc=$rc)"
else
    ok "verify accepts a matching stamp"
fi

# Unstamped dir (a pre-stamp build): unknown provenance is stale by contract.
rm -f "$bdir/.mqvpn-boringssl-provenance"
rc="$(run_guarded bssl_guard_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ] || [ -d "$bdir" ]; then
    bad "guard did not wipe an unstamped build dir (rc=$rc)"
else
    ok "guard wipes an unstamped build dir"
fi

# Consume-only path: a mismatch must fail loudly, never wipe-and-continue.
bdir="$(make_build_dir build1b)"
echo "0000000000000000000000000000000000000000000000000000000000000000" \
    > "$bdir/.mqvpn-boringssl-provenance"
rc="$(run_guarded bssl_verify_build_dir "$src" "$bdir")"
if [ "$rc" -eq 0 ]; then
    bad "verify accepted a stamp from another source"
elif ! grep -q "ERROR" "$WORK/out"; then
    bad "verify failed without saying why"
elif [ ! -d "$bdir" ]; then
    bad "verify wiped the build dir; the consume-only path must not"
else
    ok "verify rejects a stamp from another source, loudly, without wiping"
fi

# ── 2. no git metadata (the android-repro / tarball case) ─────────────────
# Nothing here is a git repo: make_src never runs `git init`. The old guard
# aborted at this point.
src="$(make_src src2)"
bdir="$(make_build_dir build2)"

rc="$(run_guarded bssl_stamp_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ] || [ -z "$(stamp_of "$bdir")" ]; then
    bad "stamp fails without git metadata (rc=$rc)"
    sed 's/^/      /' "$WORK/out"
else
    ok "stamp works without git metadata"
fi

rc="$(run_guarded bssl_guard_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ] || [ ! -f "$bdir/libssl.a" ]; then
    bad "guard fails or over-wipes without git metadata (rc=$rc)"
    sed 's/^/      /' "$WORK/out"
else
    ok "guard works without git metadata"
fi

rc="$(run_guarded bssl_verify_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ]; then
    bad "verify fails without git metadata (rc=$rc)"
    sed 's/^/      /' "$WORK/out"
else
    ok "verify works without git metadata"
fi

# ── 3. a modified source invalidates the build dir ────────────────────────
# The property `git rev-parse HEAD` cannot have: this edit is uncommitted, so
# a commit-based stamp would still read as a match.
echo "int ssl_patched(void);" >> "$src/ssl.h"
rc="$(run_guarded bssl_guard_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ]; then
    bad "guard errored on a modified source (rc=$rc)"
elif [ -d "$bdir" ]; then
    bad "guard kept a build dir after the source was modified"
else
    ok "guard wipes a build dir after the source was modified"
fi

# A new file must count too, not just changed contents.
bdir="$(make_build_dir build3)"
run_guarded bssl_stamp_build_dir "$src" "$bdir" > /dev/null
echo "int extra(void);" > "$src/crypto/extra.h"
rc="$(run_guarded bssl_guard_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ] || [ -d "$bdir" ]; then
    bad "guard kept a build dir after a file was added to the source (rc=$rc)"
else
    ok "guard wipes a build dir after a file was added to the source"
fi

# ── 4. the digest ignores what android-repro deliberately varies ──────────
# Two copies of one source, differing in mtimes, ownership bits we can change
# unprivileged (mode), and directory-entry order, must stamp identically —
# otherwise the reproducibility gate's two trees would disagree about their
# own source.
a="$(make_src copyA)"
b="$WORK/copyB"
mkdir -p "$b"
tar -C "$a" -cf - . | tar -C "$b" -xmf -
find "$b" -type f -exec touch -t 199901010000 {} +
chmod -R g-rwx,o-rwx "$b"
da="$(bash -c "source '$GUARD'; bssl_source_digest '$a'")"
db="$(bash -c "source '$GUARD'; bssl_source_digest '$b'")"
if [ -z "$da" ] || [ "$da" != "$db" ]; then
    bad "digest differs between copies of one source (mtime/mode sensitivity): $da vs $db"
else
    ok "digest ignores mtimes, modes and copy location"
fi

# ── 5. build dirs INSIDE the source tree ──────────────────────────────────
# build.sh puts its build dir at boringssl/build and ios/build-ios.sh at
# boringssl/build-ios; only scripts/build_android.sh builds out of tree. The
# cases above all used a sibling build dir, i.e. the out-of-tree layout only,
# and so missed the in-tree one entirely: a digest that walks into the build
# dir also walks over the stamp file living there, so the stamp is false the
# moment it is written. That shipped — the iOS CI job failed at
# `build-ios.sh mqvpn` with "build dir is stale or unstamped", and every
# build.sh run silently re-built BoringSSL from scratch.
src="$(make_src src5)"
bdir="$(make_build_dir src5/build-ios)"

rc="$(run_guarded bssl_stamp_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ]; then
    bad "stamp failed for a build dir inside the source tree (rc=$rc)"
    sed 's/^/      /' "$WORK/out"
else
    rc="$(run_guarded bssl_verify_build_dir "$src" "$bdir")"
    if [ "$rc" -ne 0 ]; then
        bad "the stamp it just wrote does not verify (rc=$rc); the digest is self-invalidating"
        sed 's/^/      /' "$WORK/out"
    else
        ok "an in-tree build dir stamps and verifies"
    fi
fi

# A second in-tree build dir (build.sh's, next to the iOS one) must not
# invalidate this one — otherwise two consumers on one machine wipe each
# other's BoringSSL build on every run.
other="$(make_build_dir src5/build)"
echo "more output" > "$other/extra.o"
rc="$(run_guarded bssl_verify_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ]; then
    bad "a sibling in-tree build dir invalidated the stamp (rc=$rc)"
    sed 's/^/      /' "$WORK/out"
else
    ok "a sibling in-tree build dir does not invalidate the stamp"
fi

# The exclusion must stay as narrow as the consumers require. Anything wider
# drops real source from provenance, and the guard then reports a match across
# a pin bump that only touched the dropped files — the "the bump never landed"
# failure it exists to prevent. Two ways to get that wrong, one case each:
# excluding by NAME would take BoringSSL's real util/build/ source dir with it,
# and a './build*' wildcard would take any top-level dir upstream adds under
# that prefix.
for probe in util/build build-support; do
    mkdir -p "$src/$probe"
    echo "package build" > "$src/$probe/build.go"
    run_guarded bssl_stamp_build_dir "$src" "$bdir" > /dev/null
    echo "// patched" >> "$src/$probe/build.go"
    rc="$(run_guarded bssl_verify_build_dir "$src" "$bdir")"
    if [ "$rc" -eq 0 ]; then
        bad "a change under $probe/ went unnoticed; the build-dir exclusion is too wide"
    else
        ok "a change under $probe/ still invalidates the stamp"
    fi
done

# ── 6. missing/empty source is an error, not a silent pass ────────────────
rc="$(run_guarded bssl_source_digest "$WORK/does-not-exist")"
if [ "$rc" -eq 0 ]; then
    bad "digest of a missing source tree succeeded"
else
    ok "digest of a missing source tree fails loudly"
fi

mkdir -p "$WORK/empty-src"
rc="$(run_guarded bssl_source_digest "$WORK/empty-src")"
if [ "$rc" -eq 0 ]; then
    bad "digest of an empty source tree succeeded (submodule not checked out)"
else
    ok "digest of an empty source tree fails loudly"
fi

if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS"
