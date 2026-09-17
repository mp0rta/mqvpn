#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and contributors
#
# Verifies that the committed certificate fixtures under tests/certs are one
# consistent set: every well-formed leaf chains to chain-root.der through
# chain-intermediate.der, other-leaf.der chains to other-intermediate.der
# and NOT to chain-root.der, every leaf's AKI is the committed intermediate's
# SKI (so a regenerated chain with stale leaves is caught), and the three
# byte-patched leaves are exactly the patched forms the identity tests rely
# on. A partially regenerated directory fails here on every PR instead of
# only on Windows CI.
set -euo pipefail
cd "$(dirname "$0")/certs"

fail=0
say_fail() {
    echo "FAIL: $*"
    fail=1
}

leaves=(chain-leaf identity-dns identity-wildcard identity-ip identity-cn-only
        identity-wildcard-partial identity-wildcard-multi)
patched=(identity-san-nul identity-san-mixed identity-san-malformed)

root=$(mktemp); inter=$(mktemp); oint=$(mktemp); oleaf=$(mktemp)
trap 'rm -f "$root" "$inter" "$oint" "$oleaf"' EXIT
openssl x509 -in chain-root.der -inform DER -out "$root"
openssl x509 -in chain-intermediate.der -inform DER -out "$inter"
openssl x509 -in other-intermediate.der -inform DER -out "$oint"

for f in "${leaves[@]}"; do
    out=$(openssl verify -CAfile "$root" -untrusted "$inter" -purpose sslserver \
          <(openssl x509 -in "$f.der" -inform DER) 2>&1) || true
    if [[ "$out" != *": OK" ]]; then say_fail "$f.der does not verify under chain-root: $out"; fi
done

# other-leaf: convert once (a conversion failure is a setup error, not a "rejection")
if ! openssl x509 -in other-leaf.der -inform DER -out "$oleaf" 2>/dev/null; then say_fail "other-leaf.der does not load"; fi
out=$(openssl verify -partial_chain -CAfile "$oint" -purpose sslserver "$oleaf" 2>&1) || true
if [[ "$out" != *": OK" ]]; then say_fail "other-leaf.der does not chain to other-intermediate: $out"; fi
# the negative case must be a genuine verification failure (exit 2 + "verification failed"),
# not a command/setup error — an operational failure must not read as "rejected"
# (an && … || … list so `set -e` does not abort on the expected non-zero exit)
out=$(openssl verify -CAfile "$root" -untrusted "$oint" -purpose sslserver "$oleaf" 2>&1) && rc=0 || rc=$?
if [[ $rc -ne 2 || "$out" != *"verification failed"* || "$out" != *"unable to get local issuer certificate"* ]]; then
    say_fail "other-leaf.der under chain-root: expected a clean trust rejection, got rc=$rc: $out"
fi

# every leaf (patched ones included) must have been issued by the committed
# intermediate: compare its AKI to the intermediate's SKI. gen_chain.sh emits
# keyid-only AKIs, so the value is the single last line of `-ext` output.
# `|| true`: a leaf that does not load must reach say_fail with an empty AKI,
# not abort the script silently (pipefail + 2>/dev/null would print nothing).
ski=$(openssl x509 -in "$inter" -noout -ext subjectKeyIdentifier 2>/dev/null | tail -1 | tr -d ' ') || true
if [[ -z "$ski" ]]; then say_fail "cannot read the intermediate's SKI"; fi
for f in "${leaves[@]}" "${patched[@]}"; do
    aki=$(openssl x509 -in "$f.der" -inform DER -noout -ext authorityKeyIdentifier 2>/dev/null | tail -1 | tr -d ' ') || true
    if [[ "$aki" != "$ski" ]]; then say_fail "$f.der AKI ($aki) != intermediate SKI ($ski): stale leaf"; fi
done

# byte-patched leaves: the exact bytes the identity tests depend on
if ! python3 - <<'EOF'
import sys
def find(f, needle):
    d = open(f, "rb").read()
    if d.find(needle) < 0:
        print(f"FAIL: {f}: pattern not found"); sys.exit(1)
    return d
find("identity-san-nul.der", b"\x82\x12a.example.com\x00evil")
d = find("identity-san-mixed.der", b"\x82\x12a.example.com\x00evil")
if d.find(b"\x82\x0da.example.com") < 0: print("FAIL: identity-san-mixed.der: valid entry missing"); sys.exit(1)
d = find("identity-san-malformed.der", b"\xff\x0da.example.com")
if d.find(b"\x82\x0da.example.com") >= 0: print("FAIL: identity-san-malformed.der: an intact dNSName entry remains"); sys.exit(1)
EOF
then fail=1; fi

# the malformed leaf must still be a loadable certificate whose SAN does not decode
if ! openssl x509 -in identity-san-malformed.der -inform DER -noout 2>/dev/null; then
    say_fail "identity-san-malformed.der does not load as a certificate (the patch must hit the SAN, not the subject)"
fi
out=$(openssl x509 -in identity-san-malformed.der -inform DER -noout -text 2>&1) || true
if [[ "$out" == *"DNS:a.example.com"* ]]; then say_fail "identity-san-malformed.der: SAN still decodes"; fi

# the fullchain served by tests must be leaf + intermediate, in that order
n=$(grep -c "BEGIN CERTIFICATE" chain-fullchain.crt 2>/dev/null || true); n=${n:-0}
if [[ "$n" != 2 ]]; then say_fail "chain-fullchain.crt has $n certificates, expected 2"; fi
if ! cmp -s <(openssl x509 -in chain-fullchain.crt -outform DER) chain-leaf.der; then
    say_fail "chain-fullchain.crt first certificate != chain-leaf.der"
fi

if [[ $fail -ne 0 ]]; then exit 1; fi
echo "PASS: certificate fixtures are consistent"
