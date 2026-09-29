#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and contributors
#
# Regenerates every chain/identity fixture under tests/certs/ (the self-signed
# test.crt/test.key/test.der pair is separate and NOT touched). Run from this
# directory. One run regenerates ALL keys and certificates, so commit the
# whole output together: tests/test_server.c byte-compares chain-leaf.der
# and chain-intermediate.der, and tests/check_cert_fixtures.sh re-verifies
# the committed set.
#
#   mqvpn test root CA (committed as chain-root.der; trusted only where a
#   test says so — never in a real store)
#     └─ mqvpn test intermediate CA        → chain-intermediate.der
#          ├─ mqvpn-test                   → chain-leaf.key/.der, chain-fullchain.crt
#          ├─ a.example.com                → identity-dns.der
#          ├─ *.example.com                → identity-wildcard.der
#          ├─ 192.0.2.10 / 2001:db8::1 / ::ffff:198.51.100.7 → identity-ip.der
#          ├─ (no SAN, CN a.example.com)   → identity-cn-only.der
#          ├─ f*.example.com               → identity-wildcard-partial.der
#          ├─ *.*.example.com              → identity-wildcard-multi.der
#          ├─ a.example.comzevil, z→NUL    → identity-san-nul.der  (a.example.com\0evil)
#          ├─ same + a.example.com, z→NUL  → identity-san-mixed.der
#          └─ a.example.com, SAN tag→0xff  → identity-san-malformed.der (CN "malformed")
#   other root CA (NOT committed, trusted nowhere)
#     └─ other intermediate CA            → other-intermediate.der
#          └─ a.example.com                → other-leaf.der
#
# The three patched leaves have invalid signatures (the TBSCertificate
# changed after issuance); the tests that use them assert an identity
# verdict that is reached before trust is consulted.
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
days=3650
ec="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"

# mkroot PREFIX CN
mkroot() {
    # shellcheck disable=SC2086
    openssl req -x509 $ec -keyout "$tmp/$1.key" -out "$tmp/$1.crt" -days "$days" \
        -subj "/CN=$2" -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}
# mkint PREFIX ROOTPREFIX CN
mkint() {
    # shellcheck disable=SC2086
    openssl req $ec -keyout "$tmp/$1.key" -out "$tmp/$1.csr" -subj "/CN=$3" 2>/dev/null
    printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' > "$tmp/$1.ext"
    openssl x509 -req -in "$tmp/$1.csr" -CA "$tmp/$2.crt" -CAkey "$tmp/$2.key" \
        -CAcreateserial -out "$tmp/$1.crt" -days "$days" -extfile "$tmp/$1.ext" 2>/dev/null
}
# mkleaf PREFIX INTPREFIX CN SAN("" = no SAN extension) [KEYFILE]
mkleaf() {
    keyout="$tmp/$1.key"
    if [ $# -ge 5 ]; then keyout="$5"; fi
    # shellcheck disable=SC2086
    openssl req $ec -keyout "$keyout" -out "$tmp/$1.csr" -subj "/CN=$3" 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' > "$tmp/$1.ext"
    if [ -n "$4" ]; then printf 'subjectAltName=%s\n' "$4" >> "$tmp/$1.ext"; fi
    openssl x509 -req -in "$tmp/$1.csr" -CA "$tmp/$2.crt" -CAkey "$tmp/$2.key" \
        -CAcreateserial -out "$tmp/$1.crt" -days "$days" -extfile "$tmp/$1.ext" 2>/dev/null
    openssl x509 -in "$tmp/$1.crt" -outform DER -out "$tmp/$1.der"
}
# offset_of FILE STRING → byte offset of the first occurrence (ASCII in DER).
# Every patched leaf uses a CN that does not contain the needle, so the
# first occurrence is the SAN entry. Aborts if the needle is absent (dash
# would otherwise evaluate $((off + 13)) with an empty off as 13). A needle
# matched twice on one line would print two offsets; that is rejected too.
offset_of() {
    off=$(grep -bo -a -F -m1 "$2" "$1" | cut -d: -f1)
    case $off in
        ''|*[!0-9]*)
            echo "gen_chain.sh: '$2' not found exactly once in $1" >&2
            exit 1 ;;
    esac
    printf '%s' "$off"
}
# patch_byte FILE OFFSET ESCAPE   (%b escape, e.g. '\000' or '\377')
patch_byte() {
    printf '%b' "$3" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}

# ---- trusted chain ----
mkroot root "mqvpn test root CA"
mkint  int root "mqvpn test intermediate CA"
mkleaf leaf int "mqvpn-test" "DNS:mqvpn-test" chain-leaf.key
cat "$tmp/leaf.crt" "$tmp/int.crt" > chain-fullchain.crt
cp "$tmp/leaf.der" chain-leaf.der
openssl x509 -in "$tmp/int.crt"  -outform DER -out chain-intermediate.der
openssl x509 -in "$tmp/root.crt" -outform DER -out chain-root.der

mkleaf idns   int "a.example.com" "DNS:a.example.com"
cp "$tmp/idns.der" identity-dns.der
mkleaf iwild  int "wildcard" "DNS:*.example.com"
cp "$tmp/iwild.der" identity-wildcard.der
mkleaf iip    int "ip" "IP:192.0.2.10,IP:2001:db8::1,IP:::ffff:198.51.100.7"
cp "$tmp/iip.der" identity-ip.der
mkleaf icn    int "a.example.com" ""
cp "$tmp/icn.der" identity-cn-only.der
mkleaf iwpart int "partial" "DNS:f*.example.com"
cp "$tmp/iwpart.der" identity-wildcard-partial.der
mkleaf iwmult int "multi" "DNS:*.*.example.com"
cp "$tmp/iwmult.der" identity-wildcard-multi.der

# NUL inside a dNSName: "a.example.comzevil" with the 'z' (index 13) → 0x00
# gives "a.example.com\0evil" — the classic truncation shape.
mkleaf inul int "nul" "DNS:a.example.comzevil"
off=$(offset_of "$tmp/inul.der" "a.example.comzevil")
cp "$tmp/inul.der" identity-san-nul.der
patch_byte identity-san-nul.der $((off + 13)) '\000'
# same, followed by a valid matching entry
mkleaf imix int "mixed" "DNS:a.example.comzevil,DNS:a.example.com"
off=$(offset_of "$tmp/imix.der" "a.example.comzevil")
cp "$tmp/imix.der" identity-san-mixed.der
patch_byte identity-san-mixed.der $((off + 13)) '\000'
# malformed SAN: a leaf whose CN does not contain the SAN string (so the
# first occurrence IS the SAN entry); its dNSName tag byte (0x82, two bytes
# before the string — short-form length) becomes 0xff, which is no
# GeneralName choice. The certificate itself still loads; only the SAN is
# undecodable.
mkleaf imal int "malformed" "DNS:a.example.com"
off=$(offset_of "$tmp/imal.der" "a.example.com")
cp "$tmp/imal.der" identity-san-malformed.der
patch_byte identity-san-malformed.der $((off - 2)) '\377'

# ---- second, untrusted chain (its root never leaves $tmp) ----
mkroot oroot "other root CA"
mkint  oint oroot "other intermediate CA"
mkleaf oleaf oint "a.example.com" "DNS:a.example.com"
openssl x509 -in "$tmp/oint.crt" -outform DER -out other-intermediate.der
cp "$tmp/oleaf.der" other-leaf.der

# ---- self-check: every well-formed leaf verifies under its own root ----
for p in leaf idns iwild iip icn iwpart iwmult; do
    openssl verify -CAfile "$tmp/root.crt" -untrusted "$tmp/int.crt" \
        -purpose sslserver "$tmp/$p.crt" > /dev/null
done
openssl verify -CAfile "$tmp/oroot.crt" -untrusted "$tmp/oint.crt" \
    -purpose sslserver "$tmp/oleaf.crt" > /dev/null
echo "fixtures regenerated"
