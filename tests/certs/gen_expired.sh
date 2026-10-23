#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and contributors
#
# Regenerates expired.crt/expired.key: a self-signed mqvpn-test certificate
# whose validity ended in 2020, so a store that trusts it still rejects it as
# expired (X509 error 10) and nothing else. Run from this directory.
# `openssl req -x509` cannot backdate before OpenSSL 3.4, hence `openssl ca`.
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
touch "$tmp/index.txt"
cat > "$tmp/ca.cnf" <<EOF
[ca]
default_ca = d
[d]
database = $tmp/index.txt
new_certs_dir = $tmp
serial = $tmp/serial
default_md = sha256
policy = p
copy_extensions = copy
[p]
commonName = supplied
EOF
echo 01 > "$tmp/serial"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout expired.key -out "$tmp/req.csr" -subj "/CN=mqvpn-test" \
    -addext "subjectAltName=DNS:mqvpn-test" 2>/dev/null
openssl ca -batch -selfsign -config "$tmp/ca.cnf" -keyfile expired.key \
    -in "$tmp/req.csr" -startdate 20200101000000Z -enddate 20200102000000Z \
    -notext -out expired.crt 2>/dev/null
