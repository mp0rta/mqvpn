#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# hybrid_h2_v6_sink.py — Test 8 IPv6 TCP-lane target for
# test_e2e_hybrid_h2.sh. Binds an AF_INET6 listener on a given address:port,
# accepts exactly one connection, and keeps a running received-byte total in
# a file (rewritten after every recv()) so the caller can observe continued
# progress across a path-down failover — the same "keep polling the byte
# counter" technique Test 6's lane responder uses for its sticky-RAW
# continuity check, applied here to a real IPv6 TCP-lane flow. Unlike
# hybrid_h2_lane_responder.py, this script does not record the peer address
# (Test 8 uses a fixed Tcp=stream policy, so there is no sticky-RAW-vs-lane
# ambiguity to resolve — see that test's rationale for why peer address
# matters only under Tcp=auto).
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
bytes_file = sys.argv[3]

srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((host, port))
srv.listen(1)
conn, _ = srv.accept()

total = 0
with open(bytes_file, "w") as f:
    f.write("0")

conn.settimeout(120)
try:
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        total += len(chunk)
        with open(bytes_file, "w") as f:
            f.write(str(total))
except (socket.timeout, OSError):
    pass
