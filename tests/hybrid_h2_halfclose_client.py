#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# hybrid_h2_halfclose_client.py — Test 4 client half of the asymmetric-close
# (SHUT_WR) e2e proof. Sends a fixed payload, half-closes the write side
# (shutdown(SHUT_WR)) while keeping the read side open, and prints whatever
# the peer sends back before it closes. The caller (test_e2e_hybrid_h2.sh)
# pairs this with a server-side responder that deliberately waits for the
# peer FIN (recv() returning empty) before replying — so a reply arriving
# here is proof the half-close survived end-to-end through the tunnel's
# TCP-lane relay, rather than the client/server side collapsing it into a
# full close.
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port), timeout=10)
s.sendall(b"hello\n")
s.shutdown(socket.SHUT_WR)  # half-close: no more writes, keep reading
data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
print(data.decode(), end="")
s.close()
