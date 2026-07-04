#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# hybrid_h2_rst_target.py — Test 5 egress-side target for the abortive-close
# (RST) e2e proof. Accepts one connection and streams a steady trickle of
# data so the caller can observe "flowing" before the abort. On SIGTERM it
# sets SO_LINGER{on=1, timeout=0} and closes the socket, which makes the
# kernel discard any unsent data and send a real RST instead of the usual
# FIN — an actual abortive close, not an incidental one. The caller
# (test_e2e_hybrid_h2.sh) sends the SIGTERM while the connection is live and
# asserts the client-side reader (through the tunnel) tears down promptly,
# proving the RST propagated through the server's H3 error-mapping rather
# than the client hanging until the idle-eviction sweep.
import signal
import socket
import struct
import sys
import time

port = int(sys.argv[1])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(1)
conn, _ = srv.accept()


def on_term(signum, frame):
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()
    sys.exit(0)


signal.signal(signal.SIGTERM, on_term)

while True:
    try:
        conn.sendall(b"data\n")
    except (BrokenPipeError, OSError):
        # Peer went away before our own SIGTERM fired — nothing left to do.
        sys.exit(0)
    time.sleep(0.1)
