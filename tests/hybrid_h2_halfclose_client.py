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
#
# The sleep before shutdown() is deliberate: sendall() immediately followed
# by shutdown() risks the data and the FIN going out back-to-back with no
# intervening round trip, i.e. "coalesced" from the test's point of view —
# the original version of this test had no such gap. Sleeping here forces a
# real round trip (data flushed, relayed server-side, ACKed) to complete
# before the FIN goes out as a distinct, later event, which is the closer
# analogue of the server-side dispatch gap C1 fixes (mqvpn_server.c
# cb_request_read: a fin observed after the body notify has already fully
# drained). Note for future readers: unit-level tracing (tests/
# test_tcp_egress.c's mqvpn_tcp_bodiless_fin_becomes_shut_wr) found that
# xquic's H3 layer resolves EVERY xqc_h3_request_send_body(NULL, 0, fin=1)
# call — coalesced or not — through the ordinary XQC_REQ_NOTIFY_READ_BODY
# notify path (a fin-only send still emits a 2-byte empty-DATA-frame header,
# never a truly bodiless QUIC STREAM frame), so this delay is a defense-in-
# depth improvement to this e2e test rather than a guaranteed reproduction
# of the standalone XQC_REQ_NOTIFY_READ_EMPTY_FIN notify shape; the
# deterministic regression coverage for that exact notify lives in the unit
# test above.
import socket
import sys
import time

host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port), timeout=10)
s.sendall(b"hello\n")
time.sleep(0.5)
s.shutdown(socket.SHUT_WR)  # half-close: no more writes, keep reading
data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
print(data.decode(), end="")
s.close()
