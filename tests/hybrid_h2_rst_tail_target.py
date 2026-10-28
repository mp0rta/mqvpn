#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# hybrid_h2_rst_tail_target.py — Test 5b egress-side origin for the
# data-then-reset ("lingering close") e2e measurement. Accepts one
# connection, writes N bytes of a position-dependent pattern, waits until
# its own kernel reports the send queue empty (SIOCOUTQ == 0: every byte
# has been acknowledged by the peer, i.e. the mqvpn server's egress socket
# holds it), then closes with SO_LINGER{1,0} so the kernel sends a RST.
# Waiting for the queue to drain first means the origin itself discards
# nothing: whatever the reader in the client netns does not receive was
# lost on the far side of the server's egress socket.
#
# With "fin" as the third argument it closes normally instead (a FIN): the
# control case, which must deliver every byte.
#
# Prints one line: "sent=<N> drained=<0|1> drain_ms=<ms>".
#
# usage: hybrid_h2_rst_tail_target.py <port> <nbytes> [rst|fin]
import fcntl
import socket
import struct
import sys
import time

SIOCOUTQ = 0x5411  # == TIOCOUTQ on Linux

_BASE = bytes((i * 7) & 0xFF for i in range(256))
_BLOCKS = {}


def _block(b):
    # 64 KiB block b of the pattern: byte i of the stream is
    # (i * 7 + i // 65536) & 0xff. Cheap to regenerate on either side, and a
    # shifted, repeated or zero-filled block does not match the expected bytes.
    blk = _BLOCKS.get(b)
    if blk is None:
        table = bytes((v + b) & 0xFF for v in range(256))
        blk = _BLOCKS[b] = _BASE.translate(table) * 256
    return blk


def pattern(off, n):
    out = []
    while n > 0:
        b, i = divmod(off, 65536)
        take = min(n, 65536 - i)
        out.append(_block(b)[i:i + take])
        off += take
        n -= take
    return b"".join(out)


port = int(sys.argv[1])
total = int(sys.argv[2])
close_mode = sys.argv[3] if len(sys.argv) > 3 else "rst"
data = pattern(0, total)  # built before accept() so the send runs at line rate
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(1)
srv.settimeout(30)
conn, _ = srv.accept()
conn.settimeout(30)

conn.sendall(data)

t0 = time.monotonic()
drained = 0
while time.monotonic() - t0 < 20:
    outq = struct.unpack("i", fcntl.ioctl(conn.fileno(), SIOCOUTQ, b"\0\0\0\0"))[0]
    if outq == 0:
        drained = 1
        break
    time.sleep(0.001)
drain_ms = int((time.monotonic() - t0) * 1000)

if close_mode == "rst":
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
conn.close()
print("sent=%d drained=%d drain_ms=%d" % (total, drained, drain_ms), flush=True)
