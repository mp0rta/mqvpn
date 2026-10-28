#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# hybrid_h2_rst_tail_reader.py — Test 5b client-netns reader. Connects
# through the tunnel to hybrid_h2_rst_tail_target.py, reads until the
# connection ends, and checks every byte it received against the target's
# pattern.
#
# Prints one line:
#   "received=<K> end=<FIN|RST|TIMEOUT|ERROR> pattern_ok=<0|1>"
# FIN = clean EOF, RST = ECONNRESET.
#
# usage: hybrid_h2_rst_tail_reader.py <host> <port> <timeout_s>
import socket
import sys

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


host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.create_connection((host, port), timeout=timeout)
s.settimeout(timeout)
received = 0
ok = 1
end = "ERROR"
try:
    while True:
        b = s.recv(262144)
        if not b:
            end = "FIN"
            break
        if ok and b != pattern(received, len(b)):
            ok = 0
        received += len(b)
except ConnectionResetError:
    end = "RST"
except socket.timeout:
    end = "TIMEOUT"
print("received=%d end=%s pattern_ok=%d" % (received, end, ok), flush=True)
