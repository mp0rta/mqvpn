#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# hybrid_h2_lane_sender.py — continuous TCP sender shared by Test 6 (tcp=auto
# sticky per-flow lane e2e proof, v4, default cadence) and Test 8 (IPv6
# TCP-lane aggregation/failover, larger chunk + faster cadence). Connects
# once and then keeps sending a fixed-size chunk on a fixed cadence FOREVER
# (until the peer closes or this process is killed) — deliberately NOT a
# one-shot connect-and-idle client. socket.create_connection resolves
# host via getaddrinfo, so it is family-agnostic (v4 or a raw v6 literal)
# with no code path difference — the only real difference between the two
# tests is chunk size/cadence, exposed as optional argv below (Test 6's
# 2-arg invocation gets the original b"x"/0.2s behavior unchanged via the
# defaults).
#
# Test 6's core claim (a flow's lane decision, once made at SYN time, is
# never re-evaluated even after the trigger condition — active path count —
# changes under it) can only be observed by watching NEW bytes continue to
# land correctly on the SAME connection across a live path bring-up. A
# one-shot sender would make that observation vacuously true (nothing new is
# ever sent to check). Test 8 reuses the same continuous-sender shape for its
# own failover continuity check.
import socket
import sys
import time

host, port = sys.argv[1], int(sys.argv[2])
chunk_size = int(sys.argv[3]) if len(sys.argv) > 3 else 1
cadence = float(sys.argv[4]) if len(sys.argv) > 4 else 0.2
s = socket.create_connection((host, port), timeout=10)
chunk = b"x" * chunk_size
try:
    while True:
        s.sendall(chunk)
        time.sleep(cadence)
except (BrokenPipeError, ConnectionResetError, OSError):
    pass
