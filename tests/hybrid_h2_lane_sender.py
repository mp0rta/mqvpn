#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# hybrid_h2_lane_sender.py — Test 6 continuous TCP sender for the tcp=auto
# sticky per-flow lane e2e proof. Connects once and then keeps sending a
# small chunk on a fixed cadence FOREVER (until the peer closes or this
# process is killed) — deliberately NOT a one-shot connect-and-idle client.
# The test's core claim (a flow's lane decision, once made at SYN time, is
# never re-evaluated even after the trigger condition — active path count —
# changes under it) can only be observed by watching NEW bytes continue to
# land correctly on the SAME connection across a live path bring-up. A
# one-shot sender would make that observation vacuously true (nothing new is
# ever sent to check).
import socket
import sys
import time

host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port), timeout=10)
try:
    while True:
        s.sendall(b"x")
        time.sleep(0.2)
except (BrokenPipeError, ConnectionResetError, OSError):
    pass
