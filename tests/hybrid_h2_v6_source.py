#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# hybrid_h2_v6_source.py — Test 8 continuous IPv6 TCP-lane sender for
# test_e2e_hybrid_h2.sh. Connects once (create_connection resolves a raw v6
# literal host via getaddrinfo, no bracket form needed) and then keeps
# sending fixed-size chunks on a fixed cadence FOREVER (until the peer
# closes or this process is killed) — deliberately not a one-shot
# connect-and-idle client, so the failover check has a live flow whose byte
# counter keeps climbing across a path being dropped mid-test.
import socket
import sys
import time

host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port), timeout=10)
chunk = b"x" * 4096
try:
    while True:
        s.sendall(chunk)
        time.sleep(0.05)
except (BrokenPipeError, ConnectionResetError, OSError):
    pass
