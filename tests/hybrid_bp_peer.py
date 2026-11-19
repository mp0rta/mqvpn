#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# hybrid_bp_peer.py — one end of a TCP connection for
# test_e2e_hybrid_backpressure.sh.
#
#   hybrid_bp_peer.py (listen|connect) IP PORT tx TOTAL PROGRESS_FILE
#       Send TOTAL bytes of a fixed pattern as fast as the socket takes them.
#       PROGRESS_FILE holds "<bytes handed to the kernel>" while sending and
#       "<bytes> <sha256>" once everything is sent.
#   hybrid_bp_peer.py (listen|connect) IP PORT rx GO_FILE RESULT_FILE
#       Read nothing until GO_FILE exists, then read to EOF and write
#       "<bytes> <sha256>" to RESULT_FILE.
import hashlib
import os
import random
import socket
import sys
import threading
import time

how, ip, port, role = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]


def put(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


if how == "listen":
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ip, port))
    srv.listen(1)
    conn, _ = srv.accept()
else:
    conn = socket.create_connection((ip, port), timeout=20)
    conn.settimeout(None)

sha = hashlib.sha256()
if role == "tx":
    total, progress = int(sys.argv[5]), sys.argv[6]
    block = random.Random(1).randbytes(1 << 16)
    sent, done = 0, False

    def report():  # a blocked send must not freeze the reported count
        while not done:
            put(progress, str(sent))
            time.sleep(0.1)

    reporter = threading.Thread(target=report)
    reporter.start()
    while sent < total:
        chunk = block[: min(len(block), total - sent)]
        conn.sendall(chunk)
        sha.update(chunk)
        sent += len(chunk)
    done = True
    reporter.join()
    # Before the EOF: the receiver's result must not appear before this one.
    put(progress, "%d %s" % (sent, sha.hexdigest()))
    conn.shutdown(socket.SHUT_WR)
    while conn.recv(65536):  # hold the socket until the peer closes
        pass
else:
    go, result = sys.argv[5], sys.argv[6]
    while not os.path.exists(go):
        time.sleep(0.1)
    got = 0
    while True:
        data = conn.recv(1 << 16)
        if not data:
            break
        sha.update(data)
        got += len(data)
    put(result, "%d %s" % (got, sha.hexdigest()))
conn.close()
