#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
"""Transport smoke for CI runners without a netns e2e harness (macOS, Windows).

Starts the client against a local UDP listener that is not a server and
checks what the platform's transport wiring alone guarantees:

  1. the client's first datagram reaches the listener and is a padded QUIC
     Initial (>= 1200 bytes, RFC 9000 section 14.1) — socket creation, path
     registration and the bundled transport's send all worked;
  2. the listener answers with a Version Negotiation packet (RFC 9000
     section 17.2.1: the client's connection IDs echoed, only a reserved
     version offered, section 6.3), and the client acts on it: it must
     abandon the attempt (section 6.2), which the core logs as "connection
     closed (errno=83)". Only a datagram delivered by the platform's read
     event, the transport's receive helper and the core's receive entry point
     can cause that;
  3. with --graceful, SIGTERM runs the whole teardown: exit status 0 and the
     core's "udp-tx: sends=N" line with N >= 1 (printed by client_destroy
     from the transport's own counters).

No handshake ever completes, so no TUN, route, DNS or kill-switch state is
touched. Usage:
  ci_transport_smoke.py [--path IFACE] [--sudo] [--graceful] <mqvpn-binary>
"""
import argparse
import re
import socket
import subprocess
import sys
import time

# The core's close line carrying xquic's TRA_VERSION_NEGOTIATION_ERROR (0x53),
# which xquic sets only while parsing a Version Negotiation packet. A client
# that never receives the reply closes later with another errno (the
# handshake-stall abort), so this line proves the receive path.
VN_REACTION = "connection closed (errno=83)"


def fail(msg):
    print(f"transport smoke: FAIL: {msg}")
    sys.exit(1)


def read_log(path):
    with open(path, "rb") as f:
        return f.read().decode(errors="replace")


def long_header_cids(data):
    """(dcid, scid) of a QUIC long-header packet (RFC 9000 section 17.2). Each
    length is one byte, so both IDs lie within a datagram of >= 1200 bytes."""
    dcid_end = 6 + data[5]
    return data[6:dcid_end], data[dcid_end + 1:dcid_end + 1 + data[dcid_end]]


def version_negotiation(dcid, scid):
    """Version Negotiation reply to a packet that carried dcid/scid: the
    connection IDs echoed swapped, and only a reserved version (0x?a?a?a?a)
    offered, which no client supports (RFC 9000 sections 17.2.1 and 6.3)."""
    return (bytes([0xC0]) + bytes(4) + bytes([len(scid)]) + scid + bytes([len(dcid)]) + dcid
            + bytes.fromhex("1a2a3a4a"))


def stop(proc, args):
    if proc.poll() is None:
        if args.graceful:
            # Under sudo the client runs as root; signal sudo through sudo, and
            # sudo relays SIGTERM to the client.
            kill = ["kill", "-TERM", str(proc.pid)]
            subprocess.run((["sudo", "-n"] + kill) if args.sudo else kill, check=False)
        else:
            proc.kill()
    try:
        return proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        fail("client did not exit within 30 s of the stop request")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--path", help="interface to pin the single path to (--path)")
    ap.add_argument("--sudo", action="store_true", help="run the client under sudo -n")
    ap.add_argument("--graceful", action="store_true",
                    help="stop with SIGTERM and check the teardown line and exit status")
    ap.add_argument("--log", default="transport-smoke.log")
    args = ap.parse_args()

    lst = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    lst.bind(("127.0.0.1", 0))
    lst.settimeout(20)
    port = lst.getsockname()[1]

    cmd = [args.binary, "--mode", "client", "--server", f"127.0.0.1:{port}",
           "--auth-key", "ci-transport-smoke", "--insecure", "--no-reconnect"]
    if args.path:
        cmd += ["--path", args.path]
    if args.sudo:
        cmd = ["sudo", "-n"] + cmd
    print("running:", " ".join(cmd))

    with open(args.log, "wb") as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        try:
            try:
                data, peer = lst.recvfrom(65535)
            except socket.timeout:
                fail("no datagram from the client within 20 s")
            print(f"listener: {len(data)} bytes from {peer[0]}:{peer[1]}")
            if len(data) < 1200:
                fail(f"first datagram is {len(data)} bytes, not a padded QUIC Initial")
            if not data[0] & 0x80:
                fail("first datagram is not a QUIC long-header packet")
            lst.sendto(version_negotiation(*long_header_cids(data)), peer)
            deadline = time.monotonic() + 10
            while VN_REACTION not in read_log(args.log):
                if proc.poll() is not None:
                    fail(f"client exited (status {proc.returncode}) after the Version "
                         "Negotiation reply")
                if time.monotonic() > deadline:
                    fail("client did not act on the Version Negotiation reply within 10 s "
                         "(no receive path?)")
                time.sleep(0.2)
            print("client acted on the Version Negotiation reply")
        finally:
            rc = stop(proc, args)
            log.flush()
            out = read_log(args.log)
            print("---- client log (tail) ----")
            print(out[-6000:])

    if args.graceful:
        if rc != 0:
            fail(f"client exit status {rc} after SIGTERM, want 0")
        m = re.search(r"udp-tx: sends=(\d+)", out)
        if not m or int(m.group(1)) < 1:
            fail("no 'udp-tx: sends=N' (N >= 1) teardown line in the client log")
    print("transport smoke: PASS")


if __name__ == "__main__":
    main()
