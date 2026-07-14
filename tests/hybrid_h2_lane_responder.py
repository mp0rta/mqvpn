#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# hybrid_h2_lane_responder.py — target-side responder shared by Test 6
# (tcp=auto sticky per-flow lane e2e proof, v4, records peer address) and
# Test 8 (IPv6 TCP-lane aggregation/failover, v6 bind host, no peer address
# to record — see the peer_file paragraph below). Optional argv (bind host,
# peer_file) default to Test 6's original behavior, so its 3-arg invocation
# (port, peer_file, bytes_file) is unchanged.
#
# Why peer address, not the client's [STATUS] lane counters: c->pkts_lane_tcp
# is bumped by mqvpn_hybrid_classify() the moment a packet is classified as
# TCP-protocol/non-excluded (src/mqvpn_client.c's tun_decide_lane, the
# `case MQVPN_LANE_TCP: c->pkts_lane_tcp++;` line) — BEFORE the AUTO mode's
# per-flow sticky RAW/TCP-lane verdict (hybrid_tcp_syn_policy +
# mqvpn_tcp_lane_lookup) is even consulted. Under Tcp=auto this counter
# increments identically whether a flow's packets end up sticky-RAW'd or
# actually fed to lwIP — it cannot tell the two apart, so it is USELESS for
# this test (see the caller's comment for the verified read of that code
# path). This script instead observes the one signal that structurally can't
# lie: which TCP connection this target sees.
#   - A sticky-RAW flow rides the plain CONNECT-IP tunnel as an unmodified,
#     kernel-ip_forward'd packet (no NAT anywhere in this topology — same
#     mechanism proven by Test 7's byte-identical RAW transfers) — so its
#     peer address, as this listener observes it, is the CLIENT's own
#     tunnel-assigned address.
#   - A real TCP-lane flow is relayed by the SERVER's own brand-new
#     connect() out of src/hybrid/tcp_egress.c's svr_tcp_egress_start_connect
#     — a socket the SERVER process opens itself. It can never carry the
#     client's tunnel address as ITS peer address (that address belongs to
#     the client's TUN interface, not to anything the server process could
#     bind pass as a source for a plain outbound connect()).
# Recording addr[0] the instant accept() returns, before any data exchange,
# makes this an unambiguous, code-grounded proxy for which lane a flow
# actually used — independent of (and unlike) the stubbed/misleading packet
# counters.
#
# Also tracks a running received-byte total (bytes_file, rewritten after
# every recv()) so the caller can confirm a flow keeps making progress
# across a live path bring-up — the direct proof that its sticky decision
# was never silently re-evaluated mid-life: a reclassification bug would
# starve this counter (lwIP has no pcb for a non-SYN packet on a flow it
# never saw the SYN for), not raise a clean error.
#
# Test 8 has no sticky-RAW-vs-lane ambiguity to resolve (it uses a fixed
# Tcp=stream policy, not tcp=auto), so peer_file is optional there — pass ""
# to skip peer recording entirely. It also binds a real v6 literal instead of
# "0.0.0.0", so the optional host argv selects the listening socket's address
# family (a literal containing ':' is v6) instead of hardcoding AF_INET.
import socket
import sys

port = int(sys.argv[1])
peer_file = sys.argv[2]
bytes_file = sys.argv[3]
host = sys.argv[4] if len(sys.argv) > 4 else "0.0.0.0"

family = socket.AF_INET6 if ":" in host else socket.AF_INET
srv = socket.socket(family, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((host, port))
srv.listen(1)
conn, addr = srv.accept()

if peer_file:
    with open(peer_file, "w") as f:
        f.write(addr[0])

total = 0
with open(bytes_file, "w") as f:
    f.write("0")

conn.settimeout(120)
try:
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        total += len(chunk)
        with open(bytes_file, "w") as f:
            f.write(str(total))
except (socket.timeout, OSError):
    pass
