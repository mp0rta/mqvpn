#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# Regenerate the fuzz_tcp_lane seed corpus (fuzz/corpus/tcp_lane/). Each
# output file is one raw inner IP packet in libFuzzer plain-file format —
# exactly the bytes LLVMFuzzerTestOneInput receives. Pure stdlib (no scapy /
# pcap dependency); rerun after a wire-format change to the classifier's
# accepted packet shapes (mqvpn_parse_l3l4).
#
#   python3 fuzz/corpus/gen_tcp_lane_corpus.py [output-dir]
#     (default output-dir: the tcp_lane/ dir next to this script)

import os
import struct
import sys


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4_hdr(proto, total_len, src, dst, ident=0x1234, flags_frag=0, ttl=64,
            ihl=5, options=b""):
    ver_ihl = (4 << 4) | ihl
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total_len, ident,
                      flags_frag, ttl, proto, 0, src, dst) + options
    c = _csum(hdr)
    return hdr[:10] + struct.pack("!H", c) + hdr[12:]


def tcp_hdr(sport, dport, seq, ack, flags, src, dst, win=8192, data=b""):
    doff_res_flags = (5 << 12) | flags
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, doff_res_flags,
                      win, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(hdr) + len(data))
    c = _csum(pseudo + hdr + data)
    return hdr[:16] + struct.pack("!H", c) + hdr[18:] + data


def udp_hdr(sport, dport, data):
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "tcp_lane")
    os.makedirs(outdir, exist_ok=True)

    src = bytes([10, 0, 0, 2])
    dst = bytes([93, 184, 216, 34])  # outside any tunnel subnet

    def write(name, pkt):
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(pkt)

    # 1. SYN
    tcp = tcp_hdr(51000, 80, 1000, 0, 0x02, src, dst)
    write("01_syn.bin", ip4_hdr(6, 20 + len(tcp), src, dst) + tcp)

    # 2. Data segment (PSH+ACK) with an HTTP request payload
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tcp = tcp_hdr(51000, 80, 1001, 5000, 0x18, src, dst, data=payload)
    write("02_data.bin", ip4_hdr(6, 20 + len(tcp), src, dst) + tcp)

    # 3. FIN+ACK
    tcp = tcp_hdr(51000, 80, 1050, 5100, 0x11, src, dst)
    write("03_fin.bin", ip4_hdr(6, 20 + len(tcp), src, dst) + tcp)

    # 4. IPv4 with a 4-byte options word (IHL=6): four NOPs
    tcp = tcp_hdr(51001, 443, 2000, 0, 0x02, src, dst)
    write("04_ipopts_syn.bin",
          ip4_hdr(6, 24 + len(tcp), src, dst, ihl=6, options=b"\x01\x01\x01\x01") + tcp)

    # 5. Truncated: first 10 bytes only of a 20-byte IPv4 header
    write("05_truncated.bin", ip4_hdr(6, 40, src, dst)[:10])

    # 6. UDP (DNS-shaped) — exercises the classifier's DGRAM verdict
    udp = udp_hdr(5000, 53, b"\x00\x01\x00\x00")
    write("06_udp.bin", ip4_hdr(17, 20 + len(udp), src, dst) + udp)

    print("wrote", sorted(os.listdir(outdir)))


if __name__ == "__main__":
    main()
