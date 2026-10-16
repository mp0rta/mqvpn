// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
//
// The segmentation and checksum logic follows wireguard-go's
// tun/offload_linux.go (gsoSplit, gsoNoneChecksum), which is MIT licensed:
//
//   Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
//
//   Permission is hereby granted, free of charge, to any person obtaining a
//   copy of this software and associated documentation files (the
//   "Software"), to deal in the Software without restriction, including
//   without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to
//   permit persons to whom the Software is furnished to do so, subject to
//   the following conditions:
//
//   The above copyright notice and this permission notice shall be included
//   in all copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
//   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
//   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Differences from the Go original: segments are produced one at a time by
// an iterator instead of all at once, the checksum is computed in the host
// byte order (see csum_sum), and CWR is cleared on every segment but the
// first, as the kernel's tcp_gso_segment() does.

#include "tun_offload.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#define IPV4_MIN_HLEN 20
#define IPV6_HLEN     40
#define TCP_MIN_HLEN  20
#define UDP_HLEN      8

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_CWR 0x80

/*
 * Ones' complement sum, accumulated over native-endian loads. The sum of
 * byte-swapped 16-bit words is the byte swap of the sum (RFC 1071 section
 * 2(B)), so no byte order conversion is needed as long as every input comes
 * from memory the same way and the result is stored back with memcpy().
 * Words are summed 32 bits at a time into a 64-bit accumulator; since
 * 2^16 == 1 (mod 65535) the high half adds in like a low one after folding.
 */
static uint64_t
csum_sum(const uint8_t *p, size_t n, uint64_t acc)
{
    while (n >= 8) {
        uint64_t w;
        memcpy(&w, p, 8);
        acc += (w & 0xffffffffu) + (w >> 32);
        p += 8;
        n -= 8;
    }
    if (n >= 4) {
        uint32_t w;
        memcpy(&w, p, 4);
        acc += w;
        p += 4;
        n -= 4;
    }
    if (n >= 2) {
        uint16_t w;
        memcpy(&w, p, 2);
        acc += w;
        p += 2;
        n -= 2;
    }
    if (n) {
        uint16_t w = 0; /* odd trailing byte, zero padded at the high address */
        memcpy(&w, p, 1);
        acc += w;
    }
    return acc;
}

static uint16_t
csum_fold(uint64_t acc)
{
    while (acc >> 16)
        acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)acc;
}

/* Store the complement of acc at p. A computed 0 is sent as 0xffff, which
 * ones' complement treats as the same value and which UDP requires (0 there
 * means "no checksum"); the kernel's skb_checksum_help() does the same. */
static void
csum_store(uint8_t *p, uint64_t acc)
{
    uint16_t c = (uint16_t)~csum_fold(acc);
    if (c == 0) c = 0xffff;
    memcpy(p, &c, 2);
}

/* Pseudo-header sum over the addresses of the IP header at ip. */
static uint64_t
csum_pseudo(const uint8_t *ip, int v6, uint8_t proto, size_t l4len)
{
    const uint8_t tail[4] = {0, proto, (uint8_t)(l4len >> 8), (uint8_t)l4len};
    uint64_t acc = v6 ? csum_sum(ip + 8, 32, 0) : csum_sum(ip + 12, 8, 0);
    return csum_sum(tail, 4, acc);
}

static uint16_t
get_be16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return ntohs(v);
}

static void
put_be16(uint8_t *p, uint16_t v)
{
    v = htons(v);
    memcpy(p, &v, 2);
}

int
mqvpn_vnet_finish_csum(uint8_t *pkt, size_t len, const struct virtio_net_hdr *vh)
{
    size_t start = vh->csum_start;
    size_t at = start + (size_t)vh->csum_offset;

    if (start >= len || at + 2 > len) return -1;

    /* The field holds the pseudo-header sum the kernel left for us; fold it
     * into the sum over the transport header and payload. */
    uint64_t acc = csum_sum(pkt + at, 2, 0);
    pkt[at] = pkt[at + 1] = 0;
    csum_store(pkt + at, csum_sum(pkt + start, len - start, acc));
    return 0;
}

int
mqvpn_gso_begin(mqvpn_gso_iter_t *it, const uint8_t *pkt, size_t len,
                const struct virtio_net_hdr *vh)
{
    uint8_t type = vh->gso_type & (uint8_t)~VIRTIO_NET_HDR_GSO_ECN;
    int v6;
    uint8_t proto;

    if (vh->gso_size == 0 || len < IPV4_MIN_HLEN) return -1;

    switch (type) {
    case VIRTIO_NET_HDR_GSO_TCPV4:
        v6 = 0;
        proto = IPPROTO_TCP;
        break;
    case VIRTIO_NET_HDR_GSO_TCPV6:
        v6 = 1;
        proto = IPPROTO_TCP;
        break;
    case VIRTIO_NET_HDR_GSO_UDP_L4:
        /* One type for both families: the packet says which. */
        v6 = (pkt[0] >> 4) == 6;
        proto = IPPROTO_UDP;
        break;
    default: return -1;
    }
    if ((pkt[0] >> 4) != (v6 ? 6 : 4)) return -1;

    size_t ip_hlen;
    if (v6) {
        /* Extension headers sit between the fixed header and the transport
         * header; the kernel says where the transport header starts. */
        if (!(vh->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)) {
            ip_hlen = IPV6_HLEN;
        } else {
            ip_hlen = vh->csum_start;
        }
        if (ip_hlen < IPV6_HLEN || len < IPV6_HLEN || len - IPV6_HLEN > 0xffff) return -1;
    } else {
        ip_hlen = (size_t)(pkt[0] & 0x0f) * 4;
        if (ip_hlen < IPV4_MIN_HLEN || len > 0xffff) return -1;
        if ((vh->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) && vh->csum_start != ip_hlen)
            return -1;
    }

    size_t l4hlen;
    if (proto == IPPROTO_TCP) {
        if (len < ip_hlen + TCP_MIN_HLEN) return -1;
        l4hlen = (size_t)(pkt[ip_hlen + 12] >> 4) * 4;
        if (l4hlen < TCP_MIN_HLEN) return -1;
        if ((vh->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) && vh->csum_offset != 16) return -1;
    } else {
        l4hlen = UDP_HLEN;
        if ((vh->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) && vh->csum_offset != 6) return -1;
    }
    if (len < ip_hlen + l4hlen) return -1;

    memset(it, 0, sizeof(*it));
    it->pkt = pkt;
    it->len = len;
    it->hdr_len = ip_hlen + l4hlen;
    it->ip_hlen = (uint16_t)ip_hlen;
    it->gso_size = vh->gso_size;
    it->proto = proto;
    it->v6 = (uint8_t)v6;
    if (!v6) it->ip_id0 = get_be16(pkt + 4);
    if (proto == IPPROTO_TCP) {
        uint32_t seq;
        memcpy(&seq, pkt + ip_hlen + 4, 4);
        it->seq0 = ntohl(seq);
    }
    return 0;
}

int
mqvpn_gso_next(mqvpn_gso_iter_t *it, uint8_t *out, size_t out_cap)
{
    if (it->done) return 0;

    size_t payload_total = it->len - it->hdr_len;
    size_t seg = payload_total - it->off;
    if (seg > it->gso_size) seg = it->gso_size;
    size_t total = it->hdr_len + seg;
    int last = (it->off + seg >= payload_total);

    if (total > out_cap) return -1;

    memcpy(out, it->pkt, it->hdr_len);
    memcpy(out + it->hdr_len, it->pkt + it->hdr_len + it->off, seg);

    size_t ip_hlen = it->ip_hlen;
    uint8_t *l4 = out + ip_hlen;
    size_t l4len = total - ip_hlen;

    if (it->v6) {
        put_be16(out + 4, (uint16_t)(total - IPV6_HLEN));
    } else {
        put_be16(out + 2, (uint16_t)total);
        put_be16(out + 4, (uint16_t)(it->ip_id0 + it->idx));
        out[10] = out[11] = 0;
        csum_store(out + 10, csum_sum(out, ip_hlen, 0));
    }

    if (it->proto == IPPROTO_TCP) {
        uint32_t seq = htonl(it->seq0 + (uint32_t)it->off);
        memcpy(l4 + 4, &seq, 4);
        if (!last) l4[13] &= (uint8_t) ~(TCP_FLAG_FIN | TCP_FLAG_PSH);
        if (it->idx) l4[13] &= (uint8_t)~TCP_FLAG_CWR;
        l4[16] = l4[17] = 0;
        csum_store(l4 + 16,
                   csum_sum(l4, l4len, csum_pseudo(out, it->v6, IPPROTO_TCP, l4len)));
    } else {
        put_be16(l4 + 4, (uint16_t)l4len);
        l4[6] = l4[7] = 0;
        csum_store(l4 + 6,
                   csum_sum(l4, l4len, csum_pseudo(out, it->v6, IPPROTO_UDP, l4len)));
    }

    it->off += seg;
    it->idx++;
    if (last) it->done = 1;
    return (int)total;
}
