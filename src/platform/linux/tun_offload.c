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
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#define IPV4_MIN_HLEN 20
#define IPV6_HLEN     40
#define TCP_MIN_HLEN  20
#define UDP_HLEN      8

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
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

/* ---------------------------------------------------------------------------
 * TCP and UDP GRO
 * ------------------------------------------------------------------------- */

#define GRO_SLOTS   8
#define GRO_MAX_LEN 65535
/* Segments in one UDP GSO packet: UDP_MAX_SEGMENTS, which is 64 before Linux
 * 6.9 (128 after); the kernel rejects a larger virtio GSO packet. */
#define GRO_UDP_MAX_SEGS 64

typedef struct {
    int used;
    int closed;   /* nothing more may be merged (short segment or PSH) */
    int ack_only; /* holds one pure ACK, which only a later ACK may replace */
    int v6;
    uint8_t proto; /* IPPROTO_TCP or IPPROTO_UDP */
    uint16_t ip_hlen;
    uint16_t l4_hlen;  /* TCP header with options, or the UDP header */
    uint16_t gso_size; /* payload of the first segment */
    uint16_t next_id;  /* UDP over IPv4: IP ID the next datagram must carry */
    uint32_t nseg;
    uint32_t next_seq; /* host order */
    size_t len;
    uint8_t buf[GRO_MAX_LEN];
} gro_entry_t;

struct mqvpn_gro {
    mqvpn_gro_emit_fn emit;
    void *ctx;
    unsigned victim; /* round robin slot to evict when the table is full */
    int udp4, udp6;  /* UDP runs may be held (the TUN took USO) */
    int udp_refused; /* a UDP GSO packet was refused: merge no more UDP */
    uint64_t pushed, supers, merged, acks;
    uint64_t udp_supers, udp_merged; /* the UDP part of supers / merged */
    gro_entry_t e[GRO_SLOTS];
};

mqvpn_gro_t *
mqvpn_gro_new(mqvpn_gro_emit_fn emit, void *ctx)
{
    mqvpn_gro_t *g = calloc(1, sizeof(*g));
    if (g) {
        g->emit = emit;
        g->ctx = ctx;
    }
    return g;
}

void
mqvpn_gro_free(mqvpn_gro_t *g)
{
    free(g);
}

void
mqvpn_gro_set_udp(mqvpn_gro_t *g, int v4, int v6)
{
    mqvpn_gro_flush(g);
    g->udp4 = v4 != 0;
    g->udp6 = v6 != 0;
    g->udp_refused = 0;
}

void
mqvpn_gro_udp_stats(const mqvpn_gro_t *g, uint64_t *supers, uint64_t *merged)
{
    *supers = g->udp_supers;
    *merged = g->udp_merged;
}

void
mqvpn_gro_stats(const mqvpn_gro_t *g, uint64_t *pushed, uint64_t *supers,
                uint64_t *merged, uint64_t *acks)
{
    *pushed = g->pushed;
    *supers = g->supers;
    *merged = g->merged;
    *acks = g->acks;
}

int
mqvpn_gro_pending(const mqvpn_gro_t *g)
{
    for (int i = 0; i < GRO_SLOTS; i++)
        if (g->e[i].used) return 1;
    return 0;
}

/* What a packet looks like to the merger. */
typedef struct {
    int v6;
    uint8_t proto;
    size_t ip_hlen;
    size_t l4_hlen;
    size_t payload;
    uint32_t seq;
    uint8_t flags;
} gro_pkt_t;

/* A plain TCP segment or UDP datagram: no IP options or extension headers,
 * not a fragment, lengths consistent. TCP: either data with only ACK (and
 * PSH) set, or a pure ACK (no payload, only the ACK flag). UDP, only when
 * the TUN takes USO for the family: a payload, a checksum (a zero one would
 * become a computed one when the kernel splits the datagrams again) and a UDP
 * length that covers the whole packet (no surplus area). */
static int
gro_parse(const mqvpn_gro_t *gro, const uint8_t *p, size_t len, gro_pkt_t *g)
{
    if (len < IPV4_MIN_HLEN) return 0;
    if ((p[0] >> 4) == 4) {
        if (p[0] != 0x45) return 0;
        if ((get_be16(p + 6) & 0x3fff) != 0 || get_be16(p + 2) != len) return 0;
        g->v6 = 0;
        g->proto = p[9];
        g->ip_hlen = IPV4_MIN_HLEN;
    } else if ((p[0] >> 4) == 6) {
        if (len < IPV6_HLEN || get_be16(p + 4) != len - IPV6_HLEN) return 0;
        g->v6 = 1;
        g->proto = p[6];
        g->ip_hlen = IPV6_HLEN;
    } else {
        return 0;
    }
    if (g->proto == IPPROTO_UDP) {
        if (!(g->v6 ? gro->udp6 : gro->udp4) || gro->udp_refused) return 0;
        if (len < g->ip_hlen + UDP_HLEN) return 0;
        const uint8_t *u = p + g->ip_hlen;
        if (get_be16(u + 4) != len - g->ip_hlen) return 0;
        if (u[6] == 0 && u[7] == 0) return 0;
        g->l4_hlen = UDP_HLEN;
        g->payload = len - g->ip_hlen - UDP_HLEN;
        g->seq = 0;
        g->flags = 0;
        return g->payload > 0;
    }
    if (g->proto != IPPROTO_TCP || len < g->ip_hlen + TCP_MIN_HLEN) return 0;
    const uint8_t *t = p + g->ip_hlen;
    g->l4_hlen = (size_t)(t[12] >> 4) * 4;
    if (g->l4_hlen < TCP_MIN_HLEN || g->ip_hlen + g->l4_hlen > len) return 0;
    if (t[12] & 0x0f) return 0; /* reserved bits or AccECN's AE flag */
    g->flags = t[13];
    g->payload = len - g->ip_hlen - g->l4_hlen;
    /* Data: ACK, optionally PSH. Pure ACK: ACK alone. */
    uint8_t flags = g->payload ? (uint8_t)(g->flags & ~TCP_FLAG_PSH) : g->flags;
    if (flags != TCP_FLAG_ACK) return 0;
    uint32_t seq;
    memcpy(&seq, t + 4, 4);
    g->seq = ntohl(seq);
    return 1;
}

static void
gro_emit_plain(mqvpn_gro_t *g, const uint8_t *p, size_t len)
{
    struct virtio_net_hdr vh;
    memset(&vh, 0, sizeof(vh));
    g->emit(g->ctx, &vh, p, len);
}

/* The kernel refused a UDP GSO packet: stop merging UDP and write the
 * datagrams one by one, as the splitter cuts them back (IPv4 IDs were
 * consecutive, so they come out as they went in). udp4/udp6 stay set: runs
 * of other flows, and a datagram parsed before the refusal, may still be
 * held, and a later datagram of their flow must flush them first. */
static void
gro_udp_fallback(mqvpn_gro_t *g, gro_entry_t *e, const struct virtio_net_hdr *vh)
{
    static uint8_t seg[GRO_MAX_LEN];
    mqvpn_gso_iter_t it;
    int n;

    g->udp_refused = 1;
    if (mqvpn_gso_begin(&it, e->buf, e->len, vh) < 0) return;
    while ((n = mqvpn_gso_next(&it, seg, sizeof(seg))) > 0)
        gro_emit_plain(g, seg, (size_t)n);
}

static void
gro_flush_entry(mqvpn_gro_t *g, gro_entry_t *e)
{
    if (!e->used) return;
    e->used = 0;
    if (e->nseg == 1) {
        gro_emit_plain(g, e->buf, e->len);
        return;
    }

    uint8_t *ip = e->buf;
    uint8_t *l4 = ip + e->ip_hlen;
    size_t l4len = e->len - e->ip_hlen;
    int udp = e->proto == IPPROTO_UDP;

    if (e->v6) {
        put_be16(ip + 4, (uint16_t)(e->len - IPV6_HLEN));
    } else {
        put_be16(ip + 2, (uint16_t)e->len);
        ip[10] = ip[11] = 0;
        csum_store(ip + 10, csum_sum(ip, e->ip_hlen, 0));
    }
    /* Partial checksum: the field carries the pseudo-header sum, not
     * complemented, for the kernel (or a NIC) to finish. For UDP the kernel
     * takes the length out of that sum again for each datagram it cuts, so
     * the header carries the length of the whole run. */
    if (udp) put_be16(l4 + 4, (uint16_t)l4len);
    uint16_t ph = csum_fold(csum_pseudo(ip, e->v6, e->proto, l4len));
    memcpy(l4 + (udp ? 6 : 16), &ph, 2);

    struct virtio_net_hdr vh;
    memset(&vh, 0, sizeof(vh));
    vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    if (udp)
        vh.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4;
    else
        vh.gso_type = e->v6 ? VIRTIO_NET_HDR_GSO_TCPV6 : VIRTIO_NET_HDR_GSO_TCPV4;
    vh.hdr_len = (uint16_t)(e->ip_hlen + e->l4_hlen);
    vh.gso_size = e->gso_size;
    vh.csum_start = e->ip_hlen;
    vh.csum_offset = udp ? 6 : 16;
    g->supers++;
    g->merged += e->nseg;
    if (udp) {
        g->udp_supers++;
        g->udp_merged += e->nseg;
    }
    if (g->emit(g->ctx, &vh, e->buf, e->len) == -EINVAL && udp)
        gro_udp_fallback(g, e, &vh);
}

void
mqvpn_gro_flush(mqvpn_gro_t *g)
{
    for (int i = 0; i < GRO_SLOTS; i++)
        gro_flush_entry(g, &g->e[i]);
}

/* Same flow: protocol, addresses and ports. */
static int
gro_same_flow(const gro_entry_t *e, const uint8_t *p, const gro_pkt_t *k)
{
    if (e->v6 != k->v6 || e->proto != k->proto) return 0;
    size_t alen = k->v6 ? 32 : 8;
    size_t aoff = k->v6 ? 8 : 12;
    return memcmp(e->buf + aoff, p + aoff, alen) == 0 &&
           memcmp(e->buf + e->ip_hlen, p + k->ip_hlen, 4) == 0;
}

/* Can p be appended to e? Mirrors the kernel's GRO flush conditions: same
 * IP header fields, same TCP header except sequence/checksum (ACK number,
 * flags, window and options must match), data in sequence and not larger than
 * the first segment. */
static int
gro_can_append(const gro_entry_t *e, const uint8_t *p, const gro_pkt_t *k)
{
    if (e->closed || e->ack_only || k->l4_hlen != e->l4_hlen) return 0;
    if (k->payload > e->gso_size || k->seq != e->next_seq) return 0;
    if (e->len + k->payload > GRO_MAX_LEN) return 0;
    if (k->v6) {
        if (memcmp(e->buf, p, 4) != 0 || e->buf[7] != p[7]) return 0;
    } else {
        /* TOS, flags/fragment offset (DF), TTL */
        if (e->buf[1] != p[1] || e->buf[6] != p[6] || e->buf[8] != p[8]) return 0;
    }
    const uint8_t *a = e->buf + e->ip_hlen, *b = p + k->ip_hlen;
    if (memcmp(a + 8, b + 8, 4) != 0) return 0; /* ACK number */
    if ((a[13] & (uint8_t)~TCP_FLAG_PSH) != (b[13] & (uint8_t)~TCP_FLAG_PSH)) return 0;
    if (memcmp(a + 14, b + 14, 2) != 0) return 0; /* window */
    if (k->l4_hlen > TCP_MIN_HLEN && memcmp(a + 20, b + 20, k->l4_hlen - 20) != 0)
        return 0; /* options */
    return 1;
}

/* Can the pure ACK p take the place of the one e holds? Only a later
 * cumulative ACK of the flow can: same sequence number, TOS, DF and TTL
 * (traffic class, flow label and hop limit), same TCP options (SACK blocks
 * included), and an ACK number strictly ahead, so it acknowledges all the
 * held one did and carries the newer window. A repeated ACK number is a
 * duplicate ACK or a window update, events the sender counts, so such an ACK
 * never replaces another. */
static int
gro_ack_supersedes(const gro_entry_t *e, const uint8_t *p, const gro_pkt_t *k)
{
    if (k->l4_hlen != e->l4_hlen) return 0;
    if (k->v6) {
        if (memcmp(e->buf, p, 4) != 0 || e->buf[7] != p[7]) return 0;
    } else {
        if (e->buf[1] != p[1] || e->buf[6] != p[6] || e->buf[8] != p[8]) return 0;
    }
    const uint8_t *a = e->buf + e->ip_hlen, *b = p + k->ip_hlen;
    if (memcmp(a + 4, b + 4, 4) != 0) return 0; /* sequence number */
    if (k->l4_hlen > TCP_MIN_HLEN && memcmp(a + 20, b + 20, k->l4_hlen - 20) != 0)
        return 0; /* options */
    uint32_t held, ack;
    memcpy(&held, a + 8, 4);
    memcpy(&ack, b + 8, 4);
    return (int32_t)(ntohl(ack) - ntohl(held)) > 0;
}

/* Can the UDP datagram p join the run e holds? Same IP header fields (TOS,
 * DF and TTL, or traffic class, flow label and hop limit), an IPv4 ID one
 * past the last one (the kernel numbers the datagrams it cuts that way), and
 * a payload of the run's size, or a smaller one that ends the run: the GSO
 * size is that of every datagram but the last. */
static int
gro_udp_can_append(const gro_entry_t *e, const uint8_t *p, const gro_pkt_t *k)
{
    if (e->closed || k->payload > e->gso_size) return 0;
    if (e->nseg >= GRO_UDP_MAX_SEGS || e->len + k->payload > GRO_MAX_LEN) return 0;
    if (k->v6) return memcmp(e->buf, p, 4) == 0 && e->buf[7] == p[7];
    return e->buf[1] == p[1] && e->buf[6] == p[6] && e->buf[8] == p[8] &&
           get_be16(p + 4) == e->next_id;
}

/* Can a packet we do not merge belong to a flow with something held? Then
 * whatever its addresses hold goes out first. A TCP packet can, and a UDP one
 * once UDP runs may be held (even after a refused write ended merging). Its
 * ports may sit behind IPv4 options or IPv6 extension headers, or in another
 * fragment, so the caller matches on the addresses only; an IPv6 packet that
 * is not UDP may be TCP or UDP behind such a header. */
static int
gro_may_follow_held(const mqvpn_gro_t *g, const uint8_t *p, size_t len)
{
    int ver = p[0] >> 4;
    if (ver == 4) {
        if (len < IPV4_MIN_HLEN) return 0;
        return p[9] == IPPROTO_TCP || (p[9] == IPPROTO_UDP && g->udp4);
    }
    if (ver == 6) {
        if (len < IPV6_HLEN) return 0;
        return p[6] != IPPROTO_UDP || g->udp6;
    }
    return 0;
}

void
mqvpn_gro_push(mqvpn_gro_t *g, const uint8_t *p, size_t len)
{
    gro_pkt_t k;
    g->pushed++;

    if (len == 0) {
        gro_emit_plain(g, p, len);
        return;
    }

    /* Longer than an entry's buffer: never merged, but still ordered. */
    if (len > GRO_MAX_LEN || !gro_parse(g, p, len, &k)) {
        /* Not mergeable. Packets of other flows may pass; but a TCP packet we
         * cannot merge (SYN, FIN, RST, ...) must not overtake data or an ACK
         * of its own flow still held back, nor a UDP datagram we cannot merge
         * (a fragment, no checksum, any after a refused write, ...) the
         * datagrams held for its flow. */
        if (gro_may_follow_held(g, p, len)) {
            int v6 = (p[0] >> 4) == 6;
            size_t aoff = v6 ? 8 : 12, alen = v6 ? 32 : 8;
            for (int i = 0; i < GRO_SLOTS; i++) {
                gro_entry_t *e = &g->e[i];
                if (e->used && e->v6 == v6 && memcmp(e->buf + aoff, p + aoff, alen) == 0)
                    gro_flush_entry(g, e);
            }
        }
        gro_emit_plain(g, p, len);
        return;
    }

    gro_entry_t *free_slot = NULL;
    for (int i = 0; i < GRO_SLOTS; i++) {
        gro_entry_t *e = &g->e[i];
        if (!e->used) {
            if (!free_slot) free_slot = e;
            continue;
        }
        if (!gro_same_flow(e, p, &k)) continue;
        if (k.proto == IPPROTO_UDP) {
            if (gro_udp_can_append(e, p, &k)) {
                memcpy(e->buf + e->len, p + k.ip_hlen + UDP_HLEN, k.payload);
                e->len += k.payload;
                e->nseg++;
                e->next_id++;
                if (k.payload < e->gso_size) e->closed = 1;
                return;
            }
        } else if (k.payload == 0) {
            if (e->ack_only && gro_ack_supersedes(e, p, &k)) {
                memcpy(e->buf, p, len);
                e->len = len;
                g->acks++;
                return;
            }
        } else if (gro_can_append(e, p, &k)) {
            memcpy(e->buf + e->len, p + k.ip_hlen + k.l4_hlen, k.payload);
            e->len += k.payload;
            e->next_seq += (uint32_t)k.payload;
            e->nseg++;
            if (k.flags & TCP_FLAG_PSH) e->buf[e->ip_hlen + 13] |= TCP_FLAG_PSH;
            if (k.payload < e->gso_size || (k.flags & TCP_FLAG_PSH)) e->closed = 1;
            return;
        }
        /* Same flow, cannot join: send what we hold first, then start over. */
        gro_flush_entry(g, e);
        free_slot = e;
        break;
    }

    if (!free_slot) {
        free_slot = &g->e[g->victim++ % GRO_SLOTS];
        gro_flush_entry(g, free_slot);
    }
    gro_entry_t *e = free_slot;
    e->used = 1;
    e->ack_only = k.proto == IPPROTO_TCP && k.payload == 0;
    e->v6 = k.v6;
    e->proto = k.proto;
    e->next_id = k.v6 ? 0 : (uint16_t)(get_be16(p + 4) + 1);
    e->ip_hlen = (uint16_t)k.ip_hlen;
    e->l4_hlen = (uint16_t)k.l4_hlen;
    e->gso_size = (uint16_t)k.payload;
    e->nseg = 1;
    e->next_seq = k.seq + (uint32_t)k.payload;
    e->len = len;
    e->closed = (k.flags & TCP_FLAG_PSH) != 0;
    memcpy(e->buf, p, len);
}
