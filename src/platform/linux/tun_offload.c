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
#include <stdlib.h>
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

/* ---------------------------------------------------------------------------
 * TCP GRO
 * ------------------------------------------------------------------------- */

#define GRO_SLOTS   8
#define GRO_MAX_LEN 65535

typedef struct {
    int used;
    int closed; /* nothing more may be merged (short segment or PSH) */
    int v6;
    uint16_t ip_hlen;
    uint16_t tcp_hlen;
    uint16_t gso_size; /* payload of the first segment */
    uint32_t nseg;
    uint32_t next_seq; /* host order */
    size_t len;
    uint8_t buf[GRO_MAX_LEN];
} gro_entry_t;

struct mqvpn_gro {
    mqvpn_gro_emit_fn emit;
    void *ctx;
    unsigned victim; /* round robin slot to evict when the table is full */
    uint64_t pushed, supers, merged;
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
mqvpn_gro_stats(const mqvpn_gro_t *g, uint64_t *pushed, uint64_t *supers,
                uint64_t *merged)
{
    *pushed = g->pushed;
    *supers = g->supers;
    *merged = g->merged;
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
    size_t ip_hlen;
    size_t tcp_hlen;
    size_t payload;
    uint32_t seq;
    uint8_t flags;
} gro_pkt_t;

/* A plain TCP data segment: no IP options or extension headers, not a
 * fragment, lengths consistent, only ACK (and PSH) set, payload present. */
static int
gro_parse(const uint8_t *p, size_t len, gro_pkt_t *g)
{
    if (len < IPV4_MIN_HLEN) return 0;
    if ((p[0] >> 4) == 4) {
        if (p[0] != 0x45 || len < IPV4_MIN_HLEN + TCP_MIN_HLEN || p[9] != IPPROTO_TCP)
            return 0;
        if ((get_be16(p + 6) & 0x3fff) != 0 || get_be16(p + 2) != len) return 0;
        g->v6 = 0;
        g->ip_hlen = IPV4_MIN_HLEN;
    } else if ((p[0] >> 4) == 6) {
        if (len < IPV6_HLEN + TCP_MIN_HLEN || p[6] != IPPROTO_TCP) return 0;
        if (get_be16(p + 4) != len - IPV6_HLEN) return 0;
        g->v6 = 1;
        g->ip_hlen = IPV6_HLEN;
    } else {
        return 0;
    }
    const uint8_t *t = p + g->ip_hlen;
    g->tcp_hlen = (size_t)(t[12] >> 4) * 4;
    if (g->tcp_hlen < TCP_MIN_HLEN || g->ip_hlen + g->tcp_hlen >= len) return 0;
    if (t[12] & 0x0f) return 0; /* reserved bits or AccECN's AE flag */
    g->flags = t[13];
    if ((g->flags & ~TCP_FLAG_PSH) != 0x10) return 0; /* ACK, optionally PSH */
    g->payload = len - g->ip_hlen - g->tcp_hlen;
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
    uint8_t *tcp = ip + e->ip_hlen;
    size_t l4len = e->len - e->ip_hlen;

    if (e->v6) {
        put_be16(ip + 4, (uint16_t)(e->len - IPV6_HLEN));
    } else {
        put_be16(ip + 2, (uint16_t)e->len);
        ip[10] = ip[11] = 0;
        csum_store(ip + 10, csum_sum(ip, e->ip_hlen, 0));
    }
    /* Partial checksum: the field carries the pseudo-header sum, not
     * complemented, for the kernel (or a NIC) to finish. */
    uint16_t ph = csum_fold(csum_pseudo(ip, e->v6, IPPROTO_TCP, l4len));
    memcpy(tcp + 16, &ph, 2);

    struct virtio_net_hdr vh;
    memset(&vh, 0, sizeof(vh));
    vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    vh.gso_type = e->v6 ? VIRTIO_NET_HDR_GSO_TCPV6 : VIRTIO_NET_HDR_GSO_TCPV4;
    vh.hdr_len = (uint16_t)(e->ip_hlen + e->tcp_hlen);
    vh.gso_size = e->gso_size;
    vh.csum_start = e->ip_hlen;
    vh.csum_offset = 16;
    g->supers++;
    g->merged += e->nseg;
    g->emit(g->ctx, &vh, e->buf, e->len);
}

void
mqvpn_gro_flush(mqvpn_gro_t *g)
{
    for (int i = 0; i < GRO_SLOTS; i++)
        gro_flush_entry(g, &g->e[i]);
}

/* Same flow: addresses and ports. */
static int
gro_same_flow(const gro_entry_t *e, const uint8_t *p, const gro_pkt_t *k)
{
    if (e->v6 != k->v6) return 0;
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
    if (e->closed || k->tcp_hlen != e->tcp_hlen) return 0;
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
    if (k->tcp_hlen > TCP_MIN_HLEN && memcmp(a + 20, b + 20, k->tcp_hlen - 20) != 0)
        return 0; /* options */
    return 1;
}

void
mqvpn_gro_push(mqvpn_gro_t *g, const uint8_t *p, size_t len)
{
    gro_pkt_t k;
    g->pushed++;

    if (!gro_parse(p, len, &k)) {
        /* Not mergeable. Packets of other flows may pass; but a TCP packet we
         * cannot merge (SYN, FIN, ACK-only, ...) must not overtake data of
         * its own flow still held back. */
        if ((p[0] >> 4) == 4 || (p[0] >> 4) == 6) {
            for (int i = 0; i < GRO_SLOTS; i++) {
                gro_entry_t *e = &g->e[i];
                if (!e->used) continue;
                size_t ip_hlen = e->ip_hlen;
                int v6 = e->v6;
                if ((int)((p[0] >> 4) == 6) != v6 || len < ip_hlen + 4) continue;
                if (p[v6 ? 6 : 9] != IPPROTO_TCP) continue;
                size_t aoff = v6 ? 8 : 12, alen = v6 ? 32 : 8;
                if (memcmp(e->buf + aoff, p + aoff, alen) == 0 &&
                    memcmp(e->buf + ip_hlen, p + ip_hlen, 4) == 0)
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
        if (gro_can_append(e, p, &k)) {
            memcpy(e->buf + e->len, p + k.ip_hlen + k.tcp_hlen, k.payload);
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
    e->v6 = k.v6;
    e->ip_hlen = (uint16_t)k.ip_hlen;
    e->tcp_hlen = (uint16_t)k.tcp_hlen;
    e->gso_size = (uint16_t)k.payload;
    e->nseg = 1;
    e->next_seq = k.seq + (uint32_t)k.payload;
    e->len = len;
    e->closed = (k.flags & TCP_FLAG_PSH) != 0;
    memcpy(e->buf, p, len);
}
