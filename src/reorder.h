// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_REORDER_H
#define MQVPN_REORDER_H

/*
 * reorder.h — foundation types for the flow-aware reorder-only datagram
 * delivery shim (design spec v2.5).
 *
 * This header is header-only (static inline) and dependency-light so it can be
 * unit-tested and linked into both the library and platform layers.
 *
 *   - wire header v1 codec + self-describing type dispatch (§8.1/§8.2/§8.3, §7)
 */

#include <stddef.h>
#include <stdint.h>

/* ─────────────────────────── §8: wire format ──────────────────────────────
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Flags     |       Sequence Number  (hi)   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Sequence Number (lo, 32 bits)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Type  (1B): 0x01 = REORDERED_UDP_PACKET_V1
 * Flags (1B): §8.3
 * Seq   (6B): 48-bit per-flow sequence number, big-endian
 * header = 8 bytes; inner IP packet follows at offset 8.
 */

#define MQVPN_REORDER_TYPE_V1    0x01 /* §8.1 REORDERED_UDP_PACKET_V1 */
#define MQVPN_REORDER_FLAG_RESET 0x01 /* §8.3 bit 0: FLOW_RESET */
#define MQVPN_REORDER_HDR_LEN    8    /* §8.2 fixed header length */

/*
 * §8.1 self-describing dispatch on the first byte:
 *   upper nibble == 4 or 6 → bare inner IP packet (RAW)
 *   == 0x01                → REORDERED_UDP_PACKET_V1
 *   else                   → unknown type → drop
 */
typedef enum {
    MQVPN_REORDER_KIND_RAW,
    MQVPN_REORDER_KIND_REORDER_V1,
    MQVPN_REORDER_KIND_UNKNOWN,
} mqvpn_reorder_kind_t;

static inline mqvpn_reorder_kind_t
mqvpn_reorder_classify_byte(uint8_t b0)
{
    uint8_t nibble = (uint8_t)(b0 >> 4);
    if (nibble == 4 || nibble == 6) {
        return MQVPN_REORDER_KIND_RAW;
    }
    if (b0 == MQVPN_REORDER_TYPE_V1) {
        return MQVPN_REORDER_KIND_REORDER_V1;
    }
    return MQVPN_REORDER_KIND_UNKNOWN;
}

/*
 * Encode an 8-byte reorder header into out8. Only the low 48 bits of seq are
 * emitted (big-endian into out8[2..7]); higher bits are ignored (§7).
 */
static inline void
mqvpn_reorder_wire_encode(uint8_t *out8, uint8_t type, uint8_t flags, uint64_t seq)
{
    out8[0] = type;
    out8[1] = flags;
    out8[2] = (uint8_t)(seq >> 40);
    out8[3] = (uint8_t)(seq >> 32);
    out8[4] = (uint8_t)(seq >> 24);
    out8[5] = (uint8_t)(seq >> 16);
    out8[6] = (uint8_t)(seq >> 8);
    out8[7] = (uint8_t)(seq);
}

/*
 * Decode an 8-byte reorder header. Returns 0 on success, -1 if len < 8 (§21
 * "datagram length < header"). seq is the 48-bit big-endian value (high 16
 * bits of the uint64_t are always 0).
 */
static inline int
mqvpn_reorder_wire_decode(const uint8_t *in, size_t len, uint8_t *type, uint8_t *flags,
                          uint64_t *seq)
{
    if (len < MQVPN_REORDER_HDR_LEN) {
        return -1;
    }
    *type = in[0];
    *flags = in[1];
    *seq = ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32) | ((uint64_t)in[4] << 24) |
           ((uint64_t)in[5] << 16) | ((uint64_t)in[6] << 8) | ((uint64_t)in[7]);
    return 0;
}

/* ─────────────────────────── §6: flow identity ────────────────────────────
 *
 * Flow identity is the inner 5-tuple (§6.1). Addresses/ports are NOT
 * normalized: forward and reverse directions are distinct flows, and IPv4 and
 * IPv6 are distinct flows. The key is never put on the wire (§6.2); each
 * endpoint keys its local hash table by the full 5-tuple and may mix in a
 * per-process random seed for hash-flooding resistance (the seed need not
 * match the peer's).
 *
 * ports are stored in host byte order. IPv4 addresses use the first 4 bytes of
 * the 16-byte arrays with the remainder zeroed.
 */
typedef struct {
    uint8_t ip_version; /* 4 or 6 */
    uint8_t proto;      /* L4 protocol (UDP = 17) */
    uint16_t src_port;  /* host order */
    uint16_t dst_port;  /* host order */
    uint8_t src_ip[16]; /* v4 in [0..3], rest zero */
    uint8_t dst_ip[16];
} mqvpn_flow_key_t;

/* Returns 1 if the two 5-tuples are identical, 0 otherwise (§6.3: logical flow
 * distinction is a full 5-tuple compare). */
static inline int
mqvpn_flow_key_eq(const mqvpn_flow_key_t *a, const mqvpn_flow_key_t *b)
{
    return a->ip_version == b->ip_version && a->proto == b->proto &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           memcmp(a->src_ip, b->src_ip, sizeof(a->src_ip)) == 0 &&
           memcmp(a->dst_ip, b->dst_ip, sizeof(a->dst_ip)) == 0;
}

/*
 * Keyed hash over the 5-tuple, seeded with a per-process value (§6.2). v1 uses
 * FNV-1a over the struct bytes mixed with the seed; a SipHash upgrade is future
 * work. Same key + same seed always yields the same hash.
 */
static inline uint64_t
mqvpn_flow_key_hash(const mqvpn_flow_key_t *k, uint64_t seed)
{
    const uint64_t fnv_prime = 1099511628211ULL;
    uint64_t h = 14695981039346656037ULL ^ seed;
    const uint8_t *p = (const uint8_t *)k;
    for (size_t i = 0; i < sizeof(*k); i++) {
        h ^= p[i];
        h *= fnv_prime;
    }
    return h;
}

#endif /* MQVPN_REORDER_H */
