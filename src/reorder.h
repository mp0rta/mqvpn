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
 *   - flow identity: 5-tuple key, compare, and keyed hash (§6)
 *   - phase-1 config struct, defaults, and validation (§16)
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Public ABI enums (mqvpn_reorder_mode_t, mqvpn_reorder_profile_t) are owned by
 * the public header so config setters can take them. Do not redefine here. */
#include "libmqvpn.h"

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

/* mqvpn_flow_key_hash() reads the raw struct bytes, so the layout must be free
 * of interior padding (1 + 1 + 2 + 2 + 16 + 16 = 38). Pin it: any padding would
 * feed indeterminate bytes into the hash. */
_Static_assert(
    sizeof(mqvpn_flow_key_t) == 38,
    "mqvpn_flow_key_t must be padding-free: flow_key_hash reads raw struct bytes");

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
 *
 * This reads the raw struct bytes via memcpy-equivalent pointer access, so it
 * relies on mqvpn_flow_key_t being padding-free (pinned by the _Static_assert
 * above). Note that flow_key_eq() deliberately compares field-by-field instead —
 * the two functions intentionally differ in how they treat the struct layout.
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

/* ───────────────────────────── §16: config ────────────────────────────────
 *
 * Phase-1 configuration. Values and semantics follow §16.1 / §16.2. The struct
 * is consumed by the library; surfaces (builder API / INI / JSON) translate
 * into it.
 */

#define MQVPN_REORDER_MAX_RULES 16

/* A single port/protocol → profile rule (§15.1 / §16.1 repeated [ReorderRule]). */
typedef struct {
    uint8_t proto; /* L4 protocol (UDP = 17) */
    uint16_t port; /* matched against src or dst (host order) */
    mqvpn_reorder_profile_t profile;
} mqvpn_reorder_rule_t;

typedef struct {
    mqvpn_reorder_mode_t mode; /* master gate (§16.2 enabled) */

    /* receiver-side (§16.2) */
    uint32_t max_wait_ms;                  /* v1 fixed gap wait */
    uint32_t cap_packets_per_flow;         /* ring.cap, must be power of two */
    uint64_t max_buffer_bytes_per_flow;    /* per-flow byte limit */
    uint16_t classify_window;              /* ACK-direction classify window */
    uint16_t ack_demote_max_large_packets; /* demote threshold (count) */
    uint32_t small_packet_threshold_bytes; /* inner UDP payload small/large split */

    /* sender + receiver reset coordination (§10.5 / §14.2) */
    uint32_t reset_mark_packets;  /* K: FLOW_RESET marks on new flow */
    uint32_t reset_idle_grace_ms; /* honor FLOW_RESET when idle > this */

    /* table + pool limits (§13.5 / §14) */
    uint32_t max_flows;                /* per-table cap (both sides) */
    uint64_t global_max_buffer_bytes;  /* shared pool limit */
    uint32_t ingress_idle_timeout_sec; /* inbound (receiver) idle eviction */
    uint32_t egress_idle_timeout_sec;  /* outbound (sender) idle eviction */

    /* internal/test knob — not exposed via any public setter */
    int eval_force_no_demotion;

    mqvpn_reorder_rule_t rules[MQVPN_REORDER_MAX_RULES];
    int n_rules;
} mqvpn_reorder_config_t;

/* Populate cfg with the §16.1 default values. */
static inline void
mqvpn_reorder_config_default(mqvpn_reorder_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = MQVPN_REORDER_OFF;
    cfg->max_wait_ms = 30;
    cfg->cap_packets_per_flow = 1024;
    cfg->max_buffer_bytes_per_flow = 1572864ULL;
    cfg->classify_window = 64;
    cfg->ack_demote_max_large_packets = 3;
    cfg->small_packet_threshold_bytes = 200;
    cfg->reset_mark_packets = 8;
    cfg->reset_idle_grace_ms = 10000;
    cfg->max_flows = 65536;
    cfg->global_max_buffer_bytes = 67108864ULL;
    cfg->ingress_idle_timeout_sec = 30;
    cfg->egress_idle_timeout_sec = 300;
    cfg->eval_force_no_demotion = 0;
    cfg->n_rules = 0;
}

/*
 * Validate cross-side invariants. Returns 0 if valid, -1 otherwise.
 *   - ingress_idle must be strictly less than egress_idle (§14.2: receiver idle
 *     eviction must fire before the sender's, so the reset backstop holds).
 *   - cap_packets_per_flow must be a non-zero power of two (§13.1 ring index).
 */
static inline int
mqvpn_reorder_config_validate(const mqvpn_reorder_config_t *cfg)
{
    if (cfg->ingress_idle_timeout_sec >= cfg->egress_idle_timeout_sec) {
        return -1;
    }
    uint32_t cap = cfg->cap_packets_per_flow;
    if (!(cap && !(cap & (cap - 1)))) {
        return -1;
    }
    return 0;
}

#endif /* MQVPN_REORDER_H */
