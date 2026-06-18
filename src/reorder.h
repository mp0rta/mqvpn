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
 *
 * §7 DESIGN INVARIANT — per-flow lifetime < 2^48 packets: the wire seq space is
 * NOT reconstructed mod 2^48 on RX (expected is a monotone uint64_t that tracks
 * raw wire values). A single 5-tuple flow that sent 2^48 (~2.8e14) packets would
 * wrap the wire seq to 0 while RX expected sits at 2^48, late-dropping everything
 * after. This is intentionally unhandled: at realistic single-flow VPN rates that
 * is years-to-decades of continuous saturation, far beyond any flow's idle-evict
 * lifetime. Flows are reset (FLOW_RESET, seq→0) long before approaching 2^48, so
 * the wire seq never actually wraps in practice. If a use case ever sustains a
 * single flow past this bound, add QUIC-style windowed seq reconstruction on RX.
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

/* ─────────────────── §19: capability negotiation (mqvpn-reorder) ───────────
 *
 * §19.2: the capability is advertised as an HTTP header on the CONNECT-IP
 * exchange. Wire name is lowercase "mqvpn-reorder" with value "v1". The client
 * sends it in its request when reorder is locally enabled; the server echoes it
 * in its 200 response only when it also has reorder enabled AND the client
 * advertised. §19.3: a sender MUST observe the peer's advertisement before it
 * stamps any datagram (pre-negotiation traffic is RAW, §19.4).
 */
#define MQVPN_REORDER_HDR_NAME  "mqvpn-reorder"
#define MQVPN_REORDER_HDR_VALUE "v1"

/*
 * Returns 1 iff (name[0..name_len), value[0..value_len)) is a well-formed
 * mqvpn-reorder advertisement: lowercase name "mqvpn-reorder" and value "v1".
 * Used by both the client (response header) and server (request header) parse
 * sites so the match rule is defined in exactly one place. Unit-tested.
 */
static inline int
mqvpn_reorder_header_match(const void *name, size_t name_len, const void *value,
                           size_t value_len)
{
    const size_t n = sizeof(MQVPN_REORDER_HDR_NAME) - 1;  /* 13 */
    const size_t v = sizeof(MQVPN_REORDER_HDR_VALUE) - 1; /* 2 */
    return name_len == n && memcmp(name, MQVPN_REORDER_HDR_NAME, n) == 0 &&
           value_len == v && memcmp(value, MQVPN_REORDER_HDR_VALUE, v) == 0;
}

/* §19.3: a side advertises/echoes mqvpn-reorder only when it can actually RECEIVE
 * reordered packets — reorder enabled AND the local rx engine allocated. If the
 * engine is NULL (config validation failure / OOM) but we still advertised, the
 * peer would stamp packets that we then drop (reorder_rx == NULL) → a one-way
 * blackhole. Gating both the client advertise and the server echo on this keeps
 * negotiation honest (a failed engine cleanly falls back to RAW on both ends).
 * `rx_engine` is the opaque mqvpn_reorder_rx_t* (void* to avoid the type here). */
static inline int
mqvpn_reorder_should_advertise(mqvpn_reorder_mode_t mode, const void *rx_engine)
{
    return mode != MQVPN_REORDER_OFF && rx_engine != NULL;
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

/* ─────────────────── §4 / §10.2: inner-IP 5-tuple parser ───────────────────
 *
 * mqvpn_reorder_parse_5tuple() extracts the inner 5-tuple from a bare inner IP
 * packet, for both the TX gating path (§10.2) and the RX dispatch. It returns 0
 * only for a parseable, non-fragmented UDP packet; -1 for anything that must be
 * sent RAW (§4 / §4.1): too short, not IPv4/IPv6, fragmented, non-UDP, or an
 * IPv6 chain we cannot walk to a UDP header.
 *
 * On success out->{ip_version, proto=17, src/dst_ip, src/dst_port(host order)}
 * are filled (v4 addresses in [0..3], rest zero, per §6.1).
 */
#define MQVPN_IPPROTO_UDP 17

/* IPv6 extension headers we walk through to reach the UDP header (§4.1). */
#define MQVPN_IP6_HOPOPTS  0  /* Hop-by-Hop Options */
#define MQVPN_IP6_ROUTING  43 /* Routing */
#define MQVPN_IP6_FRAGMENT 44 /* Fragment → not eligible (§4.1) */
#define MQVPN_IP6_DSTOPTS  60 /* Destination Options */

static inline int
mqvpn_reorder_parse_5tuple(const uint8_t *pkt, size_t len, mqvpn_flow_key_t *out)
{
    if (len < 1) {
        return -1;
    }
    uint8_t version = (uint8_t)(pkt[0] >> 4);

    if (version == 4) {
        /* IPv4: need at least the 20-byte fixed header. */
        if (len < 20) {
            return -1;
        }
        uint8_t ihl = (uint8_t)(pkt[0] & 0x0f);
        size_t hdr_len = (size_t)ihl * 4;
        if (ihl < 5 || len < hdr_len) {
            return -1;
        }
        /* §4.1: MF set or fragment offset != 0 → RAW (port not visible / order
         * across fragments breaks). flags+frag-offset is the 16-bit field at
         * offset 6; bit 13 (0x2000) = MF, low 13 bits = offset. */
        uint16_t frag = (uint16_t)((pkt[6] << 8) | pkt[7]);
        if (frag & 0x3fff) {
            return -1;
        }
        if (pkt[9] != MQVPN_IPPROTO_UDP) {
            return -1;
        }
        /* UDP header (8 bytes) must fit after the IP header. */
        if (len < hdr_len + 8) {
            return -1;
        }
        memset(out, 0, sizeof(*out));
        out->ip_version = 4;
        out->proto = MQVPN_IPPROTO_UDP;
        memcpy(out->src_ip, pkt + 12, 4);
        memcpy(out->dst_ip, pkt + 16, 4);
        out->src_port = (uint16_t)((pkt[hdr_len] << 8) | pkt[hdr_len + 1]);
        out->dst_port = (uint16_t)((pkt[hdr_len + 2] << 8) | pkt[hdr_len + 3]);
        return 0;
    }

    if (version == 6) {
        /* IPv6: 40-byte fixed header, then walk the extension-header chain. */
        if (len < 40) {
            return -1;
        }
        uint8_t next = pkt[6];
        size_t off = 40;
        /* Bound the walk: each ext header is >= 8 bytes, so the chain length is
         * bounded by len; cap iterations defensively regardless. */
        for (int i = 0; i < 16; i++) {
            if (next == MQVPN_IPPROTO_UDP) {
                if (len < off + 8) {
                    return -1;
                }
                memset(out, 0, sizeof(*out));
                out->ip_version = 6;
                out->proto = MQVPN_IPPROTO_UDP;
                memcpy(out->src_ip, pkt + 8, 16);
                memcpy(out->dst_ip, pkt + 24, 16);
                out->src_port = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
                out->dst_port = (uint16_t)((pkt[off + 2] << 8) | pkt[off + 3]);
                return 0;
            }
            if (next == MQVPN_IP6_FRAGMENT) {
                return -1; /* §4.1: fragmented → RAW */
            }
            if (next == MQVPN_IP6_HOPOPTS || next == MQVPN_IP6_ROUTING ||
                next == MQVPN_IP6_DSTOPTS) {
                /* Each of these ext headers: next(1) + hdr_ext_len(1, in 8-octet
                 * units excluding the first 8) + ... */
                if (len < off + 2) {
                    return -1;
                }
                uint8_t hdr_ext_len = pkt[off + 1];
                size_t ext_bytes = (size_t)(hdr_ext_len + 1) * 8;
                next = pkt[off];
                off += ext_bytes;
                if (off > len) {
                    return -1;
                }
                continue;
            }
            /* Unknown / unsupported next-header (incl. TCP, ICMPv6) → RAW. */
            return -1;
        }
        return -1; /* chain too long */
    }

    return -1; /* not IPv4 or IPv6 */
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
    uint32_t explicit_wait_ms; /* per-rule override; 0 = unset */
    uint32_t explicit_cap;     /* per-rule override; 0 = unset */
    uint32_t resolved_wait_ms; /* filled by finalize */
    uint32_t resolved_cap;     /* filled by finalize */
} mqvpn_reorder_rule_t;

/* Map a profile to its (wait_ms, cap) preset. Returns 1 and writes both outputs
 * when the profile carries a preset; returns 0 and leaves outputs untouched for
 * profiles with no preset (low_latency / default_udp). */
static inline int
mqvpn_reorder_profile_preset(mqvpn_reorder_profile_t profile, uint32_t *wait_ms,
                             uint32_t *cap)
{
    switch (profile) {
    case MQVPN_RPROF_QUIC_BULK:
    case MQVPN_RPROF_CELLULAR_BOND:
        *wait_ms = 50;
        *cap = 1024;
        return 1;
    case MQVPN_RPROF_FIBER_LTE:
        *wait_ms = 50;
        *cap = 2048;
        return 1;
    default: return 0; /* low_latency / default_udp: no preset */
    }
}

typedef struct {
    mqvpn_reorder_mode_t mode; /* master gate (§16.2 enabled) */

    /* receiver-side (§16.2) */
    uint32_t max_wait_ms;               /* v1 fixed gap wait */
    uint32_t cap_packets_per_flow;      /* ring.cap, must be power of two */
    uint64_t max_buffer_bytes_per_flow; /* per-flow byte limit */
    uint16_t classify_window; /* ACK-direction classify window; 0 = demotion disabled */
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

    /* per-rule param resolution: set when a global MaxWaitMs/CapPackets was
     * explicitly provided, letting that global value punch through a profile
     * preset (tier 2 precedence in mqvpn_reorder_config_finalize). */
    uint8_t has_explicit_wait;
    uint8_t has_explicit_cap;

    mqvpn_reorder_rule_t rules[MQVPN_REORDER_MAX_RULES];
    int n_rules;
} mqvpn_reorder_config_t;

/* First rule whose proto matches and port == src or dst; NULL if none. Shared by
 * TX (eligibility) and RX (per-flow wait/cap) so the match is identical. */
static inline const mqvpn_reorder_rule_t *
mqvpn_reorder_match_rule(const mqvpn_reorder_config_t *cfg, const mqvpn_flow_key_t *key)
{
    for (int i = 0; i < cfg->n_rules; i++) {
        const mqvpn_reorder_rule_t *r = &cfg->rules[i];
        if (r->proto != key->proto) continue;
        if (r->port == key->src_port || r->port == key->dst_port) return r;
    }
    return NULL;
}

/* Resolve each rule's effective (wait,cap): rule-explicit > global-explicit >
 * profile-preset > builtin. Idempotent. Run AFTER full config parse (rule- and
 * global-explicit arrive in separate sections). Tiers 2 & 4 intentionally read
 * the same storage (cfg->max_wait_ms holds the builtin default when not explicit;
 * has_explicit_* only lets a global value punch through a preset). resolved_cap
 * is forced to a non-zero power of two (defends against a bad explicit cap that
 * slipped parse). */
static inline void
mqvpn_reorder_config_finalize(mqvpn_reorder_config_t *cfg)
{
    for (int i = 0; i < cfg->n_rules; i++) {
        mqvpn_reorder_rule_t *r = &cfg->rules[i];
        uint32_t pw = 0, pc = 0;
        int has_preset = mqvpn_reorder_profile_preset(r->profile, &pw, &pc);
        r->resolved_wait_ms = r->explicit_wait_ms      ? r->explicit_wait_ms
                              : cfg->has_explicit_wait ? cfg->max_wait_ms
                              : has_preset             ? pw
                                                       : cfg->max_wait_ms;
        /* An invalid (non-pow2 / zero) per-rule explicit_cap is treated as UNSET
         * so precedence falls through correctly (global-explicit > preset >
         * builtin) instead of skipping the global tier. */
        uint32_t rcap = r->explicit_cap;
        if (rcap == 0 || (rcap & (rcap - 1))) rcap = 0;
        uint32_t cap = rcap                    ? rcap
                       : cfg->has_explicit_cap ? cfg->cap_packets_per_flow
                       : has_preset            ? pc
                                               : cfg->cap_packets_per_flow;
        /* Defensive: chosen tier should already be pow2 (global cap is validated
         * pre-finalize; presets are pow2). Clamp the impossible case to builtin. */
        if (cap == 0 || (cap & (cap - 1))) cap = 1024;
        r->resolved_cap = cap;
    }
}

/* ─────────────────────────── §17: RX statistics ───────────────────────────
 *
 * Per-flow receiver counters (§17). Lives here (not in reorder_rx.c) so the RX
 * snapshot accessor (mqvpn_reorder_rx_get_stats) can return it across the TU
 * boundary. wait period 1 回 = arm_gap_timer 1 回; each period ends in exactly
 * one of filled / timeout / overflow / demote / reset, giving the §17 identity:
 *
 *   gap_count = gap_filled_count + gap_timeout_count + gap_overflow_count
 *             + gap_demote_count  + gap_reset_count
 */

/* added-latency histogram: smallest i with residence_us <= bound[i].
 * bucket[0] == residence 0 (in-order pass-through). bucket[11] == overflow (>512ms). */
#define MQVPN_REORDER_LAT_BUCKETS 12

typedef struct {
    uint64_t delivered_count;
    uint64_t too_late_drop_count;
    uint64_t too_far_ahead_drop_count;
    uint64_t duplicate_drop_count;
    uint64_t per_flow_limit_drop_count;
    uint64_t pool_drop_count;
    uint64_t reset_discard_count; /* §17: old-epoch buffered packets discarded on reset */
    uint64_t gap_count;           /* gap episodes opened (buffer went empty→nonempty) */
    uint64_t gap_filled_count;    /* gap episodes closed by the missing seq arriving */
    uint64_t gap_timeout_count;   /* §17: periods ended by timeout skip (§12.1) */
    uint64_t gap_overflow_count;  /* §17: periods ended by overflow_flush (§12.3) */
    uint64_t gap_demote_count;    /* §17: periods ended by ACK demote flush (§11.6) */
    uint64_t gap_reset_count;     /* §17: periods ended by FLOW_RESET discard (§11.6) */
    uint64_t ack_demote_count;    /* §17: flows demoted to pass-through (§11.6) */
    uint64_t residence_bucket[MQVPN_REORDER_LAT_BUCKETS]; /* added-latency histogram */
    uint64_t residence_max_us;                            /* exact max residence */
} mqvpn_reorder_stats_t;

/* Added-latency percentiles over the residence histogram (non-static so the
 * control API can link them). _percentile spans all buckets (includes the
 * residence-0 in-order packets); _buffered_percentile starts at bucket 1 so it
 * reflects only packets that actually waited in the reorder buffer. Both return
 * milliseconds. */
double mqvpn_reorder_latency_percentile(const mqvpn_reorder_stats_t *st, double q);
double mqvpn_reorder_latency_buffered_percentile(const mqvpn_reorder_stats_t *st,
                                                 double q);

/* Fold every counter of `src` (including the residence histogram + max) into
 * `dst`. Public so the server-side cross-conn aggregator reuses ONE accumulation
 * path instead of a hand-rolled field list that silently drops new fields. */
void mqvpn_reorder_stats_accumulate(mqvpn_reorder_stats_t *dst,
                                    const mqvpn_reorder_stats_t *src);

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
    cfg->has_explicit_wait = 0;
    cfg->has_explicit_cap = 0;
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
