// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_classifier.c — unit tests for the hybrid-mode ingress classifier (H1):
 * lane selection (TCP / DGRAM / RAW) + hybrid config default/validate.
 *
 * Build: see CMakeLists.txt (test_classifier target)
 */
#include "hybrid/classifier.h"
#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define ASSERT_EQ_INT(a, b, msg)                                              \
    do {                                                                      \
        if ((long long)(a) == (long long)(b)) {                               \
            g_pass++;                                                         \
        } else {                                                              \
            g_fail++;                                                         \
            fprintf(stderr, "FAIL [%s]: %lld != %lld\n", msg, (long long)(a), \
                    (long long)(b));                                          \
        }                                                                     \
    } while (0)

/* ── packet builders (local copies; deliberately not shared with the reorder
 *    tests — each suite owns its fixtures) ─────────────────────────────── */

/* Build a minimal IPv4 UDP packet into buf; returns total length. */
static size_t
build_v4_udp(uint8_t *buf, uint16_t sport, uint16_t dport, uint16_t frag_field,
             uint8_t proto)
{
    memset(buf, 0, 28);
    buf[0] = 0x45; /* version 4, IHL 5 */
    buf[6] = (uint8_t)(frag_field >> 8);
    buf[7] = (uint8_t)(frag_field);
    buf[9] = proto; /* protocol */
    buf[12] = 10;
    buf[13] = 0;
    buf[14] = 0;
    buf[15] = 1; /* src 10.0.0.1 */
    buf[16] = 10;
    buf[17] = 0;
    buf[18] = 0;
    buf[19] = 2; /* dst 10.0.0.2 */
    buf[20] = (uint8_t)(sport >> 8);
    buf[21] = (uint8_t)(sport); /* UDP sport */
    buf[22] = (uint8_t)(dport >> 8);
    buf[23] = (uint8_t)(dport); /* UDP dport */
    return 28;
}

/* Build a minimal IPv4 TCP packet (20 IP + 20 TCP = 40 bytes). */
static size_t
build_v4_tcp(uint8_t *buf, uint16_t sport, uint16_t dport, uint16_t frag_field)
{
    memset(buf, 0, 40);
    buf[0] = 0x45; /* version 4, IHL 5 */
    buf[6] = (uint8_t)(frag_field >> 8);
    buf[7] = (uint8_t)(frag_field);
    buf[9] = 6; /* protocol = TCP */
    buf[12] = 10;
    buf[13] = 0;
    buf[14] = 0;
    buf[15] = 1; /* src 10.0.0.1 */
    buf[16] = 10;
    buf[17] = 0;
    buf[18] = 0;
    buf[19] = 2; /* dst 10.0.0.2 */
    buf[20] = (uint8_t)(sport >> 8);
    buf[21] = (uint8_t)(sport); /* TCP sport */
    buf[22] = (uint8_t)(dport >> 8);
    buf[23] = (uint8_t)(dport); /* TCP dport */
    buf[32] = 0x50;             /* data offset = 5 (20-byte TCP header) */
    return 40;
}

/* Build a minimal IPv6 packet with the given next-header; L4 bytes zeroed
 * except ports at offset 40. Returns a length that fits a 20-byte TCP header. */
static size_t
build_v6(uint8_t *buf, uint8_t next_header, uint16_t sport, uint16_t dport)
{
    memset(buf, 0, 60);
    buf[0] = 0x60; /* version 6 */
    buf[6] = next_header;
    buf[8] = 0x20;
    buf[9] = 0x01; /* src starts 2001:... */
    buf[24] = 0x20;
    buf[25] = 0x02;
    buf[40] = (uint8_t)(sport >> 8);
    buf[41] = (uint8_t)(sport);
    buf[42] = (uint8_t)(dport >> 8);
    buf[43] = (uint8_t)(dport);
    buf[52] = 0x50; /* TCP data offset = 5, harmless for UDP */
    return 60;
}

/* Build a v6 packet whose BASE Next Header (offset 6) is an extension header
 * (Hop-by-Hop Options, hdr_ext_len=0 -> 8-byte ext header) with TCP reached
 * through it. mqvpn_parse_l3l4 walks the chain and still verdicts this
 * MQVPN_L4_TCP, but the base NH isn't TCP — used to test the base-NH==TCP
 * gate (lwIP's netif input path pre-accept-drops anything it can't strip
 * inline, orphaning a would-be PENDING_ACCEPT slot). */
static size_t
build_v6_ext_then_tcp(uint8_t *buf, uint16_t sport, uint16_t dport)
{
    memset(buf, 0, 68);
    buf[0] = 0x60; /* version 6 */
    buf[6] = 0;    /* base NH = Hop-by-Hop Options */
    buf[8] = 0x20;
    buf[9] = 0x01; /* src 2001:... */
    buf[24] = 0x20;
    buf[25] = 0x02; /* dst 2002:... */
    buf[40] = 6;    /* ext header's own next header = TCP */
    buf[41] = 0;    /* hdr_ext_len = 0 -> 8-byte ext header */
    buf[48] = (uint8_t)(sport >> 8);
    buf[49] = (uint8_t)(sport);
    buf[50] = (uint8_t)(dport >> 8);
    buf[51] = (uint8_t)(dport);
    buf[60] = 0x50; /* TCP data offset = 5, harmless */
    return 68;      /* 40 (v6 fixed hdr) + 8 (ext hdr) + 20 (TCP hdr) */
}

/* Build a direct v6 TCP packet (base NH == TCP, no ext headers) with
 * fully-specified 16-byte src/dst addresses — needed for the address-class
 * ineligibility gate tests (v4-mapped / multicast / unspecified), where
 * build_v6's hardcoded 2001:.../2002:... addresses can't express the needed
 * bit patterns. */
static size_t
build_v6_tcp_addrs(uint8_t *buf, const uint8_t src[16], const uint8_t dst[16],
                   uint16_t sport, uint16_t dport)
{
    memset(buf, 0, 60);
    buf[0] = 0x60; /* version 6 */
    buf[6] = 6;    /* base NH = TCP */
    memcpy(buf + 8, src, 16);
    memcpy(buf + 24, dst, 16);
    buf[40] = (uint8_t)(sport >> 8);
    buf[41] = (uint8_t)(sport);
    buf[42] = (uint8_t)(dport >> 8);
    buf[43] = (uint8_t)(dport);
    buf[52] = 0x50; /* TCP data offset = 5, harmless */
    return 60;
}

static mqvpn_hybrid_config_t
make_pol(int enabled, mqvpn_hybrid_tcp_mode_t mode)
{
    mqvpn_hybrid_config_t pol;
    mqvpn_hybrid_config_default(&pol);
    pol.enabled = enabled;
    pol.tcp_mode = mode;
    return pol;
}

/* ── lane selection ────────────────────────────────────────────────────── */

static void
test_classify_udp_always_dgram(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;

    /* v4 UDP → DGRAM regardless of enabled/tcp_mode. */
    size_t n = build_v4_udp(buf, 1111, 443, 0, 17);
    mqvpn_hybrid_config_t pol = make_pol(0, MQVPN_HYBRID_TCP_RAW);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_DGRAM,
                  "v4 udp disabled+raw -> dgram");
    pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_DGRAM,
                  "v4 udp enabled+stream -> dgram");
    ASSERT_EQ_INT(k.proto, 17, "v4 udp key proto");
    ASSERT_EQ_INT(k.src_port, 1111, "v4 udp key sport");

    /* v6 UDP → DGRAM too. */
    n = build_v6(buf, 17, 2222, 443);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_DGRAM,
                  "v6 udp -> dgram");
    ASSERT_EQ_INT(k.ip_version, 6, "v6 udp key version");
}

static void
test_classify_v4_tcp_gates(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    size_t n = build_v4_tcp(buf, 2222, 80, 0);

    /* enabled + STREAM → TCP lane. */
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "v4 tcp enabled+stream -> tcp");
    ASSERT_EQ_INT(k.proto, 6, "v4 tcp key proto");
    ASSERT_EQ_INT(k.ip_version, 4, "v4 tcp key version");
    ASSERT_EQ_INT(k.src_port, 2222, "v4 tcp key sport");

    /* enabled + AUTO → TCP lane (static gate passes; per-flow auto is later). */
    pol = make_pol(1, MQVPN_HYBRID_TCP_AUTO);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "v4 tcp enabled+auto -> tcp");

    /* enabled + RAW → RAW. */
    pol = make_pol(1, MQVPN_HYBRID_TCP_RAW);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 tcp enabled+raw -> raw");

    /* disabled + STREAM → RAW. */
    pol = make_pol(0, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 tcp disabled+stream -> raw");
}

static void
test_classify_tunnel_subnet_tcp_raw(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    size_t n = build_v4_tcp(buf, 2222, 80, 0); /* dst 10.0.0.2 */

    /* client_tunnel_subnet[0] (v4) set (10.0.0.0/24, the e2e/default pool
     * shape): TCP destined INSIDE it must be RAW even under enabled+stream —
     * the server's egress ACL denies the tunnel subnet unconditionally, so
     * the lane would only ever RST (see classifier.c's comment). */
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_parse_cidr("10.0.0.0/24", &pol.client_tunnel_subnet[0]), 0,
                  "tunnel subnet cidr parses");
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 tcp dst in tunnel subnet + stream -> raw");

    /* AUTO passes the same static gate — inside-subnet must be RAW too. */
    pol.tcp_mode = MQVPN_HYBRID_TCP_AUTO;
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 tcp dst in tunnel subnet + auto -> raw");

    /* Outside the subnet: the lane verdict is unaffected. */
    pol.tcp_mode = MQVPN_HYBRID_TCP_STREAM;
    buf[16] = 10;
    buf[17] = 222;
    buf[18] = 0;
    buf[19] = 1; /* dst 10.222.0.1 */
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "v4 tcp dst outside tunnel subnet -> tcp");

    /* family == 0 (default / not learned): gate off, verdict as before —
     * pinned so the unset sentinel can't accidentally match-all. */
    memset(&pol.client_tunnel_subnet[0], 0, sizeof(pol.client_tunnel_subnet[0]));
    buf[16] = 10;
    buf[17] = 0;
    buf[18] = 0;
    buf[19] = 2; /* dst back inside 10.0.0.0/24 */
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "unset tunnel subnet (family 0) -> tcp unchanged");

    /* UDP inside the subnet is untouched — the exclusion is a TCP-lane
     * concern only (DGRAM never hits the egress ACL). */
    ASSERT_EQ_INT(mqvpn_parse_cidr("10.0.0.0/24", &pol.client_tunnel_subnet[0]), 0,
                  "tunnel subnet cidr re-parses");
    n = build_v4_udp(buf, 1111, 443, 0, 17); /* dst 10.0.0.2 */
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_DGRAM,
                  "v4 udp dst in tunnel subnet -> dgram unchanged");
}

/* mqvpn_tunnel_subnet_learn{,_v6}: the ADDRESS_ASSIGN → tunnel-subnet
 * widening rule, pinned at host-unit level (the e2e-only alternative would
 * let a "simplification" that honors the wire /32 verbatim pass ctest while
 * silently breaking the tunnel-subnet exclusion in deployment — the /32 is
 * this client's own address, never the pool subnet). */
static void
test_tunnel_subnet_learn(void)
{
    const uint8_t ip[4] = {10, 0, 0, 2};
    mqvpn_cidr_entry_t e;

    /* /32 (today's server behavior): widened to /24, net masked to .0. */
    mqvpn_tunnel_subnet_learn(ip, 32, &e);
    ASSERT_EQ_INT(e.family, 4, "/32 widens: family v4");
    ASSERT_EQ_INT(e.prefix_len, 24, "/32 widens: prefix_len /24");
    ASSERT_EQ_INT(e.net[0], 10, "/32 widens: net[0] 10");
    ASSERT_EQ_INT(e.net[1], 0, "/32 widens: net[1] 0");
    ASSERT_EQ_INT(e.net[2], 0, "/32 widens: net[2] 0 (masked off)");

    /* Narrower-than-/24 wire prefixes all widen to the same /24. */
    mqvpn_tunnel_subnet_learn(ip, 28, &e);
    ASSERT_EQ_INT(e.prefix_len, 24, "/28 widens: prefix_len /24");
    ASSERT_EQ_INT(e.net[2], 0, "/28 widens: net[2] 0");

    /* /24 exactly: honored as-is. */
    mqvpn_tunnel_subnet_learn(ip, 24, &e);
    ASSERT_EQ_INT(e.prefix_len, 24, "/24 honored: prefix_len /24");
    ASSERT_EQ_INT(e.net[2], 0, "/24 honored: net[2] 0");

    /* Wider than /24: honored as-is (a /16 pool signaled on the wire must
     * not be narrowed back to /24). */
    const uint8_t ip16[4] = {10, 0, 5, 2};
    mqvpn_tunnel_subnet_learn(ip16, 16, &e);
    ASSERT_EQ_INT(e.prefix_len, 16, "/16 honored: prefix_len /16");
    ASSERT_EQ_INT(e.net[1], 0, "/16 honored: net[1] 0 (masked off)");

    /* Degenerate prefix <= 0: family stays 0 — the "not learned" sentinel
     * that keeps the classifier gate OFF (mqvpn_cidr_match's own family
     * check, no separate caller-side guard needed anymore). */
    mqvpn_tunnel_subnet_learn(ip, 0, &e);
    ASSERT_EQ_INT(e.family, 0, "/0 -> unset sentinel");
    mqvpn_tunnel_subnet_learn(ip, -1, &e);
    ASSERT_EQ_INT(e.family, 0, "negative prefix -> unset sentinel");
}

/* mqvpn_tunnel_subnet_learn_v6: unlike the v4 form, the assigned prefix is
 * honored DIRECTLY — no >=24-style widening (that clamp is a v4-pool-only
 * artifact). */
static void
test_tunnel_subnet_learn_v6(void)
{
    const uint8_t ip6[16] = {0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    mqvpn_cidr_entry_t e;

    /* /64: honored as-is, no widening. */
    mqvpn_tunnel_subnet_learn_v6(ip6, 64, &e);
    ASSERT_EQ_INT(e.family, 6, "v6 learn: family v6");
    ASSERT_EQ_INT(e.prefix_len, 64, "v6 learn: prefix_len honored as-is");
    ASSERT_EQ_INT(e.net[0], 0xfd, "v6 learn: net[0] preserved");
    ASSERT_EQ_INT(e.net[8], 0, "v6 learn: net[8] masked off past /64");

    /* /128 (host route): honored as-is, nothing masked off. */
    mqvpn_tunnel_subnet_learn_v6(ip6, 128, &e);
    ASSERT_EQ_INT(e.prefix_len, 128, "v6 learn /128: prefix_len honored");
    ASSERT_EQ_INT(e.net[15], 1, "v6 learn /128: net[15] preserved");

    /* Degenerate prefix: unset sentinel. */
    mqvpn_tunnel_subnet_learn_v6(ip6, 0, &e);
    ASSERT_EQ_INT(e.family, 0, "v6 learn /0 -> unset sentinel");
    mqvpn_tunnel_subnet_learn_v6(ip6, -1, &e);
    ASSERT_EQ_INT(e.family, 0, "v6 learn negative prefix -> unset sentinel");
    mqvpn_tunnel_subnet_learn_v6(ip6, 129, &e);
    ASSERT_EQ_INT(e.family, 0, "v6 learn prefix > 128 -> unset sentinel");
}

/* mqvpn_cidr_match: the shared matcher (classifier gate + egress ACL).
 * Direct struct literals — no parse dependency. net[] = pre-masked
 * network-order bytes. v4 entry matches only v4 keys; v6 only v6; prefix
 * boundaries; unset (family==0) matches nothing. */
static void
test_cidr_match_family_strict(void)
{
    mqvpn_cidr_entry_t e = {4, 24, {10, 0, 0}}; /* 10.0.0.0/24 */
    uint8_t v4in[16] = {10, 0, 0, 1};
    uint8_t v4out[16] = {10, 0, 1, 0};
    uint8_t v6any[16] = {0x20, 0x01};
    ASSERT_EQ_INT(mqvpn_cidr_match(&e, 4, v4in), 1, "10.0.0.1 in /24");
    ASSERT_EQ_INT(mqvpn_cidr_match(&e, 4, v4out), 0, "10.0.1.0 not in /24");
    ASSERT_EQ_INT(mqvpn_cidr_match(&e, 6, v6any), 0, "v4 entry never matches v6 key");

    mqvpn_cidr_entry_t e6 = {6, 8, {0xfd}}; /* fd00::/8 */
    uint8_t ula[16] = {0xfd};
    uint8_t gua[16] = {0x20, 0x01};
    ASSERT_EQ_INT(mqvpn_cidr_match(&e6, 6, ula), 1, "fd.. in fd00::/8");
    ASSERT_EQ_INT(mqvpn_cidr_match(&e6, 6, gua), 0, "2001.. not in fd00::/8");
    ASSERT_EQ_INT(mqvpn_cidr_match(&e6, 4, v4in), 0, "v6 entry never matches v4 key");

    /* Non-byte-aligned prefixes drive mqvpn_cidr_match's partial-byte branch
     * on BOTH sides of the boundary (the existing /24 /8 /4 cases only cover
     * a byte boundary or a single positive /4 partial match). /12 splits
     * byte 1 with mask 0xF0; /10 splits byte 1 with mask 0xC0. */
    mqvpn_cidr_entry_t e12 = {4, 12, {172, 16}}; /* 172.16.0.0/12 */
    uint8_t in12[16] = {172, 16, 5, 1};          /* 172.16.5.1 — inside */
    uint8_t out12[16] = {172, 32, 0, 1}; /* 172.32.0.1 — outside (32&0xF0 != 16) */
    ASSERT_EQ_INT(mqvpn_cidr_match(&e12, 4, in12), 1, "172.16.5.1 in /12");
    ASSERT_EQ_INT(mqvpn_cidr_match(&e12, 4, out12), 0,
                  "172.32.0.1 NOT in /12 (partial byte)");

    mqvpn_cidr_entry_t e10 = {4, 10, {100, 64}}; /* 100.64.0.0/10 */
    uint8_t in10[16] = {100, 64, 0, 1};          /* 100.64.0.1 — inside */
    uint8_t out10[16] = {100, 128, 0, 1}; /* 100.128.0.1 — outside (128&0xC0 != 64) */
    ASSERT_EQ_INT(mqvpn_cidr_match(&e10, 4, in10), 1, "100.64.0.1 in /10");
    ASSERT_EQ_INT(mqvpn_cidr_match(&e10, 4, out10), 0,
                  "100.128.0.1 NOT in /10 (partial byte)");

    mqvpn_cidr_entry_t unset;
    memset(&unset, 0, sizeof(unset)); /* family==0 */
    ASSERT_EQ_INT(mqvpn_cidr_match(&unset, 4, v4in), 0, "unset matches nothing v4");
    ASSERT_EQ_INT(mqvpn_cidr_match(&unset, 6, ula), 0, "unset matches nothing v6");

    /* prefix_len == 0 with a REAL family (e.g. a parsed "0.0.0.0/0" / "::/0")
     * is the "match everything" row — a DISTINCT bit pattern from the
     * family==0 unset sentinel above (the whole point of the redesign). The
     * family gate still applies: a v4 /0 never swallows a v6 key, and vice
     * versa. Pinned because the docstrings lean on this distinction. */
    mqvpn_cidr_entry_t allv4 = {4, 0, {0}};
    ASSERT_EQ_INT(mqvpn_cidr_match(&allv4, 4, v4in), 1, "v4 /0 matches arbitrary v4");
    ASSERT_EQ_INT(mqvpn_cidr_match(&allv4, 4, v4out), 1, "v4 /0 matches any v4");
    ASSERT_EQ_INT(mqvpn_cidr_match(&allv4, 6, ula), 0, "v4 /0 still misses a v6 key");

    mqvpn_cidr_entry_t allv6 = {6, 0, {0}};
    ASSERT_EQ_INT(mqvpn_cidr_match(&allv6, 6, ula), 1, "v6 /0 matches arbitrary v6");
    ASSERT_EQ_INT(mqvpn_cidr_match(&allv6, 6, gua), 1, "v6 /0 matches any v6");
    ASSERT_EQ_INT(mqvpn_cidr_match(&allv6, 4, v4in), 0, "v6 /0 still misses a v4 key");
}

/* mqvpn_parse_cidr: family auto-detected by ':', prefix-range validated per
 * family, net[] pre-masked, and a full-form v6 literal must fit the grown
 * parse buffer (this exact string is 43 chars — the bug this test pins is a
 * too-small buf[] silently rejecting it as "too long"). */
static void
test_parse_cidr(void)
{
    mqvpn_cidr_entry_t e;

    /* v4, in-range prefix. */
    ASSERT_EQ_INT(mqvpn_parse_cidr("10.0.0.0/24", &e), 0, "v4 cidr parses");
    ASSERT_EQ_INT(e.family, 4, "v4 cidr family");
    ASSERT_EQ_INT(e.prefix_len, 24, "v4 cidr prefix_len");
    ASSERT_EQ_INT(e.net[0], 10, "v4 cidr net[0]");

    /* v4, host bits normalized off (route-table convention). */
    ASSERT_EQ_INT(mqvpn_parse_cidr("10.0.0.5/8", &e), 0, "v4 host-bits cidr parses");
    ASSERT_EQ_INT(e.net[0], 10, "v4 host-bits net[0]");
    ASSERT_EQ_INT(e.net[3], 0, "v4 host-bits net[3] masked off");

    /* v4, non-byte-aligned prefix: drives mqvpn_cidr_premask's partial-byte
     * (rem) branch, masking host bits off WITHIN a byte. "172.31.255.1/12"
     * → net {172,16,0,0}: byte 1 = 31 (0x1F) & 0xF0 = 0x10 = 16. */
    ASSERT_EQ_INT(mqvpn_parse_cidr("172.31.255.1/12", &e), 0, "v4 /12 cidr parses");
    ASSERT_EQ_INT(e.prefix_len, 12, "v4 /12 prefix_len");
    ASSERT_EQ_INT(e.net[0], 172, "v4 /12 net[0]");
    ASSERT_EQ_INT(e.net[1], 16, "v4 /12 net[1] partial-byte masked (31 -> 16)");
    ASSERT_EQ_INT(e.net[2], 0, "v4 /12 net[2] masked off");
    /* "100.127.0.1/10" → net {100,64,0,0}: byte 1 = 127 (0x7F) & 0xC0 = 64. */
    ASSERT_EQ_INT(mqvpn_parse_cidr("100.127.0.1/10", &e), 0, "v4 /10 cidr parses");
    ASSERT_EQ_INT(e.prefix_len, 10, "v4 /10 prefix_len");
    ASSERT_EQ_INT(e.net[1], 64, "v4 /10 net[1] partial-byte masked (127 -> 64)");

    /* v4, out-of-range prefix rejected. */
    ASSERT_EQ_INT(mqvpn_parse_cidr("1.2.3.4/33", &e), -1, "v4 prefix > 32 rejected");

    /* v6, in-range prefix, auto-detected by ':'. */
    ASSERT_EQ_INT(mqvpn_parse_cidr("2001:db8::/32", &e), 0, "v6 cidr parses");
    ASSERT_EQ_INT(e.family, 6, "v6 cidr family");
    ASSERT_EQ_INT(e.prefix_len, 32, "v6 cidr prefix_len");
    ASSERT_EQ_INT(e.net[0], 0x20, "v6 cidr net[0]");
    ASSERT_EQ_INT(e.net[1], 0x01, "v6 cidr net[1]");
    ASSERT_EQ_INT(e.net[4], 0, "v6 cidr net[4] masked off past /32");

    /* v6, out-of-range prefix rejected. */
    ASSERT_EQ_INT(mqvpn_parse_cidr("2001:db8::/129", &e), -1, "v6 prefix > 128 rejected");

    /* Full-form v6 literal (43 chars incl. the /128 suffix) must NOT be
     * rejected by a too-small parse buffer. */
    const char *full_v6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128";
    ASSERT_EQ_INT((int)strlen(full_v6), 43, "full-form v6 literal length sanity");
    ASSERT_EQ_INT(mqvpn_parse_cidr(full_v6, &e), 0, "full-form v6 cidr parses");
    ASSERT_EQ_INT(e.family, 6, "full-form v6 family");
    ASSERT_EQ_INT(e.prefix_len, 128, "full-form v6 prefix_len /128 (nothing masked)");
    ASSERT_EQ_INT(e.net[0], 0x20, "full-form v6 net[0]");
    ASSERT_EQ_INT(e.net[15], 0x34, "full-form v6 net[15] (host bits kept at /128)");

    /* Malformed input rejected outright. */
    ASSERT_EQ_INT(mqvpn_parse_cidr("not-a-cidr", &e), -1, "garbage rejected");
    ASSERT_EQ_INT(mqvpn_parse_cidr("10.0.0.0", &e), -1, "missing prefix rejected");
    ASSERT_EQ_INT(mqvpn_parse_cidr(NULL, &e), -1, "NULL string rejected");
    ASSERT_EQ_INT(mqvpn_parse_cidr("10.0.0.0/24", NULL), -1, "NULL out rejected");
}

/* v6 TCP is no longer forced to RAW (the v1 restriction is lifted): it gets
 * the same enabled/tcp_mode/tunnel-subnet gates as v4 TCP, matched against
 * client_tunnel_subnet[1] (the v6 entry) instead of [0]. */
static void
test_classify_v6_tcp_tunnel_subnet(void)
{
    uint8_t buf[80];
    mqvpn_flow_key_t k;
    size_t n = build_v6(buf, 6, 4444, 8080); /* direct TCP, dst 2002:... */
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);

    /* No v6 tunnel subnet learned (family 0 unset sentinel): gate off,
     * verdict is TCP — this is the case the old v1 guard used to force to
     * RAW unconditionally. */
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "v6 tcp enabled+stream, no tunnel subnet -> tcp");
    ASSERT_EQ_INT(k.ip_version, 6, "v6 tcp key version");
    ASSERT_EQ_INT(k.proto, 6, "v6 tcp key proto");

    /* client_tunnel_subnet[1] (v6) set to 2002::/16 — matches the packet's
     * dst (2002:...) — must be RAW, mirroring the v4 tunnel-subnet
     * carve-out (index 1 = v6, per mqvpn_hybrid_config_t's docstring). */
    ASSERT_EQ_INT(mqvpn_parse_cidr("2002::/16", &pol.client_tunnel_subnet[1]), 0,
                  "v6 tunnel subnet cidr parses");
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 tcp dst in tunnel subnet -> raw");

    /* Outside the v6 subnet (dst 2003:...): unaffected -> TCP. */
    buf[24] = 0x20;
    buf[25] = 0x03;
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "v6 tcp dst outside tunnel subnet -> tcp");

    /* The v6 entry above must not cross-wire the v4 gate — v4 TCP keys off
     * client_tunnel_subnet[0] only. */
    mqvpn_hybrid_config_t pol_v4 = make_pol(1, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_parse_cidr("2002::/16", &pol_v4.client_tunnel_subnet[1]), 0,
                  "v6 tunnel subnet cidr parses (v4-unaffected check)");
    uint8_t vbuf[64];
    size_t vn = build_v4_tcp(vbuf, 2222, 80, 0); /* dst 10.0.0.2 */
    ASSERT_EQ_INT(mqvpn_hybrid_classify(vbuf, vn, &pol_v4, &k), MQVPN_LANE_TCP,
                  "v4 tcp unaffected by v6 tunnel subnet entry");
}

/* base-NH==TCP gate (spec §3.C): mqvpn_parse_l3l4 walks the v6 ext-header
 * chain to reach TCP, so MQVPN_L4_TCP alone doesn't mean lwIP can actually
 * PRE-ACCEPT the flow — only a direct (no ext headers) TCP packet can. */
static void
test_classify_v6_tcp_base_nh_gate(void)
{
    uint8_t buf[80];
    mqvpn_flow_key_t k;
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);

    /* Base NH = Hop-by-Hop (0), TCP reached via the ext header chain -> RAW,
     * even though mqvpn_parse_l3l4 verdicts MQVPN_L4_TCP. */
    size_t n = build_v6_ext_then_tcp(buf, 4444, 8080);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 tcp via ext header (base NH != TCP) -> raw");

    /* Direct v6 TCP (base NH == TCP, no ext headers) is unaffected -> TCP. */
    n = build_v6(buf, 6, 4444, 8080);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "v6 tcp base NH == TCP -> tcp");
}

/* address-class pre-accept-drop guard (spec §3.C rev7/rev8): each case here
 * mirrors a concrete lwIP pre-accept drop site that would otherwise orphan a
 * PENDING_ACCEPT slot, so the classifier routes it RAW instead of laning it. */
static void
test_classify_v6_address_class_ineligible(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);
    uint8_t normal_src[16] = {0x20, 0x01};
    uint8_t normal_dst[16] = {0x20, 0x02};

    /* dst is v4-mapped (::ffff:0:0/96). */
    uint8_t v4mapped[16] = {0};
    v4mapped[10] = 0xff;
    v4mapped[11] = 0xff;
    v4mapped[12] = 10;
    v4mapped[15] = 1;
    size_t n = build_v6_tcp_addrs(buf, normal_src, v4mapped, 4444, 8080);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 tcp v4-mapped dst -> raw");

    /* src is v4-mapped. */
    n = build_v6_tcp_addrs(buf, v4mapped, normal_dst, 4444, 8080);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 tcp v4-mapped src -> raw");

    /* multicast source (src[0] == 0xff). */
    uint8_t mcast[16] = {0xff, 0x02};
    n = build_v6_tcp_addrs(buf, mcast, normal_dst, 4444, 8080);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 tcp multicast src -> raw");

    /* multicast destination (dst[0] == 0xff). */
    n = build_v6_tcp_addrs(buf, normal_src, mcast, 4444, 8080);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 tcp multicast dst -> raw");

    /* unspecified source (:: — all 16 bytes zero). */
    uint8_t unspec[16] = {0};
    n = build_v6_tcp_addrs(buf, unspec, normal_dst, 4444, 8080);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 tcp unspecified src -> raw");

    /* Sanity: a clean, eligible packet still classifies TCP (no false
     * positive from the ineligibility gate). */
    n = build_v6_tcp_addrs(buf, normal_src, normal_dst, 4444, 8080);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "v6 tcp normal addrs -> tcp (no false positive)");
}

static void
test_classify_fragments_and_other_raw(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);

    /* IPv4 first fragment (MF=1) carrying TCP → RAW. */
    size_t n = build_v4_tcp(buf, 2222, 80, 0x2000);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 tcp MF fragment -> raw");

    /* IPv4 non-first fragment (offset != 0) → RAW. */
    n = build_v4_tcp(buf, 2222, 80, 0x0001);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 non-first fragment -> raw");

    /* IPv6 Fragment ext header → RAW. */
    n = build_v6(buf, 44, 0, 0);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 fragment ext -> raw");

    /* ICMPv4 → RAW. */
    n = build_v4_udp(buf, 0, 0, 0, 1);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 icmp -> raw");
}

static void
test_classify_malformed_raw(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);

    /* Truncated IPv4 (10 bytes) → RAW. */
    build_v4_udp(buf, 1111, 443, 0, 17);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, 10, &pol, &k), MQVPN_LANE_RAW,
                  "v4 truncated -> raw");

    /* Truncated v6 ext chain (hopopts header cut off) → RAW. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x60;
    buf[6] = 0; /* next header = Hop-by-Hop, but ext header truncated */
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, 41, &pol, &k), MQVPN_LANE_RAW,
                  "v6 truncated ext chain -> raw");
}

static void
test_classify_null_out_key(void)
{
    uint8_t buf[64];
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);

    /* out_key == NULL must be crash-free for both happy verdicts. */
    size_t n = build_v4_tcp(buf, 2222, 80, 0);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, NULL), MQVPN_LANE_TCP,
                  "tcp with NULL out_key");
    n = build_v4_udp(buf, 1111, 443, 0, 17);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, NULL), MQVPN_LANE_DGRAM,
                  "udp with NULL out_key");
}

static void
test_classify_null_policy(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    size_t n = build_v4_tcp(buf, 2222, 80, 0);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, NULL, &k), MQVPN_LANE_RAW,
                  "v4 tcp NULL policy -> raw (defensive)");
}

/* ── config default / validate ─────────────────────────────────────────── */

static void
test_hybrid_config_default(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    ASSERT_EQ_INT(cfg.enabled, 0, "default enabled");
    ASSERT_EQ_INT(cfg.tcp_mode, MQVPN_HYBRID_TCP_AUTO, "default tcp_mode auto");
    ASSERT_EQ_INT(cfg.tcp_max_flows, 256, "default tcp_max_flows");
    ASSERT_EQ_INT(cfg.tcp_idle_timeout_sec, 300, "default tcp_idle_timeout_sec");
    ASSERT_EQ_INT(cfg.tcp_max_global_flows, MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT,
                  "default tcp_max_global_flows");
}

static void
test_hybrid_config_validate(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(&cfg), 0, "validate default ok");

    cfg.tcp_max_flows = 0;
    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(&cfg), -1, "validate max_flows=0 -> -1");

    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_max_global_flows = 0;
    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(&cfg), -1,
                  "validate max_global_flows=0 -> -1");

    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(NULL), -1, "validate NULL -> -1");

    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_mode = (mqvpn_hybrid_tcp_mode_t)(MQVPN_HYBRID_TCP_AUTO + 1);
    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(&cfg), -1,
                  "validate tcp_mode out of range -> -1");
}

static void
test_hybrid_config_sanitize(void)
{
    mqvpn_hybrid_config_t cfg;
    const char *names[8];

    /* Valid config: nothing reset, nothing named. */
    mqvpn_hybrid_config_default(&cfg);
    ASSERT_EQ_INT(mqvpn_hybrid_config_sanitize(&cfg, names, 8), 0,
                  "sanitize default resets nothing");

    /* One bad scalar: ONLY that field resets — enabled, other fields, and
     * the ACL lists stay exactly as configured (the whole point vs a
     * whole-block default reset, which would fail-open on the deny list). */
    mqvpn_hybrid_config_default(&cfg);
    cfg.enabled = 1;
    cfg.tcp_idle_timeout_sec = 60;
    cfg.tcp_max_flows = 99;
    ASSERT_EQ_INT(mqvpn_parse_cidr("203.0.113.0/24", &cfg.egress_deny[0]), 0,
                  "sanitize test deny cidr parses");
    cfg.n_egress_deny = 1;
    cfg.tcp_max_global_flows = 0; /* the typo */
    ASSERT_EQ_INT(mqvpn_hybrid_config_sanitize(&cfg, names, 8), 1,
                  "sanitize resets exactly one field");
    ASSERT_EQ_INT(strcmp(names[0], "TcpMaxGlobalFlows"), 0,
                  "sanitize names the bad field (INI spelling)");
    ASSERT_EQ_INT((int)cfg.tcp_max_global_flows, MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT,
                  "bad field reset to its default");
    ASSERT_EQ_INT(cfg.enabled, 1, "enabled untouched");
    ASSERT_EQ_INT((int)cfg.tcp_idle_timeout_sec, 60, "valid scalar untouched");
    ASSERT_EQ_INT((int)cfg.tcp_max_flows, 99, "other valid scalar untouched");
    ASSERT_EQ_INT(cfg.n_egress_deny, 1, "deny list untouched");
    ASSERT_EQ_INT(cfg.egress_deny[0].family, 4, "deny entry family untouched");
    ASSERT_EQ_INT(cfg.egress_deny[0].prefix_len, 24, "deny entry prefix_len untouched");
    ASSERT_EQ_INT(cfg.egress_deny[0].net[0], 203, "deny entry net[0] untouched");
    ASSERT_EQ_INT(cfg.egress_deny[0].net[2], 113, "deny entry net[2] untouched");
    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(&cfg), 0,
                  "sanitized config passes validate");

    /* All four checked fields bad at once: all reset, all named. */
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_mode = (mqvpn_hybrid_tcp_mode_t)(MQVPN_HYBRID_TCP_AUTO + 1);
    cfg.tcp_max_flows = 0;
    cfg.tcp_connect_timeout_sec = 0;
    cfg.tcp_max_global_flows = 0;
    ASSERT_EQ_INT(mqvpn_hybrid_config_sanitize(&cfg, names, 8), 4,
                  "sanitize resets all four checked fields");
    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(&cfg), 0,
                  "fully-sanitized config passes validate");

    /* NULL cfg and truncated names[] are safe. */
    ASSERT_EQ_INT(mqvpn_hybrid_config_sanitize(NULL, names, 8), 0, "sanitize NULL -> 0");
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_max_flows = 0;
    cfg.tcp_max_global_flows = 0;
    ASSERT_EQ_INT(mqvpn_hybrid_config_sanitize(&cfg, names, 1), 2,
                  "count exceeds max_names without overflow");
}

int
main(void)
{
    test_classify_udp_always_dgram();
    test_classify_v4_tcp_gates();
    test_classify_tunnel_subnet_tcp_raw();
    test_tunnel_subnet_learn();
    test_tunnel_subnet_learn_v6();
    test_cidr_match_family_strict();
    test_parse_cidr();
    test_classify_v6_tcp_tunnel_subnet();
    test_classify_v6_tcp_base_nh_gate();
    test_classify_v6_address_class_ineligible();
    test_classify_fragments_and_other_raw();
    test_classify_malformed_raw();
    test_classify_null_out_key();
    test_classify_null_policy();

    test_hybrid_config_default();
    test_hybrid_config_validate();
    test_hybrid_config_sanitize();

    fprintf(stderr, "test_classifier: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
