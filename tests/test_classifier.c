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

    /* client_tunnel_subnet set (10.0.0.0/24, the e2e/default pool shape):
     * TCP destined INSIDE it must be RAW even under enabled+stream — the
     * server's egress ACL denies the tunnel subnet unconditionally, so the
     * lane would only ever RST (see classifier.c's comment). */
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_parse_cidr_v4("10.0.0.0/24", &pol.client_tunnel_subnet), 0,
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

    /* mask == 0 (default / not learned): gate off, verdict as before —
     * pinned so the zero-value sentinel can't accidentally match-all
     * ((ip & 0) == 0 would otherwise swallow every destination). */
    pol.client_tunnel_subnet.net = 0;
    pol.client_tunnel_subnet.mask = 0;
    buf[16] = 10;
    buf[17] = 0;
    buf[18] = 0;
    buf[19] = 2; /* dst back inside 10.0.0.0/24 */
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "unset tunnel subnet (mask 0) -> tcp unchanged");

    /* UDP inside the subnet is untouched — the exclusion is a TCP-lane
     * concern only (DGRAM never hits the egress ACL). */
    ASSERT_EQ_INT(mqvpn_parse_cidr_v4("10.0.0.0/24", &pol.client_tunnel_subnet), 0,
                  "tunnel subnet cidr re-parses");
    n = build_v4_udp(buf, 1111, 443, 0, 17); /* dst 10.0.0.2 */
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_DGRAM,
                  "v4 udp dst in tunnel subnet -> dgram unchanged");
}

/* mqvpn_tunnel_subnet_learn: the ADDRESS_ASSIGN → tunnel-subnet widening
 * rule, pinned at host-unit level (the e2e-only alternative would let a
 * "simplification" that honors the wire /32 verbatim pass ctest while
 * silently breaking the tunnel-subnet exclusion in deployment — the /32 is
 * this client's own address, never the pool subnet). */
static void
test_tunnel_subnet_learn(void)
{
    const uint8_t ip[4] = {10, 0, 0, 2};
    mqvpn_cidr_entry_t e;

    /* /32 (today's server behavior): widened to /24, net masked to .0. */
    mqvpn_tunnel_subnet_learn(ip, 32, &e);
    ASSERT_EQ_INT((long long)e.net, 0x0A000000LL, "/32 widens: net 10.0.0.0");
    ASSERT_EQ_INT((long long)e.mask, 0xFFFFFF00LL, "/32 widens: mask /24");

    /* Narrower-than-/24 wire prefixes all widen to the same /24. */
    mqvpn_tunnel_subnet_learn(ip, 28, &e);
    ASSERT_EQ_INT((long long)e.mask, 0xFFFFFF00LL, "/28 widens: mask /24");
    ASSERT_EQ_INT((long long)e.net, 0x0A000000LL, "/28 widens: net 10.0.0.0");

    /* /24 exactly: honored as-is. */
    mqvpn_tunnel_subnet_learn(ip, 24, &e);
    ASSERT_EQ_INT((long long)e.mask, 0xFFFFFF00LL, "/24 honored: mask /24");
    ASSERT_EQ_INT((long long)e.net, 0x0A000000LL, "/24 honored: net 10.0.0.0");

    /* Wider than /24: honored as-is (a /16 pool signaled on the wire must
     * not be narrowed back to /24). */
    const uint8_t ip16[4] = {10, 0, 5, 2};
    mqvpn_tunnel_subnet_learn(ip16, 16, &e);
    ASSERT_EQ_INT((long long)e.mask, 0xFFFF0000LL, "/16 honored: mask /16");
    ASSERT_EQ_INT((long long)e.net, 0x0A000000LL, "/16 honored: net 10.0.0.0");

    /* Degenerate prefix <= 0: mask 0 — the "not learned" sentinel that
     * keeps the classifier gate OFF (its mask != 0 guard). */
    mqvpn_tunnel_subnet_learn(ip, 0, &e);
    ASSERT_EQ_INT((long long)e.mask, 0LL, "/0 -> mask 0 sentinel");
    mqvpn_tunnel_subnet_learn(ip, -1, &e);
    ASSERT_EQ_INT((long long)e.mask, 0LL, "negative prefix -> mask 0 sentinel");
}

/* mqvpn_cidr_match: the shared matcher (classifier gate + egress ACL). */
static void
test_cidr_match(void)
{
    mqvpn_cidr_entry_t e;
    ASSERT_EQ_INT(mqvpn_parse_cidr_v4("10.0.0.0/24", &e), 0, "match cidr parses");
    ASSERT_EQ_INT(mqvpn_cidr_match(&e, 0x0A000001u), 1, "10.0.0.1 in 10.0.0.0/24");
    ASSERT_EQ_INT(mqvpn_cidr_match(&e, 0x0A000100u), 0, "10.0.1.0 not in /24");

    /* mask == 0 matches everything — the documented "0.0.0.0/0" ACL-row
     * semantic; sentinel users must gate on mask != 0 themselves. */
    e.net = 0;
    e.mask = 0;
    ASSERT_EQ_INT(mqvpn_cidr_match(&e, 0xC0A80101u), 1, "mask 0 matches all");
}

static void
test_classify_v6_tcp_raw_v1(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    size_t n = build_v6(buf, 6, 4444, 8080);
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 tcp enabled+stream -> raw (v1)");
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
    ASSERT_EQ_INT(mqvpn_parse_cidr_v4("203.0.113.0/24", &cfg.egress_deny[0]), 0,
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
    ASSERT_EQ_INT((int)cfg.egress_deny[0].net, (int)0xCB007100, "deny entry untouched");
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
    test_cidr_match();
    test_classify_v6_tcp_raw_v1();
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
