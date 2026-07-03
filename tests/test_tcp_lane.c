// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_tcp_lane.c — unit tests for the client-side TCP-lane flow table
 * skeleton (H2b): sticky-lane lookup, SYN-time commit, cap enforcement.
 *
 * Note on the #include: same idiom as test_reorder_rx.c — tcp_lane.c's
 * internal struct mqvpn_tcp_lane/mqvpn_tcp_flow_t layout is not part of the
 * public header, so the TU is pulled in directly rather than compiled as a
 * separate CMake source (do NOT also list src/hybrid/tcp_lane.c in
 * CMakeLists.txt — that would compile the TU twice).
 *
 * Build: see CMakeLists.txt (test_tcp_lane target). Gated on
 * MQVPN_HYBRID_TCP_LANE_BUILD and linked against lwip_core since Task 8:
 * the accept callback calls real lwIP (tcp_arg/tcp_recv/...). This TU also
 * provides the cli_tcp_lane_open_stream stub — the real one lives in
 * mqvpn_client.c, which is not linked here.
 */
/* Shrink the sticky-RAW marker cap (production default 4096) so the
 * marker-cap branch is testable without 4096 inserts. Must precede the
 * #include of the TU. */
#define TCP_LANE_RAW_MARKER_CAP 4u
#include "hybrid/tcp_lane.c"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

/* ─── cli_tcp_lane_open_stream stub (real impl: mqvpn_client.c) ─── */

static int g_open_stream_calls;
static void *g_open_stream_flow;
static mqvpn_flow_key_t g_open_stream_key;

void
cli_tcp_lane_open_stream(void *client_ctx, void *flow_handle, const mqvpn_flow_key_t *key)
{
    (void)client_ctx;
    g_open_stream_calls++;
    g_open_stream_flow = flow_handle;
    g_open_stream_key = *key;
}

static uint64_t
fake_clock(void *ctx)
{
    (void)ctx;
    return 12345;
}

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

#define ASSERT_TRUE(cond, msg)                   \
    do {                                         \
        if (cond) {                              \
            g_pass++;                            \
        } else {                                 \
            g_fail++;                            \
            fprintf(stderr, "FAIL [%s]\n", msg); \
        }                                        \
    } while (0)

static mqvpn_flow_key_t
make_key(uint16_t src_port, uint16_t dst_port)
{
    mqvpn_flow_key_t k;
    memset(&k, 0, sizeof(k));
    k.ip_version = 4;
    k.proto = 6; /* TCP */
    k.src_port = src_port;
    k.dst_port = dst_port;
    k.src_ip[0] = 10;
    k.src_ip[1] = 0;
    k.src_ip[2] = 0;
    k.src_ip[3] = 1;
    k.dst_ip[0] = 10;
    k.dst_ip[1] = 0;
    k.dst_ip[2] = 0;
    k.dst_ip[3] = 2;
    return k;
}

static void
test_new_flow_and_lookup(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xabcdULL, NULL, NULL, NULL);
    ASSERT_TRUE(lane != NULL, "lane_new succeeds");

    mqvpn_flow_key_t k = make_key(4000, 80);
    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw), 0,
                  "lookup miss on brand-new flow");

    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 1), 0, "on_syn to_tcp commits");

    out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw), 1,
                  "lookup hit after commit");
    ASSERT_EQ_INT(out_raw, 0, "committed flow is not sticky-RAW");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 1, "flows_active == 1");
    ASSERT_EQ_INT(stats.flows_total, 1, "flows_total == 1");

    /* Duplicate commit is a caller bug (protocol: lookup-then-commit) —
     * refused, counted in flows_rejected_other, no shadowing insert. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 1), -1, "duplicate on_syn refused");
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_rejected_other, 1,
                  "duplicate counted in flows_rejected_other");
    ASSERT_EQ_INT(stats.flows_total, 1, "no shadowing duplicate inserted");

    mqvpn_tcp_lane_free(lane);
}

static void
test_sticky_raw(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x1234ULL, NULL, NULL, NULL);
    ASSERT_TRUE(lane != NULL, "lane_new succeeds");

    mqvpn_flow_key_t k = make_key(4001, 443);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0), 0,
                  "on_syn to_tcp=0 records sticky-RAW");

    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw), 1,
                  "lookup hit after sticky-RAW commit");
    ASSERT_EQ_INT(out_raw, 1, "sticky-RAW flow reports is_raw");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 0, "sticky-RAW does not count as active");
    ASSERT_EQ_INT(stats.flows_total, 1, "flows_total == 1");

    mqvpn_tcp_lane_free(lane);
}

static void
test_cap_rejection(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_max_flows = 1;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x5678ULL, NULL, NULL, NULL);
    ASSERT_TRUE(lane != NULL, "lane_new succeeds");

    mqvpn_flow_key_t k1 = make_key(5000, 80);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k1, 1), 0, "first on_syn succeeds");

    mqvpn_flow_key_t k2 = make_key(5001, 80);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k2, 1), -1,
                  "second on_syn rejected at cap");
    /* Rejection means NO insertion: the rejected key must stay absent. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k2, NULL), 0,
                  "rejected key not inserted (lookup miss)");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_rejected_cap, 1, "flows_rejected_cap == 1");

    /* Split-cap: a sticky-RAW marker is NOT blocked by the (full) TCP flow
     * cap and does not count as a TCP-lane rejection. */
    mqvpn_flow_key_t k3 = make_key(5002, 80);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k3, 0), 0,
                  "sticky-RAW marker succeeds at full tcp flow cap");
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_rejected_cap, 1,
                  "marker insert did not bump flows_rejected_cap");
    ASSERT_EQ_INT(stats.raw_markers_active, 1, "raw_markers_active == 1");

    mqvpn_tcp_lane_free(lane);
}

static void
test_markers_dont_consume_tcp_budget(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_max_flows = 1;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x9abcULL, NULL, NULL, NULL);
    ASSERT_TRUE(lane != NULL, "lane_new succeeds");

    /* Fill the (test-shrunk) marker cap with sticky-RAW markers first... */
    for (uint16_t i = 0; i < TCP_LANE_RAW_MARKER_CAP; i++) {
        mqvpn_flow_key_t k = make_key((uint16_t)(6000 + i), 80);
        ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0), 0,
                      "sticky-RAW marker succeeds");
    }

    /* ...then a TCP-lane flow still fits: markers spent none of the budget. */
    mqvpn_flow_key_t kt = make_key(7000, 443);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &kt, 1), 0,
                  "to_tcp still succeeds after markers (separate budgets)");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 1, "flows_active == 1");
    ASSERT_EQ_INT(stats.raw_markers_active, TCP_LANE_RAW_MARKER_CAP,
                  "raw_markers_active == marker cap");
    ASSERT_EQ_INT(stats.flows_rejected_cap, 0, "no cap rejections");
    ASSERT_EQ_INT(stats.flows_total, TCP_LANE_RAW_MARKER_CAP + 1,
                  "flows_total counts both kinds");

    mqvpn_tcp_lane_free(lane);
}

static void
test_marker_cap(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg); /* tcp_max_flows = 256 (not the limit) */
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xdef0ULL, NULL, NULL, NULL);
    ASSERT_TRUE(lane != NULL, "lane_new succeeds");

    /* Fill the (test-shrunk) marker cap. */
    for (uint16_t i = 0; i < TCP_LANE_RAW_MARKER_CAP; i++) {
        mqvpn_flow_key_t k = make_key((uint16_t)(8000 + i), 80);
        ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0), 0, "marker succeeds below cap");
    }

    /* Next marker is refused: -1, silent (no flows_rejected_cap), no insert. */
    mqvpn_flow_key_t kx = make_key(8999, 80);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &kx, 0), -1,
                  "marker rejected at marker cap");
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &kx, NULL), 0,
                  "rejected marker key not inserted (lookup miss)");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_rejected_cap, 0,
                  "marker-cap hit is not a TCP-lane rejection");
    ASSERT_EQ_INT(stats.raw_markers_active, TCP_LANE_RAW_MARKER_CAP,
                  "raw_markers_active stays at cap");

    /* TCP-lane commits are unaffected by the full marker table. */
    mqvpn_flow_key_t kt = make_key(9000, 443);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &kt, 1), 0,
                  "to_tcp still succeeds at full marker cap");

    mqvpn_tcp_lane_free(lane);
}

/* Pin the SYN-time ↔ accept-time key correspondence: the key the accept
 * callback rebuilds from the pcb (host-order ports, network-order u32 IPs)
 * must be byte-identical to the key mqvpn_hybrid_classify built from the
 * raw SYN — a mismatch means find_flow misses and EVERY connection is
 * refused. The classifier runs on a crafted SYN; the pcb is faked with the
 * field values lwIP's tcp_listen_input would set (local/remote ip copied
 * network-order from the IP header, ports ntohs'd to host order). */
static void
test_accept_key_correspondence(void)
{
    /* SYN 10.0.0.1:4000 -> 93.184.216.34:80 */
    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45; /* v4, IHL 5 */
    pkt[2] = 0;
    pkt[3] = 40;  /* total length */
    pkt[8] = 64;  /* TTL */
    pkt[9] = 6;   /* TCP */
    pkt[12] = 10; /* src 10.0.0.1 */
    pkt[13] = 0;
    pkt[14] = 0;
    pkt[15] = 1;
    pkt[16] = 93; /* dst 93.184.216.34 */
    pkt[17] = 184;
    pkt[18] = 216;
    pkt[19] = 34;
    pkt[20] = 0x0F; /* src port 4000 */
    pkt[21] = 0xA0;
    pkt[22] = 0; /* dst port 80 */
    pkt[23] = 80;
    pkt[32] = 0x50; /* data offset 5 */
    pkt[33] = 0x02; /* SYN */

    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.enabled = 1;
    cfg.tcp_mode = MQVPN_HYBRID_TCP_STREAM;

    mqvpn_flow_key_t key;
    memset(&key, 0, sizeof(key));
    ASSERT_EQ_INT(mqvpn_hybrid_classify(pkt, sizeof(pkt), &cfg, &key), MQVPN_LANE_TCP,
                  "crafted SYN classifies to the TCP lane");
    ASSERT_TRUE(mqvpn_tcp_syn_flag(pkt, sizeof(pkt)), "crafted SYN is flow-starting");

    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x4242ULL, NULL, fake_clock, NULL);
    ASSERT_TRUE(lane != NULL, "lane_new succeeds");
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &key, 1), 0, "SYN-time commit");

    /* Fake accepted pcb, fields as tcp_listen_input sets them: local/remote
     * ip ip_addr_copy'd from the IP header (network order), ports assigned
     * from the already-ntohs'd TCP header (host order). ESTABLISHED so the
     * tcp_recv/tcp_sent/tcp_err setters' state asserts pass. */
    struct tcp_pcb pcb;
    memset(&pcb, 0, sizeof(pcb));
    pcb.state = ESTABLISHED;
    IP4_ADDR(&pcb.local_ip, 93, 184, 216, 34);
    IP4_ADDR(&pcb.remote_ip, 10, 0, 0, 1);
    pcb.local_port = 80;
    pcb.remote_port = 4000;

    g_open_stream_calls = 0;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lwip_accept(lane, &pcb, ERR_OK), ERR_OK,
                  "accept matches the SYN-committed flow");
    ASSERT_EQ_INT(g_open_stream_calls, 1, "open_stream called exactly once");
    ASSERT_TRUE(mqvpn_flow_key_eq(&g_open_stream_key, &key),
                "accept-rebuilt key is byte-identical to the classifier key");
    ASSERT_TRUE(g_open_stream_flow == pcb.callback_arg,
                "pcb arg wired to the flow handle");

    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)g_open_stream_flow;
    ASSERT_EQ_INT(f->state, TCP_FLOW_PENDING_STREAM, "flow is PENDING_STREAM");
    ASSERT_TRUE(f->pcb == &pcb, "flow holds the pcb");
    ASSERT_EQ_INT(f->target_port, 80, "target_port from pcb local_port");
    ASSERT_TRUE(ip4_addr_eq(&f->target_ip, &pcb.local_ip), "target_ip from pcb local_ip");
    ASSERT_EQ_INT(f->last_activity_us, 12345, "last_activity stamped via clock_fn");

    /* bind (mqvpn_client.c calls this after opening the H3 request) */
    int fake_req, fake_stream;
    mqvpn_tcp_lane_bind_h3_request(f, &fake_req, &fake_stream);
    ASSERT_EQ_INT(f->state, TCP_FLOW_ACTIVE, "bind moves flow to ACTIVE");
    ASSERT_TRUE(f->h3_request == &fake_req && f->stream == &fake_stream,
                "bind stores the opaque request/stream");

    /* Unknown pcb (no SYN-time commit) → refused, no stream open. The stub
     * pcb is safe here: the callback returns non-ERR_OK WITHOUT touching the
     * pcb (vendored tcp_in.c aborts it after the callback returns). */
    struct tcp_pcb stray;
    memset(&stray, 0, sizeof(stray));
    stray.state = ESTABLISHED;
    IP4_ADDR(&stray.local_ip, 93, 184, 216, 34);
    IP4_ADDR(&stray.remote_ip, 10, 0, 0, 1);
    stray.local_port = 80;
    stray.remote_port = 4001; /* never committed */
    ASSERT_TRUE(mqvpn_tcp_lane_lwip_accept(lane, &stray, ERR_OK) != ERR_OK,
                "untracked pcb refused");
    ASSERT_EQ_INT(g_open_stream_calls, 1, "no stream open for untracked pcb");

    /* pcb-pool exhaustion shape: (NULL, ERR_MEM) must be tolerated. */
    ASSERT_TRUE(mqvpn_tcp_lane_lwip_accept(lane, NULL, ERR_MEM) != ERR_OK,
                "NULL pcb (pool exhaustion) tolerated");
    ASSERT_EQ_INT(g_open_stream_calls, 1, "no stream open for NULL pcb");

    mqvpn_tcp_lane_free(lane);
}

int
main(void)
{
    test_new_flow_and_lookup();
    test_sticky_raw();
    test_cap_rejection();
    test_markers_dont_consume_tcp_budget();
    test_marker_cap();
    test_accept_key_correspondence();

    fprintf(stderr, "test_tcp_lane: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
