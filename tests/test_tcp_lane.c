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

/* Task 10: observe tcp_recved via tcp_lane.c's compile-time substitution
 * hook — calling the REAL tcp_recved on the stack-fake pcbs below would
 * touch rcv_wnd internals (and assert). Must precede the #include; the hook
 * function is defined after it (forward declaration suffices — the macro
 * only expands inside tcp_lane.c's bodies). */
struct tcp_pcb;
static void test_recved_hook(struct tcp_pcb *pcb, unsigned int len);
#define MQVPN_TCP_LANE_TEST_RECVED(pcb, len) test_recved_hook((pcb), (len))

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

/* ─── tcp_recved observability (via MQVPN_TCP_LANE_TEST_RECVED) ─── */

static int g_recved_calls;
static uint32_t g_recved_total;

static void
test_recved_hook(struct tcp_pcb *pcb, unsigned int len)
{
    (void)pcb;
    g_recved_calls++;
    g_recved_total += len;
}

/* ─── cli_tcp_lane_h3_send test double (real impl: mqvpn_client.c) ───
 *
 * xqc-free per the one-way boundary: tcp_lane.c calls this normalized
 * helper, never xquic itself. A small per-call return script drives
 * EAGAIN/partial-accept scenarios (script exhausted => accept everything);
 * every accepted byte is appended to g_h3_capture so tests can assert the
 * EXACT relayed byte sequence (no duplicates, no loss, FIFO order). */

#define H3_SCRIPT_MAX 16
static ssize_t g_h3_script[H3_SCRIPT_MAX];
static int g_h3_script_len, g_h3_script_pos;
static int g_h3_send_calls;
static int g_h3_fin_attempts; /* calls with fin=1 */
static int g_h3_fin_sent;     /* a fin=1 call returned >= 0 */
static size_t g_h3_fin_len;   /* len of the last fin=1 call */
static uint8_t g_h3_capture[512 * 1024];
static size_t g_h3_capture_len;

/* Ordered call log — lets tests pin ORDERING (e.g. "the FIN call happens
 * strictly after every data call", not just "both eventually happened"). */
#define H3_LOG_MAX 64
typedef struct {
    size_t len;
    int fin;
    ssize_t ret;
} h3_call_t;
static h3_call_t g_h3_log[H3_LOG_MAX];
static int g_h3_log_len;

ssize_t
cli_tcp_lane_h3_send(void *h3_request, const uint8_t *buf, size_t len, int fin)
{
    (void)h3_request;
    g_h3_send_calls++;
    ssize_t ret = (ssize_t)len; /* default: accept everything */
    if (g_h3_script_pos < g_h3_script_len) {
        ret = g_h3_script[g_h3_script_pos++];
    }
    if (ret > (ssize_t)len) {
        ret = (ssize_t)len;
    }
    if (ret > 0 && buf) {
        size_t room = sizeof(g_h3_capture) - g_h3_capture_len;
        size_t n = ((size_t)ret <= room) ? (size_t)ret : room;
        memcpy(g_h3_capture + g_h3_capture_len, buf, n);
        g_h3_capture_len += n;
    }
    if (fin) {
        g_h3_fin_attempts++;
        g_h3_fin_len = len;
        if (ret >= 0) {
            g_h3_fin_sent = 1;
        }
    }
    if (g_h3_log_len < H3_LOG_MAX) {
        g_h3_log[g_h3_log_len].len = len;
        g_h3_log[g_h3_log_len].fin = fin;
        g_h3_log[g_h3_log_len].ret = ret;
        g_h3_log_len++;
    }
    return ret;
}

static void
h3_script_clear(void)
{
    g_h3_script_len = 0;
    g_h3_script_pos = 0;
}

static void
h3_script_push(ssize_t v)
{
    g_h3_script[g_h3_script_len++] = v;
}

/* ─── settable fake clock (carry-over: observe established re-stamping) ─── */

static uint64_t g_fake_now = 12345;

static uint64_t
fake_clock(void *ctx)
{
    (void)ctx;
    return g_fake_now;
}

/* ─── relay fixtures ─── */

/* Rolling byte pattern shared by every pbuf a test creates; mirrored into
 * g_expected so `capture == expected` proves exact-sequence relay. */
static uint8_t g_expected[512 * 1024];
static size_t g_expected_len;
static uint8_t g_seq;

static void
relay_reset(void)
{
    h3_script_clear();
    g_h3_send_calls = 0;
    g_h3_fin_attempts = 0;
    g_h3_fin_sent = 0;
    g_h3_fin_len = 0;
    g_h3_capture_len = 0;
    g_h3_log_len = 0;
    g_recved_calls = 0;
    g_recved_total = 0;
    g_expected_len = 0;
    g_seq = 0;
    g_fake_now = 12345;
}

/* Real PBUF_RAM pbuf (MEM_LIBC_MALLOC=1 => plain malloc; no lwip_init or
 * pool init needed), filled with the rolling pattern. */
static struct pbuf *
mk_pbuf(uint16_t len)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    if (!p) {
        return NULL;
    }
    uint8_t *d = (uint8_t *)p->payload;
    for (uint16_t i = 0; i < len; i++) {
        d[i] = g_seq;
        g_expected[g_expected_len++] = g_seq;
        g_seq++;
    }
    return p;
}

/* Chain n segments (via pbuf_cat, which adjusts tot_len down the chain) into
 * ONE multi-pbuf chain — exercises tcp_lane_uplink_send_from's
 * pbuf_copy_partial slicing path (p->next != NULL), unlike mk_pbuf's single
 * contiguous PBUF_RAM allocation. Each segment's bytes still land in
 * g_expected via mk_pbuf, so the chain's concatenated payload is a
 * contiguous run of the rolling pattern. */
static struct pbuf *
mk_pbuf_chain(const uint16_t *seg_lens, int n)
{
    struct pbuf *head = NULL;
    for (int i = 0; i < n; i++) {
        struct pbuf *seg = mk_pbuf(seg_lens[i]);
        if (!seg) {
            if (head) {
                pbuf_free(head);
            }
            return NULL;
        }
        if (!head) {
            head = seg;
        } else {
            pbuf_cat(head, seg);
        }
    }
    return head;
}

/* SYN-commit + fake-pcb accept + bind (+ optional 2xx establish) — the same
 * dance test_accept_key_correspondence pins, packaged for the relay tests.
 * pcb is caller-owned stack memory: callers must NULL f->pcb before
 * lane_free (the teardown loop would tcp_abort a pool-foreign pcb). */
static mqvpn_tcp_flow_t *
setup_flow(mqvpn_tcp_lane_t *lane, struct tcp_pcb *pcb, uint16_t src_port, void *req,
           void *stream, int establish)
{
    mqvpn_flow_key_t k;
    memset(&k, 0, sizeof(k));
    k.ip_version = 4;
    k.proto = 6; /* TCP */
    k.src_port = src_port;
    k.dst_port = 80;
    k.src_ip[0] = 10;
    k.src_ip[3] = 1;
    k.dst_ip[0] = 93;
    k.dst_ip[1] = 184;
    k.dst_ip[2] = 216;
    k.dst_ip[3] = 34;
    if (mqvpn_tcp_lane_on_syn(lane, &k, 1) != 0) {
        return NULL;
    }
    memset(pcb, 0, sizeof(*pcb));
    pcb->state = ESTABLISHED;
    IP4_ADDR(&pcb->local_ip, 93, 184, 216, 34);
    IP4_ADDR(&pcb->remote_ip, 10, 0, 0, 1);
    pcb->local_port = 80;
    pcb->remote_port = src_port;
    if (mqvpn_tcp_lane_lwip_accept(lane, pcb, ERR_OK) != ERR_OK) {
        return NULL;
    }
    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)g_open_stream_flow;
    mqvpn_tcp_lane_bind_h3_request(f, req, stream);
    if (establish) {
        mqvpn_tcp_lane_on_stream_established(lane, stream);
    }
    return f;
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
    relay_reset();
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

    /* bind (mqvpn_client.c calls this after opening the H3 request). Task 9:
     * bind alone no longer activates the flow — it stays PENDING_STREAM
     * until the H3 response gate (on_stream_established/_rejected) fires. */
    int fake_req, fake_stream;
    mqvpn_tcp_lane_bind_h3_request(f, &fake_req, &fake_stream);
    ASSERT_EQ_INT(f->state, TCP_FLOW_PENDING_STREAM,
                  "bind alone stays PENDING_STREAM (2xx gate not yet fired)");
    ASSERT_TRUE(f->h3_request == &fake_req && f->stream == &fake_stream,
                "bind stores the opaque request/stream");

    /* Flow-not-found tolerance: a stream pointer that matches no bound flow
     * must no-op silently (stream may outlive the flow after a future
     * Task 12/13 removal), not crash or touch an unrelated flow. */
    int unrelated_stream;
    mqvpn_tcp_lane_on_stream_established(lane, &unrelated_stream);
    ASSERT_EQ_INT(
        f->state, TCP_FLOW_PENDING_STREAM,
        "on_stream_established on unknown stream leaves the real flow untouched");
    mqvpn_tcp_lane_on_stream_rejected(lane, &unrelated_stream);
    ASSERT_EQ_INT(f->state, TCP_FLOW_PENDING_STREAM,
                  "on_stream_rejected on unknown stream leaves the real flow untouched");
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_h3_writable(lane, &unrelated_stream), 0,
                  "on_h3_writable on unknown stream is a harmless no-op");
    /* NULL lane/stream must also be tolerated (defensive callers). */
    mqvpn_tcp_lane_on_stream_established(NULL, &fake_stream);
    mqvpn_tcp_lane_on_stream_established(lane, NULL);
    mqvpn_tcp_lane_on_stream_rejected(NULL, &fake_stream);
    mqvpn_tcp_lane_on_stream_rejected(lane, NULL);
    ASSERT_EQ_INT(f->state, TCP_FLOW_PENDING_STREAM,
                  "NULL lane/stream args are tolerated, no state change");

    /* 2xx response: PENDING_STREAM -> ACTIVE, last_activity re-stamped via
     * clock_fn. The clock is settable (carry-over from Task 9, which
     * couldn't observe the re-stamp): advance it so the re-stamp is
     * distinguishable from the accept-time stamp. */
    g_fake_now = 67890;
    mqvpn_tcp_lane_on_stream_established(lane, &fake_stream);
    ASSERT_EQ_INT(f->state, TCP_FLOW_ACTIVE,
                  "on_stream_established moves flow to ACTIVE");
    ASSERT_EQ_INT(f->last_activity_us, 67890, "last_activity re-stamped on activation");
    g_fake_now = 12345;

    /* Non-2xx response on a second bound flow: PENDING_STREAM -> CLOSING.
     * Key must match the pcb2 5-tuple below (10.0.0.1:4002 -> 93.184.216.34:80
     * — the same addresses test_accept_key_correspondence's first flow uses,
     * NOT make_key()'s generic 10.0.0.1/10.0.0.2), since the accept callback
     * rebuilds the key from the pcb's local/remote ip/port. */
    mqvpn_flow_key_t key2;
    memset(&key2, 0, sizeof(key2));
    key2.ip_version = 4;
    key2.proto = 6; /* TCP */
    key2.src_port = 4002;
    key2.dst_port = 80;
    key2.src_ip[0] = 10;
    key2.src_ip[1] = 0;
    key2.src_ip[2] = 0;
    key2.src_ip[3] = 1;
    key2.dst_ip[0] = 93;
    key2.dst_ip[1] = 184;
    key2.dst_ip[2] = 216;
    key2.dst_ip[3] = 34;
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &key2, 1), 0,
                  "second flow SYN-time commit");
    struct tcp_pcb pcb2;
    memset(&pcb2, 0, sizeof(pcb2));
    pcb2.state = ESTABLISHED;
    IP4_ADDR(&pcb2.local_ip, 93, 184, 216, 34);
    IP4_ADDR(&pcb2.remote_ip, 10, 0, 0, 1);
    pcb2.local_port = 80;
    pcb2.remote_port = 4002;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lwip_accept(lane, &pcb2, ERR_OK), ERR_OK,
                  "second flow accepted");
    mqvpn_tcp_flow_t *f2 = (mqvpn_tcp_flow_t *)g_open_stream_flow;
    int fake_req2, fake_stream2;
    mqvpn_tcp_lane_bind_h3_request(f2, &fake_req2, &fake_stream2);
    ASSERT_EQ_INT(f2->state, TCP_FLOW_PENDING_STREAM,
                  "second flow bound, still PENDING_STREAM");
    mqvpn_tcp_lane_on_stream_rejected(lane, &fake_stream2);
    ASSERT_EQ_INT(f2->state, TCP_FLOW_CLOSING,
                  "on_stream_rejected moves flow to CLOSING");
    /* Rejecting/activating an unrelated stream must not disturb this flow. */
    ASSERT_EQ_INT(f->state, TCP_FLOW_ACTIVE,
                  "first flow unaffected by second flow's rejection");
    f2->pcb = NULL; /* stack-fake pcb; detach before lane_free (see below) */

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
    ASSERT_EQ_INT(g_open_stream_calls, 2, "no stream open for untracked pcb");

    /* pcb-pool exhaustion shape: (NULL, ERR_MEM) must be tolerated. */
    ASSERT_TRUE(mqvpn_tcp_lane_lwip_accept(lane, NULL, ERR_MEM) != ERR_OK,
                "NULL pcb (pool exhaustion) tolerated");
    ASSERT_EQ_INT(g_open_stream_calls, 2, "no stream open for NULL pcb");

    /* The pcb above is a stack fake — lane_free's abort loop would
     * tcp_abort → tcp_free (memp_free) it and corrupt lwIP's pools, so
     * detach it first. The abort loop itself needs a REAL pool pcb (full
     * checksummed handshake through lwip_ctx) to exercise — deliberately
     * NOT faked here; covered by the e2e checkpoints. */
    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

/* ─── Task 10: uplink relay (lwIP recv -> H3 send_body) ───
 *
 * Each test builds its own lane + one bound flow via setup_flow(), drives
 * mqvpn_tcp_lane_on_lwip_recv/_on_h3_writable/_on_stream_established
 * directly (same-TU static calls — no lwIP callback indirection needed),
 * and asserts against the cli_tcp_lane_h3_send test double's capture/log
 * plus the tcp_recved observability hook. relay_reset() clears all of that
 * shared test-double state; it must run before every test that touches the
 * relay path. */

static void
test_relay_full_accept(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x1111ULL, NULL, fake_clock, NULL);
    ASSERT_TRUE(lane != NULL, "lane_new succeeds");

    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 5100, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow set up and established");
    ASSERT_EQ_INT(f->state, TCP_FLOW_ACTIVE, "flow is ACTIVE");

    struct pbuf *p = mk_pbuf(500);
    ASSERT_TRUE(p != NULL, "pbuf alloc");
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p, ERR_OK), ERR_OK,
                  "recv accepted");

    ASSERT_EQ_INT(g_h3_send_calls, 1, "one h3 send call (full accept, no retry needed)");
    ASSERT_EQ_INT(g_h3_capture_len, 500, "all 500 bytes relayed");
    ASSERT_TRUE(memcmp(g_h3_capture, g_expected, 500) == 0,
                "relayed bytes match the exact source sequence");
    ASSERT_EQ_INT(g_recved_calls, 1, "tcp_recved called once, immediately");
    ASSERT_EQ_INT(g_recved_total, 500, "tcp_recved(500) — full accept, no withholding");
    ASSERT_EQ_INT(f->uplink_withheld, 0, "not withheld");
    ASSERT_EQ_INT(f->uplink_queued_bytes, 0, "queue empty after full accept");
    ASSERT_TRUE(f->uplink_q_head == NULL, "no queued node");

    f->pcb = NULL; /* stack-fake pcb; detach before lane_free */
    mqvpn_tcp_lane_free(lane);
}

static void
test_relay_eagain_then_writable_flush(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x2222ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 5200, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    h3_script_push(MQVPN_TCP_LANE_H3_SEND_AGAIN);
    struct pbuf *p = mk_pbuf(1000);
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p, ERR_OK);

    ASSERT_EQ_INT(g_h3_send_calls, 1, "one send attempt (EAGAIN)");
    ASSERT_EQ_INT(g_h3_capture_len, 0, "no bytes captured on EAGAIN");
    ASSERT_EQ_INT(g_recved_calls, 0, "tcp_recved withheld on EAGAIN");
    ASSERT_EQ_INT(f->uplink_withheld, 1,
                  "withheld set (backpressure signal, no threshold)");
    ASSERT_EQ_INT(f->uplink_queued_bytes, 1000, "whole pbuf stashed at offset 0");
    ASSERT_EQ_INT(f->uplink_withheld_recved, 1000,
                  "deferred-recved total tracks the pbuf");

    /* Writable notify; script now exhausted -> default full accept. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_h3_writable(lane, &fake_stream), 0,
                  "on_h3_writable returns 0");

    ASSERT_EQ_INT(g_h3_send_calls, 2, "retry attempt sent");
    ASSERT_EQ_INT(g_h3_capture_len, 1000, "all bytes now relayed");
    ASSERT_TRUE(memcmp(g_h3_capture, g_expected, 1000) == 0,
                "exact byte sequence, no dup");
    ASSERT_EQ_INT(f->uplink_withheld, 0, "withheld cleared below low-water");
    ASSERT_EQ_INT(f->uplink_queued_bytes, 0, "queue drained");
    ASSERT_EQ_INT(g_recved_calls, 1, "single batched tcp_recved on resume");
    ASSERT_EQ_INT(g_recved_total, 1000, "recved(withheld total)");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_relay_partial_accept(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x3333ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 5300, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    h3_script_push(300); /* partial accept: only 300 of 1000 bytes */
    struct pbuf *p = mk_pbuf(1000);
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p, ERR_OK);

    ASSERT_EQ_INT(g_h3_capture_len, 300, "only the accepted prefix relayed so far");
    ASSERT_TRUE(memcmp(g_h3_capture, g_expected, 300) == 0,
                "accepted prefix matches source");
    ASSERT_TRUE(f->uplink_q_head != NULL, "node stashed for the unsent remainder");
    ASSERT_EQ_INT(f->uplink_q_head->offset, 300,
                  "resume offset == bytes already accepted");
    ASSERT_EQ_INT(f->uplink_queued_bytes, 700, "queued_bytes == unsent remainder only");
    ASSERT_EQ_INT(g_recved_calls, 0, "withheld (backpressure signal, no threshold)");

    /* Writable notify: script exhausted -> full accept of the remaining 700. */
    mqvpn_tcp_lane_on_h3_writable(lane, &fake_stream);

    ASSERT_EQ_INT(g_h3_capture_len, 1000, "full 1000 bytes relayed, no duplication");
    ASSERT_TRUE(memcmp(g_h3_capture, g_expected, 1000) == 0,
                "EXACT byte sequence: prefix + resumed remainder, no dup/gap");
    ASSERT_TRUE(f->uplink_q_head == NULL, "queue drained");
    ASSERT_EQ_INT(g_recved_calls, 1, "batched recved on resume");
    ASSERT_EQ_INT(g_recved_total, 1000, "recved covers the whole original pbuf");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_relay_pending_stream_buffering(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x4444ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f =
        setup_flow(lane, &pcb, 5400, &fake_req, &fake_stream, 0 /* not established */);
    ASSERT_TRUE(f != NULL, "flow bound, PENDING_STREAM");
    ASSERT_EQ_INT(f->state, TCP_FLOW_PENDING_STREAM, "still PENDING_STREAM");

    struct pbuf *p1 = mk_pbuf(2000);
    struct pbuf *p2 = mk_pbuf(1500);
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p1, ERR_OK);
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p2, ERR_OK);

    ASSERT_EQ_INT(g_h3_send_calls, 0, "nothing sent before the 2xx gate opens");
    ASSERT_EQ_INT(f->uplink_queued_bytes, 3500, "both pbufs buffered");
    ASSERT_EQ_INT(f->uplink_withheld, 0, "well below high-water, not withheld");
    ASSERT_EQ_INT(g_recved_calls, 2,
                  "recved not withheld below high-water (already-ACKed data)");
    ASSERT_EQ_INT(g_recved_total, 3500, "both recved immediately");

    /* 2xx arrives: PENDING_STREAM -> ACTIVE, flush drains the buffered queue
     * IN ORDER. */
    mqvpn_tcp_lane_on_stream_established(lane, &fake_stream);

    ASSERT_EQ_INT(f->state, TCP_FLOW_ACTIVE, "now ACTIVE");
    ASSERT_EQ_INT(g_h3_send_calls, 2, "one send call per buffered node");
    ASSERT_EQ_INT(g_h3_capture_len, 3500, "all buffered bytes relayed");
    ASSERT_TRUE(memcmp(g_h3_capture, g_expected, 3500) == 0,
                "relayed in FIFO order: p1 then p2, no interleave");
    ASSERT_TRUE(f->uplink_q_head == NULL, "queue drained on establish");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_relay_pending_stream_high_water(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x5555ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 5500, &fake_req, &fake_stream, 0);
    ASSERT_TRUE(f != NULL, "flow bound, PENDING_STREAM");

    const uint16_t seg = 9000;
    const int n = 30; /* 9000*29=261000 < HIGH_WATER(262144) <= 9000*30=270000 */
    for (int i = 0; i < n; i++) {
        struct pbuf *p = mk_pbuf(seg);
        ASSERT_TRUE(p != NULL, "pbuf alloc");
        mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p, ERR_OK);
    }

    ASSERT_EQ_INT(f->uplink_queued_bytes, (uint32_t)seg * n, "all 30 segments queued");
    ASSERT_EQ_INT(f->uplink_withheld, 1, "high-water crossed -> withheld latched");
    ASSERT_EQ_INT(g_recved_total, 9000u * 29u,
                  "the 29 segments below high-water were recved immediately");
    ASSERT_EQ_INT(f->uplink_withheld_recved, 9000,
                  "only the crossing segment is deferred");

    mqvpn_tcp_lane_on_stream_established(lane, &fake_stream);

    ASSERT_EQ_INT(g_h3_capture_len, (size_t)seg * n,
                  "every buffered byte eventually relayed");
    ASSERT_TRUE(memcmp(g_h3_capture, g_expected, (size_t)seg * n) == 0,
                "exact in-order relay across the whole buffered backlog");
    ASSERT_EQ_INT(f->uplink_withheld, 0,
                  "withheld cleared once queue drains below low-water");
    ASSERT_EQ_INT(g_recved_total, (uint32_t)seg * n,
                  "deferred segment's recved eventually caught up");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_relay_fin_ordering(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x6666ULL, NULL, fake_clock, NULL);

    /* (a) FIN arrives while data is still backlogged: the fin call must be
     * strictly AFTER every data call in the log, never interleaved before
     * the backlog drains (fin-after-data ordering). */
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 5600, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    h3_script_push(MQVPN_TCP_LANE_H3_SEND_AGAIN); /* first data send blocks */
    struct pbuf *p = mk_pbuf(400);
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p, ERR_OK);
    ASSERT_TRUE(f->uplink_q_head != NULL, "data backlogged");

    /* Peer FIN while the queue is non-empty: recv(NULL) latches
     * tcp_fin_seen and calls flush(), which (script now exhausted, so the
     * retry fully accepts) drains the backlog and then fires the fin —
     * three h3 calls total, in a pinned order. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_recv(f, &pcb, NULL, ERR_OK), ERR_OK,
                  "recv(NULL) == FIN accepted");
    ASSERT_EQ_INT(f->tcp_fin_seen, 1, "tcp_fin_seen latched");
    ASSERT_EQ_INT(f->fin_sent_to_h3, 1, "fin sent once the backlog drained");
    ASSERT_EQ_INT(g_h3_log_len, 3, "initial EAGAIN + successful retry + fin");
    ASSERT_TRUE(g_h3_log[0].len == 400 && g_h3_log[0].fin == 0 && g_h3_log[0].ret < 0,
                "log[0]: initial data attempt, EAGAIN");
    ASSERT_TRUE(g_h3_log[1].len == 400 && g_h3_log[1].fin == 0 && g_h3_log[1].ret == 400,
                "log[1]: retried data attempt, fully accepted");
    ASSERT_TRUE(g_h3_log[2].len == 0 && g_h3_log[2].fin == 1,
                "log[2]: fin call strictly AFTER both data calls, never before");
    ASSERT_EQ_INT(g_h3_capture_len, 400, "the 400 data bytes, captured exactly once");

    f->pcb = NULL;

    /* (b) FIN on an already-empty queue: sent immediately, no data calls. */
    relay_reset();
    struct tcp_pcb pcb2;
    int fake_req2, fake_stream2;
    mqvpn_tcp_flow_t *f2 = setup_flow(lane, &pcb2, 5601, &fake_req2, &fake_stream2, 1);
    ASSERT_TRUE(f2 != NULL, "second flow established");
    ASSERT_TRUE(f2->uplink_q_head == NULL, "queue starts empty");

    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_recv(f2, &pcb2, NULL, ERR_OK), ERR_OK,
                  "recv(NULL) on empty queue");
    ASSERT_EQ_INT(f2->fin_sent_to_h3, 1, "fin sent immediately, no backlog to wait on");
    ASSERT_EQ_INT(g_h3_log_len, 1, "only the fin call, no data calls");
    ASSERT_TRUE(g_h3_log[0].len == 0 && g_h3_log[0].fin == 1, "the one call is the fin");

    f2->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_relay_repeated_eagain_writable(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x7777ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 5700, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    /* Backlog must clear LOW_WATER (64 KiB) or the very first writable
     * notify's low-water check (queued_bytes < LOW_WATER, no separate
     * "did we make progress" gate — see tcp_lane_uplink_flush) would
     * legitimately resume recved before anything actually drained. 3 * 30000
     * = 90000 > LOW_WATER, so the repeated-EAGAIN backpressure stays
     * observable across every notify below. */
    for (int i = 0; i < 5; i++) {
        h3_script_push(MQVPN_TCP_LANE_H3_SEND_AGAIN);
    }
    struct pbuf *p1 = mk_pbuf(30000);
    struct pbuf *p2 = mk_pbuf(30000);
    struct pbuf *p3 = mk_pbuf(30000);
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p1, ERR_OK); /* attempts send: EAGAIN */
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p2, ERR_OK); /* queue non-empty: stash only */
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p3, ERR_OK); /* stash only */

    ASSERT_EQ_INT(g_h3_send_calls, 1,
                  "only the first recv attempted a send (FIFO backlog)");
    ASSERT_EQ_INT(f->uplink_queued_bytes, 90000, "all three segments queued");
    ASSERT_EQ_INT(f->uplink_withheld, 1, "withheld after the EAGAIN");
    ASSERT_EQ_INT(g_recved_calls, 0, "withheld — nothing recved yet");

    for (int i = 0; i < 4; i++) {
        ASSERT_EQ_INT(mqvpn_tcp_lane_on_h3_writable(lane, &fake_stream), 0,
                      "writable notify tolerated even under repeated EAGAIN");
    }

    ASSERT_EQ_INT(g_h3_send_calls, 5, "one retry attempt per notify, all EAGAIN");
    ASSERT_EQ_INT(g_h3_capture_len, 0, "nothing captured yet");
    ASSERT_EQ_INT(f->uplink_queued_bytes, 90000,
                  "backlog unchanged across repeated EAGAIN");
    ASSERT_TRUE(f->uplink_q_head != NULL && f->uplink_q_head->offset == 0,
                "head node offset unchanged — no partial corruption");
    ASSERT_EQ_INT(f->uplink_withheld, 1,
                  "still withheld — backlog never dropped below low-water");
    ASSERT_EQ_INT(g_recved_calls, 0, "still withheld");

    /* Final writable notify: script exhausted -> full accept drains all
     * three queued nodes in one flush() call. */
    mqvpn_tcp_lane_on_h3_writable(lane, &fake_stream);

    ASSERT_EQ_INT(g_h3_capture_len, 90000,
                  "exactly one full relay of the backlog, no duplication");
    ASSERT_TRUE(memcmp(g_h3_capture, g_expected, 90000) == 0,
                "byte-exact FIFO order across all 3 segments, once");
    ASSERT_TRUE(f->uplink_q_head == NULL, "queue fully drained");
    ASSERT_EQ_INT(f->uplink_withheld, 0, "withheld cleared below low-water");
    /* 90000 > 65535: tcp_lane_recved's u16_t-chunking loop (tcp_recved takes
     * a u16_t) splits the single resume into 2 calls (65535 + 24465). */
    ASSERT_EQ_INT(g_recved_calls, 2,
                  "batched resume recved, chunked at the u16_t boundary");
    ASSERT_EQ_INT(g_recved_total, 90000, "covers the whole backlog");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_relay_chained_pbuf_gt_mss(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x8888ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 5800, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    /* 3 segments, 4000 bytes each = 12000 total > TCP_MSS (8960): forces the
     * slice loop (pbuf_copy_partial into a TCP_MSS-sized stack buffer) to
     * iterate at least twice. */
    uint16_t segs[3] = {4000, 4000, 4000};
    struct pbuf *chain = mk_pbuf_chain(segs, 3);
    ASSERT_TRUE(chain != NULL, "chain alloc");
    ASSERT_EQ_INT(chain->tot_len, 12000, "chain tot_len == sum of segments");
    ASSERT_TRUE(chain->next != NULL, "actually chained (not coalesced into one pbuf)");

    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, chain, ERR_OK);

    ASSERT_EQ_INT(g_h3_capture_len, 12000,
                  "entire chain relayed, no truncation at TCP_MSS");
    ASSERT_TRUE(memcmp(g_h3_capture, g_expected, 12000) == 0,
                "slice loop preserves exact byte order across the MSS boundary");
    ASSERT_TRUE(g_h3_send_calls >= 2, "chain forces at least 2 slice sends past TCP_MSS");
    ASSERT_EQ_INT(g_recved_calls, 1, "full accept -> immediate single recved");
    ASSERT_EQ_INT(g_recved_total, 12000, "recved covers the whole chain");

    f->pcb = NULL;
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
    test_relay_full_accept();
    test_relay_eagain_then_writable_flush();
    test_relay_partial_accept();
    test_relay_pending_stream_buffering();
    test_relay_pending_stream_high_water();
    test_relay_fin_ordering();
    test_relay_repeated_eagain_writable();
    test_relay_chained_pbuf_gt_mss();

    fprintf(stderr, "test_tcp_lane: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
