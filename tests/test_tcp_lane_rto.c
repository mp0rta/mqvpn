// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_tcp_lane_rto.c — TCP-lane downloads into a receiver that stops
 * taking data, through lwIP's retransmission timeout.
 *
 * test_tcp_lane.c substitutes tcp_write/tcp_sndbuf/tcp_output with scripted
 * doubles on stack-fake pcbs, so it cannot reach lwIP's retransmission
 * logic. This file includes the same two lane TUs with no lwIP hooks: every
 * flow is a real pcb accepted through a real IPv4 handshake fed into
 * mqvpn_lwip_input, every downlink write is a real tcp_write, and the inner
 * host is a model of a Linux receiver (below) whose ACKs are crafted
 * packets. The H3 side is a per-request double that serves a finite
 * response.
 *
 * A receiver that runs out of socket memory in the middle of a burst
 * answers with a zero window while lwIP still has a fast retransmit
 * pending. The cases here check that the download resumes once the
 * receiver reads again, whether lwIP gets there through the persist timer
 * or through the retransmission timer.
 */
#include "hybrid/tcp_lane.c"
#include "hybrid/tcp_lane_uplink.c"

#include "hybrid/classifier.h"
#include "hybrid/lwip_glue.h"
#include "lwip/memp.h"

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

#define ASSERT_TRUE(cond, msg)                   \
    do {                                         \
        if (cond) {                              \
            g_pass++;                            \
        } else {                                 \
            g_fail++;                            \
            fprintf(stderr, "FAIL [%s]\n", msg); \
        }                                        \
    } while (0)

/* ─── H3 doubles (real implementations live in mqvpn_client.c) ─── */

/* A finite response: object_left bytes, then FIN. */
typedef struct {
    uint64_t object_left;
    uint64_t delivered;
} test_req_t;

static void *g_open_flow;

int
cli_tcp_lane_open_stream(void *client_ctx, void *flow_handle, const mqvpn_flow_key_t *key)
{
    (void)client_ctx;
    (void)key;
    g_open_flow = flow_handle;
    return 0;
}

ssize_t
cli_tcp_lane_h3_send(void *h3_request, const uint8_t *buf, size_t len, int fin)
{
    (void)h3_request;
    (void)buf;
    (void)fin;
    return (ssize_t)len;
}

ssize_t
cli_tcp_lane_h3_recv(void *h3_request, uint8_t *buf, size_t len, int *fin)
{
    test_req_t *r = (test_req_t *)h3_request;
    if (!r->object_left) {
        *fin = 1;
        return 0;
    }
    size_t n = r->object_left < len ? (size_t)r->object_left : len;
    r->object_left -= n;
    *fin = r->object_left == 0;
    memset(buf, (int)(r->delivered & 0xff), n);
    r->delivered += n;
    return (ssize_t)n;
}

void
cli_tcp_lane_h3_close(void *h3_request)
{
    (void)h3_request;
}

/* ─── clock ─── */

static uint64_t g_now_us = 1000000;

static uint64_t
test_clock(void *ctx)
{
    (void)ctx;
    return g_now_us;
}

/* ─── inner host: IPv4 packet builders and the lwIP output capture ─── */

#define HOST_IP   0x0a000001u /* 10.0.0.1, the LAN host behind the client */
#define SERVER_IP 0x5db8d822u /* 93.184.216.34, the flow's destination */
#define TUN_MTU   1382        /* a common tunnel TUN MTU: lwIP MSS 1342 */

#define MAX_PORTS 16 /* also the lane's TcpMaxFlows here */
#define PORT_BASE 20000
static uint32_t g_synack_isn[MAX_PORTS];

static uint32_t
csum_add(const uint8_t *d, size_t len, uint32_t sum)
{
    size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += (uint32_t)((d[i] << 8) | d[i + 1]);
    }
    if (i < len) {
        sum += (uint32_t)(d[i] << 8);
    }
    return sum;
}

static uint16_t
csum_fold(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static void
put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t
get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Receive window the inner host advertises: the 16-bit field, scaled by
 * g_host_wscale (offered in the SYN, as Linux and other common stacks do).
 * The defaults give ~8 MB, a receiver with room to spare; 0 models one
 * whose socket buffer is full because its application stopped reading. */
static uint16_t g_host_wnd = 0xffff;
static uint8_t g_host_wscale = 7;

/* Host -> server TCP segment with no payload; a SYN carries an MSS option. */
static size_t
build_v4(uint8_t *buf, uint16_t sport, uint32_t seq, uint32_t ack, uint8_t flags)
{
    int syn = (flags & TCP_SYN) != 0;
    size_t tcp_len = syn ? (g_host_wscale ? 28 : 24) : 20;
    size_t len = 20 + tcp_len;
    memset(buf, 0, len);
    buf[0] = 0x45;
    buf[2] = (uint8_t)(len >> 8);
    buf[3] = (uint8_t)len;
    buf[8] = 64;
    buf[9] = 6;
    put32(buf + 12, HOST_IP);
    put32(buf + 16, SERVER_IP);
    uint16_t ipc = csum_fold(csum_add(buf, 20, 0));
    buf[10] = (uint8_t)(ipc >> 8);
    buf[11] = (uint8_t)ipc;

    uint8_t *t = buf + 20;
    t[0] = (uint8_t)(sport >> 8);
    t[1] = (uint8_t)sport;
    t[2] = 0;
    t[3] = 80;
    put32(t + 4, seq);
    put32(t + 8, ack);
    t[12] = (uint8_t)((tcp_len / 4) << 4);
    t[13] = flags;
    t[14] = (uint8_t)(g_host_wnd >> 8); /* a SYN's window is never scaled */
    t[15] = (uint8_t)g_host_wnd;
    if (syn) {
        t[20] = 2;
        t[21] = 4;
        t[22] = 1460 >> 8;
        t[23] = 1460 & 0xff;
        if (g_host_wscale) {
            t[24] = 1; /* NOP */
            t[25] = 3; /* window scale */
            t[26] = 3;
            t[27] = g_host_wscale;
        }
    }
    uint8_t ph[12];
    put32(ph, HOST_IP);
    put32(ph + 4, SERVER_IP);
    ph[8] = 0;
    ph[9] = 6;
    ph[10] = (uint8_t)(tcp_len >> 8);
    ph[11] = (uint8_t)tcp_len;
    uint16_t tc = csum_fold(csum_add(t, tcp_len, csum_add(ph, 12, 0)));
    t[16] = (uint8_t)(tc >> 8);
    t[17] = (uint8_t)tc;
    return len;
}

static void rcv_segment(uint16_t dport, uint32_t seq, uint32_t len, int fin);
static int g_bad_csum;

/* Every IPv4 TCP packet lwIP sends must carry valid IP and TCP checksums;
 * a bad one would be dropped by the host before its TCP sees it. */
static void
check_csum(const uint8_t *pkt, size_t len)
{
    size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
    size_t ip_len = ((size_t)pkt[2] << 8) | pkt[3];
    if (pkt[9] != 6 || ihl < 20 || ip_len < ihl + 20 || ip_len > len) {
        return;
    }
    const uint8_t *t = pkt + ihl;
    size_t tcp_len = ip_len - ihl;
    uint8_t ph[12];
    memcpy(ph, pkt + 12, 8);
    ph[8] = 0;
    ph[9] = 6;
    ph[10] = (uint8_t)(tcp_len >> 8);
    ph[11] = (uint8_t)tcp_len;
    int tcp_bad = csum_fold(csum_add(t, tcp_len, csum_add(ph, 12, 0))) != 0;
    int ip_bad = csum_fold(csum_add(pkt, ihl, 0)) != 0;
    if ((tcp_bad || ip_bad) && g_bad_csum++ < 10) {
        fprintf(stderr, "bad %s checksum: seq %u flags %02x\n", ip_bad ? "IP" : "TCP",
                get32(t + 4), t[13]);
    }
}

static void
test_output(const uint8_t *pkt, size_t len, void *ctx)
{
    (void)ctx;
    if (len < 40 || (pkt[0] >> 4) != 4) {
        return;
    }
    const uint8_t *t = pkt + (pkt[0] & 0x0f) * 4;
    uint16_t dport = (uint16_t)((t[2] << 8) | t[3]);
    size_t ip_len = ((size_t)pkt[2] << 8) | pkt[3];
    size_t hdrs = (size_t)(pkt[0] & 0x0f) * 4 + (size_t)(t[12] >> 4) * 4;
    check_csum(pkt, len);
    if (dport >= PORT_BASE && dport < PORT_BASE + MAX_PORTS && ip_len >= hdrs) {
        rcv_segment(dport, get32(t + 4), (uint32_t)(ip_len - hdrs),
                    (t[13] & TCP_FIN) != 0);
    }
    if ((t[13] & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) && dport >= PORT_BASE &&
        dport < PORT_BASE + MAX_PORTS) {
        g_synack_isn[dport - PORT_BASE] = get32(t + 4);
    }
}

/* ─── fixture ─── */

static mqvpn_lwip_ctx_t *g_ctx;

typedef struct {
    uint16_t sport;
    uint32_t host_isn;
    test_req_t req;
    int stream; /* address used as the opaque cli_stream_t* */
    mqvpn_tcp_flow_t *f;
} test_flow_t;

static mqvpn_tcp_lane_t *
new_lane(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.enabled = 1;
    cfg.tcp_mode = MQVPN_HYBRID_TCP_STREAM;
    cfg.tcp_max_flows = MAX_PORTS;
    mqvpn_tcp_lane_t *lane =
        mqvpn_tcp_lane_new(&cfg, 0x6d656dULL, NULL, test_clock, NULL);
    mqvpn_lwip_ctx_set_accept_cb(g_ctx, mqvpn_tcp_lane_lwip_accept, lane);
    return lane;
}

/* Real handshake, then bind and establish the H3 side. */
static int
open_flow(mqvpn_tcp_lane_t *lane, test_flow_t *tf, uint16_t sport)
{
    memset(tf, 0, sizeof(*tf));
    tf->sport = sport;
    tf->host_isn = 1000u + sport;

    uint8_t pkt[72];
    size_t n = build_v4(pkt, sport, tf->host_isn, 0, TCP_SYN);
    mqvpn_hybrid_config_t ccfg;
    mqvpn_hybrid_config_default(&ccfg);
    ccfg.enabled = 1;
    ccfg.tcp_mode = MQVPN_HYBRID_TCP_STREAM;
    mqvpn_flow_key_t key;
    if (mqvpn_hybrid_classify(pkt, n, &ccfg, &key) != MQVPN_LANE_TCP) return -1;
    if (mqvpn_tcp_lane_on_syn(lane, &key, 1, 0) != 0) return -1;
    g_synack_isn[sport - PORT_BASE] = 0;
    if (mqvpn_lwip_input(g_ctx, pkt, n) != 0) return -1;
    uint32_t sisn = g_synack_isn[sport - PORT_BASE];
    if (!sisn) return -1;
    g_open_flow = NULL;
    n = build_v4(pkt, sport, tf->host_isn + 1, sisn + 1, TCP_ACK);
    if (mqvpn_lwip_input(g_ctx, pkt, n) != 0 || !g_open_flow) return -1;
    tf->f = (mqvpn_tcp_flow_t *)g_open_flow;
    mqvpn_tcp_lane_bind_h3_request(tf->f, &tf->req, &tf->stream);
    mqvpn_tcp_lane_on_stream_established(lane, &tf->stream);
    return tf->f->state == TCP_FLOW_ACTIVE ? 0 : -1;
}

static void
pump(mqvpn_tcp_lane_t *lane, test_flow_t *tf)
{
    (void)mqvpn_tcp_lane_downlink_pump(lane, &tf->stream);
}

/* ─── a receiving host modelled on Linux ─── */

/* The inner host as a Linux receiver, for the tests below: it takes
 * in-order data that starts inside the window it last offered (trimming
 * what it already has), its application reads `rate` bytes a step out of
 * a `rcvbuf`-byte socket buffer, and it offers min(free space, clamp),
 * rounded down to its window scale, never moving the right edge back and
 * offering nothing while less than one MSS is free in a buffer more than
 * half full. Linux holds rcv_ssthresh, the clamp here, at 4 * advmss
 * (5840) under socket memory pressure, so a slow sink on a loaded box
 * offers ~5.8 KB at a time, less than one lane read. It acknowledges
 * arriving data at once and, after a read, sends a window update only when
 * the window it would now offer is at least twice what is left of the last
 * one (tcp_cleanup_rbuf). */
typedef struct {
    int on;
    uint32_t rcv_nxt, adv_right;
    uint32_t recvq, rcvbuf, clamp, rate;
    uint64_t got;
    int fin, need_ack;
    uint64_t last_rx_us;
    /* Out of receive memory, as Linux 6.x handles it: in-order data past
     * the next nomem_room bytes is dropped and answered at once with a
     * zero window at rcv_nxt (the right edge moves back), and every data
     * segment that arrives beyond the zero window is answered at once
     * with a duplicate ACK (data is not rate-limited). */
    int nomem;
    uint32_t nomem_room;
    /* Drops in-order data with no answer and no window change. */
    int silent_drop;
    uint32_t acks; /* ACKs owed at once, sent by the next step */
} rcv_host_t;
static rcv_host_t g_rh[MAX_PORTS];

static void
rcv_segment(uint16_t dport, uint32_t seq, uint32_t len, int fin)
{
    rcv_host_t *h = &g_rh[dport - PORT_BASE];
    if (!h->on || (!len && !fin)) {
        return;
    }
    if (h->silent_drop && len && (int32_t)(seq + len - h->rcv_nxt) > 0) {
        return;
    }
    h->need_ack = 1;
    if ((int32_t)(seq - h->rcv_nxt) > 0) {
        if (h->nomem && h->adv_right == h->rcv_nxt) {
            h->acks++;
        }
        return; /* out of order: re-ACK what we have */
    }
    uint32_t old = h->rcv_nxt - seq;
    if (old >= len + (fin ? 1u : 0u)) {
        return; /* all old: re-ACK */
    }
    len -= old;
    if (len && h->nomem) {
        if (h->nomem_room < len || h->adv_right == h->rcv_nxt) {
            h->adv_right = h->rcv_nxt;
            h->acks++;
            return;
        }
        h->nomem_room -= len;
    }
    if (len && (int32_t)(h->adv_right - h->rcv_nxt) <= 0) {
        return; /* closed window: dropped */
    }
    h->rcv_nxt += len;
    h->recvq += len;
    h->got += len;
    if (len) {
        h->last_rx_us = g_now_us;
    }
    if (fin) {
        h->rcv_nxt++;
        h->fin = 1;
    }
}

static uint32_t
rcv_select_window(const rcv_host_t *h)
{
    if (h->nomem && h->adv_right == h->rcv_nxt) {
        return 0;
    }
    uint32_t free_space = h->recvq < h->rcvbuf ? h->rcvbuf - h->recvq : 0;
    uint32_t w = free_space < h->rcvbuf / 2 && free_space < 1342 ? 0 : free_space;
    if (w > h->clamp) {
        w = h->clamp;
    }
    w &= ~((1u << g_host_wscale) - 1);
    if (w > (0xffffu << g_host_wscale)) {
        w = 0xffffu << g_host_wscale;
    }
    if ((int32_t)(h->rcv_nxt + w - h->adv_right) < 0) {
        w = h->adv_right - h->rcv_nxt; /* never shrink the offered window */
    }
    return w;
}

static void
rcv_send_ack(test_flow_t *tf, rcv_host_t *h)
{
    uint32_t w = rcv_select_window(h);
    h->adv_right = h->rcv_nxt + w;
    h->need_ack = 0;
    uint16_t saved = g_host_wnd;
    g_host_wnd = (uint16_t)(w >> g_host_wscale);
    uint8_t pkt[72];
    size_t n = build_v4(pkt, tf->sport, tf->host_isn + 1, h->rcv_nxt, TCP_ACK);
    g_host_wnd = saved;
    (void)mqvpn_lwip_input(g_ctx, pkt, n);
}

static void
rcv_open(test_flow_t *tf, uint32_t rcvbuf, uint32_t clamp, uint32_t rate)
{
    rcv_host_t *h = &g_rh[tf->sport - PORT_BASE];
    memset(h, 0, sizeof(*h));
    h->on = 1;
    h->rcv_nxt = g_synack_isn[tf->sport - PORT_BASE] + 1;
    h->adv_right = h->rcv_nxt;
    h->rcvbuf = rcvbuf;
    h->clamp = clamp;
    h->rate = rate;
    h->last_rx_us = g_now_us;
    rcv_send_ack(tf, h);
}

/* One step of the host: the application reads, then the host sends what
 * Linux would. */
static void
rcv_step(test_flow_t *tf)
{
    rcv_host_t *h = &g_rh[tf->sport - PORT_BASE];
    if (!h->on || h->fin) {
        return; /* nothing more to say on a connection the lane has closed */
    }
    uint32_t r = h->recvq < h->rate ? h->recvq : h->rate;
    h->recvq -= r;
    if (h->acks) {
        uint32_t a = h->acks;
        h->acks = 0;
        h->need_ack = 0;
        while (a-- > 0 && h->on) {
            rcv_send_ack(tf, h);
        }
    } else if (h->need_ack) {
        rcv_send_ack(tf, h);
    } else if (r) {
        uint32_t left = h->adv_right - h->rcv_nxt;
        uint32_t w = rcv_select_window(h);
        if (2 * left <= h->rcvbuf && w >= 2 * left && w > left) {
            rcv_send_ack(tf, h);
        }
    }
}

#define RCV_STEP_US 10000 /* 10 ms */

/* `steps` steps of the hosts, lwIP's timers and the lane's tick. */
static void
rcv_run(mqvpn_tcp_lane_t *lane, test_flow_t *fl, int n, int steps)
{
    for (int s = 0; s < steps; s++) {
        for (int i = 0; i < n; i++) {
            rcv_step(&fl[i]);
        }
        g_now_us += RCV_STEP_US;
        mqvpn_lwip_tick(g_ctx);
        mqvpn_tcp_lane_tick(lane, g_now_us);
    }
}

static void
rcv_close_all(test_flow_t *fl, int n)
{
    for (int i = 0; i < n; i++) {
        g_rh[fl[i].sport - PORT_BASE].on = 0;
    }
}

/* Opens n lane flows whose hosts offer `clamp` from the handshake on (the
 * handshake ACK carries the same window the host model then keeps). */
static int
rcv_open_flows(mqvpn_tcp_lane_t *lane, test_flow_t *fl, int n, uint32_t clamp)
{
    uint16_t saved = g_host_wnd;
    g_host_wnd = (uint16_t)(clamp >> g_host_wscale);
    int ok = 1;
    for (int i = 0; i < n; i++) {
        ok &= open_flow(lane, &fl[i], (uint16_t)(PORT_BASE + i)) == 0;
    }
    g_host_wnd = saved;
    return ok;
}

/* A receiver that runs out of socket memory in the middle of a burst, the
 * way Linux 6.x answers it: the first segment of the burst still fits, the
 * next is dropped and answered at once with a zero window, and every
 * segment behind it, now beyond that window, draws a duplicate ACK. The
 * third duplicate makes lwIP retransmit the lost segment, which cannot go
 * out into the zero window, so it waits on the unsent queue while the
 * segments behind it stay unacknowledged until the retransmission timer
 * requeues them. The application then reads everything and the window
 * opens (5888 bytes, window scale 7) `delay_steps` steps after that
 * timeout. The receiver must get new data within 2 s and the download must
 * reach its end. */
static void
test_zero_window_burst_resumes(int delay_steps)
{
    char k[64], msg[160];
    snprintf(k, sizeof(k), "zero window burst +%d ms", delay_steps * RCV_STEP_US / 1000);
    mqvpn_tcp_lane_t *lane = new_lane();
    static test_flow_t fl[1];
    int ok = rcv_open_flows(lane, fl, 1, 65536);
    snprintf(msg, sizeof(msg), "%s: flow opened", k);
    ASSERT_TRUE(ok, msg);
    if (!ok) {
        mqvpn_tcp_lane_free(lane);
        return;
    }
    rcv_host_t *h = &g_rh[fl[0].sport - PORT_BASE];
    const struct tcp_pcb *pcb = fl[0].f->pcb;
    fl[0].req.object_left = 16u << 20;
    rcv_open(&fl[0], 4u << 20, 65536, 65536);
    pump(lane, &fl[0]);
    rcv_run(lane, fl, 1, 100);
    h->rate = 0;
    h->nomem = 1;
    h->nomem_room = TUN_MTU - 40;
    int fast = 0, rto = 0;
    for (int s = 0; s < 1000 && !rto; s++) {
        rcv_run(lane, fl, 1, 1);
        fast |= pcb->snd_wnd == 0 && pcb->unsent != NULL && pcb->unacked != NULL &&
                TCP_SEQ_LT(lwip_ntohl(pcb->unsent->tcphdr->seqno),
                           lwip_ntohl(pcb->unacked->tcphdr->seqno));
        rto = fast && pcb->unacked == NULL;
    }
    snprintf(msg, sizeof(msg), "%s: the lost segment waits on unsent for the zero window",
             k);
    ASSERT_TRUE(fast, msg);
    snprintf(msg, sizeof(msg), "%s: until the retransmission timer requeues the rest", k);
    ASSERT_TRUE(rto, msg);
    rcv_run(lane, fl, 1, delay_steps);
    h->nomem = 0;
    h->recvq = 0;
    h->clamp = 5888;
    h->rate = 6250;
    rcv_send_ack(&fl[0], h);
    uint64_t got0 = h->got;
    rcv_run(lane, fl, 1, 200);
    snprintf(msg, sizeof(msg), "%s: the receiver gets new data within 2 s", k);
    ASSERT_TRUE(h->got > got0, msg);
    rcv_run(lane, fl, 1, 3000);
    snprintf(msg, sizeof(msg), "%s: and the download reaches its end", k);
    ASSERT_TRUE(h->fin, msg);
    rcv_close_all(fl, 1);
    mqvpn_tcp_lane_free(lane);
}

/* A receiver that keeps offering its 5888-byte window while it silently
 * drops every data segment (socket memory: no answer, no window change)
 * through `rtos` retransmission timeouts, then reads everything. Its window
 * update changes nothing lwIP acts on, so lwIP delivers again at its next
 * retransmission timeout, and must do so within 2 s of it. */
static void
test_silent_drop_resumes(int rtos)
{
    char k[48], msg[128];
    snprintf(k, sizeof(k), "silent drop %d RTOs", rtos);
    mqvpn_tcp_lane_t *lane = new_lane();
    static test_flow_t fl[1];
    int ok = rcv_open_flows(lane, fl, 1, 5888);
    snprintf(msg, sizeof(msg), "%s: flow opened", k);
    ASSERT_TRUE(ok, msg);
    if (!ok) {
        mqvpn_tcp_lane_free(lane);
        return;
    }
    rcv_host_t *h = &g_rh[fl[0].sport - PORT_BASE];
    const struct tcp_pcb *pcb = fl[0].f->pcb;
    fl[0].req.object_left = 2u << 20;
    rcv_open(&fl[0], 256u << 10, 5888, 6250);
    pump(lane, &fl[0]);
    rcv_run(lane, fl, 1, 100);
    h->silent_drop = 1;
    for (int s = 0; s < 20000 && pcb->nrtx < rtos; s++) {
        rcv_run(lane, fl, 1, 1);
    }
    snprintf(msg, sizeof(msg), "%s: reached", k);
    ASSERT_TRUE(pcb->nrtx >= rtos, msg);
    h->silent_drop = 0;
    h->recvq = 0;
    rcv_send_ack(&fl[0], h);
    int due_steps = (pcb->rto - pcb->rtime) * TCP_SLOW_INTERVAL * 1000 / RCV_STEP_US;
    uint64_t got0 = h->got;
    int resumed = -1;
    for (int s = 0; s < 20000 && resumed < 0; s++) {
        rcv_run(lane, fl, 1, 1);
        if (h->got > got0) {
            resumed = s;
        }
    }
    snprintf(msg, sizeof(msg), "%s: delivers again within 2 s of its next timeout", k);
    ASSERT_TRUE(resumed >= 0 && resumed <= due_steps + 200, msg);
    rcv_run(lane, fl, 1, 3000);
    snprintf(msg, sizeof(msg), "%s: and the download reaches its end", k);
    ASSERT_TRUE(h->fin, msg);
    rcv_close_all(fl, 1);
    mqvpn_tcp_lane_free(lane);
}

/* Every segment is back in the pool once the lanes are freed. */
static int
pool_all_free(void)
{
    static void *held[MEMP_NUM_TCP_SEG + 1];
    int n = 0;
    while (n <= MEMP_NUM_TCP_SEG && (held[n] = memp_malloc(MEMP_TCP_SEG)) != NULL) {
        n++;
    }
    for (int i = 0; i < n; i++) {
        memp_free(MEMP_TCP_SEG, held[i]);
    }
    return n == MEMP_NUM_TCP_SEG;
}

int
main(void)
{
    g_ctx = mqvpn_lwip_ctx_new(test_clock, NULL, test_output, NULL, TUN_MTU);
    if (!g_ctx) {
        fprintf(stderr, "test_tcp_lane_rto: lwip ctx\n");
        return 1;
    }
    test_zero_window_burst_resumes(0);
    test_zero_window_burst_resumes(100);
    test_zero_window_burst_resumes(400);
    test_silent_drop_resumes(2);
    test_silent_drop_resumes(4);
    ASSERT_EQ_INT(g_bad_csum, 0, "lwIP output: every IP and TCP checksum valid");
    ASSERT_TRUE(pool_all_free(), "teardown: every test returned its segments");
    mqvpn_lwip_ctx_free(g_ctx);
    fprintf(stderr, "test_tcp_lane_rto: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
