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
#include <stdint.h> /* int8_t/uint16_t/uint8_t for the Task 11 hook forward decls below */

/* Shrink the sticky-RAW marker cap (production default 4096) so the
 * marker-cap branch is testable without 4096 inserts. Must precede the
 * #include of the TU. */
#define TCP_LANE_RAW_MARKER_CAP 4u

/* C1: same idea for the CLOSING routing-marker cap (production default
 * 4096) — shrunk so the cap-eviction branch is testable without 4096
 * clean-closes. Must precede the #include of the TU. */
#define TCP_LANE_CLOSING_CAP 4u

/* Task 10: observe tcp_recved via tcp_lane.c's compile-time substitution
 * hook — calling the REAL tcp_recved on the stack-fake pcbs below would
 * touch rcv_wnd internals (and assert). Must precede the #include; the hook
 * function is defined after it (forward declaration suffices — the macro
 * only expands inside tcp_lane.c's bodies). */
struct tcp_pcb;
static void test_recved_hook(struct tcp_pcb *pcb, unsigned int len);
#define MQVPN_TCP_LANE_TEST_RECVED(pcb, len) test_recved_hook((pcb), (len))

/* Task 11: downlink hooks, same compile-time substitution idiom. Forward-
 * declared here with plain stdint-width types instead of lwIP's own
 * err_t/u16_t/u8_t aliases — those typedefs (lwip/err.h, lwip/arch.h) are
 * not visible yet at this point in the file (before tcp_lane.c pulls in
 * lwip/tcp.h below), but they resolve to EXACTLY these underlying types, so
 * the forward declaration used at every macro-expansion call site inside
 * tcp_lane.c and the real definition below (where the lwIP aliases ARE
 * visible) describe the identical type — no mismatch. Calling the REAL
 * tcp_write/tcp_shutdown/tcp_output on the stack-fake pcbs below would
 * touch send-queue/pbuf-chain internals never initialized by a real
 * tcp_new()+accept (tcp_sndbuf is a pure field read and would technically
 * be safe, but is hooked too for scriptability independent of mutating the
 * fake pcb's field — see the .c-side comment on these same macro names). */
static int8_t test_tcp_write_hook(struct tcp_pcb *pcb, const void *dataptr, uint16_t len,
                                  uint8_t apiflags);
#define MQVPN_TCP_LANE_TCP_WRITE(pcb, buf, len, flags) \
    test_tcp_write_hook((pcb), (buf), (len), (flags))

/* u32, not u16: with LWIP_WND_SCALE the real snd_buf is a 32-bit
 * tcpwnd_size_t (TCP_SND_BUF is 2 MiB in lwip_port/lwipopts.h), and tests
 * must be able to script sndbuf values above 65535. */
static uint32_t test_tcp_sndbuf_hook(struct tcp_pcb *pcb);
#define MQVPN_TCP_LANE_TCP_SNDBUF(pcb) test_tcp_sndbuf_hook(pcb)

static int8_t test_tcp_shutdown_hook(struct tcp_pcb *pcb, int shut_rx, int shut_tx);
#define MQVPN_TCP_LANE_TCP_SHUTDOWN(pcb, rx, tx) test_tcp_shutdown_hook((pcb), (rx), (tx))

static void test_tcp_output_hook(struct tcp_pcb *pcb);
#define MQVPN_TCP_LANE_TCP_OUTPUT(pcb) test_tcp_output_hook(pcb)

/* Task 12: tcp_abort/tcp_close hooks, same idiom. Calling the REAL
 * tcp_abort/tcp_close on the stack-fake pcbs below would tcp_free()
 * (memp_free) memory lwIP's pool never allocated and corrupt the
 * active_pcbs list — see tcp_lane_internal.h's comment on these two
 * macros. Both are recording-only (void real signatures; nothing to
 * script). */
static void test_tcp_abort_hook(struct tcp_pcb *pcb);
#define MQVPN_TCP_LANE_TCP_ABORT(pcb) test_tcp_abort_hook(pcb)

static void test_tcp_close_hook(struct tcp_pcb *pcb);
#define MQVPN_TCP_LANE_TCP_CLOSE(pcb) test_tcp_close_hook(pcb)

#include "hybrid/tcp_lane.c"
/* tcp_lane.c crossed its ~800-line extraction trigger: the uplink QUEUE +
 * SEND + FLUSH + FIN machinery moved to its own TU (tcp_lane_internal.h
 * documents why). Pull it into this same translation unit exactly like
 * tcp_lane.c above — same file-local-struct reason, do NOT also list it in
 * CMakeLists.txt (would compile it twice). */
#include "hybrid/tcp_lane_uplink.c"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

/* ─── cli_tcp_lane_open_stream stub (real impl: mqvpn_client.c) ───
 *
 * Task 12 ERR_ABRT plumbing: the real function returns nonzero when a
 * failure path called mqvpn_tcp_lane_abort_pending (which tcp_abort()s the
 * pcb) — the accept callback frame must then return ERR_ABRT to lwIP. The
 * stub mirrors both shapes: g_open_stream_fail=1 scripts the failure path
 * (calls the REAL abort_pending exactly like every failure branch in
 * mqvpn_client.c does, and propagates its return verbatim). */

static int g_open_stream_calls;
static void *g_open_stream_flow;
static mqvpn_flow_key_t g_open_stream_key;
static int g_open_stream_fail;

int
cli_tcp_lane_open_stream(void *client_ctx, void *flow_handle, const mqvpn_flow_key_t *key)
{
    (void)client_ctx;
    g_open_stream_calls++;
    g_open_stream_flow = flow_handle;
    g_open_stream_key = *key;
    if (g_open_stream_fail) {
        return mqvpn_tcp_lane_abort_pending(flow_handle);
    }
    return 0;
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

/* ─── Task 11 downlink hooks: tcp_write/tcp_sndbuf/tcp_shutdown/tcp_output
 * observability + scripting ───
 *
 * tcp_write: captures every accepted byte (byte-exact assertions, same
 * discipline as the h3_send capture below) and is scriptable via a small
 * err_t queue (default ERR_OK == accept, matching real tcp_write's common
 * case; push ERR_MEM or a generic fatal code to drive the pause/error
 * paths). tcp_sndbuf: a single settable value (real tcp_sndbuf is a pure
 * field read with no side effect to script around — one knob suffices).
 * tcp_shutdown: records call count + args, return scriptable (default
 * ERR_OK). tcp_output: call-count only (latency-fix observability). */

#define TW_SCRIPT_MAX 16
static int8_t g_tw_script[TW_SCRIPT_MAX];
static int g_tw_script_len, g_tw_script_pos;
static int g_tcp_write_calls;
static uint8_t g_tcp_write_capture[512 * 1024];
static size_t g_tcp_write_capture_len;

static void
tw_script_clear(void)
{
    g_tw_script_len = 0;
    g_tw_script_pos = 0;
}

static void
tw_script_push(int8_t v)
{
    g_tw_script[g_tw_script_len++] = v;
}

static int8_t
test_tcp_write_hook(struct tcp_pcb *pcb, const void *dataptr, uint16_t len,
                    uint8_t apiflags)
{
    (void)pcb;
    (void)apiflags;
    g_tcp_write_calls++;
    int8_t ret = ERR_OK;
    if (g_tw_script_pos < g_tw_script_len) {
        ret = g_tw_script[g_tw_script_pos++];
    }
    if (ret == ERR_OK && dataptr) {
        size_t room = sizeof(g_tcp_write_capture) - g_tcp_write_capture_len;
        size_t n = ((size_t)len <= room) ? (size_t)len : room;
        memcpy(g_tcp_write_capture + g_tcp_write_capture_len, dataptr, n);
        g_tcp_write_capture_len += n;
    }
    return ret;
}

static uint32_t g_tcp_sndbuf_value = 0xFFFFu; /* default: plenty of room */

static uint32_t
test_tcp_sndbuf_hook(struct tcp_pcb *pcb)
{
    (void)pcb;
    return g_tcp_sndbuf_value;
}

static int g_tcp_shutdown_calls;
static int g_tcp_shutdown_last_rx, g_tcp_shutdown_last_tx;
static int8_t g_tcp_shutdown_ret = ERR_OK;

static int8_t
test_tcp_shutdown_hook(struct tcp_pcb *pcb, int shut_rx, int shut_tx)
{
    (void)pcb;
    g_tcp_shutdown_calls++;
    g_tcp_shutdown_last_rx = shut_rx;
    g_tcp_shutdown_last_tx = shut_tx;
    return g_tcp_shutdown_ret;
}

static int g_tcp_output_calls;

static void
test_tcp_output_hook(struct tcp_pcb *pcb)
{
    (void)pcb;
    g_tcp_output_calls++;
}

/* ─── Task 12 tcp_abort/tcp_close observability ─── */

static int g_tcp_abort_calls;
static struct tcp_pcb *g_tcp_abort_last_pcb;

static void
test_tcp_abort_hook(struct tcp_pcb *pcb)
{
    g_tcp_abort_calls++;
    g_tcp_abort_last_pcb = pcb;
}

static int g_tcp_close_calls;
static struct tcp_pcb *g_tcp_close_last_pcb;

static void
test_tcp_close_hook(struct tcp_pcb *pcb)
{
    g_tcp_close_calls++;
    g_tcp_close_last_pcb = pcb;
}

/* ─── cli_tcp_lane_h3_close test double (real impl: mqvpn_client.c) ─── */

static int g_h3_close_calls;
static void *g_h3_close_last_req;

void
cli_tcp_lane_h3_close(void *h3_request)
{
    g_h3_close_calls++;
    g_h3_close_last_req = h3_request;
}

/* ─── cli_tcp_lane_h3_recv test double (real impl: mqvpn_client.c) ───
 *
 * Scripted delivery queue simulating the server's H3 response body: each
 * entry is either a data chunk (with an optional fin), a bare AGAIN, or a
 * bare ERR. Default on an exhausted script is AGAIN (NOT "accept
 * everything" like h3_send's double) — that is what makes the drain loop
 * inside mqvpn_tcp_lane_downlink_pump actually terminate once a test's
 * scripted deliveries run out, mirroring xquic's real "nothing more
 * buffered right now" signal.
 *
 * fin is LEVEL-TRIGGERED, like the real xquic (tcp_lane.h H3_RECV contract,
 * xqc_h3_request.c:795-801): once any entry with fin=1 has been delivered,
 * an exhausted script returns 0 with *fin=1 instead of AGAIN — every later
 * call re-reports the fin. The downlink drain's stash path DEPENDS on this
 * (it drops the local fin flag when a data+fin chunk gets stashed and
 * relies on the re-report at the resumed drain); an edge-triggered double
 * would falsify that path (see test_downlink_fin_stashed_with_data). */

typedef struct {
    const uint8_t *data;
    size_t len;
    int fin;
    int special; /* 0 = normal, 1 = AGAIN, 2 = ERR */
} h3_recv_entry_t;

#define H3_RECV_SCRIPT_MAX 32
static h3_recv_entry_t g_h3_recv_script[H3_RECV_SCRIPT_MAX];
static int g_h3_recv_script_len, g_h3_recv_script_pos;
static int g_h3_recv_calls;
static int g_h3_recv_fin_latched; /* sticky, like xquic's h3r->fin_flag */

static void
h3_recv_script_clear(void)
{
    g_h3_recv_script_len = 0;
    g_h3_recv_script_pos = 0;
    g_h3_recv_fin_latched = 0;
}

static void
h3_recv_push_data(const uint8_t *data, size_t len, int fin)
{
    h3_recv_entry_t *e = &g_h3_recv_script[g_h3_recv_script_len++];
    e->data = data;
    e->len = len;
    e->fin = fin;
    e->special = 0;
}

static void
h3_recv_push_err(void)
{
    h3_recv_entry_t *e = &g_h3_recv_script[g_h3_recv_script_len++];
    e->special = 2;
}

ssize_t
cli_tcp_lane_h3_recv(void *h3_request, uint8_t *buf, size_t len, int *fin)
{
    (void)h3_request;
    g_h3_recv_calls++;
    if (g_h3_recv_script_pos >= g_h3_recv_script_len) {
        if (g_h3_recv_fin_latched) {
            /* Level-triggered re-report: drained + fin already seen ==
             * xquic's body_buf_count==0 && fin_flag path (0 bytes, *fin=1,
             * never AGAIN again). */
            *fin = 1;
            return 0;
        }
        return MQVPN_TCP_LANE_H3_RECV_AGAIN;
    }
    h3_recv_entry_t *e = &g_h3_recv_script[g_h3_recv_script_pos++];
    if (e->special == 1) return MQVPN_TCP_LANE_H3_RECV_AGAIN;
    if (e->special == 2) return MQVPN_TCP_LANE_H3_RECV_ERR;
    size_t n = e->len;
    if (n > len) n = len; /* test chunks are always <= the TCP_MSS scratch buffer */
    if (n > 0 && e->data) {
        memcpy(buf, e->data, n);
    }
    if (e->fin) {
        g_h3_recv_fin_latched = 1;
    }
    *fin = e->fin;
    return (ssize_t)n;
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

/* Backing store for scripted downlink byte chunks — declared here (not next
 * to mk_dl_bytes below) so relay_reset can clear g_dl_src_len. */
#define DL_SRC_MAX (256 * 1024)
static uint8_t g_dl_src[DL_SRC_MAX];
static size_t g_dl_src_len;

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

    /* Task 11 downlink test-double state. */
    tw_script_clear();
    g_tcp_write_calls = 0;
    g_tcp_write_capture_len = 0;
    g_tcp_sndbuf_value = 0xFFFFu;
    g_tcp_shutdown_calls = 0;
    g_tcp_shutdown_last_rx = 0;
    g_tcp_shutdown_last_tx = 0;
    g_tcp_shutdown_ret = ERR_OK;
    g_tcp_output_calls = 0;
    h3_recv_script_clear();
    g_h3_recv_calls = 0;
    g_dl_src_len = 0;

    /* Task 12 close/error-mapping test-double state. */
    g_tcp_abort_calls = 0;
    g_tcp_abort_last_pcb = NULL;
    g_tcp_close_calls = 0;
    g_tcp_close_last_pcb = NULL;
    g_h3_close_calls = 0;
    g_h3_close_last_req = NULL;
    g_open_stream_fail = 0;
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

/* Backing store for scripted downlink byte chunks (h3_recv_push_data needs
 * pointers that stay alive across the whole test) — mirrors mk_pbuf's
 * rolling g_seq/g_expected pattern above so downlink tests get the same
 * byte-exact assertion style. Variables declared alongside g_expected/g_seq
 * above (relay_reset needs g_dl_src_len in scope); only the helper function
 * lives here. */
static const uint8_t *
mk_dl_bytes(size_t len)
{
    uint8_t *start = g_dl_src + g_dl_src_len;
    for (size_t i = 0; i < len; i++) {
        start[i] = g_seq;
        g_expected[g_expected_len++] = g_seq;
        g_seq++;
    }
    g_dl_src_len += len;
    return start;
}

/* The exact key setup_flow below builds from a given src_port — factored out
 * (Task 12) so post-teardown tests can independently recompute "the key for
 * the flow at this pcb" and assert a table lookup miss, without needing
 * setup_flow itself to hand back a key (its established callers below don't
 * need one — only the Task 12 teardown assertions do). */
static mqvpn_flow_key_t
mk_std_key(uint16_t src_port)
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
    return k;
}

/* SYN-commit + fake-pcb accept + bind (+ optional 2xx establish) — the same
 * dance test_accept_key_correspondence pins, packaged for the relay tests.
 * pcb is caller-owned stack memory: Task 12 onward, teardown paths route
 * pcb detach through the hooked MQVPN_TCP_LANE_TCP_ABORT/_CLOSE (see the
 * hooks above), so callers no longer need to manually NULL f->pcb before
 * lane_free purely to dodge a real tcp_abort — some call sites still do so
 * anyway wherever the flow is expected to still be ACTIVE (never torn down)
 * at lane_free time, which is a real "stack-fake pcb, not pool-owned"
 * precaution independent of the hooks. */
static mqvpn_tcp_flow_t *
setup_flow(mqvpn_tcp_lane_t *lane, struct tcp_pcb *pcb, uint16_t src_port, void *req,
           void *stream, int establish)
{
    mqvpn_flow_key_t k = mk_std_key(src_port);
    if (mqvpn_tcp_lane_on_syn(lane, &k, 1, 0) != 0) {
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
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 0,
                  "lookup miss on brand-new flow");

    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 1, 0), 0, "on_syn to_tcp commits");

    out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 1,
                  "lookup hit after commit");
    ASSERT_EQ_INT(out_raw, 0, "committed flow is not sticky-RAW");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 1, "flows_active == 1");
    ASSERT_EQ_INT(stats.flows_total, 1, "flows_total == 1");

    /* Duplicate commit is a caller bug (protocol: lookup-then-commit) —
     * refused, counted in flows_rejected_other, no shadowing insert. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 1, 0), -1, "duplicate on_syn refused");
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
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0, 0), 0,
                  "on_syn to_tcp=0 records sticky-RAW");

    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 1,
                  "lookup hit after sticky-RAW commit");
    ASSERT_EQ_INT(out_raw, 1, "sticky-RAW flow reports is_raw");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 0, "sticky-RAW does not count as active");
    ASSERT_EQ_INT(stats.flows_total, 1, "flows_total == 1");

    mqvpn_tcp_lane_free(lane);
}

/* ─── I2: ISN-based sticky-RAW re-evaluation ───
 *
 * tun_decide_lane (mqvpn_client.c) is the actual caller that compares a new
 * pure SYN's ISN against mqvpn_tcp_lane_marker_isn's return and decides
 * whether to call on_syn again — that policy-re-run decision itself lives
 * outside tcp_lane.c and has no dedicated unit-test harness (tun_decide_lane
 * is a static function with no test target of its own, same situation C1's
 * "final-ACK-shape packet still routes to lwip_input" note already flagged).
 * These tests pin the tcp_lane.c-side CONTRACT tun_decide_lane relies on:
 * marker_isn's storage/retrieval, and on_syn's stale-sticky-RAW-marker
 * replacement (both re-record and RAW->TCP transition). */

static void
test_marker_isn_stored_and_retrieved(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x1235ULL, NULL, NULL, NULL);
    ASSERT_TRUE(lane != NULL, "lane_new succeeds");

    mqvpn_flow_key_t k = make_key(4002, 443);
    ASSERT_EQ_INT(mqvpn_tcp_lane_marker_isn(lane, &k), 0,
                  "no marker yet -> 0 (unknown key)");

    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0, 0xdeadbeefu), 0,
                  "on_syn to_tcp=0 records sticky-RAW with an ISN");
    ASSERT_EQ_INT(mqvpn_tcp_lane_marker_isn(lane, &k), 0xdeadbeefu,
                  "marker_isn returns the stored ISN — same-ISN retransmit "
                  "case: tun_decide_lane compares this and stays RAW without "
                  "ever calling on_syn again");

    /* A real (non-marker) TCP-lane flow has no meaningful ISN — accessor
     * returns 0 for it too, not the stale marker value from a DIFFERENT
     * key. */
    mqvpn_flow_key_t k2 = make_key(4003, 443);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k2, 1, 0x11111111u), 0,
                  "on_syn to_tcp=1 commits a real flow");
    ASSERT_EQ_INT(mqvpn_tcp_lane_marker_isn(lane, &k2), 0,
                  "marker_isn is 0 for a non-sticky-RAW entry, regardless of "
                  "what syn_isn on_syn was called with");

    mqvpn_tcp_lane_free(lane);
}

static void
test_syn_isn_mismatch_replaces_marker_raw_to_raw(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x1236ULL, NULL, NULL, NULL);
    ASSERT_TRUE(lane != NULL, "lane_new succeeds");

    mqvpn_flow_key_t k = make_key(4004, 443);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0, 100), 0, "first sticky-RAW marker");
    ASSERT_EQ_INT(mqvpn_tcp_lane_marker_isn(lane, &k), 100u, "ISN 100 stored");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_total, 1, "one entry so far");

    /* Different ISN (200 != 100): tun_decide_lane's contract is to call
     * on_syn again — pin on_syn's own side: it must remove the stale
     * marker (not shadow it) and record the NEW verdict/ISN, again as
     * sticky-RAW (the re-evaluated policy can legitimately land on RAW
     * again — a single-path client that briefly saw >=2 paths and then
     * dropped back to one, for instance). */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0, 200), 0,
                  "on_syn succeeds on ISN mismatch — stale marker replaced");
    ASSERT_EQ_INT(mqvpn_tcp_lane_marker_isn(lane, &k), 200u,
                  "marker now holds the NEW ISN, not the stale one");

    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_total, 2,
                  "flows_total counts the replacement as a new insert (not "
                  "a no-op re-affirmation)");
    ASSERT_EQ_INT(stats.raw_markers_active, 1,
                  "exactly one marker live — the stale one was actually "
                  "removed, not left as a shadowing duplicate");
    ASSERT_EQ_INT(stats.flows_rejected_other, 0, "NOT treated as a caller-bug duplicate");

    mqvpn_tcp_lane_free(lane);
}

static void
test_syn_isn_mismatch_replaces_marker_raw_to_tcp(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x1237ULL, NULL, NULL, NULL);
    ASSERT_TRUE(lane != NULL, "lane_new succeeds");

    mqvpn_flow_key_t k = make_key(4005, 443);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0, 300), 0,
                  "sticky-RAW marker, ISN 300");

    /* Different ISN, and this time the re-run policy lands on TCP (e.g. a
     * second path came up between the two connections). */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 1, 400), 0,
                  "on_syn succeeds — RAW marker replaced by a real TCP-lane flow");

    int out_raw = -1, out_closing = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, &out_closing), 1,
                  "lookup finds the new entry");
    ASSERT_EQ_INT(out_raw, 0, "no longer sticky-RAW");
    ASSERT_EQ_INT(out_closing, 0, "not CLOSING either — a fresh PENDING_ACCEPT flow");
    ASSERT_EQ_INT(mqvpn_tcp_lane_marker_isn(lane, &k), 0,
                  "marker_isn is 0 now — this key is a real flow, not a marker");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 1, "counts as an active TCP-lane flow");
    ASSERT_EQ_INT(stats.raw_markers_active, 0,
                  "the old marker is gone, not just shadowed");
    ASSERT_EQ_INT(stats.flows_rejected_other, 0, "NOT a caller-bug duplicate");

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
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k1, 1, 0), 0, "first on_syn succeeds");

    mqvpn_flow_key_t k2 = make_key(5001, 80);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k2, 1, 0), -1,
                  "second on_syn rejected at cap");
    /* Rejection means NO insertion: the rejected key must stay absent. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k2, NULL, NULL), 0,
                  "rejected key not inserted (lookup miss)");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_rejected_cap, 1, "flows_rejected_cap == 1");

    /* Split-cap: a sticky-RAW marker is NOT blocked by the (full) TCP flow
     * cap and does not count as a TCP-lane rejection. */
    mqvpn_flow_key_t k3 = make_key(5002, 80);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k3, 0, 0), 0,
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
        ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0, 0), 0,
                      "sticky-RAW marker succeeds");
    }

    /* ...then a TCP-lane flow still fits: markers spent none of the budget. */
    mqvpn_flow_key_t kt = make_key(7000, 443);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &kt, 1, 0), 0,
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
        ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0, 0), 0,
                      "marker succeeds below cap");
    }

    /* Next marker is refused: -1, silent (no flows_rejected_cap), no insert. */
    mqvpn_flow_key_t kx = make_key(8999, 80);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &kx, 0, 0), -1,
                  "marker rejected at marker cap");
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &kx, NULL, NULL), 0,
                  "rejected marker key not inserted (lookup miss)");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_rejected_cap, 0,
                  "marker-cap hit is not a TCP-lane rejection");
    ASSERT_EQ_INT(stats.raw_markers_active, TCP_LANE_RAW_MARKER_CAP,
                  "raw_markers_active stays at cap");

    /* TCP-lane commits are unaffected by the full marker table. */
    mqvpn_flow_key_t kt = make_key(9000, 443);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &kt, 1, 0), 0,
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
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &key, 1, 0), 0, "SYN-time commit");

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

    /* Non-2xx response on a second bound flow: PENDING_STREAM -> full
     * teardown (Task 12: RST the pcb, RST the H3 request, remove from the
     * table — no longer a CLOSING-and-inert state, since on_stream_rejected
     * now does the real locally-initiated kill). Key must match the pcb2
     * 5-tuple below (10.0.0.1:4002 -> 93.184.216.34:80 — the same addresses
     * test_accept_key_correspondence's first flow uses, NOT make_key()'s
     * generic 10.0.0.1/10.0.0.2), since the accept callback rebuilds the key
     * from the pcb's local/remote ip/port. */
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
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &key2, 1, 0), 0,
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
    /* f2 is freed as of the call above — do not touch it again. The hooked
     * MQVPN_TCP_LANE_TCP_ABORT is what makes this safe on pcb2 (a stack
     * fake, not a real pool pcb) — no manual `f2->pcb = NULL` dodge needed
     * anymore. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key2, NULL, NULL), 0,
                  "rejected flow fully removed from the table");
    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "pcb2 aborted on rejection");
    ASSERT_TRUE(g_tcp_abort_last_pcb == &pcb2, "the RIGHT pcb was aborted");
    ASSERT_EQ_INT(g_h3_close_calls, 1, "H3 request2 RST on rejection");
    ASSERT_TRUE(g_h3_close_last_req == &fake_req2, "the RIGHT request was RST");
    /* Rejecting/activating an unrelated stream must not disturb the first
     * flow (a DIFFERENT flow, never touched by any of the above). */
    ASSERT_EQ_INT(f->state, TCP_FLOW_ACTIVE,
                  "first flow unaffected by second flow's rejection");

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

/* Shared post-fatal-error checks (Task 12 contract change): pins
 * mqvpn_tcp_lane_on_relay_error's FULL teardown — RST the pcb (via the
 * hooked MQVPN_TCP_LANE_TCP_ABORT), RST the H3 request, and remove the flow
 * from the table entirely. This REPLACES the pre-Task-12 contract (flow
 * sits CLOSING-and-inert, still dereferenceable) — on_relay_error now frees
 * the flow synchronously inside the triggering call, so there is no `f` left
 * to pass in: identify what used to be the flow by its key/pcb/h3_request
 * instead. Every one of assert_flow_failed_closed's call sites must NOT
 * touch its `f`/`fN` variable again after the triggering call (it's a
 * dangling pointer) — this is why the callers below no longer have a
 * trailing `f->pcb = NULL;` line: the pcb was already detached+aborted
 * (via the hook) inside the very call that triggered this assertion. */
static void
assert_flow_failed_closed(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key,
                          struct tcp_pcb *pcb, void *h3_request)
{
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, key, NULL, NULL), 0,
                  "flow fully removed from the table on relay error (lookup miss)");
    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "pcb aborted exactly once");
    ASSERT_TRUE(g_tcp_abort_last_pcb == pcb, "the RIGHT pcb was aborted");
    ASSERT_EQ_INT(g_h3_close_calls, 1, "H3 request RST exactly once");
    ASSERT_TRUE(g_h3_close_last_req == h3_request, "the RIGHT request was RST");
}

static void
test_relay_fatal_error_paths(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);

    /* (a) Fatal error on the ACTIVE fast-path send (first attempt, empty
     * queue — the recv callback's direct send_from). */
    relay_reset();
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0x9999ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 5900, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    h3_script_push(MQVPN_TCP_LANE_H3_SEND_ERR);
    struct pbuf *p = mk_pbuf(500);
    /* CRITICAL contract (lwIP tcp_in.c): the teardown inside this call
     * tcp_abort()ed pcb, so the recv frame MUST return ERR_ABRT — on
     * ERR_OK the core would continue into TF_GOT_FIN/tcp_output on the
     * freed pcb. ERR_ABRT despite the consumed pbuf matches convention
     * (lwIP gives up its inseg reference on the aborted path too). */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p, ERR_OK), ERR_ABRT,
                  "recv frame returns ERR_ABRT after aborting its own pcb");
    g_expected_len -= 500; /* bytes were never relayed; keep mirror aligned */
    ASSERT_EQ_INT(g_h3_capture_len, 0, "no bytes captured on immediate fatal error");
    /* f is freed as of the call above — do not touch it again. */
    mqvpn_flow_key_t key_a = mk_std_key(5900);
    assert_flow_failed_closed(lane, &key_a, &pcb, &fake_req);

    /* (b) Fatal error mid-flush with a non-empty queue: EAGAIN builds a
     * 2-node backlog, then the writable retry hits the hard error — BOTH
     * queued nodes must be freed, not just the failing head. */
    relay_reset();
    struct tcp_pcb pcb2;
    int fake_req2, fake_stream2;
    mqvpn_tcp_flow_t *f2 = setup_flow(lane, &pcb2, 5901, &fake_req2, &fake_stream2, 1);
    ASSERT_TRUE(f2 != NULL, "flow established");

    h3_script_push(MQVPN_TCP_LANE_H3_SEND_AGAIN);
    struct pbuf *q1 = mk_pbuf(700);
    struct pbuf *q2 = mk_pbuf(800);
    mqvpn_tcp_lane_on_lwip_recv(f2, &pcb2, q1, ERR_OK); /* EAGAIN -> stash */
    mqvpn_tcp_lane_on_lwip_recv(f2, &pcb2, q2, ERR_OK); /* backlog -> stash */
    ASSERT_EQ_INT(f2->uplink_queued_bytes, 1500, "two nodes backlogged");
    ASSERT_EQ_INT(f2->uplink_withheld, 1, "withheld under backpressure");

    h3_script_push(MQVPN_TCP_LANE_H3_SEND_ERR);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_h3_writable(lane, &fake_stream2), 0,
                  "writable returns 0 even when the retry hits a fatal error");
    g_expected_len -= 1500;
    ASSERT_EQ_INT(g_h3_capture_len, 0, "nothing relayed before the mid-flush error");
    /* f2 is freed as of the call above — do not touch it again. */
    mqvpn_flow_key_t key_b = mk_std_key(5901);
    assert_flow_failed_closed(lane, &key_b, &pcb2, &fake_req2);

    /* (c) Fatal error on the FIN send (empty queue, recv(NULL) drives
     * maybe_fin directly): must also fail closed, NOT stay ACTIVE with a
     * FIN that can never be delivered. */
    relay_reset();
    struct tcp_pcb pcb3;
    int fake_req3, fake_stream3;
    mqvpn_tcp_flow_t *f3 = setup_flow(lane, &pcb3, 5902, &fake_req3, &fake_stream3, 1);
    ASSERT_TRUE(f3 != NULL, "flow established");
    ASSERT_TRUE(f3->uplink_q_head == NULL, "queue starts empty");

    h3_script_push(MQVPN_TCP_LANE_H3_SEND_ERR);
    /* Same lwIP ERR_ABRT contract as case (a) — the FIN branch's flush ->
     * maybe_fin fatal path tcp_abort()ed pcb3 inside this recv frame. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_recv(f3, &pcb3, NULL, ERR_OK), ERR_ABRT,
                  "recv(NULL) frame returns ERR_ABRT when the fin-send teardown "
                  "aborted its pcb");
    /* f3 is freed as of the call above (on_relay_error runs synchronously
     * inside maybe_fin's fatal-send branch) — do not touch it again; the
     * pre-Task-12 checks here ("tcp_fin_seen latched", "fin NOT marked
     * sent") observed f3's intermediate state and are no longer possible to
     * assert. g_h3_fin_attempts (a global counter, not a flow field) still
     * pins that exactly one fin attempt was made before the failure. */
    ASSERT_EQ_INT(g_h3_fin_attempts, 1, "exactly one fin attempt");
    mqvpn_flow_key_t key_c = mk_std_key(5902);
    assert_flow_failed_closed(lane, &key_c, &pcb3, &fake_req3);

    mqvpn_tcp_lane_free(lane);
}

static void
test_relay_lane_free_with_queued_backlog(void)
{
    /* Teardown-owns-the-queue: lane_free on a flow with ~90 KB still queued
     * must free every node AND pbuf (tcp_lane_uplink_queue_free runs in the
     * teardown loop). Leak-checked by the sanitizer build; the normal run
     * still pins "no crash / no double-free". Same shape as
     * test_relay_repeated_eagain_writable but WITHOUT the final draining
     * writable notify. */
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xaaaaULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 6000, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    h3_script_push(MQVPN_TCP_LANE_H3_SEND_AGAIN);
    struct pbuf *p1 = mk_pbuf(30000);
    struct pbuf *p2 = mk_pbuf(30000);
    struct pbuf *p3 = mk_pbuf(30000);
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p1, ERR_OK);
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p2, ERR_OK);
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p3, ERR_OK);
    ASSERT_EQ_INT(f->uplink_queued_bytes, 90000, "90 KB backlogged, never drained");
    ASSERT_TRUE(f->uplink_q_head != NULL, "queue non-empty at teardown");
    g_expected_len -= 90000; /* never relayed */

    f->pcb = NULL; /* stack-fake pcb, detach before the abort loop */
    mqvpn_tcp_lane_free(lane);
    /* Success criterion beyond "didn't crash" is the sanitizer build: ASan
     * flags any leaked pbuf/node or double pbuf_free here. */
    ASSERT_TRUE(1, "lane_free with a queued backlog completed");
}

static void
test_relay_fin_during_pending_stream(void)
{
    /* Data + FIN both arrive PRE-2xx (PENDING_STREAM): nothing may be sent
     * before the gate; on establish the flush must send the data first and
     * the fin strictly last. The fin's first attempt is scripted EAGAIN to
     * also cover maybe_fin's AGAIN branch (fin stays pending — tcp_fin_seen
     * && !fin_sent_to_h3 IS the retry state) and its writable-notify
     * completion. */
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xbbbbULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f =
        setup_flow(lane, &pcb, 6100, &fake_req, &fake_stream, 0 /* pre-2xx */);
    ASSERT_TRUE(f != NULL, "flow bound, PENDING_STREAM");

    struct pbuf *p = mk_pbuf(600);
    mqvpn_tcp_lane_on_lwip_recv(f, &pcb, p, ERR_OK);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_recv(f, &pcb, NULL, ERR_OK), ERR_OK,
                  "recv(NULL) pre-2xx tolerated");
    ASSERT_EQ_INT(f->tcp_fin_seen, 1, "tcp_fin_seen latched while PENDING_STREAM");
    ASSERT_EQ_INT(g_h3_send_calls, 0, "no data AND no fin sent before the 2xx gate");
    ASSERT_EQ_INT(f->uplink_queued_bytes, 600, "data buffered pre-2xx");

    /* 2xx: flush sends the data (script[0] full accept), then the fin
     * attempt gets script[1] = AGAIN -> stays pending. */
    h3_script_push(600);
    h3_script_push(MQVPN_TCP_LANE_H3_SEND_AGAIN);
    mqvpn_tcp_lane_on_stream_established(lane, &fake_stream);

    ASSERT_EQ_INT(f->state, TCP_FLOW_ACTIVE, "established");
    ASSERT_EQ_INT(g_h3_capture_len, 600, "data relayed on establish");
    ASSERT_TRUE(memcmp(g_h3_capture, g_expected, 600) == 0, "data byte-exact");
    ASSERT_EQ_INT(g_h3_fin_attempts, 1, "fin attempted after the data drained");
    ASSERT_EQ_INT(f->fin_sent_to_h3, 0, "fin still pending after EAGAIN");
    ASSERT_TRUE(f->uplink_q_head == NULL, "data queue empty — only the fin is pending");

    /* Writable notify: queue already empty, so flush goes straight to
     * maybe_fin; script exhausted -> accepted. */
    mqvpn_tcp_lane_on_h3_writable(lane, &fake_stream);

    ASSERT_EQ_INT(f->fin_sent_to_h3, 1, "fin sent on the writable retry");
    ASSERT_EQ_INT(g_h3_fin_attempts, 2, "exactly one fin retry");
    ASSERT_EQ_INT(g_h3_log_len, 3, "data + fin(EAGAIN) + fin(accepted)");
    ASSERT_TRUE(g_h3_log[0].len == 600 && g_h3_log[0].fin == 0,
                "log[0]: the data send, before any fin");
    ASSERT_TRUE(g_h3_log[1].len == 0 && g_h3_log[1].fin == 1 && g_h3_log[1].ret < 0,
                "log[1]: first fin attempt, EAGAIN");
    ASSERT_TRUE(g_h3_log[2].len == 0 && g_h3_log[2].fin == 1 && g_h3_log[2].ret >= 0,
                "log[2]: fin strictly last, accepted");
    ASSERT_EQ_INT(g_h3_capture_len, 600, "no data duplication around the fin retries");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

/* ─── Task 11: downlink relay (H3 recv_body -> lwIP tcp_write) ───
 *
 * Same fixtures/idioms as the Task 10 uplink section above: setup_flow()
 * for a bound+established flow, relay_reset() before every test, byte-exact
 * assertions against a rolling g_seq pattern (mk_dl_bytes here instead of
 * mk_pbuf — the "source" is a scripted H3 recv_body delivery, not a pbuf). */

static void
test_downlink_basic(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xd001ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 7100, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    const uint8_t *c1 = mk_dl_bytes(500);
    const uint8_t *c2 = mk_dl_bytes(300);
    h3_recv_push_data(c1, 500, 0);
    h3_recv_push_data(c2, 300, 0);
    /* script exhausted after these two -> AGAIN, pump loop terminates */

    ASSERT_EQ_INT(mqvpn_tcp_lane_downlink_pump(lane, &fake_stream), 0, "pump returns 0");

    ASSERT_EQ_INT(g_tcp_write_calls, 2, "one tcp_write per scripted chunk");
    ASSERT_EQ_INT(g_tcp_write_capture_len, 800, "both chunks written");
    ASSERT_TRUE(memcmp(g_tcp_write_capture, g_expected, 800) == 0,
                "byte-exact relay, no dup/gap");
    ASSERT_EQ_INT(g_tcp_output_calls, 1,
                  "tcp_output called exactly once per pump, not once per write");
    ASSERT_EQ_INT(f->downlink_paused, 0, "not paused");
    ASSERT_EQ_INT(f->fin_received_from_h3, 0, "no fin yet");
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 0, "no shutdown without fin");

    /* NULL/unknown-stream tolerance, mirrors on_h3_writable's coverage. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_downlink_pump(NULL, &fake_stream), 0,
                  "NULL lane tolerated");
    ASSERT_EQ_INT(mqvpn_tcp_lane_downlink_pump(lane, NULL), 0, "NULL stream tolerated");
    int unrelated;
    ASSERT_EQ_INT(mqvpn_tcp_lane_downlink_pump(lane, &unrelated), 0,
                  "unknown stream tolerated");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_downlink_err_mem_stash_and_resume(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xd002ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 7200, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    const uint8_t *c1 = mk_dl_bytes(400);
    const uint8_t *c2 = mk_dl_bytes(600);
    h3_recv_push_data(c1, 400, 0);
    h3_recv_push_data(c2, 600, 0);
    tw_script_push(ERR_MEM); /* first tcp_write fails transiently */

    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);

    ASSERT_EQ_INT(g_h3_recv_calls, 1,
                  "recv stopped after the failed write — c2 not read yet");
    ASSERT_EQ_INT(g_tcp_write_calls, 1, "one write attempt");
    ASSERT_EQ_INT(g_tcp_write_capture_len, 0, "nothing captured on ERR_MEM");
    ASSERT_EQ_INT(f->downlink_paused, 1, "paused on ERR_MEM");
    ASSERT_TRUE(f->downlink_stash != NULL, "stash allocated");
    ASSERT_EQ_INT(f->downlink_stash_len, 400, "stash holds the failed chunk");
    ASSERT_EQ_INT(g_tcp_output_calls, 0, "no output attempted — nothing was written");

    /* M1: a pump call while paused now attempts the stash retry INLINE
     * (guarded — tcp_lane_downlink_stash_retry, never a recursive call
     * back into the pump) instead of unconditionally waiting for
     * on_lwip_sent — an ERR_MEM'd retry must not be stranded until a
     * sent-notify that may never come. Script a SECOND transient failure
     * first to pin the "still blocked" sub-case: the retry is attempted
     * (write call count increments) but the drain does NOT resume. */
    tw_script_push(ERR_MEM);
    ASSERT_EQ_INT(mqvpn_tcp_lane_downlink_pump(lane, &fake_stream), 0,
                  "pump while paused returns 0 (flow still live either way)");
    ASSERT_EQ_INT(g_tcp_write_calls, 2, "retry attempted, still fails");
    ASSERT_EQ_INT(g_tcp_write_capture_len, 0, "nothing captured — retry failed again");
    ASSERT_EQ_INT(f->downlink_paused, 1, "still paused — retry failed");
    ASSERT_EQ_INT(g_h3_recv_calls, 1, "drain not resumed while still paused");

    /* Now let the retry succeed (no more scripted failures, ample sndbuf):
     * a pump call — NOT on_lwip_sent — flushes the stash and resumes
     * draining recv_body for c2, entirely via the xquic-notify path. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_downlink_pump(lane, &fake_stream), 0,
                  "pump succeeds once room is available");

    ASSERT_EQ_INT(f->downlink_paused, 0, "resumed");
    ASSERT_EQ_INT(f->downlink_stash_len, 0, "stash slot drained");
    ASSERT_EQ_INT(g_tcp_write_calls, 4,
                  "2 failed attempts + stash flush + the resumed drain's write for c2");
    ASSERT_EQ_INT(g_tcp_write_capture_len, 1000, "both chunks eventually written");
    ASSERT_TRUE(
        memcmp(g_tcp_write_capture, g_expected, 1000) == 0,
        "byte-exact whole stream: stash (c1) flushed BEFORE the resumed drain (c2)");
    /* 3, not 2: c1 (before the pause) + c2 (on resume) + one more call that
     * returns AGAIN (the drain loop always re-checks after the last real
     * chunk to confirm it's actually drained, per the recv contract). */
    ASSERT_EQ_INT(g_h3_recv_calls, 3, "c2 read on resume, then AGAIN confirms drained");
    ASSERT_TRUE(g_tcp_output_calls >= 1,
                "tcp_output called on the flush and/or resumed pump");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

/* M1 regression pin: the SAME stash-retry helper is still reachable from
 * on_lwip_sent (the real sent-notify), not just from the pump entry point
 * exercised above — a paused flow that receives NO further xquic-side
 * notify (nothing more buffered upstream) must still resume once the pcb
 * itself signals room via tcp_sent. */
static void
test_downlink_sent_notify_still_resumes(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xd0021ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 7201, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    const uint8_t *c1 = mk_dl_bytes(400);
    h3_recv_push_data(c1, 400, 0);
    tw_script_push(ERR_MEM);
    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);
    ASSERT_EQ_INT(f->downlink_paused, 1, "paused on ERR_MEM");
    ASSERT_EQ_INT(f->downlink_stash_len, 400, "stash holds the failed chunk");

    /* No further pump call — only the sent-notify fires. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_sent(f, &pcb, 0), ERR_OK,
                  "sent notify tolerated");
    ASSERT_EQ_INT(f->downlink_paused, 0, "resumed via on_lwip_sent alone");
    ASSERT_EQ_INT(g_tcp_write_capture_len, 400, "stash flushed");
    ASSERT_TRUE(memcmp(g_tcp_write_capture, g_expected, 400) == 0, "byte-exact");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_downlink_sndbuf_gate(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xd003ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 7300, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    /* First notify: ample sndbuf, chunk fits and writes normally. */
    const uint8_t *c1 = mk_dl_bytes(200);
    h3_recv_push_data(c1, 200, 0);
    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);
    ASSERT_EQ_INT(g_tcp_write_calls, 1, "first chunk written");
    ASSERT_EQ_INT(g_tcp_write_capture_len, 200, "first chunk captured");
    ASSERT_EQ_INT(f->downlink_paused, 0, "not paused after the first chunk");

    /* Second notify: sndbuf has since shrunk below the chunk size — the
     * SNDBUF gate must catch this BEFORE ever attempting tcp_write (distinct
     * code path from the ERR_MEM-after-attempt case above). */
    h3_recv_script_clear();
    g_tcp_sndbuf_value = 50;
    const uint8_t *c2 = mk_dl_bytes(300);
    h3_recv_push_data(c2, 300, 0);
    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);

    ASSERT_EQ_INT(g_tcp_write_calls, 1,
                  "no tcp_write attempt for the sndbuf-blocked chunk");
    ASSERT_EQ_INT(g_tcp_write_capture_len, 200,
                  "capture unchanged — second chunk not written");
    ASSERT_EQ_INT(f->downlink_paused, 1, "paused on the sndbuf gate");
    ASSERT_TRUE(f->downlink_stash != NULL, "stash allocated");
    ASSERT_EQ_INT(f->downlink_stash_len, 300, "stash holds the blocked chunk");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_downlink_fin_with_data(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xd004ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 7400, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    const uint8_t *c1 = mk_dl_bytes(250);
    h3_recv_push_data(c1, 250, 1); /* fin delivered WITH the final data chunk */

    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);

    ASSERT_EQ_INT(g_tcp_write_calls, 1, "the data was written");
    ASSERT_EQ_INT(g_tcp_write_capture_len, 250, "all 250 bytes captured");
    ASSERT_TRUE(memcmp(g_tcp_write_capture, g_expected, 250) == 0, "byte-exact");
    ASSERT_EQ_INT(f->fin_received_from_h3, 1, "fin_received_from_h3 set");
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 1, "tcp_shutdown called exactly once");
    ASSERT_EQ_INT(g_tcp_shutdown_last_rx, 0, "shut_rx == 0 (TX-side half-close only)");
    ASSERT_EQ_INT(g_tcp_shutdown_last_tx, 1, "shut_tx == 1");
    ASSERT_EQ_INT(g_tcp_output_calls, 1, "output flushed for the data write");

    /* A further pump call must not re-fire tcp_shutdown (idempotent via
     * fin_received_from_h3), even if somehow re-notified. */
    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 1, "shutdown not re-fired on a later pump");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_downlink_fin_only(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xd005ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 7500, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    h3_recv_push_data(NULL, 0, 1); /* bare fin, no data */

    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);

    ASSERT_EQ_INT(g_tcp_write_calls, 0, "no data means no tcp_write attempt");
    ASSERT_EQ_INT(f->fin_received_from_h3, 1, "fin_received_from_h3 set");
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 1, "tcp_shutdown called exactly once");
    ASSERT_EQ_INT(g_tcp_output_calls, 0,
                  "tcp_output NOT called — nothing was written this pump");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_downlink_fin_while_paused(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xd006ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 7600, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    /* c2 carries the fin but sits UNREAD behind the pause — the pump stops
     * consuming recv_body the instant c1's write fails, so it never even
     * gets to look at c2 yet. This is the "fin still undelivered in xquic's
     * buffer at pause time" scenario the reconciliation note calls out. */
    const uint8_t *c1 = mk_dl_bytes(300);
    const uint8_t *c2 = mk_dl_bytes(200);
    h3_recv_push_data(c1, 300, 0);
    h3_recv_push_data(c2, 200, 1);
    tw_script_push(ERR_MEM);

    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);

    ASSERT_EQ_INT(g_h3_recv_calls, 1, "only c1 read before the pause");
    ASSERT_EQ_INT(f->downlink_paused, 1, "paused");
    ASSERT_EQ_INT(f->downlink_stash_len, 300, "c1 stashed");
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 0, "fin not reached yet — no shutdown");
    ASSERT_EQ_INT(f->fin_received_from_h3, 0, "fin not observed yet");

    /* Resume: stash flush writes c1, then the pump's own resume call reads
     * and writes c2, observes fin, and shuts down — the fin is never lost. */
    g_tcp_sndbuf_value = 0xFFFFu;
    mqvpn_tcp_lane_on_lwip_sent(f, &pcb, 0);

    ASSERT_EQ_INT(f->downlink_paused, 0, "resumed");
    ASSERT_EQ_INT(g_h3_recv_calls, 2, "c2 read on resume");
    ASSERT_EQ_INT(g_tcp_write_capture_len, 500,
                  "both chunks written, byte-exact whole stream");
    ASSERT_TRUE(memcmp(g_tcp_write_capture, g_expected, 500) == 0,
                "c1 then c2, no dup/gap");
    ASSERT_EQ_INT(f->fin_received_from_h3, 1, "fin observed on resume");
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 1, "shutdown fired on resume — fin never lost");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_downlink_fin_stashed_with_data(void)
{
    /* The OTHER fin-across-pause shape (vs test_downlink_fin_while_paused's
     * fin-still-unread): the fin arrives ON the very chunk whose tcp_write
     * fails. The drain stashes the chunk and BREAKS BEFORE its fin check —
     * the local fin flag is deliberately discarded, relying on recv's
     * level-triggered re-report (tcp_lane.h H3_RECV contract,
     * xqc_h3_request.c:795-801) at the resumed drain. This test is what
     * makes that reliance a pinned regression: an edge-triggered recv (or a
     * future drain refactor that honors only an edge-triggered reading of
     * the contract) loses the FIN here and never reaches tcp_shutdown. */
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xd009ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 7900, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    const uint8_t *c1 = mk_dl_bytes(350);
    h3_recv_push_data(c1, 350, 1); /* data + fin in the SAME delivery */
    tw_script_push(ERR_MEM);       /* ...and its write fails */

    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);

    ASSERT_EQ_INT(f->downlink_paused, 1, "paused on the failed write");
    ASSERT_EQ_INT(f->downlink_stash_len, 350, "data+fin chunk stashed");
    ASSERT_EQ_INT(f->fin_received_from_h3, 0,
                  "local fin dropped at the stash boundary — not yet acted on");
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 0, "no shutdown before the data is delivered");

    /* Resume: stash flush writes the data, the resumed pump's recv gets the
     * level-triggered 0-byte fin re-report, and shutdown fires. */
    g_tcp_sndbuf_value = 0xFFFFu;
    mqvpn_tcp_lane_on_lwip_sent(f, &pcb, 0);

    ASSERT_EQ_INT(f->downlink_paused, 0, "resumed");
    ASSERT_EQ_INT(g_tcp_write_capture_len, 350, "the stashed chunk written on resume");
    ASSERT_TRUE(memcmp(g_tcp_write_capture, g_expected, 350) == 0, "byte-exact");
    ASSERT_EQ_INT(f->fin_received_from_h3, 1, "fin recovered via the re-report");
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 1,
                  "tcp_shutdown exactly once — fin not lost across the stash boundary");
    ASSERT_EQ_INT(g_tcp_shutdown_last_tx, 1, "TX-side half-close");

    /* And a further pump stays idempotent even though recv keeps
     * re-reporting fin=1 forever (level-triggered). */
    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 1, "no shutdown re-fire on later pumps");

    f->pcb = NULL;
    mqvpn_tcp_lane_free(lane);
}

static void
test_downlink_fatal_recv_error(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xd007ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 7700, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    h3_recv_push_err();
    ASSERT_EQ_INT(mqvpn_tcp_lane_downlink_pump(lane, &fake_stream), -1,
                  "pump returns -1 on a fatal recv error");
    ASSERT_EQ_INT(g_tcp_write_calls, 0, "no write attempted");

    /* f is freed as of the call above — do not touch it again. */
    mqvpn_flow_key_t key = mk_std_key(7700);
    assert_flow_failed_closed(lane, &key, &pcb, &fake_req);
    mqvpn_tcp_lane_free(lane);
}

static void
test_downlink_pump_on_torn_down_flow(void)
{
    /* Task 12 contract change: a flow that a prior event already killed
     * (here, on_stream_rejected) is no longer "sitting CLOSING and
     * inert" (test_downlink_pump_on_closing_flow's pre-Task-12 name/shape)
     * — it is REMOVED from the table entirely. A later downlink_pump call
     * against the same (now-unknown) stream must therefore land on the
     * ordinary "unknown stream" no-op path (find_flow_by_stream misses),
     * observably identical (0 return, no recv_body/write/output calls) but
     * via a different internal reason. */
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xd008ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 7800, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    mqvpn_tcp_lane_on_stream_rejected(lane, &fake_stream);
    /* f is freed as of the call above — do not touch it again. */
    mqvpn_flow_key_t key = mk_std_key(7800);
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, NULL, NULL), 0,
                  "rejected flow fully removed");
    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "pcb aborted on rejection");
    ASSERT_TRUE(g_tcp_abort_last_pcb == &pcb, "the RIGHT pcb was aborted");
    ASSERT_EQ_INT(g_h3_close_calls, 1, "H3 request RST on rejection");
    ASSERT_TRUE(g_h3_close_last_req == &fake_req, "the RIGHT request was RST");

    const uint8_t *c1 = mk_dl_bytes(100);
    h3_recv_push_data(c1, 100, 0);

    ASSERT_EQ_INT(mqvpn_tcp_lane_downlink_pump(lane, &fake_stream), 0,
                  "pump on a removed flow's stream returns 0");
    ASSERT_EQ_INT(g_h3_recv_calls, 0, "recv_body never called — unknown stream");
    ASSERT_EQ_INT(g_tcp_write_calls, 0, "no write for an unknown stream");
    ASSERT_EQ_INT(g_tcp_output_calls, 0, "no output for an unknown stream");

    mqvpn_tcp_lane_free(lane);
}

/* ─── Task 12: mqvpn_tcp_syn_flag pure-parser cases ───
 *
 * Carry-over from the header's inline helper (tcp_lane.h): only a single
 * "pure SYN" case existed before (test_accept_key_correspondence's crafted
 * packet), never a dedicated case sweep. Each case builds its own minimal
 * buffer rather than reusing that 40-byte fixture — the point here is the
 * IHL-derived-offset arithmetic and the length/version guards themselves,
 * independent of any particular 5-tuple. */
static void
test_tcp_syn_flag_cases(void)
{
    /* (a) Pure SYN, IHL=20 (no options): SYN set, ACK clear -> flow-starting. */
    {
        uint8_t pkt[34];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x45;       /* v4, IHL 5 (20 bytes) */
        pkt[20 + 13] = 0x02; /* SYN */
        ASSERT_TRUE(mqvpn_tcp_syn_flag(pkt, sizeof(pkt)), "pure SYN is flow-starting");
    }
    /* (b) SYN|ACK: NOT flow-starting (an inbound answer on the RAW downlink
     * for an unknown 5-tuple must not commit to the TCP lane). */
    {
        uint8_t pkt[34];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x45;
        pkt[20 + 13] = 0x12; /* SYN + ACK */
        ASSERT_TRUE(!mqvpn_tcp_syn_flag(pkt, sizeof(pkt)),
                    "SYN|ACK is NOT flow-starting");
    }
    /* (c) Truncated: len stops one byte short of the flags byte
     * (ihl + 14 == 34; providing only 33 must not read past the buffer). */
    {
        uint8_t pkt[33];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x45;
        ASSERT_TRUE(!mqvpn_tcp_syn_flag(pkt, sizeof(pkt)),
                    "truncated (len == ihl+13) is treated as non-SYN");
    }
    /* (d) IHL=24 (one 32-bit option word): the flags byte must be read at
     * the IHL-DERIVED offset (24+13=37), not a fixed offset — this is what
     * actually exercises the ihl arithmetic rather than just IHL=20's
     * common case. */
    {
        uint8_t pkt[38];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x46;       /* v4, IHL 6 (24 bytes) */
        pkt[24 + 13] = 0x02; /* SYN, at the ihl=24-derived offset */
        ASSERT_TRUE(mqvpn_tcp_syn_flag(pkt, sizeof(pkt)),
                    "SYN with a 24-byte IHL is flow-starting at the correct offset");
    }
    /* (e) IHL < 20 (invalid — the minimum IPv4 header is 20 bytes): must be
     * rejected before ever computing a flags-byte offset from it. */
    {
        uint8_t pkt[34];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x44; /* v4, IHL 4 (16 bytes) — invalid */
        pkt[20 + 13] =
            0x02; /* SYN, at what would be the IHL=20 offset — must not matter */
        ASSERT_TRUE(!mqvpn_tcp_syn_flag(pkt, sizeof(pkt)), "IHL < 20 is rejected");
    }
    /* (f) Chunk 3: IPv6 direct-base-NH TCP (base NH == TCP, guaranteed by
     * Chunk 2's classifier gate) is now flow-starting too, parsed at the
     * FIXED offset 40 (not IHL-derived — IPv6's fixed header is always 40
     * bytes and pkt[0]&0x0F is the traffic-class high nibble here, NOT an
     * IHL). Pure SYN -> flow-starting. */
    {
        uint8_t pkt[54]; /* 40-byte v6 header + 14 bytes of TCP header */
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x60;       /* version 6 */
        pkt[6] = 6;          /* Next Header: TCP (base NH gate) */
        pkt[40 + 13] = 0x02; /* SYN, at the fixed v6 offset */
        ASSERT_TRUE(mqvpn_tcp_syn_flag(pkt, sizeof(pkt)),
                    "v6 direct-TCP pure SYN is flow-starting at the fixed offset");
    }
    /* (g) IPv6 SYN|ACK: same non-flow-starting rule as v4 (e). */
    {
        uint8_t pkt[54];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x60;
        pkt[6] = 6;
        pkt[40 + 13] = 0x12; /* SYN + ACK */
        ASSERT_TRUE(!mqvpn_tcp_syn_flag(pkt, sizeof(pkt)),
                    "v6 SYN|ACK is NOT flow-starting");
    }
    /* (h) IPv6 too-short: len stops one byte short of the fixed flags-byte
     * offset (40 + 13 == 53; providing only 53 bytes must not read past the
     * buffer). */
    {
        uint8_t pkt[53];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x60;
        pkt[6] = 6;
        ASSERT_TRUE(!mqvpn_tcp_syn_flag(pkt, sizeof(pkt)),
                    "v6 truncated (len == 40+13) is treated as non-SYN");
    }
    /* (i) IPv6 packet whose base NH isn't TCP: the helper trusts the
     * PRECONDITION (Chunk 2's base-NH gate already ran) and does not
     * re-check pkt[6] itself — with the flags byte left at its zeroed
     * default this still correctly reads as non-SYN, exercising the fixed
     * v6 offset independent of the actual NH value. */
    {
        uint8_t pkt[54];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x60;
        pkt[6] = 17; /* Next Header: UDP */
        ASSERT_TRUE(!mqvpn_tcp_syn_flag(pkt, sizeof(pkt)),
                    "v6 non-TCP base NH with a zeroed flags byte is non-SYN");
    }
    /* (j) Neither v4 nor v6 (e.g. version 5): the dispatch's catch-all
     * "anything else -> 0" branch. */
    {
        uint8_t pkt[54];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x50; /* version 5 */
        pkt[40 + 13] = 0x02;
        ASSERT_TRUE(!mqvpn_tcp_syn_flag(pkt, sizeof(pkt)),
                    "version 5 (neither v4 nor v6) is rejected");
    }
}

/* ─── Chunk 3: mqvpn_tcp_syn_isn, IPv6 direct-TCP ───
 *
 * mqvpn_tcp_syn_isn had no dedicated packet-parsing unit test before this
 * chunk (only exercised indirectly through mqvpn_tcp_lane_on_syn, which
 * takes an already-computed ISN — see the I2 tests above). Pin the v6
 * fixed-offset-40 extraction explicitly: seq bytes at pkt[44..47], mirroring
 * the v4 ihl+4..ihl+7 idiom. */
static void
test_tcp_syn_isn_v6(void)
{
    uint8_t pkt[54];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60;       /* version 6 */
    pkt[6] = 6;          /* Next Header: TCP */
    pkt[40 + 13] = 0x02; /* SYN */
    pkt[40 + 4] = 0xde;
    pkt[40 + 5] = 0xad;
    pkt[40 + 6] = 0xbe;
    pkt[40 + 7] = 0xef;

    ASSERT_TRUE(mqvpn_tcp_syn_flag(pkt, sizeof(pkt)), "precondition: v6 pure SYN");
    ASSERT_EQ_INT(mqvpn_tcp_syn_isn(pkt, sizeof(pkt)), 0xdeadbeefu,
                  "v6 ISN read at the fixed offset (pkt[44..47])");
}

/* ─── Task 12: close/error mapping + flow removal ───
 *
 * Per-row coverage of the close-mapping table (tcp_lane.c's Task 12
 * section comment) plus the races/idempotence reconciliation D calls for.
 * test_relay_fatal_error_paths/test_downlink_fatal_recv_error above already
 * cover the "fatal relay error" row (assert_flow_failed_closed); the
 * rejection row is covered inline in test_accept_key_correspondence. What's
 * left: the lwIP-err row, the H3 closing-notify row (+ its idempotence),
 * abort_pending's real behavior, the clean bidi-FIN-completion row (both
 * orderings), and stats bookkeeping on removal. */

static void
test_lwip_err_teardown(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xe001ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 8100, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    /* In production lwIP has ALREADY freed pcb before invoking this
     * callback (vendored tcp_abandon) — the err_t value itself (RST vs.
     * timeout vs. any other internal error) is deliberately ignored. */
    mqvpn_tcp_lane_on_lwip_err(f, ERR_RST);
    /* f is freed as of the call above. */

    mqvpn_flow_key_t key = mk_std_key(8100);
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, NULL, NULL), 0,
                  "flow removed on lwIP-initiated err");
    /* The defining difference from every LOCALLY-initiated kill: no
     * tcp_abort here — lwIP already freed the pcb itself. */
    ASSERT_EQ_INT(g_tcp_abort_calls, 0, "no tcp_abort — lwIP already freed the pcb");
    ASSERT_EQ_INT(g_tcp_close_calls, 0, "no tcp_close either — not the graceful path");
    ASSERT_EQ_INT(g_h3_close_calls, 1, "H3 request RST on lwIP err");
    ASSERT_TRUE(g_h3_close_last_req == &fake_req, "the RIGHT request was RST");

    /* NULL arg tolerated (defensive). */
    mqvpn_tcp_lane_on_lwip_err(NULL, ERR_RST);
    ASSERT_EQ_INT(g_h3_close_calls, 1, "NULL arg is a no-op");

    mqvpn_tcp_lane_free(lane);
}

static void
test_h3_closing_notify_teardown(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xe002ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 8200, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    mqvpn_tcp_lane_on_h3_closing(lane, &fake_stream);
    /* f is freed as of the call above. */

    mqvpn_flow_key_t key = mk_std_key(8200);
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, NULL, NULL), 0,
                  "flow removed on H3 closing-notify");
    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "pcb aborted on closing-notify");
    ASSERT_TRUE(g_tcp_abort_last_pcb == &pcb, "the RIGHT pcb was aborted");
    /* Must NOT RST the H3 request again — it's already being reset by
     * xquic (that is WHY this notify fired in the first place). */
    ASSERT_EQ_INT(g_h3_close_calls, 0,
                  "H3 request NOT closed again on its own closing-notify");

    /* Idempotence (reconciliation D): a second closing-notify on the same,
     * already-removed stream is a no-op — no double-abort, no crash. */
    mqvpn_tcp_lane_on_h3_closing(lane, &fake_stream);
    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "no double-abort on a repeated closing-notify");
    ASSERT_EQ_INT(g_h3_close_calls, 0, "still no h3 close");

    /* Unknown stream / NULL args tolerated. */
    int unrelated;
    mqvpn_tcp_lane_on_h3_closing(lane, &unrelated);
    mqvpn_tcp_lane_on_h3_closing(NULL, &fake_stream);
    mqvpn_tcp_lane_on_h3_closing(lane, NULL);
    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "no side effects from the unknown/NULL calls");

    mqvpn_tcp_lane_free(lane);
}

static void
test_abort_pending_real(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xe003ULL, NULL, fake_clock, NULL);

    /* Case 1: abort BEFORE bind — no h3_request exists yet (the "no live H3
     * conn / stream calloc failure / xqc_h3_request_create failure" shapes
     * in cli_tcp_lane_open_stream, all pre-bind). */
    mqvpn_flow_key_t key1 = mk_std_key(8300);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &key1, 1, 0), 0, "flow1 SYN-time commit");
    struct tcp_pcb pcb1;
    memset(&pcb1, 0, sizeof(pcb1));
    pcb1.state = ESTABLISHED;
    IP4_ADDR(&pcb1.local_ip, 93, 184, 216, 34);
    IP4_ADDR(&pcb1.remote_ip, 10, 0, 0, 1);
    pcb1.local_port = 80;
    pcb1.remote_port = 8300;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lwip_accept(lane, &pcb1, ERR_OK), ERR_OK,
                  "flow1 accepted");
    mqvpn_tcp_flow_t *f1 = (mqvpn_tcp_flow_t *)g_open_stream_flow;

    ASSERT_EQ_INT(mqvpn_tcp_lane_abort_pending(f1), 1,
                  "abort_pending reports the pcb abort (accept frame needs "
                  "this to return ERR_ABRT)");
    /* f1 is freed as of the call above. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key1, NULL, NULL), 0, "flow1 removed");
    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "pcb1 aborted");
    ASSERT_TRUE(g_tcp_abort_last_pcb == &pcb1, "the RIGHT pcb was aborted");
    ASSERT_EQ_INT(g_h3_close_calls, 0, "abort_pending never closes H3 (none existed)");

    /* Case 2: abort AFTER bind — a request DOES exist (the send-headers-
     * failure shape: the caller already closed it itself before calling
     * abort_pending). abort_pending must still not close it again. */
    mqvpn_flow_key_t key2 = mk_std_key(8301);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &key2, 1, 0), 0, "flow2 SYN-time commit");
    struct tcp_pcb pcb2;
    memset(&pcb2, 0, sizeof(pcb2));
    pcb2.state = ESTABLISHED;
    IP4_ADDR(&pcb2.local_ip, 93, 184, 216, 34);
    IP4_ADDR(&pcb2.remote_ip, 10, 0, 0, 1);
    pcb2.local_port = 80;
    pcb2.remote_port = 8301;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lwip_accept(lane, &pcb2, ERR_OK), ERR_OK,
                  "flow2 accepted");
    mqvpn_tcp_flow_t *f2 = (mqvpn_tcp_flow_t *)g_open_stream_flow;
    int fake_req2, fake_stream2;
    mqvpn_tcp_lane_bind_h3_request(f2, &fake_req2, &fake_stream2);

    ASSERT_EQ_INT(mqvpn_tcp_lane_abort_pending(f2), 1,
                  "abort_pending reports the pcb abort in the post-bind shape too");
    /* f2 is freed as of the call above. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key2, NULL, NULL), 0, "flow2 removed");
    ASSERT_EQ_INT(g_tcp_abort_calls, 2, "pcb2 also aborted");
    ASSERT_TRUE(g_tcp_abort_last_pcb == &pcb2, "the RIGHT pcb was aborted");
    ASSERT_EQ_INT(g_h3_close_calls, 0,
                  "abort_pending STILL never closes H3, even with a bound request");

    /* NULL handle: no pcb to have aborted — must report 0 (the accept
     * frame then correctly does NOT claim ERR_ABRT). */
    ASSERT_EQ_INT(mqvpn_tcp_lane_abort_pending(NULL), 0, "NULL handle reports no abort");

    mqvpn_tcp_lane_free(lane);
}

/* Chain 1 of the Task 12 ERR_ABRT plumbing: lwIP accept frame ->
 * cli_tcp_lane_open_stream failure -> abort_pending -> tcp_abort(newpcb).
 * The accept callback MUST return ERR_ABRT — any other value makes lwIP's
 * tcp_process either keep using the freed pcb (ERR_OK -> tcp_receive) or
 * tcp_abort() it a second time (other non-OK values). Reachable in
 * production via the teardown race (no live H3 conn), request-create
 * failure, and send-headers failure — not just OOM. */
static void
test_accept_open_stream_fail_returns_abrt(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xe007ULL, NULL, fake_clock, NULL);

    mqvpn_flow_key_t key = mk_std_key(8700);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &key, 1, 0), 0, "SYN-time commit");
    struct tcp_pcb pcb;
    memset(&pcb, 0, sizeof(pcb));
    pcb.state = ESTABLISHED;
    IP4_ADDR(&pcb.local_ip, 93, 184, 216, 34);
    IP4_ADDR(&pcb.remote_ip, 10, 0, 0, 1);
    pcb.local_port = 80;
    pcb.remote_port = 8700;

    g_open_stream_fail = 1; /* stub routes through the REAL abort_pending */
    ASSERT_EQ_INT(mqvpn_tcp_lane_lwip_accept(lane, &pcb, ERR_OK), ERR_ABRT,
                  "accept frame returns ERR_ABRT after open-stream failure "
                  "aborted the pcb");
    g_open_stream_fail = 0;

    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "the pcb was aborted exactly once");
    ASSERT_TRUE(g_tcp_abort_last_pcb == &pcb, "the RIGHT pcb was aborted");
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, NULL, NULL), 0, "flow removed");
    ASSERT_EQ_INT(g_h3_close_calls, 0, "no H3 request existed to close");

    mqvpn_tcp_lane_free(lane);
}

/* Chain 4 of the Task 12 ERR_ABRT plumbing: lwIP sent frame. Two sub-chains:
 * (a) the stash-rewrite tcp_write hits a FATAL error (not ERR_MEM) ->
 * on_relay_error aborts the pcb inside on_lwip_sent; (b) the rewrite
 * succeeds but the RESUMED drain hits a fatal recv error -> the pump core
 * aborts the pcb inside on_lwip_sent. Both must surface as ERR_ABRT from
 * the sent callback — on ERR_OK, tcp_in.c's TCP_EVENT_SENT site continues
 * into recv_data/tcp_output on the freed pcb. */
static void
test_lwip_sent_teardown_returns_abrt(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);

    /* (a) stash-rewrite fatal. Pause the flow first via an ERR_MEM write. */
    relay_reset();
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xe008ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 8800, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    const uint8_t *c1 = mk_dl_bytes(300);
    h3_recv_push_data(c1, 300, 0);
    tw_script_push(ERR_MEM); /* pause: chunk stashed */
    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream);
    ASSERT_EQ_INT(f->downlink_paused, 1, "paused with a stashed chunk");
    g_expected_len -= 300; /* never written — teardown below discards it */

    tw_script_push(ERR_ARG); /* the rewrite attempt now fails FATALLY */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_sent(f, &pcb, 0), ERR_ABRT,
                  "sent frame returns ERR_ABRT when the stash rewrite's "
                  "teardown aborted its pcb");
    /* f is freed as of the call above. */
    mqvpn_flow_key_t key_a = mk_std_key(8800);
    assert_flow_failed_closed(lane, &key_a, &pcb, &fake_req);
    mqvpn_tcp_lane_free(lane);

    /* (b) resumed-drain fatal: rewrite succeeds, the resumed pump's recv
     * errors. */
    relay_reset();
    lane = mqvpn_tcp_lane_new(&cfg, 0xe009ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb2;
    int fake_req2, fake_stream2;
    mqvpn_tcp_flow_t *f2 = setup_flow(lane, &pcb2, 8801, &fake_req2, &fake_stream2, 1);
    ASSERT_TRUE(f2 != NULL, "flow established");

    const uint8_t *c2 = mk_dl_bytes(200);
    h3_recv_push_data(c2, 200, 0);
    tw_script_push(ERR_MEM); /* pause: chunk stashed */
    mqvpn_tcp_lane_downlink_pump(lane, &fake_stream2);
    ASSERT_EQ_INT(f2->downlink_paused, 1, "paused with a stashed chunk");

    h3_recv_push_err(); /* the resumed drain's first recv is fatal */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_sent(f2, &pcb2, 0), ERR_ABRT,
                  "sent frame returns ERR_ABRT when the resumed drain's "
                  "teardown aborted its pcb");
    /* f2 is freed as of the call above. The stash WAS written on the
     * successful rewrite before the fatal recv. */
    ASSERT_EQ_INT(g_tcp_write_capture_len, 200, "stash flushed before the fatal recv");
    ASSERT_TRUE(memcmp(g_tcp_write_capture, g_expected, 200) == 0, "byte-exact");
    mqvpn_flow_key_t key_b = mk_std_key(8801);
    assert_flow_failed_closed(lane, &key_b, &pcb2, &fake_req2);
    mqvpn_tcp_lane_free(lane);
}

static void
test_clean_close_uplink_fin_first(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xe004ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 8400, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    /* Uplink FIN first: the inner client's TCP FIN arrives, forwarded to H3
     * (accepted immediately — the h3_send test double defaults to
     * accept-everything). Only one side is done — no clean-close yet. */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_recv(f, &pcb, NULL, ERR_OK), ERR_OK,
                  "recv(NULL) tolerated");
    ASSERT_EQ_INT(f->fin_sent_to_h3, 1, "uplink fin forwarded to H3");
    ASSERT_EQ_INT(f->fin_received_from_h3, 0, "downlink fin not yet observed");
    ASSERT_EQ_INT(g_tcp_close_calls, 0, "not done yet — only one side FIN'd");

    /* Downlink FIN second: the H3 response body ends, forwarded to the pcb
     * via tcp_shutdown — THIS side observes both flags set and triggers the
     * clean close. -1 here reuses downlink_pump's "flow no longer live, do
     * not propagate as an xquic error" contract; it is not a failure. */
    h3_recv_push_data(NULL, 0, 1);
    ASSERT_EQ_INT(mqvpn_tcp_lane_downlink_pump(lane, &fake_stream), -1,
                  "pump signals the flow is gone (clean close, not an error)");
    /* f is freed as of the call above. */

    /* C1: the flow is NOT removed on a clean bidi-FIN completion — it
     * transitions to TCP_FLOW_CLOSING, a routing-residency marker. lookup
     * must still find it (found=1), report it as NOT sticky-RAW, and flag
     * it as CLOSING via *out_closing. */
    mqvpn_flow_key_t key = mk_std_key(8400);
    int out_raw = -1, out_closing = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, &out_raw, &out_closing), 1,
                  "flow stays in the table as a CLOSING routing marker (C1)");
    ASSERT_EQ_INT(out_raw, 0, "CLOSING is never reported as sticky-RAW");
    ASSERT_EQ_INT(out_closing, 1, "lookup reports the CLOSING marker");
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 1, "downlink tcp_shutdown called once");
    ASSERT_EQ_INT(g_tcp_shutdown_last_rx, 0, "shut_rx == 0");
    ASSERT_EQ_INT(g_tcp_shutdown_last_tx, 1, "shut_tx == 1");
    ASSERT_EQ_INT(g_tcp_close_calls, 1, "graceful tcp_close called exactly once");
    ASSERT_TRUE(g_tcp_close_last_pcb == &pcb, "the RIGHT pcb was closed");
    ASSERT_EQ_INT(g_tcp_abort_calls, 0, "NOT aborted — this is the graceful path");
    ASSERT_EQ_INT(g_h3_close_calls, 0, "NOT RST — both directions FIN'd cleanly");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 0,
                  "n_tcp_flows decremented — a CLOSING marker is not an active flow");
    ASSERT_EQ_INT(lane->n_closing, 1, "n_closing incremented for the new marker");

    mqvpn_tcp_lane_free(lane);
}

static void
test_clean_close_downlink_fin_first(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xe005ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 8500, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    /* Downlink FIN first: the H3 response body ends before the inner
     * client's TCP FIN arrives. Only one side is done — no clean-close. */
    h3_recv_push_data(NULL, 0, 1);
    ASSERT_EQ_INT(mqvpn_tcp_lane_downlink_pump(lane, &fake_stream), 0,
                  "pump completes normally — only one side FIN'd so far");
    ASSERT_EQ_INT(f->fin_received_from_h3, 1, "downlink fin forwarded to the pcb");
    ASSERT_EQ_INT(f->fin_sent_to_h3, 0, "uplink fin not yet observed");
    ASSERT_EQ_INT(g_tcp_close_calls, 0, "not done yet");

    /* Uplink FIN second: the inner client's TCP FIN arrives, forwarded to
     * H3 — THIS side observes both flags set and triggers the clean close.
     * ERR_OK, NOT ERR_ABRT, even though the flow is freed inside this
     * frame: the pcb was gracefully tcp_close()d (which does not free a
     * FIN_WAIT_1/LAST_ACK pcb), never tcp_abort()ed — falsely claiming
     * ERR_ABRT would make lwIP believe the pcb is gone and leak/stall it
     * (the GONE-vs-ABORTED distinction in tcp_lane_flow_status_t). */
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_lwip_recv(f, &pcb, NULL, ERR_OK), ERR_OK,
                  "clean-close recv(NULL) frame stays ERR_OK (pcb closed, not aborted)");
    /* f is freed as of the call above. */

    /* C1: same routing-residency transition as the uplink-FIN-first shape
     * above, just reached via the other ordering. */
    mqvpn_flow_key_t key = mk_std_key(8500);
    int out_raw = -1, out_closing = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, &out_raw, &out_closing), 1,
                  "flow stays in the table as a CLOSING routing marker (C1)");
    ASSERT_EQ_INT(out_raw, 0, "CLOSING is never reported as sticky-RAW");
    ASSERT_EQ_INT(out_closing, 1, "lookup reports the CLOSING marker");
    ASSERT_EQ_INT(g_tcp_shutdown_calls, 1, "downlink tcp_shutdown called once");
    ASSERT_EQ_INT(g_tcp_close_calls, 1, "graceful tcp_close called exactly once");
    ASSERT_TRUE(g_tcp_close_last_pcb == &pcb, "the RIGHT pcb was closed");
    ASSERT_EQ_INT(g_tcp_abort_calls, 0, "NOT aborted — this is the graceful path");
    ASSERT_EQ_INT(g_h3_close_calls, 0, "NOT RST — both directions FIN'd cleanly");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 0,
                  "n_tcp_flows decremented — a CLOSING marker is not an active flow");
    ASSERT_EQ_INT(lane->n_closing, 1, "n_closing incremented for the new marker");

    mqvpn_tcp_lane_free(lane);
}

static void
test_removal_updates_stats(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xe006ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 8600, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 1, "one active flow before removal");

    mqvpn_tcp_lane_abort_pending(f); /* any of the four teardown paths would do */
    /* f is freed as of the call above. */

    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 0, "flows_active decremented on removal");

    mqvpn_tcp_lane_free(lane);
}

/* ─── CLOSING routing-marker residency (C1) ───
 *
 * Drives a flow through the SAME clean bidi-FIN sequence
 * test_clean_close_uplink_fin_first pins, then exercises the grace sweep /
 * cap eviction / tuple-reuse paths on the resulting CLOSING marker. */

/* Establish + cleanly close (uplink-FIN-first shape) a flow, leaving it as
 * a TCP_FLOW_CLOSING routing marker still in the table — NOT freed. `pcb`
 * must be caller-owned stack memory that outlives the flow's ACTIVE phase
 * (same convention as setup_flow). */
static mqvpn_tcp_flow_t *
make_closing_flow(mqvpn_tcp_lane_t *lane, struct tcp_pcb *pcb, uint16_t src_port,
                  void *req, void *stream)
{
    mqvpn_tcp_flow_t *f = setup_flow(lane, pcb, src_port, req, stream, 1);
    if (!f) {
        return NULL;
    }
    mqvpn_tcp_lane_on_lwip_recv(f, pcb, NULL, ERR_OK); /* uplink fin -> H3 */
    h3_recv_push_data(NULL, 0, 1);                     /* downlink fin */
    mqvpn_tcp_lane_downlink_pump(lane, stream);        /* -> TCP_FLOW_CLOSING */
    return f;
}

static void
test_closing_grace_sweep_survives_then_expires(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf101ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = make_closing_flow(lane, &pcb, 9101, &fake_req, &fake_stream);
    ASSERT_TRUE(f != NULL, "flow reaches CLOSING");
    ASSERT_EQ_INT(lane->n_closing, 1, "n_closing == 1");

    mqvpn_flow_key_t key = mk_std_key(9101);

    /* Well within the grace window: survives. */
    g_fake_now += (TCP_LANE_CLOSING_GRACE_US - 1000000ULL);
    mqvpn_tcp_lane_tick(lane, g_fake_now);
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, NULL, NULL), 1,
                  "CLOSING marker survives a sweep within the grace window");
    ASSERT_EQ_INT(lane->n_closing, 1, "still 1");

    /* Past the grace window: swept. */
    g_fake_now += 2000000ULL;
    mqvpn_tcp_lane_tick(lane, g_fake_now);
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, NULL, NULL), 0,
                  "CLOSING marker swept once past TCP_LANE_CLOSING_GRACE_US");
    ASSERT_EQ_INT(lane->n_closing, 0, "n_closing decremented on sweep");

    mqvpn_tcp_lane_free(lane);
}

static void
test_closing_grace_sweep_runs_with_idle_timeout_zero(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 0; /* idle-eviction opt-out */
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf102ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = make_closing_flow(lane, &pcb, 9102, &fake_req, &fake_stream);
    ASSERT_TRUE(f != NULL, "flow reaches CLOSING");

    mqvpn_flow_key_t key = mk_std_key(9102);
    g_fake_now += TCP_LANE_CLOSING_GRACE_US + 1000000ULL;
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, NULL, NULL), 0,
                  "CLOSING grace sweep runs even with tcp_idle_timeout_sec == 0 — a "
                  "DIFFERENT mechanism/rationale than idle-eviction");
    ASSERT_EQ_INT(lane->n_closing, 0, "n_closing decremented");

    mqvpn_tcp_lane_free(lane);
}

static void
test_closing_cap_eviction(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf103ULL, NULL, fake_clock, NULL);

    struct tcp_pcb pcbs[TCP_LANE_CLOSING_CAP + 1];
    int reqs[TCP_LANE_CLOSING_CAP + 1], streams[TCP_LANE_CLOSING_CAP + 1];
    mqvpn_flow_key_t keys[TCP_LANE_CLOSING_CAP + 1];

    /* Fill the cap exactly, each one strictly newer than the last (distinct
     * last_activity_us stamps) so "oldest" is unambiguous. */
    for (uint16_t i = 0; i < TCP_LANE_CLOSING_CAP; i++) {
        keys[i] = mk_std_key((uint16_t)(9200 + i));
        mqvpn_tcp_flow_t *f = make_closing_flow(lane, &pcbs[i], (uint16_t)(9200 + i),
                                                &reqs[i], &streams[i]);
        ASSERT_TRUE(f != NULL, "closing flow created");
        g_fake_now += 1000000ULL; /* strictly increasing stamps */
    }
    ASSERT_EQ_INT(lane->n_closing, TCP_LANE_CLOSING_CAP, "at cap");
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &keys[0], NULL, NULL), 1,
                  "oldest still present, at cap");

    /* One more closing transition at cap: evicts the OLDEST (index 0)
     * immediately, not counted against flows_rejected_*. */
    uint16_t idx = TCP_LANE_CLOSING_CAP;
    keys[idx] = mk_std_key((uint16_t)(9200 + idx));
    mqvpn_tcp_flow_t *f = make_closing_flow(lane, &pcbs[idx], (uint16_t)(9200 + idx),
                                            &reqs[idx], &streams[idx]);
    ASSERT_TRUE(f != NULL, "cap-overflow closing flow created");

    ASSERT_EQ_INT(lane->n_closing, TCP_LANE_CLOSING_CAP, "still at cap — one evicted");
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &keys[0], NULL, NULL), 0,
                  "oldest CLOSING entry evicted on cap overflow");
    for (uint16_t i = 1; i <= TCP_LANE_CLOSING_CAP; i++) {
        ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &keys[i], NULL, NULL), 1,
                      "every newer CLOSING entry survives the eviction");
    }

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_rejected_cap, 0,
                  "CLOSING cap eviction is churn bookkeeping, not a rejection");
    ASSERT_EQ_INT(stats.flows_rejected_other, 0, "not counted as a rejection either");

    mqvpn_tcp_lane_free(lane);
}

static void
test_syn_during_closing_reevaluates(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf104ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = make_closing_flow(lane, &pcb, 9300, &fake_req, &fake_stream);
    ASSERT_TRUE(f != NULL, "flow reaches CLOSING");
    ASSERT_EQ_INT(lane->n_closing, 1, "n_closing == 1 before reuse");

    mqvpn_flow_key_t key = mk_std_key(9300);
    int out_raw = -1, out_closing = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, &out_raw, &out_closing), 1,
                  "lookup finds the CLOSING marker");
    ASSERT_EQ_INT(out_closing, 1,
                  "confirmed CLOSING — tun_decide_lane's cue to re-run "
                  "policy on a pure SYN");

    /* tun_decide_lane's contract (mqvpn_client.c): a pure SYN hitting a
     * CLOSING entry re-runs policy via on_syn, which removes the stale
     * marker itself. Pin on_syn's side of that contract directly. */
    ASSERT_EQ_INT(
        mqvpn_tcp_lane_on_syn(lane, &key, 1, 0), 0,
        "on_syn succeeds — stale CLOSING marker removed, fresh commit inserted");

    ASSERT_EQ_INT(lane->n_closing, 0, "the stale marker is gone, not just shadowed");
    int is_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &key, &is_raw, NULL), 1,
                  "a brand-new entry now occupies the key");
    ASSERT_EQ_INT(is_raw, 0, "the new entry is a real TCP-lane flow, not sticky-RAW");

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_active, 1,
                  "the new commit counts as an active TCP-lane flow");
    ASSERT_EQ_INT(stats.flows_rejected_other, 0, "NOT treated as a caller-bug duplicate");

    mqvpn_tcp_lane_free(lane);
}

/* ─── Idle-timeout eviction sweep (Task 13) ───
 *
 * All tests here use a small tcp_idle_timeout_sec (5s) instead of the 300s
 * default so the clock-advance math stays readable; g_fake_now starts at
 * relay_reset's fixed 12345 baseline in every test. */

static void
test_idle_eviction_basic(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 5;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf001ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 9001, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    mqvpn_flow_key_t k = mk_std_key(9001);
    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 1,
                  "flow present before sweep");

    g_fake_now += (uint64_t)(cfg.tcp_idle_timeout_sec + 1) * 1000000ULL;
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 1, "idle flow evicted");
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 0,
                  "lookup miss after eviction");
    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "teardown funnel aborted the pcb");
    ASSERT_EQ_INT(g_h3_close_calls, 1, "teardown funnel closed the h3 request");

    mqvpn_tcp_lane_free(lane);
}

static void
test_idle_eviction_fresh_survives(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 5;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf002ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 9002, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    g_fake_now += 1ULL * 1000000ULL; /* well under the 5s timeout */
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 0, "fresh flow survives the sweep");
    mqvpn_flow_key_t k = mk_std_key(9002);
    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 1,
                  "flow still present");
    ASSERT_EQ_INT(g_tcp_abort_calls, 0, "no teardown fired");

    mqvpn_tcp_lane_free(lane);
}

static void
test_idle_eviction_sticky_raw_survives(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 5;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf003ULL, NULL, fake_clock, NULL);

    mqvpn_flow_key_t k = make_key(4100, 80);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 0, 0), 0,
                  "sticky-RAW marker committed");

    g_fake_now += 1000ULL * 1000000ULL; /* ancient by any timeout */
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 0,
                  "sticky-RAW marker never idle-evicted, however ancient");
    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 1,
                  "marker still present");
    ASSERT_EQ_INT(out_raw, 1, "still sticky-RAW");

    mqvpn_tcp_lane_free(lane);
}

static void
test_idle_eviction_timeout_zero_never_evicts(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 0; /* opt-out: never evict */
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf004ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 9004, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    g_fake_now += 1000000ULL * 1000000ULL; /* absurdly far in the future */
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 0, "timeout=0 disables the sweep entirely");
    mqvpn_flow_key_t k = mk_std_key(9004);
    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 1, "flow untouched");

    mqvpn_tcp_lane_free(lane);
}

/* Pins fix B: a to_tcp=1 flow committed by on_syn but never fed through the
 * lwIP accept callback (PENDING_ACCEPT, no pcb, no h3_request) must be
 * stamped at creation time, not carry the calloc'd last_activity_us == 0
 * that would otherwise make it evictable on the very first sweep. */
static void
test_idle_eviction_pending_accept_stamped(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 5;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf005ULL, NULL, fake_clock, NULL);

    mqvpn_flow_key_t k = make_key(4200, 80);
    ASSERT_EQ_INT(mqvpn_tcp_lane_on_syn(lane, &k, 1, 0), 0,
                  "to_tcp flow committed, PENDING_ACCEPT");

    g_fake_now += 1ULL * 1000000ULL; /* well under the 5s timeout */
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 0,
                  "PENDING_ACCEPT survives a sweep within the timeout");
    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 1,
                  "flow still pending-accept");

    g_fake_now += (uint64_t)(cfg.tcp_idle_timeout_sec + 1) * 1000000ULL;
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 1,
                  "PENDING_ACCEPT evicted once truly idle from its creation stamp");
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 0,
                  "lookup miss after eviction");
    ASSERT_EQ_INT(g_tcp_abort_calls, 0, "no pcb existed to abort (never reached accept)");
    ASSERT_EQ_INT(g_h3_close_calls, 0, "no h3 request existed to close (never bound)");

    mqvpn_tcp_lane_free(lane);
}

/* Pins audit item C: a later on_lwip_sent stamp (downlink-traffic activity)
 * overrides the original creation-time stamp, so a flow well past its
 * ORIGINAL deadline survives once activity refreshed the clock. */
static void
test_idle_eviction_activity_refresh(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 5;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf006ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 9006, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    /* Advance to just under the original timeout, then refresh via the
     * downlink sent-callback stamp (uplink data uses on_lwip_recv; downlink
     * data reaches last_activity_us via on_lwip_sent, fired when lwIP ACKs
     * our tcp_write — see the audit comment on mqvpn_tcp_lane_on_lwip_sent). */
    g_fake_now += (uint64_t)(cfg.tcp_idle_timeout_sec - 1) * 1000000ULL;
    mqvpn_tcp_lane_on_lwip_sent(f, f->pcb, 0);

    /* Push past what would have been the ORIGINAL creation-based deadline —
     * the refreshed stamp must keep the flow alive here. */
    g_fake_now += (uint64_t)(cfg.tcp_idle_timeout_sec - 1) * 1000000ULL;
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 0,
                  "activity refresh keeps the flow alive past the original deadline");
    mqvpn_flow_key_t k = mk_std_key(9006);
    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 1,
                  "flow still present");

    /* Finally let it go idle for real, measured from the refreshed stamp. */
    g_fake_now += (uint64_t)(cfg.tcp_idle_timeout_sec + 1) * 1000000ULL;
    mqvpn_tcp_lane_tick(lane, g_fake_now);
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 1,
                  "eventually evicted once truly idle from the refreshed stamp");

    mqvpn_tcp_lane_free(lane);
}

/* Pins the sweep's saved-next chain walk: two flows forced into ONE hash
 * bucket, the bucket HEAD idle and its chain successor fresh. Evicting the
 * head frees it mid-walk — the walk must continue to the successor through
 * the next pointer saved BEFORE the teardown, and must not evict the fresh
 * successor. (on_syn inserts at the bucket head, so the LAST-created flow
 * is the head.) */
static void
test_idle_eviction_same_bucket_head_evicted(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 5;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf007ULL, NULL, fake_clock, NULL);

    /* Find a second src_port whose key lands in the same bucket as port
     * 9100's — the test TU has full struct visibility, so compute buckets
     * exactly the way find_flow does. */
    mqvpn_flow_key_t ka = mk_std_key(9100);
    uint32_t bucket_a =
        (uint32_t)(mqvpn_flow_key_hash(&ka, lane->hash_seed) & (lane->n_buckets - 1));
    uint16_t port_b = 0;
    for (uint16_t p = 9101; p != 0; p++) {
        mqvpn_flow_key_t kb = mk_std_key(p);
        uint32_t bucket_b =
            (uint32_t)(mqvpn_flow_key_hash(&kb, lane->hash_seed) & (lane->n_buckets - 1));
        if (bucket_b == bucket_a) {
            port_b = p;
            break;
        }
    }
    ASSERT_TRUE(port_b != 0, "found a same-bucket second port");

    struct tcp_pcb pcb_a, pcb_b;
    int req_a, stream_a, req_b, stream_b;
    /* A first (becomes the chain successor), B second (becomes the head). */
    mqvpn_tcp_flow_t *fa = setup_flow(lane, &pcb_a, 9100, &req_a, &stream_a, 1);
    mqvpn_tcp_flow_t *fb = setup_flow(lane, &pcb_b, port_b, &req_b, &stream_b, 1);
    ASSERT_TRUE(fa != NULL && fb != NULL, "both same-bucket flows established");
    ASSERT_TRUE(lane->buckets[bucket_a] == fb && fb->next == fa,
                "chain shape as intended: head B -> successor A");

    /* Keep A fresh (activity stamp at +4s), leave B idle from creation. */
    g_fake_now += 4ULL * 1000000ULL;
    mqvpn_tcp_lane_on_lwip_sent(fa, fa->pcb, 0);

    g_fake_now += 2ULL * 1000000ULL; /* B age 6s > 5s; A age 2s */
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 1, "only the idle head evicted");
    int out_raw = -1;
    mqvpn_flow_key_t kb = mk_std_key(port_b);
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &kb, &out_raw, NULL), 0, "head B gone");
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &ka, &out_raw, NULL), 1,
                  "fresh successor A survived the head's mid-walk free");
    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "exactly one pcb aborted");

    mqvpn_tcp_lane_free(lane);
}

/* PENDING_STREAM eviction: H3 request opened and bound (pre-2xx gate), so
 * the teardown funnel must close BOTH sides — pcb abort AND h3 close. */
static void
test_idle_eviction_pending_stream(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 5;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf008ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f =
        setup_flow(lane, &pcb, 9008, &fake_req, &fake_stream, /*establish=*/0);
    ASSERT_TRUE(f != NULL, "flow bound, still PENDING_STREAM");
    ASSERT_EQ_INT(f->state, TCP_FLOW_PENDING_STREAM, "pre-2xx state");

    g_fake_now += 6ULL * 1000000ULL;
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 1, "PENDING_STREAM flow evicted");
    ASSERT_EQ_INT(g_tcp_abort_calls, 1, "pcb aborted");
    ASSERT_EQ_INT(g_h3_close_calls, 1, "bound h3 request closed");
    mqvpn_flow_key_t k = mk_std_key(9008);
    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 0, "flow gone");

    mqvpn_tcp_lane_free(lane);
}

/* Exact boundary: age == timeout must NOT evict (the sweep's strict >). */
static void
test_idle_eviction_exact_boundary(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 5;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf009ULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb;
    int fake_req, fake_stream;
    mqvpn_tcp_flow_t *f = setup_flow(lane, &pcb, 9009, &fake_req, &fake_stream, 1);
    ASSERT_TRUE(f != NULL, "flow established");

    g_fake_now += (uint64_t)cfg.tcp_idle_timeout_sec * 1000000ULL; /* age == timeout */
    mqvpn_tcp_lane_tick(lane, g_fake_now);

    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 0,
                  "age == timeout is NOT evicted (strict >)");
    mqvpn_flow_key_t k = mk_std_key(9009);
    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &k, &out_raw, NULL), 1,
                  "flow still present");

    /* One second later (also re-satisfies the cadence gate) the age is
     * strictly past the timeout — now it goes. */
    g_fake_now += 1ULL * 1000000ULL;
    mqvpn_tcp_lane_tick(lane, g_fake_now);
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 1, "evicted once strictly past the timeout");

    mqvpn_tcp_lane_free(lane);
}

/* Pins the 1s cadence gate: a tick < 1s after the previous sweep must skip
 * the walk entirely, even with an idle-eligible flow in the table. */
static void
test_idle_eviction_sweep_cadence_gate(void)
{
    relay_reset();
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_idle_timeout_sec = 5;
    mqvpn_tcp_lane_t *lane = mqvpn_tcp_lane_new(&cfg, 0xf00aULL, NULL, fake_clock, NULL);
    struct tcp_pcb pcb_a, pcb_b;
    int req_a, stream_a, req_b, stream_b;
    mqvpn_tcp_flow_t *fa = setup_flow(lane, &pcb_a, 9010, &req_a, &stream_a, 1);
    ASSERT_TRUE(fa != NULL, "flow A established");

    /* Sweep once (evicts A) to latch last_sweep_us. */
    g_fake_now += 6ULL * 1000000ULL;
    mqvpn_tcp_lane_tick(lane, g_fake_now);
    mqvpn_tcp_lane_stats_t stats;
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 1, "A evicted; sweep timestamp latched");

    /* New flow, made idle-eligible IMMEDIATELY by backdating its stamp (the
     * test TU has struct visibility; no legitimate stamp path could age a
     * flow within the sub-second window this test needs). */
    mqvpn_tcp_flow_t *fb = setup_flow(lane, &pcb_b, 9011, &req_b, &stream_b, 1);
    ASSERT_TRUE(fb != NULL, "flow B established");
    fb->last_activity_us = 12345; /* ancient: the pre-advance baseline */

    g_fake_now += 500000ULL; /* +0.5s — inside the gate window */
    mqvpn_tcp_lane_tick(lane, g_fake_now);
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 1,
                  "gated tick did not sweep (idle-eligible B untouched)");
    mqvpn_flow_key_t kb = mk_std_key(9011);
    int out_raw = -1;
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &kb, &out_raw, NULL), 1, "B still present");

    g_fake_now += 500000ULL; /* +1.0s total since the last sweep — gate opens */
    mqvpn_tcp_lane_tick(lane, g_fake_now);
    mqvpn_tcp_lane_get_stats(lane, &stats);
    ASSERT_EQ_INT(stats.flows_idle_evicted, 2, "next sweep after the gate evicts B");
    ASSERT_EQ_INT(mqvpn_tcp_lane_lookup(lane, &kb, &out_raw, NULL), 0, "B gone");

    mqvpn_tcp_lane_free(lane);
}

int
main(void)
{
    test_new_flow_and_lookup();
    test_sticky_raw();
    test_marker_isn_stored_and_retrieved();
    test_syn_isn_mismatch_replaces_marker_raw_to_raw();
    test_syn_isn_mismatch_replaces_marker_raw_to_tcp();
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
    test_relay_fatal_error_paths();
    test_relay_lane_free_with_queued_backlog();
    test_relay_fin_during_pending_stream();
    test_downlink_basic();
    test_downlink_err_mem_stash_and_resume();
    test_downlink_sent_notify_still_resumes();
    test_downlink_sndbuf_gate();
    test_downlink_fin_with_data();
    test_downlink_fin_only();
    test_downlink_fin_while_paused();
    test_downlink_fin_stashed_with_data();
    test_downlink_fatal_recv_error();
    test_downlink_pump_on_torn_down_flow();
    test_tcp_syn_flag_cases();
    test_tcp_syn_isn_v6();
    test_lwip_err_teardown();
    test_h3_closing_notify_teardown();
    test_abort_pending_real();
    test_accept_open_stream_fail_returns_abrt();
    test_lwip_sent_teardown_returns_abrt();
    test_clean_close_uplink_fin_first();
    test_clean_close_downlink_fin_first();
    test_removal_updates_stats();

    test_closing_grace_sweep_survives_then_expires();
    test_closing_grace_sweep_runs_with_idle_timeout_zero();
    test_closing_cap_eviction();
    test_syn_during_closing_reevaluates();
    test_idle_eviction_basic();
    test_idle_eviction_fresh_survives();
    test_idle_eviction_sticky_raw_survives();
    test_idle_eviction_timeout_zero_never_evicts();
    test_idle_eviction_pending_accept_stamped();
    test_idle_eviction_activity_refresh();
    test_idle_eviction_same_bucket_head_evicted();
    test_idle_eviction_pending_stream();
    test_idle_eviction_exact_boundary();
    test_idle_eviction_sweep_cadence_gate();

    fprintf(stderr, "test_tcp_lane: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
