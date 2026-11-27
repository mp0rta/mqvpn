// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_path_activation.c - every path of a multipath client comes up with the
 * tunnel
 *
 * An mqvpn client with several paths and an mqvpn server in one process,
 * joined by in-memory links of one fixed one-way delay and run on a virtual
 * clock (mqvpn_clock_test_sources): no socket, no sleep, and every run is the
 * same.
 *
 * xquic opens a new path on the next unused path ID only once the server has
 * acknowledged the client's connection IDs for that path ID
 * (xqc_conn_get_available_path_id). The client issues them for every path ID
 * when the handshake is confirmed, and the server's acknowledgments then make
 * the path IDs usable one after another, each time with a
 * ready_to_create_path notification; past the path ID limit, the server's
 * grant of more path IDs does the same. A path that finds no usable path ID
 * yet has to wait for the next notification, not for its retry timer (5 s),
 * and the wait must not use up its retry budget.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "libmqvpn.h"
#include "mqvpn_internal.h"

#define SEC      1000000ULL
#define DELAY_US 10000ULL   /* one-way delay of every link */
#define START_US (1 * SEC)  /* the virtual CLOCK_BOOTTIME at the start */
#define RUN_US   (10 * SEC) /* how much virtual time a run may take */
/* Every path is ACTIVE this soon after the tunnel: 50 round trips, and 4 s
 * before a path that waited for its retry timer (5 s) could be. */
#define UP_WITHIN_US (1 * SEC)

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST(name)                 \
    static void test_##name(void); \
    static void run_##name(void)   \
    {                              \
        g_tests_run++;             \
        printf("  %-50s ", #name); \
        test_##name();             \
        g_tests_passed++;          \
        printf("PASS\n");          \
    }                              \
    static void test_##name(void)

#define ASSERT_EQ(a, b)                                                                \
    do {                                                                               \
        if ((a) != (b)) {                                                              \
            printf("FAIL\n    %s:%d: %s == %lld, expected %lld\n", __FILE__, __LINE__, \
                   #a, (long long)(a), (long long)(b));                                \
            exit(1);                                                                   \
        }                                                                              \
    } while (0)

#define ASSERT_NOT_NULL(a)                                                   \
    do {                                                                     \
        if ((a) == NULL) {                                                   \
            printf("FAIL\n    %s:%d: %s is NULL\n", __FILE__, __LINE__, #a); \
            exit(1);                                                         \
        }                                                                    \
    } while (0)

/* ── Virtual clock ── */

static uint64_t g_now; /* virtual CLOCK_BOOTTIME, us */

static uint64_t
boot_us(void)
{
    return g_now;
}

static uint64_t
wall_us(void)
{
    return UINT64_C(1767225600000000) + g_now; /* 2026-01-01 */
}

/* ── Links ──
 * Datagrams in flight. Every link has the same delay, so one FIFO keeps
 * them in delivery order. */

typedef struct pkt_s {
    struct pkt_s *next;
    uint64_t at;   /* delivery time */
    int to_server; /* 1: client to server, 0: server to client */
    int path;      /* the client path it travels on */
    size_t len;
    uint8_t data[];
} pkt_t;

static pkt_t *g_head, **g_tail = &g_head;
static int g_npaths;
static struct sockaddr_in g_srv_addr, g_path_addr[MQVPN_MAX_PATHS];
static int g_tunnel_up;

static void
link_send(int to_server, int path, const mqvpn_datagram_t *bufs, unsigned n)
{
    for (unsigned i = 0; i < n; i++) {
        pkt_t *p = malloc(sizeof(*p) + bufs[i].len);
        if (p == NULL) abort();
        p->next = NULL;
        p->at = g_now + DELAY_US;
        p->to_server = to_server;
        p->path = path;
        p->len = bufs[i].len;
        memcpy(p->data, bufs[i].data, bufs[i].len);
        *g_tail = p;
        g_tail = &p->next;
    }
}

static void
links_free(void)
{
    while (g_head != NULL) {
        pkt_t *p = g_head;
        g_head = p->next;
        free(p);
    }
    g_tail = &g_head;
}

static int
cli_send(void *ctx, const mqvpn_datagram_t *bufs, unsigned n, const struct sockaddr *peer,
         socklen_t peer_len)
{
    (void)peer;
    (void)peer_len;
    link_send(1, (int)(intptr_t)ctx, bufs, n);
    return (int)n;
}

static int
srv_send(void *ctx, mqvpn_server_tx_scope_t scope, const mqvpn_datagram_t *bufs,
         unsigned n, const struct sockaddr *peer, socklen_t peer_len)
{
    const struct sockaddr_in *sin = (const struct sockaddr_in *)peer;
    (void)ctx;
    (void)scope;
    (void)peer_len;
    for (int i = 0; sin != NULL && i < g_npaths; i++) {
        if (sin->sin_addr.s_addr == g_path_addr[i].sin_addr.s_addr &&
            sin->sin_port == g_path_addr[i].sin_port) {
            link_send(0, i, bufs, n);
        }
    }
    return (int)n;
}

/* ── Callbacks ── */

static void
tun_out(const uint8_t *pkt, size_t len, void *ctx)
{
    (void)pkt;
    (void)len;
    (void)ctx;
}

static void
cli_tunnel_ready(const mqvpn_tunnel_info_t *info, void *ctx)
{
    (void)info;
    (void)ctx;
    g_tunnel_up = 1;
}

static void
srv_tunnel_ready(const mqvpn_tunnel_info_t *info, void *ctx)
{
    (void)info;
    (void)ctx;
}

static void
quiet_log(mqvpn_log_level_t level, const char *msg, void *ctx)
{
    (void)level;
    (void)msg;
    (void)ctx;
}

/* ── The run ── */

typedef struct {
    uint64_t tunnel_up_us;               /* 0: the tunnel never came up */
    uint64_t active_us[MQVPN_MAX_PATHS]; /* 0: the path never became ACTIVE */
    int retries[MQVPN_MAX_PATHS];        /* recreate_retries at the end */
    int n_active;
} run_result_t;

static void
set_addr(struct sockaddr_in *a, const char *ip, int port)
{
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &a->sin_addr);
}

static void
common_config(mqvpn_config_t *cfg, uint64_t init_max_path_id)
{
    mqvpn_config_set_auth_key(cfg, "path-activation-psk-0123456789abcdef0123456789ab");
    mqvpn_config_set_multipath(cfg, 1);
    mqvpn_config_set_init_max_path_id(cfg, init_max_path_id);
    mqvpn_config_set_log_level(cfg, MQVPN_LOG_WARN);
}

static uint64_t
next_timer(uint64_t interest_ms)
{
    return g_now + (interest_ms > 0 ? interest_ms : 1) * 1000;
}

static uint64_t
client_timer(mqvpn_client_t *c)
{
    mqvpn_interest_t in = {.struct_size = sizeof(in)};
    mqvpn_client_get_interest(c, &in);
    return next_timer((uint64_t)in.next_timer_ms);
}

static uint64_t
server_timer(mqvpn_server_t *s)
{
    mqvpn_interest_t in = {.struct_size = sizeof(in)};
    mqvpn_server_get_interest(s, &in);
    return next_timer((uint64_t)in.next_timer_ms);
}

/* A client with npaths paths connects to the server, both ends advertising
 * init_max_path_id (0: xquic's default, 8); returns when every path is
 * ACTIVE or after RUN_US of virtual time. Like a platform, each step reads
 * what has arrived on a socket (the server's, then each path's) and ticks
 * once per socket read, then runs the timers that are due. */
static void
run_paths(int npaths, uint64_t init_max_path_id, run_result_t *r)
{
    memset(r, 0, sizeof(*r));
    g_npaths = npaths;
    g_tunnel_up = 0;
    g_now = START_US;
    mqvpn_clock_test_sources(boot_us, wall_us);

    set_addr(&g_srv_addr, "10.255.0.1", 443);
    mqvpn_config_t *scfg = mqvpn_config_new();
    ASSERT_NOT_NULL(scfg);
    mqvpn_config_set_listen(scfg, "10.255.0.1", 443);
    mqvpn_config_set_subnet(scfg, "10.0.0.0/24");
    mqvpn_config_set_tls_cert(scfg, TEST_CERT_FILE, TEST_KEY_FILE);
    common_config(scfg, init_max_path_id);
    mqvpn_server_callbacks_t scb = MQVPN_SERVER_CALLBACKS_INIT;
    scb.tun_output = tun_out;
    scb.tunnel_config_ready = srv_tunnel_ready;
    scb.log = quiet_log;
    mqvpn_server_t *s = mqvpn_server_new(scfg, &scb, NULL);
    ASSERT_NOT_NULL(s);
    static const mqvpn_server_transport_ops_t sops = {
        .struct_size = sizeof(mqvpn_server_transport_ops_t), .send = srv_send};
    ASSERT_EQ(mqvpn_server_set_transport(s, &sops, NULL,
                                         (const struct sockaddr *)&g_srv_addr,
                                         sizeof(g_srv_addr)),
              MQVPN_OK);
    ASSERT_EQ(mqvpn_server_start(s), MQVPN_OK);

    mqvpn_config_t *ccfg = mqvpn_config_new();
    ASSERT_NOT_NULL(ccfg);
    mqvpn_config_set_server(ccfg, "10.255.0.1", 443);
    mqvpn_config_set_insecure(ccfg, 1);
    mqvpn_config_set_reconnect(ccfg, 0, 5);
    common_config(ccfg, init_max_path_id);
    mqvpn_client_callbacks_t ccb = MQVPN_CLIENT_CALLBACKS_INIT;
    ccb.tun_output = tun_out;
    ccb.tunnel_config_ready = cli_tunnel_ready;
    ccb.log = quiet_log;
    mqvpn_client_t *c = mqvpn_client_new(ccfg, &ccb, NULL);
    ASSERT_NOT_NULL(c);
    static const mqvpn_path_ops_t pops = {.struct_size = sizeof(mqvpn_path_ops_t),
                                          .send = cli_send};
    mqvpn_path_handle_t handle[MQVPN_MAX_PATHS];
    for (int i = 0; i < npaths; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.1.%d.2", i);
        set_addr(&g_path_addr[i], ip, 40000 + i);
        mqvpn_path_desc_t d = {.struct_size = sizeof(d)};
        snprintf(d.iface, sizeof(d.iface), "wan%d", i);
        memcpy(d.local_addr, &g_path_addr[i], sizeof(g_path_addr[i]));
        d.local_addr_len = sizeof(g_path_addr[i]);
        handle[i] = mqvpn_client_add_path(c, &d, &pops, (void *)(intptr_t)i, NULL);
        ASSERT_EQ(handle[i] >= 0, 1);
    }
    ASSERT_EQ(mqvpn_client_set_server_addr(c, (const struct sockaddr *)&g_srv_addr,
                                           sizeof(g_srv_addr)),
              MQVPN_OK);
    ASSERT_EQ(mqvpn_client_connect(c), MQVPN_OK);
    uint64_t cli_at = client_timer(c), srv_at = server_timer(s);

    while (r->n_active < npaths && g_now < START_US + RUN_US) {
        uint64_t t = cli_at < srv_at ? cli_at : srv_at;
        if (g_head != NULL && g_head->at < t) t = g_head->at;
        g_now = t;

        pkt_t *due = NULL, **due_tail = &due;
        while (g_head != NULL && g_head->at <= g_now) {
            pkt_t *p = g_head;
            g_head = p->next;
            if (g_head == NULL) g_tail = &g_head;
            p->next = NULL;
            *due_tail = p;
            due_tail = &p->next;
        }
        for (int sock = -1; sock < npaths && due != NULL; sock++) {
            int got = 0;
            for (pkt_t **pp = &due; *pp != NULL;) {
                pkt_t *p = *pp;
                if (sock < 0 ? !p->to_server : (p->to_server || p->path != sock)) {
                    pp = &p->next;
                    continue;
                }
                if (sock < 0) {
                    mqvpn_server_on_socket_recv(
                        s, p->data, p->len,
                        (const struct sockaddr *)&g_path_addr[p->path],
                        sizeof(g_path_addr[p->path]));
                } else {
                    mqvpn_client_on_socket_recv(c, handle[sock], p->data, p->len,
                                                (const struct sockaddr *)&g_srv_addr,
                                                sizeof(g_srv_addr));
                }
                *pp = p->next;
                free(p);
                got = 1;
            }
            if (got && sock < 0) {
                mqvpn_server_tick(s);
                srv_at = server_timer(s);
            }
            if (got && sock >= 0) {
                mqvpn_client_tick(c);
                cli_at = client_timer(c);
            }
        }
        if (g_now >= srv_at) {
            mqvpn_server_tick(s);
            srv_at = server_timer(s);
        }
        if (g_now >= cli_at) {
            mqvpn_client_tick(c);
            cli_at = client_timer(c);
        }

        if (g_tunnel_up && r->tunnel_up_us == 0) {
            r->tunnel_up_us = g_now;
            ASSERT_EQ(mqvpn_client_set_tun_active(c, 1, -1), MQVPN_OK);
        }
        mqvpn_path_info_t pi[MQVPN_MAX_PATHS];
        int np = 0;
        if (mqvpn_client_get_paths(c, pi, MQVPN_MAX_PATHS, &np) != MQVPN_OK) continue;
        for (int k = 0; k < np && k < MQVPN_MAX_PATHS; k++) {
            for (int i = 0; i < npaths; i++) {
                if (pi[k].handle != handle[i] || pi[k].status != MQVPN_PATH_ACTIVE ||
                    r->active_us[i] != 0)
                    continue;
                r->active_us[i] = g_now;
                r->n_active++;
            }
        }
    }

    for (int i = 0; i < npaths; i++) {
        ASSERT_NOT_NULL(
            mqvpn_client_test_get_path_state_name(c, handle[i], &r->retries[i]));
    }
    mqvpn_client_destroy(c);
    mqvpn_server_destroy(s);
    mqvpn_config_free(ccfg);
    mqvpn_config_free(scfg);
    links_free();
    mqvpn_clock_test_sources(NULL, NULL);
}

static void
check_paths_come_up_with_the_tunnel(int npaths, uint64_t init_max_path_id)
{
    run_result_t r;
    run_paths(npaths, init_max_path_id, &r);

    int late = 0;
    for (int i = 0; i < npaths; i++) {
        if (r.active_us[i] == 0 || r.active_us[i] > r.tunnel_up_us + UP_WITHIN_US ||
            r.retries[i] != 0)
            late = 1;
    }
    if (r.tunnel_up_us == 0 || late) {
        if (r.tunnel_up_us == 0)
            printf("FAIL\n    tunnel never up\n");
        else
            printf("FAIL\n    tunnel up at %.3f s\n", r.tunnel_up_us / 1e6);
        for (int i = 0; i < npaths; i++) {
            if (r.active_us[i] == 0)
                printf("    wan%d never ACTIVE, retries %d\n", i, r.retries[i]);
            else
                printf("    wan%d ACTIVE at %.3f s, retries %d\n", i,
                       r.active_us[i] / 1e6, r.retries[i]);
        }
        exit(1);
    }
}

TEST(three_paths_come_up_with_the_tunnel)
{
    check_paths_come_up_with_the_tunnel(3, 0);
}

TEST(max_paths_come_up_with_the_tunnel)
{
    check_paths_come_up_with_the_tunnel(MQVPN_MAX_PATHS, 0);
}

/* Path IDs 0 to 2 for four paths: the fourth waits for the server's grant of
 * more path IDs (PATHS_BLOCKED, then MAX_PATH_ID), and for the
 * ready_to_create_path notification that follows it. */
TEST(path_past_the_path_id_limit_comes_up_with_the_grant)
{
    check_paths_come_up_with_the_tunnel(4, 2);
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("test_path_activation: paths of a multipath client\n");

    run_three_paths_come_up_with_the_tunnel();
    run_max_paths_come_up_with_the_tunnel();
    run_path_past_the_path_id_limit_comes_up_with_the_grant();

    printf("\n%d/%d tests passed\n", g_tests_passed, g_tests_run);
    return g_tests_passed == g_tests_run ? 0 : 1;
}
