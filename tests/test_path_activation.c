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
 * and the wait must not use up its retry budget. So does a path that xquic
 * closed and the client creates again, from its retry timer or from
 * mqvpn_client_reactivate_path().
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
/* Path IDs 0 to 2 for two paths: the second time path 1 is created again,
 * it needs path ID 3, past the limit. */
#define CYCLES 3
/* How often the client sends a packet into the tunnel during those. */
#define TRAFFIC_US (SEC / 10)
/* Between outages: longer than the 30 s after which a stable path's retry
 * count is reset. */
#define QUIET_US (40 * SEC)
/* xquic closes a path once nothing has arrived on it for its idle timeout
 * (120 s). */
#define OUTAGE_MAX_US  (130 * SEC)
#define RECOVER_MAX_US (30 * SEC)
/* A reactivated path is ACTIVE this soon after its link works again: 4 s
 * before its retry timer (5 s) could create it. */
#define REACTIVATED_WITHIN_US (1 * SEC)
/* A path left to its retry timer, on a link that stays down STILL_DOWN_US
 * after xquic closed the path: four retries fail, and the fifth, 12 to 15 s
 * after the link works again, brings the path back. Had a retry been spent
 * twice, the path would be closed for good before that. */
#define STILL_DOWN_US     (130 * SEC)
#define RETRIED_WITHIN_US (20 * SEC)

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
static int g_blackhole[MQVPN_MAX_PATHS]; /* 1: the path loses every datagram */
static uint8_t g_tun_ip[4];              /* the client's address in the tunnel */
static uint64_t g_traffic_us;            /* 0, or the client sends a packet this often */
static uint64_t g_next_tx_us;

static void
link_send(int to_server, int path, const mqvpn_datagram_t *bufs, unsigned n)
{
    if (g_blackhole[path]) return;
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
    (void)ctx;
    memcpy(g_tun_ip, info->assigned_ip, sizeof(g_tun_ip));
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

/* ── The run ──
 * One client with g_npaths paths and the server. Like a platform, each step
 * reads what has arrived on a socket (the server's, then each path's) and
 * ticks once per socket read, then runs the timers that are due. */

static mqvpn_server_t *g_s;
static mqvpn_client_t *g_c;
static mqvpn_config_t *g_scfg, *g_ccfg;
static mqvpn_path_handle_t g_handle[MQVPN_MAX_PATHS];
static uint64_t g_cli_at, g_srv_at; /* when each end's timer is due */
static uint64_t g_tunnel_up_us;     /* 0: the tunnel is not up yet */

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
 * init_max_path_id (0: xquic's default, 8). */
static void
sim_start(int npaths, uint64_t init_max_path_id)
{
    g_npaths = npaths;
    g_tunnel_up = 0;
    g_tunnel_up_us = 0;
    memset(g_blackhole, 0, sizeof(g_blackhole));
    g_now = START_US;
    mqvpn_clock_test_sources(boot_us, wall_us);

    set_addr(&g_srv_addr, "10.255.0.1", 443);
    g_scfg = mqvpn_config_new();
    ASSERT_NOT_NULL(g_scfg);
    mqvpn_config_set_listen(g_scfg, "10.255.0.1", 443);
    mqvpn_config_set_subnet(g_scfg, "10.0.0.0/24");
    mqvpn_config_set_tls_cert(g_scfg, TEST_CERT_FILE, TEST_KEY_FILE);
    common_config(g_scfg, init_max_path_id);
    mqvpn_server_callbacks_t scb = MQVPN_SERVER_CALLBACKS_INIT;
    scb.tun_output = tun_out;
    scb.tunnel_config_ready = srv_tunnel_ready;
    scb.log = quiet_log;
    g_s = mqvpn_server_new(g_scfg, &scb, NULL);
    ASSERT_NOT_NULL(g_s);
    static const mqvpn_server_transport_ops_t sops = {
        .struct_size = sizeof(mqvpn_server_transport_ops_t), .send = srv_send};
    ASSERT_EQ(mqvpn_server_set_transport(g_s, &sops, NULL,
                                         (const struct sockaddr *)&g_srv_addr,
                                         sizeof(g_srv_addr)),
              MQVPN_OK);
    ASSERT_EQ(mqvpn_server_start(g_s), MQVPN_OK);

    g_ccfg = mqvpn_config_new();
    ASSERT_NOT_NULL(g_ccfg);
    mqvpn_config_set_server(g_ccfg, "10.255.0.1", 443);
    mqvpn_config_set_insecure(g_ccfg, 1);
    mqvpn_config_set_reconnect(g_ccfg, 0, 5);
    common_config(g_ccfg, init_max_path_id);
    mqvpn_client_callbacks_t ccb = MQVPN_CLIENT_CALLBACKS_INIT;
    ccb.tun_output = tun_out;
    ccb.tunnel_config_ready = cli_tunnel_ready;
    ccb.log = quiet_log;
    g_c = mqvpn_client_new(g_ccfg, &ccb, NULL);
    ASSERT_NOT_NULL(g_c);
    static const mqvpn_path_ops_t pops = {.struct_size = sizeof(mqvpn_path_ops_t),
                                          .send = cli_send};
    for (int i = 0; i < npaths; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "10.1.%d.2", i);
        set_addr(&g_path_addr[i], ip, 40000 + i);
        mqvpn_path_desc_t d = {.struct_size = sizeof(d)};
        snprintf(d.iface, sizeof(d.iface), "wan%d", i);
        memcpy(d.local_addr, &g_path_addr[i], sizeof(g_path_addr[i]));
        d.local_addr_len = sizeof(g_path_addr[i]);
        g_handle[i] = mqvpn_client_add_path(g_c, &d, &pops, (void *)(intptr_t)i, NULL);
        ASSERT_EQ(g_handle[i] >= 0, 1);
    }
    ASSERT_EQ(mqvpn_client_set_server_addr(g_c, (const struct sockaddr *)&g_srv_addr,
                                           sizeof(g_srv_addr)),
              MQVPN_OK);
    ASSERT_EQ(mqvpn_client_connect(g_c), MQVPN_OK);
    g_cli_at = client_timer(g_c);
    g_srv_at = server_timer(g_s);
}

static void
sim_step(void)
{
    uint64_t t = g_cli_at < g_srv_at ? g_cli_at : g_srv_at;
    if (g_head != NULL && g_head->at < t) t = g_head->at;
    if (g_traffic_us != 0 && g_tunnel_up_us != 0 && g_next_tx_us < t) t = g_next_tx_us;
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
    for (int sock = -1; sock < g_npaths && due != NULL; sock++) {
        int got = 0;
        for (pkt_t **pp = &due; *pp != NULL;) {
            pkt_t *p = *pp;
            if (sock < 0 ? !p->to_server : (p->to_server || p->path != sock)) {
                pp = &p->next;
                continue;
            }
            if (sock < 0) {
                mqvpn_server_on_socket_recv(
                    g_s, p->data, p->len, (const struct sockaddr *)&g_path_addr[p->path],
                    sizeof(g_path_addr[p->path]));
            } else {
                mqvpn_client_on_socket_recv(g_c, g_handle[sock], p->data, p->len,
                                            (const struct sockaddr *)&g_srv_addr,
                                            sizeof(g_srv_addr));
            }
            *pp = p->next;
            free(p);
            got = 1;
        }
        if (got && sock < 0) {
            mqvpn_server_tick(g_s);
            g_srv_at = server_timer(g_s);
        }
        if (got && sock >= 0) {
            mqvpn_client_tick(g_c);
            g_cli_at = client_timer(g_c);
        }
    }
    if (g_now >= g_srv_at) {
        mqvpn_server_tick(g_s);
        g_srv_at = server_timer(g_s);
    }
    if (g_now >= g_cli_at) {
        mqvpn_client_tick(g_c);
        g_cli_at = client_timer(g_c);
    }

    if (g_traffic_us != 0 && g_tunnel_up_us != 0 && g_now >= g_next_tx_us) {
        uint8_t ip[64] = {0x45, 0, 0, sizeof(ip), 0, 0, 0, 0, 64, 17}; /* IPv4, UDP */
        memcpy(ip + 12, g_tun_ip, sizeof(g_tun_ip));
        memcpy(ip + 16, (const uint8_t[]){10, 0, 0, 1}, 4);
        ASSERT_EQ(mqvpn_client_on_tun_packet(g_c, ip, sizeof(ip)), MQVPN_OK);
        mqvpn_client_tick(g_c);
        g_cli_at = client_timer(g_c);
        g_next_tx_us = g_now + g_traffic_us;
    }
    if (g_tunnel_up && g_tunnel_up_us == 0) {
        g_tunnel_up_us = g_now;
        g_next_tx_us = g_now;
        ASSERT_EQ(mqvpn_client_set_tun_active(g_c, 1, -1), MQVPN_OK);
    }
}

static void
sim_stop(void)
{
    mqvpn_client_destroy(g_c);
    mqvpn_server_destroy(g_s);
    mqvpn_config_free(g_ccfg);
    mqvpn_config_free(g_scfg);
    links_free();
    g_traffic_us = 0;
    mqvpn_clock_test_sources(NULL, NULL);
}

/* Path i's public status, -1 if the client does not list it. */
static int
path_status(int i)
{
    mqvpn_path_info_t pi[MQVPN_MAX_PATHS];
    int np = 0;
    if (mqvpn_client_get_paths(g_c, pi, MQVPN_MAX_PATHS, &np) != MQVPN_OK) return -1;
    for (int k = 0; k < np && k < MQVPN_MAX_PATHS; k++) {
        if (pi[k].handle == g_handle[i]) return (int)pi[k].status;
    }
    return -1;
}

static int
path_retries(int i)
{
    int retries = 0;
    ASSERT_NOT_NULL(mqvpn_client_test_get_path_state_name(g_c, g_handle[i], &retries));
    return retries;
}

/* Steps until path i has the status, or for at most timeout_us; 1 if it has
 * it. */
static int
run_until_status(int i, mqvpn_path_status_t status, uint64_t timeout_us)
{
    uint64_t end = g_now + timeout_us;
    while (path_status(i) != (int)status) {
        if (g_now >= end) return 0;
        sim_step();
    }
    return 1;
}

static void
run_for(uint64_t us)
{
    uint64_t end = g_now + us;
    while (g_now < end)
        sim_step();
}

/* Returns when every path is ACTIVE or after RUN_US of virtual time. */
static void
run_paths(int npaths, uint64_t init_max_path_id, run_result_t *r)
{
    memset(r, 0, sizeof(*r));
    sim_start(npaths, init_max_path_id);
    while (r->n_active < npaths && g_now < START_US + RUN_US) {
        sim_step();
        for (int i = 0; i < npaths; i++) {
            if (r->active_us[i] != 0 || path_status(i) != MQVPN_PATH_ACTIVE) continue;
            r->active_us[i] = g_now;
            r->n_active++;
        }
    }
    r->tunnel_up_us = g_tunnel_up_us;
    for (int i = 0; i < npaths; i++)
        r->retries[i] = path_retries(i);
    sim_stop();
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

/* Path 1 of two loses every datagram until xquic has closed it (DEGRADED)
 * and for still_down_us more, then works again, CYCLES times, QUIET_US
 * apart. With reactivate, the platform calls mqvpn_client_reactivate_path()
 * as the link comes back, as netmon does on a link-up event, and ticks;
 * without it, the path's retry timer creates it again. Each time the path is
 * ACTIVE within_us after its link works again, and a reactivated path spends
 * no retry.
 *
 * The tunnel carries a packet every TRAFFIC_US, as a tunnel in use does:
 * xquic writes PATHS_BLOCKED when it refuses a path for want of a path ID,
 * and sends it with the next packet of the connection. */
static void
check_path_comes_back_after_outages(int reactivate, uint64_t still_down_us,
                                    uint64_t within_us)
{
    uint64_t back_us[CYCLES] = {0}; /* 0: not ACTIVE within RECOVER_MAX_US */
    int ret[CYCLES] = {0}, retries_before[CYCLES] = {0}, retries_after[CYCLES] = {0};
    int bad = 0;

    sim_start(2, 2);
    g_traffic_us = TRAFFIC_US;
    if (!run_until_status(0, MQVPN_PATH_ACTIVE, RUN_US) ||
        !run_until_status(1, MQVPN_PATH_ACTIVE, RUN_US)) {
        printf("FAIL\n    paths never ACTIVE\n");
        exit(1);
    }
    for (int n = 0; n < CYCLES; n++) {
        run_for(QUIET_US);
        g_blackhole[1] = 1;
        if (!run_until_status(1, MQVPN_PATH_DEGRADED, OUTAGE_MAX_US)) {
            printf("FAIL\n    cycle %d: wan1 never DEGRADED\n", n + 1);
            exit(1);
        }
        run_for(still_down_us);
        g_blackhole[1] = 0;
        uint64_t healed = g_now;
        retries_before[n] = path_retries(1);
        if (reactivate) {
            ret[n] = mqvpn_client_reactivate_path(g_c, g_handle[1]);
            g_cli_at = g_now;
        }
        if (run_until_status(1, MQVPN_PATH_ACTIVE, RECOVER_MAX_US))
            back_us[n] = g_now - healed;
        retries_after[n] = path_retries(1);
        if (back_us[n] == 0 || back_us[n] > within_us ||
            (reactivate && retries_after[n] != retries_before[n]))
            bad = 1;
    }
    sim_stop();

    if (bad) {
        printf("FAIL\n");
        for (int n = 0; n < CYCLES; n++) {
            printf("    cycle %d: ", n + 1);
            if (reactivate) printf("reactivate %s, ", mqvpn_error_string(ret[n]));
            if (back_us[n] == 0)
                printf("not ACTIVE");
            else
                printf("ACTIVE %.3f s after the link came back", back_us[n] / 1e6);
            printf(", retries %d -> %d\n", retries_before[n], retries_after[n]);
        }
        exit(1);
    }
}

TEST(reactivated_path_comes_back_without_a_retry)
{
    check_path_comes_back_after_outages(1, 0, REACTIVATED_WITHIN_US);
}

TEST(retried_path_spends_one_retry_per_attempt)
{
    check_path_comes_back_after_outages(0, STILL_DOWN_US, RETRIED_WITHIN_US);
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("test_path_activation: paths of a multipath client\n");

    run_three_paths_come_up_with_the_tunnel();
    run_max_paths_come_up_with_the_tunnel();
    run_path_past_the_path_id_limit_comes_up_with_the_grant();
    run_reactivated_path_comes_back_without_a_retry();
    run_retried_path_spends_one_retry_per_attempt();

    printf("\n%d/%d tests passed\n", g_tests_passed, g_tests_run);
    return g_tests_passed == g_tests_run ? 0 : 1;
}
