/*
 * platform_linux.c — Linux platform layer for libmqvpn
 *
 * Bridges libmqvpn (sans-I/O) with Linux-specific I/O:
 *   - libevent event loop driving tick()
 *   - TUN device creation and I/O
 *   - UDP socket creation via path_mgr
 *   - Signal handling (SIGINT/SIGTERM)
 *
 * Routing and killswitch are in separate files (routing.c, killswitch.c).
 */

#include "platform_internal.h"
#include "platform_linux.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* ================================================================
 *  libmqvpn callbacks
 * ================================================================ */

/* Forward declarations for event handlers */
static void on_tun_read(evutil_socket_t fd, short what, void *arg);
static void on_socket_read(evutil_socket_t fd, short what, void *arg);

static void
cb_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    platform_ctx_t *p = (platform_ctx_t *)user_ctx;
    if (p->tun_up && p->tun.fd >= 0)
        mqvpn_tun_write(&p->tun, pkt, len);
}

static void
cb_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    platform_ctx_t *p = (platform_ctx_t *)user_ctx;

    /* Create TUN device */
    const char *tun_name = p->tun.name[0] ? p->tun.name : "mqvpn0";
    if (mqvpn_tun_create(&p->tun, tun_name) < 0) {
        LOG_ERR("TUN create failed");
        goto fail;
    }

    /* Set IPv4 address */
    char local_ip[INET_ADDRSTRLEN];
    snprintf(local_ip, sizeof(local_ip), "%d.%d.%d.%d",
             info->assigned_ip[0], info->assigned_ip[1],
             info->assigned_ip[2], info->assigned_ip[3]);
    char peer_ip[INET_ADDRSTRLEN];
    snprintf(peer_ip, sizeof(peer_ip), "%d.%d.%d.%d",
             info->server_ip[0], info->server_ip[1],
             info->server_ip[2], info->server_ip[3]);

    if (mqvpn_tun_set_addr(&p->tun, local_ip, peer_ip, 32) < 0) goto fail;
    if (mqvpn_tun_set_mtu(&p->tun, info->mtu) < 0) goto fail;
    if (mqvpn_tun_up(&p->tun) < 0) goto fail;

    /* Set IPv6 address if available */
    if (info->has_v6) {
        p->has_v6 = 1;
        char v6str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, info->assigned_ip6, v6str, sizeof(v6str));
        if (mqvpn_tun_set_addr6(&p->tun, v6str, info->assigned_prefix6) < 0)
            LOG_WRN("failed to set IPv6 address on TUN (continuing IPv4-only)");
    }

    LOG_INF("TUN %s configured: %s → %s (mtu=%d)", p->tun.name, local_ip, peer_ip, info->mtu);

    /* Set up routes, killswitch, DNS */
    if (setup_routes(p) < 0) {
        LOG_ERR("route setup failed, aborting tunnel");
        goto fail;
    }
    if (setup_killswitch(p) < 0) {
        LOG_ERR("killswitch setup failed, aborting tunnel");
        goto fail;
    }
    if (p->dns.n_servers > 0) {
        if (mqvpn_dns_apply(&p->dns) < 0)
            LOG_WRN("DNS override failed (continuing without DNS override)");
    }

    /* Register TUN read event */
    p->ev_tun = event_new(p->eb, p->tun.fd, EV_READ | EV_PERSIST,
                           on_tun_read, p);
    if (!p->ev_tun) {
        LOG_ERR("failed to create TUN event");
        goto fail;
    }
    event_add(p->ev_tun, NULL);
    p->tun_up = 1;

    /* Tell library the TUN is active */
    mqvpn_client_set_tun_active(p->client, 1, p->tun.fd);
    return;

fail:
    cleanup_killswitch(p);
    cleanup_routes(p);
    mqvpn_dns_restore(&p->dns);
    if (p->tun.fd >= 0) mqvpn_tun_destroy(&p->tun);
    p->tun.fd = -1;
    p->tun_up = 0;
    mqvpn_client_disconnect(p->client);
}

static void
cb_tunnel_closed(mqvpn_error_t reason, void *user_ctx)
{
    platform_ctx_t *p = (platform_ctx_t *)user_ctx;
    LOG_INF("tunnel closed: %s", mqvpn_error_string(reason));
}

static void
cb_ready_for_tun(void *user_ctx)
{
    /* Backpressure cleared — TUN reading will resume on next tick */
    (void)user_ctx;
}

static void
cb_state_changed(mqvpn_client_state_t old_state, mqvpn_client_state_t new_state,
                 void *user_ctx)
{
    platform_ctx_t *p = (platform_ctx_t *)user_ctx;
    static const char *names[] = {
        "IDLE", "CONNECTING", "AUTHENTICATING",
        "TUNNEL_READY", "ESTABLISHED", "RECONNECTING", "CLOSED"
    };
    const char *os = (old_state < 7) ? names[old_state] : "?";
    const char *ns = (new_state < 7) ? names[new_state] : "?";
    LOG_INF("state: %s → %s", os, ns);

    /* On CLOSED, clean up platform resources */
    if (new_state == MQVPN_STATE_CLOSED) {
        cleanup_killswitch(p);
        cleanup_routes(p);
        mqvpn_dns_restore(&p->dns);
        if (p->tun_up) {
            if (p->ev_tun) { event_del(p->ev_tun); event_free(p->ev_tun); p->ev_tun = NULL; }
            mqvpn_tun_destroy(&p->tun);
            p->tun.fd = -1;
            p->tun_up = 0;
        }
        if (p->shutting_down)
            event_base_loopbreak(p->eb);
    }
}

static void
cb_path_event(mqvpn_path_handle_t path, mqvpn_path_status_t status, void *user_ctx)
{
    (void)user_ctx;
    static const char *snames[] = {"PENDING", "ACTIVE", "DEGRADED", "STANDBY", "CLOSED"};
    const char *sn = (status < 5) ? snames[status] : "?";
    LOG_INF("path %lld -> %s", (long long)path, sn);
}

static void
cb_mtu_updated(int mtu, void *user_ctx)
{
    platform_ctx_t *p = (platform_ctx_t *)user_ctx;
    if (p->tun_up)
        mqvpn_tun_set_mtu(&p->tun, mtu);
    LOG_INF("TUN MTU updated to %d", mtu);
}

static void
cb_log(mqvpn_log_level_t level, const char *msg, void *user_ctx)
{
    (void)user_ctx;
    switch (level) {
    case MQVPN_LOG_DEBUG: LOG_DBG("[lib] %s", msg); break;
    case MQVPN_LOG_INFO:  LOG_INF("[lib] %s", msg); break;
    case MQVPN_LOG_WARN:  LOG_WRN("[lib] %s", msg); break;
    case MQVPN_LOG_ERROR: LOG_ERR("[lib] %s", msg); break;
    }
}

static void
cb_reconnect_scheduled(int delay_sec, void *user_ctx)
{
    (void)user_ctx;
    LOG_INF("reconnect scheduled in %d seconds", delay_sec);
}

/* ================================================================
 *  Event handlers
 * ================================================================ */

static void on_tick_timer(evutil_socket_t fd, short what, void *arg);

static void
schedule_next_tick(platform_ctx_t *p)
{
    mqvpn_interest_t interest;
    mqvpn_client_get_interest(p->client, &interest);

    int ms = interest.next_timer_ms;
    struct timeval tv = {
        .tv_sec  = ms / 1000,
        .tv_usec = (ms % 1000) * 1000,
    };
    event_add(p->ev_tick, &tv);

    /* Enable/disable TUN read based on interest */
    if (p->tun_up && p->tun.fd >= 0) {
        if (interest.tun_readable && !event_pending(p->ev_tun, EV_READ, NULL))
            event_add(p->ev_tun, NULL);
        else if (!interest.tun_readable && event_pending(p->ev_tun, EV_READ, NULL))
            event_del(p->ev_tun);
    }
}

static void
on_tick_timer(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;

    mqvpn_client_tick(p->client);
    schedule_next_tick(p);
}

static void
on_tun_read(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;
    uint8_t buf[65536];

    for (int i = 0; i < 64; i++) {
        int n = mqvpn_tun_read(&p->tun, buf, sizeof(buf));
        if (n <= 0) break;

        int ret = mqvpn_client_on_tun_packet(p->client, buf, (size_t)n);
        if (ret == MQVPN_ERR_AGAIN) {
            /* Backpressure — stop reading TUN until ready_for_tun callback */
            event_del(p->ev_tun);
            break;
        }
    }
}

static void
on_socket_read(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;
    uint8_t buf[65536];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);

    for (int i = 0; i < 64; i++) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n <= 0) break;

        /* Find which library path handle matches this fd */
        mqvpn_path_handle_t handle = -1;
        for (int j = 0; j < p->path_mgr.n_paths; j++) {
            if (p->path_mgr.paths[j].fd == fd) {
                handle = p->lib_path_handles[j];
                break;
            }
        }
        if (handle < 0) break;

        mqvpn_client_on_socket_recv(p->client, handle, buf, (size_t)n,
                                     (struct sockaddr *)&peer, peer_len);
    }
    /* Drive engine after receiving packets */
    mqvpn_client_tick(p->client);
    schedule_next_tick(p);
}

static void
on_signal(evutil_socket_t sig, short what, void *arg)
{
    (void)sig; (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;

    LOG_INF("received signal, shutting down...");
    p->shutting_down = 1;
    mqvpn_client_disconnect(p->client);
    /* state_changed callback will call event_base_loopbreak on CLOSED */
}

/* ================================================================
 *  Main entry point: linux_platform_run_client
 * ================================================================ */

int
linux_platform_run_client(const mqvpn_client_cfg_t *cfg)
{
    int rc = 1;
    platform_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.tun.fd = -1;
    ctx.server_port = cfg->server_port;
    ctx.killswitch_enabled = cfg->kill_switch;

    /* Pre-set TUN name */
    if (cfg->tun_name)
        snprintf(ctx.tun.name, sizeof(ctx.tun.name), "%s", cfg->tun_name);

    /* DNS setup */
    mqvpn_dns_init(&ctx.dns);
    for (int i = 0; i < cfg->n_dns; i++)
        mqvpn_dns_add_server(&ctx.dns, cfg->dns_servers[i]);

    /* Resolve server address */
    if (mqvpn_resolve_host(cfg->server_addr, &ctx.server_addr, &ctx.server_addrlen) < 0) {
        LOG_ERR("could not resolve server address: %s", cfg->server_addr);
        return 1;
    }
    mqvpn_sa_set_port(&ctx.server_addr, (uint16_t)cfg->server_port);

    /* Create libmqvpn config */
    mqvpn_config_t *lib_cfg = mqvpn_config_new();
    if (!lib_cfg) { LOG_ERR("failed to allocate config"); return 1; }

    mqvpn_config_set_server(lib_cfg, cfg->server_addr, cfg->server_port);
    if (cfg->auth_key) mqvpn_config_set_auth_key(lib_cfg, cfg->auth_key);
    mqvpn_config_set_insecure(lib_cfg, cfg->insecure);
    mqvpn_config_set_multipath(lib_cfg, cfg->n_paths > 1 ? 1 : 0);
    mqvpn_config_set_reconnect(lib_cfg, cfg->reconnect,
                                cfg->reconnect_interval > 0 ? cfg->reconnect_interval : 5);
    mqvpn_config_set_killswitch_hint(lib_cfg, cfg->kill_switch);

    /* Map xquic log level back to library log level */
    mqvpn_log_level_t lib_log;
    if (cfg->log_level >= 5) lib_log = MQVPN_LOG_DEBUG;
    else if (cfg->log_level >= 3) lib_log = MQVPN_LOG_INFO;
    else if (cfg->log_level >= 2) lib_log = MQVPN_LOG_WARN;
    else lib_log = MQVPN_LOG_ERROR;
    mqvpn_config_set_log_level(lib_cfg, lib_log);

    mqvpn_config_set_scheduler(lib_cfg,
        cfg->scheduler == 1 ? MQVPN_SCHED_WLB : MQVPN_SCHED_MINRTT);

    /* Create callbacks */
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output          = cb_tun_output;
    cbs.tunnel_config_ready = cb_tunnel_config_ready;
    cbs.send_packet         = NULL;  /* fd-only mode */
    cbs.tunnel_closed       = cb_tunnel_closed;
    cbs.ready_for_tun       = cb_ready_for_tun;
    cbs.state_changed       = cb_state_changed;
    cbs.path_event          = cb_path_event;
    cbs.mtu_updated         = cb_mtu_updated;
    cbs.log                 = cb_log;
    cbs.reconnect_scheduled = cb_reconnect_scheduled;

    /* Create client */
    ctx.client = mqvpn_client_new(lib_cfg, &cbs, &ctx);
    mqvpn_config_free(lib_cfg);
    if (!ctx.client) {
        LOG_ERR("failed to create mqvpn client");
        return 1;
    }

    /* Set server address on client */
    mqvpn_client_set_server_addr(ctx.client,
        (struct sockaddr *)&ctx.server_addr, ctx.server_addrlen);

    /* Create event base */
    ctx.eb = event_base_new();
    if (!ctx.eb) { LOG_ERR("event_base_new failed"); goto cleanup; }

    /* Create UDP sockets */
    mqvpn_path_mgr_init(&ctx.path_mgr);
    if (cfg->n_paths > 0) {
        for (int i = 0; i < cfg->n_paths; i++)
            mqvpn_path_mgr_add(&ctx.path_mgr, cfg->path_ifaces[i], &ctx.server_addr);
    } else {
        mqvpn_path_mgr_add(&ctx.path_mgr, NULL, &ctx.server_addr);
    }

    /* Register paths with library and create socket events */
    for (int i = 0; i < ctx.path_mgr.n_paths; i++) {
        mqvpn_path_t *mp = &ctx.path_mgr.paths[i];
        mqvpn_path_desc_t desc = {0};
        desc.struct_size = sizeof(desc);
        desc.fd = mp->fd;
        snprintf(desc.iface, sizeof(desc.iface), "%s", mp->iface);
        if (mp->local_addrlen > 0 && mp->local_addrlen <= sizeof(desc.local_addr)) {
            memcpy(desc.local_addr, &mp->local_addr, mp->local_addrlen);
            desc.local_addr_len = mp->local_addrlen;
        }

        ctx.lib_path_handles[i] = mqvpn_client_add_path_fd(ctx.client, mp->fd, &desc);
        if (ctx.lib_path_handles[i] < 0) {
            LOG_ERR("failed to register path %d with library", i);
            goto cleanup;
        }

        ctx.ev_udp[i] = event_new(ctx.eb, mp->fd, EV_READ | EV_PERSIST,
                                   on_socket_read, &ctx);
        event_add(ctx.ev_udp[i], NULL);
    }

    /* Signal handlers */
    ctx.ev_sigint  = evsignal_new(ctx.eb, SIGINT,  on_signal, &ctx);
    ctx.ev_sigterm = evsignal_new(ctx.eb, SIGTERM, on_signal, &ctx);
    event_add(ctx.ev_sigint, NULL);
    event_add(ctx.ev_sigterm, NULL);

    /* Tick timer */
    ctx.ev_tick = event_new(ctx.eb, -1, 0, on_tick_timer, &ctx);

    /* Connect */
    if (mqvpn_client_connect(ctx.client) != MQVPN_OK) {
        LOG_ERR("client connect failed");
        goto cleanup;
    }

    /* Schedule initial tick */
    schedule_next_tick(&ctx);

    LOG_INF("entering event loop...");
    event_base_dispatch(ctx.eb);
    rc = 0;

cleanup:
    /* Clean up platform resources */
    cleanup_killswitch(&ctx);
    cleanup_routes(&ctx);
    mqvpn_dns_restore(&ctx.dns);

    if (ctx.tun_up) {
        if (ctx.ev_tun) { event_del(ctx.ev_tun); event_free(ctx.ev_tun); }
        mqvpn_tun_destroy(&ctx.tun);
    }

    for (int i = 0; i < ctx.path_mgr.n_paths; i++) {
        if (ctx.ev_udp[i]) { event_del(ctx.ev_udp[i]); event_free(ctx.ev_udp[i]); }
    }

    if (ctx.ev_tick)    { event_del(ctx.ev_tick);    event_free(ctx.ev_tick); }
    if (ctx.ev_sigint)  { event_del(ctx.ev_sigint);  event_free(ctx.ev_sigint); }
    if (ctx.ev_sigterm) { event_del(ctx.ev_sigterm); event_free(ctx.ev_sigterm); }

    mqvpn_path_mgr_destroy(&ctx.path_mgr);
    mqvpn_client_destroy(ctx.client);

    if (ctx.eb) event_base_free(ctx.eb);

    return rc;
}

/* ================================================================
 *  Server platform layer
 * ================================================================ */

typedef struct {
    mqvpn_server_t     *server;
    struct event_base  *eb;
    struct event       *ev_tick;
    struct event       *ev_tun;
    struct event       *ev_socket;
    struct event       *ev_sigint;
    struct event       *ev_sigterm;
    mqvpn_tun_t         tun;
    int                 tun_up;
    int                 udp_fd;
    int                 shutting_down;
} server_platform_ctx_t;

static void svr_on_tick(evutil_socket_t fd, short what, void *arg);
static void svr_on_tun_read(evutil_socket_t fd, short what, void *arg);

static void
svr_schedule_next_tick(server_platform_ctx_t *sp)
{
    mqvpn_interest_t interest;
    mqvpn_server_get_interest(sp->server, &interest);

    int ms = interest.next_timer_ms;
    struct timeval tv = {
        .tv_sec  = ms / 1000,
        .tv_usec = (ms % 1000) * 1000,
    };
    event_add(sp->ev_tick, &tv);

    /* Enable/disable TUN read based on interest */
    if (sp->tun_up && sp->tun.fd >= 0 && sp->ev_tun) {
        if (interest.tun_readable && !event_pending(sp->ev_tun, EV_READ, NULL))
            event_add(sp->ev_tun, NULL);
        else if (!interest.tun_readable && event_pending(sp->ev_tun, EV_READ, NULL))
            event_del(sp->ev_tun);
    }
}

static void
svr_on_tick(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    server_platform_ctx_t *sp = (server_platform_ctx_t *)arg;
    mqvpn_server_tick(sp->server);
    svr_schedule_next_tick(sp);
}

static void
svr_cb_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    server_platform_ctx_t *sp = (server_platform_ctx_t *)user_ctx;
    if (sp->tun_up && sp->tun.fd >= 0)
        mqvpn_tun_write(&sp->tun, pkt, len);
}

static void
svr_cb_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    server_platform_ctx_t *sp = (server_platform_ctx_t *)user_ctx;

    /* Create TUN device */
    const char *tun_name = sp->tun.name[0] ? sp->tun.name : "mqvpn0";
    if (mqvpn_tun_create(&sp->tun, tun_name) < 0) {
        LOG_ERR("TUN create failed");
        return;
    }

    /* Set IPv4 address — server gets assigned_ip (the .1 address) */
    char srv_ip[INET_ADDRSTRLEN], base_ip[INET_ADDRSTRLEN];
    snprintf(srv_ip, sizeof(srv_ip), "%d.%d.%d.%d",
             info->assigned_ip[0], info->assigned_ip[1],
             info->assigned_ip[2], info->assigned_ip[3]);
    snprintf(base_ip, sizeof(base_ip), "%d.%d.%d.%d",
             info->server_ip[0], info->server_ip[1],
             info->server_ip[2], info->server_ip[3]);

    if (mqvpn_tun_set_addr(&sp->tun, srv_ip, base_ip,
                            info->assigned_prefix) < 0) return;
    if (mqvpn_tun_set_mtu(&sp->tun, info->mtu) < 0) return;
    if (mqvpn_tun_up(&sp->tun) < 0) return;

    /* IPv6 if available */
    if (info->has_v6) {
        char v6str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, info->assigned_ip6, v6str, sizeof(v6str));
        if (mqvpn_tun_set_addr6(&sp->tun, v6str, info->assigned_prefix6) < 0)
            LOG_WRN("failed to set IPv6 on TUN (continuing IPv4-only)");
    }

    LOG_INF("TUN %s configured: %s (mtu=%d)", sp->tun.name, srv_ip, info->mtu);

    /* Register TUN read event */
    sp->ev_tun = event_new(sp->eb, sp->tun.fd, EV_READ | EV_PERSIST,
                            svr_on_tun_read, sp);
    if (sp->ev_tun) {
        event_add(sp->ev_tun, NULL);
        sp->tun_up = 1;
    }
}

static void
svr_cb_log(mqvpn_log_level_t level, const char *msg, void *user_ctx)
{
    (void)user_ctx;
    switch (level) {
    case MQVPN_LOG_DEBUG: LOG_DBG("[svr] %s", msg); break;
    case MQVPN_LOG_INFO:  LOG_INF("[svr] %s", msg); break;
    case MQVPN_LOG_WARN:  LOG_WRN("[svr] %s", msg); break;
    case MQVPN_LOG_ERROR: LOG_ERR("[svr] %s", msg); break;
    }
}

static void
svr_on_tun_read(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    server_platform_ctx_t *sp = (server_platform_ctx_t *)arg;
    uint8_t buf[65536];

    for (int i = 0; i < 64; i++) {
        int n = mqvpn_tun_read(&sp->tun, buf, sizeof(buf));
        if (n <= 0) break;

        int ret = mqvpn_server_on_tun_packet(sp->server, buf, (size_t)n);
        if (ret == MQVPN_ERR_AGAIN) {
            /* Backpressure — stop reading TUN */
            event_del(sp->ev_tun);
            break;
        }
    }
    mqvpn_server_tick(sp->server);
    svr_schedule_next_tick(sp);
}

static void
svr_on_socket_read(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    server_platform_ctx_t *sp = (server_platform_ctx_t *)arg;
    uint8_t buf[65536];
    struct sockaddr_in6 peer;
    socklen_t peer_len;

    for (int i = 0; i < 64; i++) {
        peer_len = sizeof(peer);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n <= 0) break;

        mqvpn_server_on_socket_recv(sp->server, buf, (size_t)n,
                                     (struct sockaddr *)&peer, peer_len);
    }
    mqvpn_server_tick(sp->server);
    svr_schedule_next_tick(sp);
}

static void
svr_on_signal(evutil_socket_t sig, short what, void *arg)
{
    (void)sig; (void)what;
    server_platform_ctx_t *sp = (server_platform_ctx_t *)arg;
    LOG_INF("received signal, shutting down server...");
    sp->shutting_down = 1;
    event_base_loopbreak(sp->eb);
}

static int
svr_create_udp_socket(const char *addr, int port,
                       struct sockaddr_storage *out_addr,
                       socklen_t *out_addrlen)
{
    sa_family_t af = AF_INET;
    struct in_addr  addr4;
    struct in6_addr addr6;
    if (addr && addr[0]) {
        if (inet_pton(AF_INET6, addr, &addr6) == 1)
            af = AF_INET6;
        else if (inet_pton(AF_INET, addr, &addr4) == 1)
            af = AF_INET;
        else {
            LOG_ERR("invalid listen address: %s", addr);
            return -1;
        }
    }

    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) { LOG_ERR("socket: %s", strerror(errno)); return -1; }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERR("fcntl: %s", strerror(errno));
        close(fd);
        return -1;
    }

    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    int bufsize = 1 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    memset(out_addr, 0, sizeof(*out_addr));
    if (af == AF_INET6) {
        int v6only = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out_addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        if (addr && addr[0]) sin6->sin6_addr = addr6;
        else sin6->sin6_addr = in6addr_any;
        *out_addrlen = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)out_addr;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        if (addr && addr[0]) sin->sin_addr = addr4;
        else sin->sin_addr.s_addr = htonl(INADDR_ANY);
        *out_addrlen = sizeof(struct sockaddr_in);
    }

    if (bind(fd, (struct sockaddr *)out_addr, *out_addrlen) < 0) {
        LOG_ERR("bind %s:%d: %s",
                addr ? addr : (af == AF_INET6 ? "::" : "0.0.0.0"),
                port, strerror(errno));
        close(fd);
        return -1;
    }

    LOG_INF("UDP socket bound to %s:%d",
            addr ? addr : (af == AF_INET6 ? "::" : "0.0.0.0"), port);
    return fd;
}

int
linux_platform_run_server(const mqvpn_server_cfg_t *cfg)
{
    int rc = 1;
    server_platform_ctx_t sp;
    memset(&sp, 0, sizeof(sp));
    sp.tun.fd = -1;
    sp.udp_fd = -1;

    if (cfg->tun_name)
        snprintf(sp.tun.name, sizeof(sp.tun.name), "%s", cfg->tun_name);

    /* Create libmqvpn config */
    mqvpn_config_t *lib_cfg = mqvpn_config_new();
    if (!lib_cfg) { LOG_ERR("failed to allocate config"); return 1; }

    mqvpn_config_set_listen(lib_cfg, cfg->listen_addr, cfg->listen_port);
    mqvpn_config_set_subnet(lib_cfg, cfg->subnet);
    if (cfg->subnet6) mqvpn_config_set_subnet6(lib_cfg, cfg->subnet6);
    if (cfg->cert_file && cfg->key_file)
        mqvpn_config_set_tls_cert(lib_cfg, cfg->cert_file, cfg->key_file);
    if (cfg->auth_key) mqvpn_config_set_auth_key(lib_cfg, cfg->auth_key);
    mqvpn_config_set_max_clients(lib_cfg, cfg->max_clients);
    mqvpn_config_set_scheduler(lib_cfg,
        cfg->scheduler == 1 ? MQVPN_SCHED_WLB : MQVPN_SCHED_MINRTT);

    mqvpn_log_level_t lib_log;
    if (cfg->log_level >= 5) lib_log = MQVPN_LOG_DEBUG;
    else if (cfg->log_level >= 3) lib_log = MQVPN_LOG_INFO;
    else if (cfg->log_level >= 2) lib_log = MQVPN_LOG_WARN;
    else lib_log = MQVPN_LOG_ERROR;
    mqvpn_config_set_log_level(lib_cfg, lib_log);

    /* Create server callbacks */
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = svr_cb_tun_output;
    cbs.tunnel_config_ready = svr_cb_tunnel_config_ready;
    cbs.send_packet = NULL;  /* fd-only mode */
    cbs.log = svr_cb_log;

    /* Create server */
    sp.server = mqvpn_server_new(lib_cfg, &cbs, &sp);
    mqvpn_config_free(lib_cfg);
    if (!sp.server) {
        LOG_ERR("failed to create mqvpn server");
        return 1;
    }

    /* Create UDP socket */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    sp.udp_fd = svr_create_udp_socket(cfg->listen_addr, cfg->listen_port,
                                       &local_addr, &local_addrlen);
    if (sp.udp_fd < 0) goto cleanup;

    mqvpn_server_set_socket_fd(sp.server, sp.udp_fd,
                               (struct sockaddr *)&local_addr, local_addrlen);

    /* Create event base */
    sp.eb = event_base_new();
    if (!sp.eb) { LOG_ERR("event_base_new failed"); goto cleanup; }

    /* Start server (triggers tunnel_config_ready → TUN creation) */
    if (mqvpn_server_start(sp.server) != MQVPN_OK) {
        LOG_ERR("server start failed");
        goto cleanup;
    }

    /* Register socket read event */
    sp.ev_socket = event_new(sp.eb, sp.udp_fd, EV_READ | EV_PERSIST,
                              svr_on_socket_read, &sp);
    event_add(sp.ev_socket, NULL);

    /* Signal handlers */
    sp.ev_sigint  = evsignal_new(sp.eb, SIGINT,  svr_on_signal, &sp);
    sp.ev_sigterm = evsignal_new(sp.eb, SIGTERM, svr_on_signal, &sp);
    event_add(sp.ev_sigint, NULL);
    event_add(sp.ev_sigterm, NULL);

    /* Tick timer */
    sp.ev_tick = event_new(sp.eb, -1, 0, svr_on_tick, &sp);
    svr_schedule_next_tick(&sp);

    LOG_INF("mqvpn server ready — listening on %s:%d, subnet %s",
            cfg->listen_addr ? cfg->listen_addr : "0.0.0.0",
            cfg->listen_port, cfg->subnet);

    event_base_dispatch(sp.eb);
    rc = 0;

cleanup:
    LOG_INF("server shutting down");
    if (sp.tun_up) {
        if (sp.ev_tun) { event_del(sp.ev_tun); event_free(sp.ev_tun); }
        mqvpn_tun_destroy(&sp.tun);
    }
    if (sp.ev_socket)  { event_del(sp.ev_socket);  event_free(sp.ev_socket); }
    if (sp.ev_tick)    { event_del(sp.ev_tick);    event_free(sp.ev_tick); }
    if (sp.ev_sigint)  { event_del(sp.ev_sigint);  event_free(sp.ev_sigint); }
    if (sp.ev_sigterm) { event_del(sp.ev_sigterm); event_free(sp.ev_sigterm); }
    if (sp.udp_fd >= 0) close(sp.udp_fd);
    mqvpn_server_destroy(sp.server);
    if (sp.eb) event_base_free(sp.eb);

    return rc;
}
