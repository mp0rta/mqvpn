/*
 * platform_windows.c — Windows platform layer for libmqvpn
 *
 * Bridges libmqvpn (sans-I/O) with Windows-specific I/O:
 *   - libevent event loop driving tick()
 *   - Wintun TUN device via reader thread + socketpair
 *   - UDP sockets via path_mgr
 *   - Ctrl+C handling via SetConsoleCtrlHandler
 *
 * Routing, killswitch, and DNS are in separate files.
 */

#ifdef _WIN32

#  include "platform_internal_win.h"
#  include "platform_windows.h"
#  include "log.h"

#  include <stdio.h>
#  include <stdlib.h>
#  include <string.h>

/* ── Global for Ctrl+C handler (single-instance) ── */
static platform_win_ctx_t *g_signal_ctx = NULL;

/* ================================================================
 *  libmqvpn callbacks
 * ================================================================ */

static void on_tun_read(evutil_socket_t fd, short what, void *arg);
static void on_socket_read(evutil_socket_t fd, short what, void *arg);

static void
cb_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    platform_win_ctx_t *p = (platform_win_ctx_t *)user_ctx;
    if (p->tun_up && p->tun.session) mqvpn_tun_win_write(&p->tun, pkt, len);
}

static void
cb_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    platform_win_ctx_t *p = (platform_win_ctx_t *)user_ctx;

    /* Clean up stale TUN from previous connection (reconnect case) */
    if (p->ev_tun) {
        event_del(p->ev_tun);
        event_free(p->ev_tun);
        p->ev_tun = NULL;
    }
    if (p->tun.adapter) {
        mqvpn_tun_win_destroy(&p->tun);
        p->tun_up = 0;
    }

    /* Create TUN device */
    if (mqvpn_tun_win_create(&p->tun, p->tun_name_cfg) < 0) {
        LOG_ERR("TUN create failed");
        goto fail;
    }

    /* Set IPv4 address */
    char local_ip[INET_ADDRSTRLEN];
    snprintf(local_ip, sizeof(local_ip), "%d.%d.%d.%d", info->assigned_ip[0],
             info->assigned_ip[1], info->assigned_ip[2], info->assigned_ip[3]);
    char peer_ip[INET_ADDRSTRLEN];
    snprintf(peer_ip, sizeof(peer_ip), "%d.%d.%d.%d", info->server_ip[0],
             info->server_ip[1], info->server_ip[2], info->server_ip[3]);

    if (mqvpn_tun_win_set_addr(&p->tun, local_ip, peer_ip, 32) < 0) goto fail;
    if (mqvpn_tun_win_set_mtu(&p->tun, info->mtu) < 0) goto fail;

    /* Set IPv6 address if available */
    if (info->has_v6) {
        p->has_v6 = 1;
        char v6str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, info->assigned_ip6, v6str, sizeof(v6str));
        if (mqvpn_tun_win_set_addr6(&p->tun, v6str, info->assigned_prefix6) < 0)
            LOG_WRN("failed to set IPv6 address on TUN (continuing IPv4-only)");
    }

    LOG_INF("TUN %s configured: %s -> %s (mtu=%d)", p->tun.name, local_ip, peer_ip,
            info->mtu);

    /* Set up routes, killswitch, DNS */
    if (win_setup_routes(p) < 0) {
        LOG_ERR("route setup failed, aborting tunnel");
        goto fail;
    }
    if (win_setup_killswitch(p) < 0) {
        LOG_ERR("killswitch setup failed, aborting tunnel");
        goto fail;
    }
    if (p->n_dns > 0) {
        p->dns_if_index = p->tun.if_index;
        if (win_setup_dns(p) < 0)
            LOG_WRN("DNS override failed (continuing without DNS override)");
    }

    /* Start reader thread */
    if (mqvpn_tun_win_start_reader(&p->tun) < 0) {
        LOG_ERR("TUN reader thread start failed");
        goto fail;
    }

    /* Register TUN pipe read event */
    p->ev_tun = event_new(p->eb, p->tun.pipe_rd, EV_READ | EV_PERSIST, on_tun_read, p);
    if (!p->ev_tun) {
        LOG_ERR("failed to create TUN event");
        goto fail;
    }
    event_add(p->ev_tun, NULL);
    p->tun_up = 1;

    /* Tell library the TUN is active */
    mqvpn_client_set_tun_active(p->client, 1, -1);
    return;

fail:
    win_cleanup_killswitch(p);
    win_cleanup_routes(p);
    win_cleanup_dns(p);
    if (p->tun.adapter) mqvpn_tun_win_destroy(&p->tun);
    p->tun_up = 0;
    mqvpn_client_disconnect(p->client);
}

static void
cb_tunnel_closed(mqvpn_error_t reason, void *user_ctx)
{
    (void)user_ctx;
    LOG_INF("tunnel closed: %s", mqvpn_error_string(reason));
}

static void
cb_ready_for_tun(void *user_ctx)
{
    (void)user_ctx;
}

static void
cb_state_changed(mqvpn_client_state_t old_state, mqvpn_client_state_t new_state,
                 void *user_ctx)
{
    platform_win_ctx_t *p = (platform_win_ctx_t *)user_ctx;
    static const char *names[] = {"IDLE",         "CONNECTING",  "AUTHENTICATING",
                                  "TUNNEL_READY", "ESTABLISHED", "RECONNECTING",
                                  "CLOSED"};
    const char *os = (old_state < 7) ? names[old_state] : "?";
    const char *ns = (new_state < 7) ? names[new_state] : "?";
    LOG_INF("state: %s -> %s", os, ns);

    if (new_state == MQVPN_STATE_RECONNECTING || new_state == MQVPN_STATE_CLOSED) {
        win_cleanup_killswitch(p);
        win_cleanup_routes(p);
        win_cleanup_dns(p);
        if (p->tun_up) {
            if (p->ev_tun) {
                event_del(p->ev_tun);
                event_free(p->ev_tun);
                p->ev_tun = NULL;
            }
            mqvpn_tun_win_destroy(&p->tun);
            p->tun_up = 0;
            mqvpn_client_set_tun_active(p->client, 0, -1);
        }
        if (new_state == MQVPN_STATE_CLOSED && p->shutting_down)
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
    platform_win_ctx_t *p = (platform_win_ctx_t *)user_ctx;
    if (p->tun_up) mqvpn_tun_win_set_mtu(&p->tun, mtu);
    LOG_INF("TUN MTU updated to %d", mtu);
}

static void
cb_log(mqvpn_log_level_t level, const char *msg, void *user_ctx)
{
    (void)user_ctx;
    switch (level) {
    case MQVPN_LOG_DEBUG: LOG_DBG("[lib] %s", msg); break;
    case MQVPN_LOG_INFO: LOG_INF("[lib] %s", msg); break;
    case MQVPN_LOG_WARN: LOG_WRN("[lib] %s", msg); break;
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
schedule_next_tick(platform_win_ctx_t *p)
{
    mqvpn_interest_t interest;
    mqvpn_client_get_interest(p->client, &interest);

    int ms = interest.next_timer_ms;
    struct timeval tv = {
        .tv_sec = ms / 1000,
        .tv_usec = (ms % 1000) * 1000,
    };
    event_add(p->ev_tick, &tv);

    /* Enable/disable TUN read based on interest */
    if (p->tun_up && p->ev_tun) {
        if (interest.tun_readable && !event_pending(p->ev_tun, EV_READ, NULL))
            event_add(p->ev_tun, NULL);
        else if (!interest.tun_readable && event_pending(p->ev_tun, EV_READ, NULL))
            event_del(p->ev_tun);
    }
}

static void
on_tick_timer(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    platform_win_ctx_t *p = (platform_win_ctx_t *)arg;

    mqvpn_client_tick(p->client);
    schedule_next_tick(p);
}

/*
 * Read framed packets from the TUN reader thread socketpair.
 * Frame format: [2-byte big-endian length][IP packet payload]
 */
static void
on_tun_read(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    platform_win_ctx_t *p = (platform_win_ctx_t *)arg;
    uint8_t frame[2 + 65536];

    for (int i = 0; i < 64; i++) {
        /* Read length header */
        int n = recv(p->tun.pipe_rd, (char *)frame, 2, MSG_PEEK);
        if (n < 2) break;

        uint16_t pkt_len = ((uint16_t)frame[0] << 8) | frame[1];
        if (pkt_len == 0 || pkt_len > 65535) {
            /* Drain bad frame header */
            recv(p->tun.pipe_rd, (char *)frame, 2, 0);
            continue;
        }

        int total = 2 + pkt_len;
        n = recv(p->tun.pipe_rd, (char *)frame, total, 0);
        if (n < total) break;

        int ret = mqvpn_client_on_tun_packet(p->client, frame + 2, pkt_len);
        if (ret == MQVPN_ERR_AGAIN) {
            event_del(p->ev_tun);
            break;
        }
    }
}

static void
on_socket_read(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    platform_win_ctx_t *p = (platform_win_ctx_t *)arg;
    uint8_t buf[65536];
    struct sockaddr_storage peer;
    int peer_len = sizeof(peer);

    for (int i = 0; i < 64; i++) {
        int n = recvfrom((SOCKET)fd, (char *)buf, sizeof(buf), 0,
                         (struct sockaddr *)&peer, &peer_len);
        if (n <= 0 || (size_t)n > sizeof(buf)) break;

        /* Find which library path handle matches this fd */
        mqvpn_path_handle_t handle = -1;
        for (int j = 0; j < p->path_mgr.n_paths; j++) {
            if (p->path_mgr.paths[j].fd == (int)fd) {
                handle = p->lib_path_handles[j];
                break;
            }
        }
        if (handle < 0) break;

        mqvpn_client_on_socket_recv(p->client, handle, buf, (size_t)n,
                                    (struct sockaddr *)&peer, peer_len);
    }
    mqvpn_client_tick(p->client);
    schedule_next_tick(p);
}

/* ── Ctrl+C handler ── */

static BOOL WINAPI
console_ctrl_handler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        platform_win_ctx_t *p = g_signal_ctx;
        if (p) {
            LOG_INF("received Ctrl+C, shutting down...");
            p->shutting_down = 1;
            mqvpn_client_disconnect(p->client);
        }
        return TRUE;
    }
    return FALSE;
}

/* ================================================================
 *  DNS helper (from platform/linux/dns.c — portable subset)
 * ================================================================ */

static int
win_resolve_host(const char *host, struct sockaddr_storage *out, socklen_t *out_len)
{
    struct in_addr a4;
    struct in6_addr a6;

    if (inet_pton(AF_INET, host, &a4) == 1) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        memset(sin, 0, sizeof(*sin));
        sin->sin_family = AF_INET;
        sin->sin_addr = a4;
        *out_len = sizeof(struct sockaddr_in);
        return 0;
    }
    if (inet_pton(AF_INET6, host, &a6) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        memset(sin6, 0, sizeof(*sin6));
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = a6;
        *out_len = sizeof(struct sockaddr_in6);
        return 0;
    }

    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM};
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;

    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

static void
win_sa_set_port(struct sockaddr_storage *ss, uint16_t port)
{
    if (ss->ss_family == AF_INET)
        ((struct sockaddr_in *)ss)->sin_port = htons(port);
    else if (ss->ss_family == AF_INET6)
        ((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
}

/* ================================================================
 *  Main entry point: win_platform_run_client
 * ================================================================ */

int
win_platform_run_client(const mqvpn_client_cfg_t *cfg)
{
    int rc = 1;
    platform_win_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.server_port = cfg->server_port;
    ctx.killswitch_enabled = cfg->kill_switch;

    /* TUN name */
    if (cfg->tun_name) {
        snprintf(ctx.tun_name_cfg, sizeof(ctx.tun_name_cfg), "%s", cfg->tun_name);
    } else {
        snprintf(ctx.tun_name_cfg, sizeof(ctx.tun_name_cfg), "mqvpn0");
    }

    /* DNS setup */
    for (int i = 0; i < cfg->n_dns && i < 4; i++) {
        snprintf(ctx.dns_servers[i], sizeof(ctx.dns_servers[i]), "%s",
                 cfg->dns_servers[i]);
        ctx.n_dns++;
    }

    /* Resolve server address */
    if (win_resolve_host(cfg->server_addr, &ctx.server_addr, &ctx.server_addrlen) < 0) {
        LOG_ERR("could not resolve server address: %s", cfg->server_addr);
        return 1;
    }
    win_sa_set_port(&ctx.server_addr, (uint16_t)cfg->server_port);

    /* Store server IP string for routing */
    if (ctx.server_addr.ss_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in *)&ctx.server_addr)->sin_addr,
                  ctx.server_ip_str, sizeof(ctx.server_ip_str));
    } else {
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ctx.server_addr)->sin6_addr,
                  ctx.server_ip_str, sizeof(ctx.server_ip_str));
    }

    /* Create libmqvpn config */
    mqvpn_config_t *lib_cfg = mqvpn_config_new();
    if (!lib_cfg) {
        LOG_ERR("failed to allocate config");
        return 1;
    }

    mqvpn_config_set_server(lib_cfg, cfg->server_addr, cfg->server_port);
    if (cfg->auth_key) mqvpn_config_set_auth_key(lib_cfg, cfg->auth_key);
    mqvpn_config_set_insecure(lib_cfg, cfg->insecure);
    mqvpn_config_set_multipath(lib_cfg, cfg->n_paths > 1 ? 1 : 0);
    mqvpn_config_set_reconnect(lib_cfg, cfg->reconnect,
                               cfg->reconnect_interval > 0 ? cfg->reconnect_interval : 5);
    mqvpn_config_set_killswitch_hint(lib_cfg, cfg->kill_switch);

    mqvpn_log_level_t lib_log;
    if (cfg->log_level >= 5)
        lib_log = MQVPN_LOG_DEBUG;
    else if (cfg->log_level >= 3)
        lib_log = MQVPN_LOG_INFO;
    else if (cfg->log_level >= 2)
        lib_log = MQVPN_LOG_WARN;
    else
        lib_log = MQVPN_LOG_ERROR;
    mqvpn_config_set_log_level(lib_cfg, lib_log);

    mqvpn_config_set_scheduler(lib_cfg, cfg->scheduler == 1 ? MQVPN_SCHED_WLB
                                                            : MQVPN_SCHED_MINRTT);

    /* Create callbacks */
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = cb_tun_output;
    cbs.tunnel_config_ready = cb_tunnel_config_ready;
    cbs.send_packet = NULL; /* fd-only mode */
    cbs.tunnel_closed = cb_tunnel_closed;
    cbs.ready_for_tun = cb_ready_for_tun;
    cbs.state_changed = cb_state_changed;
    cbs.path_event = cb_path_event;
    cbs.mtu_updated = cb_mtu_updated;
    cbs.log = cb_log;
    cbs.reconnect_scheduled = cb_reconnect_scheduled;

    /* Create client */
    ctx.client = mqvpn_client_new(lib_cfg, &cbs, &ctx);
    mqvpn_config_free(lib_cfg);
    if (!ctx.client) {
        LOG_ERR("failed to create mqvpn client");
        return 1;
    }

    mqvpn_client_set_server_addr(ctx.client, (struct sockaddr *)&ctx.server_addr,
                                 ctx.server_addrlen);

    /* Create event base */
    ctx.eb = event_base_new();
    if (!ctx.eb) {
        LOG_ERR("event_base_new failed");
        goto cleanup;
    }

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

        ctx.ev_udp[i] = event_new(ctx.eb, (evutil_socket_t)mp->fd, EV_READ | EV_PERSIST,
                                  on_socket_read, &ctx);
        event_add(ctx.ev_udp[i], NULL);
    }

    /* Ctrl+C handler */
    g_signal_ctx = &ctx;
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

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
    SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
    g_signal_ctx = NULL;

    win_cleanup_killswitch(&ctx);
    win_cleanup_routes(&ctx);
    win_cleanup_dns(&ctx);

    if (ctx.tun_up) {
        if (ctx.ev_tun) {
            event_del(ctx.ev_tun);
            event_free(ctx.ev_tun);
        }
        mqvpn_tun_win_destroy(&ctx.tun);
    }

    for (int i = 0; i < ctx.path_mgr.n_paths; i++) {
        if (ctx.ev_udp[i]) {
            event_del(ctx.ev_udp[i]);
            event_free(ctx.ev_udp[i]);
        }
    }

    if (ctx.ev_tick) {
        event_del(ctx.ev_tick);
        event_free(ctx.ev_tick);
    }

    mqvpn_path_mgr_destroy(&ctx.path_mgr);
    mqvpn_client_destroy(ctx.client);

    if (ctx.eb) event_base_free(ctx.eb);

    return rc;
}

/* ================================================================
 *  Server platform layer (placeholder — server typically runs Linux)
 * ================================================================ */

int
win_platform_run_server(const mqvpn_server_cfg_t *cfg)
{
    (void)cfg;
    LOG_ERR("Windows server mode is not yet implemented");
    return 1;
}

#endif /* _WIN32 */
