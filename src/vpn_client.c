#include "vpn_client.h"
#include "path_mgr.h"
#include "flow_sched.h"
#include "tun.h"
#include "dns.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <net/if.h>
#include <inttypes.h>
#include <sys/wait.h>

#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

#define PACKET_BUF_SIZE  65536
#define MASQUE_FRAME_BUF (PACKET_BUF_SIZE + 16)

#define PATH_RECREATE_DELAY_SEC   5
#define PATH_RECREATE_MAX_RETRIES 6
#define TUN_RESUME_SAFETY_MS      100
#define XQC_SNDQ_MAX_PKTS         16384
#define RECONNECT_BACKOFF_MAX_SEC 60

static uint64_t
mqvpn_now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

/* ---------- forward declarations ---------- */

typedef struct cli_ctx_s        cli_ctx_t;
typedef struct cli_conn_s       cli_conn_t;
typedef struct cli_stream_s     cli_stream_t;

static void cli_tun_read_handler(int fd, short what, void *arg);
static void cli_reconnect_callback(int fd, short what, void *arg);
static int  cli_start_connection(cli_ctx_t *ctx);

/* ---------- client context ---------- */

struct cli_ctx_s {
    const mqvpn_client_cfg_t *cfg;

    xqc_engine_t        *engine;
    struct event_base   *eb;
    struct event        *ev_engine;  /* xquic timer */
    struct event        *ev_tun;     /* TUN device read (added after tunnel up) */
    struct event        *ev_sigint;
    struct event        *ev_sigterm;
    struct event        *ev_path_recreate;  /* timer to re-create removed paths */
    struct event        *ev_tun_resume;     /* safety timer to resume TUN read */
    int                  path_recreate_retries;

    /* Multipath: per-path UDP sockets */
    mqvpn_path_mgr_t     path_mgr;
    struct sockaddr_storage server_addr;
    socklen_t            server_addrlen;

    mqvpn_tun_t          tun;
    int                  tun_up;
    int                  tun_paused;     /* TUN reading paused (QUIC backpressure) */
    uint64_t             tun_drop_cnt;   /* TUN write failure counter */

    /* Split tunneling state */
    int                  routing_configured;
    int                  routing6_configured; /* IPv6 data plane routes */
    char                 orig_gateway[INET6_ADDRSTRLEN];
    char                 orig_iface[IFNAMSIZ];
    char                 server_ip_str[INET6_ADDRSTRLEN];

    cli_conn_t          *conn;

    mqvpn_dns_t          dns;

    /* Kill switch state */
    int                  killswitch_active;
    char                 ks_comment[64];  /* iptables comment tag */

    /* Reconnection state */
    int                  shutting_down;   /* SIGINT/SIGTERM received */
    struct event        *ev_reconnect;    /* reconnect timer */
    int                  reconnect_attempts;
};

/* ---------- per-connection state ---------- */

struct cli_conn_s {
    cli_ctx_t           *ctx;
    xqc_h3_conn_t       *h3_conn;
    xqc_cid_t            cid;
    size_t               dgram_mss;

    /* MASQUE session */
    xqc_h3_request_t    *masque_request;
    uint64_t             masque_stream_id;
    int                  tunnel_ok;       /* 200 received */
    int                  addr_assigned;   /* IPv4 ADDRESS_ASSIGN received */
    uint8_t              assigned_ip[4];
    uint8_t              assigned_prefix;
    int                  addr6_assigned;  /* IPv6 ADDRESS_ASSIGN received */
    uint8_t              assigned_ip6[16];
    uint8_t              assigned_prefix6;
    uint64_t             dgram_lost_cnt;
    uint64_t             dgram_acked_cnt;
};

/* ---------- per-stream state ---------- */

struct cli_stream_s {
    cli_conn_t          *conn;
    xqc_h3_request_t    *h3_request;
    uint8_t             *capsule_buf;
    size_t               capsule_len;
    size_t               capsule_cap;
};

/* ---------- static context ---------- */

static cli_ctx_t g_cli;

static void
cli_log_conn_stats(const char *tag, const xqc_cid_t *cid)
{
    if (!g_cli.engine || !cid) {
        return;
    }
    xqc_conn_stats_t st = xqc_conn_get_stats(g_cli.engine, cid);
    LOG_INF("%s: send=%u recv=%u lost=%u lost_dgram=%u srtt=%.2fms min_rtt=%.2fms inflight=%" PRIu64 " app_bytes=%" PRIu64 " standby_bytes=%" PRIu64 " mp_state=%d",
            tag,
            st.send_count, st.recv_count, st.lost_count, st.lost_dgram_count,
            (double)st.srtt / 1000.0, (double)st.min_rtt / 1000.0,
            st.inflight_bytes, st.total_app_bytes, st.standby_path_app_bytes,
            st.mp_state);
}

static void
cli_signal_event_callback(evutil_socket_t sig, short events, void *arg)
{
    (void)sig;
    (void)events;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    ctx->shutting_down = 1;
    if (ctx->ev_reconnect) {
        event_del(ctx->ev_reconnect);
    }
    event_base_loopbreak(ctx->eb);
}

/* ================================================================
 *  xquic log callback
 * ================================================================ */

static void
cli_xqc_log_write(xqc_log_level_t lvl, const void *buf, size_t size,
                   void *engine_user_data)
{
    (void)engine_user_data;
    (void)lvl;
    LOG_DBG("[xquic] %.*s", (int)size, (const char *)buf);
}

/* ================================================================
 *  Engine timer
 * ================================================================ */

static void
cli_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
    cli_ctx_t *ctx = (cli_ctx_t *)engine_user_data;
    struct timeval tv;
    tv.tv_sec  = (long)(wake_after / 1000000);
    tv.tv_usec = (long)(wake_after % 1000000);
    event_add(ctx->ev_engine, &tv);
}

static void
cli_engine_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    xqc_engine_main_logic(ctx->engine);
}

/* ================================================================
 *  UDP socket write (xquic → network)
 * ================================================================ */

static ssize_t
cli_write_socket(const unsigned char *buf, size_t size,
                 const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                 void *conn_user_data)
{
    /* Legacy single-path write — use primary path */
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    int fd = mqvpn_path_mgr_get_fd(&conn->ctx->path_mgr, 0);
    ssize_t res;
    do {
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
    } while (res < 0 && errno == EINTR);

    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return XQC_SOCKET_EAGAIN;
        }
        return XQC_SOCKET_ERROR;
    }
    return res;
}

static ssize_t
cli_write_socket_ex(uint64_t path_id,
                    const unsigned char *buf, size_t size,
                    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                    void *conn_user_data)
{
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    int fd = mqvpn_path_mgr_get_fd(&conn->ctx->path_mgr, path_id);
    ssize_t res;
    do {
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
    } while (res < 0 && errno == EINTR);

    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return XQC_SOCKET_EAGAIN;
        }
        return XQC_SOCKET_ERROR;
    }
    return res;
}

/* ================================================================
 *  UDP socket read (network → xquic)
 * ================================================================ */

static void
cli_socket_read_handler(cli_ctx_t *ctx, int sock_fd)
{
    unsigned char buf[PACKET_BUF_SIZE];
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);

    /* Find local addr for this path's socket */
    mqvpn_path_t *path = mqvpn_path_mgr_find_by_fd(&ctx->path_mgr, sock_fd);
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen = sizeof(local_addr);
    if (path) {
        memcpy(&local_addr, &path->local_addr, sizeof(local_addr));
        local_addrlen = path->local_addrlen;
    } else {
        memset(&local_addr, 0, sizeof(local_addr));
    }

    for (;;) {
        ssize_t n = recvfrom(sock_fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            LOG_ERR("recvfrom: %s", strerror(errno));
            break;
        }

        uint64_t recv_time = mqvpn_now_us();
        xqc_engine_packet_process(
            ctx->engine, buf, (size_t)n,
            (struct sockaddr *)&local_addr, local_addrlen,
            (struct sockaddr *)&peer_addr, peer_addrlen,
            (xqc_usec_t)recv_time, NULL);
    }
    xqc_engine_finish_recv(ctx->engine);
}

static void
cli_socket_event_callback(int fd, short what, void *arg)
{
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    if (what & EV_READ) {
        cli_socket_read_handler(ctx, fd);
    }
}

/* ================================================================
 *  Split tunneling: route server IP via original gateway
 * ================================================================ */

static int
cli_run_ip_cmd(const char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        LOG_WRN("fork for ip command failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        execvp("ip", (char * const *)argv);
        _exit(127);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        LOG_WRN("waitpid failed: %s", strerror(errno));
        return -1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -1;
    }
    return 0;
}

static int
cli_discover_route(const char *server_ip, sa_family_t af,
                    char *gateway, size_t gateway_len,
                    char *iface, size_t iface_len)
{
    int fds[2];
    if (pipe(fds) < 0) {
        LOG_WRN("pipe failed: %s", strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        LOG_WRN("fork failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        const char *const argv4[] = {"ip", "-4", "route", "get", server_ip, NULL};
        const char *const argv6[] = {"ip", "-6", "route", "get", server_ip, NULL};
        const char *const *argv = (af == AF_INET6) ? argv6 : argv4;
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        close(fds[1]);
        execvp("ip", (char * const *)argv);
        _exit(127);
    }

    close(fds[1]);
    char out[1024];
    ssize_t nread = read(fds[0], out, sizeof(out) - 1);
    close(fds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || nread <= 0) {
        return -1;
    }

    out[nread] = '\0';
    gateway[0] = '\0';
    iface[0] = '\0';

    char *saveptr = NULL;
    for (char *tok = strtok_r(out, " \t\r\n", &saveptr);
         tok;
         tok = strtok_r(NULL, " \t\r\n", &saveptr)) {
        if (strcmp(tok, "via") == 0) {
            tok = strtok_r(NULL, " \t\r\n", &saveptr);
            if (tok) {
                snprintf(gateway, gateway_len, "%s", tok);
            }
            continue;
        }
        if (strcmp(tok, "dev") == 0) {
            tok = strtok_r(NULL, " \t\r\n", &saveptr);
            if (tok) {
                snprintf(iface, iface_len, "%s", tok);
            }
            continue;
        }
    }

    if (iface[0] == '\0') {
        return -1;
    }
    return 0;
}

static int
cli_setup_routes(cli_ctx_t *ctx)
{
    sa_family_t af = ctx->server_addr.ss_family;
    int prefix = mqvpn_sa_host_prefix(&ctx->server_addr);

    /* Extract server IP string */
    mqvpn_sa_ntop(&ctx->server_addr, ctx->server_ip_str, sizeof(ctx->server_ip_str));

    /* Discover current gateway and interface for the server IP */
    if (cli_discover_route(ctx->server_ip_str, af,
                            ctx->orig_gateway, sizeof(ctx->orig_gateway),
                            ctx->orig_iface, sizeof(ctx->orig_iface)) < 0) {
        LOG_WRN("could not determine original iface for %s",
                ctx->server_ip_str);
        return -1;
    }

    char host_cidr[INET6_ADDRSTRLEN + 5];
    snprintf(host_cidr, sizeof(host_cidr), "%s/%d", ctx->server_ip_str, prefix);
    const char *ip_flag = (af == AF_INET6) ? "-6" : "-4";

    if (ctx->orig_gateway[0] != '\0') {
        LOG_INF("split tunnel: server %s via %s dev %s",
                ctx->server_ip_str, ctx->orig_gateway, ctx->orig_iface);
        const char *const pin_route[] = {
            "ip", ip_flag, "route", "replace", host_cidr, "via", ctx->orig_gateway,
            "dev", ctx->orig_iface, NULL
        };
        if (cli_run_ip_cmd(pin_route) < 0) {
            LOG_WRN("failed to pin server route");
            return -1;
        }
    } else {
        LOG_INF("split tunnel: server %s on-link dev %s (no pin route needed)",
                ctx->server_ip_str, ctx->orig_iface);
    }

    /* Add 0.0.0.0/1 + 128.0.0.0/1 instead of default route.
     * These are more specific than 0.0.0.0/0, so they always win
     * regardless of existing default route metrics (WireGuard/OpenVPN technique).
     * Note: IPv4 catch-all only — data plane is IPv4. */
    const char *const tun_route_low[] = {
        "ip", "route", "replace", "0.0.0.0/1", "dev", ctx->tun.name, NULL
    };
    const char *const tun_route_high[] = {
        "ip", "route", "replace", "128.0.0.0/1", "dev", ctx->tun.name, NULL
    };
    if (cli_run_ip_cmd(tun_route_low) < 0 || cli_run_ip_cmd(tun_route_high) < 0) {
        LOG_WRN("failed to set catch-all routes via %s", ctx->tun.name);
        /* Clean up partial state */
        const char *const undo_low[] = {
            "ip", "route", "del", "0.0.0.0/1", "dev", ctx->tun.name, NULL
        };
        const char *const undo_high[] = {
            "ip", "route", "del", "128.0.0.0/1", "dev", ctx->tun.name, NULL
        };
        (void)cli_run_ip_cmd(undo_low);
        (void)cli_run_ip_cmd(undo_high);
        if (ctx->orig_gateway[0] != '\0') {
            const char *const undo_pin[] = {
                "ip", ip_flag, "route", "del", host_cidr, "via", ctx->orig_gateway,
                "dev", ctx->orig_iface, NULL
            };
            (void)cli_run_ip_cmd(undo_pin);
        }
        return -1;
    }

    ctx->routing_configured = 1;

    /* Add IPv6 catch-all routes if IPv6 data plane is active */
    if (ctx->conn && ctx->conn->addr6_assigned) {
        const char *const tun6_low[] = {
            "ip", "-6", "route", "replace", "::/1", "dev", ctx->tun.name, NULL
        };
        const char *const tun6_high[] = {
            "ip", "-6", "route", "replace", "8000::/1", "dev", ctx->tun.name, NULL
        };
        if (cli_run_ip_cmd(tun6_low) == 0 && cli_run_ip_cmd(tun6_high) == 0) {
            ctx->routing6_configured = 1;
            LOG_INF("IPv6 catch-all routes set via %s", ctx->tun.name);
        } else {
            LOG_WRN("failed to set IPv6 catch-all routes (continuing IPv4-only)");
        }
    }

    return 0;
}

static void
cli_cleanup_routes(cli_ctx_t *ctx)
{
    if (!ctx->routing_configured)
        return;

    /* Remove IPv6 catch-all routes if configured */
    if (ctx->routing6_configured) {
        const char *const del6_low[] = {
            "ip", "-6", "route", "del", "::/1", "dev", ctx->tun.name, NULL
        };
        const char *const del6_high[] = {
            "ip", "-6", "route", "del", "8000::/1", "dev", ctx->tun.name, NULL
        };
        (void)cli_run_ip_cmd(del6_low);
        (void)cli_run_ip_cmd(del6_high);
        ctx->routing6_configured = 0;
    }

    /* Remove IPv4 TUN catch-all routes */
    const char *const del_low[] = {
        "ip", "route", "del", "0.0.0.0/1", "dev", ctx->tun.name, NULL
    };
    const char *const del_high[] = {
        "ip", "route", "del", "128.0.0.0/1", "dev", ctx->tun.name, NULL
    };
    (void)cli_run_ip_cmd(del_low);
    (void)cli_run_ip_cmd(del_high);

    /* Remove server IP pinned route (only if gateway was set) */
    if (ctx->orig_gateway[0] != '\0') {
        const char *ip_flag = (ctx->server_addr.ss_family == AF_INET6) ? "-6" : "-4";
        int prefix = mqvpn_sa_host_prefix(&ctx->server_addr);
        char host_cidr[INET6_ADDRSTRLEN + 5];
        snprintf(host_cidr, sizeof(host_cidr), "%s/%d", ctx->server_ip_str, prefix);
        const char *const del_pin[] = {
            "ip", ip_flag, "route", "del", host_cidr, "via", ctx->orig_gateway,
            "dev", ctx->orig_iface, NULL
        };
        (void)cli_run_ip_cmd(del_pin);
    }

    ctx->routing_configured = 0;
    LOG_INF("split tunnel routes cleaned up");
}

/* ================================================================
 *  Kill switch: iptables rules to prevent traffic leaking
 * ================================================================ */

static int
cli_run_iptables_cmd(const char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        LOG_WRN("fork for iptables command failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        execvp(argv[0], (char * const *)argv);
        _exit(127);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        LOG_WRN("waitpid failed: %s", strerror(errno));
        return -1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -1;
    }
    return 0;
}

static void cli_cleanup_killswitch(cli_ctx_t *ctx);

static int
cli_setup_killswitch(cli_ctx_t *ctx)
{
    if (!ctx->cfg->kill_switch || ctx->killswitch_active)
        return 0;

    snprintf(ctx->ks_comment, sizeof(ctx->ks_comment),
             "mqvpn-ks:%d", (int)getpid());

    int is_v6 = (ctx->server_addr.ss_family == AF_INET6);

    /* IPv4 rules (always needed — TUN data plane is IPv4) */
    const char *allow_tun[] = {
        "iptables", "-I", "OUTPUT", "-o", ctx->tun.name,
        "-j", "ACCEPT", "-m", "comment", "--comment", ctx->ks_comment, NULL
    };
    const char *allow_lo4[] = {
        "iptables", "-I", "OUTPUT", "-o", "lo",
        "-j", "ACCEPT", "-m", "comment", "--comment", ctx->ks_comment, NULL
    };
    const char *drop_all4[] = {
        "iptables", "-A", "OUTPUT", "-j", "DROP",
        "-m", "comment", "--comment", ctx->ks_comment, NULL
    };

    if (cli_run_iptables_cmd(allow_tun) < 0 ||
        cli_run_iptables_cmd(allow_lo4) < 0 ||
        cli_run_iptables_cmd(drop_all4) < 0) {
        LOG_WRN("failed to set up iptables kill switch rules");
        /* Rollback any partial rules */
        ctx->killswitch_active = 1;
        cli_cleanup_killswitch(ctx);
        return -1;
    }

    /* Mark active so cleanup always runs from this point */
    ctx->killswitch_active = 1;

    int prefix = mqvpn_sa_host_prefix(&ctx->server_addr);
    char server_cidr[INET6_ADDRSTRLEN + 5];
    snprintf(server_cidr, sizeof(server_cidr), "%s/%d", ctx->server_ip_str, prefix);

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", ctx->cfg->server_port);

    if (!is_v6) {
        /* IPv4 server: allow only UDP to VPN port via iptables */
        const char *allow_server[] = {
            "iptables", "-I", "OUTPUT", "-p", "udp",
            "-d", server_cidr, "--dport", port_str,
            "-o", ctx->orig_iface, "-j", "ACCEPT",
            "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        if (cli_run_iptables_cmd(allow_server) < 0) {
            cli_cleanup_killswitch(ctx);
            return -1;
        }
    } else {
        /* IPv6 server: allow only UDP to VPN port via ip6tables + block IPv6 leaks */
        const char *v6_allow_server[] = {
            "ip6tables", "-I", "OUTPUT", "-p", "udp",
            "-d", server_cidr, "--dport", port_str,
            "-o", ctx->orig_iface, "-j", "ACCEPT",
            "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        const char *v6_allow_lo[] = {
            "ip6tables", "-I", "OUTPUT", "-o", "lo",
            "-j", "ACCEPT", "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        const char *v6_drop_all[] = {
            "ip6tables", "-A", "OUTPUT", "-j", "DROP",
            "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        if (cli_run_iptables_cmd(v6_allow_server) < 0 ||
            cli_run_iptables_cmd(v6_allow_lo) < 0 ||
            cli_run_iptables_cmd(v6_drop_all) < 0) {
            cli_cleanup_killswitch(ctx);
            return -1;
        }
    }

    /* IPv6 data plane: allow TUN for IPv6 traffic */
    if (ctx->conn && ctx->conn->addr6_assigned) {
        const char *v6_allow_tun[] = {
            "ip6tables", "-I", "OUTPUT", "-o", ctx->tun.name,
            "-j", "ACCEPT", "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        (void)cli_run_iptables_cmd(v6_allow_tun);

        if (!is_v6) {
            /* Server is IPv4 — need ip6tables lo/drop rules too */
            const char *v6_allow_lo[] = {
                "ip6tables", "-I", "OUTPUT", "-o", "lo",
                "-j", "ACCEPT", "-m", "comment", "--comment", ctx->ks_comment, NULL
            };
            const char *v6_drop_all[] = {
                "ip6tables", "-A", "OUTPUT", "-j", "DROP",
                "-m", "comment", "--comment", ctx->ks_comment, NULL
            };
            (void)cli_run_iptables_cmd(v6_allow_lo);
            (void)cli_run_iptables_cmd(v6_drop_all);
        }
    }
    LOG_INF("kill switch enabled (comment=%s)", ctx->ks_comment);
    return 0;
}

static void
cli_cleanup_killswitch(cli_ctx_t *ctx)
{
    if (!ctx->killswitch_active)
        return;

    int is_v6 = (ctx->server_addr.ss_family == AF_INET6);
    int prefix = mqvpn_sa_host_prefix(&ctx->server_addr);
    char server_cidr[INET6_ADDRSTRLEN + 5];
    snprintf(server_cidr, sizeof(server_cidr), "%s/%d", ctx->server_ip_str, prefix);

    /* Remove IPv4 rules (always present) */
    const char *del_tun[] = {
        "iptables", "-D", "OUTPUT", "-o", ctx->tun.name,
        "-j", "ACCEPT", "-m", "comment", "--comment", ctx->ks_comment, NULL
    };
    while (cli_run_iptables_cmd(del_tun) == 0) {}

    const char *del_lo4[] = {
        "iptables", "-D", "OUTPUT", "-o", "lo",
        "-j", "ACCEPT", "-m", "comment", "--comment", ctx->ks_comment, NULL
    };
    while (cli_run_iptables_cmd(del_lo4) == 0) {}

    const char *del_drop4[] = {
        "iptables", "-D", "OUTPUT", "-j", "DROP",
        "-m", "comment", "--comment", ctx->ks_comment, NULL
    };
    while (cli_run_iptables_cmd(del_drop4) == 0) {}

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", ctx->cfg->server_port);

    if (!is_v6) {
        /* IPv4 server rule */
        const char *del_server[] = {
            "iptables", "-D", "OUTPUT", "-p", "udp",
            "-d", server_cidr, "--dport", port_str,
            "-o", ctx->orig_iface, "-j", "ACCEPT",
            "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        while (cli_run_iptables_cmd(del_server) == 0) {}
    } else {
        /* IPv6 server rules */
        const char *v6_del_server[] = {
            "ip6tables", "-D", "OUTPUT", "-p", "udp",
            "-d", server_cidr, "--dport", port_str,
            "-o", ctx->orig_iface, "-j", "ACCEPT",
            "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        while (cli_run_iptables_cmd(v6_del_server) == 0) {}

        const char *v6_del_lo[] = {
            "ip6tables", "-D", "OUTPUT", "-o", "lo",
            "-j", "ACCEPT", "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        while (cli_run_iptables_cmd(v6_del_lo) == 0) {}

        const char *v6_del_drop[] = {
            "ip6tables", "-D", "OUTPUT", "-j", "DROP",
            "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        while (cli_run_iptables_cmd(v6_del_drop) == 0) {}
    }

    /* Clean up IPv6 data plane TUN rule (added regardless of server family) */
    {
        const char *v6_del_tun[] = {
            "ip6tables", "-D", "OUTPUT", "-o", ctx->tun.name,
            "-j", "ACCEPT", "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        while (cli_run_iptables_cmd(v6_del_tun) == 0) {}
    }

    if (!is_v6) {
        /* Server was IPv4 — clean up IPv6 data plane lo/drop rules */
        const char *v6_del_lo[] = {
            "ip6tables", "-D", "OUTPUT", "-o", "lo",
            "-j", "ACCEPT", "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        while (cli_run_iptables_cmd(v6_del_lo) == 0) {}

        const char *v6_del_drop[] = {
            "ip6tables", "-D", "OUTPUT", "-j", "DROP",
            "-m", "comment", "--comment", ctx->ks_comment, NULL
        };
        while (cli_run_iptables_cmd(v6_del_drop) == 0) {}
    }

    ctx->killswitch_active = 0;
    LOG_INF("kill switch rules removed");
}

/* ================================================================
 *  TUN device setup (called after ADDRESS_ASSIGN)
 * ================================================================ */

static int
cli_setup_tun(cli_ctx_t *ctx, const uint8_t *ip, uint8_t prefix)
{
    (void)prefix;

    if (mqvpn_tun_create(&ctx->tun, ctx->cfg->tun_name) < 0) {
        return -1;
    }

    char local_ip[INET_ADDRSTRLEN];
    snprintf(local_ip, sizeof(local_ip), "%d.%d.%d.%d",
             ip[0], ip[1], ip[2], ip[3]);

    /* Peer is .1 (server side of the tunnel) */
    char peer_ip[INET_ADDRSTRLEN];
    snprintf(peer_ip, sizeof(peer_ip), "%d.%d.%d.1", ip[0], ip[1], ip[2]);

    if (mqvpn_tun_set_addr(&ctx->tun, local_ip, peer_ip, 32) < 0) {
        return -1;
    }
    /* Set MTU based on QUIC datagram MSS minus MASQUE framing overhead.
     * IPv6 requires minimum link MTU of 1280 (RFC 8200 §5); the kernel
     * refuses to add IPv6 addresses on devices with smaller MTU and will
     * remove existing ones if MTU drops below 1280.  ICMP PTB (RFC 9484
     * §10.1) handles packets exceeding actual tunnel capacity during the
     * brief PMTUD convergence window. */
    int tun_mtu = 1280;
    if (ctx->conn && ctx->conn->dgram_mss > 0) {
        size_t udp_mss = xqc_h3_ext_masque_udp_mss(
            ctx->conn->dgram_mss, ctx->conn->masque_stream_id);
        if (udp_mss >= 68) {
            tun_mtu = (int)udp_mss;
        }
        LOG_INF("TUN MTU from dgram_mss=%zu masque_udp_mss=%zu → %d",
                ctx->conn->dgram_mss, udp_mss, tun_mtu);
    }
    if (ctx->conn && ctx->conn->addr6_assigned && tun_mtu < 1280) {
        tun_mtu = 1280;
    }
    if (mqvpn_tun_set_mtu(&ctx->tun, tun_mtu) < 0) {
        return -1;
    }
    if (mqvpn_tun_up(&ctx->tun) < 0) {
        return -1;
    }

    /* Set IPv6 address on TUN if assigned */
    if (ctx->conn && ctx->conn->addr6_assigned) {
        char v6str[INET6_ADDRSTRLEN];
        struct in6_addr a6;
        memcpy(&a6, ctx->conn->assigned_ip6, 16);
        inet_ntop(AF_INET6, &a6, v6str, sizeof(v6str));
        if (mqvpn_tun_set_addr6(&ctx->tun, v6str,
                                 ctx->conn->assigned_prefix6) < 0) {
            LOG_WRN("failed to set IPv6 address on TUN (continuing IPv4-only)");
        }
    }

    LOG_INF("TUN %s configured: %s → %s", ctx->tun.name, local_ip, peer_ip);

    /* Set up split tunneling routes */
    if (cli_setup_routes(ctx) < 0) {
        LOG_ERR("split tunnel route setup failed, aborting tunnel");
        goto fail;
    }

    /* Enable kill switch if configured */
    if (cli_setup_killswitch(ctx) < 0) {
        LOG_ERR("kill switch setup failed, aborting tunnel");
        goto fail;
    }

    /* Apply DNS override if configured */
    if (ctx->dns.n_servers > 0) {
        if (mqvpn_dns_apply(&ctx->dns) < 0) {
            LOG_ERR("DNS override setup failed, aborting tunnel");
            goto fail;
        }
    }

    /* Register TUN read event only after route/killswitch/DNS setup succeeds. */
    ctx->ev_tun = event_new(ctx->eb, ctx->tun.fd,
                             EV_READ | EV_PERSIST,
                             cli_tun_read_handler, ctx);
    if (!ctx->ev_tun) {
        LOG_ERR("failed to create TUN event");
        goto fail;
    }
    if (event_add(ctx->ev_tun, NULL) < 0) {
        LOG_ERR("failed to register TUN event");
        event_free(ctx->ev_tun);
        ctx->ev_tun = NULL;
        goto fail;
    }
    ctx->tun_up = 1;

    return 0;

fail:
    /* Fail-close: if setup steps fail, ensure no partial tunnel state remains. */
    cli_cleanup_killswitch(ctx);
    cli_cleanup_routes(ctx);
    mqvpn_dns_restore(&ctx->dns);
    if (ctx->tun.fd >= 0) {
        mqvpn_tun_destroy(&ctx->tun);
    }
    ctx->tun.fd = -1;
    ctx->tun_up = 0;
    return -1;
}

/* ================================================================
 *  TUN read handler (local apps → MASQUE datagram to server)
 * ================================================================ */

static void
cli_tun_resume_safety(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    if (ctx->tun_paused && ctx->ev_tun) {
        event_add(ctx->ev_tun, NULL);
        ctx->tun_paused = 0;
        LOG_DBG("TUN read resumed (safety timer)");
    }
}

/* ---- ICMP Packet Too Big (RFC 9484 §10.1) ---- */

#define PTB_RATE_LIMIT  10  /* max PTB responses per second */

static int     cli_ptb_tokens    = PTB_RATE_LIMIT;
static int64_t cli_ptb_refill_ms = 0;

static int
cli_ptb_rate_allow(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t now_ms = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    if (now_ms - cli_ptb_refill_ms >= 1000) {
        cli_ptb_tokens = PTB_RATE_LIMIT;
        cli_ptb_refill_ms = now_ms;
    }
    if (cli_ptb_tokens > 0) {
        cli_ptb_tokens--;
        return 1;
    }
    return 0;
}

/*
 * Send ICMP Destination Unreachable / Fragmentation Needed (type=3, code=4)
 * back to the TUN device when a packet is too large for the QUIC tunnel.
 */
static void
cli_send_icmp_ptb(cli_conn_t *conn, const uint8_t *orig_pkt, size_t orig_len,
                   size_t tunnel_mtu)
{
    if (orig_len < 20 || !conn->addr_assigned) return;
    if (!cli_ptb_rate_allow()) return;

    size_t ihl = (orig_pkt[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > orig_len) return;
    size_t icmp_data_len = ihl + 8;
    if (icmp_data_len > orig_len) icmp_data_len = orig_len;

    size_t total_len = 20 + 8 + icmp_data_len;
    uint8_t pkt[128];
    if (total_len > sizeof(pkt)) return;
    memset(pkt, 0, total_len);

    /* IP header: client assigned addr → original src */
    pkt[0]  = 0x45;
    pkt[1]  = 0xC0;                            /* DSCP=CS6 */
    pkt[2]  = (total_len >> 8) & 0xFF;
    pkt[3]  = total_len & 0xFF;
    pkt[8]  = 64;                              /* TTL */
    pkt[9]  = 1;                               /* ICMP */
    memcpy(pkt + 12, conn->assigned_ip, 4);    /* src = client TUN */
    memcpy(pkt + 16, orig_pkt + 12, 4);        /* dst = original src */

    uint32_t cksum = 0;
    for (int i = 0; i < 20; i += 2)
        cksum += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ip_cksum = ~(uint16_t)cksum;
    pkt[10] = ip_cksum >> 8;
    pkt[11] = ip_cksum & 0xFF;

    /* ICMP: type=3 (Dest Unreachable), code=4 (Frag Needed) */
    uint8_t *icmp = pkt + 20;
    icmp[0] = 3;
    icmp[1] = 4;
    uint16_t mtu16 = (tunnel_mtu > 0xFFFF) ? 0xFFFF : (uint16_t)tunnel_mtu;
    icmp[6] = mtu16 >> 8;
    icmp[7] = mtu16 & 0xFF;
    memcpy(icmp + 8, orig_pkt, icmp_data_len);

    size_t icmp_total = 8 + icmp_data_len;
    cksum = 0;
    for (size_t i = 0; i < icmp_total; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmp_total)
            cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t icmp_cksum = ~(uint16_t)cksum;
    icmp[2] = icmp_cksum >> 8;
    icmp[3] = icmp_cksum & 0xFF;

    mqvpn_tun_write(&conn->ctx->tun, pkt, total_len);
    LOG_DBG("sent ICMP Fragmentation Needed (mtu=%zu) to TUN", tunnel_mtu);
}

/*
 * Send ICMPv6 Packet Too Big (type=2, code=0) back to the TUN device.
 */
static void
cli_send_icmpv6_ptb(cli_conn_t *conn, const uint8_t *orig_pkt, size_t orig_len,
                      size_t tunnel_mtu)
{
    if (orig_len < 40 || !conn->addr6_assigned) return;
    if (!cli_ptb_rate_allow()) return;

    size_t icmpv6_data_len = orig_len;
    if (40 + 8 + icmpv6_data_len > 1280)
        icmpv6_data_len = 1280 - 40 - 8;
    size_t icmpv6_len = 8 + icmpv6_data_len;
    size_t total_len = 40 + icmpv6_len;

    uint8_t pkt[1280];
    memset(pkt, 0, total_len);

    /* IPv6 header */
    pkt[0] = 0x60;
    pkt[4] = (icmpv6_len >> 8) & 0xFF;
    pkt[5] = icmpv6_len & 0xFF;
    pkt[6] = 58;    /* next header: ICMPv6 */
    pkt[7] = 64;    /* hop limit */
    memcpy(pkt + 8, conn->assigned_ip6, 16);   /* src = client TUN */
    memcpy(pkt + 24, orig_pkt + 8, 16);        /* dst = original src */

    /* ICMPv6 Packet Too Big: type=2, code=0 */
    uint8_t *icmp = pkt + 40;
    icmp[0] = 2;
    icmp[1] = 0;
    uint32_t mtu32 = (uint32_t)tunnel_mtu;
    icmp[4] = (mtu32 >> 24) & 0xFF;
    icmp[5] = (mtu32 >> 16) & 0xFF;
    icmp[6] = (mtu32 >>  8) & 0xFF;
    icmp[7] = mtu32 & 0xFF;
    memcpy(icmp + 8, orig_pkt, icmpv6_data_len);

    /* ICMPv6 checksum with pseudo-header */
    uint32_t cksum = 0;
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[8 + i] << 8) | pkt[8 + i + 1];
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[24 + i] << 8) | pkt[24 + i + 1];
    cksum += (uint32_t)(icmpv6_len >> 16);
    cksum += (uint32_t)(icmpv6_len & 0xFFFF);
    cksum += 58;
    for (size_t i = 0; i < icmpv6_len; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmpv6_len)
            cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t icmp_cksum = ~(uint16_t)cksum;
    icmp[2] = icmp_cksum >> 8;
    icmp[3] = icmp_cksum & 0xFF;

    mqvpn_tun_write(&conn->ctx->tun, pkt, total_len);
    LOG_DBG("sent ICMPv6 Packet Too Big (mtu=%zu) to TUN", tunnel_mtu);
}

static void
cli_tun_read_handler(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    cli_conn_t *conn = ctx->conn;

    if (!conn || !conn->tunnel_ok) return;

    uint8_t pkt[PACKET_BUF_SIZE];
    uint8_t frame_buf[MASQUE_FRAME_BUF];

    for (;;) {
        int n = mqvpn_tun_read(&ctx->tun, pkt, sizeof(pkt));
        if (n <= 0) break;

        if (n < 1) continue;
        uint8_t ip_ver = pkt[0] >> 4;

        if (ip_ver == 4) {
            if (n < 20) continue;
            /* Validate source IP matches assigned address */
            if (conn->addr_assigned &&
                memcmp(pkt + 12, conn->assigned_ip, 4) != 0) {
                LOG_DBG("dropping outbound packet: src IPv4 mismatch");
                continue;
            }
        } else if (ip_ver == 6) {
            if (n < 40 || !conn->addr6_assigned) continue;
            if (memcmp(pkt + 8, conn->assigned_ip6, 16) != 0) {
                LOG_DBG("dropping outbound packet: src IPv6 mismatch");
                continue;
            }
        } else {
            continue;
        }

        /* RFC 9484 §10.1: if packet exceeds tunnel capacity, send ICMP PTB */
        if (conn->dgram_mss > 0) {
            size_t udp_mss = xqc_h3_ext_masque_udp_mss(
                conn->dgram_mss, conn->masque_stream_id);
            if ((size_t)n > udp_mss) {
                if (ip_ver == 4)
                    cli_send_icmp_ptb(conn, pkt, (size_t)n, udp_mss);
                else
                    cli_send_icmpv6_ptb(conn, pkt, (size_t)n, udp_mss);
                continue;
            }
        }

        size_t frame_written = 0;
        xqc_int_t xret = xqc_h3_ext_masque_frame_udp(
            frame_buf, sizeof(frame_buf), &frame_written,
            conn->masque_stream_id, pkt, (size_t)n);
        if (xret != XQC_OK) {
            LOG_ERR("masque_frame_udp: %d", xret);
            continue;
        }

        uint64_t dgram_id;
        /* Set flow hash for xquic's WLB scheduler (no-op if MinRTT) */
        uint32_t fh = flow_hash_pkt(pkt, n);
        xqc_conn_set_dgram_flow_hash(
            xqc_h3_conn_get_xqc_conn(conn->h3_conn), fh);
        xret = xqc_h3_ext_datagram_send(
            conn->h3_conn, frame_buf, frame_written,
            &dgram_id, XQC_DATA_QOS_HIGH);
        if (xret == -XQC_EAGAIN) {
            /* QUIC send queue full — pause TUN reading */
            event_del(ctx->ev_tun);
            ctx->tun_paused = 1;
            LOG_DBG("TUN read paused (QUIC backpressure)");
            struct timeval tv = { .tv_sec = 0,
                                  .tv_usec = TUN_RESUME_SAFETY_MS * 1000 };
            event_add(ctx->ev_tun_resume, &tv);
            break;
        }
        if (xret < 0) {
            LOG_DBG("datagram_send: %d", xret);
        }
    }

    xqc_engine_main_logic(ctx->engine);
}

/* ================================================================
 *  H3 connection callbacks
 * ================================================================ */

/* ================================================================
 *  Session teardown (reusable for reconnect and final cleanup)
 * ================================================================ */

static void
cli_teardown_session(cli_ctx_t *ctx)
{
    /* Stop TUN read */
    if (ctx->ev_tun) {
        event_free(ctx->ev_tun);
        ctx->ev_tun = NULL;
    }
    ctx->tun_paused = 0;

    /* Remove kill switch, routes and DNS */
    cli_cleanup_killswitch(ctx);
    cli_cleanup_routes(ctx);
    mqvpn_dns_restore(&ctx->dns);

    /* Destroy TUN device */
    if (ctx->tun_up) {
        mqvpn_tun_destroy(&ctx->tun);
        ctx->tun.fd = -1;
        ctx->tun_up = 0;
    }

    /* Free connection object */
    if (ctx->conn) {
        free(ctx->conn);
        ctx->conn = NULL;
    }
}

static void
cli_schedule_reconnect(cli_ctx_t *ctx)
{
    /* Exponential backoff: base * 2^attempts, capped */
    int base = ctx->cfg->reconnect_interval;
    if (base <= 0) base = 5;
    int delay = base;
    for (int i = 0; i < ctx->reconnect_attempts && delay < RECONNECT_BACKOFF_MAX_SEC; i++) {
        delay *= 2;
    }
    if (delay > RECONNECT_BACKOFF_MAX_SEC) {
        delay = RECONNECT_BACKOFF_MAX_SEC;
    }
    ctx->reconnect_attempts++;

    LOG_INF("reconnecting in %d seconds (attempt %d)...",
            delay, ctx->reconnect_attempts);

    struct timeval tv = { .tv_sec = delay };
    event_add(ctx->ev_reconnect, &tv);
}

static int
cli_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
                           void *user_data)
{
    (void)cid;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    conn->h3_conn = h3_conn;
    conn->dgram_mss = xqc_h3_ext_datagram_get_mss(h3_conn);
    return 0;
}

static int
cli_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
                          void *user_data)
{
    (void)h3_conn; (void)cid;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    cli_ctx_t *ctx = conn->ctx;
    int err = xqc_h3_conn_get_errno(h3_conn);
    LOG_INF("connection closed (errno=%d)", err);
    cli_log_conn_stats("client conn stats",
                       cid ? cid : &conn->cid);
    LOG_INF("client dgram summary: acked=%" PRIu64 " lost=%" PRIu64,
            conn->dgram_acked_cnt, conn->dgram_lost_cnt);

    cli_teardown_session(ctx);

    if (!ctx->shutting_down && ctx->cfg->reconnect) {
        cli_schedule_reconnect(ctx);
        return 0;
    }

    if (ctx->eb) {
        event_base_loopbreak(ctx->eb);
    }
    return 0;
}

/* ================================================================
 *  MASQUE tunnel start (called after handshake)
 * ================================================================ */

static int
cli_masque_start_tunnel(cli_conn_t *conn)
{
    cli_stream_t *stream = calloc(1, sizeof(*stream));
    if (!stream) return -1;
    stream->conn = conn;

    xqc_h3_request_t *req = xqc_h3_request_create(
        conn->ctx->engine, &conn->cid, NULL, stream);
    if (!req) {
        LOG_ERR("xqc_h3_request_create failed");
        free(stream);
        return -1;
    }
    stream->h3_request = req;
    conn->masque_request = req;

    /* Build Extended CONNECT headers */
    char authority[256];
    snprintf(authority, sizeof(authority), "%s:%d",
             conn->ctx->cfg->server_addr, conn->ctx->cfg->server_port);

    /* Prepare authorization header value if auth_key is set */
    char auth_value[300];
    int has_auth = (conn->ctx->cfg->auth_key &&
                    conn->ctx->cfg->auth_key[0] != '\0');
    if (has_auth) {
        snprintf(auth_value, sizeof(auth_value), "Bearer %s",
                 conn->ctx->cfg->auth_key);
    }

    xqc_http_header_t hdrs[7] = {
        { .name  = {.iov_base = ":method",   .iov_len = 7},
          .value = {.iov_base = "CONNECT",   .iov_len = 7},    .flags = 0 },
        { .name  = {.iov_base = ":protocol", .iov_len = 9},
          .value = {.iov_base = "connect-ip",.iov_len = 10},   .flags = 0 },
        { .name  = {.iov_base = ":scheme",   .iov_len = 7},
          .value = {.iov_base = "https",     .iov_len = 5},    .flags = 0 },
        { .name  = {.iov_base = ":authority",.iov_len = 10},
          .value = {.iov_base = authority,   .iov_len = strlen(authority)}, .flags = 0 },
        { .name  = {.iov_base = ":path",     .iov_len = 5},
          .value = {.iov_base = "/.well-known/masque/ip/*/*/", .iov_len = 27}, .flags = 0 },
        { .name  = {.iov_base = "capsule-protocol", .iov_len = 16},
          .value = {.iov_base = "?1",        .iov_len = 2},    .flags = 0 },
    };
    int hdr_count = 6;
    if (has_auth) {
        hdrs[hdr_count].name  = (struct iovec){.iov_base = "authorization", .iov_len = 13};
        hdrs[hdr_count].value = (struct iovec){.iov_base = auth_value, .iov_len = strlen(auth_value)};
        hdrs[hdr_count].flags = 0;
        hdr_count++;
    }
    xqc_http_headers_t headers = {
        .headers  = hdrs,
        .count    = hdr_count,
        .capacity = 7,
    };

    ssize_t ret = xqc_h3_request_send_headers(req, &headers, 0);
    if (ret < 0) {
        LOG_ERR("send Extended CONNECT: %zd", ret);
        conn->masque_request = NULL;
        xqc_h3_request_close(req);
        /* stream is freed in cli_request_close_notify callback */
        return -1;
    }

    conn->masque_stream_id = xqc_h3_stream_id(req);
    LOG_INF("Extended CONNECT sent (stream_id=%" PRIu64 ")",
            conn->masque_stream_id);
    return 0;
}

static void
cli_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    cli_conn_t *conn = (cli_conn_t *)user_data;
    conn->dgram_mss = xqc_h3_ext_datagram_get_mss(h3_conn);
    LOG_INF("handshake finished (dgram_mss=%zu)", conn->dgram_mss);
    cli_masque_start_tunnel(conn);
}

/* ================================================================
 *  H3 request callbacks (capsule parsing)
 * ================================================================ */

static int
cli_request_close_notify(xqc_h3_request_t *h3_request,
                          void *strm_user_data)
{
    (void)h3_request;
    cli_stream_t *stream = (cli_stream_t *)strm_user_data;
    if (stream) {
        if (stream->conn) {
            stream->conn->tunnel_ok = 0;
        }
        free(stream->capsule_buf);
        free(stream);
    }
    return 0;
}

#define MAX_CAPSULE_BUF  65536

static int
cli_stream_append_capsules(cli_stream_t *stream, const uint8_t *buf, size_t len)
{
    if (len == 0) {
        return 0;
    }

    size_t need = stream->capsule_len + len;
    if (need > MAX_CAPSULE_BUF) {
        LOG_ERR("capsule buffer exceeds max (%zu > %d)", need, MAX_CAPSULE_BUF);
        return -1;
    }
    if (need > stream->capsule_cap) {
        size_t new_cap = stream->capsule_cap ? stream->capsule_cap * 2 : 4096;
        while (new_cap < need) {
            new_cap *= 2;
        }
        uint8_t *new_buf = realloc(stream->capsule_buf, new_cap);
        if (!new_buf) {
            return -1;
        }
        stream->capsule_buf = new_buf;
        stream->capsule_cap = new_cap;
    }

    memcpy(stream->capsule_buf + stream->capsule_len, buf, len);
    stream->capsule_len += len;
    return 0;
}

static void
cli_process_capsules(cli_stream_t *stream)
{
    cli_conn_t *conn = stream->conn;

    while (stream->capsule_len > 0) {
        uint64_t cap_type;
        const uint8_t *cap_payload;
        size_t cap_len, consumed;

        xqc_int_t xret = xqc_h3_ext_capsule_decode(
            stream->capsule_buf, stream->capsule_len,
            &cap_type, &cap_payload, &cap_len, &consumed);
        if (xret != XQC_OK) {
            break;
        }

        if (cap_type == XQC_H3_CAPSULE_ADDRESS_ASSIGN) {
            /* Loop over all entries (RFC 9484 §4.7.1: capsule may contain
             * multiple assigned addresses) */
            const uint8_t *ap = cap_payload;
            size_t aremain = cap_len;
            while (aremain > 0) {
                uint64_t req_id;
                uint8_t ip_ver, ip_addr[16], prefix;
                size_t ip_len = 16, aa_consumed;
                xret = xqc_h3_ext_connectip_parse_address_assign(
                    ap, aremain, &req_id, &ip_ver,
                    ip_addr, &ip_len, &prefix, &aa_consumed);
                if (xret != XQC_OK) break;

                if (ip_ver == 4 && !conn->addr_assigned) {
                    memcpy(conn->assigned_ip, ip_addr, 4);
                    conn->assigned_prefix = prefix;
                    conn->addr_assigned = 1;
                    LOG_INF("ADDRESS_ASSIGN: req_id=%" PRIu64 " IPv4 "
                            "%d.%d.%d.%d/%d",
                            req_id,
                            ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3],
                            prefix);
                } else if (ip_ver == 6 && !conn->addr6_assigned) {
                    memcpy(conn->assigned_ip6, ip_addr, 16);
                    conn->assigned_prefix6 = prefix;
                    conn->addr6_assigned = 1;
                    char v6str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, ip_addr, v6str, sizeof(v6str));
                    LOG_INF("ADDRESS_ASSIGN: req_id=%" PRIu64 " IPv6 "
                            "%s/%d", req_id, v6str, prefix);
                } else {
                    LOG_INF("ADDRESS_ASSIGN: req_id=%" PRIu64 " ipv%d "
                            "(duplicate, ignored)", req_id, ip_ver);
                }
                ap += aa_consumed;
                aremain -= aa_consumed;
            }
        } else if (cap_type == XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT) {
            /* Validate ordering requirements (RFC 9484 §4.7.3 MUST) */
            xret = xqc_h3_ext_connectip_validate_route_advertisement(
                cap_payload, cap_len);
            if (xret != XQC_OK) {
                LOG_ERR("ROUTE_ADVERTISEMENT validation failed: %d "
                        "(RFC 9484 §4.7.3 ordering violation)", xret);
                /* RFC 9484 §4.7.3: MUST abort the stream */
                xqc_h3_request_close(stream->h3_request);
                return;
            }

            uint8_t ip_ver, start_ip[16], end_ip[16], ip_proto;
            size_t ip_len, bytes_consumed;

            const uint8_t *rp = cap_payload;
            size_t rremain = cap_len;
            while (rremain > 0) {
                ip_len = 16;
                xret = xqc_h3_ext_connectip_parse_route_advertisement(
                    rp, rremain, &ip_ver, start_ip, end_ip,
                    &ip_len, &ip_proto, &bytes_consumed);
                if (xret != XQC_OK) break;
                LOG_INF("ROUTE_ADVERTISEMENT: ipv%d proto=%d "
                        "%d.%d.%d.%d-%d.%d.%d.%d",
                        ip_ver, ip_proto,
                        start_ip[0], start_ip[1], start_ip[2], start_ip[3],
                        end_ip[0], end_ip[1], end_ip[2], end_ip[3]);
                rp += bytes_consumed;
                rremain -= bytes_consumed;
            }
        } else {
            /* RFC 9297 §3.2: unknown capsule types MUST be silently ignored */
        }

        if (consumed < stream->capsule_len) {
            memmove(stream->capsule_buf,
                    stream->capsule_buf + consumed,
                    stream->capsule_len - consumed);
        }
        stream->capsule_len -= consumed;
    }
}

static int
cli_request_read_notify(xqc_h3_request_t *h3_request,
                         xqc_request_notify_flag_t flag, void *strm_user_data)
{
    cli_stream_t *stream = (cli_stream_t *)strm_user_data;
    cli_conn_t *conn = stream->conn;
    unsigned char fin = 0;

    /* Handle response headers (200 OK) */
    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers) {
            for (int i = 0; i < (int)headers->count; i++) {
                xqc_http_header_t *h = &headers->headers[i];
                if (h->name.iov_len == 7
                    && memcmp(h->name.iov_base, ":status", 7) == 0
                    && h->value.iov_len == 3
                    && memcmp(h->value.iov_base, "200", 3) == 0) {
                    conn->tunnel_ok = 1;
                    LOG_INF("tunnel 200 OK");
                }
            }
        }
    }

    /* Handle body (capsules) */
    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char buf[4096];
        ssize_t n;
        do {
            n = xqc_h3_request_recv_body(h3_request, buf, sizeof(buf), &fin);
            if (n <= 0) break;
            if (cli_stream_append_capsules(stream, buf, (size_t)n) < 0) {
                LOG_ERR("capsule buffer OOM");
                return -1;
            }
            cli_process_capsules(stream);
        } while (n > 0 && !fin);

        /* Set up TUN after ADDRESS_ASSIGN */
        if (conn->addr_assigned && !conn->ctx->tun_up) {
            if (cli_setup_tun(conn->ctx, conn->assigned_ip, conn->assigned_prefix) < 0) {
                LOG_ERR("TUN setup failed after ADDRESS_ASSIGN");
                return -1;
            }
            /* Tunnel is up — reset reconnection backoff */
            conn->ctx->reconnect_attempts = 0;
        }
    }

    return 0;
}

static int
cli_request_write_notify(xqc_h3_request_t *h3_request,
                          void *strm_user_data)
{
    (void)h3_request; (void)strm_user_data;
    return 0;
}

/* ================================================================
 *  H3 datagram callbacks (server → client: IP packets)
 * ================================================================ */

/* Send ICMP Time Exceeded back through tunnel (RFC 9484 §4.4 SHOULD) */
static void
cli_send_icmp_time_exceeded(cli_conn_t *conn, const uint8_t *orig_pkt,
                            size_t orig_len)
{
    if (orig_len < 20 || !conn->addr_assigned) return;

    size_t ihl = (orig_pkt[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > orig_len) return;
    size_t icmp_data_len = ihl + 8;
    if (icmp_data_len > orig_len) icmp_data_len = orig_len;

    size_t total_len = 20 + 8 + icmp_data_len;
    uint8_t pkt[128];
    if (total_len > sizeof(pkt)) return;
    memset(pkt, 0, total_len);

    /* IP header: client assigned addr → original src */
    pkt[0]  = 0x45;
    pkt[1]  = 0xC0;
    pkt[2]  = (total_len >> 8) & 0xFF;
    pkt[3]  = total_len & 0xFF;
    pkt[8]  = 64;
    pkt[9]  = 1;   /* ICMP */
    memcpy(pkt + 12, conn->assigned_ip, 4);
    memcpy(pkt + 16, orig_pkt + 12, 4);

    uint32_t cksum = 0;
    for (int i = 0; i < 20; i += 2)
        cksum += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ip_cksum = ~(uint16_t)cksum;
    pkt[10] = ip_cksum >> 8;
    pkt[11] = ip_cksum & 0xFF;

    uint8_t *icmp = pkt + 20;
    icmp[0] = 11;
    icmp[1] = 0;
    memcpy(icmp + 8, orig_pkt, icmp_data_len);

    size_t icmp_total = 8 + icmp_data_len;
    cksum = 0;
    for (size_t i = 0; i < icmp_total; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmp_total)
            cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t icmp_cksum = ~(uint16_t)cksum;
    icmp[2] = icmp_cksum >> 8;
    icmp[3] = icmp_cksum & 0xFF;

    /* Send back through TUN to local app */
    mqvpn_tun_write(&conn->ctx->tun, pkt, total_len);
    LOG_DBG("sent ICMP Time Exceeded to local app");
}

/* Send ICMPv6 Time Exceeded (type=3, code=0) back to local app */
static void
cli_send_icmpv6_time_exceeded(cli_conn_t *conn, const uint8_t *orig_pkt,
                               size_t orig_len)
{
    if (orig_len < 40 || !conn->addr6_assigned) return;

    /* ICMPv6 payload: as much of original packet as fits in 1280 MTU */
    size_t icmpv6_data_len = orig_len;
    if (40 + 8 + icmpv6_data_len > 1280)
        icmpv6_data_len = 1280 - 40 - 8;
    size_t icmpv6_len = 8 + icmpv6_data_len;
    size_t total_len = 40 + icmpv6_len;

    uint8_t pkt[1280];
    memset(pkt, 0, total_len);

    /* IPv6 header */
    pkt[0] = 0x60;
    pkt[4] = (icmpv6_len >> 8) & 0xFF;
    pkt[5] = icmpv6_len & 0xFF;
    pkt[6] = 58;    /* next header: ICMPv6 */
    pkt[7] = 64;    /* hop limit */
    memcpy(pkt + 8, conn->assigned_ip6, 16);   /* src = client assigned */
    memcpy(pkt + 24, orig_pkt + 8, 16);        /* dst = original src */

    /* ICMPv6 Time Exceeded */
    uint8_t *icmp = pkt + 40;
    icmp[0] = 3;
    icmp[1] = 0;
    memcpy(icmp + 8, orig_pkt, icmpv6_data_len);

    /* Checksum with pseudo-header */
    uint32_t cksum = 0;
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[8 + i] << 8) | pkt[8 + i + 1];
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[24 + i] << 8) | pkt[24 + i + 1];
    cksum += (uint32_t)(icmpv6_len >> 16);
    cksum += (uint32_t)(icmpv6_len & 0xFFFF);
    cksum += 58;
    for (size_t i = 0; i < icmpv6_len; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmpv6_len)
            cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t icmp_cksum = ~(uint16_t)cksum;
    icmp[2] = icmp_cksum >> 8;
    icmp[3] = icmp_cksum & 0xFF;

    mqvpn_tun_write(&conn->ctx->tun, pkt, total_len);
    LOG_DBG("sent ICMPv6 Time Exceeded to local app");
}

static void
cli_dgram_read_notify(xqc_h3_conn_t *h3_conn, const void *data,
                       size_t data_len, void *user_data, uint64_t ts)
{
    (void)h3_conn; (void)ts;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    if (!conn || !conn->ctx->tun_up) return;

    uint64_t qsid = 0, ctx_id = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    xqc_int_t xret = xqc_h3_ext_masque_unframe_udp(
        (const uint8_t *)data, data_len, &qsid, &ctx_id,
        &payload, &payload_len);
    if (xret != XQC_OK) {
        LOG_DBG("unframe_udp: %d", xret);
        return;
    }

    /* Check IP version */
    if (payload_len < 1) return;
    uint8_t ip_ver = payload[0] >> 4;
    uint8_t fwd_pkt[PACKET_BUF_SIZE];

    if (ip_ver == 4) {
        if (payload_len < 20) return;

        /* Decrement TTL before forwarding (RFC 9484 §4.3 MUST) */
        memcpy(fwd_pkt, payload, payload_len);
        if (fwd_pkt[8] <= 1) {
            LOG_DBG("dropping packet: TTL expired");
            cli_send_icmp_time_exceeded(conn, payload, payload_len);
            return;
        }
        fwd_pkt[8]--;
        uint32_t sum = ((uint32_t)fwd_pkt[10] << 8 | fwd_pkt[11]) + 0x0100;
        sum = (sum & 0xFFFF) + (sum >> 16);
        fwd_pkt[10] = (sum >> 8) & 0xFF;
        fwd_pkt[11] = sum & 0xFF;

    } else if (ip_ver == 6) {
        if (payload_len < 40 || !conn->addr6_assigned) return;

        /* Decrement Hop Limit (byte 7) before forwarding */
        memcpy(fwd_pkt, payload, payload_len);
        if (fwd_pkt[7] <= 1) {
            LOG_DBG("dropping IPv6 packet: hop limit expired");
            cli_send_icmpv6_time_exceeded(conn, payload, payload_len);
            return;
        }
        fwd_pkt[7]--;
        /* IPv6 has no header checksum */

    } else {
        LOG_DBG("dropping non-IP packet (version=%d len=%zu)", ip_ver, payload_len);
        return;
    }

    /* Write IP packet to TUN (delivered to local apps) */
    int wret = mqvpn_tun_write(&conn->ctx->tun, fwd_pkt, payload_len);
    if (wret < 0) {
        conn->ctx->tun_drop_cnt++;
        if (wret == MQVPN_TUN_EAGAIN) {
            LOG_DBG("TUN write EAGAIN (drops=%" PRIu64 ")", conn->ctx->tun_drop_cnt);
        } else {
            LOG_WRN("TUN write failed (drops=%" PRIu64 ")", conn->ctx->tun_drop_cnt);
        }
    }
}

static void
cli_dgram_write_notify(xqc_h3_conn_t *h3_conn, void *user_data)
{
    (void)h3_conn;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    if (!conn) return;
    cli_ctx_t *ctx = conn->ctx;

    if (ctx->tun_paused && ctx->ev_tun) {
        event_add(ctx->ev_tun, NULL);
        ctx->tun_paused = 0;
        evtimer_del(ctx->ev_tun_resume);
        LOG_DBG("TUN read resumed (QUIC queue has space)");
    }
}

static void
cli_dgram_acked_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
                        void *user_data)
{
    (void)conn; (void)dgram_id;
    cli_conn_t *cli_conn = (cli_conn_t *)user_data;
    if (!cli_conn) return;
    cli_conn->dgram_acked_cnt++;
}

static int
cli_dgram_lost_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
                       void *user_data)
{
    (void)conn;
    cli_conn_t *cli_conn = (cli_conn_t *)user_data;
    if (!cli_conn) return 0;
    cli_conn->dgram_lost_cnt++;
    if ((cli_conn->dgram_lost_cnt % 256) == 0) {
        LOG_WRN("client datagram loss checkpoint: lost=%" PRIu64 " acked=%" PRIu64 " (last_dgram_id=%" PRIu64 ")",
                cli_conn->dgram_lost_cnt, cli_conn->dgram_acked_cnt, dgram_id);
        cli_log_conn_stats("client loss checkpoint", &cli_conn->cid);
    }
    return 0;
}

static void
cli_dgram_mss_updated_notify(xqc_h3_conn_t *conn, size_t mss,
                              void *user_data)
{
    (void)conn;
    cli_conn_t *cli_conn = (cli_conn_t *)user_data;
    if (cli_conn) {
        cli_conn->dgram_mss = mss;
    }
    LOG_INF("datagram MSS updated: %zu", mss);

    /* Update TUN MTU if tunnel is already up */
    if (cli_conn && cli_conn->ctx->tun_up) {
        size_t udp_mss = xqc_h3_ext_masque_udp_mss(
            mss, cli_conn->masque_stream_id);
        if (udp_mss >= 68) {
            int new_mtu = (int)udp_mss;
            if (cli_conn->addr6_assigned && new_mtu < 1280)
                new_mtu = 1280;
            mqvpn_tun_set_mtu(&cli_conn->ctx->tun, new_mtu);
        }
    }
}

/* ================================================================
 *  TLS callbacks
 * ================================================================ */

static int
cli_cert_verify_cb(const unsigned char *certs[], const size_t cert_len[],
                   size_t certs_len, void *conn_user_data)
{
    (void)certs; (void)cert_len; (void)certs_len;
    /* This callback is reached when BoringSSL chain verification fails
     * (e.g. self-signed cert, unknown CA).  Only accept in insecure mode. */
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    if (conn && conn->ctx && conn->ctx->cfg && conn->ctx->cfg->insecure) {
        return 0;   /* --insecure: accept any cert */
    }
    LOG_ERR("TLS certificate verification failed (use --insecure to skip)");
    return -1;      /* reject */
}

static void
cli_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    (void)token; (void)token_len; (void)user_data;
}

static void
cli_save_session_cb(const char *data, size_t data_len, void *user_data)
{
    (void)data; (void)data_len; (void)user_data;
}

static void
cli_save_tp_cb(const char *data, size_t data_len, void *user_data)
{
    (void)data; (void)data_len; (void)user_data;
}

/* ================================================================
 *  Multipath callbacks
 * ================================================================ */

static void
cli_ready_to_create_path(const xqc_cid_t *cid, void *conn_user_data)
{
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    cli_ctx_t *ctx = conn->ctx;

    if (ctx->cfg->n_paths <= 1) {
        return;  /* single-path mode */
    }

    LOG_INF("ready_to_create_path: adding secondary paths");

    for (int i = 1; i < ctx->path_mgr.n_paths; i++) {
        mqvpn_path_t *p = &ctx->path_mgr.paths[i];
        if (p->in_use) continue;

        uint64_t new_path_id = 0;
        xqc_int_t ret = xqc_conn_create_path(
            ctx->engine, &conn->cid, &new_path_id, 0);
        if (ret < 0) {
            LOG_WRN("xqc_conn_create_path[%d]: %d", i, ret);
            return;
        }

        p->path_id = new_path_id;
        p->in_use = 1;
        LOG_INF("path[%d] created: path_id=%" PRIu64 " iface=%s",
                i, new_path_id, p->iface);
    }
}

static void
cli_path_recreate_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    cli_conn_t *conn = ctx->conn;

    if (!conn || !conn->h3_conn) {
        return;  /* connection shutting down */
    }

    int recreated = 0;
    for (int i = 0; i < ctx->path_mgr.n_paths; i++) {
        mqvpn_path_t *p = &ctx->path_mgr.paths[i];
        if (!p->in_use && p->active && p->fd >= 0) {
            uint64_t new_path_id = 0;
            xqc_int_t ret = xqc_conn_create_path(
                ctx->engine, &conn->cid, &new_path_id, 0);
            if (ret < 0) {
                LOG_WRN("path re-create[%d]: xqc_conn_create_path failed: %d",
                        i, ret);
            } else {
                p->path_id = new_path_id;
                p->in_use = 1;
                recreated++;
                LOG_INF("path[%d] re-created: path_id=%" PRIu64 " iface=%s",
                        i, new_path_id, p->iface);
            }
        }
    }

    xqc_engine_main_logic(ctx->engine);

    /* Reset retries only if all recreated paths survived main_logic
     * (i.e. were not immediately removed by xquic) */
    if (recreated > 0) {
        int all_survived = 1;
        for (int i = 0; i < ctx->path_mgr.n_paths; i++) {
            mqvpn_path_t *p = &ctx->path_mgr.paths[i];
            if (p->active && p->fd >= 0 && !p->in_use) {
                all_survived = 0;
                break;
            }
        }
        if (all_survived) {
            ctx->path_recreate_retries = 0;
        }
    }
}

static void
cli_path_removed(const xqc_cid_t *cid, uint64_t path_id,
                  void *conn_user_data)
{
    (void)cid;
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    cli_ctx_t *ctx = conn->ctx;

    mqvpn_path_t *p = mqvpn_path_mgr_find_by_path_id(&ctx->path_mgr, path_id);
    if (p) {
        LOG_INF("path removed: path_id=%" PRIu64 " iface=%s", path_id, p->iface);
        p->in_use = 0;
        p->path_id = 0;

        /* Schedule path re-creation (with retry limit) */
        if (ctx->ev_path_recreate && p->active && p->fd >= 0
            && ctx->path_recreate_retries < PATH_RECREATE_MAX_RETRIES) {
            ctx->path_recreate_retries++;
            struct timeval tv = { .tv_sec = PATH_RECREATE_DELAY_SEC };
            event_add(ctx->ev_path_recreate, &tv);
            LOG_INF("path re-creation scheduled in %d sec (attempt %d/%d)",
                    PATH_RECREATE_DELAY_SEC,
                    ctx->path_recreate_retries, PATH_RECREATE_MAX_RETRIES);
        } else if (ctx->path_recreate_retries >= PATH_RECREATE_MAX_RETRIES) {
            LOG_WRN("path re-creation: max retries (%d) reached, giving up",
                    PATH_RECREATE_MAX_RETRIES);
        }
    } else {
        LOG_WRN("path_removed: unknown path_id=%" PRIu64, path_id);
    }
}

/* ================================================================
 *  Resolve server address
 * ================================================================ */

static int
cli_resolve_server(cli_ctx_t *ctx)
{
    socklen_t addrlen;
    if (mqvpn_resolve_host(ctx->cfg->server_addr, &ctx->server_addr, &addrlen) < 0) {
        LOG_ERR("failed to resolve server address: %s", ctx->cfg->server_addr);
        return -1;
    }
    mqvpn_sa_set_port(&ctx->server_addr, (uint16_t)ctx->cfg->server_port);
    ctx->server_addrlen = addrlen;

    char resolved[INET6_ADDRSTRLEN];
    mqvpn_sa_ntop(&ctx->server_addr, resolved, sizeof(resolved));
    LOG_INF("resolved server: %s -> %s (%s)", ctx->cfg->server_addr, resolved,
            ctx->server_addr.ss_family == AF_INET6 ? "IPv6" : "IPv4");
    return 0;
}

/* ================================================================
 *  Create a new QUIC/H3 connection (used for initial + reconnect)
 * ================================================================ */

static int
cli_start_connection(cli_ctx_t *ctx)
{
    /* Re-resolve server address (hostname may have changed IP) */
    if (cli_resolve_server(ctx) < 0) {
        return -1;
    }

    cli_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        LOG_ERR("calloc conn");
        return -1;
    }
    conn->ctx = ctx;
    ctx->conn = conn;

    int multipath = (ctx->cfg->n_paths > 1) ? 1 : 0;

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.max_datagram_frame_size = 65535;
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.enable_multipath = multipath;
    conn_settings.mp_ping_on = multipath;
    conn_settings.pacing_on = 1;
    conn_settings.cong_ctrl_callback = xqc_bbr2_cb;
    conn_settings.cc_params.cc_optimization_flags =
        XQC_BBR2_FLAG_RTTVAR_COMPENSATION | XQC_BBR2_FLAG_FAST_CONVERGENCE;
    conn_settings.sndq_packets_used_max = XQC_SNDQ_MAX_PKTS;
    conn_settings.so_sndbuf = 8 * 1024 * 1024;
    if (ctx->cfg->scheduler == MQVPN_SCHED_WLB) {
        conn_settings.scheduler_callback = xqc_wlb_scheduler_cb;
    } else {
        conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    }

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    if (ctx->cfg->insecure) {
        conn_ssl_config.cert_verify_flag = XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
    } else {
        conn_ssl_config.cert_verify_flag = XQC_TLS_CERT_FLAG_NEED_VERIFY;
    }

    const xqc_cid_t *cid = xqc_h3_connect(
        ctx->engine, &conn_settings,
        NULL, 0,
        ctx->cfg->server_addr, 0,
        &conn_ssl_config,
        (struct sockaddr *)&ctx->server_addr, ctx->server_addrlen,
        conn);
    if (!cid) {
        LOG_ERR("xqc_h3_connect failed");
        free(conn);
        ctx->conn = NULL;
        return -1;
    }

    memcpy(&conn->cid, cid, sizeof(*cid));
    if (conn->h3_conn) {
        xqc_h3_ext_datagram_set_user_data(conn->h3_conn, conn);
    }

    LOG_INF("connecting to %s:%d (multipath=%d, paths=%d) ...",
            ctx->cfg->server_addr, ctx->cfg->server_port,
            multipath, ctx->path_mgr.n_paths);
    return 0;
}

/* ================================================================
 *  Reconnect timer callback
 * ================================================================ */

static void
cli_reconnect_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;

    if (ctx->shutting_down) {
        return;
    }

    LOG_INF("attempting reconnection (attempt %d)...", ctx->reconnect_attempts);

    /* Reset path in_use flags so xquic creates fresh paths */
    for (int i = 0; i < ctx->path_mgr.n_paths; i++) {
        ctx->path_mgr.paths[i].in_use = 0;
    }
    ctx->path_recreate_retries = 0;

    /* Mark primary path as in-use */
    ctx->path_mgr.paths[0].path_id = 0;
    ctx->path_mgr.paths[0].in_use = 1;

    if (cli_start_connection(ctx) < 0) {
        LOG_WRN("reconnection failed, will retry");
        cli_schedule_reconnect(ctx);
        return;
    }

    xqc_engine_main_logic(ctx->engine);
}

/* ================================================================
 *  Client main
 * ================================================================ */

int
mqvpn_client_run(const mqvpn_client_cfg_t *cfg)
{
    memset(&g_cli, 0, sizeof(g_cli));
    g_cli.cfg = cfg;
    g_cli.tun.fd = -1;

    /* Initialize DNS and check for stale backup */
    mqvpn_dns_init(&g_cli.dns);
    if (mqvpn_dns_has_stale_backup(&g_cli.dns)) {
        mqvpn_dns_restore_stale(&g_cli.dns);
    }
    for (int i = 0; i < cfg->n_dns; i++) {
        mqvpn_dns_add_server(&g_cli.dns, cfg->dns_servers[i]);
    }

    /* Create event base */
    g_cli.eb = event_base_new();
    if (!g_cli.eb) {
        LOG_ERR("event_base_new failed");
        return -1;
    }

    g_cli.ev_engine = event_new(g_cli.eb, -1, 0, cli_engine_callback, &g_cli);
    g_cli.ev_path_recreate = event_new(g_cli.eb, -1, 0,
                                        cli_path_recreate_callback, &g_cli);
    g_cli.ev_tun_resume = evtimer_new(g_cli.eb, cli_tun_resume_safety, &g_cli);
    g_cli.ev_sigint = evsignal_new(g_cli.eb, SIGINT, cli_signal_event_callback, &g_cli);
    g_cli.ev_sigterm = evsignal_new(g_cli.eb, SIGTERM, cli_signal_event_callback, &g_cli);
    if (!g_cli.ev_sigint || !g_cli.ev_sigterm) {
        LOG_ERR("failed to create signal events");
        return -1;
    }
    event_add(g_cli.ev_sigint, NULL);
    event_add(g_cli.ev_sigterm, NULL);

    /* ---- xquic engine setup ---- */
    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups  = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cbs = {
        .set_event_timer = cli_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err  = cli_xqc_log_write,
            .xqc_log_write_stat = cli_xqc_log_write,
        },
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket                = cli_write_socket,
        .write_socket_ex             = cli_write_socket_ex,
        .save_token                  = cli_save_token,
        .save_session_cb             = cli_save_session_cb,
        .save_tp_cb                  = cli_save_tp_cb,
        .cert_verify_cb              = cli_cert_verify_cb,
        .ready_to_create_path_notify = cli_ready_to_create_path,
        .path_removed_notify         = cli_path_removed,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        LOG_ERR("xqc_engine_get_default_config failed");
        return -1;
    }
    config.cfg_log_level = (xqc_log_level_t)cfg->log_level;

    g_cli.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config,
                                      &engine_ssl_config, &engine_cbs,
                                      &tcbs, &g_cli);
    if (!g_cli.engine) {
        LOG_ERR("xqc_engine_create failed");
        return -1;
    }

    /* H3 callbacks */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify      = cli_h3_conn_create_notify,
            .h3_conn_close_notify       = cli_h3_conn_close_notify,
            .h3_conn_handshake_finished = cli_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_close_notify  = cli_request_close_notify,
            .h3_request_read_notify   = cli_request_read_notify,
            .h3_request_write_notify  = cli_request_write_notify,
        },
        .h3_ext_dgram_cbs = {
            .dgram_read_notify        = cli_dgram_read_notify,
            .dgram_write_notify       = cli_dgram_write_notify,
            .dgram_acked_notify       = cli_dgram_acked_notify,
            .dgram_lost_notify        = cli_dgram_lost_notify,
            .dgram_mss_updated_notify = cli_dgram_mss_updated_notify,
        },
    };

    xqc_int_t ret = xqc_h3_ctx_init(g_cli.engine, &h3_cbs);
    if (ret != XQC_OK) {
        LOG_ERR("xqc_h3_ctx_init: %d", ret);
        return -1;
    }

    /* H3 settings: Extended CONNECT + datagram */
    xqc_h3_conn_settings_t h3s = {
        .max_field_section_size       = 32 * 1024,
        .qpack_blocked_streams        = 64,
        .qpack_enc_max_table_capacity = 16 * 1024,
        .qpack_dec_max_table_capacity = 16 * 1024,
        .enable_connect_protocol      = 1,
        .h3_datagram                  = 1,
    };
    xqc_h3_engine_set_local_settings(g_cli.engine, &h3s);

    /* ---- Resolve server address ---- */
    if (cli_resolve_server(&g_cli) < 0) {
        return -1;
    }

    /* ---- Create UDP sockets (one per path) ---- */
    mqvpn_path_mgr_init(&g_cli.path_mgr);

    if (cfg->n_paths > 0) {
        /* Multipath: create one socket per specified interface */
        for (int i = 0; i < cfg->n_paths; i++) {
            int idx = mqvpn_path_mgr_add(&g_cli.path_mgr, cfg->path_ifaces[i],
                                          &g_cli.server_addr);
            if (idx < 0) {
                LOG_ERR("failed to create path socket for %s", cfg->path_ifaces[i]);
                return -1;
            }
        }
    } else {
        /* Single-path: one socket on any interface */
        int idx = mqvpn_path_mgr_add(&g_cli.path_mgr, NULL, &g_cli.server_addr);
        if (idx < 0) {
            return -1;
        }
    }

    /* Register all path sockets with libevent */
    for (int i = 0; i < g_cli.path_mgr.n_paths; i++) {
        mqvpn_path_t *p = &g_cli.path_mgr.paths[i];
        p->ev_socket = event_new(g_cli.eb, p->fd,
                                  EV_READ | EV_PERSIST,
                                  cli_socket_event_callback, &g_cli);
        event_add(p->ev_socket, NULL);
    }

    /* Mark primary path (path 0) as in-use with path_id=0 */
    g_cli.path_mgr.paths[0].path_id = 0;
    g_cli.path_mgr.paths[0].in_use = 1;

    if (cfg->scheduler == MQVPN_SCHED_WLB) {
        LOG_INF("WLB scheduler enabled (xquic-internal)");
    }

    /* ---- Reconnect timer ---- */
    g_cli.ev_reconnect = event_new(g_cli.eb, -1, 0,
                                    cli_reconnect_callback, &g_cli);

    if (cfg->reconnect) {
        LOG_INF("auto-reconnect enabled (base interval=%ds)", cfg->reconnect_interval);
    }

    /* ---- Initial connection ---- */
    if (cli_start_connection(&g_cli) < 0) {
        return -1;
    }

    /* ---- Main event loop ---- */
    event_base_dispatch(g_cli.eb);

    /* ---- Cleanup ---- */
    LOG_INF("client shutting down");

    /* Destroy xquic engine first — it may fire callbacks that access conn/paths */
    xqc_engine_destroy(g_cli.engine);
    g_cli.engine = NULL;

    /* Now tear down session (routes, killswitch, TUN, conn) */
    cli_teardown_session(&g_cli);

    /* Free remaining libevent objects */
    if (g_cli.ev_reconnect)      event_free(g_cli.ev_reconnect);
    if (g_cli.ev_sigterm)        event_free(g_cli.ev_sigterm);
    if (g_cli.ev_sigint)         event_free(g_cli.ev_sigint);
    if (g_cli.ev_tun)            event_free(g_cli.ev_tun);
    if (g_cli.ev_tun_resume)     event_free(g_cli.ev_tun_resume);
    if (g_cli.ev_path_recreate)  event_free(g_cli.ev_path_recreate);
    if (g_cli.ev_engine)         event_free(g_cli.ev_engine);
    mqvpn_path_mgr_destroy(&g_cli.path_mgr);
    event_base_free(g_cli.eb);

    return 0;
}
