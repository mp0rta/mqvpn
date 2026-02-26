#include "log.h"
#include "config.h"
#include "auth.h"
#include "vpn_client.h"
#include "vpn_server.h"
#include "flow_sched.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static void
usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  sudo %s --config <path>                  (mode from config)\n"
        "  sudo %s --mode client --server <host:port> [options]\n"
        "  sudo %s --mode server --listen <bind:port> [options]\n"
        "\n"
        "Options:\n"
        "  --config PATH             Configuration file (INI format)\n"
        "  --mode client|server      Operating mode (required if no config)\n"
        "  --server HOST:PORT        Server address, IPv4 only (client mode)\n"
        "  --listen BIND:PORT        Listen address (server mode, default 0.0.0.0:443)\n"
        "  --subnet CIDR             Client IP pool (server mode, default 10.0.0.0/24)\n"
        "  --tun-name NAME           TUN device name (default mqvpn0)\n"
        "  --cert PATH               TLS certificate (server mode)\n"
        "  --key PATH                TLS private key (server mode)\n"
        "  --insecure                Accept untrusted certs (client mode, testing only)\n"
        "  --auth-key KEY            PSK for authentication\n"
        "  --genkey                  Generate a random PSK and exit\n"
        "  --path IFACE              Network interface for multipath (repeatable, client mode)\n"
        "  --dns ADDR                DNS server to use (repeatable, client mode, max 4)\n"
        "  --no-reconnect            Disable automatic reconnection (client mode)\n"
        "  --kill-switch             Block traffic outside the VPN tunnel (client mode)\n"
        "  --scheduler minrtt|wlb    Multipath scheduler (default wlb)\n"
        "  --max-clients N           Max concurrent clients (server mode, default 64)\n"
        "  --log-level debug|info|warn|error  (default info)\n"
        "  --help                    Show this help\n"
        "\n"
        "CLI options override config file values.\n",
        prog, prog, prog);
}

static int
parse_host_port(const char *str, char *host, size_t host_len, int *port)
{
    /* Handle [host]:port or host:port */
    const char *colon = strrchr(str, ':');
    if (!colon) {
        fprintf(stderr, "error: expected HOST:PORT, got '%s'\n", str);
        return -1;
    }
    size_t hlen = (size_t)(colon - str);
    if (hlen >= host_len) hlen = host_len - 1;
    memcpy(host, str, hlen);
    host[hlen] = '\0';
    *port = atoi(colon + 1);
    if (*port <= 0 || *port > 65535) {
        fprintf(stderr, "error: invalid port in '%s'\n", str);
        return -1;
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    static struct option long_opts[] = {
        {"config",      required_argument, NULL, 'C'},
        {"mode",        required_argument, NULL, 'm'},
        {"server",      required_argument, NULL, 's'},
        {"listen",      required_argument, NULL, 'l'},
        {"subnet",      required_argument, NULL, 'n'},
        {"tun-name",    required_argument, NULL, 't'},
        {"cert",        required_argument, NULL, 'c'},
        {"key",         required_argument, NULL, 'k'},
        {"insecure",    no_argument,       NULL, 'i'},
        {"auth-key",    required_argument, NULL, 'a'},
        {"genkey",      no_argument,       NULL, 'G'},
        {"path",        required_argument, NULL, 'p'},
        {"dns",         required_argument, NULL, 'd'},
        {"scheduler",   required_argument, NULL, 'S'},
        {"max-clients", required_argument, NULL, 'M'},
        {"log-level",   required_argument, NULL, 'L'},
        {"no-reconnect", no_argument,      NULL, 'R'},
        {"kill-switch",  no_argument,      NULL, 'K'},
        {"help",        no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    const char *config_path = NULL;
    const char *mode        = NULL;
    const char *server_str  = NULL;
    const char *listen_str  = NULL;   /* NULL means "not set by CLI" */
    const char *subnet      = NULL;
    const char *tun_name    = NULL;
    const char *cert_file   = NULL;
    const char *key_file    = NULL;
    int         insecure    = -1;     /* -1 means "not set by CLI" */
    const char *auth_key    = NULL;
    int         genkey      = 0;
    const char *log_level_str = NULL;
    const char *scheduler_str = NULL;
    int         max_clients = -1;     /* -1 means "not set by CLI" */
    const char *path_ifaces[MQVPN_MAX_PATH_IFACES];
    int         n_paths = 0;
    const char *dns_servers[4];
    int         n_dns = 0;
    int         no_reconnect = 0;
    int         kill_switch  = -1;  /* -1 = not set by CLI */

    int opt;
    while ((opt = getopt_long(argc, argv, "C:m:s:l:n:t:c:k:ia:Gp:d:S:M:L:h",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'C': config_path = optarg; break;
        case 'm': mode = optarg; break;
        case 's': server_str = optarg; break;
        case 'l': listen_str = optarg; break;
        case 'n': subnet = optarg; break;
        case 't': tun_name = optarg; break;
        case 'c': cert_file = optarg; break;
        case 'k': key_file = optarg; break;
        case 'i': insecure = 1; break;
        case 'a': auth_key = optarg; break;
        case 'G': genkey = 1; break;
        case 'p':
            if (n_paths < MQVPN_MAX_PATH_IFACES) {
                path_ifaces[n_paths++] = optarg;
            } else {
                fprintf(stderr, "error: max %d paths supported\n", MQVPN_MAX_PATH_IFACES);
                return 1;
            }
            break;
        case 'd':
            if (n_dns < 4) {
                dns_servers[n_dns++] = optarg;
            } else {
                fprintf(stderr, "error: max 4 DNS servers supported\n");
                return 1;
            }
            break;
        case 'S': scheduler_str = optarg; break;
        case 'M': max_clients = atoi(optarg); break;
        case 'R': no_reconnect = 1; break;
        case 'K': kill_switch = 1; break;
        case 'L': log_level_str = optarg; break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* --genkey: generate PSK and exit */
    if (genkey) {
        return mqvpn_auth_genkey() < 0 ? 1 : 0;
    }

    /* Load config file (if given), then apply CLI overrides */
    mqvpn_config_t file_cfg;
    mqvpn_config_defaults(&file_cfg);

    if (config_path) {
        if (mqvpn_config_load(&file_cfg, config_path) < 0) {
            return 1;
        }
    }

    /* CLI overrides config file values */
    const char *eff_tun_name    = tun_name    ? tun_name    : file_cfg.tun_name;
    const char *eff_log_level   = log_level_str ? log_level_str : file_cfg.log_level;
    const char *eff_scheduler   = scheduler_str ? scheduler_str : file_cfg.scheduler;
    const char *eff_listen      = listen_str  ? listen_str  : file_cfg.listen;
    const char *eff_subnet      = subnet      ? subnet      : file_cfg.subnet;
    const char *eff_cert        = cert_file   ? cert_file   : file_cfg.cert_file;
    const char *eff_key         = key_file    ? key_file    : file_cfg.key_file;
    int         eff_insecure    = insecure >= 0 ? insecure  : file_cfg.insecure;
    int         eff_max_clients = max_clients >= 0 ? max_clients : file_cfg.max_clients;

    /* Auth key: CLI > config (use auth_key for client, server_auth_key for server) */
    const char *eff_auth_key = auth_key ? auth_key :
                               (file_cfg.auth_key[0] ? file_cfg.auth_key : NULL);

    /* Determine mode: CLI > config file > error */
    const char *eff_mode = mode;
    if (!eff_mode) {
        if (config_path) {
            eff_mode = file_cfg.is_server ? "server" : "client";
            /* Client mode needs server address */
            if (!file_cfg.is_server && file_cfg.server_addr[0] == '\0') {
                fprintf(stderr,
                    "error: config has no [Server] Address and no --mode specified\n");
                usage(argv[0]);
                return 1;
            }
        } else {
            fprintf(stderr, "error: --mode is required\n");
            usage(argv[0]);
            return 1;
        }
    }

    /* Server address: CLI > config */
    const char *eff_server = server_str ? server_str : file_cfg.server_addr;

    /* Set log level */
    mqvpn_log_level_t log_level = MQVPN_LOG_INFO;
    if      (strcmp(eff_log_level, "debug") == 0) log_level = MQVPN_LOG_DEBUG;
    else if (strcmp(eff_log_level, "info")  == 0) log_level = MQVPN_LOG_INFO;
    else if (strcmp(eff_log_level, "warn")  == 0) log_level = MQVPN_LOG_WARN;
    else if (strcmp(eff_log_level, "error") == 0) log_level = MQVPN_LOG_ERROR;
    mqvpn_log_set_level(log_level);

    /* Parse scheduler */
    int scheduler = MQVPN_SCHED_MINRTT;
    if (strcmp(eff_scheduler, "wlb") == 0) {
        scheduler = MQVPN_SCHED_WLB;
    } else if (strcmp(eff_scheduler, "minrtt") != 0) {
        fprintf(stderr, "error: --scheduler must be 'minrtt' or 'wlb'\n");
        return 1;
    }

    /* Map our log level to xquic log level (roughly) */
    int xqc_log_level;
    switch (log_level) {
    case MQVPN_LOG_DEBUG: xqc_log_level = 5; break; /* XQC_LOG_DEBUG */
    case MQVPN_LOG_INFO:  xqc_log_level = 3; break; /* XQC_LOG_INFO */
    case MQVPN_LOG_WARN:  xqc_log_level = 2; break; /* XQC_LOG_WARN */
    case MQVPN_LOG_ERROR: xqc_log_level = 1; break; /* XQC_LOG_ERROR */
    default: xqc_log_level = 3; break;
    }

    /* Paths: CLI paths override config paths entirely */
    if (n_paths == 0 && file_cfg.n_paths > 0) {
        n_paths = file_cfg.n_paths;
        for (int i = 0; i < n_paths; i++) {
            path_ifaces[i] = file_cfg.paths[i];
        }
    }

    /* DNS: CLI servers override config DNS entirely */
    if (n_dns == 0 && file_cfg.n_dns > 0) {
        n_dns = file_cfg.n_dns;
        for (int i = 0; i < n_dns; i++) {
            dns_servers[i] = file_cfg.dns_servers[i];
        }
    }

    if (strcmp(eff_mode, "client") == 0) {
        if (!eff_server || eff_server[0] == '\0') {
            fprintf(stderr, "error: --server is required for client mode\n");
            return 1;
        }

        char host[256];
        int port;
        if (parse_host_port(eff_server, host, sizeof(host), &port) < 0) {
            return 1;
        }

        if (eff_insecure) {
            LOG_WRN("--insecure: accepting untrusted certificates");
        }

        int eff_reconnect = no_reconnect ? 0 : file_cfg.reconnect;

        mqvpn_client_cfg_t cfg = {
            .server_addr = host,
            .server_port = port,
            .tun_name    = eff_tun_name,
            .insecure    = eff_insecure,
            .log_level   = xqc_log_level,
            .n_paths     = n_paths,
            .scheduler   = scheduler,
            .auth_key    = eff_auth_key,
            .n_dns       = n_dns,
            .reconnect   = eff_reconnect,
            .reconnect_interval = file_cfg.reconnect_interval,
            .kill_switch = kill_switch >= 0 ? kill_switch : file_cfg.kill_switch,
        };
        for (int i = 0; i < n_paths; i++) {
            cfg.path_ifaces[i] = path_ifaces[i];
        }
        for (int i = 0; i < n_dns; i++) {
            cfg.dns_servers[i] = dns_servers[i];
        }
        return mqvpn_client_run(&cfg);

    } else if (strcmp(eff_mode, "server") == 0) {
        if (!eff_auth_key || eff_auth_key[0] == '\0') {
            fprintf(stderr,
                "error: --auth-key is required for server mode\n"
                "       generate one with: mqvpn --genkey\n");
            return 1;
        }

        char bind_addr[256] = "0.0.0.0";
        int  bind_port = 443;
        if (parse_host_port(eff_listen, bind_addr, sizeof(bind_addr), &bind_port) < 0) {
            return 1;
        }

        mqvpn_server_cfg_t cfg = {
            .listen_addr = bind_addr,
            .listen_port = bind_port,
            .subnet      = eff_subnet,
            .tun_name    = eff_tun_name,
            .cert_file   = eff_cert,
            .key_file    = eff_key,
            .log_level   = xqc_log_level,
            .scheduler   = scheduler,
            .auth_key    = eff_auth_key,
            .max_clients = eff_max_clients,
        };
        return mqvpn_server_run(&cfg);

    } else {
        fprintf(stderr, "error: --mode must be 'client' or 'server'\n");
        return 1;
    }
}
