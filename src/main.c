#include "log.h"
#include "vpn_client.h"
#include "vpn_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static void
usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  sudo %s --mode client --server <host:port> [options]\n"
        "  sudo %s --mode server --listen <bind:port> [options]\n"
        "\n"
        "Options:\n"
        "  --mode client|server      Operating mode (required)\n"
        "  --server HOST:PORT        Server address (client mode)\n"
        "  --listen BIND:PORT        Listen address (server mode, default 0.0.0.0:443)\n"
        "  --subnet CIDR             Client IP pool (server mode, default 10.0.0.0/24)\n"
        "  --tun-name NAME           TUN device name (default mqvpn0)\n"
        "  --cert PATH               TLS certificate (server mode)\n"
        "  --key PATH                TLS private key (server mode)\n"
        "  --insecure                Skip TLS cert verification (client mode)\n"
        "  --path IFACE              Network interface for multipath (repeatable, client mode)\n"
        "  --log-level debug|info|warn|error  (default info)\n"
        "  --help                    Show this help\n",
        prog, prog);
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
        {"mode",      required_argument, NULL, 'm'},
        {"server",    required_argument, NULL, 's'},
        {"listen",    required_argument, NULL, 'l'},
        {"subnet",    required_argument, NULL, 'n'},
        {"tun-name",  required_argument, NULL, 't'},
        {"cert",      required_argument, NULL, 'c'},
        {"key",       required_argument, NULL, 'k'},
        {"insecure",  no_argument,       NULL, 'i'},
        {"path",      required_argument, NULL, 'p'},
        {"log-level", required_argument, NULL, 'L'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    const char *mode        = NULL;
    const char *server_str  = NULL;
    const char *listen_str  = "0.0.0.0:443";
    const char *subnet      = "10.0.0.0/24";
    const char *tun_name    = "mqvpn0";
    const char *cert_file   = "server.crt";
    const char *key_file    = "server.key";
    int         insecure    = 0;
    const char *log_level_str = "info";
    const char *path_ifaces[MQVPN_MAX_PATH_IFACES];
    int         n_paths = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, "m:s:l:n:t:c:k:ip:L:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'm': mode = optarg; break;
        case 's': server_str = optarg; break;
        case 'l': listen_str = optarg; break;
        case 'n': subnet = optarg; break;
        case 't': tun_name = optarg; break;
        case 'c': cert_file = optarg; break;
        case 'k': key_file = optarg; break;
        case 'i': insecure = 1; break;
        case 'p':
            if (n_paths < MQVPN_MAX_PATH_IFACES) {
                path_ifaces[n_paths++] = optarg;
            } else {
                fprintf(stderr, "error: max %d paths supported\n", MQVPN_MAX_PATH_IFACES);
                return 1;
            }
            break;
        case 'L': log_level_str = optarg; break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!mode) {
        fprintf(stderr, "error: --mode is required\n");
        usage(argv[0]);
        return 1;
    }

    /* Set log level */
    mqvpn_log_level_t log_level = MQVPN_LOG_INFO;
    if      (strcmp(log_level_str, "debug") == 0) log_level = MQVPN_LOG_DEBUG;
    else if (strcmp(log_level_str, "info")  == 0) log_level = MQVPN_LOG_INFO;
    else if (strcmp(log_level_str, "warn")  == 0) log_level = MQVPN_LOG_WARN;
    else if (strcmp(log_level_str, "error") == 0) log_level = MQVPN_LOG_ERROR;
    mqvpn_log_set_level(log_level);

    /* Map our log level to xquic log level (roughly) */
    int xqc_log_level;
    switch (log_level) {
    case MQVPN_LOG_DEBUG: xqc_log_level = 5; break; /* XQC_LOG_DEBUG */
    case MQVPN_LOG_INFO:  xqc_log_level = 3; break; /* XQC_LOG_INFO */
    case MQVPN_LOG_WARN:  xqc_log_level = 2; break; /* XQC_LOG_WARN */
    case MQVPN_LOG_ERROR: xqc_log_level = 1; break; /* XQC_LOG_ERROR */
    default: xqc_log_level = 3; break;
    }

    if (strcmp(mode, "client") == 0) {
        if (!server_str) {
            fprintf(stderr, "error: --server is required for client mode\n");
            return 1;
        }

        char host[256];
        int port;
        if (parse_host_port(server_str, host, sizeof(host), &port) < 0) {
            return 1;
        }

        if (insecure) {
            LOG_WRN("--insecure: TLS certificate verification disabled");
        }

        mqvpn_client_cfg_t cfg = {
            .server_addr = host,
            .server_port = port,
            .tun_name    = tun_name,
            .insecure    = insecure,
            .log_level   = xqc_log_level,
            .n_paths     = n_paths,
        };
        for (int i = 0; i < n_paths; i++) {
            cfg.path_ifaces[i] = path_ifaces[i];
        }
        return mqvpn_client_run(&cfg);

    } else if (strcmp(mode, "server") == 0) {
        char bind_addr[256] = "0.0.0.0";
        int  bind_port = 443;
        if (listen_str) {
            if (parse_host_port(listen_str, bind_addr, sizeof(bind_addr), &bind_port) < 0) {
                return 1;
            }
        }

        mqvpn_server_cfg_t cfg = {
            .listen_addr = bind_addr,
            .listen_port = bind_port,
            .subnet      = subnet,
            .tun_name    = tun_name,
            .cert_file   = cert_file,
            .key_file    = key_file,
            .log_level   = xqc_log_level,
        };
        return mqvpn_server_run(&cfg);

    } else {
        fprintf(stderr, "error: --mode must be 'client' or 'server'\n");
        return 1;
    }
}
