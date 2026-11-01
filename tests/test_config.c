// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_config.c — unit tests for INI config parser
 *
 * Build: cc -o tests/test_config tests/test_config.c src/config.c src/log.c \
 *            -Isrc -Iinclude
 */
#include "config.h"
#include "libmqvpn.h" /* MQVPN_RECV_RATE_LIMIT_MAX */
#include "mqvpn_sched_names.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_pass = 0, g_fail = 0;

#define ASSERT_EQ_INT(a, b, msg)                                               \
    do {                                                                       \
        if ((a) == (b)) {                                                      \
            g_pass++;                                                          \
        } else {                                                               \
            g_fail++;                                                          \
            fprintf(stderr, "FAIL [%s]: %d != %d\n", msg, (int)(a), (int)(b)); \
        }                                                                      \
    } while (0)

#define ASSERT_EQ_ULL(a, b, msg)                                                       \
    do {                                                                               \
        if ((a) == (b)) {                                                              \
            g_pass++;                                                                  \
        } else {                                                                       \
            g_fail++;                                                                  \
            fprintf(stderr, "FAIL [%s]: %llu != %llu\n", msg, (unsigned long long)(a), \
                    (unsigned long long)(b));                                          \
        }                                                                              \
    } while (0)

#define ASSERT_EQ_STR(a, b, msg)                                         \
    do {                                                                 \
        if (strcmp((a), (b)) == 0) {                                     \
            g_pass++;                                                    \
        } else {                                                         \
            g_fail++;                                                    \
            fprintf(stderr, "FAIL [%s]: '%s' != '%s'\n", msg, (a), (b)); \
        }                                                                \
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

/* Helper: write string to a temp file and return path */
static char *
write_tmp(const char *content)
{
    static char path[256];
    snprintf(path, sizeof(path), "/tmp/test_config_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return NULL;
    }
    write(fd, content, strlen(content));
    close(fd);
    return path;
}

/* ---- Tests ---- */

static void
test_defaults(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);

    ASSERT_EQ_STR(cfg.tun_name, "mqvpn0", "default tun_name");
    ASSERT_EQ_STR(cfg.log_level, "info", "default log_level");
    ASSERT_EQ_STR(cfg.listen, "0.0.0.0:443", "default listen");
    ASSERT_EQ_STR(cfg.subnet, "10.0.0.0/24", "default subnet");
    ASSERT_EQ_STR(cfg.cert_file, "server.crt", "default cert_file");
    ASSERT_EQ_STR(cfg.key_file, "server.key", "default key_file");
    ASSERT_EQ_INT(cfg.insecure, 0, "default insecure");
    ASSERT_EQ_INT(cfg.max_clients, 64, "default max_clients");
    ASSERT_EQ_INT(cfg.n_paths, 0, "default n_paths");
    ASSERT_EQ_INT(cfg.n_dns, 0, "default n_dns");
    ASSERT_EQ_STR(cfg.scheduler, "wlb", "default scheduler");
    ASSERT_EQ_STR(cfg.cc, "bbr2", "default cc");
    ASSERT_EQ_STR(cfg.reinjection, "off", "default reinjection");
    ASSERT_EQ_INT(cfg.reinjection_srtt_factor_pct, 110,
                  "default reinjection_srtt_factor_pct");
    ASSERT_EQ_INT(cfg.reinjection_hard_deadline_ms, 500,
                  "default reinjection_hard_deadline_ms");
    ASSERT_EQ_INT(cfg.reinjection_deadline_lower_bound_ms, 20,
                  "default reinjection_deadline_lower_bound_ms");
    ASSERT_EQ_INT(cfg.is_server, 0, "default is_server");
    ASSERT_EQ_STR(cfg.server_addr, "", "default server_addr");
    ASSERT_EQ_STR(cfg.auth_key, "", "default auth_key");
    ASSERT_EQ_STR(cfg.server_auth_key, "", "default server_auth_key");
}

static void
test_parse_server_config(void)
{
    const char *ini = "[Interface]\n"
                      "TunName = tun-server\n"
                      "Listen = 0.0.0.0:8443\n"
                      "Subnet = 10.1.0.0/24\n"
                      "LogLevel = debug\n"
                      "\n"
                      "[TLS]\n"
                      "Cert = /etc/mqvpn/cert.pem\n"
                      "Key = /etc/mqvpn/key.pem\n"
                      "\n"
                      "[Auth]\n"
                      "Key = supersecretkey123\n"
                      "MaxClients = 32\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "server config parse ok");
    ASSERT_EQ_INT(cfg.is_server, 1, "detected server mode");
    ASSERT_EQ_STR(cfg.tun_name, "tun-server", "tun_name");
    ASSERT_EQ_STR(cfg.listen, "0.0.0.0:8443", "listen");
    ASSERT_EQ_STR(cfg.subnet, "10.1.0.0/24", "subnet");
    ASSERT_EQ_STR(cfg.log_level, "debug", "log_level");
    ASSERT_EQ_STR(cfg.cert_file, "/etc/mqvpn/cert.pem", "cert_file");
    ASSERT_EQ_STR(cfg.key_file, "/etc/mqvpn/key.pem", "key_file");
    ASSERT_EQ_STR(cfg.server_auth_key, "supersecretkey123", "auth_key");
    ASSERT_EQ_INT(cfg.max_clients, 32, "max_clients");
}

static void
test_parse_client_config(void)
{
    const char *ini = "[Server]\n"
                      "Address = vpn.example.com:443\n"
                      "ServerName = sni.example.com\n"
                      "Insecure = true\n"
                      "\n"
                      "[Auth]\n"
                      "Key = myclientkey\n"
                      "\n"
                      "[Interface]\n"
                      "TunName = tun-client\n"
                      "DNS = 1.1.1.1, 8.8.8.8\n"
                      "\n"
                      "[Multipath]\n"
                      "Scheduler = minrtt\n"
                      "Path = eth0\n"
                      "Path = wlan0\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "client config parse ok");
    ASSERT_EQ_INT(cfg.is_server, 0, "detected client mode");
    ASSERT_EQ_STR(cfg.server_addr, "vpn.example.com:443", "server_addr");
    ASSERT_EQ_STR(cfg.tls_server_name, "sni.example.com", "tls_server_name");
    ASSERT_EQ_INT(cfg.insecure, 1, "insecure");
    ASSERT_EQ_STR(cfg.auth_key, "myclientkey", "auth_key");
    ASSERT_EQ_STR(cfg.tun_name, "tun-client", "tun_name");
    ASSERT_EQ_INT(cfg.n_dns, 2, "n_dns");
    ASSERT_EQ_STR(cfg.dns_servers[0], "1.1.1.1", "dns[0]");
    ASSERT_EQ_STR(cfg.dns_servers[1], "8.8.8.8", "dns[1]");
    ASSERT_EQ_STR(cfg.scheduler, "minrtt", "scheduler");
    ASSERT_EQ_INT(cfg.n_paths, 2, "n_paths");
    ASSERT_EQ_STR(cfg.paths[0], "eth0", "path[0]");
    ASSERT_EQ_STR(cfg.paths[1], "wlan0", "path[1]");
}

static void
test_parse_scheduler_backup_fec(void)
{
    const char *ini = "[Server]\n"
                      "Address = vpn.example.com:443\n"
                      "\n"
                      "[Auth]\n"
                      "Key = myclientkey\n"
                      "\n"
                      "[Multipath]\n"
                      "Scheduler = backup_fec\n"
                      "Path = eth0\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "scheduler backup_fec config parse ok");
    ASSERT_EQ_STR(cfg.scheduler, "backup_fec", "scheduler backup_fec");
}

static void
test_parse_scheduler_wlb_udp_pin(void)
{
    const char *ini = "[Server]\n"
                      "Address = vpn.example.com:443\n"
                      "\n"
                      "[Auth]\n"
                      "Key = myclientkey\n"
                      "\n"
                      "[Multipath]\n"
                      "Scheduler = wlb_udp_pin\n"
                      "Path = eth0\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "scheduler wlb_udp_pin config parse ok");
    ASSERT_EQ_STR(cfg.scheduler, "wlb_udp_pin", "scheduler wlb_udp_pin");
}

static void
test_parse_cc_ini(void)
{
    const char *ini = "[Multipath]\n"
                      "CC = bbr\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "cc ini parse ok");
    ASSERT_EQ_STR(cfg.cc, "bbr", "cc bbr from INI");
}

static void
test_parse_cc_json(void)
{
    const char *json = "{\"cc\": \"cubic\"}";
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load_json_filecfg(&cfg, json);

    ASSERT_EQ_INT(rc, 0, "cc json parse ok");
    ASSERT_EQ_STR(cfg.cc, "cubic", "cc cubic from JSON");
}

static void
test_parse_init_max_path_id_bounds(void)
{
    const char *ini_ok = "[Multipath]\n"
                         "InitMaxPathId = 128\n";
    char *path = write_tmp(ini_ok);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "InitMaxPathId max parse ok");
    ASSERT_EQ_ULL(cfg.init_max_path_id, 128ULL, "InitMaxPathId max stored");

    const char *ini_bad = "[Multipath]\n"
                          "InitMaxPathId = 129\n";
    path = write_tmp(ini_bad);
    mqvpn_config_defaults(&cfg);
    rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "InitMaxPathId overflow is warning-only");
    ASSERT_EQ_ULL(cfg.init_max_path_id, 0, "InitMaxPathId overflow ignored");
}

static void
test_parse_init_max_path_id_json_bounds(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load_json_filecfg(&cfg, "{\"init_max_path_id\":128}");
    ASSERT_EQ_INT(rc, 0, "JSON init_max_path_id max parse ok");
    ASSERT_EQ_ULL(cfg.init_max_path_id, 128ULL, "JSON init_max_path_id max");

    mqvpn_config_defaults(&cfg);
    rc = mqvpn_config_load_json_filecfg(&cfg, "{\"init_max_path_id\":129}");
    ASSERT_EQ_INT(rc, 0, "JSON init_max_path_id overflow is warning-only");
    ASSERT_EQ_ULL(cfg.init_max_path_id, 0, "JSON init_max_path_id overflow ignored");
}

static void
test_comments_whitespace(void)
{
    const char *ini = "# This is a comment\n"
                      "; This is also a comment\n"
                      "\n"
                      "   [Interface]   \n"
                      "  TunName   =   my-tun   \n"
                      "  # inline not supported, just full-line\n"
                      "\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "comment/whitespace parse ok");
    ASSERT_EQ_STR(cfg.tun_name, "my-tun", "tun_name trimmed");
}

static void
test_unknown_key_warns(void)
{
    const char *ini = "[Interface]\n"
                      "TunName = test\n"
                      "UnknownKey = somevalue\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    /* Should succeed (unknown keys are warned, not errors) */
    ASSERT_EQ_INT(rc, 0, "unknown key no error");
    ASSERT_EQ_STR(cfg.tun_name, "test", "known key still parsed");
}

static void
test_missing_file_error(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, "/tmp/nonexistent_config_file_12345.conf");

    ASSERT_TRUE(rc != 0, "missing file returns error");
}

static void
test_path_accumulation(void)
{
    const char *ini = "[Multipath]\n"
                      "Path = eth0\n"
                      "Path = wlan0\n"
                      "Path = usb0\n"
                      "Path = lte0\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "path accumulation parse ok");
    ASSERT_EQ_INT(cfg.n_paths, 4, "4 paths");
    ASSERT_EQ_STR(cfg.paths[0], "eth0", "path[0]");
    ASSERT_EQ_STR(cfg.paths[1], "wlan0", "path[1]");
    ASSERT_EQ_STR(cfg.paths[2], "usb0", "path[2]");
    ASSERT_EQ_STR(cfg.paths[3], "lte0", "path[3]");
}

static void
test_backup_path_ini(void)
{
    const char *ini = "[Multipath]\n"
                      "Scheduler = failover\n"
                      "Path = eth0\n"
                      "BackupPath = wwan0\n"
                      "Path = eth1\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "backup path parse ok");
    ASSERT_EQ_STR(cfg.scheduler, "failover", "scheduler failover");
    ASSERT_EQ_INT(cfg.n_paths, 3, "3 paths");
    ASSERT_EQ_STR(cfg.paths[1], "wwan0", "path[1]");
    ASSERT_EQ_INT(cfg.path_backup[0], 0, "path[0] not backup");
    ASSERT_EQ_INT(cfg.path_backup[1], 1, "path[1] backup");
    ASSERT_EQ_INT(cfg.path_backup[2], 0, "path[2] not backup");
}

static void
test_backup_paths_json(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load_json_filecfg(
        &cfg, "{\"paths\":[\"eth0\"],\"backup_paths\":[\"wwan0\",\"wwan1\"]}");
    ASSERT_EQ_INT(rc, 0, "backup_paths json parse ok");
    ASSERT_EQ_INT(cfg.n_paths, 3, "3 paths");
    ASSERT_EQ_STR(cfg.paths[0], "eth0", "path[0]");
    ASSERT_EQ_STR(cfg.paths[2], "wwan1", "path[2]");
    ASSERT_EQ_INT(cfg.path_backup[0], 0, "path[0] not backup");
    ASSERT_EQ_INT(cfg.path_backup[1], 1, "path[1] backup");
    ASSERT_EQ_INT(cfg.path_backup[2], 1, "path[2] backup");

    mqvpn_config_defaults(&cfg);
    rc = mqvpn_config_load_json_filecfg(&cfg, "{\"backup_paths\":[\"wwan0\"]}");
    ASSERT_EQ_INT(rc, 0, "backup_paths alone parse ok");
    ASSERT_EQ_INT(cfg.n_paths, 1, "1 path");
    ASSERT_EQ_INT(cfg.path_backup[0], 1, "path[0] backup");
}

static void
test_dns_comma_split(void)
{
    const char *ini = "[Interface]\n"
                      "DNS = 1.1.1.1,8.8.8.8, 9.9.9.9 ,  208.67.222.222  \n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "dns comma split parse ok");
    ASSERT_EQ_INT(cfg.n_dns, 4, "4 dns servers");
    ASSERT_EQ_STR(cfg.dns_servers[0], "1.1.1.1", "dns[0]");
    ASSERT_EQ_STR(cfg.dns_servers[1], "8.8.8.8", "dns[1]");
    ASSERT_EQ_STR(cfg.dns_servers[2], "9.9.9.9", "dns[2]");
    ASSERT_EQ_STR(cfg.dns_servers[3], "208.67.222.222", "dns[3]");
}

static void
test_boolean_parsing(void)
{
    /* Test various boolean representations */
    const char *ini_true = "[Server]\n"
                           "Address = host:443\n"
                           "Insecure = true\n";

    char *path = write_tmp(ini_true);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.insecure, 1, "insecure=true");

    /* Only true/false (any case) are booleans; anything else fails the load
     * instead of being read as false. */
    const char *rejected[] = {"yes", "no", "1", "0", "on", "off", "auto", ""};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        char ini[96];
        snprintf(ini, sizeof(ini), "[Server]\nAddress = host:443\nInsecure = %s\n",
                 rejected[i]);
        path = write_tmp(ini);
        mqvpn_config_defaults(&cfg);
        ASSERT_EQ_INT(mqvpn_config_load(&cfg, path), -1, rejected[i]);
        unlink(path);
    }

    /* A later valid duplicate does not cancel an earlier invalid line. */
    path = write_tmp("[Server]\nAddress = host:443\nInsecure = on\nInsecure = true\n");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, path), -1, "invalid then valid duplicate");
    unlink(path);

    path = write_tmp("[Server]\nAddress = host:443\nInsecure = TRUE\n");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, path), 0, "insecure=TRUE loads");
    unlink(path);
    ASSERT_EQ_INT(cfg.insecure, 1, "insecure=TRUE");

    const char *ini_false = "[Server]\n"
                            "Address = host:443\n"
                            "Insecure = false\n";

    path = write_tmp(ini_false);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.insecure, 0, "insecure=false");
}

static void
test_mode_detection(void)
{
    /* Server: has [Interface] Listen → is_server=1 */
    const char *ini_server = "[Interface]\n"
                             "Listen = 0.0.0.0:443\n";

    char *path = write_tmp(ini_server);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.is_server, 1, "Listen → server mode");

    /* Client: has [Server] Address → is_server=0 */
    const char *ini_client = "[Server]\n"
                             "Address = host:443\n";

    path = write_tmp(ini_client);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.is_server, 0, "Address → client mode");
}

static void
test_empty_file(void)
{
    const char *ini = "\n\n\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "empty file ok");
}

static void
test_malformed_section_header(void)
{
    /* Missing closing bracket → should warn and skip, not crash */
    const char *ini = "[Interface\n"
                      "TunName = broken\n"
                      "[Interface]\n"
                      "TunName = fixed\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "malformed section no error");
    /* First TunName is under malformed section (skipped), second is valid */
    ASSERT_EQ_STR(cfg.tun_name, "fixed", "valid section parsed after malformed");

    path = write_tmp("[Interface]\nListen=0.0.0.0:443\n"
                     "[Control\nListen=127.0.0.1:9090\n");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, path), 0, "malformed section skipped");
    unlink(path);
    ASSERT_EQ_STR(cfg.listen, "0.0.0.0:443", "malformed section cannot clobber previous");
    ASSERT_EQ_STR(cfg.control_listen, "", "malformed control section not applied");
}

static void
test_file_encoding(void)
{
    mqvpn_file_config_t cfg;
    const char *bom_files[] = {
        "\xef\xbb\xbf[Server]\r\nAddress=host:443\r\n[Interface]\r\nKillSwitch=true",
        "\xef\xbb\xbf {\"server_addr\":\"host:443\",\"kill_switch\":true}",
    };
    for (size_t i = 0; i < sizeof(bom_files) / sizeof(bom_files[0]); i++) {
        char *path = write_tmp(bom_files[i]);
        mqvpn_config_defaults(&cfg);
        ASSERT_EQ_INT(mqvpn_config_load(&cfg, path), 0, "UTF-8 BOM accepted");
        unlink(path);
        ASSERT_EQ_STR(cfg.server_addr, "host:443", "first BOM section parsed");
        ASSERT_EQ_INT(cfg.kill_switch, 1, "CRLF and final line without newline parsed");
    }

    const char ini[] = "[Server]\nAddress=host:443\n\0\n[Interface]\nKillSwitch=true\n";
    char *path = write_tmp("");
    FILE *fp = fopen(path, "wb");
    ASSERT_TRUE(fp != NULL, "open raw INI");
    if (!fp) return;
    ASSERT_EQ_INT((int)fwrite(ini, 1, sizeof(ini) - 1, fp), (int)sizeof(ini) - 1,
                  "write raw INI");
    fclose(fp);
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, path), -1, "raw NUL in INI rejected");
    unlink(path);
    ASSERT_EQ_STR(cfg.server_addr, "", "NUL rejected before applying config");
}

static void
capture_warning(mqvpn_log_level_t level, const char *msg, void *ctx)
{
    (void)level;
    snprintf(ctx, 1024, "%s", msg);
}

static void
test_physical_line_numbers(void)
{
    char *path = write_tmp("[Interface]\n\n\n\nMTU=bad\n");
    char warning[1024] = "";
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_log_set_sink(capture_warning, warning);
    int rc = mqvpn_config_load(&cfg, path);
    mqvpn_log_set_sink(NULL, NULL);
    unlink(path);
    ASSERT_EQ_INT(rc, 0, "invalid MTU is warning-only");
    ASSERT_TRUE(strstr(warning, ":5: invalid MTU") != NULL, "blank lines are counted");
}

static void
test_host_port_strict(void)
{
    char host[256];
    int port = 0;
    ASSERT_EQ_INT(mqvpn_parse_host_port("example.com:1", host, sizeof(host), &port), 0,
                  "lowest port accepted");
    ASSERT_EQ_STR(host, "example.com", "host retained");
    ASSERT_EQ_INT(port, 1, "lowest port");
    ASSERT_EQ_INT(mqvpn_parse_host_port("[::1]:65535", host, sizeof(host), &port), 0,
                  "IPv6 and highest port accepted");
    ASSERT_EQ_STR(host, "::1", "IPv6 brackets removed");
    ASSERT_EQ_INT(port, 65535, "highest port");
    const char *bad[] = {"host:443oops",  "host:4294967739",
                         "[::1]:443oops", "host:99999999999999999999999",
                         "host:0",        "host:65536",
                         "host:-1",       "host:+443",
                         "host: 443",     "host:",
                         ":443",          "[]:443",
                         "[::1]443",      "host"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        ASSERT_EQ_INT(mqvpn_parse_host_port(bad[i], host, sizeof(host), &port), -1,
                      bad[i]);
    ASSERT_EQ_INT(mqvpn_parse_host_port("longhost:443", host, 4, &port), -1,
                  "host cannot be silently truncated");
}

static void
test_malformed_line_no_equals(void)
{
    /* Line without '=' → should warn and skip */
    const char *ini = "[Interface]\n"
                      "TunName = good\n"
                      "this line has no equals\n"
                      "LogLevel = debug\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "no-equals line no error");
    ASSERT_EQ_STR(cfg.tun_name, "good", "key before malformed parsed");
    ASSERT_EQ_STR(cfg.log_level, "debug", "key after malformed parsed");
}

static void
test_key_outside_section(void)
{
    /* Key=Value before any [Section] → should warn */
    const char *ini = "TunName = orphan\n"
                      "[Interface]\n"
                      "TunName = valid\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "key outside section no error");
    ASSERT_EQ_STR(cfg.tun_name, "valid", "valid section key overrides orphan");
}

static void
test_max_paths_exceeded(void)
{
    /* (MQVPN_CONFIG_MAX_PATHS + 1)th path should be ignored */
    const char *ini = "[Multipath]\n"
                      "Path = eth0\n"
                      "Path = eth1\n"
                      "Path = eth2\n"
                      "Path = eth3\n"
                      "Path = eth4\n"
                      "Path = eth5\n"
                      "Path = eth6\n"
                      "Path = eth7\n"
                      "Path = eth8\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "max paths exceeded no error");
    ASSERT_EQ_INT(cfg.n_paths, MQVPN_CONFIG_MAX_PATHS, "capped at MAX paths");
    ASSERT_EQ_STR(cfg.paths[MQVPN_CONFIG_MAX_PATHS - 1], "eth7",
                  "last accepted path is eth7");
}

static void
test_max_paths_exceeded_json(void)
{
    /* JSON path array exceeding cap must be silently capped (parity with INI). */
    const char *json = "{"
                       "\"mode\":\"client\","
                       "\"server\":\"1.2.3.4:443\","
                       "\"paths\":[\"eth0\",\"eth1\",\"eth2\",\"eth3\","
                       "\"eth4\",\"eth5\",\"eth6\",\"eth7\",\"eth8\"]"
                       "}";

    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load_json_filecfg(&cfg, json);

    ASSERT_EQ_INT(rc, 0, "JSON max paths exceeded no error");
    ASSERT_EQ_INT(cfg.n_paths, MQVPN_CONFIG_MAX_PATHS, "JSON capped at MAX paths");
    ASSERT_EQ_STR(cfg.paths[MQVPN_CONFIG_MAX_PATHS - 1], "eth7",
                  "JSON last accepted path is eth7");
}

static void
test_max_clients_edge_cases(void)
{
    /* MaxClients = 0 → should fallback to 64 */
    const char *ini_zero = "[Auth]\n"
                           "MaxClients = 0\n";

    char *path = write_tmp(ini_zero);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.max_clients, 64, "MaxClients=0 → default 64");

    /* MaxClients = -1 → should fallback to 64 */
    const char *ini_neg = "[Auth]\n"
                          "MaxClients = -1\n";

    path = write_tmp(ini_neg);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.max_clients, 64, "MaxClients=-1 → default 64");

    /* MaxClients = abc → invalid, fallback to 64 */
    const char *ini_abc = "[Auth]\n"
                          "MaxClients = abc\n";

    path = write_tmp(ini_abc);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.max_clients, 64, "MaxClients=abc → default 64");

    /* MaxClients = 128 → valid */
    const char *ini_valid = "[Auth]\n"
                            "MaxClients = 128\n";

    path = write_tmp(ini_valid);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.max_clients, 128, "MaxClients=128 → 128");
}

static void
test_parse_reinjection_config(void)
{
    /* Valid [Multipath] Reinjection* keys parse into the struct. */
    const char *ini = "[Multipath]\n"
                      "Reinjection = deadline\n"
                      "ReinjectionSrttFactorPct = 150\n"
                      "ReinjectionHardDeadlineMs = 300\n"
                      "ReinjectionDeadlineLowerBoundMs = 10\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "reinjection config parse ok");
    ASSERT_EQ_STR(cfg.reinjection, "deadline", "reinjection");
    ASSERT_EQ_INT(cfg.reinjection_srtt_factor_pct, 150, "reinjection_srtt_factor_pct");
    ASSERT_EQ_INT(cfg.reinjection_hard_deadline_ms, 300, "reinjection_hard_deadline_ms");
    ASSERT_EQ_INT(cfg.reinjection_deadline_lower_bound_ms, 10,
                  "reinjection_deadline_lower_bound_ms");
}

static void
test_reinjection_out_of_range_falls_back(void)
{
    /* ReinjectionSrttFactorPct = 50 → below min (100) → fallback to 110 */
    char *path = write_tmp("[Multipath]\nReinjectionSrttFactorPct = 50\n");
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.reinjection_srtt_factor_pct, 110,
                  "ReinjectionSrttFactorPct=50 → default 110");

    /* ReinjectionHardDeadlineMs = 0 → below min (1) → fallback to 500 */
    path = write_tmp("[Multipath]\nReinjectionHardDeadlineMs = 0\n");
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.reinjection_hard_deadline_ms, 500,
                  "ReinjectionHardDeadlineMs=0 → default 500");

    /* ReinjectionDeadlineLowerBoundMs = 999999 → above max (60000) → fallback to 20 */
    path = write_tmp("[Multipath]\nReinjectionDeadlineLowerBoundMs = 999999\n");
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.reinjection_deadline_lower_bound_ms, 20,
                  "ReinjectionDeadlineLowerBoundMs=999999 → default 20");
}

static void
test_empty_value(void)
{
    /* Key with empty value → empty string */
    const char *ini = "[Interface]\n"
                      "TunName = \n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_STR(cfg.tun_name, "", "empty value → empty string");
}

static void
test_duplicate_keys_last_wins(void)
{
    const char *ini = "[Interface]\n"
                      "TunName = first\n"
                      "TunName = second\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_STR(cfg.tun_name, "second", "duplicate key: last wins");
}

static void
test_case_insensitive_section(void)
{
    /* Section names are case-insensitive */
    const char *ini = "[interface]\n"
                      "TunName = lower\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_STR(cfg.tun_name, "lower", "lowercase [interface] works");
}

static void
test_unknown_section(void)
{
    /* Unknown section → keys under it should be warned, not crash */
    const char *ini = "[Unknown]\n"
                      "Foo = bar\n"
                      "[Interface]\n"
                      "TunName = after_unknown\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "unknown section no error");
    ASSERT_EQ_STR(cfg.tun_name, "after_unknown", "key after unknown section parsed");
}

static void
test_dns_empty_entries(void)
{
    /* Trailing comma, leading comma, double commas → no empty entries */
    const char *ini = "[Interface]\n"
                      "DNS = ,, 1.1.1.1 ,, 8.8.8.8 ,,\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(cfg.n_dns, 2, "empty DNS entries skipped");
    ASSERT_EQ_STR(cfg.dns_servers[0], "1.1.1.1", "dns[0] after empty");
    ASSERT_EQ_STR(cfg.dns_servers[1], "8.8.8.8", "dns[1] after empty");
}

static void
test_semicolon_comment(void)
{
    const char *ini = "; semicolon comment\n"
                      "[Interface]\n"
                      "; another comment\n"
                      "TunName = commented\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_STR(cfg.tun_name, "commented", "semicolon comments ignored");
}

/* ================================================================
 *  Kill switch config tests
 * ================================================================ */

static void
test_killswitch_default_off(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);

    ASSERT_EQ_INT(cfg.kill_switch, 0, "default kill_switch off");
}

static void
test_killswitch_config_parse(void)
{
    const char *ini = "[Interface]\n"
                      "KillSwitch = true\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(cfg.kill_switch, 1, "kill_switch enabled from config");
}

static void
test_killswitch_config_false(void)
{
    const char *ini = "[Interface]\n"
                      "KillSwitch = false\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(cfg.kill_switch, 0, "kill_switch disabled from config");
}

static void
test_manage_routes_default_on(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);

    ASSERT_EQ_INT(cfg.manage_routes, 1, "default manage_routes on");
}

static void
test_manage_routes_ini_false(void)
{
    const char *ini = "[Interface]\n"
                      "ManageRoutes = false\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(cfg.manage_routes, 0, "manage_routes disabled from INI");
}

/* ================================================================
 *  Reconnect config tests
 * ================================================================ */

static void
test_reconnect_defaults(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);

    ASSERT_EQ_INT(cfg.reconnect, 1, "default reconnect enabled");
    ASSERT_EQ_INT(cfg.reconnect_interval, 5, "default reconnect interval 5s");
}

static void
test_reconnect_config_parse(void)
{
    const char *ini = "[Interface]\n"
                      "Reconnect = false\n"
                      "ReconnectInterval = 10\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(cfg.reconnect, 0, "reconnect disabled from config");
    ASSERT_EQ_INT(cfg.reconnect_interval, 10, "reconnect interval from config");
}

static void
test_reconnect_config_true(void)
{
    const char *ini = "[Interface]\n"
                      "Reconnect = true\n"
                      "ReconnectInterval = 30\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(cfg.reconnect, 1, "reconnect enabled from config");
    ASSERT_EQ_INT(cfg.reconnect_interval, 30, "reconnect interval 30s");
}

static void
test_reconnect_interval_invalid(void)
{
    const char *ini = "[Interface]\n"
                      "ReconnectInterval = -5\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(cfg.reconnect_interval, 5, "negative interval → default 5");
}

static void
test_reconnect_interval_invalid_string(void)
{
    const char *ini = "[Interface]\n"
                      "ReconnectInterval = abc\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(cfg.reconnect_interval, 5, "invalid interval → default 5");
}

/* ================================================================
 *  MTU config tests
 * ================================================================ */

static void
test_mtu_default(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(cfg.tun_mtu, 0, "default tun_mtu is 0 (auto)");
}

static void
test_mtu_config_parse(void)
{
    const char *ini = "[Interface]\nMTU = 1350\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.tun_mtu, 1350, "MTU 1350 parsed");
}

static void
test_mtu_below_floor_ignored(void)
{
    const char *ini = "[Interface]\nMTU = 500\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.tun_mtu, 0, "MTU < 1280 ignored → stays 0");
}

static void
test_mtu_above_ceiling_ignored(void)
{
    const char *ini = "[Interface]\nMTU = 9001\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.tun_mtu, 0, "MTU > 9000 ignored → stays 0");
}

static void
test_mtu_invalid_string_ignored(void)
{
    const char *ini = "[Interface]\nMTU = abc\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.tun_mtu, 0, "invalid MTU string ignored");
}

static void
test_path_mtu_parse(void)
{
    char *path = write_tmp("[Interface]\nPathMTU = 1492\n");
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(cfg.path_mtu, 0, "default path_mtu is 0");
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.path_mtu, 1492, "PathMTU 1492 parsed");

    path = write_tmp("[Interface]\nPathMTU = 1000\n");
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.path_mtu, 0, "PathMTU < 1280 ignored");
}

static void
test_pmtud_parse(void)
{
    char *path = write_tmp("[Interface]\nPMTUD = true\n");
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(cfg.pmtud, 0, "default pmtud is off");
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.pmtud, 1, "PMTUD true parsed");

    path = write_tmp("[Interface]\nPMTUD = on\n");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, path), -1, "PMTUD on fails the load");
    unlink(path);
}

static void
test_mtu_json_parse(void)
{
    const char *json = "{\"mtu\": 1400}";
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load_json_filecfg(&cfg, json);
    ASSERT_EQ_INT(cfg.tun_mtu, 1400, "JSON MTU 1400 parsed");
}

/* ================================================================
 *  Subnet6 config tests
 * ================================================================ */

static void
test_subnet6_default(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);

    ASSERT_EQ_STR(cfg.subnet6, "", "default subnet6 empty");
}

static void
test_subnet6_config_parse(void)
{
    const char *ini = "[Interface]\n"
                      "Listen = 0.0.0.0:443\n"
                      "Subnet = 10.0.0.0/24\n"
                      "Subnet6 = fd00:abcd::/112\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "subnet6 config parse ok");
    ASSERT_EQ_STR(cfg.subnet6, "fd00:abcd::/112", "subnet6 parsed");
}

static void
test_subnet6_various_prefixes(void)
{
    /* /96 prefix */
    const char *ini_96 = "[Interface]\n"
                         "Listen = 0.0.0.0:443\n"
                         "Subnet6 = fd00:1234::/96\n";

    char *path = write_tmp(ini_96);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_STR(cfg.subnet6, "fd00:1234::/96", "subnet6 /96 stored");

    /* /126 prefix */
    const char *ini_126 = "[Interface]\n"
                          "Listen = 0.0.0.0:443\n"
                          "Subnet6 = fd00:abcd:ef01::/126\n";

    path = write_tmp(ini_126);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_STR(cfg.subnet6, "fd00:abcd:ef01::/126", "subnet6 /126 stored");
}

static void
test_subnet6_whitespace_trimmed(void)
{
    const char *ini = "[Interface]\n"
                      "Listen = 0.0.0.0:443\n"
                      "Subnet6 =   fd00:abcd::/112   \n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_STR(cfg.subnet6, "fd00:abcd::/112", "subnet6 whitespace trimmed");
}

static void
test_subnet6_not_set(void)
{
    /* Server config without Subnet6 → subnet6 stays empty */
    const char *ini = "[Interface]\n"
                      "Listen = 0.0.0.0:443\n"
                      "Subnet = 10.0.0.0/24\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_STR(cfg.subnet6, "", "subnet6 empty when not set");
}

static void
test_subnet6_duplicate_last_wins(void)
{
    const char *ini = "[Interface]\n"
                      "Listen = 0.0.0.0:443\n"
                      "Subnet6 = fd00:1::/112\n"
                      "Subnet6 = fd00:2::/112\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_STR(cfg.subnet6, "fd00:2::/112", "subnet6 duplicate: last wins");
}

static void
test_auth_users_ini(void)
{
    const char *ini = "[Interface]\n"
                      "Listen = 0.0.0.0:443\n"
                      "[Auth]\n"
                      "User = alice:alice-key\n"
                      "User = bob:bob-key\n"
                      "User = alice:alice-key-v2\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "auth users ini parse ok");
    ASSERT_EQ_INT(cfg.n_users, 2, "2 users parsed");
    ASSERT_EQ_STR(cfg.user_names[0], "alice", "user[0] name");
    ASSERT_EQ_STR(cfg.user_keys[0], "alice-key-v2", "user[0] updated key");
    ASSERT_EQ_STR(cfg.user_names[1], "bob", "user[1] name");
}

static void
test_auth_users_ini_invalid_ignored(void)
{
    const char *ini = "[Interface]\n"
                      "Listen = 0.0.0.0:443\n"
                      "[Auth]\n"
                      "User = invalid-without-colon\n"
                      "User = alice:alice-key\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "invalid auth user ignored");
    ASSERT_EQ_INT(cfg.n_users, 1, "only valid user parsed");
    ASSERT_EQ_STR(cfg.user_names[0], "alice", "valid user kept");
}

static void
test_username_length(void)
{
    char name[64], ini[512], json[512];
    memset(name, 'a', sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    snprintf(ini, sizeof(ini),
             "[Auth]\nUser=%s:original\nUser=%sX:wrong\n"
             "User=%sY:also-wrong\n",
             name, name, name);
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, path), 0, "long INI usernames skipped");
    unlink(path);
    ASSERT_EQ_INT(cfg.n_users, 1, "only 63-byte username accepted");
    ASSERT_EQ_STR(cfg.user_keys[0], "original", "long name cannot overwrite prefix");

    const char *forms[] = {"{\"users\":[\"%s:original\",\"%sX:wrong\"]}",
                           "{\"users\":[{\"name\":\"%s\",\"key\":\"original\"},"
                           "{\"name\":\"%sX\",\"key\":\"wrong\"}]}"};
    for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); i++) {
        snprintf(json, sizeof(json), forms[i], name, name);
        mqvpn_config_defaults(&cfg);
        ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, json), -1,
                      "long JSON username rejected");
        ASSERT_EQ_INT(cfg.n_users, 1, "JSON only applied valid prefix entry");
        ASSERT_EQ_STR(cfg.user_keys[0], "original", "JSON prefix key retained");
    }
}

static void
test_json_config_load(void)
{
    const char *json = "{"
                       "\"mode\":\"server\","
                       "\"listen\":\"0.0.0.0:8443\","
                       "\"subnet\":\"10.20.0.0/24\","
                       "\"auth_key\":\"legacy\","
                       "\"max_clients\":120,"
                       "\"paths\":[\"eth0\",\"wlan0\"],"
                       "\"dns\":[\"1.1.1.1\",\"8.8.8.8\"],"
                       "\"users\":[{\"name\":\"alice\",\"key\":\"a1\"},\"bob:b2\"]"
                       "}";

    char *path = write_tmp(json);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "json config parse ok");
    ASSERT_EQ_INT(cfg.is_server, 1, "json mode server");
    ASSERT_EQ_STR(cfg.listen, "0.0.0.0:8443", "json listen");
    ASSERT_EQ_STR(cfg.subnet, "10.20.0.0/24", "json subnet");
    ASSERT_EQ_INT(cfg.max_clients, 120, "json max clients");
    ASSERT_EQ_INT(cfg.n_paths, 2, "json paths");
    ASSERT_EQ_STR(cfg.paths[1], "wlan0", "json path[1]");
    ASSERT_EQ_INT(cfg.n_dns, 2, "json dns");
    ASSERT_EQ_INT(cfg.n_users, 2, "json users");
    ASSERT_EQ_STR(cfg.user_names[0], "alice", "json user[0]");
}

static void
test_json_client_config_load(void)
{
    const char *json = "{"
                       "\"mode\":\"client\","
                       "\"server_addr\":\"vpn.example.com:443\","
                       "\"tls_server_name\":\"sni.example.com\","
                       "\"auth_key\":\"client-key\","
                       "\"insecure\":true,"
                       "\"tun_name\":\"mqvpn7\","
                       "\"log_level\":\"debug\","
                       "\"dns\":[\"1.1.1.1\",\"8.8.8.8\"],"
                       "\"paths\":[\"eth0\",\"wlan0\"],"
                       "\"reconnect\":false,"
                       "\"reconnect_interval\":9,"
                       "\"kill_switch\":true,"
                       "\"manage_routes\":false,"
                       "\"scheduler\":\"minrtt\""
                       "}";

    char *path = write_tmp(json);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "json client config parse ok");
    ASSERT_EQ_INT(cfg.is_server, 0, "json client mode");
    ASSERT_EQ_STR(cfg.server_addr, "vpn.example.com:443", "json client server_addr");
    ASSERT_EQ_STR(cfg.tls_server_name, "sni.example.com", "json client tls_server_name");
    ASSERT_EQ_STR(cfg.auth_key, "client-key", "json client auth_key");
    ASSERT_EQ_INT(cfg.insecure, 1, "json client insecure");
    ASSERT_EQ_STR(cfg.tun_name, "mqvpn7", "json client tun_name");
    ASSERT_EQ_STR(cfg.log_level, "debug", "json client log_level");
    ASSERT_EQ_INT(cfg.n_dns, 2, "json client dns count");
    ASSERT_EQ_STR(cfg.dns_servers[1], "8.8.8.8", "json client dns[1]");
    ASSERT_EQ_INT(cfg.n_paths, 2, "json client path count");
    ASSERT_EQ_STR(cfg.paths[0], "eth0", "json client path[0]");
    ASSERT_EQ_INT(cfg.reconnect, 0, "json client reconnect");
    ASSERT_EQ_INT(cfg.reconnect_interval, 9, "json client reconnect interval");
    ASSERT_EQ_INT(cfg.kill_switch, 1, "json client kill switch");
    ASSERT_EQ_INT(cfg.manage_routes, 0, "json client manage_routes");
    ASSERT_EQ_STR(cfg.scheduler, "minrtt", "json client scheduler");
}

static void
test_parse_json_scheduler_wlb_udp_pin(void)
{
    const char *json = "{"
                       "\"mode\":\"client\","
                       "\"server_addr\":\"vpn.example.com:443\","
                       "\"auth_key\":\"k\","
                       "\"paths\":[\"eth0\"],"
                       "\"scheduler\":\"wlb_udp_pin\""
                       "}";
    char *path = write_tmp(json);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "json scheduler wlb_udp_pin parse ok");
    ASSERT_EQ_STR(cfg.scheduler, "wlb_udp_pin", "json scheduler wlb_udp_pin");
}

static void
test_json_duplicate_users_last_wins(void)
{
    const char *json = "{"
                       "\"listen\":\"0.0.0.0:443\","
                       "\"users\":[\"alice:old\", {\"name\":\"alice\",\"key\":\"new\"}]"
                       "}";

    char *path = write_tmp(json);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "json duplicate users parse ok");
    ASSERT_EQ_INT(cfg.n_users, 1, "json duplicate users collapsed");
    ASSERT_EQ_STR(cfg.user_keys[0], "new", "json duplicate user last wins");
}

static void
test_json_invalid_users_error(void)
{
    const char *json = "{"
                       "\"listen\":\"0.0.0.0:443\","
                       "\"users\":[{\"name\":\"alice\"}]"
                       "}";

    char *path = write_tmp(json);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    char error[1024] = "";
    mqvpn_log_set_sink(capture_warning, error);
    int rc = mqvpn_config_load(&cfg, path);
    mqvpn_log_set_sink(NULL, NULL);
    unlink(path);

    ASSERT_TRUE(rc != 0, "json invalid users returns error");
    ASSERT_TRUE(strstr(error, "config: invalid \"users\"") != NULL,
                "invalid users identifies the setting");
    ASSERT_TRUE(strstr(error, "names up to 63 bytes") != NULL,
                "invalid users explains the name limit");
}

static void
test_json_users_brace_in_string_value(void)
{
    /* A '}' inside a string value must not be mistaken for the object's
     * closing brace (regression for the naive strchr(p, '}') scan). */
    const char *json = "{"
                       "\"listen\":\"0.0.0.0:443\","
                       "\"users\":[{\"name\":\"a}b\",\"key\":\"k1\"},\"carol:c3\"]"
                       "}";

    char *path = write_tmp(json);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "json users brace-in-string parse ok");
    ASSERT_EQ_INT(cfg.n_users, 2, "json users brace-in-string count");
    ASSERT_EQ_STR(cfg.user_names[0], "a}b", "json users brace-in-string name");
    ASSERT_EQ_STR(cfg.user_keys[0], "k1", "json users brace-in-string key");
    ASSERT_EQ_STR(cfg.user_names[1], "carol", "json users string-form name after object");
    ASSERT_EQ_STR(cfg.user_keys[1], "c3", "json users string-form key after object");
}

static void
test_json_users_escaped_quote_in_value(void)
{
    /* \" inside an object-form value must not terminate the string scan
     * early. */
    const char *json = "{"
                       "\"listen\":\"0.0.0.0:443\","
                       "\"users\":[{\"name\":\"dave\",\"key\":\"k\\\"2\"}]"
                       "}";

    char *path = write_tmp(json);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "json users escaped-quote parse ok");
    ASSERT_EQ_INT(cfg.n_users, 1, "json users escaped-quote count");
    ASSERT_EQ_STR(cfg.user_names[0], "dave", "json users escaped-quote name");
    ASSERT_EQ_STR(cfg.user_keys[0], "k\"2", "json users escaped-quote key");
}

/* ================================================================
 *  JSON parser strictness (whole-document validation)
 * ================================================================ */

static void
test_json_syntax_error_fails(void)
{
    char opens[41], closes[41], deep[128];
    memset(opens, '[', 40);
    opens[40] = '\0';
    memset(closes, ']', 40);
    closes[40] = '\0';
    snprintf(deep, sizeof(deep), "{\"unused\":%s%s}", opens, closes);

    const char *bad[] = {
        "{\"mtu\":1400",
        "{\"mtu\":1400} x",
        "{\"mtu\":1400,}",
        "{\"mtu\":1400 // c\n}",
        "{\"tun_name\":\"a\xff"
        "b\"}",
        "{\"tun_name\":\"\\ud800\"}",
        "{\"unused\":1e400}",
        deep,
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        mqvpn_file_config_t cfg;
        mqvpn_config_defaults(&cfg);
        cfg.tun_mtu = 1300;
        ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, bad[i]), -1, bad[i]);
        ASSERT_EQ_INT(cfg.tun_mtu, 1300, "syntax error: cfg untouched");

        char *path = write_tmp(bad[i]);
        mqvpn_config_defaults(&cfg);
        cfg.tun_mtu = 1300;
        ASSERT_EQ_INT(mqvpn_config_load(&cfg, path), -1, bad[i]);
        ASSERT_EQ_INT(cfg.tun_mtu, 1300, "syntax error via file: cfg untouched");
        unlink(path);
    }
}

static void
test_json_file_raw_nul_fails(void)
{
    char path[] = "/tmp/test_config_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0, "raw NUL: mkstemp");
    if (fd < 0) return;
    ssize_t w = write(fd, "{\"mtu\":1400}\0 x", 15);
    close(fd);
    ASSERT_EQ_INT((int)w, 15, "raw NUL: file written");

    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    cfg.tun_mtu = 1300;
    char error[1024] = "";
    mqvpn_log_set_sink(capture_warning, error);
    int rc = mqvpn_config_load(&cfg, path);
    mqvpn_log_set_sink(NULL, NULL);
    ASSERT_EQ_INT(rc, -1, "raw NUL in JSON file fails");
    ASSERT_TRUE(strstr(error, path) != NULL, "raw NUL: log identifies the file");
    ASSERT_TRUE(strstr(error, "NUL byte at offset 12") != NULL,
                "raw NUL: log identifies the byte offset");
    ASSERT_TRUE(strstr(error, "save the file as UTF-8 (not UTF-16)") != NULL,
                "raw NUL: log explains how to fix the encoding");
    ASSERT_EQ_INT(cfg.tun_mtu, 1300, "raw NUL: cfg untouched");
    unlink(path);
}

static void
test_json_nested_key_not_lifted(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc =
        mqvpn_config_load_json_filecfg(&cfg, "{\"hybrid\":{\"mtu\":1500},\"mtu\":1400}");
    ASSERT_EQ_INT(rc, 0, "nested mtu + top mtu: rc");
    ASSERT_EQ_INT(cfg.tun_mtu, 1400, "top-level mtu wins over nested");

    mqvpn_config_defaults(&cfg);
    rc = mqvpn_config_load_json_filecfg(&cfg, "{\"hybrid\":{\"mtu\":1500}}");
    ASSERT_EQ_INT(rc, 0, "nested mtu only: rc");
    ASSERT_EQ_INT(cfg.tun_mtu, 0, "nested mtu is not top-level mtu");

    mqvpn_config_defaults(&cfg);
    rc = mqvpn_config_load_json_filecfg(&cfg,
                                        "{\"reorder_rules\":[{\"max_wait_ms\":77}]}");
    ASSERT_EQ_INT(rc, 0, "rule max_wait_ms: rc");
    ASSERT_EQ_INT(cfg.reorder.has_explicit_wait, 0,
                  "rule max_wait_ms does not leak into reorder");
}

static void
test_json_duplicate_key_first_wins(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load_json_filecfg(&cfg, "{\"mtu\":1400,\"mtu\":1500}");
    ASSERT_EQ_INT(rc, 0, "duplicate key: rc");
    ASSERT_EQ_INT(cfg.tun_mtu, 1400, "duplicate key: first wins");
}

static void
test_json_numeric_type_strict(void)
{
    char json[128];
    mqvpn_file_config_t cfg;

    static const char *mtu_bad[] = {"1400.0", "\"1400\"", "true", "1.4e3"};
    for (size_t i = 0; i < sizeof(mtu_bad) / sizeof(mtu_bad[0]); i++) {
        snprintf(json, sizeof(json), "{\"mtu\":%s}", mtu_bad[i]);
        mqvpn_config_defaults(&cfg);
        ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, json), 0, json);
        ASSERT_EQ_INT(cfg.tun_mtu, 0, json);
    }

    static const char *mc_bad[] = {"2147483648", "-2147483648", "4294967297", "\"abc\""};
    for (size_t i = 0; i < sizeof(mc_bad) / sizeof(mc_bad[0]); i++) {
        snprintf(json, sizeof(json), "{\"max_clients\":%s}", mc_bad[i]);
        mqvpn_config_defaults(&cfg);
        cfg.max_clients = 99;
        ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, json), 0, json);
        ASSERT_EQ_INT(cfg.max_clients, 64, json);
    }

    static const char *pid_bad[] = {"18446744073709551615", "18446744073709551616", "-1"};
    for (size_t i = 0; i < sizeof(pid_bad) / sizeof(pid_bad[0]); i++) {
        snprintf(json, sizeof(json), "{\"init_max_path_id\":%s}", pid_bad[i]);
        mqvpn_config_defaults(&cfg);
        ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, json), 0, json);
        ASSERT_EQ_ULL(cfg.init_max_path_id, 0ULL, json);
    }
}

static void
test_json_string_decoding(void)
{
    char json[512];
    char longname[301];
    memset(longname, 't', 300);
    longname[300] = '\0';
    snprintf(json, sizeof(json), "{\"tun_name\":\"%s\"}", longname);

    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, json), 0, "long tun_name: rc");
    ASSERT_EQ_INT((int)strlen(cfg.tun_name), (int)sizeof(cfg.tun_name) - 1,
                  "long tun_name truncated");

    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, "{\"tun_name\":\"a\\u0000b\"}"), 0,
                  "tun_name with \\u0000: rc");
    ASSERT_EQ_STR(cfg.tun_name, "mqvpn0", "tun_name with \\u0000 rejected");

    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(
        mqvpn_config_load_json_filecfg(&cfg, "{\"auth_key\":\"a\\\"b\\\\c\\u00e9\\n\"}"),
        0, "escaped auth_key: rc");
    ASSERT_EQ_STR(cfg.auth_key, "a\"b\\c\xc3\xa9\n", "escapes decoded");
}

static void
test_json_users_shapes(void)
{
    char json[1024];
    char pad[601];
    memset(pad, 'x', 600);
    pad[600] = '\0';
    snprintf(json, sizeof(json),
             "{\"users\":[{\"name\":\"u1\",\"key\":\"k1\",\"pad\":\"%s\"}]}", pad);

    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, json), 0, "600-byte user object");
    ASSERT_EQ_INT(cfg.n_users, 1, "600-byte user object: n_users");

    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, "{\"users\":[5]}"), -1,
                  "numeric user element");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, "{\"users\":[\"nocolon\"]}"), -1,
                  "user string without colon");

    char name[201], key[201];
    memset(name, 'n', 200);
    name[200] = '\0';
    memset(key, 'k', 200);
    key[200] = '\0';
    snprintf(json, sizeof(json), "{\"users\":[\"%s:%s\"]}", name, key);
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, json), -1,
                  "200-byte username rejected before pair truncation");
    ASSERT_EQ_INT(cfg.n_users, 0, "long username not added");

    char longa[361];
    memset(longa, 'a', 360);
    longa[360] = '\0';
    snprintf(json, sizeof(json), "{\"users\":[\"%s:k\"]}", longa);
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, json), -1,
                  "colon past the 359-byte pair cap");

    static const char *preload = "{\"users\":[\"alice:a1\",\"bob:b2\"]}";
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, preload), 0, "preload users");
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, "{\"users\":\"x\"}"), -1,
                  "non-array users");
    ASSERT_EQ_INT(cfg.n_users, 2, "non-array users: n_users kept");
    ASSERT_EQ_STR(cfg.user_names[0], "alice", "non-array users: name[0] kept");
    ASSERT_EQ_STR(cfg.user_names[1], "bob", "non-array users: name[1] kept");

    static const char *unterminated = "{\"users\":[\"zed:1\",";
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load_json_filecfg(&cfg, preload);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, unterminated), -1,
                  "unterminated users");
    ASSERT_EQ_INT(cfg.n_users, 2, "unterminated users: n_users kept");
    ASSERT_EQ_STR(cfg.user_names[0], "alice", "unterminated users: name[0] kept");
    ASSERT_EQ_STR(cfg.user_names[1], "bob", "unterminated users: name[1] kept");

    char *path = write_tmp(unterminated);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load_json_filecfg(&cfg, preload);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, path), -1, "unterminated users via file");
    unlink(path);
    ASSERT_EQ_INT(cfg.n_users, 2, "unterminated users via file: n_users kept");
    ASSERT_EQ_STR(cfg.user_names[0], "alice", "unterminated users via file: name[0]");
    ASSERT_EQ_STR(cfg.user_names[1], "bob", "unterminated users via file: name[1]");
}

static void
test_json_dns_paths_atomic(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(
        mqvpn_config_load_json_filecfg(
            &cfg, "{\"dns\":[\"1.1.1.1\",\"8.8.8.8\"],\"paths\":[\"eth0\",\"wlan0\"]}"),
        0, "preload dns/paths");

    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, "{\"dns\":[\"9.9.9.9\",123]}"), 0,
                  "bad dns element: rc");
    ASSERT_EQ_INT(cfg.n_dns, 2, "bad dns element: n_dns kept");
    ASSERT_EQ_STR(cfg.dns_servers[0], "1.1.1.1", "bad dns element: dns[0] kept");

    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, "{\"paths\":[\"eth9\",123]}"), 0,
                  "bad path element: rc");
    ASSERT_EQ_INT(cfg.n_paths, 2, "bad path element: n_paths kept");
    ASSERT_EQ_STR(cfg.paths[0], "eth0", "bad path element: paths[0] kept");

    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(
        mqvpn_config_load_json_filecfg(&cfg, "{\"hybrid\":{\"egress_allow\":[1]}}"), -1,
        "non-string egress_allow element");
}

static void
test_json_reorder_rules_types(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, "{\"reorder_rules\":[1]}"), -1,
                  "non-object reorder rule");

    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(
        mqvpn_config_load_json_filecfg(&cfg, "{\"reorder_rules\":[{\"port\":\"443\"}]}"),
        0, "string port: rc");
    ASSERT_EQ_INT(cfg.reorder.n_rules, 1, "string port: rule added");
    ASSERT_EQ_INT(cfg.reorder.rules[0].port, 0, "string port: begin-time default");

    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(
        mqvpn_config_load_json_filecfg(&cfg, "{\"reorder_rules\":[{\"max_wait_ms\":0}]}"),
        0, "max_wait_ms 0: rc");
    ASSERT_EQ_INT(cfg.reorder.n_rules, 1, "max_wait_ms 0: rule added");
    ASSERT_EQ_INT(cfg.reorder.rules[0].explicit_wait_ms, 0, "max_wait_ms 0 rejected");

    static const char *cap_bad[] = {"{\"reorder_rules\":[{\"cap_packets\":0}]}",
                                    "{\"reorder_rules\":[{\"cap_packets\":3}]}"};
    for (size_t i = 0; i < sizeof(cap_bad) / sizeof(cap_bad[0]); i++) {
        mqvpn_config_defaults(&cfg);
        ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&cfg, cap_bad[i]), 0, cap_bad[i]);
        ASSERT_EQ_INT(cfg.reorder.n_rules, 1, cap_bad[i]);
        ASSERT_EQ_INT(cfg.reorder.rules[0].explicit_cap, 0, cap_bad[i]);
    }

    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(
                      &cfg, "{\"reorder_rules\":[{\"cap_packets\":4096}]}"),
                  0, "cap_packets 4096: rc");
    ASSERT_EQ_INT(cfg.reorder.rules[0].explicit_cap, 4096, "cap_packets 4096 accepted");

    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(
        mqvpn_config_load_json_filecfg(&cfg, "{\"reorder_rules\":[{\"proto\":6}]}"), 0,
        "numeric proto: rc");
    ASSERT_EQ_INT(cfg.reorder.rules[0].proto, 17, "numeric proto: default UDP kept");
}

/* ================================================================
 *  Buffer boundary and edge case tests
 * ================================================================ */

static void
test_tun_name_max_length(void)
{
    char long_name[64];
    memset(long_name, 'A', 63);
    long_name[63] = '\0';
    char ini[256];
    snprintf(ini, sizeof(ini), "[Interface]\nTunName = %s\n", long_name);
    char *f = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, f), 0, "load long TunName");
    ASSERT_TRUE(strlen(cfg.tun_name) < 32, "TunName truncated to buffer size");
    unlink(f);
}

static void
test_dns_exceeds_max(void)
{
    const char *ini = "[Interface]\n"
                      "DNS = 1.1.1.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 208.67.222.222\n";
    char *f = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, f);
    ASSERT_EQ_INT(cfg.n_dns, 4, "DNS capped at 4");
    unlink(f);
}

static void
test_reconnect_interval_overflow(void)
{
    const char *ini = "[Interface]\n"
                      "Reconnect = true\n"
                      "ReconnectInterval = 999999999\n";
    char *f = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, f);
    ASSERT_EQ_INT(cfg.reconnect_interval, 999999999,
                  "huge interval stored as-is (no upper clamp)");
    unlink(f);
}

static void
test_value_contains_equals(void)
{
    const char *ini = "[Auth]\n"
                      "Key = abc=def=ghi\n";
    char *f = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, f);
    ASSERT_EQ_STR(cfg.auth_key, "abc=def=ghi", "value with = preserved");
    unlink(f);
}

static void
test_parse_control_section(void)
{
    const char *ini = "[Interface]\n"
                      "Listen = 0.0.0.0:443\n"
                      "\n"
                      "[Control]\n"
                      "Listen = 127.0.0.1:9090\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "[Control] parse ok");
    ASSERT_EQ_STR(cfg.control_listen, "127.0.0.1:9090", "control_listen");
}

static void
test_parse_control_absent(void)
{
    const char *ini = "[Interface]\n"
                      "Listen = 0.0.0.0:443\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "no [Control] is ok");
    ASSERT_EQ_STR(cfg.control_listen, "", "control_listen empty when section absent");
}

static void
test_parse_control_json(void)
{
    const char *json = "{ \"mode\": \"server\","
                       "  \"listen\": \"0.0.0.0:443\","
                       "  \"control_listen\": \"1.2.3.4:9091\" }";
    char *path = write_tmp(json);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "JSON control_listen parse ok");
    ASSERT_EQ_STR(cfg.control_listen, "1.2.3.4:9091", "JSON control_listen");
}

static void
test_parse_control_unknown_key(void)
{
    const char *ini = "[Interface]\n"
                      "Listen = 0.0.0.0:443\n"
                      "\n"
                      "[Control]\n"
                      "Foo = bar\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "[Control] unknown key is non-fatal");
    ASSERT_EQ_STR(cfg.control_listen, "", "control_listen unchanged on unknown key");
}

/* ================================================================
 *  mqvpn_resolve_control_endpoint helper tests (per-field merge)
 * ================================================================ */

static void
test_resolve_ini_only(void)
{
    char buf[256] = {0};
    const char *out_addr = NULL;
    int out_port = 0;
    int rc = mqvpn_resolve_control_endpoint("127.0.0.1:9090", /* file_listen */
                                            NULL,             /* cli_addr */
                                            0, 0,             /* cli_port, cli_port_set */
                                            buf, sizeof(buf), &out_addr, &out_port);
    ASSERT_EQ_INT(rc, 0, "resolve INI only ok");
    ASSERT_EQ_INT(out_port, 9090, "INI port");
    ASSERT_TRUE(out_addr != NULL && strcmp(out_addr, "127.0.0.1") == 0, "INI addr");
}

static void
test_resolve_cli_port_overrides(void)
{
    char buf[256] = {0};
    const char *out_addr = NULL;
    int out_port = 0;
    int rc = mqvpn_resolve_control_endpoint("127.0.0.1:9090", NULL, 9091, 1, buf,
                                            sizeof(buf), &out_addr, &out_port);
    ASSERT_EQ_INT(rc, 0, "resolve CLI port override ok");
    ASSERT_EQ_INT(out_port, 9091, "CLI port wins");
    ASSERT_TRUE(out_addr != NULL && strcmp(out_addr, "127.0.0.1") == 0,
                "INI addr preserved");
}

static void
test_resolve_cli_addr_overrides(void)
{
    char buf[256] = {0};
    const char *out_addr = NULL;
    int out_port = 0;
    int rc = mqvpn_resolve_control_endpoint("127.0.0.1:9090", "0.0.0.0", 0, 0, buf,
                                            sizeof(buf), &out_addr, &out_port);
    ASSERT_EQ_INT(rc, 0, "resolve CLI addr override ok");
    ASSERT_EQ_INT(out_port, 9090, "INI port preserved");
    ASSERT_TRUE(out_addr != NULL && strcmp(out_addr, "0.0.0.0") == 0, "CLI addr wins");
}

static void
test_resolve_explicit_disable(void)
{
    char buf[256] = {0};
    const char *out_addr = NULL;
    int out_port = -1;
    int rc = mqvpn_resolve_control_endpoint("127.0.0.1:9090", NULL, 0,
                                            1, /* cli_port=0, cli_port_set=1 */
                                            buf, sizeof(buf), &out_addr, &out_port);
    ASSERT_EQ_INT(rc, 0, "resolve explicit disable ok");
    ASSERT_EQ_INT(out_port, 0, "--control-port 0 disables even when INI is set");
}

static void
test_resolve_no_input(void)
{
    char buf[256] = {0};
    const char *out_addr = NULL;
    int out_port = -1;
    int rc = mqvpn_resolve_control_endpoint("", NULL, 0, 0, buf, sizeof(buf), &out_addr,
                                            &out_port);
    ASSERT_EQ_INT(rc, 0, "resolve no input ok");
    ASSERT_EQ_INT(out_port, 0, "disabled when no INI and no CLI");
    ASSERT_TRUE(out_addr == NULL, "addr stays NULL when no input");
}

static void
test_resolve_malformed_ini(void)
{
    char buf[256] = {0};
    const char *out_addr = NULL;
    int out_port = -1;
    int rc = mqvpn_resolve_control_endpoint("not_a_host_port", NULL, 0, 0, buf,
                                            sizeof(buf), &out_addr, &out_port);
    ASSERT_EQ_INT(rc, -1, "malformed INI returns -1");
}

static void
test_resolve_trailing_garbage_port(void)
{
    /* "9090garbage" must NOT silently parse as 9090 — strtol contract. */
    char buf[256] = {0};
    const char *out_addr = NULL;
    int out_port = -1;
    int rc = mqvpn_resolve_control_endpoint("127.0.0.1:9090garbage", NULL, 0, 0, buf,
                                            sizeof(buf), &out_addr, &out_port);
    ASSERT_EQ_INT(rc, -1, "trailing garbage in port returns -1");

    /* Same for IPv6 bracket form. */
    rc = mqvpn_resolve_control_endpoint("[::1]:9090garbage", NULL, 0, 0, buf, sizeof(buf),
                                        &out_addr, &out_port);
    ASSERT_EQ_INT(rc, -1, "trailing garbage in v6 port returns -1");
}

static void
test_resolve_port_leading_junk(void)
{
    /* Port must be a bare unsigned decimal — no leading whitespace, no sign. */
    char buf[256] = {0};
    const char *out_addr = NULL;
    int out_port = -1;

    int rc = mqvpn_resolve_control_endpoint("127.0.0.1: 9090", NULL, 0, 0, buf,
                                            sizeof(buf), &out_addr, &out_port);
    ASSERT_EQ_INT(rc, -1, "leading whitespace in port returns -1");

    rc = mqvpn_resolve_control_endpoint("127.0.0.1:+9090", NULL, 0, 0, buf, sizeof(buf),
                                        &out_addr, &out_port);
    ASSERT_EQ_INT(rc, -1, "leading + sign in port returns -1");

    rc = mqvpn_resolve_control_endpoint("127.0.0.1:-9090", NULL, 0, 0, buf, sizeof(buf),
                                        &out_addr, &out_port);
    ASSERT_EQ_INT(rc, -1, "leading - sign in port returns -1");

    rc = mqvpn_resolve_control_endpoint("127.0.0.1:", NULL, 0, 0, buf, sizeof(buf),
                                        &out_addr, &out_port);
    ASSERT_EQ_INT(rc, -1, "empty port returns -1");
}

/* ── [Hybrid] section (H1) ──────────────────────────────────────────────── */

static void
test_hybrid_defaults_when_absent(void)
{
    /* No [Hybrid] section → classifier defaults (0/AUTO/256/300). */
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(cfg.hybrid.enabled, 0, "hybrid default enabled off");
    ASSERT_EQ_INT(cfg.hybrid.tcp_mode, MQVPN_HYBRID_TCP_AUTO, "hybrid default tcp auto");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_max_flows, 256, "hybrid default tcp_max_flows");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_idle_timeout_sec, 300,
                  "hybrid default tcp_idle_timeout_sec");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_connect_timeout_sec, 10,
                  "hybrid default tcp_connect_timeout_sec");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_max_global_flows,
                  MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT,
                  "hybrid default tcp_max_global_flows");
    ASSERT_EQ_INT(cfg.hybrid.n_egress_allow, 0, "hybrid default no egress_allow entries");
    ASSERT_EQ_INT(cfg.hybrid.n_egress_deny, 0, "hybrid default no egress_deny entries");

    /* Loading a config without [Hybrid] must keep the defaults. */
    char *p = write_tmp("[Interface]\nListen = 0.0.0.0:443\n");
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, p);
    unlink(p);
    ASSERT_EQ_INT(rc, 0, "no-hybrid ini load ok");
    ASSERT_EQ_INT(cfg.hybrid.enabled, 0, "no-hybrid keeps enabled off");
    ASSERT_EQ_INT(cfg.hybrid.tcp_mode, MQVPN_HYBRID_TCP_AUTO, "no-hybrid keeps tcp auto");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_max_flows, 256, "no-hybrid keeps tcp_max_flows");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_idle_timeout_sec, 300,
                  "no-hybrid keeps tcp_idle_timeout_sec");
}

static void
test_hybrid_section_parse(void)
{
    mqvpn_file_config_t cfg;

    /* INI parse */
    char *p = write_tmp("[Hybrid]\n"
                        "Enabled = true\n"
                        "Tcp = raw\n"
                        "TcpMaxFlows = 128\n"
                        "TcpIdleTimeoutSec = 60\n");
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, p);
    unlink(p);
    ASSERT_EQ_INT(rc, 0, "hybrid ini load ok");
    ASSERT_EQ_INT(cfg.hybrid.enabled, 1, "hybrid ini enabled");
    ASSERT_EQ_INT(cfg.hybrid.tcp_mode, MQVPN_HYBRID_TCP_RAW, "hybrid ini tcp raw");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_max_flows, 128, "hybrid ini tcp_max_flows");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_idle_timeout_sec, 60, "hybrid ini idle timeout");

    /* Tcp mode value is case-insensitive (mirrors reorder Enabled=/Profile=) */
    p = write_tmp("[Hybrid]\nTcp = STREAM\n");
    mqvpn_config_defaults(&cfg);
    rc = mqvpn_config_load(&cfg, p);
    unlink(p);
    ASSERT_EQ_INT(rc, 0, "hybrid ini stream load ok");
    ASSERT_EQ_INT(cfg.hybrid.tcp_mode, MQVPN_HYBRID_TCP_STREAM,
                  "hybrid ini tcp STREAM case-insensitive");

    /* JSON parse: same keys inside a bounded "hybrid" object */
    mqvpn_config_defaults(&cfg);
    rc = mqvpn_config_load_json_filecfg(&cfg, "{\"hybrid\":{"
                                              "\"enabled\":true,"
                                              "\"tcp\":\"raw\","
                                              "\"tcp_max_flows\":128,"
                                              "\"tcp_idle_timeout_sec\":60"
                                              "}}");
    ASSERT_EQ_INT(rc, 0, "hybrid json load ok");
    ASSERT_EQ_INT(cfg.hybrid.enabled, 1, "hybrid json enabled");
    ASSERT_EQ_INT(cfg.hybrid.tcp_mode, MQVPN_HYBRID_TCP_RAW, "hybrid json tcp raw");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_max_flows, 128, "hybrid json tcp_max_flows");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_idle_timeout_sec, 60, "hybrid json idle timeout");
}

static void
test_advanced_recv_rate_limit(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(cfg.recv_rate_limit == 0, 1, "recv_rate_limit default 0");

    char *p = write_tmp("[Advanced]\nRecvRateLimit = 125000000\n");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "advanced ini load ok");
    unlink(p);
    ASSERT_EQ_INT(cfg.recv_rate_limit == 125000000ULL, 1, "ini recv_rate_limit");

    p = write_tmp("{\"advanced\": {\"recv_rate_limit\": 125000000}}");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "advanced json load ok");
    unlink(p);
    ASSERT_EQ_INT(cfg.recv_rate_limit == 125000000ULL, 1, "json recv_rate_limit");

    /* Range cap (MQVPN_RECV_RATE_LIMIT_MAX): values above it must be
     * rejected (warn-and-continue, field keeps its default) — an
     * over-range rate would overflow xquic's rate x srtt(us) u64 window
     * product and pin the window at the MINIMUM, the opposite of intent. */
    char over[128];
    snprintf(over, sizeof(over), "[Advanced]\nRecvRateLimit = %llu\n",
             (unsigned long long)MQVPN_RECV_RATE_LIMIT_MAX + 1);
    p = write_tmp(over);
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "over-max ini warns, load rc 0");
    unlink(p);
    ASSERT_EQ_INT(cfg.recv_rate_limit == 0, 1, "over-max ini rejected → default 0");

    snprintf(over, sizeof(over), "[Advanced]\nRecvRateLimit = %llu\n",
             (unsigned long long)MQVPN_RECV_RATE_LIMIT_MAX);
    p = write_tmp(over);
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "boundary ini load ok");
    unlink(p);
    ASSERT_EQ_INT(cfg.recv_rate_limit == MQVPN_RECV_RATE_LIMIT_MAX, 1,
                  "boundary value == max accepted");

    snprintf(over, sizeof(over), "{\"advanced\": {\"recv_rate_limit\": %llu}}",
             (unsigned long long)MQVPN_RECV_RATE_LIMIT_MAX + 1);
    p = write_tmp(over);
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "over-max json warns, load rc 0");
    unlink(p);
    ASSERT_EQ_INT(cfg.recv_rate_limit == 0, 1, "over-max json rejected → default 0");
}

static void
test_advanced_udp_gso(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(cfg.udp_gso, 1, "udp_gso default 1 (absent)");

    char *p = write_tmp("[Advanced]\nUdpGso = false\n");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "advanced ini load ok");
    unlink(p);
    ASSERT_EQ_INT(cfg.udp_gso, 0, "ini UdpGso=false");

    p = write_tmp("{\"advanced\": {\"udp_gso\": false}}");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "advanced json load ok");
    unlink(p);
    ASSERT_EQ_INT(cfg.udp_gso, 0, "json udp_gso=false");
}

static void
test_advanced_udp_gro(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(cfg.udp_gro, 1, "udp_gro default 1 (absent)");

    char *p = write_tmp("[Advanced]\nUdpGro = false\n");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "advanced ini load ok");
    unlink(p);
    ASSERT_EQ_INT(cfg.udp_gro, 0, "ini UdpGro=false");

    p = write_tmp("{\"advanced\": {\"udp_gro\": false}}");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "advanced json load ok");
    unlink(p);
    ASSERT_EQ_INT(cfg.udp_gro, 0, "json udp_gro=false");
}

static void
test_advanced_tun_offload(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(cfg.tun_offload, 1, "tun_offload default 1 (absent)");
    ASSERT_EQ_INT(cfg.tun_gro, 1, "tun_gro default 1 (absent)");

    char *p = write_tmp("[Advanced]\nTunOffload = false\nTunGro = false\n");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "advanced ini load ok");
    unlink(p);
    ASSERT_EQ_INT(cfg.tun_offload, 0, "ini TunOffload=false");
    ASSERT_EQ_INT(cfg.tun_gro, 0, "ini TunGro=false");

    p = write_tmp("{\"advanced\": {\"tun_offload\": false, \"tun_gro\": false}}");
    mqvpn_config_defaults(&cfg);
    ASSERT_EQ_INT(mqvpn_config_load(&cfg, p), 0, "advanced json load ok");
    unlink(p);
    ASSERT_EQ_INT(cfg.tun_offload, 0, "json tun_offload=false");
    ASSERT_EQ_INT(cfg.tun_gro, 0, "json tun_gro=false");
}

/* ── [Hybrid] EgressAllow/EgressDeny lists + TcpConnectTimeoutSec ───────── */

static void
test_hybrid_egress_acl_ini(void)
{
    const char *ini = "[Hybrid]\n"
                      "EgressAllow = 10.0.0.0/8\n"
                      "EgressAllow = 192.168.1.0/24\n"
                      "EgressDeny = 172.16.5.0/24\n"
                      "TcpConnectTimeoutSec = 20\n"
                      "TcpMaxGlobalFlows = 8192\n";

    char *p = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, p);
    unlink(p);

    ASSERT_EQ_INT(rc, 0, "egress acl ini load ok");
    ASSERT_EQ_INT(cfg.hybrid.n_egress_allow, 2, "2 egress_allow entries parsed");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[0].family, 4, "allow[0] family");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[0].prefix_len, 8, "allow[0] prefix_len");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[0].net[0], 10, "allow[0] net[0]");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[1].prefix_len, 24, "allow[1] prefix_len");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[1].net[0], 192, "allow[1] net[0]");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[1].net[1], 168, "allow[1] net[1]");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[1].net[2], 1, "allow[1] net[2]");
    ASSERT_EQ_INT(cfg.hybrid.n_egress_deny, 1, "1 egress_deny entry parsed");
    ASSERT_EQ_INT(cfg.hybrid.egress_deny[0].net[0], 172, "deny[0] net[0]");
    ASSERT_EQ_INT(cfg.hybrid.egress_deny[0].net[1], 16, "deny[0] net[1]");
    ASSERT_EQ_INT(cfg.hybrid.egress_deny[0].net[2], 5, "deny[0] net[2]");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_connect_timeout_sec, 20, "tcp_connect_timeout_sec");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_max_global_flows, 8192, "tcp_max_global_flows");

    /* Host bits in the address part are deliberately masked off (route-table
     * convention): "10.0.0.5/8" stores net 10.0.0.0, not 10.0.0.5. */
    mqvpn_cidr_entry_t e;
    ASSERT_EQ_INT(mqvpn_parse_cidr("10.0.0.5/8", &e), 0, "host-bits cidr parses");
    ASSERT_EQ_INT(e.net[0], 10, "host bits normalized off the net");
    ASSERT_EQ_INT(e.net[3], 0, "host bits normalized off the net (last byte)");
}

static void
test_hybrid_egress_acl_ini_invalid_ignored(void)
{
    const char *ini = "[Hybrid]\n"
                      "EgressAllow = not-a-cidr\n"
                      "EgressAllow = 10.0.0.0/8\n"
                      "EgressAllow = 1.2.3.4/33\n";

    char *p = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, p);
    unlink(p);

    ASSERT_EQ_INT(rc, 0, "malformed egress acl entries don't abort load");
    ASSERT_EQ_INT(cfg.hybrid.n_egress_allow, 1, "only the valid entry parsed");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[0].net[0], 10, "valid entry kept");
}

static void
test_hybrid_egress_acl_json(void)
{
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load_json_filecfg(&cfg, "{\"hybrid\":{"
                                                  "\"egress_allow\":[\"10.0.0.0/8\"],"
                                                  "\"egress_deny\":[\"172.16.5.0/24\"],"
                                                  "\"tcp_connect_timeout_sec\":20,"
                                                  "\"tcp_max_global_flows\":8192"
                                                  "}}");
    ASSERT_EQ_INT(rc, 0, "egress acl json load ok");
    ASSERT_EQ_INT(cfg.hybrid.n_egress_allow, 1, "1 egress_allow entry parsed (json)");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[0].net[0], 10, "allow[0] net[0] (json)");
    ASSERT_EQ_INT(cfg.hybrid.n_egress_deny, 1, "1 egress_deny entry parsed (json)");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_connect_timeout_sec, 20,
                  "tcp_connect_timeout_sec (json)");
    ASSERT_EQ_INT((int)cfg.hybrid.tcp_max_global_flows, 8192,
                  "tcp_max_global_flows (json)");
}

/* [Hybrid] EgressAllow/EgressDeny is a hand-coded repeated key (config.c's
 * SEC_HYBRID case), NOT a cfg_keys[] scalar descriptor row — so this is the
 * only place a v6 entry needs its own parse-path test; there is no
 * scalar-parity row to add alongside it (see the table refactor, PR #185). */
static void
test_hybrid_egress_acl_ini_v6(void)
{
    const char *ini = "[Hybrid]\n"
                      "EgressAllow = fd00::/8\n"
                      "EgressDeny = 2001:db8::/32\n";

    char *p = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, p);
    unlink(p);

    ASSERT_EQ_INT(rc, 0, "v6 egress acl ini load ok");
    ASSERT_EQ_INT(cfg.hybrid.n_egress_allow, 1, "1 v6 egress_allow entry parsed");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[0].family, 6, "v6 allow[0] family");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[0].prefix_len, 8, "v6 allow[0] prefix_len");
    ASSERT_EQ_INT(cfg.hybrid.egress_allow[0].net[0], 0xfd, "v6 allow[0] net[0]");
    ASSERT_EQ_INT(cfg.hybrid.n_egress_deny, 1, "1 v6 egress_deny entry parsed");
    ASSERT_EQ_INT(cfg.hybrid.egress_deny[0].family, 6, "v6 deny[0] family");
    ASSERT_EQ_INT(cfg.hybrid.egress_deny[0].prefix_len, 32, "v6 deny[0] prefix_len");
    ASSERT_EQ_INT(cfg.hybrid.egress_deny[0].net[0], 0x20, "v6 deny[0] net[0]");
    ASSERT_EQ_INT(cfg.hybrid.egress_deny[0].net[1], 0x01, "v6 deny[0] net[1]");
}

/* ── INI ↔ JSON scalar-key parity (pins the descriptor-table refactor) ──── */

/* RedundantPorts is a complex key: errors set redundant_ports_err instead of
 * being downgraded to warn-and-ignore. */
static void
redundant_ports_ini(const char *val, mqvpn_file_config_t *c)
{
    char ini[1536];
    snprintf(ini, sizeof(ini), "[Multipath]\nRedundantPorts = %s\n", val);
    char *path = write_tmp(ini);
    mqvpn_config_defaults(c);
    mqvpn_config_load(c, path);
    unlink(path);
}

static void
redundant_ports_json(const char *val, mqvpn_file_config_t *c)
{
    char js[1536];
    snprintf(js, sizeof(js), "{\"redundant_ports\":%s}", val);
    mqvpn_config_defaults(c);
    mqvpn_config_load_json_filecfg(c, js);
}

static void
test_redundant_ports_ini_json(void)
{
    mqvpn_file_config_t a, b;
    redundant_ports_ini("4200,9000", &a);
    redundant_ports_json("\"4200,9000\"", &b);
    ASSERT_EQ_STR(a.redundant_ports, "4200,9000", "rports ini value");
    ASSERT_EQ_STR(b.redundant_ports, "4200,9000", "rports json value");
    ASSERT_EQ_INT(a.redundant_ports_err, 0, "rports ini ok");
    ASSERT_EQ_INT(b.redundant_ports_err, 0, "rports json ok");

    char longlist[512] = "", spaces[512] = "", huge[1200];
    for (int i = 0; i < 60; i++)
        strcat(longlist, "4200,"); /* 300 chars */
    memset(spaces, ' ', 300);
    memset(huge, '1', 1100);
    huge[1100] = '\0';

    redundant_ports_ini(longlist, &a);
    ASSERT_EQ_INT(a.redundant_ports_err, 1, "rports ini 300 chars");
    char q[1300];
    snprintf(q, sizeof(q), "\"%s\"", longlist);
    redundant_ports_json(q, &b);
    ASSERT_EQ_INT(b.redundant_ports_err, 1, "rports json 300 chars");
    snprintf(q, sizeof(q), "\"%sabc\"", spaces);
    redundant_ports_json(q, &b);
    ASSERT_EQ_INT(b.redundant_ports_err, 1, "rports json spaces then abc");
    snprintf(q, sizeof(q), "\"%s\"", huge);
    redundant_ports_json(q, &b);
    ASSERT_EQ_INT(b.redundant_ports_err, 1, "rports json 1100 chars");
    redundant_ports_json("[4200]", &b);
    ASSERT_EQ_INT(b.redundant_ports_err, 1, "rports json non-string");
    redundant_ports_json("\"4200,abc\"", &b);
    ASSERT_EQ_INT(b.redundant_ports_err, 1, "rports json bad token");
    redundant_ports_ini("4200,abc", &a);
    ASSERT_EQ_INT(a.redundant_ports_err, 1, "rports ini bad token");
    ASSERT_EQ_STR(a.redundant_ports, "4200,abc", "rports ini bad value kept");
    ASSERT_EQ_STR(b.redundant_ports, "4200,abc", "rports json bad value kept");

    redundant_ports_json("\"  4200  \"", &b);
    ASSERT_EQ_STR(b.redundant_ports, "4200", "rports json trimmed");
    ASSERT_EQ_INT(b.redundant_ports_err, 0, "rports json trimmed ok");
    snprintf(q, sizeof(q), "\"%s4200\"", spaces);
    redundant_ports_json(q, &b);
    ASSERT_EQ_STR(b.redundant_ports, "4200", "rports json 300 spaces then 4200");
    ASSERT_EQ_INT(b.redundant_ports_err, 0, "rports json 300 spaces ok");
}

static void
test_redundant_ini_bool(void)
{
    const char *vals[] = {"true", "false", "TRUE", "False", "on", "off", "no", "bogus"};
    const int want_rc[] = {0, 0, 0, 0, -1, -1, -1, -1};
    const int want[] = {1, 0, 1, 0, 0, 0, 0, 0};
    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        char ini[64];
        snprintf(ini, sizeof(ini), "[Multipath]\nRedundant = %s\n", vals[i]);
        char *path = write_tmp(ini);
        mqvpn_file_config_t c;
        mqvpn_config_defaults(&c);
        ASSERT_EQ_INT(mqvpn_config_load(&c, path), want_rc[i], vals[i]);
        unlink(path);
        ASSERT_EQ_INT(c.redundant, want[i], vals[i]);
    }
}

static void
test_json_bool_strict(void)
{
    /* A bool key must be a JSON true/false; a string such as "on" (or even
     * "true") fails the load, in every scope. */
    const char *bad[] = {
        "{\"insecure\":\"true\"}",
        "{\"hybrid\":{\"enabled\":\"on\"}}",
        "{\"reorder\":{\"enabled\":\"on\"}}",
        "{\"advanced\":{\"udp_gso\":1}}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        mqvpn_file_config_t c;
        mqvpn_config_defaults(&c);
        ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&c, bad[i]), -1, bad[i]);
    }
    mqvpn_file_config_t c;
    mqvpn_config_defaults(&c);
    ASSERT_EQ_INT(mqvpn_config_load_json_filecfg(&c, "{\"hybrid\":{\"enabled\":true}}"),
                  0, "hybrid enabled true loads");
    ASSERT_EQ_INT(c.hybrid.enabled, 1, "hybrid enabled true");
}

static void
test_ini_json_scalar_parity(void)
{
    /* Every scalar key, non-default value. Complex keys (DNS/User/Path/
     * ReorderRule) are deliberately absent so both structs keep defaults
     * there and whole-struct memcmp is meaningful. */
    const char *ini = "[Interface]\n"
                      "TunName = tparity0\n"
                      "Listen = 192.0.2.1:8443\n"
                      "Subnet = 10.99.0.0/24\n"
                      "Subnet6 = fd00:beef::/112\n"
                      "LogLevel = debug\n"
                      "KillSwitch = true\n"
                      "ManageRoutes = false\n"
                      "Reconnect = false\n"
                      "ReconnectInterval = 17\n"
                      "MTU = 1420\n"
                      "PathMTU = 1492\n"
                      "PMTUD = true\n"
                      "[Server]\n"
                      "Address = vpn.parity.test:4433\n"
                      "ServerName = sni.parity.test\n"
                      "Insecure = true\n"
                      "[TLS]\n"
                      "Cert = /tmp/parity.crt\n"
                      "Key = /tmp/parity.key\n"
                      "[Auth]\n"
                      "MaxClients = 120\n"
                      "[Control]\n"
                      "Listen = 127.0.0.2:9091\n"
                      "[Multipath]\n"
                      "Scheduler = min_srtt\n"
                      "AllowClientScheduler = true\n"
                      "RequestServerScheduler = true\n"
                      "CC = cubic\n"
                      "InitMaxPathId = 16\n"
                      "Reinjection = deadline\n"
                      "ReinjectionSrttFactorPct = 150\n"
                      "ReinjectionHardDeadlineMs = 300\n"
                      "ReinjectionDeadlineLowerBoundMs = 10\n"
                      "Redundant = true\n"
                      "[Reorder]\n"
                      "Enabled = true\n"
                      "MaxWaitMs = 55\n"
                      "CapPackets = 256\n"
                      "MaxBytesPerFlow = 5000000\n"
                      "ClassifyWindow = 33\n"
                      "AckDemoteMaxLarge = 7\n"
                      "SmallPacketThreshold = 333\n"
                      "ResetMarkPackets = 9\n"
                      "ResetIdleGraceMs = 400\n"
                      "MaxFlows = 77\n"
                      "GlobalMaxBytes = 9000000\n"
                      "IngressIdleSec = 11\n"
                      "EgressIdleSec = 22\n"
                      "[Hybrid]\n"
                      "Enabled = true\n"
                      "Tcp = raw\n"
                      "TcpMaxFlows = 128\n"
                      "TcpIdleTimeoutSec = 60\n"
                      "TcpConnectTimeoutSec = 20\n"
                      "TcpMaxGlobalFlows = 8192\n"
                      "[Advanced]\n"
                      "RecvRateLimit = 77\n"
                      "UdpGso = false\n"
                      "UdpGro = false\n"
                      "TunOffload = false\n"
                      "TunGro = false\n";
    /* NOTE: [Auth] Key is INI-only dual-write (auth_key + server_auth_key);
     * mirror it in JSON by setting BOTH json keys to the same value. */
    const char *ini_auth_extra = "[Auth]\nKey = parity-secret\n";
    const char *json = "{"
                       "\"tun_name\":\"tparity0\","
                       "\"listen\":\"192.0.2.1:8443\","
                       "\"subnet\":\"10.99.0.0/24\","
                       "\"subnet6\":\"fd00:beef::/112\","
                       "\"log_level\":\"debug\","
                       "\"kill_switch\":true,"
                       "\"manage_routes\":false,"
                       "\"reconnect\":false,"
                       "\"reconnect_interval\":17,"
                       "\"mtu\":1420,"
                       "\"path_mtu\":1492,"
                       "\"pmtud\":true,"
                       "\"server_addr\":\"vpn.parity.test:4433\","
                       "\"tls_server_name\":\"sni.parity.test\","
                       "\"insecure\":true,"
                       "\"cert_file\":\"/tmp/parity.crt\","
                       "\"key_file\":\"/tmp/parity.key\","
                       "\"auth_key\":\"parity-secret\","
                       "\"server_auth_key\":\"parity-secret\","
                       "\"max_clients\":120,"
                       "\"control_listen\":\"127.0.0.2:9091\","
                       "\"scheduler\":\"min_srtt\","
                       "\"allow_client_scheduler\":true,"
                       "\"request_server_scheduler\":true,"
                       "\"cc\":\"cubic\","
                       "\"init_max_path_id\":16,"
                       "\"reinjection\":\"deadline\","
                       "\"reinjection_srtt_factor_pct\":150,"
                       "\"reinjection_hard_deadline_ms\":300,"
                       "\"reinjection_deadline_lower_bound_ms\":10,"
                       "\"redundant\":true,"
                       "\"reorder\":{"
                       "\"enabled\":true,"
                       "\"max_wait_ms\":55,"
                       "\"cap_packets\":256,"
                       "\"max_bytes_per_flow\":5000000,"
                       "\"classify_window\":33,"
                       "\"ack_demote_max_large\":7,"
                       "\"small_packet_threshold\":333,"
                       "\"reset_mark_packets\":9,"
                       "\"reset_idle_grace_ms\":400,"
                       "\"max_flows\":77,"
                       "\"global_max_bytes\":9000000,"
                       "\"ingress_idle_sec\":11,"
                       "\"egress_idle_sec\":22"
                       "},"
                       "\"hybrid\":{"
                       "\"enabled\":true,"
                       "\"tcp\":\"raw\","
                       "\"tcp_max_flows\":128,"
                       "\"tcp_idle_timeout_sec\":60,"
                       "\"tcp_connect_timeout_sec\":20,"
                       "\"tcp_max_global_flows\":8192"
                       "},"
                       "\"advanced\":{"
                       "\"recv_rate_limit\":77,"
                       "\"udp_gso\":false,"
                       "\"udp_gro\":false,"
                       "\"tun_offload\":false,"
                       "\"tun_gro\":false"
                       "}"
                       "}";

    mqvpn_file_config_t a, b;

    /* INI side: concat base + auth extra into one temp file. */
    char ini_full[4096];
    snprintf(ini_full, sizeof(ini_full), "%s%s", ini, ini_auth_extra);
    char *path = write_tmp(ini_full);
    mqvpn_config_defaults(&a);
    int rc = mqvpn_config_load(&a, path);
    unlink(path);
    ASSERT_EQ_INT(rc, 0, "parity ini load ok");

    mqvpn_config_defaults(&b);
    rc = mqvpn_config_load_json_filecfg(&b, json);
    ASSERT_EQ_INT(rc, 0, "parity json load ok");

    /* Spot asserts first — memcmp failure alone is undebuggable. */
    ASSERT_EQ_STR(a.tun_name, b.tun_name, "parity tun_name");
    ASSERT_EQ_INT(a.is_server, b.is_server, "parity is_server");
    ASSERT_EQ_INT(a.tun_mtu, b.tun_mtu, "parity mtu");
    ASSERT_EQ_INT(a.path_mtu, b.path_mtu, "parity path_mtu");
    ASSERT_EQ_INT(a.pmtud, b.pmtud, "parity pmtud");
    ASSERT_EQ_INT(a.max_clients, b.max_clients, "parity max_clients");
    ASSERT_EQ_INT((int)a.init_max_path_id, (int)b.init_max_path_id,
                  "parity init_max_path_id");
    ASSERT_EQ_STR(a.reinjection, b.reinjection, "parity reinjection");
    ASSERT_EQ_INT(a.reinjection_srtt_factor_pct, b.reinjection_srtt_factor_pct,
                  "parity reinjection_srtt_factor_pct");
    ASSERT_EQ_INT(a.reinjection_hard_deadline_ms, b.reinjection_hard_deadline_ms,
                  "parity reinjection_hard_deadline_ms");
    ASSERT_EQ_INT(a.reinjection_deadline_lower_bound_ms,
                  b.reinjection_deadline_lower_bound_ms,
                  "parity reinjection_deadline_lower_bound_ms");
    ASSERT_EQ_INT(a.redundant, 1, "parity ini redundant");
    ASSERT_EQ_INT(b.redundant, 1, "parity json redundant");
    ASSERT_EQ_STR(a.auth_key, b.auth_key, "parity auth_key");
    ASSERT_EQ_STR(a.server_auth_key, b.server_auth_key, "parity server_auth_key");
    ASSERT_EQ_INT(a.reorder.mode, b.reorder.mode, "parity reorder mode");
    ASSERT_EQ_INT((int)a.reorder.max_wait_ms, (int)b.reorder.max_wait_ms,
                  "parity reorder max_wait_ms");
    ASSERT_EQ_INT(a.reorder.has_explicit_wait, b.reorder.has_explicit_wait,
                  "parity has_explicit_wait");
    ASSERT_EQ_INT(a.reorder.has_explicit_cap, b.reorder.has_explicit_cap,
                  "parity has_explicit_cap");
    ASSERT_EQ_INT((int)a.reorder.classify_window, (int)b.reorder.classify_window,
                  "parity classify_window");
    ASSERT_EQ_INT(a.allow_client_scheduler, 1, "parity ini allow_client_scheduler");
    ASSERT_EQ_INT(a.request_server_scheduler, 1, "parity ini request_server_scheduler");
    ASSERT_EQ_INT(a.allow_client_scheduler, b.allow_client_scheduler,
                  "parity allow_client_scheduler");
    ASSERT_EQ_INT(a.request_server_scheduler, b.request_server_scheduler,
                  "parity request_server_scheduler");
    ASSERT_EQ_INT(a.hybrid.enabled, b.hybrid.enabled, "parity hybrid enabled");
    ASSERT_EQ_INT(a.hybrid.tcp_mode, b.hybrid.tcp_mode, "parity hybrid tcp_mode");
    ASSERT_EQ_INT((int)a.hybrid.tcp_max_flows, (int)b.hybrid.tcp_max_flows,
                  "parity hybrid tcp_max_flows");
    ASSERT_EQ_INT((int)a.hybrid.tcp_idle_timeout_sec, (int)b.hybrid.tcp_idle_timeout_sec,
                  "parity hybrid tcp_idle_timeout_sec");
    ASSERT_EQ_INT((int)a.hybrid.tcp_connect_timeout_sec,
                  (int)b.hybrid.tcp_connect_timeout_sec,
                  "parity hybrid tcp_connect_timeout_sec");
    ASSERT_EQ_INT((int)a.hybrid.tcp_max_global_flows, (int)b.hybrid.tcp_max_global_flows,
                  "parity hybrid tcp_max_global_flows");
    ASSERT_EQ_INT((int)a.recv_rate_limit, (int)b.recv_rate_limit,
                  "parity advanced recv_rate_limit");
    ASSERT_EQ_INT(a.udp_gso, b.udp_gso, "parity advanced udp_gso");
    ASSERT_EQ_INT(a.udp_gro, b.udp_gro, "parity advanced udp_gro");
    ASSERT_EQ_INT(a.tun_offload, b.tun_offload, "parity advanced tun_offload");
    ASSERT_EQ_INT(a.tun_gro, b.tun_gro, "parity advanced tun_gro");

    /* Non-default guards: prove these asserts pass because the value was
     * actually parsed, not because it silently failed to parse on BOTH
     * sides and both structs just kept the (equal) default. */
    ASSERT_EQ_INT(a.tun_mtu, 1420, "parity mtu is non-default");
    ASSERT_EQ_INT(a.path_mtu, 1492, "parity path_mtu is non-default");
    ASSERT_EQ_INT(a.pmtud, 1, "parity pmtud is non-default");
    ASSERT_EQ_STR(a.reinjection, "deadline", "parity reinjection is non-default");
    ASSERT_EQ_INT(a.reinjection_srtt_factor_pct, 150,
                  "parity reinjection_srtt_factor_pct is non-default");
    ASSERT_EQ_INT(a.reinjection_hard_deadline_ms, 300,
                  "parity reinjection_hard_deadline_ms is non-default");
    ASSERT_EQ_INT(a.reinjection_deadline_lower_bound_ms, 10,
                  "parity reinjection_deadline_lower_bound_ms is non-default");
    ASSERT_EQ_INT((int)a.reorder.max_flows, 77,
                  "parity reorder max_flows is non-default");
    ASSERT_EQ_INT((int)a.reorder.classify_window, 33,
                  "parity classify_window is non-default");
    ASSERT_EQ_INT((int)a.reorder.small_packet_threshold_bytes, 333,
                  "guard small_packet_threshold parsed");
    ASSERT_EQ_INT(a.hybrid.tcp_mode, MQVPN_HYBRID_TCP_RAW,
                  "parity hybrid tcp_mode is non-default");
    ASSERT_EQ_INT((int)a.hybrid.tcp_max_flows, 128,
                  "parity hybrid tcp_max_flows is non-default");
    ASSERT_EQ_INT((int)a.hybrid.tcp_connect_timeout_sec, 20,
                  "parity hybrid tcp_connect_timeout_sec is non-default");
    ASSERT_EQ_INT((int)a.hybrid.tcp_max_global_flows, 8192,
                  "parity hybrid tcp_max_global_flows is non-default");
    ASSERT_EQ_INT((int)a.recv_rate_limit, 77,
                  "parity advanced recv_rate_limit is non-default");
    ASSERT_EQ_INT(a.udp_gso, 0, "parity advanced udp_gso is non-default");
    ASSERT_EQ_INT(a.udp_gro, 0, "parity advanced udp_gro is non-default");
    ASSERT_EQ_INT(a.tun_offload, 0, "parity advanced tun_offload is non-default");
    ASSERT_EQ_INT(a.tun_gro, 0, "parity advanced tun_gro is non-default");

    /* Both structs were memset by mqvpn_config_defaults → padding is zero
     * → whole-struct compare is deterministic. */
    ASSERT_EQ_INT(memcmp(&a, &b, sizeof(a)), 0, "parity full-struct memcmp");
}

static void
test_ini_json_invalid_scalar_parity(void)
{
    /* Invalid values must leave the same struct outcome on both surfaces.
     * (Warnings differ historically; only the resulting struct is pinned.)
     * Every INI load must return 0: invalid scalars warn-and-continue, they
     * never fail the load. */
    mqvpn_file_config_t a, b;
    int rc;

    /* MTU out of range → keep default (0) on both sides */
    char *p = write_tmp("[Interface]\nMTU = 100\n");
    mqvpn_config_defaults(&a);
    rc = mqvpn_config_load(&a, p);
    unlink(p);
    ASSERT_EQ_INT(rc, 0, "invalid mtu ini load rc 0");
    mqvpn_config_defaults(&b);
    mqvpn_config_load_json_filecfg(&b, "{\"mtu\":100}");
    ASSERT_EQ_INT(a.tun_mtu, 0, "invalid mtu ini keeps default");
    ASSERT_EQ_INT(b.tun_mtu, 0, "invalid mtu json keeps default");

    /* MaxClients invalid → 64 on both sides */
    p = write_tmp("[Auth]\nMaxClients = -3\n");
    mqvpn_config_defaults(&a);
    rc = mqvpn_config_load(&a, p);
    unlink(p);
    ASSERT_EQ_INT(rc, 0, "invalid max_clients ini load rc 0");
    mqvpn_config_defaults(&b);
    mqvpn_config_load_json_filecfg(&b, "{\"max_clients\":-3}");
    ASSERT_EQ_INT(a.max_clients, 64, "invalid max_clients ini -> 64");
    ASSERT_EQ_INT(b.max_clients, 64, "invalid max_clients json -> 64");

    /* MaxClients PARSE-FAIL → 64 on both sides. NOTE: on the JSON side this
     * passes against pre-refactor code for a coincidental reason (old code
     * silently skips the write and the default happens to be 64); after A3
     * the table writes the 64 fallback explicitly + warns (accepted
     * deviation (2) in the plan background). The struct outcome is pinned
     * either way, so this block stays in the A1 listing unconditionally. */
    p = write_tmp("[Auth]\nMaxClients = abc\n");
    mqvpn_config_defaults(&a);
    rc = mqvpn_config_load(&a, p);
    unlink(p);
    ASSERT_EQ_INT(rc, 0, "parse-fail max_clients ini load rc 0");
    mqvpn_config_defaults(&b);
    mqvpn_config_load_json_filecfg(&b, "{\"max_clients\":\"abc\"}");
    ASSERT_EQ_INT(a.max_clients, 64, "parse-fail max_clients ini -> 64");
    ASSERT_EQ_INT(b.max_clients, 64, "parse-fail max_clients json -> 64");

    /* InitMaxPathId over bound → keep default 0 on both sides */
    p = write_tmp("[Multipath]\nInitMaxPathId = 129\n");
    mqvpn_config_defaults(&a);
    rc = mqvpn_config_load(&a, p);
    unlink(p);
    ASSERT_EQ_INT(rc, 0, "over-bound impid ini load rc 0");
    mqvpn_config_defaults(&b);
    mqvpn_config_load_json_filecfg(&b, "{\"init_max_path_id\":129}");
    ASSERT_EQ_INT((int)a.init_max_path_id, 0, "over-bound impid ini keeps 0");
    ASSERT_EQ_INT((int)b.init_max_path_id, 0, "over-bound impid json keeps 0");

    /* Reorder u16 over 0xffff → keep default on both sides */
    p = write_tmp("[Reorder]\nClassifyWindow = 70000\n");
    mqvpn_config_defaults(&a);
    rc = mqvpn_config_load(&a, p);
    unlink(p);
    ASSERT_EQ_INT(rc, 0, "over-bound classify_window ini load rc 0");
    mqvpn_config_defaults(&b);
    mqvpn_config_load_json_filecfg(&b, "{\"reorder\":{\"classify_window\":70000}}");
    ASSERT_EQ_INT((int)a.reorder.classify_window, (int)b.reorder.classify_window,
                  "over-bound classify_window parity");

    /* Reorder u32 in (2^31, 2^32) must parse on BOTH sides (deb2115 pin) */
    p = write_tmp("[Reorder]\nMaxFlows = 3000000000\n");
    mqvpn_config_defaults(&a);
    rc = mqvpn_config_load(&a, p);
    unlink(p);
    ASSERT_EQ_INT(rc, 0, "u32 high ini load rc 0");
    mqvpn_config_defaults(&b);
    mqvpn_config_load_json_filecfg(&b, "{\"reorder\":{\"max_flows\":3000000000}}");
    ASSERT_EQ_INT(a.reorder.max_flows == 3000000000u, 1, "u32 high ini");
    ASSERT_EQ_INT(b.reorder.max_flows == 3000000000u, 1, "u32 high json");

    /* Hybrid Tcp invalid → warn and fall back to default AUTO on both sides
     * (mirrors the reorder Enabled= invalid handling: value ignored). */
    p = write_tmp("[Hybrid]\nTcp = bogus\n");
    mqvpn_config_defaults(&a);
    rc = mqvpn_config_load(&a, p);
    unlink(p);
    ASSERT_EQ_INT(rc, 0, "invalid hybrid tcp ini load rc 0");
    mqvpn_config_defaults(&b);
    mqvpn_config_load_json_filecfg(&b, "{\"hybrid\":{\"tcp\":\"bogus\"}}");
    ASSERT_EQ_INT(a.hybrid.tcp_mode, MQVPN_HYBRID_TCP_AUTO,
                  "invalid hybrid tcp ini falls back to auto");
    ASSERT_EQ_INT(b.hybrid.tcp_mode, MQVPN_HYBRID_TCP_AUTO,
                  "invalid hybrid tcp json falls back to auto");
}

/* Table-driven round-trip test over MQVPN_SCHED_LIST / MQVPN_CC_LIST
 * (src/mqvpn_sched_names.h): every row must survive from_name(name) ==
 * enum and to_name(enum) == name. This is the mechanical parity check the
 * X-macro table exists for — a future row addition/removal is exercised
 * here automatically without editing this test. */
static void
test_sched_cc_name_roundtrip(void)
{
#define MQVPN_SCHED_ROUNDTRIP_CHECK(enum_val, str)                                     \
    ASSERT_EQ_INT(mqvpn_sched_from_name(str), (int)(enum_val),                         \
                  "sched from_name(" str ") == " #enum_val);                           \
    ASSERT_EQ_STR(mqvpn_sched_to_name(enum_val), str, "sched to_name(" #enum_val ")"); \
    ASSERT_TRUE(mqvpn_sched_is_valid(enum_val), "sched is_valid(" #enum_val ")");
    MQVPN_SCHED_LIST(MQVPN_SCHED_ROUNDTRIP_CHECK)
#undef MQVPN_SCHED_ROUNDTRIP_CHECK

#define MQVPN_CC_ROUNDTRIP_CHECK(enum_val, str)                                  \
    ASSERT_EQ_INT(mqvpn_cc_from_name(str), (int)(enum_val),                      \
                  "cc from_name(" str ") == " #enum_val);                        \
    ASSERT_EQ_STR(mqvpn_cc_to_name(enum_val), str, "cc to_name(" #enum_val ")"); \
    ASSERT_TRUE(mqvpn_cc_is_valid(enum_val), "cc is_valid(" #enum_val ")");
    MQVPN_CC_LIST(MQVPN_CC_ROUNDTRIP_CHECK)
#undef MQVPN_CC_ROUNDTRIP_CHECK

#define MQVPN_REINJ_ROUNDTRIP_CHECK(enum_val, str)                                     \
    ASSERT_EQ_INT(mqvpn_reinj_from_name(str), (int)(enum_val),                         \
                  "reinj from_name(" str ") == " #enum_val);                           \
    ASSERT_EQ_STR(mqvpn_reinj_to_name(enum_val), str, "reinj to_name(" #enum_val ")"); \
    ASSERT_TRUE(mqvpn_reinj_is_valid(enum_val), "reinj is_valid(" #enum_val ")");
    MQVPN_REINJ_LIST(MQVPN_REINJ_ROUNDTRIP_CHECK)
#undef MQVPN_REINJ_ROUNDTRIP_CHECK

    /* Unrecognized strings must be rejected by both tables. */
    ASSERT_EQ_INT(mqvpn_sched_from_name("bogus"), -1, "sched from_name(bogus)");
    ASSERT_EQ_INT(mqvpn_sched_from_name(NULL), -1, "sched from_name(NULL)");
    ASSERT_EQ_INT(mqvpn_cc_from_name("bogus"), -1, "cc from_name(bogus)");
    ASSERT_EQ_INT(mqvpn_cc_from_name(NULL), -1, "cc from_name(NULL)");
    ASSERT_EQ_INT(mqvpn_reinj_from_name("bogus"), -1, "reinj from_name(bogus)");
    ASSERT_EQ_INT(mqvpn_reinj_from_name(NULL), -1, "reinj from_name(NULL)");
    ASSERT_EQ_INT(mqvpn_reinj_from_name("dgram"), -1, "reinj from_name(dgram)");
}

int
main(void)
{
    test_defaults();
    test_file_encoding();
    test_physical_line_numbers();
    test_host_port_strict();
    test_username_length();
    test_parse_server_config();
    test_parse_client_config();
    test_parse_scheduler_backup_fec();
    test_parse_scheduler_wlb_udp_pin();
    test_parse_cc_ini();
    test_parse_cc_json();
    test_parse_init_max_path_id_bounds();
    test_parse_init_max_path_id_json_bounds();
    test_comments_whitespace();
    test_unknown_key_warns();
    test_missing_file_error();
    test_path_accumulation();
    test_backup_path_ini();
    test_backup_paths_json();
    test_dns_comma_split();
    test_boolean_parsing();
    test_mode_detection();
    test_empty_file();
    test_malformed_section_header();
    test_malformed_line_no_equals();
    test_key_outside_section();
    test_max_paths_exceeded();
    test_max_paths_exceeded_json();
    test_max_clients_edge_cases();
    test_parse_reinjection_config();
    test_reinjection_out_of_range_falls_back();
    test_empty_value();
    test_duplicate_keys_last_wins();
    test_case_insensitive_section();
    test_unknown_section();
    test_dns_empty_entries();
    test_semicolon_comment();

    /* kill switch tests */
    test_killswitch_default_off();
    test_killswitch_config_parse();
    test_killswitch_config_false();

    /* manage_routes tests */
    test_manage_routes_default_on();
    test_manage_routes_ini_false();

    /* reconnect tests */
    test_reconnect_defaults();
    test_reconnect_config_parse();
    test_reconnect_config_true();
    test_reconnect_interval_invalid();
    test_reconnect_interval_invalid_string();

    /* MTU tests */
    test_mtu_default();
    test_mtu_config_parse();
    test_mtu_below_floor_ignored();
    test_mtu_above_ceiling_ignored();
    test_mtu_invalid_string_ignored();
    test_mtu_json_parse();
    test_path_mtu_parse();
    test_pmtud_parse();

    /* subnet6 tests */
    test_subnet6_default();
    test_subnet6_config_parse();
    test_subnet6_various_prefixes();
    test_subnet6_whitespace_trimmed();
    test_subnet6_not_set();
    test_subnet6_duplicate_last_wins();
    test_auth_users_ini();
    test_auth_users_ini_invalid_ignored();
    test_json_config_load();
    test_json_client_config_load();
    test_parse_json_scheduler_wlb_udp_pin();
    test_json_duplicate_users_last_wins();
    test_json_invalid_users_error();
    test_json_users_brace_in_string_value();
    test_json_users_escaped_quote_in_value();

    /* buffer boundary and edge case tests */
    test_tun_name_max_length();
    test_dns_exceeds_max();
    test_reconnect_interval_overflow();
    test_value_contains_equals();

    /* [Control] section tests */
    test_parse_control_section();
    test_parse_control_absent();
    test_parse_control_json();
    test_parse_control_unknown_key();

    /* mqvpn_resolve_control_endpoint helper tests */
    test_resolve_ini_only();
    test_resolve_cli_port_overrides();
    test_resolve_cli_addr_overrides();
    test_resolve_explicit_disable();
    test_resolve_no_input();
    test_resolve_malformed_ini();
    test_resolve_trailing_garbage_port();
    test_resolve_port_leading_junk();

    /* [Hybrid] section tests */
    test_hybrid_defaults_when_absent();
    test_hybrid_section_parse();
    test_advanced_recv_rate_limit();
    test_advanced_udp_gso();
    test_advanced_udp_gro();
    test_advanced_tun_offload();
    test_hybrid_egress_acl_ini();
    test_hybrid_egress_acl_ini_invalid_ignored();
    test_hybrid_egress_acl_ini_v6();
    test_hybrid_egress_acl_json();

    /* INI/JSON scalar-key parity */
    test_ini_json_scalar_parity();
    test_redundant_ports_ini_json();
    test_redundant_ini_bool();
    test_json_bool_strict();
    test_ini_json_invalid_scalar_parity();

    /* JSON parser strictness */
    test_json_syntax_error_fails();
    test_json_file_raw_nul_fails();
    test_json_nested_key_not_lifted();
    test_json_duplicate_key_first_wins();
    test_json_numeric_type_strict();
    test_json_string_decoding();
    test_json_users_shapes();
    test_json_dns_paths_atomic();
    test_json_reorder_rules_types();

    /* mqvpn_sched_names.h table parity */
    test_sched_cc_name_roundtrip();

    printf("\n=== test_config: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
