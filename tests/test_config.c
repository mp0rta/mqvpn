/*
 * test_config.c — unit tests for INI config parser
 *
 * Build: cc -o tests/test_config tests/test_config.c src/config.c src/log.c -Isrc
 */
#include "config.h"
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

    const char *ini_yes = "[Server]\n"
                          "Address = host:443\n"
                          "Insecure = yes\n";

    path = write_tmp(ini_yes);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.insecure, 1, "insecure=yes");

    const char *ini_one = "[Server]\n"
                          "Address = host:443\n"
                          "Insecure = 1\n";

    path = write_tmp(ini_one);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.insecure, 1, "insecure=1");

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
    /* 5th path should be ignored (max 4) */
    const char *ini = "[Multipath]\n"
                      "Path = eth0\n"
                      "Path = eth1\n"
                      "Path = eth2\n"
                      "Path = eth3\n"
                      "Path = eth4\n";

    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "max paths exceeded no error");
    ASSERT_EQ_INT(cfg.n_paths, 4, "capped at 4 paths");
    ASSERT_EQ_STR(cfg.paths[3], "eth3", "4th path is eth3");
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

    /* MaxClients = abc → atoi returns 0 → fallback to 64 */
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
                       "\"auth_key\":\"client-key\","
                       "\"insecure\":true,"
                       "\"tun_name\":\"mqvpn7\","
                       "\"log_level\":\"debug\","
                       "\"dns\":[\"1.1.1.1\",\"8.8.8.8\"],"
                       "\"paths\":[\"eth0\",\"wlan0\"],"
                       "\"reconnect\":false,"
                       "\"reconnect_interval\":9,"
                       "\"kill_switch\":true,"
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
    ASSERT_EQ_STR(cfg.scheduler, "minrtt", "json client scheduler");
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
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_TRUE(rc != 0, "json invalid users returns error");
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
    /* atoi(999999999) succeeds and v > 0, so it's stored as-is */
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

int
main(void)
{
    test_defaults();
    test_parse_server_config();
    test_parse_client_config();
    test_comments_whitespace();
    test_unknown_key_warns();
    test_missing_file_error();
    test_path_accumulation();
    test_dns_comma_split();
    test_boolean_parsing();
    test_mode_detection();
    test_empty_file();
    test_malformed_section_header();
    test_malformed_line_no_equals();
    test_key_outside_section();
    test_max_paths_exceeded();
    test_max_clients_edge_cases();
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

    /* reconnect tests */
    test_reconnect_defaults();
    test_reconnect_config_parse();
    test_reconnect_config_true();
    test_reconnect_interval_invalid();

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
    test_json_duplicate_users_last_wins();
    test_json_invalid_users_error();

    /* buffer boundary and edge case tests */
    test_tun_name_max_length();
    test_dns_exceeds_max();
    test_reconnect_interval_overflow();
    test_value_contains_equals();

    printf("\n=== test_config: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
