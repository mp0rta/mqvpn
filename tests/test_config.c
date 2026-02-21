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

#define ASSERT_EQ_INT(a, b, msg) do { \
    if ((a) == (b)) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL [%s]: %d != %d\n", msg, (int)(a), (int)(b)); } \
} while(0)

#define ASSERT_EQ_STR(a, b, msg) do { \
    if (strcmp((a), (b)) == 0) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL [%s]: '%s' != '%s'\n", msg, (a), (b)); } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL [%s]\n", msg); } \
} while(0)

/* Helper: write string to a temp file and return path */
static char *write_tmp(const char *content)
{
    static char path[256];
    snprintf(path, sizeof(path), "/tmp/test_config_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); return NULL; }
    write(fd, content, strlen(content));
    close(fd);
    return path;
}

/* ---- Tests ---- */

static void test_defaults(void)
{
    mqvpn_config_t cfg;
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

static void test_parse_server_config(void)
{
    const char *ini =
        "[Interface]\n"
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
    mqvpn_config_t cfg;
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

static void test_parse_client_config(void)
{
    const char *ini =
        "[Server]\n"
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
    mqvpn_config_t cfg;
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

static void test_comments_whitespace(void)
{
    const char *ini =
        "# This is a comment\n"
        "; This is also a comment\n"
        "\n"
        "   [Interface]   \n"
        "  TunName   =   my-tun   \n"
        "  # inline not supported, just full-line\n"
        "\n";

    char *path = write_tmp(ini);
    mqvpn_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "comment/whitespace parse ok");
    ASSERT_EQ_STR(cfg.tun_name, "my-tun", "tun_name trimmed");
}

static void test_unknown_key_warns(void)
{
    const char *ini =
        "[Interface]\n"
        "TunName = test\n"
        "UnknownKey = somevalue\n";

    char *path = write_tmp(ini);
    mqvpn_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    /* Should succeed (unknown keys are warned, not errors) */
    ASSERT_EQ_INT(rc, 0, "unknown key no error");
    ASSERT_EQ_STR(cfg.tun_name, "test", "known key still parsed");
}

static void test_missing_file_error(void)
{
    mqvpn_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, "/tmp/nonexistent_config_file_12345.conf");

    ASSERT_TRUE(rc != 0, "missing file returns error");
}

static void test_path_accumulation(void)
{
    const char *ini =
        "[Multipath]\n"
        "Path = eth0\n"
        "Path = wlan0\n"
        "Path = usb0\n"
        "Path = lte0\n";

    char *path = write_tmp(ini);
    mqvpn_config_t cfg;
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

static void test_dns_comma_split(void)
{
    const char *ini =
        "[Interface]\n"
        "DNS = 1.1.1.1,8.8.8.8, 9.9.9.9 ,  208.67.222.222  \n";

    char *path = write_tmp(ini);
    mqvpn_config_t cfg;
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

static void test_boolean_parsing(void)
{
    /* Test various boolean representations */
    const char *ini_true =
        "[Server]\n"
        "Address = host:443\n"
        "Insecure = true\n";

    char *path = write_tmp(ini_true);
    mqvpn_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.insecure, 1, "insecure=true");

    const char *ini_yes =
        "[Server]\n"
        "Address = host:443\n"
        "Insecure = yes\n";

    path = write_tmp(ini_yes);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.insecure, 1, "insecure=yes");

    const char *ini_one =
        "[Server]\n"
        "Address = host:443\n"
        "Insecure = 1\n";

    path = write_tmp(ini_one);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.insecure, 1, "insecure=1");

    const char *ini_false =
        "[Server]\n"
        "Address = host:443\n"
        "Insecure = false\n";

    path = write_tmp(ini_false);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.insecure, 0, "insecure=false");
}

static void test_mode_detection(void)
{
    /* Server: has [Interface] Listen → is_server=1 */
    const char *ini_server =
        "[Interface]\n"
        "Listen = 0.0.0.0:443\n";

    char *path = write_tmp(ini_server);
    mqvpn_config_t cfg;
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.is_server, 1, "Listen → server mode");

    /* Client: has [Server] Address → is_server=0 */
    const char *ini_client =
        "[Server]\n"
        "Address = host:443\n";

    path = write_tmp(ini_client);
    mqvpn_config_defaults(&cfg);
    mqvpn_config_load(&cfg, path);
    unlink(path);
    ASSERT_EQ_INT(cfg.is_server, 0, "Address → client mode");
}

static void test_empty_file(void)
{
    const char *ini = "\n\n\n";
    char *path = write_tmp(ini);
    mqvpn_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    unlink(path);

    ASSERT_EQ_INT(rc, 0, "empty file ok");
}

int main(void)
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

    printf("\n=== test_config: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
