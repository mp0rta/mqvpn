/*
 * test_dns.c — unit tests for DNS resolv.conf management
 *
 * Uses temp files so no root access needed.
 *
 * Build: cc -o tests/test_dns tests/test_dns.c src/dns.c src/log.c -Isrc
 */
#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <arpa/inet.h>

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

/* Read entire file into buf. Returns length or -1. */
static int read_file(const char *path, char *buf, size_t bufsize)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    size_t n = fread(buf, 1, bufsize - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return (int)n;
}

/* Write string to file */
static void write_file(const char *path, const char *content)
{
    FILE *fp = fopen(path, "w");
    if (fp) {
        fputs(content, fp);
        fclose(fp);
    }
}

static void test_init(void)
{
    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);

    ASSERT_EQ_INT(dns.n_servers, 0, "init n_servers");
    ASSERT_EQ_INT(dns.active, 0, "init active");
}

static void test_add_server(void)
{
    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);

    ASSERT_EQ_INT(mqvpn_dns_add_server(&dns, "1.1.1.1"), 0, "add 1st server");
    ASSERT_EQ_INT(dns.n_servers, 1, "1 server");
    ASSERT_EQ_STR(dns.servers[0], "1.1.1.1", "server[0]");

    ASSERT_EQ_INT(mqvpn_dns_add_server(&dns, "8.8.8.8"), 0, "add 2nd server");
    ASSERT_EQ_INT(dns.n_servers, 2, "2 servers");
    ASSERT_EQ_STR(dns.servers[1], "8.8.8.8", "server[1]");
}

static void test_add_server_max(void)
{
    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);

    for (int i = 0; i < 4; i++) {
        char addr[16];
        snprintf(addr, sizeof(addr), "1.0.0.%d", i + 1);
        ASSERT_EQ_INT(mqvpn_dns_add_server(&dns, addr), 0, "add server");
    }
    ASSERT_EQ_INT(dns.n_servers, 4, "4 servers");

    /* 5th should fail */
    ASSERT_TRUE(mqvpn_dns_add_server(&dns, "1.0.0.5") != 0,
                "5th server rejected");
}

static void test_apply_and_restore(void)
{
    /* Use temp files for resolv.conf and backup */
    char resolv_path[] = "/tmp/test_dns_resolv_XXXXXX";
    char backup_path[] = "/tmp/test_dns_backup_XXXXXX";
    int fd1 = mkstemp(resolv_path);
    int fd2 = mkstemp(backup_path);
    close(fd1);
    close(fd2);
    /* Remove the backup file so apply() creates it fresh */
    unlink(backup_path);

    /* Write original resolv.conf */
    const char *original = "nameserver 192.168.1.1\nsearch local\n";
    write_file(resolv_path, original);

    char lock_path[] = "/tmp/test_dns_lock_XXXXXX";
    int fd3 = mkstemp(lock_path);
    close(fd3);
    unlink(lock_path);

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.resolv_path = resolv_path;
    dns.backup_path = backup_path;
    dns.lock_path   = lock_path;
    mqvpn_dns_add_server(&dns, "1.1.1.1");
    mqvpn_dns_add_server(&dns, "8.8.8.8");

    /* Apply */
    ASSERT_EQ_INT(mqvpn_dns_apply(&dns), 0, "apply ok");
    ASSERT_EQ_INT(dns.active, 1, "active after apply");
    ASSERT_TRUE(dns.lock_fd >= 0, "lock fd acquired");

    /* Check resolv.conf was replaced */
    char buf[512];
    read_file(resolv_path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "nameserver 1.1.1.1") != NULL,
                "resolv contains 1.1.1.1");
    ASSERT_TRUE(strstr(buf, "nameserver 8.8.8.8") != NULL,
                "resolv contains 8.8.8.8");
    ASSERT_TRUE(strstr(buf, "mqvpn") != NULL,
                "resolv has mqvpn marker");

    /* Check backup was created with original content */
    read_file(backup_path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "192.168.1.1") != NULL,
                "backup contains original nameserver");

    /* Restore */
    mqvpn_dns_restore(&dns);
    ASSERT_EQ_INT(dns.active, 0, "inactive after restore");
    ASSERT_EQ_INT(dns.lock_fd, -1, "lock fd released after restore");

    /* Check resolv.conf was restored */
    read_file(resolv_path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "192.168.1.1") != NULL,
                "restored resolv contains original");

    unlink(resolv_path);
    unlink(backup_path);
    unlink(lock_path);
}

static void test_no_servers_no_apply(void)
{
    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.resolv_path = "/tmp/test_dns_nonexistent";
    dns.backup_path = "/tmp/test_dns_backup_nonexistent";

    /* No servers added → apply should return 0 but not modify anything */
    ASSERT_EQ_INT(mqvpn_dns_apply(&dns), 0, "apply with no servers ok");
    ASSERT_EQ_INT(dns.active, 0, "not active when no servers");
}

static void test_restore_without_apply(void)
{
    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);

    /* Restore should be a no-op when not active */
    mqvpn_dns_restore(&dns);
    ASSERT_EQ_INT(dns.active, 0, "restore no-op when not active");
}

static void test_stale_backup_detection(void)
{
    char resolv_path[] = "/tmp/test_dns_resolv2_XXXXXX";
    char backup_path[] = "/tmp/test_dns_backup2_XXXXXX";
    int fd1 = mkstemp(resolv_path);
    int fd2 = mkstemp(backup_path);
    close(fd1);
    close(fd2);

    /* Write stale backup (simulating crash) */
    write_file(backup_path, "nameserver 10.0.0.1\n");
    write_file(resolv_path, "# mqvpn DNS\nnameserver 1.1.1.1\n");

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.resolv_path = resolv_path;
    dns.backup_path = backup_path;

    /* Check stale backup exists */
    ASSERT_TRUE(mqvpn_dns_has_stale_backup(&dns),
                "stale backup detected");

    /* Restore from stale backup */
    mqvpn_dns_restore_stale(&dns);

    /* Check resolv.conf was restored */
    char buf[512];
    read_file(resolv_path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "10.0.0.1") != NULL,
                "stale restore successful");

    unlink(resolv_path);
    unlink(backup_path);
}

static void test_lock_contention(void)
{
    char resolv_path[] = "/tmp/test_dns_resolv3_XXXXXX";
    char backup_path[] = "/tmp/test_dns_backup3_XXXXXX";
    char lock_path[]   = "/tmp/test_dns_lock3_XXXXXX";
    int fd1 = mkstemp(resolv_path); close(fd1);
    int fd2 = mkstemp(backup_path); close(fd2); unlink(backup_path);
    int fd3 = mkstemp(lock_path);   close(fd3); unlink(lock_path);

    write_file(resolv_path, "nameserver 192.168.1.1\n");

    /* First instance acquires lock */
    mqvpn_dns_t dns1;
    mqvpn_dns_init(&dns1);
    dns1.resolv_path = resolv_path;
    dns1.backup_path = backup_path;
    dns1.lock_path   = lock_path;
    mqvpn_dns_add_server(&dns1, "1.1.1.1");
    ASSERT_EQ_INT(mqvpn_dns_apply(&dns1), 0, "1st instance apply ok");

    /* Second instance should fail to acquire lock */
    mqvpn_dns_t dns2;
    mqvpn_dns_init(&dns2);
    dns2.resolv_path = resolv_path;
    dns2.backup_path = backup_path;
    dns2.lock_path   = lock_path;
    mqvpn_dns_add_server(&dns2, "8.8.8.8");
    ASSERT_TRUE(mqvpn_dns_apply(&dns2) != 0, "2nd instance blocked by lock");
    ASSERT_EQ_INT(dns2.active, 0, "2nd instance not active");

    /* Release first instance */
    mqvpn_dns_restore(&dns1);

    /* Now second instance should succeed */
    ASSERT_EQ_INT(mqvpn_dns_apply(&dns2), 0, "2nd instance apply after release");
    mqvpn_dns_restore(&dns2);

    unlink(resolv_path);
    unlink(backup_path);
    unlink(lock_path);
}

static void test_apply_fopen_fail_releases_lock(void)
{
    /* apply() fails at fopen(resolv_path, "w") → lock must be released */
    char lock_path[]   = "/tmp/test_dns_lock4_XXXXXX";
    char backup_path[] = "/tmp/test_dns_backup4_XXXXXX";
    int fd = mkstemp(lock_path); close(fd); unlink(lock_path);
    int fd2 = mkstemp(backup_path); close(fd2); unlink(backup_path);

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.resolv_path = "/no/such/directory/resolv.conf";  /* fopen will fail */
    dns.backup_path = backup_path;
    dns.lock_path   = lock_path;
    mqvpn_dns_add_server(&dns, "1.1.1.1");

    /* apply should fail */
    ASSERT_TRUE(mqvpn_dns_apply(&dns) != 0, "apply fails on bad path");
    ASSERT_EQ_INT(dns.active, 0, "not active after failed apply");
    ASSERT_EQ_INT(dns.lock_fd, -1, "lock released after failed apply");

    /* Verify lock is actually free — a second instance should succeed in locking */
    int lfd = open(lock_path, O_CREAT | O_RDWR, 0644);
    if (lfd >= 0) {
        int got_lock = (flock(lfd, LOCK_EX | LOCK_NB) == 0);
        ASSERT_TRUE(got_lock, "lock is free after failed apply");
        close(lfd);
    }

    unlink(lock_path);
    unlink(backup_path);
}

static void test_restore_fail_releases_lock(void)
{
    /* restore() fails at copy_file() → lock must still be released */
    char resolv_path[] = "/tmp/test_dns_resolv5_XXXXXX";
    char backup_path[] = "/tmp/test_dns_backup5_XXXXXX";
    char lock_path[]   = "/tmp/test_dns_lock5_XXXXXX";
    int fd1 = mkstemp(resolv_path); close(fd1);
    int fd2 = mkstemp(backup_path); close(fd2); unlink(backup_path);
    int fd3 = mkstemp(lock_path);   close(fd3); unlink(lock_path);

    write_file(resolv_path, "nameserver 192.168.1.1\n");

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.resolv_path = resolv_path;
    dns.backup_path = backup_path;
    dns.lock_path   = lock_path;
    mqvpn_dns_add_server(&dns, "1.1.1.1");

    /* Apply succeeds */
    ASSERT_EQ_INT(mqvpn_dns_apply(&dns), 0, "apply ok before restore fail test");
    ASSERT_TRUE(dns.lock_fd >= 0, "lock held after apply");

    /* Delete backup to make restore's copy_file() fail */
    unlink(backup_path);

    /* Restore should fail but still release lock */
    mqvpn_dns_restore(&dns);
    ASSERT_EQ_INT(dns.active, 0, "not active after failed restore");
    ASSERT_EQ_INT(dns.lock_fd, -1, "lock released after failed restore");

    /* Verify lock is actually free */
    int lfd = open(lock_path, O_CREAT | O_RDWR, 0644);
    if (lfd >= 0) {
        int got_lock = (flock(lfd, LOCK_EX | LOCK_NB) == 0);
        ASSERT_TRUE(got_lock, "lock is free after failed restore");
        close(lfd);
    }

    unlink(resolv_path);
    unlink(lock_path);
}

static void test_double_apply(void)
{
    /* apply() twice without restore → second should fail (lock held) */
    char resolv_path[] = "/tmp/test_dns_resolv6_XXXXXX";
    char backup_path[] = "/tmp/test_dns_backup6_XXXXXX";
    char lock_path[]   = "/tmp/test_dns_lock6_XXXXXX";
    int fd1 = mkstemp(resolv_path); close(fd1);
    int fd2 = mkstemp(backup_path); close(fd2); unlink(backup_path);
    int fd3 = mkstemp(lock_path);   close(fd3); unlink(lock_path);

    write_file(resolv_path, "nameserver 192.168.1.1\n");

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.resolv_path = resolv_path;
    dns.backup_path = backup_path;
    dns.lock_path   = lock_path;
    mqvpn_dns_add_server(&dns, "1.1.1.1");

    /* First apply succeeds */
    ASSERT_EQ_INT(mqvpn_dns_apply(&dns), 0, "1st apply ok");
    ASSERT_EQ_INT(dns.active, 1, "active after 1st apply");

    /* Second apply on a NEW dns instance should fail due to lock */
    mqvpn_dns_t dns2;
    mqvpn_dns_init(&dns2);
    dns2.resolv_path = resolv_path;
    dns2.backup_path = backup_path;
    dns2.lock_path   = lock_path;
    mqvpn_dns_add_server(&dns2, "8.8.8.8");

    ASSERT_TRUE(mqvpn_dns_apply(&dns2) != 0, "2nd apply fails (lock held)");
    ASSERT_EQ_INT(dns2.active, 0, "2nd instance not active");

    /* Clean up */
    mqvpn_dns_restore(&dns);

    unlink(resolv_path);
    unlink(backup_path);
    unlink(lock_path);
}

static void test_long_server_address(void)
{
    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);

    /* Address near the 64-byte buffer limit */
    char long_addr[70];
    memset(long_addr, 'x', 63);
    long_addr[63] = '\0';

    ASSERT_EQ_INT(mqvpn_dns_add_server(&dns, long_addr), 0,
                  "long address accepted");
    /* Should be truncated to fit buffer */
    ASSERT_TRUE(strlen(dns.servers[0]) <= 63,
                "long address fits in buffer");
}

static void test_no_stale_backup(void)
{
    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.backup_path = "/tmp/test_dns_nonexistent_backup_xyz";

    ASSERT_EQ_INT(mqvpn_dns_has_stale_backup(&dns), 0,
                  "no stale backup when file missing");
}

static void test_restore_stale_noop(void)
{
    /* restore_stale when no backup exists → no-op */
    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.backup_path = "/tmp/test_dns_nonexistent_backup_xyz";
    dns.resolv_path = "/tmp/test_dns_nonexistent_resolv_xyz";

    /* Should not crash */
    mqvpn_dns_restore_stale(&dns);
    ASSERT_EQ_INT(dns.active, 0, "restore_stale noop when no backup");
}

static void test_apply_creates_marker(void)
{
    /* Verify the generated resolv.conf has the mqvpn marker comment */
    char resolv_path[] = "/tmp/test_dns_resolv7_XXXXXX";
    char backup_path[] = "/tmp/test_dns_backup7_XXXXXX";
    char lock_path[]   = "/tmp/test_dns_lock7_XXXXXX";
    int fd1 = mkstemp(resolv_path); close(fd1);
    int fd2 = mkstemp(backup_path); close(fd2); unlink(backup_path);
    int fd3 = mkstemp(lock_path);   close(fd3); unlink(lock_path);

    write_file(resolv_path, "nameserver 192.168.1.1\n");

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.resolv_path = resolv_path;
    dns.backup_path = backup_path;
    dns.lock_path   = lock_path;
    mqvpn_dns_add_server(&dns, "1.1.1.1");
    mqvpn_dns_add_server(&dns, "8.8.8.8");
    mqvpn_dns_add_server(&dns, "9.9.9.9");

    ASSERT_EQ_INT(mqvpn_dns_apply(&dns), 0, "apply for marker test");

    char buf[1024];
    read_file(resolv_path, buf, sizeof(buf));

    /* Should have all 3 nameservers */
    ASSERT_TRUE(strstr(buf, "nameserver 1.1.1.1") != NULL,
                "has 1.1.1.1");
    ASSERT_TRUE(strstr(buf, "nameserver 8.8.8.8") != NULL,
                "has 8.8.8.8");
    ASSERT_TRUE(strstr(buf, "nameserver 9.9.9.9") != NULL,
                "has 9.9.9.9");

    /* Should NOT have the original nameserver */
    ASSERT_TRUE(strstr(buf, "192.168.1.1") == NULL,
                "original nameserver removed");

    /* Backup has original */
    read_file(backup_path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "192.168.1.1") != NULL,
                "backup has original");

    mqvpn_dns_restore(&dns);
    unlink(resolv_path);
    unlink(backup_path);
    unlink(lock_path);
}

static void test_init_defaults(void)
{
    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);

    ASSERT_EQ_INT(dns.lock_fd, -1, "init lock_fd is -1");
    ASSERT_TRUE(strcmp(dns.resolv_path, "/etc/resolv.conf") == 0,
                "init default resolv_path");
    ASSERT_TRUE(strcmp(dns.backup_path, "/etc/resolv.conf.mqvpn.bak") == 0,
                "init default backup_path");
    ASSERT_TRUE(strcmp(dns.lock_path, "/run/mqvpn-dns.lock") == 0,
                "init default lock_path");
}

static void test_add_server_content(void)
{
    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);

    mqvpn_dns_add_server(&dns, "1.1.1.1");
    mqvpn_dns_add_server(&dns, "8.8.8.8");
    mqvpn_dns_add_server(&dns, "9.9.9.9");
    mqvpn_dns_add_server(&dns, "208.67.222.222");

    ASSERT_EQ_INT(dns.n_servers, 4, "4 servers added");
    ASSERT_TRUE(strcmp(dns.servers[0], "1.1.1.1") == 0, "server[0]");
    ASSERT_TRUE(strcmp(dns.servers[1], "8.8.8.8") == 0, "server[1]");
    ASSERT_TRUE(strcmp(dns.servers[2], "9.9.9.9") == 0, "server[2]");
    ASSERT_TRUE(strcmp(dns.servers[3], "208.67.222.222") == 0, "server[3]");
}

/* ================================================================
 *  mqvpn_resolve_host() tests
 * ================================================================ */

static void test_resolve_ipv4_literal(void)
{
    struct sockaddr_storage out;
    socklen_t out_len = 0;
    memset(&out, 0, sizeof(out));

    ASSERT_EQ_INT(mqvpn_resolve_host("1.2.3.4", &out, &out_len), 0,
                  "resolve IPv4 literal");
    ASSERT_EQ_INT(out.ss_family, AF_INET, "family is AF_INET");
    ASSERT_EQ_INT((int)out_len, (int)sizeof(struct sockaddr_in), "addrlen correct");

    struct sockaddr_in *sin = (struct sockaddr_in *)&out;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "1.2.3.4", "resolved address");
}

static void test_resolve_localhost(void)
{
    struct sockaddr_storage out;
    socklen_t out_len = 0;
    memset(&out, 0, sizeof(out));

    ASSERT_EQ_INT(mqvpn_resolve_host("localhost", &out, &out_len), 0,
                  "resolve localhost");
    /* May resolve to IPv4 or IPv6 depending on system config */
    ASSERT_TRUE(out.ss_family == AF_INET || out.ss_family == AF_INET6,
                "localhost resolves to IPv4 or IPv6");
}

static void test_resolve_invalid(void)
{
    struct sockaddr_storage out;
    socklen_t out_len = 0;
    memset(&out, 0, sizeof(out));

    ASSERT_TRUE(mqvpn_resolve_host("nonexistent.invalid", &out, &out_len) != 0,
                "resolve invalid hostname fails");
}

static void test_resolve_empty(void)
{
    struct sockaddr_storage out;
    socklen_t out_len = 0;
    memset(&out, 0, sizeof(out));

    ASSERT_TRUE(mqvpn_resolve_host("", &out, &out_len) != 0,
                "resolve empty string fails");
}

static void test_resolve_null(void)
{
    struct sockaddr_storage out;
    socklen_t out_len = 0;
    memset(&out, 0, sizeof(out));

    ASSERT_TRUE(mqvpn_resolve_host(NULL, &out, &out_len) != 0,
                "resolve NULL fails");
}

static void test_resolve_ipv6_literal(void)
{
    struct sockaddr_storage out;
    socklen_t out_len = 0;
    memset(&out, 0, sizeof(out));

    ASSERT_EQ_INT(mqvpn_resolve_host("::1", &out, &out_len), 0,
                  "resolve IPv6 literal");
    ASSERT_EQ_INT(out.ss_family, AF_INET6, "family is AF_INET6");
    ASSERT_EQ_INT((int)out_len, (int)sizeof(struct sockaddr_in6), "addrlen correct");

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&out;
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
    ASSERT_EQ_STR(buf, "::1", "resolved address");
}

static void test_resolve_ipv4_preserved(void)
{
    struct sockaddr_storage out;
    socklen_t out_len = 0;
    memset(&out, 0, sizeof(out));

    ASSERT_EQ_INT(mqvpn_resolve_host("10.0.0.1", &out, &out_len), 0,
                  "resolve IPv4 still works");
    ASSERT_EQ_INT(out.ss_family, AF_INET, "IPv4 family preserved");
    ASSERT_EQ_INT((int)out_len, (int)sizeof(struct sockaddr_in), "addrlen correct");
}

/* Test helper functions */
static void test_sa_set_port(void)
{
    struct sockaddr_storage ss;
    socklen_t len;

    /* IPv4 */
    memset(&ss, 0, sizeof(ss));
    mqvpn_resolve_host("1.2.3.4", &ss, &len);
    mqvpn_sa_set_port(&ss, 443);
    ASSERT_EQ_INT(ntohs(((struct sockaddr_in *)&ss)->sin_port), 443,
                  "set port on IPv4");

    /* IPv6 */
    memset(&ss, 0, sizeof(ss));
    mqvpn_resolve_host("::1", &ss, &len);
    mqvpn_sa_set_port(&ss, 8443);
    ASSERT_EQ_INT(ntohs(((struct sockaddr_in6 *)&ss)->sin6_port), 8443,
                  "set port on IPv6");
}

static void test_sa_ntop(void)
{
    struct sockaddr_storage ss;
    socklen_t len;
    char buf[INET6_ADDRSTRLEN];

    /* IPv4 */
    mqvpn_resolve_host("192.168.1.1", &ss, &len);
    ASSERT_TRUE(mqvpn_sa_ntop(&ss, buf, sizeof(buf)) != NULL,
                "ntop returns non-NULL for IPv4");
    ASSERT_EQ_STR(buf, "192.168.1.1", "ntop IPv4");

    /* IPv6 */
    mqvpn_resolve_host("::1", &ss, &len);
    ASSERT_TRUE(mqvpn_sa_ntop(&ss, buf, sizeof(buf)) != NULL,
                "ntop returns non-NULL for IPv6");
    ASSERT_EQ_STR(buf, "::1", "ntop IPv6");
}

static void test_sa_host_prefix(void)
{
    struct sockaddr_storage ss;
    socklen_t len;

    mqvpn_resolve_host("1.2.3.4", &ss, &len);
    ASSERT_EQ_INT(mqvpn_sa_host_prefix(&ss), 32, "IPv4 host prefix");

    mqvpn_resolve_host("::1", &ss, &len);
    ASSERT_EQ_INT(mqvpn_sa_host_prefix(&ss), 128, "IPv6 host prefix");
}

int main(void)
{
    test_init();
    test_add_server();
    test_add_server_max();
    test_apply_and_restore();
    test_no_servers_no_apply();
    test_restore_without_apply();
    test_stale_backup_detection();
    test_lock_contention();
    test_apply_fopen_fail_releases_lock();
    test_restore_fail_releases_lock();
    test_double_apply();
    test_long_server_address();
    test_no_stale_backup();
    test_restore_stale_noop();
    test_apply_creates_marker();
    test_init_defaults();
    test_add_server_content();

    /* resolve_host tests */
    test_resolve_ipv4_literal();
    test_resolve_localhost();
    test_resolve_invalid();
    test_resolve_empty();
    test_resolve_null();
    test_resolve_ipv6_literal();
    test_resolve_ipv4_preserved();

    /* sockaddr helper tests */
    test_sa_set_port();
    test_sa_ntop();
    test_sa_host_prefix();

    printf("\n=== test_dns: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
