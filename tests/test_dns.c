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
    char lock_path[] = "/tmp/test_dns_lock4_XXXXXX";
    int fd = mkstemp(lock_path); close(fd); unlink(lock_path);

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.resolv_path = "/no/such/directory/resolv.conf";  /* fopen will fail */
    dns.backup_path = "/tmp/test_dns_backup_dummy";
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

    printf("\n=== test_dns: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
