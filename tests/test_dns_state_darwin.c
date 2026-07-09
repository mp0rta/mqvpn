// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_dns_state_darwin.c — PATH-stub integration tests for the Darwin DNS
 * state machine (src/platform/darwin/dns.c): mqvpn_dns_apply/restore/
 * restore_stale driven end to end against a fake `networksetup` on PATH
 * (see tests/fake_cmd.h). Unlike test_dns_backup_darwin.c (pure
 * format/parse function tests), this file exercises the full guard/fresh
 * apply paths, the FRESH-path subset rollback vs. GUARD-path full
 * rollback distinction, and the lock/backup lifecycle contract documented
 * at the top of dns.c.
 *
 * Fixture shared by every scenario: `networksetup -listallnetworkservices`
 * reports two enumerated services — "Wi-Fi" and "Thunderbolt Bridge" (the
 * latter exercises the space-in-service-name path) — plus a disabled
 * "*Disabled Svc" entry that list_services() must skip. Every enumerated
 * service's fake `-getdnsservers` reports the SAME pre-existing value
 * ("192.168.1.1") — sufficient for every scenario below, none of which
 * assert differing per-service original values. The VPN DNS servers
 * configured via mqvpn_dns_add_server are "10.0.0.1"/"10.0.0.2" — chosen
 * to never collide with the "192.168.1.1" original value, which several
 * scenarios rely on to fail a fresh-apply `-setdnsservers` call WITHOUT
 * also failing that same service's rollback/restore call (same verb, same
 * service name, different value argument).
 */
#include "dns.h"
#include "fake_cmd.h"

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

static char g_list_file[FAKE_CMD_PATH_MAX];
static char g_getdns_file[FAKE_CMD_PATH_MAX];

/* Writes the shared fixture content files and the fake networksetup
 * script once for the whole test binary. */
static void
setup_fixture(fake_cmd_env_t *e)
{
    fake_cmd_write_content_file(
        e, "list.txt",
        "An asterisk (*) denotes that a network service is disabled.\n"
        "Wi-Fi\n"
        "Thunderbolt Bridge\n"
        "*Disabled Svc\n",
        g_list_file, sizeof(g_list_file));
    fake_cmd_write_content_file(e, "getdns.txt", "192.168.1.1\n", g_getdns_file,
                                sizeof(g_getdns_file));
    setenv("MQVPN_FAKE_LIST_FILE", g_list_file, 1);
    setenv("MQVPN_FAKE_GETDNS_FILE", g_getdns_file, 1);

    fake_cmd_install(e, "networksetup",
                     "case \"$1\" in\n"
                     "  -listallnetworkservices)\n"
                     "    cat \"$MQVPN_FAKE_LIST_FILE\"\n"
                     "    ;;\n"
                     "  -getdnsservers)\n"
                     "    cat \"$MQVPN_FAKE_GETDNS_FILE\"\n"
                     "    ;;\n"
                     "  -setdnsservers)\n"
                     "    : # logged by the shared boilerplate; no output needed\n"
                     "    ;;\n"
                     "esac");
}

/* ================================================================
 * 1. fresh apply success
 * ================================================================ */
static void
test_fresh_apply_success(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);

    char backup_path[FAKE_CMD_PATH_MAX], lock_path[FAKE_CMD_PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%s/backup1.bak", e->dir);
    snprintf(lock_path, sizeof(lock_path), "%s/lock1", e->dir);
    unlink(backup_path);
    unlink(lock_path);

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.backup_path = backup_path;
    dns.lock_path = lock_path;
    mqvpn_dns_add_server(&dns, "10.0.0.1");
    mqvpn_dns_add_server(&dns, "10.0.0.2");

    int rc = mqvpn_dns_apply(&dns);
    ASSERT_EQ_INT(rc, 0, "fresh-apply-success rc");
    ASSERT_EQ_INT(dns.active, 1, "fresh-apply-success active");
    ASSERT_TRUE(dns.lock_fd >= 0, "fresh-apply-success lock_fd held");
    ASSERT_TRUE(access(lock_path, F_OK) == 0, "fresh-apply-success lock file exists");
    ASSERT_TRUE(access(backup_path, F_OK) == 0, "fresh-apply-success backup exists");

    {
        FILE *fp = fopen(backup_path, "r");
        ASSERT_TRUE(fp != NULL, "fresh-apply-success backup opens");
        char line[512], svc[128], srv[256];
        int n = 0;
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                ASSERT_EQ_INT(
                    mqvpn_dns_backup_parse_line(line, svc, sizeof(svc), srv, sizeof(srv)),
                    0, "fresh-apply-success backup line parses");
                n++;
            }
            fclose(fp);
        }
        ASSERT_EQ_INT(n, 2, "fresh-apply-success backup has one line per service");
    }

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "networksetup|-listallnetworkservices") != NULL,
                "fresh-apply-success logs enumeration");
    ASSERT_TRUE(strstr(log, "networksetup|-getdnsservers|Wi-Fi") != NULL,
                "fresh-apply-success logs getdns Wi-Fi");
    ASSERT_TRUE(strstr(log, "networksetup|-getdnsservers|Thunderbolt Bridge") != NULL,
                "fresh-apply-success logs getdns Thunderbolt Bridge");
    ASSERT_TRUE(strstr(log, "networksetup|-setdnsservers|Wi-Fi|10.0.0.1|10.0.0.2") !=
                    NULL,
                "fresh-apply-success logs set Wi-Fi");
    ASSERT_TRUE(
        strstr(log, "networksetup|-setdnsservers|Thunderbolt Bridge|10.0.0.1|10.0.0.2") !=
            NULL,
        "fresh-apply-success logs set Thunderbolt Bridge");
    {
        char *p_get = strstr(log, "-getdnsservers");
        char *p_set = strstr(log, "-setdnsservers");
        ASSERT_TRUE(p_get != NULL && p_set != NULL && p_get < p_set,
                    "fresh-apply-success snapshot loop precedes set loop");
    }
    ASSERT_TRUE(strstr(log, "*Disabled Svc") == NULL,
                "fresh-apply-success skips disabled service");

    mqvpn_dns_restore(&dns);
    unlink(backup_path);
    unlink(lock_path);
}

/* ================================================================
 * 2. fresh apply, mid-loop set failure -> FRESH-path subset rollback
 * ================================================================ */
static void
test_fresh_apply_subset_rollback(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);

    char backup_path[FAKE_CMD_PATH_MAX], lock_path[FAKE_CMD_PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%s/backup2.bak", e->dir);
    snprintf(lock_path, sizeof(lock_path), "%s/lock2", e->dir);
    unlink(backup_path);
    unlink(lock_path);

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.backup_path = backup_path;
    dns.lock_path = lock_path;
    mqvpn_dns_add_server(&dns, "10.0.0.1");
    mqvpn_dns_add_server(&dns, "10.0.0.2");

    /* Fails only the 2nd service's VPN-value set — the rollback's
     * restore_one("Thunderbolt Bridge", "192.168.1.1") passes the
     * ORIGINAL value, so it is not also caught by this substring. */
    fake_cmd_set_fail_substr("-setdnsservers|Thunderbolt Bridge|10.0.0.1");

    int rc = mqvpn_dns_apply(&dns);
    ASSERT_EQ_INT(rc, -1, "subset-rollback rc");
    ASSERT_EQ_INT(dns.active, 0, "subset-rollback active cleared (rollback succeeded)");
    ASSERT_TRUE(access(backup_path, F_OK) != 0, "subset-rollback backup deleted");
    ASSERT_EQ_INT(dns.lock_fd, -1, "subset-rollback lock released");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "networksetup|-setdnsservers|Wi-Fi|10.0.0.1|10.0.0.2") !=
                    NULL,
                "subset-rollback Wi-Fi was set before the failure");
    /* Rollback scope is [0, applied] INCLUDING the failed service — both
     * services here, restored to the ORIGINAL ("192.168.1.1") value. */
    ASSERT_TRUE(strstr(log, "networksetup|-setdnsservers|Wi-Fi|192.168.1.1") != NULL,
                "subset-rollback restores Wi-Fi");
    ASSERT_TRUE(
        strstr(log, "networksetup|-setdnsservers|Thunderbolt Bridge|192.168.1.1") != NULL,
        "subset-rollback restores the failed service too");

    fake_cmd_clear_fail();
    unlink(lock_path);
}

/* Writes a 3-line hand-crafted backup: the 2 currently-enumerated
 * services plus "Old Svc", which the current enumeration no longer
 * reports — simulating a backup left behind by an earlier run whose own
 * restore only partially completed. Used by both guard-path scenarios. */
static void
write_guard_backup(const char *backup_path)
{
    FILE *fp = fake_fopen_w(backup_path, 0600);
    char line[512];
    if (!fp) return;
    mqvpn_dns_backup_format_line(line, sizeof(line), "Wi-Fi", "192.168.1.1");
    fputs(line, fp);
    mqvpn_dns_backup_format_line(line, sizeof(line), "Thunderbolt Bridge", "192.168.1.2");
    fputs(line, fp);
    mqvpn_dns_backup_format_line(line, sizeof(line), "Old Svc", "192.168.1.3");
    fputs(line, fp);
    fclose(fp);
}

/* ================================================================
 * 3. guard path (pre-existing backup): non-overwrite + full rollback
 *    succeeds
 * ================================================================ */
static void
test_guard_rollback_success(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);

    char backup_path[FAKE_CMD_PATH_MAX], lock_path[FAKE_CMD_PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%s/backup3.bak", e->dir);
    snprintf(lock_path, sizeof(lock_path), "%s/lock3", e->dir);
    unlink(lock_path);
    write_guard_backup(backup_path);

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.backup_path = backup_path;
    dns.lock_path = lock_path;
    mqvpn_dns_add_server(&dns, "10.0.0.1");
    mqvpn_dns_add_server(&dns, "10.0.0.2");

    fake_cmd_set_fail_substr("-setdnsservers|Wi-Fi|10.0.0.1");

    int rc = mqvpn_dns_apply(&dns);
    ASSERT_EQ_INT(rc, -1, "guard-rollback-success rc");
    ASSERT_EQ_INT(dns.active, 0, "guard-rollback-success active after full rollback");
    ASSERT_TRUE(access(backup_path, F_OK) != 0, "guard-rollback-success backup deleted");
    ASSERT_EQ_INT(dns.lock_fd, -1, "guard-rollback-success lock released");
    ASSERT_TRUE(access(lock_path, F_OK) != 0,
                "guard-rollback-success lock file unlinked");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "-getdnsservers") == NULL,
                "guard-rollback-success: pre-existing backup is never re-snapshotted");
    ASSERT_TRUE(strstr(log, "networksetup|-setdnsservers|Wi-Fi|192.168.1.1") != NULL,
                "guard-rollback-success restores Wi-Fi");
    ASSERT_TRUE(
        strstr(log, "networksetup|-setdnsservers|Thunderbolt Bridge|192.168.1.2") != NULL,
        "guard-rollback-success restores Thunderbolt Bridge");
    ASSERT_TRUE(
        strstr(log, "networksetup|-setdnsservers|Old Svc|192.168.1.3") != NULL,
        "guard-rollback-success restores Old Svc (full backup scope, not just this "
        "run's subset)");

    fake_cmd_clear_fail();
    unlink(lock_path);
}

/* ================================================================
 * 4. guard path: rollback ALSO fails -> backup and lock retained
 * ================================================================ */
static void
test_guard_rollback_failure(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);

    char backup_path[FAKE_CMD_PATH_MAX], lock_path[FAKE_CMD_PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%s/backup4.bak", e->dir);
    snprintf(lock_path, sizeof(lock_path), "%s/lock4", e->dir);
    unlink(lock_path);
    write_guard_backup(backup_path);

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.backup_path = backup_path;
    dns.lock_path = lock_path;
    mqvpn_dns_add_server(&dns, "10.0.0.1");
    mqvpn_dns_add_server(&dns, "10.0.0.2");

    /* No value qualifier this time: fails EVERY -setdnsservers call naming
     * Wi-Fi, so both the fresh-apply set AND the rollback's restore of
     * Wi-Fi fail. */
    fake_cmd_set_fail_substr("-setdnsservers|Wi-Fi");

    int rc = mqvpn_dns_apply(&dns);
    ASSERT_EQ_INT(rc, -1, "guard-rollback-failure rc");
    ASSERT_EQ_INT(dns.active, 1, "guard-rollback-failure active kept (rollback failed)");
    ASSERT_TRUE(access(backup_path, F_OK) == 0, "guard-rollback-failure backup kept");
    ASSERT_TRUE(dns.lock_fd >= 0, "guard-rollback-failure lock kept");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "-getdnsservers") == NULL,
                "guard-rollback-failure: pre-existing backup still never re-snapshotted");
    ASSERT_TRUE(
        strstr(log, "networksetup|-setdnsservers|Thunderbolt Bridge|192.168.1.2") != NULL,
        "guard-rollback-failure still restores the services not gated by the fail rule");
    ASSERT_TRUE(strstr(log, "networksetup|-setdnsservers|Old Svc|192.168.1.3") != NULL,
                "guard-rollback-failure still restores Old Svc");

    /* Clean up: retry with the fail rule cleared so state doesn't leak
     * into later scenarios. */
    fake_cmd_clear_fail();
    mqvpn_dns_restore(&dns);
    unlink(backup_path);
    unlink(lock_path);
}

/* ================================================================
 * 5. malformed pre-existing backup -> abort before any set
 * ================================================================ */
static void
test_malformed_backup_abort(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);

    char backup_path[FAKE_CMD_PATH_MAX], lock_path[FAKE_CMD_PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%s/backup5.bak", e->dir);
    snprintf(lock_path, sizeof(lock_path), "%s/lock5", e->dir);
    unlink(lock_path);

    const char *bad_content = "NoTabOnThisLineAtAll\n";
    {
        FILE *fp = fake_fopen_w(backup_path, 0600);
        if (fp) {
            fputs(bad_content, fp);
            fclose(fp);
        }
    }

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.backup_path = backup_path;
    dns.lock_path = lock_path;
    mqvpn_dns_add_server(&dns, "10.0.0.1");

    int rc = mqvpn_dns_apply(&dns);
    ASSERT_EQ_INT(rc, -1, "malformed-backup-abort rc");
    ASSERT_EQ_INT(dns.active, 0, "malformed-backup-abort not active");
    ASSERT_EQ_INT(dns.lock_fd, -1, "malformed-backup-abort lock released");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "-setdnsservers") == NULL,
                "malformed-backup-abort issues zero set calls");

    char after[256];
    FILE *fp = fopen(backup_path, "r");
    size_t n = fp ? fread(after, 1, sizeof(after) - 1, fp) : 0;
    if (fp) fclose(fp);
    after[n] = '\0';
    ASSERT_EQ_STR(after, bad_content, "malformed-backup-abort backup left untouched");

    unlink(backup_path);
    unlink(lock_path);
}

/* ================================================================
 * 6. restore(): partial failure keeps everything; clean retry finishes
 * ================================================================ */
static void
test_restore_partial_then_full(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);

    char backup_path[FAKE_CMD_PATH_MAX], lock_path[FAKE_CMD_PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%s/backup6.bak", e->dir);
    snprintf(lock_path, sizeof(lock_path), "%s/lock6", e->dir);
    unlink(backup_path);
    unlink(lock_path);

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.backup_path = backup_path;
    dns.lock_path = lock_path;
    mqvpn_dns_add_server(&dns, "10.0.0.1");
    mqvpn_dns_add_server(&dns, "10.0.0.2");

    ASSERT_EQ_INT(mqvpn_dns_apply(&dns), 0, "restore-partial: setup apply ok");
    ASSERT_EQ_INT(dns.active, 1, "restore-partial: active after setup apply");

    fake_cmd_set_fail_substr("-setdnsservers|Thunderbolt Bridge");
    mqvpn_dns_restore(&dns);
    ASSERT_EQ_INT(dns.active, 1, "restore-partial: active kept after partial failure");
    ASSERT_TRUE(access(backup_path, F_OK) == 0, "restore-partial: backup kept");
    ASSERT_TRUE(dns.lock_fd >= 0, "restore-partial: lock kept");

    fake_cmd_clear_fail();
    mqvpn_dns_restore(&dns);
    ASSERT_EQ_INT(dns.active, 0, "restore-partial: active cleared after clean retry");
    ASSERT_TRUE(access(backup_path, F_OK) != 0,
                "restore-partial: backup deleted after retry");
    ASSERT_EQ_INT(dns.lock_fd, -1, "restore-partial: lock released after retry");

    unlink(lock_path);
}

/* ================================================================
 * 7. restore_stale(): startup policy releases the lock even on a
 *    partial-failure restore; a clean retry deletes the backup
 * ================================================================ */
static void
test_restore_stale(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);

    char backup_path[FAKE_CMD_PATH_MAX], lock_path[FAKE_CMD_PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%s/backup7.bak", e->dir);
    snprintf(lock_path, sizeof(lock_path), "%s/lock7", e->dir);
    unlink(lock_path);

    {
        FILE *fp = fake_fopen_w(backup_path, 0600);
        char line[512];
        if (fp) {
            mqvpn_dns_backup_format_line(line, sizeof(line), "Wi-Fi", "192.168.1.1");
            fputs(line, fp);
            mqvpn_dns_backup_format_line(line, sizeof(line), "Thunderbolt Bridge",
                                         "192.168.1.2");
            fputs(line, fp);
            fclose(fp);
        }
    }

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.backup_path = backup_path;
    dns.lock_path = lock_path;

    ASSERT_TRUE(mqvpn_dns_has_stale_backup(&dns), "restore-stale: stale backup detected");

    fake_cmd_set_fail_substr("-setdnsservers|Thunderbolt Bridge");
    mqvpn_dns_restore_stale(&dns);
    ASSERT_TRUE(access(backup_path, F_OK) == 0,
                "restore-stale: backup kept on partial failure");
    ASSERT_EQ_INT(
        dns.lock_fd, -1,
        "restore-stale: lock released even on partial failure (startup policy)");
    ASSERT_TRUE(access(lock_path, F_OK) != 0, "restore-stale: lock file unlinked");
    ASSERT_EQ_INT(dns.active, 0, "restore-stale: active stays 0 throughout");

    fake_cmd_clear_fail();
    mqvpn_dns_restore_stale(&dns);
    ASSERT_TRUE(access(backup_path, F_OK) != 0,
                "restore-stale: backup deleted after clean retry");
    ASSERT_EQ_INT(dns.lock_fd, -1, "restore-stale: lock stays released");

    unlink(backup_path);
    unlink(lock_path);
}

/* ================================================================
 * 8. backup creation failure -> abort before any set, lock released
 * ================================================================ */
static void
test_backup_create_failure(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);

    char lock_path[FAKE_CMD_PATH_MAX];
    snprintf(lock_path, sizeof(lock_path), "%s/lock8", e->dir);
    unlink(lock_path);

    /* Parent directory doesn't exist -> write_backup()'s open(O_CREAT)
     * fails with ENOENT before the snapshot loop (and thus before any set
     * call) ever runs. */
    char backup_path[FAKE_CMD_PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%s/no_such_subdir/backup8.bak", e->dir);

    mqvpn_dns_t dns;
    mqvpn_dns_init(&dns);
    dns.backup_path = backup_path;
    dns.lock_path = lock_path;
    mqvpn_dns_add_server(&dns, "10.0.0.1");
    mqvpn_dns_add_server(&dns, "10.0.0.2");

    int rc = mqvpn_dns_apply(&dns);
    ASSERT_EQ_INT(rc, -1, "backup-create-failure rc");
    ASSERT_EQ_INT(dns.active, 0, "backup-create-failure not active");
    ASSERT_EQ_INT(dns.lock_fd, -1, "backup-create-failure lock released");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "-setdnsservers") == NULL,
                "backup-create-failure issues zero set calls");
    ASSERT_TRUE(strstr(log, "-getdnsservers") == NULL,
                "backup-create-failure issues zero snapshot calls");

    unlink(lock_path);
}

int
main(void)
{
    fake_cmd_env_t e;
    if (fake_cmd_env_init(&e) < 0) {
        fprintf(stderr, "fake_cmd_env_init failed\n");
        return 1;
    }
    setup_fixture(&e);

    test_fresh_apply_success(&e);
    test_fresh_apply_subset_rollback(&e);
    test_guard_rollback_success(&e);
    test_guard_rollback_failure(&e);
    test_malformed_backup_abort(&e);
    test_restore_partial_then_full(&e);
    test_restore_stale(&e);
    test_backup_create_failure(&e);

    fake_cmd_env_cleanup(&e);

    printf("\n=== test_dns_state_darwin: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
