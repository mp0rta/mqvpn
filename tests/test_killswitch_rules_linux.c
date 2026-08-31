// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_killswitch_rules_linux.c — PATH-stub integration tests for the Linux
 * iptables/ip6tables kill switch (src/platform/linux/killswitch.c):
 * setup_killswitch()/cleanup_killswitch() driven end to end against fake
 * `iptables`/`ip6tables` on PATH (see tests/fake_cmd.h). Linux port of
 * test_killswitch_rules_darwin.c.
 *
 * The fakes make every `-D` (delete) invocation exit 1 AFTER logging:
 * cleanup_killswitch loops `while (run_iptables_cmd(del) == 0)` — "delete
 * until iptables says no such rule" — so an always-succeeding fake would
 * spin forever. Failing -D up front bounds each loop to exactly one logged
 * attempt while still recording the exact rule shape being removed.
 * $MQVPN_FAKE_FAIL_SUBSTR stays free for per-scenario insert failures.
 *
 * Every rule needle is pinned to the FULL logged line including the
 * PID-qualified comment tag: the test runs setup_killswitch() in-process,
 * so getpid() here equals the pid production stamps into ks_comment —
 * asserting the complete `-m comment --comment mqvpn-ks:<pid>` tail pins
 * the per-process rule targeting, not just the rule shape.
 */
#include "platform_internal.h"
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

#define ASSERT_TRUE(cond, msg)                   \
    do {                                         \
        if (cond) {                              \
            g_pass++;                            \
        } else {                                 \
            g_fail++;                            \
            fprintf(stderr, "FAIL [%s]\n", msg); \
        }                                        \
    } while (0)

/* Order-pinning assertion over the fake-cmd log; matching semantics live
 * in fake_cmd_log_order() (tests/fake_cmd.h). */
static void
assert_log_order(const char *log, const char *const *needles, int n, const char *tag)
{
    if (fake_cmd_log_order(log, needles, n, tag) == 0)
        g_pass++;
    else
        g_fail++;
}

/* "mqvpn-ks:<pid>" — matches production's ks_comment because the function
 * under test runs in this very process. Filled once in main(). */
static char g_tag[64];

#define NEEDLE_MAX 192

/* Builds "<prefix>|-m|comment|--comment|<tag>" — the full logged tail every
 * kill-switch rule carries. */
static void
tagged(char *buf, const char *prefix)
{
    snprintf(buf, NEEDLE_MAX, "%s|-m|comment|--comment|%s", prefix, g_tag);
}

static void
setup_fixture(fake_cmd_env_t *e)
{
    /* Deletes always "fail" (no such rule) so cleanup's delete-until-gone
     * loops terminate after one logged attempt — see the file comment. */
    const char *body = "case \"$1\" in\n"
                       "  -D) exit 1 ;;\n"
                       "esac";
    fake_cmd_install(e, "iptables", body);
    fake_cmd_install(e, "ip6tables", body);
}

static void
init_ctx_v4(platform_ctx_t *p)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->tun.name, sizeof(p->tun.name), "mqvpn0");
    p->killswitch_enabled = 1;
    p->server_port = 51820;

    socklen_t out_len = 0;
    mqvpn_resolve_host("203.0.113.9", &p->server_addr, &out_len);
    p->server_addrlen = out_len;
    mqvpn_sa_set_port(&p->server_addr, 51820);
    /* Production fills server_ip_str in setup_routes(); the kill switch
     * reads it for the server ACCEPT rule, so the fixture fills it too. */
    mqvpn_sa_ntop(&p->server_addr, p->server_ip_str, sizeof(p->server_ip_str));
}

static void
init_ctx_v6(platform_ctx_t *p)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->tun.name, sizeof(p->tun.name), "mqvpn0");
    p->killswitch_enabled = 1;
    p->server_port = 51820;

    socklen_t out_len = 0;
    mqvpn_resolve_host("2001:db8::9", &p->server_addr, &out_len);
    p->server_addrlen = out_len;
    mqvpn_sa_set_port(&p->server_addr, 51820);
    mqvpn_sa_ntop(&p->server_addr, p->server_ip_str, sizeof(p->server_ip_str));
}

/* ================================================================
 * 1. v4 server, no v6 data plane: rule set + symmetric cleanup
 * ================================================================ */
static void
test_v4_basic(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    platform_ctx_t p;
    init_ctx_v4(&p);

    int rc = setup_killswitch(&p);
    ASSERT_EQ_INT(rc, 0, "v4 setup rc");
    ASSERT_EQ_INT(p.killswitch_active, 1, "v4 killswitch_active");
    ASSERT_TRUE(strcmp(p.ks_comment, g_tag) == 0, "v4 comment is mqvpn-ks:<pid>");

    char log[8192];
    fake_cmd_read_log(e, log, sizeof(log));
    char n1[NEEDLE_MAX], n2[NEEDLE_MAX], n3[NEEDLE_MAX], n4[NEEDLE_MAX];
    tagged(n1, "iptables|-I|OUTPUT|-o|mqvpn0|-j|ACCEPT");
    tagged(n2, "iptables|-I|OUTPUT|-o|lo|-j|ACCEPT");
    tagged(n3, "iptables|-A|OUTPUT|-j|DROP");
    tagged(n4, "iptables|-I|OUTPUT|-p|udp|-d|203.0.113.9/32|--dport|51820|-j|ACCEPT");
    const char *seq[] = {n1, n2, n3, n4};
    assert_log_order(log, seq, 4, "v4 setup rule order");
    ASSERT_TRUE(strstr(log, "ip6tables|") == NULL,
                "v4-only setup: no ip6tables commands (has_v6=0, v4 server)");

    fake_cmd_reset(e);
    cleanup_killswitch(&p);
    ASSERT_EQ_INT(p.killswitch_active, 0, "v4 cleanup clears killswitch_active");
    fake_cmd_read_log(e, log, sizeof(log));
    char c1[NEEDLE_MAX], c2[NEEDLE_MAX], c3[NEEDLE_MAX], c4[NEEDLE_MAX], c5[NEEDLE_MAX],
        c6[NEEDLE_MAX], c7[NEEDLE_MAX];
    tagged(c1, "iptables|-D|OUTPUT|-o|mqvpn0|-j|ACCEPT");
    tagged(c2, "iptables|-D|OUTPUT|-o|lo|-j|ACCEPT");
    tagged(c3, "iptables|-D|OUTPUT|-j|DROP");
    tagged(c4, "iptables|-D|OUTPUT|-p|udp|-d|203.0.113.9/32|--dport|51820|-j|ACCEPT");
    /* cleanup always sweeps the ip6tables TUN/lo/DROP shapes too —
     * belt-and-braces against a has_v6 flag that changed mid-session. */
    tagged(c5, "ip6tables|-D|OUTPUT|-o|mqvpn0|-j|ACCEPT");
    tagged(c6, "ip6tables|-D|OUTPUT|-o|lo|-j|ACCEPT");
    tagged(c7, "ip6tables|-D|OUTPUT|-j|DROP");
    const char *cseq[] = {c1, c2, c3, c4, c5, c6, c7};
    assert_log_order(log, cseq, 7, "v4 cleanup rule order");
}

/* ================================================================
 * 2. first insert fails -> rc -1, self-cleanup runs, active ends 0
 * ================================================================ */
static void
test_insert_failure_self_cleanup(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    fake_cmd_set_fail_substr("-I|OUTPUT|-o|mqvpn0");

    platform_ctx_t p;
    init_ctx_v4(&p);

    int rc = setup_killswitch(&p);
    ASSERT_EQ_INT(rc, -1, "insert-failure rc");
    ASSERT_EQ_INT(p.killswitch_active, 0, "insert-failure ends inactive");

    char log[8192];
    fake_cmd_read_log(e, log, sizeof(log));
    char d1[NEEDLE_MAX], d2[NEEDLE_MAX];
    tagged(d1, "iptables|-D|OUTPUT|-o|mqvpn0|-j|ACCEPT");
    tagged(d2, "iptables|-D|OUTPUT|-j|DROP");
    ASSERT_TRUE(strstr(log, d1) != NULL,
                "insert-failure: self-cleanup attempted the TUN delete");
    ASSERT_TRUE(strstr(log, d2) != NULL,
                "insert-failure: self-cleanup attempted the DROP delete");

    fake_cmd_clear_fail();
}

/* ================================================================
 * 2b. server-accept insert fails AFTER the base trio -> self-cleanup
 * ================================================================ */
static void
test_server_accept_failure_self_cleanup(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    /* Matches only the server ACCEPT insert (-I ... -p udp ...); cleanup's
     * matching -D also contains the substring, but the fake already fails
     * every -D after logging, so the injection changes nothing there. */
    fake_cmd_set_fail_substr("-I|OUTPUT|-p|udp");

    platform_ctx_t p;
    init_ctx_v4(&p);

    int rc = setup_killswitch(&p);
    ASSERT_EQ_INT(rc, -1, "server-accept-failure rc");
    ASSERT_EQ_INT(p.killswitch_active, 0, "server-accept-failure ends inactive");

    char log[8192];
    fake_cmd_read_log(e, log, sizeof(log));
    char n1[NEEDLE_MAX], d1[NEEDLE_MAX];
    tagged(n1, "iptables|-A|OUTPUT|-j|DROP"); /* base trio fully installed */
    tagged(d1, "iptables|-D|OUTPUT|-j|DROP"); /* then torn down again */
    const char *seq[] = {n1, d1};
    assert_log_order(log, seq, 2, "server-accept-failure install-then-teardown");

    fake_cmd_clear_fail();
}

/* ================================================================
 * 3. v6 server: base v4 trio + ip6tables server/lo/DROP rules
 * ================================================================ */
static void
test_v6_server(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    platform_ctx_t p;
    init_ctx_v6(&p);

    int rc = setup_killswitch(&p);
    ASSERT_EQ_INT(rc, 0, "v6-server setup rc");

    char log[8192];
    fake_cmd_read_log(e, log, sizeof(log));
    char n1[NEEDLE_MAX], n2[NEEDLE_MAX], n3[NEEDLE_MAX], n4[NEEDLE_MAX], n5[NEEDLE_MAX];
    tagged(n1, "iptables|-I|OUTPUT|-o|mqvpn0|-j|ACCEPT"); /* v4 base rules always */
    tagged(n2, "iptables|-A|OUTPUT|-j|DROP");
    tagged(n3, "ip6tables|-I|OUTPUT|-p|udp|-d|2001:db8::9/128|--dport|51820|-j|ACCEPT");
    tagged(n4, "ip6tables|-I|OUTPUT|-o|lo|-j|ACCEPT");
    tagged(n5, "ip6tables|-A|OUTPUT|-j|DROP");
    const char *seq[] = {n1, n2, n3, n4, n5};
    assert_log_order(log, seq, 5, "v6-server rule order");

    fake_cmd_reset(e);
    cleanup_killswitch(&p);
    ASSERT_EQ_INT(p.killswitch_active, 0, "v6-server cleanup clears active");
    fake_cmd_read_log(e, log, sizeof(log));
    char d1[NEEDLE_MAX];
    tagged(d1, "ip6tables|-D|OUTPUT|-p|udp|-d|2001:db8::9/128|--dport|51820|-j|ACCEPT");
    ASSERT_TRUE(strstr(log, d1) != NULL,
                "v6-server cleanup deletes the ip6tables server accept");
}

/* ================================================================
 * 4. v4 server + has_v6 data plane: ip6tables TUN/lo/DROP rules added
 * ================================================================ */
static void
test_v4_server_v6_dataplane(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    platform_ctx_t p;
    init_ctx_v4(&p);
    p.has_v6 = 1;

    int rc = setup_killswitch(&p);
    ASSERT_EQ_INT(rc, 0, "v6-dataplane setup rc");

    char log[8192];
    fake_cmd_read_log(e, log, sizeof(log));
    char n1[NEEDLE_MAX], n2[NEEDLE_MAX], n3[NEEDLE_MAX], n4[NEEDLE_MAX];
    tagged(n1, "iptables|-I|OUTPUT|-p|udp|-d|203.0.113.9/32|--dport|51820|-j|ACCEPT");
    tagged(n2, "ip6tables|-I|OUTPUT|-o|mqvpn0|-j|ACCEPT"); /* then v6 data plane */
    tagged(n3, "ip6tables|-I|OUTPUT|-o|lo|-j|ACCEPT");
    tagged(n4, "ip6tables|-A|OUTPUT|-j|DROP");
    const char *seq[] = {n1, n2, n3, n4};
    assert_log_order(log, seq, 4, "v6-dataplane rule order");
    ASSERT_TRUE(strstr(log, "ip6tables|-I|OUTPUT|-p|udp") == NULL,
                "v6-dataplane: no ip6tables server accept for a v4 server");

    fake_cmd_reset(e);
    cleanup_killswitch(&p);
}

/* ================================================================
 * 5. gating: disabled or already-active setup is a silent no-op
 * ================================================================ */
static void
test_gating_noops(fake_cmd_env_t *e)
{
    char log[8192];

    fake_cmd_reset(e);
    platform_ctx_t p;
    init_ctx_v4(&p);
    p.killswitch_enabled = 0;
    ASSERT_EQ_INT(setup_killswitch(&p), 0, "disabled setup rc");
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(log[0] == '\0', "disabled setup runs no commands");

    fake_cmd_reset(e);
    init_ctx_v4(&p);
    p.killswitch_active = 1; /* already set up */
    ASSERT_EQ_INT(setup_killswitch(&p), 0, "already-active setup rc");
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(log[0] == '\0', "already-active setup runs no commands");

    /* cleanup on a never-activated ctx is likewise a no-op */
    fake_cmd_reset(e);
    init_ctx_v4(&p);
    cleanup_killswitch(&p);
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(log[0] == '\0', "inactive cleanup runs no commands");
}

int
main(void)
{
    snprintf(g_tag, sizeof(g_tag), "mqvpn-ks:%d", (int)getpid());

    fake_cmd_env_t e;
    if (fake_cmd_env_init(&e) < 0) {
        fprintf(stderr, "fake_cmd_env_init failed\n");
        return 1;
    }
    setup_fixture(&e);

    test_v4_basic(&e);
    test_insert_failure_self_cleanup(&e);
    test_server_accept_failure_self_cleanup(&e);
    test_v6_server(&e);
    test_v4_server_v6_dataplane(&e);
    test_gating_noops(&e);

    fake_cmd_env_cleanup(&e);

    printf("\n=== test_killswitch_rules_linux: %d passed, %d failed ===\n", g_pass,
           g_fail);
    return g_fail ? 1 : 0;
}
