// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_killswitch_rules_darwin.c — PATH-stub integration tests for the
 * Darwin pf kill switch (src/platform/darwin/killswitch.c).
 *
 * build_pf_rules() is static, so this TU #includes killswitch.c directly
 * (same idiom as tests/test_status.c including status.c) to reach it and
 * to drive setup_killswitch()/cleanup_killswitch() against a fake `pfctl`
 * on PATH (see tests/fake_cmd.h).
 *
 * F_SETNOSIGPIPE (used unconditionally in run_pfctl_stdin's SIGPIPE guard)
 * has no Linux definition; the Linux CMake target compiles this file with
 * -DF_SETNOSIGPIPE=<value> — see the CMakeLists.txt comment at that target
 * for why the value matters (unlike dns.c's F_FULLFSYNC, this fcntl has no
 * EINVAL fallback: a value that fails on Linux would block every
 * setup_killswitch() call before pfctl is ever invoked).
 */
#include "../src/platform/darwin/killswitch.c"

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

/* build_pf_rules() only reads p->server_addr.ss_family (to pick is_v6) and
 * p->server_ip_str/p->server_port (already-formatted, used verbatim in the
 * rule text) — set the family directly rather than pulling in
 * mqvpn_resolve_host() (dns_common.c), which this test target does not
 * link (see the CMakeLists.txt comment: this TU #includes killswitch.c
 * directly and only needs log.c alongside it). */
static void
init_ctx_v4(platform_ctx_t *p, int has_v6)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->tun.name, sizeof(p->tun.name), "utun9");
    p->killswitch_enabled = 1;
    p->has_v6 = has_v6;
    p->server_port = 51820;
    snprintf(p->server_ip_str, sizeof(p->server_ip_str), "203.0.113.9");
    p->server_addr.ss_family = AF_INET;
}

static void
init_ctx_v6(platform_ctx_t *p, int has_v6)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->tun.name, sizeof(p->tun.name), "utun9");
    p->killswitch_enabled = 1;
    p->has_v6 = has_v6;
    p->server_port = 51820;
    snprintf(p->server_ip_str, sizeof(p->server_ip_str), "2001:db8::9");
    p->server_addr.ss_family = AF_INET6;
}

/* ================================================================
 * 1. build_pf_rules() truth table over (is_v6, has_v6)
 * ================================================================ */
static void
test_build_pf_rules_truth_table(void)
{
    const char *lo4 = "pass out quick on lo0 inet\n";
    const char *tun4 = "pass out quick on utun9 inet\n";
    const char *srv4 = "pass out quick inet proto udp to 203.0.113.9 port = 51820\n";
    const char *block4 = "block drop out quick inet\n";
    const char *lo6 = "pass out quick on lo0 inet6\n";
    const char *tun6 = "pass out quick on utun9 inet6\n";
    const char *srv6 = "pass out quick inet6 proto udp to 2001:db8::9 port = 51820\n";
    const char *block6 = "block drop out quick inet6\n";

    char buf[1024];
    platform_ctx_t p;

    /* (is_v6=0, has_v6=0): v4 block only, server pass present (v4 dest),
     * no v6 block at all. */
    init_ctx_v4(&p, 0);
    ASSERT_EQ_INT(build_pf_rules(&p, buf, sizeof(buf)), 0, "truth-table(0,0) rc");
    ASSERT_TRUE(strstr(buf, lo4) != NULL, "truth-table(0,0) lo4");
    ASSERT_TRUE(strstr(buf, tun4) != NULL, "truth-table(0,0) tun4");
    ASSERT_TRUE(strstr(buf, srv4) != NULL, "truth-table(0,0) srv4");
    ASSERT_TRUE(strstr(buf, block4) != NULL, "truth-table(0,0) block4");
    ASSERT_TRUE(strstr(buf, lo6) == NULL, "truth-table(0,0) no lo6");
    ASSERT_TRUE(strstr(buf, block6) == NULL, "truth-table(0,0) no block6");

    /* (is_v6=0, has_v6=1): v4 block unchanged; v6 block present with lo6 +
     * tun6 (has_v6-gated) but NO server6 pass (is_v6-gated). */
    init_ctx_v4(&p, 1);
    ASSERT_EQ_INT(build_pf_rules(&p, buf, sizeof(buf)), 0, "truth-table(0,1) rc");
    ASSERT_TRUE(strstr(buf, lo4) != NULL, "truth-table(0,1) lo4");
    ASSERT_TRUE(strstr(buf, srv4) != NULL, "truth-table(0,1) srv4");
    ASSERT_TRUE(strstr(buf, lo6) != NULL, "truth-table(0,1) lo6");
    ASSERT_TRUE(strstr(buf, tun6) != NULL, "truth-table(0,1) tun6");
    ASSERT_TRUE(strstr(buf, srv6) == NULL, "truth-table(0,1) no srv6");
    ASSERT_TRUE(strstr(buf, block6) != NULL, "truth-table(0,1) block6");

    /* (is_v6=1, has_v6=0): v4 block present but NO server4 pass (is_v6
     * gates the v4 server-pass off); v6 block has lo6 + server6 pass but
     * NO tun6 (has_v6-gated off). */
    init_ctx_v6(&p, 0);
    ASSERT_EQ_INT(build_pf_rules(&p, buf, sizeof(buf)), 0, "truth-table(1,0) rc");
    ASSERT_TRUE(strstr(buf, lo4) != NULL, "truth-table(1,0) lo4");
    ASSERT_TRUE(strstr(buf, srv4) == NULL, "truth-table(1,0) no srv4");
    ASSERT_TRUE(strstr(buf, block4) != NULL, "truth-table(1,0) block4");
    ASSERT_TRUE(strstr(buf, lo6) != NULL, "truth-table(1,0) lo6");
    ASSERT_TRUE(strstr(buf, tun6) == NULL, "truth-table(1,0) no tun6");
    ASSERT_TRUE(strstr(buf, srv6) != NULL, "truth-table(1,0) srv6");
    ASSERT_TRUE(strstr(buf, block6) != NULL, "truth-table(1,0) block6");

    /* (is_v6=1, has_v6=1): v4 block present, no server4 pass; v6 block has
     * all of lo6/tun6/srv6. */
    init_ctx_v6(&p, 1);
    ASSERT_EQ_INT(build_pf_rules(&p, buf, sizeof(buf)), 0, "truth-table(1,1) rc");
    ASSERT_TRUE(strstr(buf, srv4) == NULL, "truth-table(1,1) no srv4");
    ASSERT_TRUE(strstr(buf, lo6) != NULL, "truth-table(1,1) lo6");
    ASSERT_TRUE(strstr(buf, tun6) != NULL, "truth-table(1,1) tun6");
    ASSERT_TRUE(strstr(buf, srv6) != NULL, "truth-table(1,1) srv6");
    ASSERT_TRUE(strstr(buf, block6) != NULL, "truth-table(1,1) block6");

    /* pf's `quick` first-match-wins semantics require every pass line for
     * a family to precede that family's trailing block line. */
    {
        char *p4 = strstr(buf, block4);
        char *ptun4 = strstr(buf, tun4);
        ASSERT_TRUE(p4 != NULL && ptun4 != NULL && ptun4 < p4,
                    "truth-table: v4 pass precedes v4 block");
        char *p6 = strstr(buf, block6);
        char *plo6 = strstr(buf, lo6);
        ASSERT_TRUE(p6 != NULL && plo6 != NULL && plo6 < p6,
                    "truth-table: v6 pass precedes v6 block");
    }
}

/* ================================================================
 * 2. setup happy path: stdin ruleset captured verbatim, token parsed
 * ================================================================ */
static void
test_setup_happy(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    char stdin_file[FAKE_CMD_PATH_MAX];
    snprintf(stdin_file, sizeof(stdin_file), "%s/pf_stdin.txt", e->dir);
    unlink(stdin_file);
    setenv("MQVPN_FAKE_STDIN_FILE", stdin_file, 1);
    setenv("MQVPN_FAKE_TOKEN_LINE", "Token : 4242", 1);

    platform_ctx_t p;
    init_ctx_v4(&p, 0);

    char expected_rules[1024];
    ASSERT_EQ_INT(build_pf_rules(&p, expected_rules, sizeof(expected_rules)), 0,
                  "setup-happy: expected rules build");

    int rc = setup_killswitch(&p);
    ASSERT_EQ_INT(rc, 0, "setup-happy rc");
    ASSERT_EQ_INT(p.killswitch_active, 1, "setup-happy killswitch_active");
    ASSERT_EQ_STR(p.ks_pf_token, "4242", "setup-happy token parsed");

    char captured[1024];
    FILE *fp = fopen(stdin_file, "r");
    ASSERT_TRUE(fp != NULL, "setup-happy stdin capture file exists");
    size_t n = fp ? fread(captured, 1, sizeof(captured) - 1, fp) : 0;
    if (fp) fclose(fp);
    captured[n] = '\0';
    ASSERT_EQ_STR(captured, expected_rules,
                  "setup-happy stdin == build_pf_rules() output");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "pfctl|-a|" MQVPN_PF_ANCHOR "|-f|-") != NULL,
                "setup-happy logs the -f - load");
    ASSERT_TRUE(strstr(log, "pfctl|-E") != NULL, "setup-happy logs -E");

    cleanup_killswitch(&p);
    unlink(stdin_file);
}

/* ================================================================
 * 3. `pfctl -E` failure -> fatal, cleanup runs, active ends at 0
 * ================================================================ */
static void
test_enable_failure(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    fake_cmd_set_fail_substr("-E");

    platform_ctx_t p;
    init_ctx_v4(&p, 0);

    int rc = setup_killswitch(&p);
    ASSERT_EQ_INT(rc, -1, "enable-failure rc");
    ASSERT_EQ_INT(p.killswitch_active, 0,
                  "enable-failure: cleanup ran internally, active ends at 0");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "pfctl|-a|" MQVPN_PF_ANCHOR "|-f|-") != NULL,
                "enable-failure: rules were loaded before -E failed");
    ASSERT_TRUE(strstr(log, "pfctl|-E") != NULL, "enable-failure: -E was attempted");
    ASSERT_TRUE(strstr(log, "pfctl|-a|" MQVPN_PF_ANCHOR "|-F|all") != NULL,
                "enable-failure: cleanup's anchor flush ran");
    ASSERT_TRUE(strstr(log, "|-X|") == NULL,
                "enable-failure: no -X (no token was ever captured)");

    fake_cmd_clear_fail();
}

/* ================================================================
 * 4. `pfctl -E` succeeds but prints no Token line -> non-fatal
 * ================================================================ */
static void
test_enable_no_token(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    unsetenv("MQVPN_FAKE_TOKEN_LINE"); /* -E prints nothing */

    platform_ctx_t p;
    init_ctx_v4(&p, 0);

    int rc = setup_killswitch(&p);
    ASSERT_EQ_INT(rc, 0, "enable-no-token rc (non-fatal)");
    ASSERT_EQ_INT(p.killswitch_active, 1,
                  "enable-no-token: active despite missing token");
    ASSERT_EQ_STR(p.ks_pf_token, "", "enable-no-token: token stays empty");

    fake_cmd_reset(e); /* isolate cleanup's own log from setup's */
    cleanup_killswitch(&p);
    ASSERT_EQ_INT(p.killswitch_active, 0, "enable-no-token: cleanup clears active");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "pfctl|-a|" MQVPN_PF_ANCHOR "|-F|all") != NULL,
                "enable-no-token: cleanup flushes the anchor");
    ASSERT_TRUE(strstr(log, "|-X|") == NULL,
                "enable-no-token: no -X issued (no token to decrement)");
}

int
main(void)
{
    test_build_pf_rules_truth_table();

    fake_cmd_env_t e;
    if (fake_cmd_env_init(&e) < 0) {
        fprintf(stderr, "fake_cmd_env_init failed\n");
        return 1;
    }
    fake_cmd_install(&e, "pfctl",
                     "case \"$1\" in\n"
                     "  -a)\n"
                     "    if [ \"$3\" = \"-f\" ]; then\n"
                     "      cat > \"$MQVPN_FAKE_STDIN_FILE\"\n"
                     "    fi\n"
                     "    ;;\n"
                     "  -E)\n"
                     "    if [ -n \"$MQVPN_FAKE_TOKEN_LINE\" ]; then\n"
                     "      echo \"$MQVPN_FAKE_TOKEN_LINE\"\n"
                     "    fi\n"
                     "    ;;\n"
                     "  -X)\n"
                     "    : ;;\n"
                     "esac");

    test_setup_happy(&e);
    test_enable_failure(&e);
    test_enable_no_token(&e);

    fake_cmd_env_cleanup(&e);

    printf("\n=== test_killswitch_rules_darwin: %d passed, %d failed ===\n", g_pass,
           g_fail);
    return g_fail ? 1 : 0;
}
