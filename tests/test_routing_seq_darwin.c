// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_routing_seq_darwin.c — PATH-stub integration tests for the Darwin
 * split-tunnel routing state machine (src/platform/darwin/routing.c):
 * setup_routes()/cleanup_routes() driven end to end against a fake `route`
 * on PATH (see tests/fake_cmd.h).
 *
 * Fixture shared by every scenario: server 203.0.113.9, TUN "utun9",
 * IPv4-only (has_v6=0). `route -n get 203.0.113.9`'s canned output is set
 * per scenario via $MQVPN_FAKE_ROUTE_GET_FILE (gateway+interface lines, or
 * a "link#4" on-link gateway for the on-link scenario).
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

/* Asserts each of `needles[0..n)` appears in `log`, in that order (each
 * search resumes after the previous match) — pins call ORDER, not just
 * presence. */
static void
assert_log_order(const char *log, const char *const *needles, int n, const char *tag)
{
    const char *pos = log;
    for (int i = 0; i < n; i++) {
        const char *found = strstr(pos, needles[i]);
        if (!found) {
            g_fail++;
            fprintf(stderr, "FAIL [%s]: missing or out-of-order needle #%d: '%s'\n", tag,
                    i, needles[i]);
            return;
        }
        pos = found + strlen(needles[i]);
    }
    g_pass++;
}

static char g_route_get_file[FAKE_CMD_PATH_MAX];

static void
setup_fixture(fake_cmd_env_t *e)
{
    fake_cmd_install(e, "route",
                     "case \"$2\" in\n"
                     "  get)\n"
                     "    cat \"$MQVPN_FAKE_ROUTE_GET_FILE\"\n"
                     "    ;;\n"
                     "esac");
}

static void
set_route_get_output(fake_cmd_env_t *e, const char *content)
{
    fake_cmd_write_content_file(e, "route_get.txt", content, g_route_get_file,
                                sizeof(g_route_get_file));
    setenv("MQVPN_FAKE_ROUTE_GET_FILE", g_route_get_file, 1);
}

static void
init_ctx(platform_ctx_t *p)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->tun.name, sizeof(p->tun.name), "utun9");
    p->manage_routes = 1;
    p->has_v6 = 0;

    socklen_t out_len = 0;
    mqvpn_resolve_host("203.0.113.9", &p->server_addr, &out_len);
    p->server_addrlen = out_len;
    mqvpn_sa_set_port(&p->server_addr, 51820);
}

/* ================================================================
 * 1. happy path: gatewayed server, IPv4 catch-all, symmetric cleanup
 * ================================================================ */
static void
test_happy_path(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "   gateway: 203.0.113.1\n   interface: en0\n");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, 0, "happy-path setup rc");
    ASSERT_EQ_INT(p.routing_configured, 1, "happy-path routing_configured");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "route|-n|get|203.0.113.9",
        "route|-n|add|203.0.113.9/32|203.0.113.1",
        "route|-n|add|-net|0.0.0.0/1|-interface|utun9",
        "route|-n|add|-net|128.0.0.0/1|-interface|utun9",
    };
    assert_log_order(log, seq, 4, "happy-path setup sequence");

    fake_cmd_reset(e);
    cleanup_routes(&p);
    ASSERT_EQ_INT(p.routing_configured, 0,
                  "happy-path cleanup clears routing_configured");

    fake_cmd_read_log(e, log, sizeof(log));
    const char *cseq[] = {
        "route|-n|delete|-net|0.0.0.0/1|-interface|utun9",
        "route|-n|delete|-net|128.0.0.0/1|-interface|utun9",
        "route|-n|delete|203.0.113.9/32|203.0.113.1",
    };
    assert_log_order(log, cseq, 3, "happy-path cleanup sequence");
}

/* ================================================================
 * 2. pin `add` fails once -> `change` fallback used, overall rc 0
 * ================================================================ */
static void
test_pin_change_fallback(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "   gateway: 203.0.113.1\n   interface: en0\n");
    /* Matches only the pin's "add" (host_cidr in the line), not the
     * catch-all "-net ..." adds. */
    fake_cmd_set_fail_substr("add|203.0.113.9/32");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, 0, "pin-change-fallback rc");
    ASSERT_EQ_INT(p.routing_configured, 1, "pin-change-fallback routing_configured");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "route|-n|get|203.0.113.9",
        "route|-n|add|203.0.113.9/32|203.0.113.1",
        "route|-n|change|203.0.113.9/32|203.0.113.1",
        "route|-n|add|-net|0.0.0.0/1|-interface|utun9",
    };
    assert_log_order(log, seq, 4, "pin-change-fallback sequence");

    fake_cmd_clear_fail();
    cleanup_routes(&p);
}

/* ================================================================
 * 3. catch-all `add` failure -> full rollback, rc -1
 * ================================================================ */
static void
test_catchall_failure_rollback(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "   gateway: 203.0.113.1\n   interface: en0\n");
    /* Matches only the LOW catch-all's "add" (not its later "delete"). */
    fake_cmd_set_fail_substr("add|-net|0.0.0.0/1");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, -1, "catchall-failure rc");
    ASSERT_EQ_INT(p.routing_configured, 0, "catchall-failure routing_configured stays 0");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "route|-n|get|203.0.113.9",
        "route|-n|add|203.0.113.9/32|203.0.113.1",
        "route|-n|add|-net|0.0.0.0/1|-interface|utun9",
        "route|-n|delete|-net|0.0.0.0/1|-interface|utun9",
        "route|-n|delete|-net|128.0.0.0/1|-interface|utun9",
        "route|-n|delete|203.0.113.9/32|203.0.113.1",
    };
    assert_log_order(log, seq, 6, "catchall-failure rollback sequence");
    /* The HIGH catch-all's add is short-circuited (run_route_cmd(low) < 0
     * already makes the `||` true) — it must never be attempted. */
    ASSERT_TRUE(strstr(log, "add|-net|128.0.0.0/1") == NULL,
                "catchall-failure: high catch-all add never attempted");

    fake_cmd_clear_fail();
}

/* ================================================================
 * 4. on-link server (gateway "link#4") -> no pin route at all
 * ================================================================ */
static void
test_onlink_no_pin(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "   gateway: link#4\n   interface: en0\n");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, 0, "onlink-no-pin rc");
    ASSERT_EQ_INT(p.routing_configured, 1, "onlink-no-pin routing_configured");
    ASSERT_TRUE(p.orig_gateway[0] == '\0', "onlink-no-pin: orig_gateway parsed as empty");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "route|-n|get|203.0.113.9",
        "route|-n|add|-net|0.0.0.0/1|-interface|utun9",
        "route|-n|add|-net|128.0.0.0/1|-interface|utun9",
    };
    assert_log_order(log, seq, 3, "onlink-no-pin setup sequence");
    ASSERT_TRUE(strstr(log, "add|203.0.113.9/32") == NULL,
                "onlink-no-pin: no pin route ever added");

    fake_cmd_reset(e);
    cleanup_routes(&p);
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "delete|-net|0.0.0.0/1|-interface|utun9") != NULL,
                "onlink-no-pin cleanup deletes low catch-all");
    ASSERT_TRUE(strstr(log, "delete|-net|128.0.0.0/1|-interface|utun9") != NULL,
                "onlink-no-pin cleanup deletes high catch-all");
    ASSERT_TRUE(strstr(log, "delete|203.0.113.9/32") == NULL,
                "onlink-no-pin cleanup: no pin route to delete");
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

    test_happy_path(&e);
    test_pin_change_fallback(&e);
    test_catchall_failure_rollback(&e);
    test_onlink_no_pin(&e);

    fake_cmd_env_cleanup(&e);

    printf("\n=== test_routing_seq_darwin: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
