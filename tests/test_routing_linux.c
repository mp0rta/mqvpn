// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_routing_linux.c — PATH-stub integration tests for the Linux
 * split-tunnel routing state machine (src/platform/linux/routing.c):
 * setup_routes()/cleanup_routes() driven end to end against a fake `ip` on
 * PATH (see tests/fake_cmd.h). Linux port of test_routing_seq_darwin.c —
 * same harness, same scenario shape, `ip route` verbs instead of `route`.
 *
 * Fixture shared by every scenario: server 203.0.113.9, TUN "mqvpn0".
 * `ip -4 route get 203.0.113.9`'s canned output is set per scenario via
 * $MQVPN_FAKE_IP_ROUTE_GET_FILE ("via <gw> dev <if>" for the gatewayed
 * case, "dev <if>" only for on-link).
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

static char g_route_get_file[FAKE_CMD_PATH_MAX];

static void
setup_fixture(fake_cmd_env_t *e)
{
    /* `ip -4 route get <ip>` prints the canned discovery line; every other
     * verb (route replace/del) just logs and succeeds. Matched on "$*"
     * because the discovery call carries a family flag ("-4 route get ...")
     * while the catch-all verbs do not ("route replace ..."). */
    fake_cmd_install(e, "ip",
                     "case \"$*\" in\n"
                     "  *\"route get\"*)\n"
                     "    cat \"$MQVPN_FAKE_IP_ROUTE_GET_FILE\"\n"
                     "    ;;\n"
                     "esac");
}

static void
set_route_get_output(fake_cmd_env_t *e, const char *content)
{
    fake_cmd_write_content_file(e, "ip_route_get.txt", content, g_route_get_file,
                                sizeof(g_route_get_file));
    setenv("MQVPN_FAKE_IP_ROUTE_GET_FILE", g_route_get_file, 1);
}

static void
init_ctx(platform_ctx_t *p)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->tun.name, sizeof(p->tun.name), "mqvpn0");
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
    set_route_get_output(e, "203.0.113.9 via 203.0.113.1 dev eth0 src 192.0.2.5 uid 0\n");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, 0, "happy-path setup rc");
    ASSERT_EQ_INT(p.routing_configured, 1, "happy-path routing_configured");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "ip|-4|route|get|203.0.113.9",
        "ip|-4|route|replace|203.0.113.9/32|via|203.0.113.1|dev|eth0",
        "ip|route|replace|0.0.0.0/1|dev|mqvpn0",
        "ip|route|replace|128.0.0.0/1|dev|mqvpn0",
    };
    assert_log_order(log, seq, 4, "happy-path setup sequence");
    ASSERT_TRUE(strstr(log, "|-6|") == NULL, "happy-path: no IPv6 commands (has_v6=0)");

    fake_cmd_reset(e);
    cleanup_routes(&p);
    ASSERT_EQ_INT(p.routing_configured, 0,
                  "happy-path cleanup clears routing_configured");

    fake_cmd_read_log(e, log, sizeof(log));
    const char *cseq[] = {
        "ip|route|del|0.0.0.0/1|dev|mqvpn0",
        "ip|route|del|128.0.0.0/1|dev|mqvpn0",
        "ip|-4|route|del|203.0.113.9/32|via|203.0.113.1|dev|eth0",
    };
    assert_log_order(log, cseq, 3, "happy-path cleanup sequence");
}

/* ================================================================
 * 2. on-link server (route get has no `via`) -> no pin route at all
 * ================================================================ */
static void
test_onlink_no_pin(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "203.0.113.9 dev eth0 src 192.0.2.5 uid 0\n");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, 0, "onlink-no-pin rc");
    ASSERT_EQ_INT(p.routing_configured, 1, "onlink-no-pin routing_configured");
    ASSERT_TRUE(p.orig_gateway[0] == '\0', "onlink-no-pin: orig_gateway parsed as empty");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "ip|-4|route|get|203.0.113.9",
        "ip|route|replace|0.0.0.0/1|dev|mqvpn0",
        "ip|route|replace|128.0.0.0/1|dev|mqvpn0",
    };
    assert_log_order(log, seq, 3, "onlink-no-pin setup sequence");
    ASSERT_TRUE(strstr(log, "replace|203.0.113.9/32") == NULL,
                "onlink-no-pin: no pin route ever added");

    fake_cmd_reset(e);
    cleanup_routes(&p);
    fake_cmd_read_log(e, log, sizeof(log));
    /* Full-invocation needles (anchored at the command name): a bare
     * "del|..." would also match an erroneous `ip -6 route del ...`. */
    ASSERT_TRUE(strstr(log, "ip|route|del|0.0.0.0/1|dev|mqvpn0") != NULL,
                "onlink-no-pin cleanup deletes low catch-all");
    ASSERT_TRUE(strstr(log, "ip|route|del|128.0.0.0/1|dev|mqvpn0") != NULL,
                "onlink-no-pin cleanup deletes high catch-all");
    ASSERT_TRUE(strstr(log, "del|203.0.113.9/32") == NULL,
                "onlink-no-pin cleanup: no pin route to delete");
}

/* ================================================================
 * 3. catch-all `replace` failure -> full rollback, rc -1
 * ================================================================ */
static void
test_catchall_failure_rollback(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "203.0.113.9 via 203.0.113.1 dev eth0 src 192.0.2.5 uid 0\n");
    /* Matches only the LOW catch-all's replace (the rollback uses `del`). */
    fake_cmd_set_fail_substr("replace|0.0.0.0/1");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, -1, "catchall-failure rc");
    ASSERT_EQ_INT(p.routing_configured, 0, "catchall-failure routing_configured stays 0");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "ip|-4|route|get|203.0.113.9",
        "ip|-4|route|replace|203.0.113.9/32|via|203.0.113.1|dev|eth0",
        "ip|route|replace|0.0.0.0/1|dev|mqvpn0",
        "ip|route|del|0.0.0.0/1|dev|mqvpn0",
        "ip|route|del|128.0.0.0/1|dev|mqvpn0",
        "ip|-4|route|del|203.0.113.9/32|via|203.0.113.1|dev|eth0",
    };
    assert_log_order(log, seq, 6, "catchall-failure rollback sequence");
    /* The HIGH catch-all's replace is short-circuited (`||`) — it must
     * never be attempted. */
    ASSERT_TRUE(strstr(log, "replace|128.0.0.0/1") == NULL,
                "catchall-failure: high catch-all replace never attempted");

    fake_cmd_clear_fail();
}

/* ================================================================
 * 4. has_v6: IPv6 catch-alls set after IPv4, deleted FIRST on cleanup;
 *    a v6 failure is tolerated (rc stays 0, IPv4 routing kept)
 * ================================================================ */
static void
test_v6_catchalls(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "203.0.113.9 via 203.0.113.1 dev eth0 src 192.0.2.5 uid 0\n");

    platform_ctx_t p;
    init_ctx(&p);
    p.has_v6 = 1;

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, 0, "v6 setup rc");
    ASSERT_EQ_INT(p.routing6_configured, 1, "v6 routing6_configured");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "ip|route|replace|128.0.0.0/1|dev|mqvpn0", /* v6 comes after v4 */
        "ip|-6|route|replace|::/1|dev|mqvpn0",
        "ip|-6|route|replace|8000::/1|dev|mqvpn0",
    };
    assert_log_order(log, seq, 3, "v6 setup order (after IPv4 catch-alls)");

    fake_cmd_reset(e);
    cleanup_routes(&p);
    ASSERT_EQ_INT(p.routing6_configured, 0, "v6 cleanup clears routing6_configured");
    fake_cmd_read_log(e, log, sizeof(log));
    const char *cseq[] = {
        "ip|-6|route|del|::/1|dev|mqvpn0", /* v6 deletes FIRST */
        "ip|-6|route|del|8000::/1|dev|mqvpn0",
        "ip|route|del|0.0.0.0/1|dev|mqvpn0",
    };
    assert_log_order(log, cseq, 3, "v6 cleanup order (v6 before v4)");

    /* v6 failure tolerated: low v6 replace fails -> high never attempted,
     * routing6_configured stays 0, overall rc still 0. */
    fake_cmd_reset(e);
    fake_cmd_set_fail_substr("replace|::/1");
    platform_ctx_t q;
    init_ctx(&q);
    q.has_v6 = 1;
    rc = setup_routes(&q);
    ASSERT_EQ_INT(rc, 0, "v6-failure tolerated rc");
    ASSERT_EQ_INT(q.routing_configured, 1, "v6-failure keeps IPv4 routing");
    ASSERT_EQ_INT(q.routing6_configured, 0, "v6-failure routing6_configured stays 0");
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "replace|8000::/1") == NULL,
                "v6-failure: high v6 replace never attempted (&& short-circuit)");
    fake_cmd_clear_fail();

    fake_cmd_reset(e);
    cleanup_routes(&q);
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "|-6|route|del|") == NULL,
                "v6-failure cleanup: no v6 deletes when routing6 never configured");
}

/* ================================================================
 * 4b. v6 HIGH catch-all failure -> ::/1 rolled back (no leaked route)
 * ================================================================ */
static void
test_v6_high_failure_rollback(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "203.0.113.9 via 203.0.113.1 dev eth0 src 192.0.2.5 uid 0\n");
    fake_cmd_set_fail_substr("replace|8000::/1");

    platform_ctx_t p;
    init_ctx(&p);
    p.has_v6 = 1;

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, 0, "v6-high-failure rc (still IPv4-tolerated)");
    ASSERT_EQ_INT(p.routing_configured, 1, "v6-high-failure keeps IPv4 routing");
    ASSERT_EQ_INT(p.routing6_configured, 0, "v6-high-failure routing6 stays 0");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "ip|-6|route|replace|::/1|dev|mqvpn0",     /* installed */
        "ip|-6|route|replace|8000::/1|dev|mqvpn0", /* fails */
        "ip|-6|route|del|::/1|dev|mqvpn0",         /* rollback of the half-install:
                                                    * routing6_configured stays 0, so
                                                    * cleanup_routes() would never
                                                    * delete a leftover ::/1 */
    };
    assert_log_order(log, seq, 3, "v6-high-failure rollback sequence");

    fake_cmd_clear_fail();
    fake_cmd_reset(e);
    cleanup_routes(&p);
}

/* ================================================================
 * 4c. v6 server: -6 discovery, /128 pin, symmetric -6 pin cleanup
 * ================================================================ */
static void
test_v6_server_pin(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "2001:db8::9 via fe80::1 dev eth0 src 2001:db8::5\n");

    platform_ctx_t p;
    memset(&p, 0, sizeof(p));
    snprintf(p.tun.name, sizeof(p.tun.name), "mqvpn0");
    p.manage_routes = 1;
    socklen_t out_len = 0;
    mqvpn_resolve_host("2001:db8::9", &p.server_addr, &out_len);
    p.server_addrlen = out_len;
    mqvpn_sa_set_port(&p.server_addr, 51820);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, 0, "v6-server setup rc");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "ip|-6|route|get|2001:db8::9",
        "ip|-6|route|replace|2001:db8::9/128|via|fe80::1|dev|eth0",
        "ip|route|replace|0.0.0.0/1|dev|mqvpn0", /* v4 catch-alls regardless */
    };
    assert_log_order(log, seq, 3, "v6-server setup sequence");

    fake_cmd_reset(e);
    cleanup_routes(&p);
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "ip|-6|route|del|2001:db8::9/128|via|fe80::1|dev|eth0") !=
                    NULL,
                "v6-server cleanup deletes the -6 /128 pin");
}

/* ================================================================
 * 4d. pin failure -> rc -1 before any catch-all is attempted
 * ================================================================ */
static void
test_pin_failure(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "203.0.113.9 via 203.0.113.1 dev eth0 src 192.0.2.5 uid 0\n");
    fake_cmd_set_fail_substr("replace|203.0.113.9/32");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, -1, "pin-failure rc");
    ASSERT_EQ_INT(p.routing_configured, 0, "pin-failure routing_configured 0");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "replace|0.0.0.0/1") == NULL,
                "pin-failure: no catch-all ever attempted");

    fake_cmd_clear_fail();
}

/* ================================================================
 * 4e. HIGH v4 catch-all failure -> rollback deletes the installed LOW
 * ================================================================ */
static void
test_high_catchall_failure_rollback(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "203.0.113.9 via 203.0.113.1 dev eth0 src 192.0.2.5 uid 0\n");
    fake_cmd_set_fail_substr("replace|128.0.0.0/1");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, -1, "high-catchall-failure rc");
    ASSERT_EQ_INT(p.routing_configured, 0, "high-catchall-failure routing stays 0");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    const char *seq[] = {
        "ip|route|replace|0.0.0.0/1|dev|mqvpn0",   /* installed */
        "ip|route|replace|128.0.0.0/1|dev|mqvpn0", /* fails */
        "ip|route|del|0.0.0.0/1|dev|mqvpn0",       /* rollback removes LOW */
        "ip|route|del|128.0.0.0/1|dev|mqvpn0",
        "ip|-4|route|del|203.0.113.9/32|via|203.0.113.1|dev|eth0",
    };
    assert_log_order(log, seq, 5, "high-catchall-failure rollback sequence");

    fake_cmd_clear_fail();
}

/* ================================================================
 * 5. discovery failure -> rc -1, nothing else attempted
 * ================================================================ */
static void
test_discovery_failure(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    set_route_get_output(e, "203.0.113.9 via 203.0.113.1 dev eth0\n");
    fake_cmd_set_fail_substr("route|get");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, -1, "discovery-failure rc");
    ASSERT_EQ_INT(p.routing_configured, 0, "discovery-failure routing_configured 0");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "route|replace|") == NULL,
                "discovery-failure: no route ever added");

    fake_cmd_clear_fail();
}

/* ================================================================
 * 5b. discovery output without a `dev` token -> parse failure, rc -1
 * ================================================================ */
static void
test_discovery_no_dev_token(fake_cmd_env_t *e)
{
    fake_cmd_reset(e);
    /* Command exits 0 but the output carries no `dev` — discover_route's
     * iface[0] check must reject it. */
    set_route_get_output(e, "203.0.113.9 via 203.0.113.1 src 192.0.2.5 uid 0\n");

    platform_ctx_t p;
    init_ctx(&p);

    int rc = setup_routes(&p);
    ASSERT_EQ_INT(rc, -1, "no-dev-token rc");
    ASSERT_EQ_INT(p.routing_configured, 0, "no-dev-token routing_configured 0");

    char log[4096];
    fake_cmd_read_log(e, log, sizeof(log));
    ASSERT_TRUE(strstr(log, "route|replace|") == NULL,
                "no-dev-token: no route ever added");
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
    test_onlink_no_pin(&e);
    test_catchall_failure_rollback(&e);
    test_v6_catchalls(&e);
    test_v6_high_failure_rollback(&e);
    test_v6_server_pin(&e);
    test_pin_failure(&e);
    test_high_catchall_failure_rollback(&e);
    test_discovery_failure(&e);
    test_discovery_no_dev_token(&e);

    fake_cmd_env_cleanup(&e);

    printf("\n=== test_routing_linux: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
