// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_route_parse_darwin.c — canned-output unit tests for
 * mqvpn_parse_route_get_output() (src/platform/darwin/routing.c).
 *
 * Runs unprivileged: the parser is a pure string-to-string function, fed
 * canned `route -n get` text — no `route(8)` invocation, no network I/O.
 *
 * Case (a) is REAL `route -n get <server>` output captured on macOS 26.5
 * (arm64); the remaining cases (b)-(l) are synthetic edge cases probing the
 * gateway IP-vs-non-IP classification (link#N / lladdr / zoned v6 / length
 * guards), which is independent of exact route(8) framing. See the block
 * comment above mqvpn_parse_route_get_output() in routing.c.
 *
 * Assertions are discriminating (which vector, actual vs expected) on
 * purpose: the darwin CI job is the ONLY executor of this test, so an
 * ambiguous failure costs a full CI round trip to diagnose. The gw/ifc
 * output buffers are re-poisoned before every parser call so each vector
 * discriminates independently of case ordering (a stale-buffer bug in the
 * parser can't be masked by a previous vector's output).
 */
#include "platform_internal.h" /* mqvpn_parse_route_get_output — real
                                * prototype, so a signature change in
                                * routing.c breaks this TU at compile time
                                * instead of at runtime on darwin CI */
#include <stdio.h>
#include <string.h>

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

/* Fill an output buffer with a non-NUL poison pattern so a parser that
 * fails to write (or fails to NUL-terminate) a field is caught in THIS
 * vector, not masked by whatever the previous vector left behind. */
static void
poison(char *buf, size_t len)
{
    memset(buf, 'X', len - 1);
    buf[len - 1] = '\0';
}

int
main(void)
{
    char gw[INET6_ADDRSTRLEN];
    char ifc[IFNAMSIZ];
    int rc;

    /* (a) v4 gateway + interface, REAL `route -n get <server_ip>` output
     * captured on macOS 26.5 (arm64) — an off-link server reached via the
     * default route: note the extra "mask:" line and the trailing
     * recvpipe/sendpipe metrics table (a header row + a values row, both
     * colon-free so the parser skips them). Verifies the parser tolerates
     * real route(8) framing, not just the minimal shape. */
    {
        const char *in = "   route to: 160.251.143.149\n"
                         "destination: default\n"
                         "       mask: default\n"
                         "    gateway: 192.168.1.1\n"
                         "  interface: en0\n"
                         "      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
                         " recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  "
                         "hopcount      mtu     expire\n"
                         "       0         0         0         0         0      "
                         "    0      1500         0 \n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(a) v4-gateway rc");
        ASSERT_EQ_STR(gw, "192.168.1.1", "(a) v4-gateway gw");
        ASSERT_EQ_STR(ifc, "en0", "(a) v4-gateway iface");
    }

    /* (b) v6 gateway (fe80::1 style) -> accepted. */
    {
        const char *in = "   gateway: fe80::1\n"
                         "   interface: en0\n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(b) v6-gateway rc");
        ASSERT_EQ_STR(gw, "fe80::1", "(b) v6-gateway gw");
        ASSERT_EQ_STR(ifc, "en0", "(b) v6-gateway iface");
    }

    /* (c) zoned v6 fe80::1%en0 -> accepted, stored WITH the zone. */
    {
        const char *in = "   gateway: fe80::1%en0\n"
                         "   interface: en0\n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(c) zoned-v6 rc");
        ASSERT_EQ_STR(gw, "fe80::1%en0", "(c) zoned-v6 gw (zone kept)");
        ASSERT_EQ_STR(ifc, "en0", "(c) zoned-v6 iface");
    }

    /* (d) on-link "link#4" -> gateway empty, iface still parsed, rc=0. */
    {
        const char *in = "   gateway: link#4\n"
                         "   interface: en0\n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(d) link#N rc");
        ASSERT_EQ_STR(gw, "", "(d) link#N gw empty");
        ASSERT_EQ_STR(ifc, "en0", "(d) link#N iface");
    }

    /* (e) lladdr MAC ("gateway: a4:83:e7:12:34:56", an LLINFO cloned
     * route) -> gateway empty (fails both inet_pton(AF_INET) and
     * inet_pton(AF_INET6)). */
    {
        const char *in = "   gateway: a4:83:e7:12:34:56\n"
                         "   interface: en0\n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(e) lladdr rc");
        ASSERT_EQ_STR(gw, "", "(e) lladdr gw empty");
        ASSERT_EQ_STR(ifc, "en0", "(e) lladdr iface");
    }

    /* (f) bogus non-IP token -> gateway empty. */
    {
        const char *in = "   gateway: bogus\n"
                         "   interface: en0\n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(f) bogus rc");
        ASSERT_EQ_STR(gw, "", "(f) bogus gw empty");
        ASSERT_EQ_STR(ifc, "en0", "(f) bogus iface");
    }

    /* (g) "link#4%en0" -> the '%' splits off "link#4" as the address
     * part; "link#4" fails inet_pton for both families -> gateway
     * empty. */
    {
        const char *in = "   gateway: link#4%en0\n"
                         "   interface: en0\n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(g) link#N%zone rc");
        ASSERT_EQ_STR(gw, "", "(g) link#N%zone gw empty");
        ASSERT_EQ_STR(ifc, "en0", "(g) link#N%zone iface");
    }

    /* (h) "%en0" -> zone at position 0 leaves an empty address part
     * (ip_len == 0), which the parser explicitly excludes -> gateway
     * empty. */
    {
        const char *in = "   gateway: %en0\n"
                         "   interface: en0\n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(h) %zone-only rc");
        ASSERT_EQ_STR(gw, "", "(h) %zone-only gw empty");
        ASSERT_EQ_STR(ifc, "en0", "(h) %zone-only iface");
    }

    /* (i) 49-char non-IP string (no '%') -> ip_len (49) >= sizeof(ip_part)
     * (INET6_ADDRSTRLEN == 46) -> the length guard rejects it before even
     * trying inet_pton -> gateway empty. */
    {
        char value[50];
        memset(value, 'x', sizeof(value) - 1);
        value[sizeof(value) - 1] = '\0';
        ASSERT_EQ_INT((int)strlen(value), 49, "(i) fixture length");

        char in[256];
        snprintf(in, sizeof(in), "   gateway: %s\n   interface: en0\n", value);
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(i) 49-char rc");
        ASSERT_EQ_STR(gw, "", "(i) 49-char gw empty (length guard)");
        ASSERT_EQ_STR(ifc, "en0", "(i) 49-char iface");
    }

    /* (j) no gateway line at all -> rc=0, gateway empty, iface parsed. */
    {
        const char *in = "   interface: en0\n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(j) no-gateway-line rc");
        ASSERT_EQ_STR(gw, "", "(j) no-gateway-line gw empty");
        ASSERT_EQ_STR(ifc, "en0", "(j) no-gateway-line iface");
    }

    /* (k) no interface line -> rc=-1 (iface not found is the sole error
     * condition). */
    {
        const char *in = "   gateway: 192.168.1.1\n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, -1, "(k) no-interface-line rc");
    }

    /* (l) empty gateway value ("gateway:" with nothing after the colon)
     * -> gateway empty, iface still parsed, rc=0. */
    {
        const char *in = "   gateway:\n"
                         "   interface: en0\n";
        poison(gw, sizeof(gw));
        poison(ifc, sizeof(ifc));
        rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        ASSERT_EQ_INT(rc, 0, "(l) empty-gateway-value rc");
        ASSERT_EQ_STR(gw, "", "(l) empty-gateway-value gw empty");
        ASSERT_EQ_STR(ifc, "en0", "(l) empty-gateway-value iface");
    }

    printf("\n=== test_route_parse_darwin: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
