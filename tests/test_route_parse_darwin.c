// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_route_parse_darwin.c — canned-output unit tests for
 * mqvpn_parse_route_get_output() (src/platform/darwin/routing.c).
 *
 * Runs unprivileged: the parser is a pure string-to-string function, fed
 * canned `route -n get` text — no `route(8)` invocation, no network I/O.
 *
 * The canned multi-line shapes below (indented "   key: value" lines,
 * interleaved with unrelated keys such as "route to:"/"destination:"/
 * "flags:") are an ASSUMPTION about real `route -n get` output pending
 * hardware verification — see the block comment above
 * mqvpn_parse_route_get_output() in routing.c. If real macOS output
 * differs in indentation or key set, only the canned strings here (and
 * the parser's tolerance for them) need to change; the parser's IP-vs-
 * non-IP gateway classification is independent of exact formatting.
 *
 * Style: bare assert(), mirroring tests/test_route_check.c (same domain:
 * a small pure predicate/parser, exercised with a handful of fixed
 * inputs).
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

int mqvpn_parse_route_get_output(const char *out, char *gateway, size_t gw_len,
                                 char *iface, size_t if_len);

int
main(void)
{
    char gw[INET6_ADDRSTRLEN];
    char ifc[IFNAMSIZ];

    /* (a) v4 gateway + interface, realistic route(8) shape. */
    {
        const char *in = "   route to: 10.0.0.1\n"
                         "destination: 10.0.0.1\n"
                         "       gateway: 192.168.1.1\n"
                         "     interface: en0\n"
                         "         flags: <UP,GATEWAY,DONE>\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(strcmp(gw, "192.168.1.1") == 0);
        assert(strcmp(ifc, "en0") == 0);
    }

    /* (b) v6 gateway (fe80::1 style) -> accepted. */
    {
        const char *in = "   gateway: fe80::1\n"
                         "   interface: en0\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(strcmp(gw, "fe80::1") == 0);
        assert(strcmp(ifc, "en0") == 0);
    }

    /* (c) zoned v6 fe80::1%en0 -> accepted, stored WITH the zone. */
    {
        const char *in = "   gateway: fe80::1%en0\n"
                         "   interface: en0\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(strcmp(gw, "fe80::1%en0") == 0);
        assert(strcmp(ifc, "en0") == 0);
    }

    /* (d) on-link "link#4" -> gateway empty, iface still parsed, rc=0. */
    {
        const char *in = "   gateway: link#4\n"
                         "   interface: en0\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(gw[0] == '\0');
        assert(strcmp(ifc, "en0") == 0);
    }

    /* (e) lladdr MAC ("gateway: a4:83:e7:12:34:56", an LLINFO cloned
     * route) -> gateway empty (fails both inet_pton(AF_INET) and
     * inet_pton(AF_INET6)). */
    {
        const char *in = "   gateway: a4:83:e7:12:34:56\n"
                         "   interface: en0\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(gw[0] == '\0');
        assert(strcmp(ifc, "en0") == 0);
    }

    /* (f) bogus non-IP token -> gateway empty. */
    {
        const char *in = "   gateway: bogus\n"
                         "   interface: en0\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(gw[0] == '\0');
        assert(strcmp(ifc, "en0") == 0);
    }

    /* (g) "link#4%en0" -> the '%' splits off "link#4" as the address
     * part; "link#4" fails inet_pton for both families -> gateway
     * empty. */
    {
        const char *in = "   gateway: link#4%en0\n"
                         "   interface: en0\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(gw[0] == '\0');
        assert(strcmp(ifc, "en0") == 0);
    }

    /* (h) "%en0" -> zone at position 0 leaves an empty address part
     * (ip_len == 0), which the parser explicitly excludes -> gateway
     * empty. */
    {
        const char *in = "   gateway: %en0\n"
                         "   interface: en0\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(gw[0] == '\0');
        assert(strcmp(ifc, "en0") == 0);
    }

    /* (i) 49-char non-IP string (no '%') -> ip_len (49) >= sizeof(ip_part)
     * (INET6_ADDRSTRLEN == 46) -> the length guard rejects it before even
     * trying inet_pton -> gateway empty. */
    {
        char value[50];
        memset(value, 'x', sizeof(value) - 1);
        value[sizeof(value) - 1] = '\0';
        assert(strlen(value) == 49);

        char in[256];
        snprintf(in, sizeof(in), "   gateway: %s\n   interface: en0\n", value);
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(gw[0] == '\0');
        assert(strcmp(ifc, "en0") == 0);
    }

    /* (j) no gateway line at all -> rc=0, gateway empty, iface parsed. */
    {
        const char *in = "   interface: en0\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(gw[0] == '\0');
        assert(strcmp(ifc, "en0") == 0);
    }

    /* (k) no interface line -> rc=-1 (iface not found is the sole error
     * condition). */
    {
        const char *in = "   gateway: 192.168.1.1\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == -1);
    }

    /* (l) empty gateway value ("gateway:" with nothing after the colon)
     * -> gateway empty, iface still parsed, rc=0. */
    {
        const char *in = "   gateway:\n"
                         "   interface: en0\n";
        int rc = mqvpn_parse_route_get_output(in, gw, sizeof(gw), ifc, sizeof(ifc));
        assert(rc == 0);
        assert(gw[0] == '\0');
        assert(strcmp(ifc, "en0") == 0);
    }

    printf("test_route_parse_darwin: all OK\n");
    return 0;
}
