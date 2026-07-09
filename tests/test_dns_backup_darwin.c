// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_dns_backup_darwin.c — unit tests for
 * mqvpn_dns_backup_format_line() / mqvpn_dns_backup_parse_line()
 * (src/platform/darwin/dns.c), declared in posix/dns.h.
 *
 * Format: "<service>\t<server1> <server2> ...\n"; value "Empty" = unset.
 * Runs unprivileged: both functions are pure buffer-to-buffer formatters,
 * no networksetup(8) invocation, no filesystem I/O.
 *
 * parse_line's trailing-newline contract (verified against the darwin/
 * dns.c implementation): it strips trailing '\n'/'\r' if present but does
 * NOT require one — a line without a trailing newline parses identically
 * to one with it. This matters because the last line of a backup file
 * written without a final newline (or a line handed in already
 * newline-stripped by a caller) must still round-trip.
 */
#include "dns.h"
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

/* Round-trip helper: format(service, servers) then parse the formatted
 * line back out, asserting both fields match the originals. */
static void
assert_roundtrip(const char *service, const char *servers, const char *tag)
{
    char line[512];
    int rc = mqvpn_dns_backup_format_line(line, sizeof(line), service, servers);
    ASSERT_EQ_INT(rc, 0, tag);

    char svc_out[128], srv_out[256];
    rc = mqvpn_dns_backup_parse_line(line, svc_out, sizeof(svc_out), srv_out,
                                     sizeof(srv_out));
    ASSERT_EQ_INT(rc, 0, tag);
    ASSERT_EQ_STR(svc_out, service, tag);
    ASSERT_EQ_STR(srv_out, servers, tag);
}

int
main(void)
{
    /* Normal service round-trip. */
    assert_roundtrip("Wi-Fi", "1.1.1.1 8.8.8.8", "roundtrip-wifi");

    /* Space-containing service name round-trip. */
    assert_roundtrip("Thunderbolt Bridge", "1.1.1.1 8.8.8.8", "roundtrip-space-service");

    /* "Empty" value (the sentinel for "service currently has no DNS
     * servers configured") round-trips like any other servers string. */
    assert_roundtrip("Wi-Fi", "Empty", "roundtrip-empty-value");

    /* TAB inside service name -> format rejects (would corrupt the
     * service/servers field boundary). */
    {
        char line[512];
        int rc = mqvpn_dns_backup_format_line(line, sizeof(line), "Wi\tFi", "1.1.1.1");
        ASSERT_EQ_INT(rc, -1, "format-tab-in-service");
    }

    /* Newline inside service name -> format rejects (would split one
     * logical record into two lines). */
    {
        char line[512];
        int rc = mqvpn_dns_backup_format_line(line, sizeof(line), "Wi\nFi", "1.1.1.1");
        ASSERT_EQ_INT(rc, -1, "format-newline-in-service");
    }

    /* Newline inside servers -> format rejects, same reason. */
    {
        char line[512];
        int rc =
            mqvpn_dns_backup_format_line(line, sizeof(line), "Wi-Fi", "1.1.1.1\n8.8.8.8");
        ASSERT_EQ_INT(rc, -1, "format-newline-in-servers");
    }

    /* parse: line missing the TAB field separator entirely -> -1. */
    {
        char svc[64], srv[64];
        int rc = mqvpn_dns_backup_parse_line("Wi-Fi 1.1.1.1\n", svc, sizeof(svc), srv,
                                             sizeof(srv));
        ASSERT_EQ_INT(rc, -1, "parse-missing-tab");
    }

    /* parse: empty service (line starts with the TAB) -> -1. */
    {
        char svc[64], srv[64];
        int rc = mqvpn_dns_backup_parse_line("\t1.1.1.1\n", svc, sizeof(svc), srv,
                                             sizeof(srv));
        ASSERT_EQ_INT(rc, -1, "parse-empty-service");
    }

    /* parse: service too long for the caller's output buffer -> -1
     * (svc_len is 4, "Wi-Fi" needs 6 bytes incl. NUL). */
    {
        char svc[4], srv[64];
        int rc = mqvpn_dns_backup_parse_line("Wi-Fi\t1.1.1.1\n", svc, sizeof(svc), srv,
                                             sizeof(srv));
        ASSERT_EQ_INT(rc, -1, "parse-service-truncation");
    }

    /* parse: servers value too long for the caller's output buffer -> -1
     * (srv_len is 4, "1.1.1.1 8.8.8.8" needs 16 bytes incl. NUL). */
    {
        char svc[64], srv[4];
        int rc = mqvpn_dns_backup_parse_line("Wi-Fi\t1.1.1.1 8.8.8.8\n", svc, sizeof(svc),
                                             srv, sizeof(srv));
        ASSERT_EQ_INT(rc, -1, "parse-servers-truncation");
    }

    /* format: buffer too small for the composed "service\tservers\n"
     * output -> -1 (snprintf truncation is detected, not silently
     * accepted). */
    {
        char line[8]; /* "Wi-Fi\t1.1.1.1\n" needs 15 bytes incl. NUL */
        int rc = mqvpn_dns_backup_format_line(line, sizeof(line), "Wi-Fi", "1.1.1.1");
        ASSERT_EQ_INT(rc, -1, "format-buffer-too-small");
    }

    /* parse: empty servers field ("Wi-Fi\t\n") -> ACCEPTED with
     * servers="". This pins the CURRENT implementation behavior: the tab
     * is present and the service is non-empty, so the (newline-stripped)
     * empty value passes the length checks. Note the writer side never
     * produces this line — a service with no DNS is recorded as the
     * literal "Empty" — so an empty field only appears in a hand-edited
     * or corrupted backup. If it ever reaches restore, it would become an
     * empty networksetup argument (hardware-verify item: what
     * `networksetup -setdnsservers <svc> ""` actually does). */
    {
        char svc[64], srv[64];
        int rc =
            mqvpn_dns_backup_parse_line("Wi-Fi\t\n", svc, sizeof(svc), srv, sizeof(srv));
        ASSERT_EQ_INT(rc, 0, "parse-empty-servers-accepted");
        ASSERT_EQ_STR(svc, "Wi-Fi", "parse-empty-servers-service");
        ASSERT_EQ_STR(srv, "", "parse-empty-servers-value");
    }

    /* parse: only the FIRST tab is the field separator — embedded tabs
     * beyond it stay verbatim in the servers value (parse_line uses
     * strchr, not a full split; the format side never emits such a line
     * since servers are space-joined, so this only pins how a foreign
     * line is read back). */
    {
        char svc[64], srv[64];
        int rc = mqvpn_dns_backup_parse_line("Wi-Fi\t1.1.1.1\t8.8.8.8\n", svc,
                                             sizeof(svc), srv, sizeof(srv));
        ASSERT_EQ_INT(rc, 0, "parse-second-tab-rc");
        ASSERT_EQ_STR(svc, "Wi-Fi", "parse-second-tab-service");
        ASSERT_EQ_STR(srv, "1.1.1.1\t8.8.8.8", "parse-second-tab-kept-in-servers");
    }

    /* parse: a line with NO trailing newline parses identically to one
     * with — parse_line does not require a line terminator. */
    {
        char svc[64], srv[64];
        int rc = mqvpn_dns_backup_parse_line("Wi-Fi\t1.1.1.1 8.8.8.8", svc, sizeof(svc),
                                             srv, sizeof(srv));
        ASSERT_EQ_INT(rc, 0, "parse-no-trailing-newline");
        ASSERT_EQ_STR(svc, "Wi-Fi", "parse-no-trailing-newline-service");
        ASSERT_EQ_STR(srv, "1.1.1.1 8.8.8.8", "parse-no-trailing-newline-servers");
    }

    printf("\n=== test_dns_backup_darwin: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
