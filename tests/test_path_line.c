// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_path_line.c — the "path <handle> (<iface>) -> <status>" INFO line
 * (src/platform/path_line.h). The mqvpn-desktop GUI parses it, so its shape
 * is a compatibility surface. Own checks, not assert(): Release CI keeps them.
 */
#include "libmqvpn.h"
#include "platform/path_line.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;

static void
check(const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        g_fail++;
        fprintf(stderr, "FAIL: got \"%s\" want \"%s\"\n", got, want);
    }
}

int
main(void)
{
    char buf[128];

    platform_fmt_path_line(buf, sizeof(buf), 1, "enp5s0", MQVPN_PATH_DEGRADED);
    check(buf, "path 1 (enp5s0) -> degraded");
    /* handle not in the slot table */
    platform_fmt_path_line(buf, sizeof(buf), 9, NULL, MQVPN_PATH_ACTIVE);
    check(buf, "path 9 (?) -> active");
    /* configured "" = any interface */
    platform_fmt_path_line(buf, sizeof(buf), 2, "", MQVPN_PATH_CLOSED);
    check(buf, "path 2 (?) -> closed");

    /* PLATFORM_PATH_IFACE: slot match (any slot), else adding iface, else NULL */
    struct {
        struct {
            char iface[256];
            mqvpn_path_handle_t handle;
        } paths[3];
        int n_paths;
        const char *adding_iface;
    } ctx = {{{"eth0", 1}, {"wlan0", -1}, {"wwan0", 7}}, 3, "enp5s0"};
    const char *f;

    /* path_event fires inside add_path, before the slot stores the handle */
    PLATFORM_PATH_IFACE(f, &ctx, 3);
    platform_fmt_path_line(buf, sizeof(buf), 3, f, MQVPN_PATH_PENDING);
    check(buf, "path 3 (enp5s0) -> pending");
    PLATFORM_PATH_IFACE(f, &ctx, 1);
    platform_fmt_path_line(buf, sizeof(buf), 1, f, MQVPN_PATH_ACTIVE);
    check(buf, "path 1 (eth0) -> active");
    /* a later slot returns its own iface, not slot 0's */
    PLATFORM_PATH_IFACE(f, &ctx, 7);
    platform_fmt_path_line(buf, sizeof(buf), 7, f, MQVPN_PATH_STANDBY);
    check(buf, "path 7 (wwan0) -> standby");
    ctx.adding_iface = NULL;
    PLATFORM_PATH_IFACE(f, &ctx, 9);
    platform_fmt_path_line(buf, sizeof(buf), 9, f, MQVPN_PATH_ACTIVE);
    check(buf, "path 9 (?) -> active");

    /* 255-byte Windows name: the whole line, suffix included, must fit */
    {
        char longbuf[PLATFORM_PATH_LINE_MAX], want[PLATFORM_PATH_LINE_MAX + 8];
        char name[256];
        memset(name, 'x', 255);
        name[255] = '\0';
        platform_fmt_path_line(longbuf, sizeof(longbuf), 9223372036854775807LL, name,
                               MQVPN_PATH_DEGRADED);
        snprintf(want, sizeof(want), "path 9223372036854775807 (%s) -> degraded", name);
        check(longbuf, want);
    }

    printf("test_path_line: %s\n", g_fail ? "FAILED" : "ok");
    return g_fail ? 1 : 0;
}
