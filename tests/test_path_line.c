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

    /* path_event fires inside add_path, before the slot stores the handle */
    struct {
        char iface[16];
        mqvpn_path_handle_t handle;
    } slots[2] = {{"eth0", 1}, {"wlan0", -1}};
    const char *f;
    f = platform_path_iface(slots[0].iface, &slots[0].handle, sizeof(slots[0]), 2, 3,
                            "enp5s0");
    platform_fmt_path_line(buf, sizeof(buf), 3, f, MQVPN_PATH_PENDING);
    check(buf, "path 3 (enp5s0) -> pending");
    f = platform_path_iface(slots[0].iface, &slots[0].handle, sizeof(slots[0]), 2, 1,
                            "enp5s0");
    platform_fmt_path_line(buf, sizeof(buf), 1, f, MQVPN_PATH_ACTIVE);
    check(buf, "path 1 (eth0) -> active");
    f = platform_path_iface(slots[0].iface, &slots[0].handle, sizeof(slots[0]), 2, 9,
                            NULL);
    platform_fmt_path_line(buf, sizeof(buf), 9, f, MQVPN_PATH_ACTIVE);
    check(buf, "path 9 (?) -> active");

    printf("test_path_line: %s\n", g_fail ? "FAILED" : "ok");
    return g_fail ? 1 : 0;
}
