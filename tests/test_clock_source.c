// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_clock_source.c — mqvpn_clock_us (src/mqvpn_clock.c) on its own, so it
 * also runs on Windows, where test_clock (xquic's private token functions)
 * does not build:
 *   - the clock reads Unix time at its first reading and does not follow a
 *     step of the wall clock after it (simulated sources);
 *   - on the real sources it reads Unix time and never goes back.
 * Own checks, not assert(): the Windows CI build is Release.
 */

#include "mqvpn_internal.h"

#include <stdio.h>
#include <time.h>

#define SEC 1000000ULL

static int g_failed;

#define CHECK(cond, what)                                               \
    do {                                                                \
        if (cond) {                                                     \
            printf("  %-66s PASS\n", what);                             \
        } else {                                                        \
            printf("  %-66s FAIL (%s:%d)\n", what, __FILE__, __LINE__); \
            g_failed = 1;                                               \
        }                                                               \
    } while (0)

static uint64_t g_boot_us, g_wall_us;

static uint64_t
src_boot(void)
{
    return g_boot_us;
}

static uint64_t
src_wall(void)
{
    return g_wall_us;
}

static void
test_wall_step(void)
{
    printf("wall clock step:\n");
    uint64_t w = (uint64_t)time(NULL) * SEC;
    g_boot_us = 1000 * SEC;
    g_wall_us = w;
    mqvpn_clock_test_sources(src_boot, src_wall);
    uint64_t t0 = mqvpn_clock_us();
    CHECK(t0 == w, "the clock reads Unix time at its first reading");
    g_boot_us += SEC;
    g_wall_us -= 60 * SEC; /* NTP steps the wall clock back */
    uint64_t t1 = mqvpn_clock_us();
    g_boot_us += SEC;
    g_wall_us += 180 * SEC; /* and forward */
    uint64_t t2 = mqvpn_clock_us();
    CHECK(t1 == t0 + SEC && t2 == t1 + SEC,
          "steps of the wall clock do not move the clock");
    mqvpn_clock_test_sources(NULL, NULL);
}

static void
test_real_sources(void)
{
    printf("real sources:\n");
    mqvpn_clock_test_sources(NULL, NULL);
    uint64_t before = (uint64_t)time(NULL) * SEC;
    uint64_t t = mqvpn_clock_us();
    uint64_t after = ((uint64_t)time(NULL) + 1) * SEC;
    CHECK(t >= before && t <= after, "the clock reads Unix time");
    int back = 0;
    for (int i = 0; i < 100000; i++) {
        uint64_t n = mqvpn_clock_us();
        if (n < t) back = 1;
        t = n;
    }
    CHECK(!back, "the clock never goes back");
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("test_clock_source: mqvpn_clock_us\n");
    test_wall_step();
    test_real_sources();
    printf(g_failed ? "test_clock_source: FAIL\n" : "test_clock_source: PASS\n");
    return g_failed;
}
