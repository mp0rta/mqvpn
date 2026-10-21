// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_clock.c — the clock of the library's timers and of its xquic engines
 *
 * Not the wall clock, which NTP or an admin can step: xquic would take a step
 * as an RTT sample and as timer expiries. The clock counts CLOCK_BOOTTIME
 * (CLOCK_MONOTONIC where it does not exist), which never steps and keeps
 * counting through a suspend, so an idle timeout still fires on resume.
 *
 * It reads Unix time when the process first reads it and keeps that offset
 * from CLOCK_BOOTTIME: xquic also stamps the expiry of its address-validation
 * tokens with this clock (xqc_conn_gen_token, xqc_conn_check_token), and a
 * token outlives the process and the boot, so its expiry stays in Unix
 * seconds, comparable across restarts, reboots and versions. A step of the
 * wall clock after that first reading moves token expiry by the step until
 * the process restarts; the timers never see it.
 *
 * Windows keeps the wall clock.
 */

#include "mqvpn_internal.h"

#ifdef _WIN32
#  include <windows.h>
#else
#  include <sys/time.h>
#  include <time.h>
#endif

#ifndef _WIN32
static uint64_t
real_boot_us(void)
{
    struct timespec ts;
#  ifdef CLOCK_BOOTTIME
    clock_gettime(CLOCK_BOOTTIME, &ts);
#  else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#  endif
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

static uint64_t
real_wall_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

static uint64_t (*s_boot_us)(void) = real_boot_us;
static uint64_t (*s_wall_us)(void) = real_wall_us;

/* Unix time minus CLOCK_BOOTTIME at the first reading, modulo 2^64; 0 until
 * then. The first reading in the process wins. */
static uint64_t s_unix_offset_us;
#endif

uint64_t
mqvpn_clock_us(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return t / 10 - 11644473600000000ULL; /* FILETIME epoch → Unix epoch, in µs */
#else
    uint64_t boot = s_boot_us();
    uint64_t off = __atomic_load_n(&s_unix_offset_us, __ATOMIC_ACQUIRE);
    if (off == 0) {
        uint64_t mine = s_wall_us() - boot;
        if (__atomic_compare_exchange_n(&s_unix_offset_us, &off, mine, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            off = mine;
    }
    return boot + off;
#endif
}

void
mqvpn_clock_test_sources(uint64_t (*boot_us)(void), uint64_t (*wall_us)(void))
{
#ifdef _WIN32
    (void)boot_us;
    (void)wall_us;
#else
    s_boot_us = boot_us ? boot_us : real_boot_us;
    s_wall_us = wall_us ? wall_us : real_wall_us;
    __atomic_store_n(&s_unix_offset_us, 0, __ATOMIC_RELEASE); /* a new process */
#endif
}
