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
 * On Windows the clock counts the interrupt time (QueryInterruptTimePrecise),
 * which likewise never steps and keeps counting through sleep and hibernate.
 */

#include "mqvpn_internal.h"

#ifdef _WIN32
#  include <windows.h>
#else
#  include <sys/time.h>
#  include <time.h>
#endif

#ifdef _WIN32
typedef VOID(WINAPI *query_interrupt_time_fn)(PULONGLONG);

static uint64_t
real_boot_us(void)
{
    /* Resolved at run time: kernel32.dll exports it from Windows 10 on, but
     * not every SDK's kernel32.lib does. Racing threads store the same value. */
    static query_interrupt_time_fn query;
    if (!query)
        query = (query_interrupt_time_fn)(void (*)(void))GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "QueryInterruptTimePrecise");
    if (!query) return GetTickCount64() * 1000; /* before Windows 10; counts sleep too */
    ULONGLONG t;
    query(&t);
    return t / 10; /* 100 ns units */
}

static uint64_t
real_wall_us(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return t / 10 - 11644473600000000ULL; /* FILETIME epoch → Unix epoch, in µs */
}

#  define OFFSET_LOAD(p) \
      ((uint64_t)InterlockedCompareExchange64((volatile LONG64 *)(p), 0, 0))
#  define OFFSET_INIT(p, mine) \
      ((uint64_t)InterlockedCompareExchange64((volatile LONG64 *)(p), (LONG64)(mine), 0))
#  define OFFSET_RESET(p) InterlockedExchange64((volatile LONG64 *)(p), 0)
#else
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

static uint64_t
offset_init(uint64_t *p, uint64_t mine)
{
    uint64_t prev = 0;
    __atomic_compare_exchange_n(p, &prev, mine, false, __ATOMIC_ACQ_REL,
                                __ATOMIC_ACQUIRE);
    return prev;
}

#  define OFFSET_LOAD(p)       __atomic_load_n((p), __ATOMIC_ACQUIRE)
#  define OFFSET_INIT(p, mine) offset_init((p), (mine))
#  define OFFSET_RESET(p)      __atomic_store_n((p), 0, __ATOMIC_RELEASE)
#endif

static uint64_t (*s_boot_us)(void) = real_boot_us;
static uint64_t (*s_wall_us)(void) = real_wall_us;

/* Unix time minus the boot clock at the first reading, modulo 2^64; 0 until
 * then. The first reading in the process wins. */
static uint64_t s_unix_offset_us;

uint64_t
mqvpn_clock_us(void)
{
    uint64_t boot = s_boot_us();
    uint64_t off = OFFSET_LOAD(&s_unix_offset_us);
    if (off == 0) {
        uint64_t mine = s_wall_us() - boot;
        uint64_t prev = OFFSET_INIT(&s_unix_offset_us, mine);
        off = prev ? prev : mine;
    }
    return boot + off;
}

void
mqvpn_clock_test_sources(uint64_t (*boot_us)(void), uint64_t (*wall_us)(void))
{
    s_boot_us = boot_us ? boot_us : real_boot_us;
    s_wall_us = wall_us ? wall_us : real_wall_us;
    OFFSET_RESET(&s_unix_offset_us); /* a new process */
}

/*
 * xquic's clock is process-wide: xqc_engine_set_callback() stores
 * monotonic_ts in one global pointer, and the callback gets no context, so
 * every engine of the process runs on the clock of the engine created last.
 * All of mqvpn's engines in a process therefore share one clock: this
 * file's, or the clock_fn that clients inject (mqvpn_config_set_clock). An
 * engine on another clock is refused while others run, since switching the
 * pointer would retime their pending timers; the clock goes back to the
 * default when the last engine is gone. Not locked: like xquic's pointers,
 * this assumes that clients and servers are created and destroyed from one
 * thread at a time.
 */
static mqvpn_clock_fn s_xqc_clock_fn;
static void *s_xqc_clock_ctx;
static unsigned s_xqc_clock_users;

int
mqvpn_xqc_clock_acquire(mqvpn_clock_fn fn, void *ctx)
{
    if (s_xqc_clock_users > 0 && (fn != s_xqc_clock_fn || ctx != s_xqc_clock_ctx))
        return -1;
    s_xqc_clock_fn = fn;
    s_xqc_clock_ctx = ctx;
    s_xqc_clock_users++;
    return 0;
}

void
mqvpn_xqc_clock_release(void)
{
    if (s_xqc_clock_users == 0) return;
    if (--s_xqc_clock_users == 0) {
        s_xqc_clock_fn = NULL;
        s_xqc_clock_ctx = NULL;
    }
}

uint64_t
mqvpn_xqc_clock_now(void)
{
    if (s_xqc_clock_fn) return s_xqc_clock_fn(s_xqc_clock_ctx);
    return mqvpn_clock_us();
}
