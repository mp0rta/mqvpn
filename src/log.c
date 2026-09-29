// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "log.h"

#include <time.h>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <sys/time.h>
#endif

static mqvpn_log_level_t g_log_level = MQVPN_LOG_INFO;
static mqvpn_log_fn g_log_sink = NULL;
static void *g_log_sink_ctx = NULL;

static const char *level_str[] = {
    [MQVPN_LOG_DEBUG] = "DBG",
    [MQVPN_LOG_INFO] = "INF",
    [MQVPN_LOG_WARN] = "WRN",
    [MQVPN_LOG_ERROR] = "ERR",
};

void
mqvpn_log_set_level(mqvpn_log_level_t level)
{
    g_log_level = level;
}

void
mqvpn_log_set_sink(mqvpn_log_fn fn, void *user_ctx)
{
    g_log_sink = fn;
    g_log_sink_ctx = user_ctx;
}

void
mqvpn_log(mqvpn_log_level_t level, const char *fmt, ...)
{
    if (level < g_log_level) {
        return;
    }

    mqvpn_log_fn sink = g_log_sink;
    if (sink) {
        /* Bounded buffer on the sink path only; the stderr path below keeps
         * streaming through vfprintf as it always has. */
        char buf[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        sink(level, buf, g_log_sink_ctx);
        return;
    }

#ifdef _WIN32
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(stderr, "%02d:%02d:%02d.%03d [%s] ", st.wHour, st.wMinute, st.wSecond,
            st.wMilliseconds, level_str[level]);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    fprintf(stderr, "%02d:%02d:%02d.%03d [%s] ", tm.tm_hour, tm.tm_min, tm.tm_sec,
            (int)(tv.tv_usec / 1000), level_str[level]);
#endif

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}
