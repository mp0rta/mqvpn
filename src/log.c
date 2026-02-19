#include "log.h"

#include <time.h>
#include <sys/time.h>

static mqvpn_log_level_t g_log_level = MQVPN_LOG_INFO;

static const char *level_str[] = {
    [MQVPN_LOG_DEBUG] = "DBG",
    [MQVPN_LOG_INFO]  = "INF",
    [MQVPN_LOG_WARN]  = "WRN",
    [MQVPN_LOG_ERROR] = "ERR",
};

void
mqvpn_log_set_level(mqvpn_log_level_t level)
{
    g_log_level = level;
}

void
mqvpn_log(mqvpn_log_level_t level, const char *fmt, ...)
{
    if (level < g_log_level) {
        return;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);

    fprintf(stderr, "%02d:%02d:%02d.%03d [%s] ",
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            (int)(tv.tv_usec / 1000), level_str[level]);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}
