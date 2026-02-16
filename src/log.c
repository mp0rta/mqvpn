#include "log.h"

#include <time.h>
#include <sys/time.h>

static mpvpn_log_level_t g_log_level = MPVPN_LOG_INFO;

static const char *level_str[] = {
    [MPVPN_LOG_DEBUG] = "DBG",
    [MPVPN_LOG_INFO]  = "INF",
    [MPVPN_LOG_WARN]  = "WRN",
    [MPVPN_LOG_ERROR] = "ERR",
};

void
mpvpn_log_set_level(mpvpn_log_level_t level)
{
    g_log_level = level;
}

void
mpvpn_log(mpvpn_log_level_t level, const char *fmt, ...)
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
