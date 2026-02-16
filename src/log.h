#ifndef MPVPN_LOG_H
#define MPVPN_LOG_H

#include <stdio.h>
#include <stdarg.h>

typedef enum {
    MPVPN_LOG_DEBUG = 0,
    MPVPN_LOG_INFO,
    MPVPN_LOG_WARN,
    MPVPN_LOG_ERROR,
} mpvpn_log_level_t;

void mpvpn_log_set_level(mpvpn_log_level_t level);
void mpvpn_log(mpvpn_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define LOG_DBG(fmt, ...)  mpvpn_log(MPVPN_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...)  mpvpn_log(MPVPN_LOG_INFO,  fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...)  mpvpn_log(MPVPN_LOG_WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)  mpvpn_log(MPVPN_LOG_ERROR, fmt, ##__VA_ARGS__)

#endif /* MPVPN_LOG_H */
