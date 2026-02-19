#ifndef MQVPN_LOG_H
#define MQVPN_LOG_H

#include <stdio.h>
#include <stdarg.h>

typedef enum {
    MQVPN_LOG_DEBUG = 0,
    MQVPN_LOG_INFO,
    MQVPN_LOG_WARN,
    MQVPN_LOG_ERROR,
} mqvpn_log_level_t;

void mqvpn_log_set_level(mqvpn_log_level_t level);
void mqvpn_log(mqvpn_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define LOG_DBG(fmt, ...)  mqvpn_log(MQVPN_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...)  mqvpn_log(MQVPN_LOG_INFO,  fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...)  mqvpn_log(MQVPN_LOG_WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)  mqvpn_log(MQVPN_LOG_ERROR, fmt, ##__VA_ARGS__)

#endif /* MQVPN_LOG_H */
