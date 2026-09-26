// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_LOG_H
#define MQVPN_LOG_H

#include <stdio.h>
#include <stdarg.h>

#include "libmqvpn.h" /* mqvpn_log_fn, mqvpn_log_level_t (sole definition) */

void mqvpn_log_set_level(mqvpn_log_level_t level);

/* Process-wide sink for every global log line (the bundled binds,
 * path_state_machine, auth, ...). NULL restores the stderr writer, which is
 * the default — Linux, macOS and Windows never call this. The sink receives
 * the formatted message with no timestamp or level prefix and no trailing
 * newline (at most 1023 bytes; longer lines are truncated), on the thread
 * that logged, after the level filter; it must be safe from any thread and
 * must not log through mqvpn_log() itself. Set it once, before any
 * client exists. Hidden in libmqvpn.so like mqvpn_log itself: it exists
 * for the static-archive consumers whose stderr goes nowhere (Android
 * JNI -> logcat, iOS extension -> os_log). */
void mqvpn_log_set_sink(mqvpn_log_fn fn, void *user_ctx);
#ifdef _MSC_VER
void mqvpn_log(mqvpn_log_level_t level, const char *fmt, ...);
#else
void mqvpn_log(mqvpn_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
#endif

#define LOG_DBG(fmt, ...) mqvpn_log(MQVPN_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...) mqvpn_log(MQVPN_LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) mqvpn_log(MQVPN_LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) mqvpn_log(MQVPN_LOG_ERROR, fmt, ##__VA_ARGS__)

#endif /* MQVPN_LOG_H */
