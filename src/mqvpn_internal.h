/*
 * mqvpn_internal.h — Internal type definitions for libmqvpn
 *
 * NOT part of the public API. Do not install this header.
 */

#ifndef MQVPN_INTERNAL_H
#define MQVPN_INTERNAL_H

#include "libmqvpn.h"

/* ─── Constants ─── */

#define MQVPN_MAX_PATHS 4

/* ─── Config (opaque to callers) ─── */

struct mqvpn_config_s {
    char server_host[256];
    int server_port;
    char auth_key[256];
    int insecure;

    mqvpn_scheduler_t scheduler;
    mqvpn_log_level_t log_level;
    int multipath;
    int reconnect_enable;
    int reconnect_interval_sec;
    int killswitch_hint;

    /* Clock injection (Android: CLOCK_BOOTTIME) */
    mqvpn_clock_fn clock_fn;
    void *clock_ctx;

    /* Server-only fields */
    char listen_addr[256];
    int listen_port;
    char subnet[64];
    char subnet6[64];
    char tls_cert[256];
    char tls_key[256];
    int max_clients;
};

/* ─── State transition validation (M0-5) ─── */

int mqvpn_state_transition_valid(mqvpn_client_state_t from, mqvpn_client_state_t to);

#endif /* MQVPN_INTERNAL_H */
