// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_sched_names.h — single source of truth for scheduler/CC
 * string<->enum mapping.
 *
 * Every parser (CLI --scheduler/--cc, JSON config builder) and every
 * formatter (server status/log labels) must go through the helpers here
 * instead of hand-duplicating the string tables. This is deliberately
 * xquic-free (unlike mqvpn_scheduler.h) so it can be included from
 * xquic-independent TUs (main.c, mqvpn_config.c, mqvpn_server.c) and from
 * unit tests that don't link xquic.
 *
 * Policy that stays OUT of this table (kept at call sites, per-surface):
 *   - whether "backup_fec" is accepted depends on the XQC_ENABLE_FEC /
 *     XQC_ENABLE_XOR build flags, and main.c's CLI surface enforces that
 *     gate while mqvpn_config.c's JSON surface does not (known, intentional
 *     drift — config format is a compatibility surface, do not unify).
 *     Look up the name here first, then apply the site-specific gate.
 */
#ifndef MQVPN_SCHED_NAMES_H
#define MQVPN_SCHED_NAMES_H

#include "libmqvpn.h"

#include <string.h>

/* X-macro row: X(enum_value, "canonical_name")
 * No accepted spelling currently has more than one alias across any parser
 * (verified against src/main.c, src/mqvpn_config.c as of this table's
 * introduction) — if an alias is ever added, add a row with the same
 * canonical name reused for to_name() and a distinct string for from_name(). */
#define MQVPN_SCHED_LIST(X)                 \
    X(MQVPN_SCHED_MINRTT, "minrtt")         \
    X(MQVPN_SCHED_WLB, "wlb")               \
    X(MQVPN_SCHED_BACKUP_FEC, "backup_fec") \
    X(MQVPN_SCHED_WLB_UDP_PIN, "wlb_udp_pin")

#define MQVPN_CC_LIST(X)       \
    X(MQVPN_CC_BBR2, "bbr2")   \
    X(MQVPN_CC_BBR, "bbr")     \
    X(MQVPN_CC_CUBIC, "cubic") \
    X(MQVPN_CC_NONE, "none")

#define MQVPN_REINJ_LIST(X)             \
    X(MQVPN_REINJ_OFF, "off")           \
    X(MQVPN_REINJ_DEADLINE, "deadline") \
    X(MQVPN_REINJ_IDLE, "idle")

/* mqvpn_sched_from_name: returns the enum value, or -1 if unrecognized. */
static inline int
mqvpn_sched_from_name(const char *s)
{
    if (!s) return -1;
#define MQVPN_SCHED_FROM_NAME_CASE(enum_val, str) \
    if (strcmp(s, str) == 0) return (int)(enum_val);
    MQVPN_SCHED_LIST(MQVPN_SCHED_FROM_NAME_CASE)
#undef MQVPN_SCHED_FROM_NAME_CASE
    return -1;
}

/* mqvpn_sched_from_name_n: like from_name() for a non-NUL-terminated token of
 * exactly len bytes (header value). Exact match, no trimming; never reads
 * past len. Returns the enum value, or -1. */
static inline int
mqvpn_sched_from_name_n(const char *s, size_t len)
{
    if (!s) return -1;
#define MQVPN_SCHED_FROM_NAME_N_CASE(enum_val, str) \
    if (len == sizeof(str) - 1 && memcmp(s, str, len) == 0) return (int)(enum_val);
    MQVPN_SCHED_LIST(MQVPN_SCHED_FROM_NAME_N_CASE)
#undef MQVPN_SCHED_FROM_NAME_N_CASE
    return -1;
}

/* mqvpn_sched_to_name: canonical name for status/log use. Returns "unknown"
 * for any value outside the table, matching the pre-refactor default case
 * in mqvpn_server.c's mqvpn_scheduler_label(). */
static inline const char *
mqvpn_sched_to_name(mqvpn_scheduler_t sched)
{
    switch (sched) {
#define MQVPN_SCHED_TO_NAME_CASE(enum_val, str) \
case enum_val: return str;
        MQVPN_SCHED_LIST(MQVPN_SCHED_TO_NAME_CASE)
#undef MQVPN_SCHED_TO_NAME_CASE
    default: return "unknown";
    }
}

static inline int
mqvpn_sched_is_valid(mqvpn_scheduler_t sched)
{
    switch (sched) {
#define MQVPN_SCHED_VALID_CASE(enum_val, str) \
case enum_val: return 1;
        MQVPN_SCHED_LIST(MQVPN_SCHED_VALID_CASE)
#undef MQVPN_SCHED_VALID_CASE
    default: return 0;
    }
}

static inline int
mqvpn_cc_from_name(const char *s)
{
    if (!s) return -1;
#define MQVPN_CC_FROM_NAME_CASE(enum_val, str) \
    if (strcmp(s, str) == 0) return (int)(enum_val);
    MQVPN_CC_LIST(MQVPN_CC_FROM_NAME_CASE)
#undef MQVPN_CC_FROM_NAME_CASE
    return -1;
}

static inline const char *
mqvpn_cc_to_name(mqvpn_cc_t cc)
{
    switch (cc) {
#define MQVPN_CC_TO_NAME_CASE(enum_val, str) \
case enum_val: return str;
        MQVPN_CC_LIST(MQVPN_CC_TO_NAME_CASE)
#undef MQVPN_CC_TO_NAME_CASE
    default: return "unknown";
    }
}

static inline int
mqvpn_cc_is_valid(mqvpn_cc_t cc)
{
    switch (cc) {
#define MQVPN_CC_VALID_CASE(enum_val, str) \
case enum_val: return 1;
        MQVPN_CC_LIST(MQVPN_CC_VALID_CASE)
#undef MQVPN_CC_VALID_CASE
    default: return 0;
    }
}

/* mqvpn_reinj_from_name: returns the enum value, or -1 if unrecognized. */
static inline int
mqvpn_reinj_from_name(const char *s)
{
    if (!s) return -1;
#define MQVPN_REINJ_FROM_NAME_CASE(enum_val, str) \
    if (strcmp(s, str) == 0) return (int)(enum_val);
    MQVPN_REINJ_LIST(MQVPN_REINJ_FROM_NAME_CASE)
#undef MQVPN_REINJ_FROM_NAME_CASE
    return -1;
}

/* mqvpn_reinj_to_name: canonical name for status/log use. Returns "unknown"
 * for any value outside the table. */
static inline const char *
mqvpn_reinj_to_name(mqvpn_reinjection_t reinj)
{
    switch (reinj) {
#define MQVPN_REINJ_TO_NAME_CASE(enum_val, str) \
case enum_val: return str;
        MQVPN_REINJ_LIST(MQVPN_REINJ_TO_NAME_CASE)
#undef MQVPN_REINJ_TO_NAME_CASE
    default: return "unknown";
    }
}

static inline int
mqvpn_reinj_is_valid(mqvpn_reinjection_t reinj)
{
    switch (reinj) {
#define MQVPN_REINJ_VALID_CASE(enum_val, str) \
case enum_val: return 1;
        MQVPN_REINJ_LIST(MQVPN_REINJ_VALID_CASE)
#undef MQVPN_REINJ_VALID_CASE
    default: return 0;
    }
}

/* Compile-time coverage check: this switch has no `default`, so -Wswitch
 * (built with -Werror in the project's CI sanitizer job, see AGENTS.md G11)
 * turns "a new mqvpn_scheduler_t enumerator was added to libmqvpn.h but not
 * to MQVPN_SCHED_LIST" into a build failure. Never called; exists purely for
 * the compiler to typecheck it. This is stronger than a row-count
 * _Static_assert: it checks membership in both directions (every enumerator
 * has a table row via -Wswitch, every table row names a real enumerator via
 * the case labels), not just cardinality — and the enum values themselves
 * are ABI-fixed in libmqvpn.h, so the case labels double as a pin. */
static inline void
mqvpn_sched_list_covers_enum_(mqvpn_scheduler_t sched)
{
    switch (sched) {
#define MQVPN_SCHED_COVERAGE_CASE(enum_val, str) \
case enum_val: break;
        MQVPN_SCHED_LIST(MQVPN_SCHED_COVERAGE_CASE)
#undef MQVPN_SCHED_COVERAGE_CASE
    }
}

static inline void
mqvpn_cc_list_covers_enum_(mqvpn_cc_t cc)
{
    switch (cc) {
#define MQVPN_CC_COVERAGE_CASE(enum_val, str) \
case enum_val: break;
        MQVPN_CC_LIST(MQVPN_CC_COVERAGE_CASE)
#undef MQVPN_CC_COVERAGE_CASE
    }
}

static inline void
mqvpn_reinj_list_covers_enum_(mqvpn_reinjection_t reinj)
{
    switch (reinj) {
#define MQVPN_REINJ_COVERAGE_CASE(enum_val, str) \
case enum_val: break;
        MQVPN_REINJ_LIST(MQVPN_REINJ_COVERAGE_CASE)
#undef MQVPN_REINJ_COVERAGE_CASE
    }
}

/* CONNECT-IP header that carries the scheduler name (request and response). */
#define MQVPN_SCHED_HDR_NAME "mqvpn-scheduler"

typedef enum {
    MQVPN_SCHED_NEG_NONE = 0, /* no request header: nothing to do */
    MQVPN_SCHED_NEG_APPLY,
    MQVPN_SCHED_NEG_DISABLED,
    MQVPN_SCHED_NEG_INVALID,
    MQVPN_SCHED_NEG_BACKUP_FEC,
    MQVPN_SCHED_NEG_SERVER_BACKUP_FEC,
    MQVPN_SCHED_NEG_ALREADY_SET,
} mqvpn_sched_neg_t;

/* Server-side decision for a client scheduler request. `requested` is the
 * from_name_n() result (-1 when the value is not a known name). */
static inline mqvpn_sched_neg_t
mqvpn_sched_negotiate(int allow, mqvpn_scheduler_t server_default, int has_request,
                      int requested, int already_swapped)
{
    if (!has_request) return MQVPN_SCHED_NEG_NONE;
    if (!allow) return MQVPN_SCHED_NEG_DISABLED;
    if (requested < 0) return MQVPN_SCHED_NEG_INVALID;
    if (requested == (int)MQVPN_SCHED_BACKUP_FEC) return MQVPN_SCHED_NEG_BACKUP_FEC;
    if (server_default == MQVPN_SCHED_BACKUP_FEC)
        return MQVPN_SCHED_NEG_SERVER_BACKUP_FEC;
    if (already_swapped) return MQVPN_SCHED_NEG_ALREADY_SET;
    return MQVPN_SCHED_NEG_APPLY;
}

/* Log token for a refusal; "" for NONE/APPLY. */
static inline const char *
mqvpn_sched_neg_reason(mqvpn_sched_neg_t n)
{
    switch (n) {
    case MQVPN_SCHED_NEG_DISABLED: return "disabled";
    case MQVPN_SCHED_NEG_INVALID: return "invalid";
    case MQVPN_SCHED_NEG_BACKUP_FEC: return "backup_fec";
    case MQVPN_SCHED_NEG_SERVER_BACKUP_FEC: return "server_backup_fec";
    case MQVPN_SCHED_NEG_ALREADY_SET: return "already_set";
    default: return "";
    }
}

#endif /* MQVPN_SCHED_NAMES_H */
