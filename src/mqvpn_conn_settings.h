/*
 * mqvpn_conn_settings.h — Single source of truth for mqvpn's xquic
 * connection settings construction.
 *
 * Before extraction, mqvpn_server.c::serve and mqvpn_client.c::cli_start_connection
 * each had a ~25-line inline block that populated xqc_conn_settings_t with
 * 11 shared hardcoded fields and 4 intentionally-asymmetric fields. The
 * inline duplication carried two risks:
 *   (1) silent drift between client and server when adding a new knob,
 *   (2) intent of each asymmetry being undiscoverable from any single
 *       call site.
 *
 * mqvpn_build_conn_settings() centralises both, and the matching test
 * `tests/test_conn_settings.c` pins the asymmetric expectations so any
 * accidental change requires a deliberate test edit. To add a new knob
 * that the caller drives, extend mqvpn_conn_settings_input_t here, the
 * helper body, and the test rows in lock-step.
 */

#ifndef MQVPN_CONN_SETTINGS_H
#define MQVPN_CONN_SETTINGS_H

#include "libmqvpn.h" /* mqvpn_scheduler_t */
#include <stdbool.h>
#include <stdint.h>
#include <xquic/xquic.h>

/* Caller-driven inputs. The bools are parameterised (not a single
 * `is_server` flag) so each call site documents its intent. */
typedef struct {
    bool is_server;
    bool enable_multipath; /* server callers pass true */
    mqvpn_scheduler_t scheduler;
    uint64_t init_max_path_id; /* 0 = leave xquic default */
} mqvpn_conn_settings_input_t;

/* Populates *out with mqvpn-canonical xquic conn settings. Always begins
 * with memset(0), so the caller is not required to zero `out` first. */
void mqvpn_build_conn_settings(const mqvpn_conn_settings_input_t *in,
                               xqc_conn_settings_t *out);

#endif /* MQVPN_CONN_SETTINGS_H */
