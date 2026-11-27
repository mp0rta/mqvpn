// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/fake_xquic.h — driver-facing controls of the scripted fake xquic
 * (tests/fake_xquic.c). One engine and one connection at a time.
 *
 * Scripts are one-shot and apply to the next call only; an unscripted call
 * succeeds (create_path then hands out the next unused id). Observation
 * calls (get_stats, recv_headers, recv_body, get_mss) answer from the fake's
 * current state and never consume a script. */
#ifndef MQVPN_FAKE_XQUIC_H
#define MQVPN_FAKE_XQUIC_H

#include <stdint.h>

/* Forget every connection, path, request, script and recorded command.
 * multipath_negotiated = 0: ready_to_create_path is never delivered. */
void fake_xqc_reset(int multipath_negotiated);
/* next xqc_h3_connect */
void fake_xqc_script_connect(int ok);
/* next create_path: xqc_ret 0 OK, -XQC_EMP_CREATE_PATH, or -1 */
void fake_xqc_script_create_path(int xqc_ret, uint64_t id);
/* next close_path */
void fake_xqc_script_close_path(int ok);
/* what get_stats reports */
void fake_xqc_set_path_active(uint64_t id, int active);
/* poll-id probe: listed FIRST in paths_info; ~0 clears */
void fake_xqc_set_decoy_active_path(uint64_t id);
void fake_xqc_fire_handshake_finished(void);
void fake_xqc_fire_ready_to_create_path(void);
/* read notify: header 200 + ADDRESS_ASSIGN body + fin */
void fake_xqc_fire_tunnel_response(void);
/* stream close notifies, then h3_conn_close_notify */
void fake_xqc_fire_peer_close(void);
void fake_xqc_fire_path_removed(uint64_t id);

typedef struct {
    unsigned h3_connect, conn_close, h3_conn_close, create_path, close_path;
    int last_path_status;
    uint64_t last_close_path_id;
} fake_xqc_cmds_t;
extern fake_xqc_cmds_t fake_xqc_cmds; /* zeroed by the driver before each step */

#endif /* MQVPN_FAKE_XQUIC_H */
