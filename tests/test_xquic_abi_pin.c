// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_xquic_abi_pin.c — compile-time pin for xquic private-enum values
 * that libmqvpn depends on by numeric value.
 *
 * The library links shared xquic and includes only its PUBLIC header
 * (<xquic/xquic.h>), which types xqc_path_metrics_t.path_state as a bare
 * uint8_t. mqvpn depends on ALL of that private enum's values by number:
 * mqvpn_path_state_label() (mqvpn_server.c) maps every value to a string,
 * the validation poll (mqvpn_client.c) and mp-state label test ACTIVE, and
 * the raw value is surfaced through the public control API
 * (mqvpn_path_stat_t.state). So every value is mirrored in mqvpn_internal.h
 * as MQVPN_XQC_PATH_STATE_*.
 *
 * This test TU is the ONE place that includes xquic's private
 * src/transport/xqc_multipath.h, so it can assert each mqvpn-side mirror
 * still equals the real xqc_path_state_t enumerator at compile time. If a
 * future xquic merge renumbers the enum, this file fails to compile and the
 * mirror must be updated in lockstep.
 *
 * app_path_status is deliberately NOT pinned here: mqvpn only relays those
 * classes to xquic through the named xqc_conn_mark_path_* calls (see
 * client_notify_xqc_path_state), never by numeric value, so there is no ABI
 * value dependency to guard.
 *
 * There is no runtime behaviour here — the _Static_asserts are the test.
 */

#include "mqvpn_internal.h"              /* MQVPN_XQC_PATH_STATE_* */
#include "src/transport/xqc_multipath.h" /* xqc_path_state_t (private)  */

#define PIN_PATH_STATE(mirror, real)                                                 \
    _Static_assert((mirror) == (real), "mqvpn " #mirror " drifted from xquic " #real \
                                       " — update the mirror in mqvpn_internal.h")

PIN_PATH_STATE(MQVPN_XQC_PATH_STATE_INIT, XQC_PATH_STATE_INIT);
PIN_PATH_STATE(MQVPN_XQC_PATH_STATE_VALIDATING, XQC_PATH_STATE_VALIDATING);
PIN_PATH_STATE(MQVPN_XQC_PATH_STATE_ACTIVE, XQC_PATH_STATE_ACTIVE);
PIN_PATH_STATE(MQVPN_XQC_PATH_STATE_CLOSING, XQC_PATH_STATE_CLOSING);
PIN_PATH_STATE(MQVPN_XQC_PATH_STATE_CLOSED, XQC_PATH_STATE_CLOSED);

int
main(void)
{
    return 0;
}
