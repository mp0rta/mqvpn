// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_xquic_abi_pin.c — compile-time pin for xquic private-enum values
 * that libmqvpn depends on by numeric value.
 *
 * The library links shared xquic and includes only its PUBLIC header
 * (<xquic/xquic.h>), which exposes xqc_path_metrics_t.path_state as a bare
 * uint8_t. mqvpn compares that field against MQVPN_XQC_PATH_STATE_ACTIVE
 * (a named literal in mqvpn_internal.h) in the validation poll
 * (mqvpn_client.c) and the mp-state label (mqvpn_server.c).
 *
 * This test TU is the ONE place that includes xquic's private
 * src/transport/xqc_multipath.h, so it can assert the mqvpn-side literal
 * still equals the real xqc_path_state_t enumerator at compile time. If a
 * future xquic merge renumbers the enum, this file fails to compile and the
 * mirror in mqvpn_internal.h must be updated in lockstep.
 *
 * There is no runtime behaviour here — the _Static_asserts are the test.
 */

#include "mqvpn_internal.h"              /* MQVPN_XQC_PATH_STATE_ACTIVE */
#include "src/transport/xqc_multipath.h" /* xqc_path_state_t (private)  */

_Static_assert(MQVPN_XQC_PATH_STATE_ACTIVE == XQC_PATH_STATE_ACTIVE,
               "mqvpn's MQVPN_XQC_PATH_STATE_ACTIVE drifted from xquic's "
               "private XQC_PATH_STATE_ACTIVE — update mqvpn_internal.h");

int
main(void)
{
    return 0;
}
