// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* libFuzzer target: control-API request bytes -> dispatch() -> JSON command
 * parsing (json_mini.h) + per-command argument extraction + error-response
 * building.
 *
 * Scope: the control socket accepts TCP connections (127.0.0.1 by default,
 * but --control-addr can bind any address and the API is unauthenticated),
 * so the request parser must be crash-safe on ARBITRARY bytes. This TU
 * #include's control_socket.c — the test_reorder_rx idiom for reaching
 * file-local statics — to fuzz the real dispatch() and command table, with
 * a zeroed ctrl_socket_t: every mqvpn_server_* entry point the handlers
 * call NULL-guards (verified per function when this target was added), so
 * server == NULL exercises the dispatch + argument-extraction surface (cmd
 * lookup, add_user/remove_user/get_fec_stats argument extraction, error
 * envelopes) without a live server. Deliberately NOT covered: the library
 * side of those calls — with a real server, request-derived strings also
 * reach mqvpn_server_add_user's own validation/copying etc.; here they
 * short-circuit at the NULL guard (and mqvpn_lib is uninstrumented
 * anyway). Session-loop response bodies are likewise out of scope: they
 * are built from server state, not from request bytes.
 *
 * NOT covered: ctrl_on_read's brace-counting request-completeness scanner
 * (needs a real fd + event loop). A future target if the framing logic
 * grows beyond brace/newline detection.
 *
 * Input contract: dispatch() takes a NUL-terminated request; ctrl_on_read
 * caps a request at CTRL_MAX_REQ (4096) bytes, so longer fuzz inputs are
 * rejected up front to keep the corpus in-contract.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform/linux/control_socket.c"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > CTRL_MAX_REQ) return 0;

    char req[CTRL_MAX_REQ + 1];
    memcpy(req, data, size);
    req[size] = '\0';

    /* server=NULL / gro pointers NULL: both are handled (NULL guards in every
     * mqvpn_server_* call; get_stats reports 0 for NULL counter pointers). */
    ctrl_socket_t cs;
    memset(&cs, 0, sizeof(cs));

    /* static: CTRL_MAX_RESP_BYTES is 256 KiB — keep it off the per-call
     * stack. libFuzzer runs inputs sequentially, so no aliasing. */
    static char resp[CTRL_MAX_RESP_BYTES];
    (void)dispatch(req, resp, sizeof(resp), &cs);
    return 0;
}
