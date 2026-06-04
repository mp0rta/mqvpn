// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_control_response_bound.c — verifies CTRL_MAX_RESP_BYTES upper-bounds
 * the worst-case get_status JSON for MQVPN_MAX_USERS × MQVPN_MAX_PATHS.
 *
 * The JSON format strings are duplicated from control_socket.c:199-223 with a
 * comment anchor. If the format changes there, update both — the test will
 * fail loudly if the worst-case bound is exceeded.
 */

#include "libmqvpn.h"
#include "control_socket.h" /* CTRL_MAX_RESP_BYTES */

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int
per_path_entry_bytes(void)
{
    /* Mirrors control_socket.c:208-217 with leading "," (separator between
     * paths). The trailing %s is the longest path state label currently
     * returned by mqvpn_path_state_label() — "validating" (10 chars). */
    return snprintf(
        NULL, 0,
        ",{\"path_id\":%" PRIu64 ",\"srtt_ms\":%" PRIu64 ",\"min_rtt_ms\":%" PRIu64
        ",\"cwnd\":%" PRIu64 ",\"in_flight\":%" PRIu64 ",\"bytes_tx\":%" PRIu64
        ",\"bytes_rx\":%" PRIu64 ",\"pkt_sent\":%" PRIu64 ",\"pkt_recv\":%" PRIu64
        ",\"pkt_lost\":%" PRIu64 ",\"state\":%u,\"state_label\":\"%s\"}",
        UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
        UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT32_MAX, "validating");
}

static int
per_user_envelope_bytes(int paths_inner_bytes)
{
    /* Mirrors control_socket.c:199-203 + 220 with leading "," (separator
     * between users). username[64]/endpoint[64] in mqvpn_client_info_t →
     * 63 max printable chars each. */
    char username[64];
    char endpoint[64];
    memset(username, 'X', 63);
    username[63] = '\0';
    memset(endpoint, 'X', 63);
    endpoint[63] = '\0';

    int env = snprintf(NULL, 0,
                       ",{\"user\":\"%s\",\"endpoint\":\"%s\","
                       "\"connected_sec\":%" PRIu64 ",\"bytes_tx\":%" PRIu64
                       ",\"bytes_rx\":%" PRIu64 ",\"n_paths\":%d,\"paths\":[]}",
                       username, endpoint, UINT64_MAX, UINT64_MAX, UINT64_MAX, INT_MAX);
    return env + paths_inner_bytes;
}

static int
outer_envelope_bytes(void)
{
    /* Mirrors control_socket.c:190 + 223. n_clients is %d (INT_MAX = 10
     * digits) and the array is the only variable-width content. */
    return snprintf(NULL, 0, "{\"ok\":true,\"n_clients\":%d,\"clients\":[]}", 2147483647);
}

int
main(void)
{
    int path_entry = per_path_entry_bytes();
    int paths_block = path_entry * MQVPN_MAX_PATHS;
    int user_with_paths = per_user_envelope_bytes(paths_block);
    int outer = outer_envelope_bytes();

    /* Worst case: every user has MQVPN_MAX_PATHS entries, every numeric field
     * is at its max value, every string field at max length. */
    size_t worst_case = (size_t)outer + (size_t)user_with_paths * (size_t)MQVPN_MAX_USERS;

    printf("MQVPN_MAX_USERS    = %d\n", MQVPN_MAX_USERS);
    printf("MQVPN_MAX_PATHS    = %d\n", MQVPN_MAX_PATHS);
    printf("per-path entry     = %d bytes\n", path_entry);
    printf("per-user envelope  = %d bytes (incl. %d-byte paths block)\n", user_with_paths,
           paths_block);
    printf("outer envelope     = %d bytes\n", outer);
    printf("worst-case total   = %zu bytes\n", worst_case);
    printf("CTRL_MAX_RESP_BYTES= %d bytes\n", CTRL_MAX_RESP_BYTES);

    if (worst_case >= (size_t)CTRL_MAX_RESP_BYTES) {
        fprintf(stderr,
                "FAIL: worst-case get_status JSON (%zu) >= "
                "CTRL_MAX_RESP_BYTES (%d). Bump the buffer in "
                "control_socket.h to hold the new worst case.\n",
                worst_case, CTRL_MAX_RESP_BYTES);
        return 1;
    }

    printf("PASS\n");
    return 0;
}
