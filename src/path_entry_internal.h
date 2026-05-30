// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and contributors

/* src/path_entry_internal.h — Internal-only path slot definition.
 *
 * Shared between mqvpn_client.c, path_state_machine.c, and the
 * test_path_state_machine test target. NOT part of the public ABI —
 * never included from libmqvpn.h.
 *
 * Include policy (PR4 lint will enforce):
 *   ALLOWED:    mqvpn_client.c, path_state_machine.c, tests/test_path_state_machine.c
 *   FORBIDDEN:  platform layer, scheduler, public headers, all other modules
 *
 * Promoting this header is a deliberate PR1 tradeoff for testability.
 * Phase 4 reduces direct field access via the path_on_event() aggregator. */

#ifndef MQVPN_PATH_ENTRY_INTERNAL_H
#define MQVPN_PATH_ENTRY_INTERNAL_H

#include "libmqvpn.h"
#include <stdint.h>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#endif

/* PR3 split done — internal 9-state lifecycle. Public ABI continues to use
 * `mqvpn_path_status_t` (5 values, see libmqvpn.h). The mapping internal →
 * public is in `path_public_status_from_lifecycle()` (path_state_machine.h).
 *
 * PR2 split rationale: the legacy MQVPN_PATH_CLOSED collapses 3 distinct
 * semantics (retry exhausted but slot reusable, platform dropped pending
 * cleanup, fully free). PR3 splits PENDING into PENDING / CREATE_WAIT /
 * VALIDATING to distinguish "never tried" / "retry timer armed" / "xqc path
 * created, awaiting validation". */
typedef enum {
    PATH_LC_PENDING = 0,
    PATH_LC_CREATE_WAIT, /* PR3 — current attempt failed; auto retry timer armed */
    PATH_LC_VALIDATING,  /* PR3 — xqc_conn_create_path ok; awaiting validation */
    PATH_LC_ACTIVE,
    PATH_LC_STANDBY,
    PATH_LC_DEGRADED,
    PATH_LC_CLOSED_RECOVERABLE,
    PATH_LC_CLOSED_DROPPED,
    PATH_LC_CLOSED_FREE,
} path_lifecycle_t;

typedef struct path_entry_s {
    mqvpn_path_handle_t handle;
    int fd;
    char name[16];
    mqvpn_path_status_t status;
    path_lifecycle_t state; /* PR2 — internal 7-state, must satisfy:
                               status == path_public_status_from_lifecycle(state) */
    int platform_attached;  /* PR0 rename of `active` */
    struct sockaddr_storage local_addr;
    uint32_t local_addr_len;
    int64_t platform_net_id;
    uint32_t flags;
    uint64_t xqc_path_id;
    int xquic_path_live; /* PR0 rename of `in_use` */
    int srtt_ms;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t recreate_after_us;
    int recreate_retries;
    uint64_t path_stable_since_us;
    uint64_t state_entered_at_us;       /* PR1 — Phase 1 observability */
    uint64_t last_residence_warn_at_us; /* PR1 — residence-warn debounce, used in B10 */
} path_entry_t;

#endif /* MQVPN_PATH_ENTRY_INTERNAL_H */
