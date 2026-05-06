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
#include <sys/socket.h>

typedef struct path_entry_s {
    mqvpn_path_handle_t handle;
    int fd;
    char name[16];
    mqvpn_path_status_t status;
    int platform_attached; /* PR0 rename of `active` */
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
