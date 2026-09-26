// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* reactor.h — the Android platform's poll()/eventfd reactor.
 *
 * Platform code, not library code: compiled into libmqvpn_jni.so by the JNI
 * CMake and into tests/test_android_reactor on Linux hosts, never into
 * libmqvpn (the library keeps no event loop). One eventfd plus a fixed table
 * of MQVPN_MAX_PATHS entries {fd, handle, bind ctx, state}. The lifecycle
 * composites (add / remove / released / destroy) live here so the host test
 * covers the real code; the JNI layer only marshals.
 *
 * Threads: every call is tick-thread only, except mqvpn_android_reactor_wake()
 * (any thread). _new() may run before the poller thread exists; _free() runs
 * on the poller thread after its loop has exited. No wake() may run
 * concurrently with or after _free(): the caller excludes them (on Android,
 * the Kotlin waiter's lock shared by wake and close does). The reactor
 * asserts nothing about threads: the poller's one dedicated thread is the
 * guarantee.
 *
 * Logging goes through the global mqvpn_log() (src/log.h), so it reaches
 * logcat through the sink the JNI installs and a capturing sink in the test. */
#ifndef MQVPN_ANDROID_REACTOR_H
#define MQVPN_ANDROID_REACTOR_H

#include "libmqvpn.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mqvpn_android_reactor mqvpn_android_reactor_t;

/* Returned by mqvpn_android_reactor_path_released() when the library reports
 * MQVPN_ERR_INVALID_ARG for a handle this table holds: ledger corruption.
 * Distinct from every MQVPN_ERR_* value. The entry is poisoned (never polled,
 * dereferenced or reused again); the platform treats it as session-fatal. */
#define MQVPN_REACTOR_POISONED (-100)

typedef enum {
    MQVPN_REACTOR_ENTRY_FREE = 0,
    MQVPN_REACTOR_ENTRY_ATTACHED, /* polled; ctx library-owned */
    MQVPN_REACTOR_ENTRY_DETACHED, /* not polled; ctx still library-owned */
    MQVPN_REACTOR_ENTRY_INVALID,  /* POLLNVAL seen; waiting for take_bad_fd */
    MQVPN_REACTOR_ENTRY_POISONED, /* ledger corruption; cleared only by destroy */
} mqvpn_android_reactor_entry_state_t;

/* NULL on eventfd or allocation failure. */
mqvpn_android_reactor_t *mqvpn_android_reactor_new(void);
/* Closes the eventfd. Never touches a ctx: a non-empty table is a bug in the
 * caller's shutdown order (asserted in Debug, leaked with a WARN in Release —
 * only client_destroy may finalise a ctx). */
void mqvpn_android_reactor_free(mqvpn_android_reactor_t *r);

/* Any thread. EINTR retried; EAGAIN (a wake already pending) is success.
 * Returns 0, or -1 on any other error (logged once). */
int mqvpn_android_reactor_wake(mqvpn_android_reactor_t *r);

/* poll() over the ATTACHED fds plus the eventfd, in one pass: every path
 * whose revents has POLLIN | POLLERR | POLLHUP is drained with
 * mqvpn_bind_posix_path_drain(…, 64) (a hard error is ignored — the platform's
 * network monitor owns drop detection); the eventfd is read once (its counter
 * resets, so every pending wake is consumed); a POLLNVAL entry becomes INVALID
 * (out of the poll set, WARN, ctx untouched).
 * The eventfd never has priority over RX: returning early on a pending wake
 * would starve receive under sustained TUN enqueue.
 * Returns the number of drains performed (>= 0); EINTR returns 0; any other
 * poll() error returns -1 (logged once). client == NULL is accepted only
 * while no entry is ATTACHED, otherwise -1 without polling. */
int mqvpn_android_reactor_wait(mqvpn_android_reactor_t *r, mqvpn_client_t *client,
                               int timeout_ms);

/* The next INVALID entry's handle, or -1. Consumes it: INVALID -> DETACHED,
 * so a handle is delivered once. The platform then runs remove_path ->
 * (drops the fd from its ledger WITHOUT closing it) -> path_released.
 * Limitation, on purpose: POLLNVAL is reported only for a closed number; an
 * fd closed behind the platform AND reused before the next poll() is
 * indistinguishable from the path and is drained as if it were the path. No
 * production caller closes an fd the reactor still polls. */
mqvpn_path_handle_t mqvpn_android_reactor_take_bad_fd(mqvpn_android_reactor_t *r);

/* Reserve an entry, then build a posix bind ctx on the BORROWED fd (udp_gso =
 * gso_policy, udp_gro = gro_policy, 7 MiB buffer request, tag = iface) and
 * register it with mqvpn_client_add_path(). Returns the library handle
 * (>= 0; the entry is ATTACHED whatever the activation outcome was — the
 * ctx is library-owned and the path is kept), or -1: table full (nothing
 * built), bind construction failure, or the library refusing the path (the
 * ctx is freed here, the reservation released). The fd is never touched on
 * failure: the caller closes it. A path_event the library fires synchronously
 * from inside add_path must not call back into the reactor for this handle:
 * the entry becomes ATTACHED only after the library returns. */
mqvpn_path_handle_t mqvpn_android_reactor_add_path(mqvpn_android_reactor_t *r,
                                                   mqvpn_client_t *client, int fd,
                                                   const char *iface, int gso_policy,
                                                   int gro_policy);

/* mqvpn_client_remove_path() for every entry that is not FREE or POISONED
 * (ATTACHED, INVALID or already DETACHED — the library call is idempotent);
 * the entry becomes DETACHED whatever the library returns, and the library's
 * code is returned. FREE or POISONED -> MQVPN_ERR_INVALID_ARG, nothing
 * called. The socket is not touched: the platform closes it after this call
 * (never on the bad-fd chain). */
int mqvpn_android_reactor_remove_path(mqvpn_android_reactor_t *r, mqvpn_client_t *client,
                                      mqvpn_path_handle_t handle);

/* Entry must be DETACHED (else MQVPN_ERR_INVALID_ARG from here, nothing
 * called). Reads the bind's stats, then mqvpn_client_on_platform_path_released():
 *   MQVPN_OK            -> RX totals logged and accumulated, entry FREE
 *   MQVPN_ERR_INVALID_ARG (ledger corruption) -> entry POISONED, returns
 *                          MQVPN_REACTOR_POISONED (session-fatal for the caller)
 *   anything else (INVALID_STATE: drop/remove did not precede) -> WARN, the
 *                          entry stays DETACHED and the ctx library-owned
 *                          until destroy; the library's code is returned. */
int mqvpn_android_reactor_path_released(mqvpn_android_reactor_t *r,
                                        mqvpn_client_t *client,
                                        mqvpn_path_handle_t handle);

/* Whole-client teardown (the destroy contract of libmqvpn.h — the platform
 * quiesces RX, destroys, then closes its sockets): stop polling everything,
 * harvest every remaining ctx's RX counters (one log line of totals),
 * mqvpn_client_destroy() (the library finalises every still-attached ctx),
 * then clear the table without dereferencing anything. A NULL client only
 * clears the table (no harvest, no log line). Afterwards the table is empty
 * and wait(r, NULL, …) is legal again. */
void mqvpn_android_reactor_client_destroy(mqvpn_android_reactor_t *r,
                                          mqvpn_client_t *client);

/* Observability (tests, logging): the entry's state, or -1 if no non-FREE
 * entry carries this handle. */
int mqvpn_android_reactor_entry_state(const mqvpn_android_reactor_t *r,
                                      mqvpn_path_handle_t handle);

#ifdef __cplusplus
}
#endif
#endif /* MQVPN_ANDROID_REACTOR_H */
