// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* formal/cbmc/stubs.c — stubs for the 4 external symbols path_state_machine.c
 * links against (declared in src/path_state_machine.h:199-212, implemented in
 * src/mqvpn_client.c for the real library).
 *
 * STUB CONTRACT: the harness calls path_on_event(NULL, ...). That is safe
 * only because these stubs never dereference the client pointer — the REAL
 * accessors do (client_now_us reads c->config, client_log reads
 * c->cbs/c->log_level, path_fsm_fire_path_event reads c->cbs). The FSM
 * translation unit itself only forwards `c` and never dereferences it.
 */

#include "path_state_machine.h"

/* Observation counters read by the harness. */
unsigned stub_fired_count;  /* path_fsm_fire_path_event invocations */
unsigned stub_notify_count; /* client_notify_xqc_path_state invocations */
int stub_notify_status;     /* last app_status passed to the notify stub */

uint64_t
client_now_us(const struct mqvpn_client_s *c)
{
    (void)c;
    /* Feeds only path_mark_state_entry (state_entered_at_us), which is
     * outside the abstract slot tuple. Any constant works. */
    return 1;
}

void
client_log(struct mqvpn_client_s *c, mqvpn_log_level_t level, const char *fmt, ...)
{
    (void)c;
    (void)level;
    (void)fmt;
}

void
path_fsm_fire_path_event(struct mqvpn_client_s *c, const path_entry_t *p)
{
    (void)c;
    (void)p;
    stub_fired_count++;
}

void
client_notify_xqc_path_state(struct mqvpn_client_s *c, const path_entry_t *p,
                             int app_status)
{
    (void)c;
    (void)p;
    stub_notify_count++;
    stub_notify_status = app_status;
}
