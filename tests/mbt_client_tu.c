// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/mbt_client_tu.c — a private copy of src/mqvpn_client.c whose stateful
 * xquic calls go to the scripted fake (tests/fake_xquic.c), plus read-only
 * accessors for tests/test_path_slot_mbt.c. */
#include "fake_xquic_redirect.h"

#include "../src/mqvpn_client.c"

#include "mbt_client_tu.h"

const path_entry_t *
mbt_slot(const mqvpn_client_t *c, int idx)
{
    return &c->paths[idx];
}

int
mbt_n_paths(const mqvpn_client_t *c)
{
    return c->n_paths;
}

int
mbt_multipath_ready(const mqvpn_client_t *c)
{
    return c->multipath_ready;
}

int
mbt_hold(const mqvpn_client_t *c)
{
    return c->hold_extra_paths;
}

void
mbt_canary_bad_transition(mqvpn_client_t *c)
{
    client_set_state(c, MQVPN_STATE_ESTABLISHED);
}
