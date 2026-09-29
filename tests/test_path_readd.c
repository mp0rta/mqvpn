// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_path_readd.c — the re-add decision shared by the desktop path
 * monitors (src/platform/path_readd.h).
 *
 * Pins the decision table the two re-add bugs got wrong: a slot that still
 * owns a socket is never a re-add candidate (it belongs to reactivate), and
 * a handle the library no longer lists — its slot was recycled for another
 * path — is one. Own checks, not assert(), so the Release build that
 * Windows CI runs keeps them.
 */
#include "libmqvpn.h"
#include "platform/path_readd.h"

#include <stdio.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                           \
    do {                                           \
        if (cond) {                                \
            g_pass++;                              \
        } else {                                   \
            g_fail++;                              \
            fprintf(stderr, "FAIL [%s]\n", (msg)); \
        }                                          \
    } while (0)

#define LIMIT 5

static mqvpn_path_info_t
info(mqvpn_path_handle_t handle, mqvpn_path_status_t status)
{
    mqvpn_path_info_t pi = {0};
    pi.struct_size = sizeof(pi);
    pi.handle = handle;
    pi.status = status;
    return pi;
}

static void
test_socket_open_is_never_a_candidate(void)
{
    /* A slot that owns a socket belongs to reactivate, whatever the library
     * says about it — including CLOSED (CLOSED_RECOVERABLE with the
     * transport still attached) and a recycled handle. */
    mqvpn_path_info_t closed[] = {info(7, MQVPN_PATH_CLOSED)};
    CHECK(!path_readd_candidate(1, 0, LIMIT, 7, closed, 1), "socket + CLOSED");
    mqvpn_path_info_t other[] = {info(9, MQVPN_PATH_ACTIVE)};
    CHECK(!path_readd_candidate(1, 0, LIMIT, 7, other, 1), "socket + handle not listed");
}

static void
test_failure_limit_blocks(void)
{
    mqvpn_path_info_t closed[] = {info(7, MQVPN_PATH_CLOSED)};
    CHECK(path_readd_candidate(0, LIMIT - 1, LIMIT, 7, closed, 1), "below the limit");
    CHECK(!path_readd_candidate(0, LIMIT, LIMIT, 7, closed, 1), "at the limit");
    CHECK(!path_readd_candidate(0, LIMIT + 1, LIMIT, 7, closed, 1), "above the limit");
}

static void
test_recycled_handle_is_a_candidate(void)
{
    /* Another path's re-add took this slot's library slot: the old handle 7
     * is gone, the slot now lists handle 12 for the other path. */
    mqvpn_path_info_t recycled[] = {info(3, MQVPN_PATH_ACTIVE),
                                    info(12, MQVPN_PATH_PENDING)};
    CHECK(path_lib_allows_readd(7, recycled, 2), "handle not listed");
    CHECK(path_readd_candidate(0, 0, LIMIT, 7, recycled, 2),
          "candidate: handle not listed");
    CHECK(path_readd_candidate(0, 0, LIMIT, 7, NULL, 0), "candidate: empty list");
}

static void
test_listed_status(void)
{
    const struct {
        mqvpn_path_status_t status;
        int expect;
        const char *name;
    } cases[] = {
        {MQVPN_PATH_CLOSED, 1, "CLOSED"},     {MQVPN_PATH_PENDING, 0, "PENDING"},
        {MQVPN_PATH_ACTIVE, 0, "ACTIVE"},     {MQVPN_PATH_STANDBY, 0, "STANDBY"},
        {MQVPN_PATH_DEGRADED, 0, "DEGRADED"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        /* The slot's handle 7 sits between two other paths. */
        mqvpn_path_info_t list[] = {info(3, MQVPN_PATH_ACTIVE), info(7, cases[i].status),
                                    info(12, MQVPN_PATH_CLOSED)};
        CHECK(path_lib_allows_readd(7, list, 3) == cases[i].expect, cases[i].name);
        CHECK(path_readd_candidate(0, 0, LIMIT, 7, list, 3) == cases[i].expect,
              cases[i].name);
    }
}

int
main(void)
{
    test_socket_open_is_never_a_candidate();
    test_failure_limit_blocks();
    test_recycled_handle_is_a_candidate();
    test_listed_status();
    printf("test_path_readd: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
