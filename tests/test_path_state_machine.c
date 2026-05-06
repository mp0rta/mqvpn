/* tests/test_path_state_machine.c */
#include "path_state_machine.h"
#include "libmqvpn.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static void
test_status_name_known(void)
{
    assert(strcmp(mqvpn_path_status_name(MQVPN_PATH_PENDING), "PENDING") == 0);
    assert(strcmp(mqvpn_path_status_name(MQVPN_PATH_ACTIVE), "ACTIVE") == 0);
    assert(strcmp(mqvpn_path_status_name(MQVPN_PATH_DEGRADED), "DEGRADED") == 0);
    assert(strcmp(mqvpn_path_status_name(MQVPN_PATH_STANDBY), "STANDBY") == 0);
    assert(strcmp(mqvpn_path_status_name(MQVPN_PATH_CLOSED), "CLOSED") == 0);
}

static void
test_status_name_unknown(void)
{
    /* Out-of-range value should return non-NULL "UNKNOWN" or similar. */
    const char *s = mqvpn_path_status_name((mqvpn_path_status_t)999);
    assert(s != NULL);
    assert(strlen(s) > 0);
}

static void
test_reason_name_known(void)
{
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_ADD_FD), "ADD_FD") == 0);
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_ACTIVATE_OK),
                  "ACTIVATE_OK") == 0);
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_RETRY_RESET),
                  "RETRY_RESET") == 0);
}

int
main(void)
{
    test_status_name_known();
    test_status_name_unknown();
    test_reason_name_known();
    printf("PASS\n");
    return 0;
}
