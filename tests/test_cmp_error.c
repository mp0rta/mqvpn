// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "cmp_error.h"

#include <stdio.h>
#include <string.h>

static int g_failed = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failed++;                                                     \
        }                                                                   \
    } while (0)

static void
error_table_roundtrip(void)
{
    puts("error_table_roundtrip");
    for (size_t i = 0; i < cmp_error_count(); i++) {
        int code = 0, c = 0;
        const char *name = NULL;
        CHECK(cmp_error_at(i, &code, &name) == 0);
        CHECK(name != NULL);
        if (!name) continue;
        CHECK(cmp_error_name(code) != NULL && strcmp(cmp_error_name(code), name) == 0);
        CHECK(cmp_error_from_name(name, &c) == 0 && c == code);
        CHECK(cmp_error_message(code) != NULL);
        CHECK(strncmp(name, "MQVPN_CLIENT_", 13) == 0);
    }
    CHECK(cmp_error_at(cmp_error_count(), NULL, NULL) == -1);
}

static void
error_table_no_duplicates(void)
{
    puts("error_table_no_duplicates");
    CHECK(cmp_error_count() == 24);
    for (size_t i = 0; i < cmp_error_count(); i++) {
        for (size_t j = i + 1; j < cmp_error_count(); j++) {
            int ci = 0, cj = 0;
            const char *ni = NULL, *nj = NULL;
            CHECK(cmp_error_at(i, &ci, &ni) == 0);
            CHECK(cmp_error_at(j, &cj, &nj) == 0);
            CHECK(ci != cj);
            CHECK(ni && nj && strcmp(ni, nj) != 0);
        }
    }
}

static void
error_table_pinned_values(void)
{
    puts("error_table_pinned_values");
    CHECK(CMP_E_PARSE_ERROR == -32700);
    CHECK(CMP_E_RESPONSE_TOO_LARGE == -32000);
    CHECK(CMP_E_UNSUPPORTED == -32006);
    CHECK(CMP_E_UNAVAILABLE == 1000);
    CHECK(CMP_E_MTU_TOO_LARGE == 1011);
    CHECK(strcmp(cmp_error_name(1008), "MQVPN_CLIENT_NO_ACTIVE_PATH") == 0);
}

static void
error_unknown_code(void)
{
    puts("error_unknown_code");
    int c = 0;
    CHECK(cmp_error_name(0) == NULL);
    CHECK(cmp_error_name(-32099) == NULL);
    CHECK(cmp_error_message(0) == NULL);
    CHECK(cmp_error_from_name("MQVPN_CLIENT_NOPE", &c) == -1);
    CHECK(cmp_error_from_name(NULL, &c) == -1);
}

int
main(void)
{
    error_table_roundtrip();
    error_table_no_duplicates();
    error_table_pinned_values();
    error_unknown_code();
    return g_failed ? 1 : 0;
}
