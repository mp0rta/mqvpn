// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "cmp_error.h"

#include <string.h>

static const struct {
    int code;
    const char *name;
    const char *msg;
} k_table[] = {
#define CMP_X(n, code, msg) {(code), "MQVPN_CLIENT_" #n, (msg)},
    CMP_ERROR_LIST(CMP_X)
#undef CMP_X
};

#define K_COUNT (sizeof(k_table) / sizeof(k_table[0]))

static const char *
lookup(int code, int want_name)
{
    for (size_t i = 0; i < K_COUNT; i++)
        if (k_table[i].code == code) return want_name ? k_table[i].name : k_table[i].msg;
    return NULL;
}

const char *
cmp_error_name(int code)
{
    return lookup(code, 1);
}

const char *
cmp_error_message(int code)
{
    return lookup(code, 0);
}

int
cmp_error_from_name(const char *name, int *code_out)
{
    if (!name) return -1;
    for (size_t i = 0; i < K_COUNT; i++) {
        if (strcmp(k_table[i].name, name) == 0) {
            if (code_out) *code_out = k_table[i].code;
            return 0;
        }
    }
    return -1;
}

size_t
cmp_error_count(void)
{
    return K_COUNT;
}

int
cmp_error_at(size_t i, int *code_out, const char **name_out)
{
    if (i >= K_COUNT) return -1;
    if (code_out) *code_out = k_table[i].code;
    if (name_out) *name_out = k_table[i].name;
    return 0;
}
