// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "cmp_endpoint.h"

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
endpoint_resolve_strips_prefix(void)
{
    puts("endpoint_resolve_strips_prefix");
    char out[CMP_ENDPOINT_MAX];
    CHECK(cmp_endpoint_resolve("unix:///tmp/x.sock", out, sizeof(out)) == 0);
    CHECK(strcmp(out, "/tmp/x.sock") == 0);
    CHECK(cmp_endpoint_resolve("/tmp/y.sock", out, sizeof(out)) == 0);
    CHECK(strcmp(out, "/tmp/y.sock") == 0);
}

static void
endpoint_resolve_empty_is_default(void)
{
    puts("endpoint_resolve_empty_is_default");
    char def[CMP_ENDPOINT_MAX], out[CMP_ENDPOINT_MAX];
    CHECK(cmp_endpoint_default(def, sizeof(def)) == 0);
    CHECK(def[0] != '\0');
    CHECK(cmp_endpoint_resolve(NULL, out, sizeof(out)) == 0);
    CHECK(strcmp(out, def) == 0);
    CHECK(cmp_endpoint_resolve("", out, sizeof(out)) == 0);
    CHECK(strcmp(out, def) == 0);
    CHECK(cmp_endpoint_resolve("unix://", out, sizeof(out)) == 0);
    CHECK(strcmp(out, def) == 0);
}

static void
endpoint_resolve_too_long(void)
{
    puts("endpoint_resolve_too_long");
    char longp[301];
    memset(longp, 'a', sizeof(longp) - 1);
    longp[0] = '/';
    longp[sizeof(longp) - 1] = '\0';
    char out[CMP_ENDPOINT_MAX] = "";
    CHECK(cmp_endpoint_resolve(longp, out, sizeof(out)) == -1);
    CHECK(out[0] == '\0');
    char small[8] = "";
    CHECK(cmp_endpoint_resolve("/tmp/long.sock", small, sizeof(small)) == -1);
    CHECK(small[0] == '\0');
}

static void
endpoint_default_shape(void)
{
    puts("endpoint_default_shape");
    char def[CMP_ENDPOINT_MAX];
    CHECK(cmp_endpoint_default(def, sizeof(def)) == 0);
    static const char tail[] = "client.sock";
    size_t n = strlen(def), t = sizeof(tail) - 1;
    CHECK(n >= t && strcmp(def + n - t, tail) == 0);
#ifdef __linux__
    CHECK(strncmp(def, "/run/", 5) == 0 || strncmp(def, "/var/run/", 9) == 0);
#endif
    char tiny[4];
    CHECK(cmp_endpoint_default(tiny, sizeof(tiny)) == -1);
}

int
main(void)
{
    endpoint_resolve_strips_prefix();
    endpoint_resolve_empty_is_default();
    endpoint_resolve_too_long();
    endpoint_default_shape();
    return g_failed ? 1 : 0;
}
