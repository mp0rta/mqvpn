// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "cmp_endpoint.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#elif !defined(__APPLE__)
#  include <unistd.h>
#endif

int
cmp_endpoint_default(char *out, size_t out_len)
{
    if (!out || out_len == 0) return -1;
    int n;
#ifdef _WIN32
    char base[MAX_PATH * 3] = "C:\\ProgramData";
    WCHAR wbuf[MAX_PATH];
    DWORD wl = GetEnvironmentVariableW(L"ProgramData", wbuf, MAX_PATH);
    if (wl > 0 && wl < MAX_PATH) {
        int bl = WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)wl, base,
                                     (int)sizeof(base) - 1, NULL, NULL);
        if (bl > 0)
            base[bl] = '\0';
        else
            strcpy(base, "C:\\ProgramData");
    }
    n = snprintf(out, out_len, "%s\\mqvpn\\client.sock", base);
#elif defined(__APPLE__)
    n = snprintf(out, out_len, "/var/run/mqvpn/client.sock");
#else
    n = snprintf(out, out_len, "%s",
                 access("/run", F_OK) == 0 ? "/run/mqvpn/client.sock"
                                           : "/var/run/mqvpn/client.sock");
#endif
    if (n < 0 || (size_t)n >= out_len) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

int
cmp_endpoint_resolve(const char *configured, char *out, size_t out_len)
{
    if (!out || out_len == 0) return -1;
    if (configured && strncmp(configured, "unix://", 7) == 0) configured += 7;
    if (!configured || configured[0] == '\0') return cmp_endpoint_default(out, out_len);
    size_t n = strlen(configured);
    if (n >= out_len || n >= CMP_ENDPOINT_MAX) return -1;
    memcpy(out, configured, n + 1);
    return 0;
}
