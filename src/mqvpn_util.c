/*
 * mqvpn_util.c — Utility functions (error strings, version, key generation)
 *
 * Part of libmqvpn public API. No platform dependencies.
 */

#include "libmqvpn.h"

#include <stdio.h>
#include <string.h>

/* ─── Error strings ─── */

const char *mqvpn_error_string(mqvpn_error_t err)
{
    switch (err) {
    case MQVPN_OK:               return "OK";
    case MQVPN_ERR_INVALID_ARG:  return "invalid argument";
    case MQVPN_ERR_NO_MEMORY:    return "out of memory";
    case MQVPN_ERR_ENGINE:       return "engine error";
    case MQVPN_ERR_TLS:          return "TLS error";
    case MQVPN_ERR_AUTH:         return "authentication failure";
    case MQVPN_ERR_PROTOCOL:     return "protocol error";
    case MQVPN_ERR_POOL_FULL:    return "IP pool exhausted";
    case MQVPN_ERR_MAX_CLIENTS:  return "max clients reached";
    case MQVPN_ERR_AGAIN:        return "back-pressure";
    case MQVPN_ERR_CLOSED:       return "connection closed";
    case MQVPN_ERR_ABI_MISMATCH: return "ABI mismatch";
    case MQVPN_ERR_TIMEOUT:      return "connection timeout";
    }
    return "unknown error";
}

/* ─── Version string ─── */

const char *mqvpn_version_string(void)
{
    /* Computed once — no thread-safety concern (identical writes). */
    static char buf[32];
    if (buf[0] == '\0') {
        snprintf(buf, sizeof(buf), "%d.%d.%d",
                 MQVPN_VERSION_MAJOR, MQVPN_VERSION_MINOR, MQVPN_VERSION_PATCH);
    }
    return buf;
}

/* ─── Key generation ─── */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(char *dst, size_t dst_len,
                      const unsigned char *src, size_t src_len)
{
    size_t out_len = ((src_len + 2) / 3) * 4;
    if (dst_len < out_len + 1)
        return -1;

    size_t i = 0, j = 0;
    while (i + 2 < src_len) {
        uint32_t triple = ((uint32_t)src[i] << 16) |
                          ((uint32_t)src[i+1] << 8) |
                          (uint32_t)src[i+2];
        dst[j++] = b64_table[(triple >> 18) & 0x3F];
        dst[j++] = b64_table[(triple >> 12) & 0x3F];
        dst[j++] = b64_table[(triple >> 6) & 0x3F];
        dst[j++] = b64_table[triple & 0x3F];
        i += 3;
    }

    if (i < src_len) {
        uint32_t triple = (uint32_t)src[i] << 16;
        if (i + 1 < src_len)
            triple |= (uint32_t)src[i+1] << 8;

        dst[j++] = b64_table[(triple >> 18) & 0x3F];
        dst[j++] = b64_table[(triple >> 12) & 0x3F];
        dst[j++] = (i + 1 < src_len)
                       ? b64_table[(triple >> 6) & 0x3F]
                       : '=';
        dst[j++] = '=';
    }

    dst[j] = '\0';
    return 0;
}

int mqvpn_generate_key(char *out, size_t out_len)
{
    if (!out || out_len < 45)   /* 32 bytes → 44 chars + NUL */
        return MQVPN_ERR_INVALID_ARG;

    unsigned char raw[32];
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp)
        return MQVPN_ERR_ENGINE;

    if (fread(raw, 1, sizeof(raw), fp) != sizeof(raw)) {
        fclose(fp);
        return MQVPN_ERR_ENGINE;
    }
    fclose(fp);

    if (b64_encode(out, out_len, raw, sizeof(raw)) != 0)
        return MQVPN_ERR_INVALID_ARG;

    return MQVPN_OK;
}
