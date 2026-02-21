/*
 * auth.c — PSK authentication utilities for mqvpn
 */
#include "auth.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ---- Base64 encoding (RFC 4648) ---- */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int
mqvpn_auth_b64_encode(char *dst, size_t dst_len,
                       const unsigned char *src, size_t src_len)
{
    size_t out_len = ((src_len + 2) / 3) * 4;
    if (dst_len < out_len + 1) {
        return -1;
    }

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

        if (i + 1 < src_len) {
            dst[j++] = b64_table[(triple >> 6) & 0x3F];
        } else {
            dst[j++] = '=';
        }
        dst[j++] = '=';
    }

    dst[j] = '\0';
    return 0;
}

/* ---- Constant-time comparison ---- */

int
mqvpn_auth_ct_compare(const char *a, size_t a_len,
                       const char *b, size_t b_len)
{
    if (a_len != b_len)
        return 1;

    volatile unsigned char result = 0;
    for (size_t i = 0; i < a_len; i++) {
        result |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return result != 0;
}

/* ---- Key generation ---- */

int
mqvpn_auth_genkey(void)
{
    unsigned char raw[32];
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        LOG_ERR("genkey: cannot open /dev/urandom");
        return -1;
    }
    if (fread(raw, 1, sizeof(raw), fp) != sizeof(raw)) {
        LOG_ERR("genkey: short read from /dev/urandom");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    char b64[64];
    mqvpn_auth_b64_encode(b64, sizeof(b64), raw, sizeof(raw));
    printf("%s\n", b64);
    return 0;
}
