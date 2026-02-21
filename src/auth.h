/*
 * auth.h — PSK authentication utilities for mqvpn
 *
 * - Key generation: 32 bytes from /dev/urandom → base64
 * - Constant-time comparison for PSK verification
 * - Base64 encoding (RFC 4648)
 */
#ifndef MQVPN_AUTH_H
#define MQVPN_AUTH_H

#include <stddef.h>

/* Generate a random PSK and print to stdout. Returns 0 on success. */
int mqvpn_auth_genkey(void);

/* Constant-time comparison. Returns 0 if equal, nonzero otherwise. */
int mqvpn_auth_ct_compare(const char *a, size_t a_len,
                           const char *b, size_t b_len);

/* Base64 encode src into dst. Returns 0 on success, -1 if dst_len too small. */
int mqvpn_auth_b64_encode(char *dst, size_t dst_len,
                           const unsigned char *src, size_t src_len);

#endif /* MQVPN_AUTH_H */
