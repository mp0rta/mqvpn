// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* before anything that includes <windows.h>: wincrypt.h defines X509_NAME */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "mqvpn_engine_keys.h"

#include <stdio.h>
#include <stdlib.h>

#define ENGINE_KEY_LEN SHA256_DIGEST_LENGTH

/* far above any PEM private key */
#define TLS_KEY_FILE_MAX (64 * 1024)

_Static_assert(ENGINE_KEY_LEN < XQC_TOKEN_MAX_KEY_LEN &&
                   ENGINE_KEY_LEN <= XQC_RESET_TOKEN_MAX_KEY_LEN,
               "xquic silently ignores a key of this length");

static const char reset_key_label[] = "mqvpn stateless reset key";

int
mqvpn_engine_keys_set_client(xqc_config_t *xconfig)
{
    if (RAND_bytes((uint8_t *)xconfig->reset_token_key, ENGINE_KEY_LEN) != 1) return -1;
    xconfig->reset_token_keylen = ENGINE_KEY_LEN;
    return 0;
}

static int
derive_reset_key(xqc_config_t *xconfig, const char *tls_key_file)
{
    FILE *f = fopen(tls_key_file, "rb");
    if (!f) return -1;

    uint8_t *pem = malloc(TLS_KEY_FILE_MAX);
    if (!pem) {
        fclose(f);
        return -1;
    }
    size_t len = fread(pem, 1, TLS_KEY_FILE_MAX, f);
    int failed = ferror(f) || !feof(f) || len == 0;
    fclose(f);

    unsigned int out_len = 0;
    if (!failed &&
        !HMAC(EVP_sha256(), pem, len, (const uint8_t *)reset_key_label,
              sizeof(reset_key_label) - 1, (uint8_t *)xconfig->reset_token_key, &out_len))
        failed = 1;
    OPENSSL_cleanse(pem, TLS_KEY_FILE_MAX);
    free(pem);
    if (failed) return -1;

    xconfig->reset_token_keylen = out_len;
    return 0;
}

int
mqvpn_engine_keys_set_server(xqc_config_t *xconfig, const char *tls_key_file)
{
    for (int i = 0; i < XQC_TOKEN_MAX_KEY_VERSION; i++) {
        if (RAND_bytes(xconfig->token_key_list[i], ENGINE_KEY_LEN) != 1) return -1;
        xconfig->tk_len_list[i] = ENGINE_KEY_LEN;
    }
    return derive_reset_key(xconfig, tls_key_file);
}
