// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_engine_keys.c — xquic's fixed token key and empty stateless reset key
 * are replaced: a server's token keys in every slot, its reset key stable
 * across restarts, a client's reset key random.
 */

#undef NDEBUG
#include "mqvpn_engine_keys.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
write_key_file(char *path, const char *content)
{
    strcpy(path, "/tmp/mqvpn_test_keyXXXXXX");
    int fd = mkstemp(path);
    assert(fd >= 0);
    size_t len = strlen(content);
    assert(write(fd, content, len) == (ssize_t)len);
    close(fd);
}

static xqc_config_t
default_config(xqc_engine_type_t type)
{
    /* zeroed: xquic writes only the first 15 bytes of each default token key */
    xqc_config_t c;
    memset(&c, 0, sizeof(c));
    assert(xqc_engine_get_default_config(&c, type) == XQC_OK);
    return c;
}

static int
same_reset_key(const xqc_config_t *a, const xqc_config_t *b)
{
    return a->reset_token_keylen == b->reset_token_keylen &&
           memcmp(a->reset_token_key, b->reset_token_key, a->reset_token_keylen) == 0;
}

static void
test_client_reset_key_is_random(void)
{
    xqc_config_t a = default_config(XQC_ENGINE_CLIENT);
    xqc_config_t b = default_config(XQC_ENGINE_CLIENT);
    assert(a.reset_token_keylen == 0);

    assert(mqvpn_engine_keys_set_client(&a) == 0);
    assert(mqvpn_engine_keys_set_client(&b) == 0);
    assert(a.reset_token_keylen == 32);
    assert(!same_reset_key(&a, &b));
}

static void
test_server_token_keys_fill_every_slot(void)
{
    char path[64];
    write_key_file(path, "key");
    xqc_config_t fixed = default_config(XQC_ENGINE_SERVER);
    xqc_config_t a = fixed;
    xqc_config_t b = fixed;

    assert(mqvpn_engine_keys_set_server(&a, path) == 0);
    assert(mqvpn_engine_keys_set_server(&b, path) == 0);
    for (int i = 0; i < XQC_TOKEN_MAX_KEY_VERSION; i++) {
        assert(a.tk_len_list[i] == 32);
        assert(memcmp(a.token_key_list[i], fixed.token_key_list[i], 32) != 0);
        assert(memcmp(a.token_key_list[i], b.token_key_list[i], 32) != 0);
    }
    unlink(path);
}

static void
test_server_reset_key_follows_the_key_file(void)
{
    char path[64], other[64];
    write_key_file(path, "key");
    write_key_file(other, "another key");
    xqc_config_t a = default_config(XQC_ENGINE_SERVER);
    xqc_config_t restarted = a;
    xqc_config_t b = a;

    assert(mqvpn_engine_keys_set_server(&a, path) == 0);
    assert(mqvpn_engine_keys_set_server(&restarted, path) == 0);
    assert(mqvpn_engine_keys_set_server(&b, other) == 0);
    assert(a.reset_token_keylen == 32);
    assert(same_reset_key(&a, &restarted));
    assert(!same_reset_key(&a, &b));
    unlink(path);
    unlink(other);
}

static void
test_server_refuses_an_unusable_key_file(void)
{
    char empty[64], big[64];
    write_key_file(empty, "");
    write_key_file(big, "");
    FILE *f = fopen(big, "wb");
    assert(f);
    for (int i = 0; i < 64 * 1024; i++)
        fputc('k', f);
    fclose(f);

    xqc_config_t c = default_config(XQC_ENGINE_SERVER);
    assert(mqvpn_engine_keys_set_server(&c, "/nonexistent/key.pem") != 0);
    assert(mqvpn_engine_keys_set_server(&c, "") != 0);
    assert(mqvpn_engine_keys_set_server(&c, empty) != 0);
    assert(mqvpn_engine_keys_set_server(&c, big) != 0);
    unlink(empty);
    unlink(big);
}

int
main(void)
{
    test_client_reset_key_is_random();
    test_server_token_keys_fill_every_slot();
    test_server_reset_key_follows_the_key_file();
    test_server_refuses_an_unusable_key_file();
    fprintf(stderr, "test_engine_keys: PASS\n");
    return 0;
}
