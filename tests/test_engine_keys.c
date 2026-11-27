// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_engine_keys.c — xquic's fixed token key and empty stateless reset key
 * are replaced: a server's token keys in every slot, its reset key stable
 * across restarts, a client's reset key random. Linked with
 * --wrap=xqc_engine_create to see the config the library really passes.
 */

#undef NDEBUG
#include "mqvpn_engine_keys.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static xqc_config_t created;
static int creates;

/* Fails the creation on purpose: only the config matters here, and the fake
 * key file below would not load as a real TLS key. */
xqc_engine_t *
__wrap_xqc_engine_create(xqc_engine_type_t engine_type, const xqc_config_t *engine_config,
                         const xqc_engine_ssl_config_t *ssl_config,
                         const xqc_engine_callback_t *engine_callback,
                         const xqc_transport_callbacks_t *transport_cbs, void *user_data)
{
    (void)engine_type;
    (void)ssl_config;
    (void)engine_callback;
    (void)transport_cbs;
    (void)user_data;
    created = *engine_config;
    creates++;
    return NULL;
}

static void
tun_output_stub(const uint8_t *pkt, size_t len, void *user_ctx)
{
    (void)pkt;
    (void)len;
    (void)user_ctx;
}

static void
tunnel_ready_stub(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    (void)info;
    (void)user_ctx;
}

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
    static char big_content[64 * 1024 + 1];
    memset(big_content, 'k', sizeof(big_content) - 1);
    write_key_file(empty, "");
    write_key_file(big, big_content);

    xqc_config_t c = default_config(XQC_ENGINE_SERVER);
    assert(mqvpn_engine_keys_set_server(&c, "/nonexistent/key.pem") != 0);
    assert(mqvpn_engine_keys_set_server(&c, "") != 0);
    assert(mqvpn_engine_keys_set_server(&c, empty) != 0);
    assert(mqvpn_engine_keys_set_server(&c, big) != 0);
    unlink(empty);
    unlink(big);
}

static void
test_client_passes_its_reset_key_to_the_engine(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = tun_output_stub;
    cbs.tunnel_config_ready = tunnel_ready_stub;

    creates = 0;
    assert(mqvpn_client_new(cfg, &cbs, NULL) == NULL);
    assert(creates == 1);
    assert(created.reset_token_keylen == 32);
    mqvpn_config_free(cfg);
}

static mqvpn_server_t *
new_server(const char *key_file)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_listen(cfg, "127.0.0.1", 443);
    mqvpn_config_set_subnet(cfg, "10.0.0.0/24");
    mqvpn_config_set_tls_cert(cfg, key_file, key_file);
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = tun_output_stub;
    cbs.tunnel_config_ready = tunnel_ready_stub;
    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);
    return s;
}

static void
test_server_passes_its_keys_to_the_engine(void)
{
    char path[64];
    write_key_file(path, "key");
    xqc_config_t fixed = default_config(XQC_ENGINE_SERVER);

    creates = 0;
    assert(new_server(path) == NULL);
    assert(creates == 1);
    xqc_config_t expected = fixed;
    assert(mqvpn_engine_keys_set_server(&expected, path) == 0);
    assert(same_reset_key(&created, &expected));
    for (int i = 0; i < XQC_TOKEN_MAX_KEY_VERSION; i++) {
        assert(created.tk_len_list[i] == 32);
        assert(memcmp(created.token_key_list[i], fixed.token_key_list[i], 32) != 0);
    }
    unlink(path);
}

static void
test_server_without_its_key_file_creates_no_engine(void)
{
    creates = 0;
    assert(new_server("/nonexistent/key.pem") == NULL);
    assert(creates == 0);
}

int
main(void)
{
    test_client_reset_key_is_random();
    test_server_token_keys_fill_every_slot();
    test_server_reset_key_follows_the_key_file();
    test_server_refuses_an_unusable_key_file();
    test_client_passes_its_reset_key_to_the_engine();
    test_server_passes_its_keys_to_the_engine();
    test_server_without_its_key_file_creates_no_engine();
    fprintf(stderr, "test_engine_keys: PASS\n");
    return 0;
}
