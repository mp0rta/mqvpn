// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_jni.c — JNI bridge for libmqvpn Android SDK
 *
 * Maps NativeBridge.kt external funs to libmqvpn C API.
 *
 * Thread model: every client and reactor method (clientConnect, clientTick,
 * reactorWait, reactorAddPath, ...) must be called from the single engine
 * thread the Kotlin MqvpnPoller runs; only reactorWake may come from any
 * thread. There is one engine thread per service instance, and two may
 * overlap while a service is replaced — hence the locked per-client context
 * table below. Callbacks from libmqvpn fire on the client's engine thread
 * (the library is sans-I/O), so GetEnv normally succeeds;
 * AttachCurrentThread is the fallback.
 *
 * Transport (ABI 3): the library owns no socket. Each path fd Kotlin creates
 * is wrapped in a bundled POSIX bind ctx (send: Linux GSO/sendmmsg with the
 * sticky fallback; receive: UDP_GRO) by the reactor in src/platform/android/,
 * which also poll()s the fds and drains them on the engine thread inside
 * reactorWait. No datagram crosses JNI. tun_output stays a direct write().
 */

#include <jni.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <android/log.h>

#include "libmqvpn.h"
#include "log.h"
#include "mqvpn_internal.h"
#include "platform/android/reactor.h"
#include "reorder.h"

#define LOG_TAG   "mqvpn_jni"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

/* Android transport policy. Pushed to BOTH the core (mqvpn_config_set_udp_gso
 * in clientNew) and the bind (reactorAddPath), the way the Linux platform
 * pushes its parsed UdpGso to both, so core batching and bind GSO can never
 * split. Android is a Linux kernel: GSO/GRO engage where supported and the
 * bind falls back by itself where not. No MqvpnConfig key (no new
 * user-facing configuration in ABI 3). */
#define ANDROID_UDP_GSO 1
#define ANDROID_UDP_GRO 1

/* Global library log sink. Every mqvpn_log() line — the bind's udp-gso: /
 * udp-gro: markers and WARNs, the reactor, path_state_machine, auth — used to
 * go to the app process's stderr, which reaches nobody. Installed once in
 * JNI_OnLoad; the tag is "mqvpn" (this file's own lines keep LOG_TAG). Runs
 * on whichever thread logged; __android_log_print is thread-safe. */
static void
jni_global_log_sink(mqvpn_log_level_t level, const char *msg, void *ctx)
{
    (void)ctx;
    int prio;
    switch (level) {
    case MQVPN_LOG_DEBUG: prio = ANDROID_LOG_DEBUG; break;
    case MQVPN_LOG_WARN: prio = ANDROID_LOG_WARN; break;
    case MQVPN_LOG_ERROR: prio = ANDROID_LOG_ERROR; break;
    case MQVPN_LOG_INFO:
    default: prio = ANDROID_LOG_INFO; break;
    }
    __android_log_print(prio, "mqvpn", "%s", msg ? msg : "");
}

/* ─── JNI context (user_ctx for libmqvpn callbacks) ─── */

typedef struct {
    JavaVM *jvm;
    jobject callback_obj; /* GlobalRef — freed in reactorClientDestroy */
    int tun_fd;           /* cached for fast write() in tun_output */

    /* Cached jmethodIDs (looked up once in clientNew) */
    jmethodID mid_tunnel_config_ready;
    jmethodID mid_tunnel_closed;
    jmethodID mid_state_changed;
    jmethodID mid_path_event;
    jmethodID mid_log;
    jmethodID mid_reconnect_scheduled;
} jni_ctx_t;

/* ─── Global JavaVM (set in JNI_OnLoad) ─── */

static JavaVM *g_jvm = NULL;

/* PlatformTrust, resolved once in JNI_OnLoad. All three NULL = reject-all. */
static jclass g_platform_trust_cls = NULL;
static jmethodID g_platform_trust_verify = NULL;
static jclass g_byte_array_cls = NULL;

/*
 * JNI context per client, looked up by the client pointer. A VpnService runs
 * one client at a time, but a service being replaced while its predecessor's
 * finalizer is still running (a stop() whose join timed out) creates the next
 * client before the previous one is destroyed; a process-wide "active
 * context" would then be freed or updated for the wrong client. Small fixed
 * table under a mutex: registered in clientNew, removed in
 * reactorClientDestroy, read by clientSetTunActive.
 */
/* A client whose destroy never runs (engine thread died) keeps its slot for
 * the process's life; a VpnService process never needs more than two. */
#define JNI_MAX_CLIENTS 4
static struct {
    mqvpn_client_t *client;
    jni_ctx_t *ctx;
} g_clients[JNI_MAX_CLIENTS];
static pthread_mutex_t g_clients_lock = PTHREAD_MUTEX_INITIALIZER;

static int
ctx_register(mqvpn_client_t *client, jni_ctx_t *ctx)
{
    int rc = -1;
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < JNI_MAX_CLIENTS; i++) {
        if (!g_clients[i].client) {
            g_clients[i].client = client;
            g_clients[i].ctx = ctx;
            rc = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    return rc;
}

/* The context registered for client, or NULL; with take != 0 it is also
 * removed from the table (the caller owns it from then on). */
static jni_ctx_t *
ctx_lookup(mqvpn_client_t *client, int take)
{
    jni_ctx_t *ctx = NULL;
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < JNI_MAX_CLIENTS; i++) {
        if (g_clients[i].client == client) {
            ctx = g_clients[i].ctx;
            if (take) {
                g_clients[i].client = NULL;
                g_clients[i].ctx = NULL;
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    return ctx;
}

/*
 * Helper: get JNIEnv for the current thread.
 * Since all libmqvpn callbacks fire on the executor thread (which is a JNI
 * thread), GetEnv should succeed without AttachCurrentThread.
 *
 * If fallback attachment is needed (non-JNI thread), *did_attach is set to 1.
 * Caller MUST call the matching detach_if_needed*() (detach_if_needed_vm()
 * for this function; detach_if_needed() for the ctx-based wrapper below)
 * after the JNI upcall to prevent leaks.
 */
static JNIEnv *
get_env_vm(JavaVM *vm, int *did_attach)
{
    JNIEnv *env = NULL;
    *did_attach = 0;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        /* Fallback: attach if called from a non-JNI thread */
        if ((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK) {
            LOGE("Failed to attach thread");
            return NULL;
        }
        *did_attach = 1;
    }
    return env;
}

static void
detach_if_needed_vm(JavaVM *vm, int did_attach)
{
    if (did_attach) (*vm)->DetachCurrentThread(vm);
}

static JNIEnv *
get_env(jni_ctx_t *ctx, int *did_attach)
{
    return get_env_vm(ctx->jvm, did_attach);
}

static void
detach_if_needed(jni_ctx_t *ctx, int did_attach)
{
    detach_if_needed_vm(ctx->jvm, did_attach);
}

/* ─── JNI_OnLoad ─── */

/*
 * Common failure path for JNI_OnLoad below: clears whatever exception is
 * pending, deletes the local refs resolved so far, and logs. Returns
 * JNI_VERSION_1_6 so the library still loads; the failure is fail-closed at
 * verify time through the NULL globals, not at load time (a JNI_ERR would
 * make System.loadLibrary throw). cls/bac may each be NULL (nothing to
 * delete yet at that step).
 *
 * Apart from the Exception*, Delete*Ref and Release* family, a JNI call
 * under a pending exception is undefined behaviour (CheckJNI aborts), so
 * every step in JNI_OnLoad checks before the next call.
 */
static jint
onload_fail(JNIEnv *env, jclass cls, jclass bac, const char *step)
{
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    if (bac) (*env)->DeleteLocalRef(env, bac);
    LOGE("PlatformTrust unavailable (%s): every server certificate will be rejected",
         step);
    return JNI_VERSION_1_6;
}

/*
 * Resolves PlatformTrust.verify once, up front, so the per-handshake
 * verifier never does class/method lookup. Fail closed: if anything here
 * does not resolve, the three globals stay NULL and jni_cert_verify()
 * rejects every certificate (see below) rather than silently trusting.
 * g_platform_trust_verify is assigned last, on purpose: any earlier failure
 * must leave all three globals NULL, and each step below is checked with
 * ExceptionCheck before the next JNI call — never call into JNI (or Java)
 * while an exception from the previous call may still be pending.
 */
JNIEXPORT jint
JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    g_jvm = vm;
    mqvpn_log_set_sink(jni_global_log_sink, NULL);

    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || env == NULL) {
        LOGE("PlatformTrust unavailable (no JNIEnv): every server certificate will be "
             "rejected");
        return JNI_VERSION_1_6;
    }

    jclass cls = (*env)->FindClass(env, "com/mqvpn/sdk/native_/PlatformTrust");
    if (!cls || (*env)->ExceptionCheck(env))
        return onload_fail(env, cls, NULL, "FindClass(PlatformTrust)");

    jmethodID mid = (*env)->GetStaticMethodID(
        env, cls, "verify", "([[BLjava/lang/String;)Ljava/lang/String;");
    if (!mid || (*env)->ExceptionCheck(env))
        return onload_fail(env, cls, NULL, "GetStaticMethodID(verify)");

    jclass bac = (*env)->FindClass(env, "[B");
    if (!bac || (*env)->ExceptionCheck(env))
        return onload_fail(env, cls, bac, "FindClass([B)");

    jclass gcls = (jclass)(*env)->NewGlobalRef(env, cls);
    if (!gcls || (*env)->ExceptionCheck(env))
        return onload_fail(env, cls, bac, "NewGlobalRef(PlatformTrust)");

    jclass gbac = (jclass)(*env)->NewGlobalRef(env, bac);
    if (!gbac || (*env)->ExceptionCheck(env)) {
        (*env)->DeleteGlobalRef(env, gcls);
        return onload_fail(env, cls, bac, "NewGlobalRef([B)");
    }

    (*env)->DeleteLocalRef(env, cls);
    (*env)->DeleteLocalRef(env, bac);
    g_platform_trust_cls = gcls;
    g_byte_array_cls = gbac;
    g_platform_trust_verify = mid;
    return JNI_VERSION_1_6;
}

/* ─── libmqvpn callback trampolines ─── */

/* tun_output: hot path — direct write(), no JNI upcall */
static void
jni_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    if (ctx->tun_fd >= 0) {
        ssize_t n = write(ctx->tun_fd, pkt, len);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            LOGW("tun write failed: %s", strerror(errno));
    }
}

/* tunnel_config_ready: JNI upcall to Java */
static void
jni_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    /* Create byte arrays for IPs */
    jbyteArray assigned_ip = (*env)->NewByteArray(env, 4);
    (*env)->SetByteArrayRegion(env, assigned_ip, 0, 4, (const jbyte *)info->assigned_ip);

    jbyteArray server_ip = (*env)->NewByteArray(env, 4);
    (*env)->SetByteArrayRegion(env, server_ip, 0, 4, (const jbyte *)info->server_ip);

    jbyteArray assigned_ip6 = NULL;
    if (info->has_v6) {
        assigned_ip6 = (*env)->NewByteArray(env, 16);
        (*env)->SetByteArrayRegion(env, assigned_ip6, 0, 16,
                                   (const jbyte *)info->assigned_ip6);
    }

    /* void onNativeTunnelConfigReady(byte[] assignedIp, int prefix,
     *     byte[] assignedIp6, int prefix6, byte[] serverIp, int serverPrefix,
     *     int mtu, boolean hasV6) */
    (*env)->CallVoidMethod(
        env, ctx->callback_obj, ctx->mid_tunnel_config_ready, assigned_ip,
        (jint)info->assigned_prefix, assigned_ip6, (jint)info->assigned_prefix6,
        server_ip, (jint)info->server_prefix, (jint)info->mtu, (jboolean)info->has_v6);

    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    (*env)->DeleteLocalRef(env, assigned_ip);
    (*env)->DeleteLocalRef(env, server_ip);
    if (assigned_ip6) (*env)->DeleteLocalRef(env, assigned_ip6);

    detach_if_needed(ctx, did_attach);
}

/* tunnel_closed: JNI upcall */
static void
jni_tunnel_closed(mqvpn_error_t reason, void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    /* void onNativeTunnelClosed(int errorCode) */
    (*env)->CallVoidMethod(env, ctx->callback_obj, ctx->mid_tunnel_closed, (jint)reason);

    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    detach_if_needed(ctx, did_attach);
}

/* state_changed: JNI upcall */
static void
jni_state_changed(mqvpn_client_state_t old_state, mqvpn_client_state_t new_state,
                  void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    /* void onNativeStateChanged(int oldState, int newState) */
    (*env)->CallVoidMethod(env, ctx->callback_obj, ctx->mid_state_changed,
                           (jint)old_state, (jint)new_state);

    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    detach_if_needed(ctx, did_attach);
}

/* path_event: JNI upcall */
static void
jni_path_event(mqvpn_path_handle_t path, mqvpn_path_status_t status, void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    /* void onNativePathEvent(long pathHandle, int newStatus) */
    (*env)->CallVoidMethod(env, ctx->callback_obj, ctx->mid_path_event, (jlong)path,
                           (jint)status);

    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    detach_if_needed(ctx, did_attach);
}

/* log: JNI upcall */
static void
jni_log(mqvpn_log_level_t level, const char *msg, void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    jstring jmsg = (*env)->NewStringUTF(env, msg ? msg : "");

    /* void onNativeLog(int level, String message) */
    (*env)->CallVoidMethod(env, ctx->callback_obj, ctx->mid_log, (jint)level, jmsg);

    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    (*env)->DeleteLocalRef(env, jmsg);

    detach_if_needed(ctx, did_attach);
}

/* reconnect_scheduled: JNI upcall */
static void
jni_reconnect_scheduled(int delay_sec, void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    /* void onNativeReconnectScheduled(int delaySec) */
    (*env)->CallVoidMethod(env, ctx->callback_obj, ctx->mid_reconnect_scheduled,
                           (jint)delay_sec);

    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    detach_if_needed(ctx, did_attach);
}

/* ─── CLOCK_BOOTTIME injection ─── */

/*
 * CLOCK_BOOTTIME keeps ticking during Android Doze (deep sleep), unlike
 * CLOCK_MONOTONIC which freezes. This prevents QUIC idle timeout from
 * firing all at once after Doze exit.
 */
static uint64_t
android_clock_us(void *ctx)
{
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000;
}

/* ─── JNI method prefix ─── */

#define JNI_FN(name) Java_com_mqvpn_sdk_native_1_NativeBridge_##name

/*
 * NativeBridge is in package "com.mqvpn.sdk.native_".
 * JNI name mangling: underscore in "native_" → "_1", then package separator "_".
 * Result: Java_com_mqvpn_sdk_native_1_NativeBridge_<method>
 */

/* ─── Platform certificate verifier (mqvpn_config_set_cert_verifier) ───
 *
 * Runs on the tick thread inside the TLS handshake; never touches
 * mqvpn_client_*. Fail closed: the only `return 0` is the one after
 * PlatformTrust.verify returned null with no pending exception.
 */

/* Chains longer than this are rejected outright (fail-closed; no real
 * server comes close). */
#define JNI_CERT_MAX 64

static int
jni_call_verifier(JNIEnv *env, jclass cls, jmethodID mid, const uint8_t *const certs[],
                  const size_t cert_len[], size_t n_certs, const char *hostname)
{
    int rc = -1;
    jobjectArray arr = NULL;
    jstring jhost = NULL;
    jobject result = NULL;

    if (n_certs == 0 || n_certs > JNI_CERT_MAX) {
        LOGE("TLS certificate rejected: chain has %zu certificates (allowed 1..%d)",
             n_certs, JNI_CERT_MAX);
        return -1;
    }
    for (size_t i = 0; i < n_certs; i++)
        if (certs[i] == NULL || cert_len[i] == 0 || cert_len[i] > (size_t)INT_MAX) {
            LOGE("TLS certificate rejected: certificate %zu has an unusable length", i);
            return -1;
        }
    if (hostname == NULL || hostname[0] == '\0') {
        LOGE("TLS certificate rejected: empty host");
        return -1;
    }
    /* Mirrors HostIdentifier.classify steps 1-2 on purpose: C must refuse
     * before NewStringUTF (CheckJNI aborts on invalid modified UTF-8) and
     * before a possibly-truncated 255-byte host crosses into Java. Kotlin
     * stays the rule of record and re-checks. Change both or neither. */
    size_t hlen = strnlen(hostname, 256);
    if (hlen >= 255) {
        LOGE(
            "TLS certificate rejected: host is 255 bytes or longer (possibly truncated)");
        return -1;
    }
    for (size_t i = 0; i < hlen; i++)
        if ((unsigned char)hostname[i] < 0x21 || (unsigned char)hostname[i] > 0x7E) {
            LOGE("TLS certificate rejected: host contains a non-printable or non-ASCII "
                 "byte");
            return -1;
        }

    if (!g_byte_array_cls) {
        LOGE("TLS certificate rejected: PlatformTrust unavailable");
        return -1;
    }
    arr = (*env)->NewObjectArray(env, (jsize)n_certs, g_byte_array_cls, NULL);
    if (!arr || (*env)->ExceptionCheck(env)) goto out;
    for (size_t i = 0; i < n_certs; i++) {
        jbyteArray ba = (*env)->NewByteArray(env, (jsize)cert_len[i]);
        if (!ba || (*env)->ExceptionCheck(env)) goto out;
        (*env)->SetByteArrayRegion(env, ba, 0, (jsize)cert_len[i],
                                   (const jbyte *)certs[i]);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->DeleteLocalRef(env, ba);
            goto out;
        }
        (*env)->SetObjectArrayElement(env, arr, (jsize)i, ba);
        (*env)->DeleteLocalRef(env, ba);
        if ((*env)->ExceptionCheck(env)) goto out;
    }
    jhost =
        (*env)->NewStringUTF(env, hostname); /* printable ASCII: valid modified UTF-8 */
    if (!jhost || (*env)->ExceptionCheck(env)) goto out;

    result = (*env)->CallStaticObjectMethod(env, cls, mid, arr, jhost);
    if ((*env)->ExceptionCheck(env)) {
        /* Exception first: a NULL result under a pending exception must never read as
         * trusted. The return value is undefined under a pending exception — do not touch
         * it. */
        result = NULL;
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("TLS certificate rejected: platform verifier threw");
        goto out;
    }
    if (result == NULL) {
        rc = 0; /* trusted */
        goto out;
    }
    {
        const char *reason = (*env)->GetStringUTFChars(env, (jstring)result, NULL);
        if (!reason || (*env)->ExceptionCheck(env)) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            LOGE("TLS certificate rejected by platform (reason unavailable)");
        } else {
            LOGE("TLS certificate rejected by platform: %s", reason);
            (*env)->ReleaseStringUTFChars(env, (jstring)result, reason);
        }
    }
out:
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (result) (*env)->DeleteLocalRef(env, result);
    if (jhost) (*env)->DeleteLocalRef(env, jhost);
    if (arr) (*env)->DeleteLocalRef(env, arr);
    return rc;
}

static int
jni_cert_verify(const uint8_t *const certs[], const size_t cert_len[], size_t n_certs,
                const char *hostname, void *ctx)
{
    (void)ctx;
    if (!g_platform_trust_cls || !g_platform_trust_verify || !g_byte_array_cls) {
        LOGE("TLS certificate rejected: PlatformTrust unavailable");
        return -1;
    }
    int did_attach = 0;
    JNIEnv *env = get_env_vm(g_jvm, &did_attach);
    if (!env) return -1;
    int rc = jni_call_verifier(env, g_platform_trust_cls, g_platform_trust_verify, certs,
                               cert_len, n_certs, hostname);
    detach_if_needed_vm(g_jvm, did_attach);
    return rc;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Config methods
 * ════════════════════════════════════════════════════════════════════════════ */

/* configNew() → long */
JNIEXPORT jlong JNICALL
JNI_FN(configNew)(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    mqvpn_config_t *cfg = mqvpn_config_new();
    return (jlong)(intptr_t)cfg;
}

/* configFree(cfg: Long) */
JNIEXPORT void JNICALL
JNI_FN(configFree)(JNIEnv *env, jobject thiz, jlong cfg)
{
    (void)env;
    (void)thiz;
    mqvpn_config_free((mqvpn_config_t *)(intptr_t)cfg);
}

/* configSetServer(cfg, host, port) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetServer)(JNIEnv *env, jobject thiz, jlong cfg, jstring host, jint port)
{
    (void)thiz;
    const char *h = (*env)->GetStringUTFChars(env, host, NULL);
    if (!h) return MQVPN_ERR_NO_MEMORY;

    int rc = mqvpn_config_set_server((mqvpn_config_t *)(intptr_t)cfg, h, port);
    (*env)->ReleaseStringUTFChars(env, host, h);
    return rc;
}

/* configSetTlsServerName(cfg, name) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetTlsServerName)(JNIEnv *env, jobject thiz, jlong cfg, jstring name)
{
    (void)thiz;
    const char *n = (*env)->GetStringUTFChars(env, name, NULL);
    if (!n) return MQVPN_ERR_NO_MEMORY;

    int rc = mqvpn_config_set_tls_server_name((mqvpn_config_t *)(intptr_t)cfg, n);
    (*env)->ReleaseStringUTFChars(env, name, n);
    return rc;
}

/* configSetAuthKey(cfg, key) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetAuthKey)(JNIEnv *env, jobject thiz, jlong cfg, jstring key)
{
    (void)thiz;
    const char *k = (*env)->GetStringUTFChars(env, key, NULL);
    if (!k) return MQVPN_ERR_NO_MEMORY;

    int rc = mqvpn_config_set_auth_key((mqvpn_config_t *)(intptr_t)cfg, k);
    (*env)->ReleaseStringUTFChars(env, key, k);
    return rc;
}

/* configSetInsecure(cfg, insecure) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetInsecure)(JNIEnv *env, jobject thiz, jlong cfg, jboolean insecure)
{
    (void)env;
    (void)thiz;
    return mqvpn_config_set_insecure((mqvpn_config_t *)(intptr_t)cfg, insecure ? 1 : 0);
}

/* configSetScheduler(cfg, scheduler) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetScheduler)(JNIEnv *env, jobject thiz, jlong cfg, jint scheduler)
{
    (void)env;
    (void)thiz;
    return mqvpn_config_set_scheduler((mqvpn_config_t *)(intptr_t)cfg,
                                      (mqvpn_scheduler_t)scheduler);
}

/* configSetLogLevel(cfg, level) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetLogLevel)(JNIEnv *env, jobject thiz, jlong cfg, jint level)
{
    (void)env;
    (void)thiz;
    return mqvpn_config_set_log_level((mqvpn_config_t *)(intptr_t)cfg,
                                      (mqvpn_log_level_t)level);
}

/* configSetMultipath(cfg, enable) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetMultipath)(JNIEnv *env, jobject thiz, jlong cfg, jboolean enable)
{
    (void)env;
    (void)thiz;
    return mqvpn_config_set_multipath((mqvpn_config_t *)(intptr_t)cfg, enable ? 1 : 0);
}

/* configSetAndroidClock(cfg) → int
 * Injects CLOCK_BOOTTIME as the time source. */
JNIEXPORT jint JNICALL
JNI_FN(configSetAndroidClock)(JNIEnv *env, jobject thiz, jlong cfg)
{
    (void)env;
    (void)thiz;
    return mqvpn_config_set_clock((mqvpn_config_t *)(intptr_t)cfg, android_clock_us,
                                  NULL);
}

/* configSetPlatformCaps(cfg, caps) → int — Phase 4 reserved */
JNIEXPORT jint JNICALL
JNI_FN(configSetPlatformCaps)(JNIEnv *env, jobject thiz, jlong cfg, jint caps)
{
    (void)env;
    (void)thiz;
    (void)cfg;
    (void)caps;
    return MQVPN_OK; /* reserved — no-op */
}

/* configSetExecutionProfile(cfg, profile) → int — Phase 4 reserved */
JNIEXPORT jint JNICALL
JNI_FN(configSetExecutionProfile)(JNIEnv *env, jobject thiz, jlong cfg, jint profile)
{
    (void)env;
    (void)thiz;
    (void)cfg;
    (void)profile;
    return MQVPN_OK; /* reserved — no-op */
}

/* configSetReconnect(cfg, enable, intervalSec) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetReconnect)(JNIEnv *env, jobject thiz, jlong cfg, jboolean enable,
                           jint intervalSec)
{
    (void)env;
    (void)thiz;
    return mqvpn_config_set_reconnect((mqvpn_config_t *)(intptr_t)cfg, enable ? 1 : 0,
                                      intervalSec);
}

/* configSetKillswitchHint(cfg, enable) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetKillswitchHint)(JNIEnv *env, jobject thiz, jlong cfg, jboolean enable)
{
    (void)env;
    (void)thiz;
    return mqvpn_config_set_killswitch_hint((mqvpn_config_t *)(intptr_t)cfg,
                                            enable ? 1 : 0);
}

/* configSetReorderEnabled(cfg, mode) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetReorderEnabled)(JNIEnv *env, jobject thiz, jlong cfg, jint mode)
{
    (void)env;
    (void)thiz;
    return mqvpn_config_set_reorder_enabled((mqvpn_config_t *)(intptr_t)cfg,
                                            (mqvpn_reorder_mode_t)mode);
}

/* configAddReorderRule(cfg, proto, port, profile) → int */
JNIEXPORT jint JNICALL
JNI_FN(configAddReorderRule)(JNIEnv *env, jobject thiz, jlong cfg, jint proto, jint port,
                             jint profile)
{
    (void)env;
    (void)thiz;
    if (proto < 0 || proto > 255) return -1;
    if (port < 1 || port > 65535) return -1;
    return mqvpn_config_add_reorder_rule((mqvpn_config_t *)(intptr_t)cfg, (uint8_t)proto,
                                         (uint16_t)port,
                                         (mqvpn_reorder_profile_t)profile);
}

/* configSetHybridEnabled(cfg, enable) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetHybridEnabled)(JNIEnv *env, jobject thiz, jlong cfg, jboolean enable)
{
    (void)env;
    (void)thiz;
    return mqvpn_config_set_hybrid_enabled((mqvpn_config_t *)(intptr_t)cfg,
                                           enable ? 1 : 0);
}

/* configSetHybridTcpMode(cfg, mode: 0=stream 1=raw 2=auto) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetHybridTcpMode)(JNIEnv *env, jobject thiz, jlong cfg, jint mode)
{
    (void)env;
    (void)thiz;
    return mqvpn_config_set_hybrid_tcp_mode((mqvpn_config_t *)(intptr_t)cfg, (int)mode);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Client lifecycle
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * clientNew(cfg, callbackObj) → long (client handle)
 *
 * Creates a GlobalRef for callbackObj and caches all jmethodIDs.
 * The GlobalRef prevents GC from collecting the callback object.
 * It is released in reactorClientDestroy.
 */
JNIEXPORT jlong JNICALL
JNI_FN(clientNew)(JNIEnv *env, jobject thiz, jlong cfg, jobject callbackObj)
{
    (void)thiz;

    /* Always install the platform verifier, before any JNI-owned state is
     * allocated so a failure has nothing to clean up. This must stay the
     * first real statement in the function. cfg is the mutable handle
     * configNew() created; the jlong→pointer conversion is just that. */
    int vrc = mqvpn_config_set_cert_verifier((mqvpn_config_t *)(intptr_t)cfg,
                                             jni_cert_verify, NULL);
    if (vrc != MQVPN_OK) {
        LOGE("mqvpn_config_set_cert_verifier failed: %d", vrc);
        return 0;
    }
    /* Same constant the reactor hands the bind: one source for the policy. */
    int grc = mqvpn_config_set_udp_gso((mqvpn_config_t *)(intptr_t)cfg, ANDROID_UDP_GSO);
    if (grc != MQVPN_OK) {
        LOGE("mqvpn_config_set_udp_gso failed: %d", grc);
        return 0;
    }

    jni_ctx_t *ctx = calloc(1, sizeof(jni_ctx_t));
    if (!ctx) return 0;

    (*env)->GetJavaVM(env, &ctx->jvm);
    ctx->callback_obj = (*env)->NewGlobalRef(env, callbackObj);
    ctx->tun_fd = -1;

    if (!ctx->callback_obj) {
        LOGE("NewGlobalRef failed");
        free(ctx);
        return 0;
    }

    /* Cache jmethodIDs — these are stable for the lifetime of the class. */
    jclass cls = (*env)->GetObjectClass(env, callbackObj);

    ctx->mid_tunnel_config_ready =
        (*env)->GetMethodID(env, cls, "onNativeTunnelConfigReady", "([BI[BI[BIIZ)V");

    ctx->mid_tunnel_closed =
        (*env)->GetMethodID(env, cls, "onNativeTunnelClosed", "(I)V");

    ctx->mid_state_changed =
        (*env)->GetMethodID(env, cls, "onNativeStateChanged", "(II)V");

    ctx->mid_path_event = (*env)->GetMethodID(env, cls, "onNativePathEvent", "(JI)V");

    ctx->mid_log = (*env)->GetMethodID(env, cls, "onNativeLog", "(ILjava/lang/String;)V");

    ctx->mid_reconnect_scheduled =
        (*env)->GetMethodID(env, cls, "onNativeReconnectScheduled", "(I)V");

    (*env)->DeleteLocalRef(env, cls);

    /* Check all method IDs resolved */
    if (!ctx->mid_tunnel_config_ready || !ctx->mid_tunnel_closed ||
        !ctx->mid_state_changed || !ctx->mid_path_event || !ctx->mid_log ||
        !ctx->mid_reconnect_scheduled) {
        LOGE("Failed to resolve callback method IDs");
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->DeleteGlobalRef(env, ctx->callback_obj);
        free(ctx);
        return 0;
    }

    /* Build callbacks struct */
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = jni_tun_output;
    cbs.tunnel_config_ready = jni_tunnel_config_ready;
    cbs.tunnel_closed = jni_tunnel_closed;
    cbs.ready_for_tun = NULL; /* Android creates TUN in tunnel_config_ready */
    cbs.state_changed = jni_state_changed;
    cbs.path_event = jni_path_event;
    cbs.mtu_updated = NULL;
    cbs.log = jni_log;
    cbs.reconnect_scheduled = jni_reconnect_scheduled;

    mqvpn_client_t *client =
        mqvpn_client_new((const mqvpn_config_t *)(intptr_t)cfg, &cbs, ctx);

    if (!client) {
        LOGE("mqvpn_client_new failed");
        (*env)->DeleteGlobalRef(env, ctx->callback_obj);
        free(ctx);
        return 0;
    }

    if (ctx_register(client, ctx) != 0) {
        /* More clients alive than a service lifecycle can produce: refuse
         * rather than lose track of a context. */
        LOGE("too many live clients (%d)", JNI_MAX_CLIENTS);
        mqvpn_client_destroy(client);
        (*env)->DeleteGlobalRef(env, ctx->callback_obj);
        free(ctx);
        return 0;
    }
    return (jlong)(intptr_t)client;
}

/*
 * reactorClientDestroy(reactor: Long, client: Long)
 *
 * Whole-client teardown through the reactor (the destroy contract of
 * libmqvpn.h: stop polling, harvest RX totals, mqvpn_client_destroy — which
 * finalises every attached bind ctx — then forget the table), then releases
 * the GlobalRef on the callback object. Kotlin closes the path fds AFTER this
 * returns; the client handle is invalid afterwards. The only destroy entry
 * point. Without a reactor (a caller bug: the executor always owns one) the
 * client is destroyed directly, as clientNew does on its full-table path —
 * the reactor composite over an empty table — and the error is logged.
 */
JNIEXPORT void JNICALL
JNI_FN(reactorClientDestroy)(JNIEnv *env, jobject thiz, jlong reactor, jlong client)
{
    (void)thiz;
    mqvpn_android_reactor_t *r = (mqvpn_android_reactor_t *)(intptr_t)reactor;
    mqvpn_client_t *c = (mqvpn_client_t *)(intptr_t)client;
    if (!c) return;

    /* Take THIS client's context out of the table before the destroy
     * invalidates the pointer; a client created meanwhile keeps its own
     * entry untouched. No entry means c is not a live client of this bridge
     * (clientNew either registers a client or destroys it): leave it alone. */
    jni_ctx_t *ctx = ctx_lookup(c, 1);
    if (!ctx) {
        LOGE("reactorClientDestroy: client %p unknown (already destroyed?)", (void *)c);
        return;
    }

    if (r) {
        mqvpn_android_reactor_client_destroy(r, c);
    } else {
        LOGE("reactorClientDestroy: no reactor; destroying the client directly");
        mqvpn_client_destroy(c);
    }

    (*env)->DeleteGlobalRef(env, ctx->callback_obj);
    free(ctx);
}

/* clientConnect(client) → int */
JNIEXPORT jint JNICALL
JNI_FN(clientConnect)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)env;
    (void)thiz;
    return mqvpn_client_connect((mqvpn_client_t *)(intptr_t)client);
}

/* clientDisconnect(client) → int */
JNIEXPORT jint JNICALL
JNI_FN(clientDisconnect)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)env;
    (void)thiz;
    return mqvpn_client_disconnect((mqvpn_client_t *)(intptr_t)client);
}

/* clientSetTunActive(client, active, tunFd) → int */
JNIEXPORT jint JNICALL
JNI_FN(clientSetTunActive)(JNIEnv *env, jobject thiz, jlong client, jboolean active,
                           jint tunFd)
{
    (void)env;
    (void)thiz;
    mqvpn_client_t *c = (mqvpn_client_t *)(intptr_t)client;

    /* Update THIS client's cached tun_fd for the tun_output fast path */
    jni_ctx_t *ctx = ctx_lookup(c, 0);
    if (ctx) {
        ctx->tun_fd = active ? tunFd : -1;
    }

    return mqvpn_client_set_tun_active(c, active ? 1 : 0, tunFd);
}

/*
 * clientSetServerAddr(client, host, port) → int
 *
 * Resolves host:port to a sockaddr and calls mqvpn_client_set_server_addr().
 * Must be called before clientConnect() — xquic needs the peer address
 * before the first path can send.
 */
JNIEXPORT jint JNICALL
JNI_FN(clientSetServerAddr)(JNIEnv *env, jobject thiz, jlong client, jstring host,
                            jint port)
{
    (void)thiz;
    mqvpn_client_t *c = (mqvpn_client_t *)(intptr_t)client;
    if (!c) return MQVPN_ERR_INVALID_ARG;

    const char *h = (*env)->GetStringUTFChars(env, host, NULL);
    if (!h) return MQVPN_ERR_NO_MEMORY;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", (int)port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    int gai_rc = getaddrinfo(h, port_str, &hints, &res);
    (*env)->ReleaseStringUTFChars(env, host, h);

    if (gai_rc != 0 || !res) {
        LOGE("getaddrinfo failed: %s", gai_strerror(gai_rc));
        if (res) freeaddrinfo(res);
        return MQVPN_ERR_INVALID_ARG;
    }

    int rc = mqvpn_client_set_server_addr(c, res->ai_addr, (socklen_t)res->ai_addrlen);
    freeaddrinfo(res);
    return rc;
}

/* clientTick(client) → int */
JNIEXPORT jint JNICALL
JNI_FN(clientTick)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)env;
    (void)thiz;
    return mqvpn_client_tick((mqvpn_client_t *)(intptr_t)client);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Reactor — the engine thread's poll()/eventfd loop and the path lifecycle
 *  (src/platform/android/reactor.h). Owned by the Kotlin executor, not by a
 *  client: it outlives sessions and reactorWake never touches a client.
 * ════════════════════════════════════════════════════════════════════════════ */

/* reactorNew() → long (reactor pointer), 0 on failure */
JNIEXPORT jlong JNICALL
JNI_FN(reactorNew)(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jlong)(intptr_t)mqvpn_android_reactor_new();
}

/* reactorFree(reactor): after the poller thread has left its loop and every
 * client was destroyed through reactorClientDestroy. */
JNIEXPORT void JNICALL
JNI_FN(reactorFree)(JNIEnv *env, jobject thiz, jlong reactor)
{
    (void)env;
    (void)thiz;
    mqvpn_android_reactor_free((mqvpn_android_reactor_t *)(intptr_t)reactor);
}

/* reactorWake(reactor) → int. Any thread. */
JNIEXPORT jint JNICALL
JNI_FN(reactorWake)(JNIEnv *env, jobject thiz, jlong reactor)
{
    (void)env;
    (void)thiz;
    return mqvpn_android_reactor_wake((mqvpn_android_reactor_t *)(intptr_t)reactor);
}

/* reactorWait(reactor, client, timeoutMs) → int: drains performed, or -1.
 * client may be 0 only while no path is attached. */
JNIEXPORT jint JNICALL
JNI_FN(reactorWait)(JNIEnv *env, jobject thiz, jlong reactor, jlong client,
                    jint timeoutMs)
{
    (void)env;
    (void)thiz;
    return mqvpn_android_reactor_wait((mqvpn_android_reactor_t *)(intptr_t)reactor,
                                      (mqvpn_client_t *)(intptr_t)client, (int)timeoutMs);
}

/* reactorTakeBadFd(reactor) → long: the next handle whose fd was found closed
 * behind the platform (POLLNVAL), or -1. Delivered once. */
JNIEXPORT jlong JNICALL
JNI_FN(reactorTakeBadFd)(JNIEnv *env, jobject thiz, jlong reactor)
{
    (void)env;
    (void)thiz;
    return (jlong)mqvpn_android_reactor_take_bad_fd(
        (mqvpn_android_reactor_t *)(intptr_t)reactor);
}

/* reactorAddPath(reactor, client, fd, iface) → long (path handle), -1 on
 * failure with the fd untouched (Kotlin closes it). The fd is BORROWED: the
 * bind ctx never closes it. */
JNIEXPORT jlong JNICALL
JNI_FN(reactorAddPath)(JNIEnv *env, jobject thiz, jlong reactor, jlong client, jint fd,
                       jstring iface)
{
    (void)thiz;
    char name[16] = {0};
    if (iface) {
        const char *n = (*env)->GetStringUTFChars(env, iface, NULL);
        /* NULL: OutOfMemoryError pending. Fail with the fd untouched. */
        if (!n) return -1;
        snprintf(name, sizeof(name), "%s", n);
        (*env)->ReleaseStringUTFChars(env, iface, n);
    }
    return (jlong)mqvpn_android_reactor_add_path(
        (mqvpn_android_reactor_t *)(intptr_t)reactor, (mqvpn_client_t *)(intptr_t)client,
        (int)fd, name, ANDROID_UDP_GSO, ANDROID_UDP_GRO);
}

/* reactorRemovePath(reactor, client, pathHandle) → int. Orderly removal:
 * the library abandons the path and the reactor stops polling the fd; Kotlin
 * then closes the fd (never on the bad-fd chain) and calls reactorPathReleased. */
JNIEXPORT jint JNICALL
JNI_FN(reactorRemovePath)(JNIEnv *env, jobject thiz, jlong reactor, jlong client,
                          jlong pathHandle)
{
    (void)env;
    (void)thiz;
    return mqvpn_android_reactor_remove_path((mqvpn_android_reactor_t *)(intptr_t)reactor,
                                             (mqvpn_client_t *)(intptr_t)client,
                                             (mqvpn_path_handle_t)pathHandle);
}

/* reactorPathReleased(reactor, client, pathHandle) → int: MQVPN_OK, a library
 * error (the transport then stays library-owned until destroy), or
 * MQVPN_REACTOR_POISONED (-100: ledger corruption, end the session). */
JNIEXPORT jint JNICALL
JNI_FN(reactorPathReleased)(JNIEnv *env, jobject thiz, jlong reactor, jlong client,
                            jlong pathHandle)
{
    (void)env;
    (void)thiz;
    return mqvpn_android_reactor_path_released(
        (mqvpn_android_reactor_t *)(intptr_t)reactor, (mqvpn_client_t *)(intptr_t)client,
        (mqvpn_path_handle_t)pathHandle);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  I/O feed (TUN only — path receive happens inside reactorWait)
 * ════════════════════════════════════════════════════════════════════════════ */

/* onTunPacket(client, pkt, offset, len) → int */
JNIEXPORT jint JNICALL
JNI_FN(onTunPacket)(JNIEnv *env, jobject thiz, jlong client, jbyteArray pkt, jint offset,
                    jint len)
{
    (void)thiz;
    mqvpn_client_t *c = (mqvpn_client_t *)(intptr_t)client;

    jbyte *data = (*env)->GetByteArrayElements(env, pkt, NULL);
    if (!data) return MQVPN_ERR_NO_MEMORY;

    int rc = mqvpn_client_on_tun_packet(c, (const uint8_t *)(data + offset), (size_t)len);

    (*env)->ReleaseByteArrayElements(env, pkt, data, JNI_ABORT);
    return rc;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Query
 * ════════════════════════════════════════════════════════════════════════════ */

/* getState(client) → int */
JNIEXPORT jint JNICALL
JNI_FN(getState)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)env;
    (void)thiz;
    return (jint)mqvpn_client_get_state((const mqvpn_client_t *)(intptr_t)client);
}

/*
 * getStats(client) → LongArray:
 * [bytesTx, bytesRx, dgramSent, dgramRecv, dgramLost, dgramAcked, srttMs]
 */
JNIEXPORT jlongArray JNICALL
JNI_FN(getStats)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)thiz;
    mqvpn_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    stats.struct_size = sizeof(stats);

    int rc = mqvpn_client_get_stats((const mqvpn_client_t *)(intptr_t)client, &stats);
    if (rc != MQVPN_OK) return NULL;

    jlong values[7] = {
        (jlong)stats.bytes_tx,   (jlong)stats.bytes_rx,   (jlong)stats.dgram_sent,
        (jlong)stats.dgram_recv, (jlong)stats.dgram_lost, (jlong)stats.dgram_acked,
        (jlong)stats.srtt_ms,
    };

    jlongArray arr = (*env)->NewLongArray(env, 7);
    if (arr) (*env)->SetLongArrayRegion(env, arr, 0, 7, values);
    return arr;
}

/*
 * getPaths(client) → Array<Any>
 * Returns array of Object arrays, each: [handle, status, iface, bytesTx, bytesRx, srttMs]
 */
JNIEXPORT jobjectArray JNICALL
JNI_FN(getPaths)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)thiz;
    enum { MAX_PATHS = 8 };
    mqvpn_path_info_t paths[MAX_PATHS];
    int n_paths = 0;

    int rc = mqvpn_client_get_paths((const mqvpn_client_t *)(intptr_t)client, paths,
                                    MAX_PATHS, &n_paths);
    if (rc != MQVPN_OK || n_paths <= 0) return NULL;

    jclass objClass = (*env)->FindClass(env, "java/lang/Object");
    jobjectArray outer = (*env)->NewObjectArray(env, n_paths, objClass, NULL);
    if (!outer) return NULL;

    for (int i = 0; i < n_paths; i++) {
        /* Each path: [handle(Long), status(Int), iface(String),
         *   bytesTx(Long), bytesRx(Long), srttMs(Long)] */
        jobjectArray inner = (*env)->NewObjectArray(env, 6, objClass, NULL);

        /* Box primitives */
        jclass longCls = (*env)->FindClass(env, "java/lang/Long");
        jmethodID longOf =
            (*env)->GetStaticMethodID(env, longCls, "valueOf", "(J)Ljava/lang/Long;");

        jclass intCls = (*env)->FindClass(env, "java/lang/Integer");
        jmethodID intOf =
            (*env)->GetStaticMethodID(env, intCls, "valueOf", "(I)Ljava/lang/Integer;");

        (*env)->SetObjectArrayElement(
            env, inner, 0,
            (*env)->CallStaticObjectMethod(env, longCls, longOf, (jlong)paths[i].handle));
        (*env)->SetObjectArrayElement(
            env, inner, 1,
            (*env)->CallStaticObjectMethod(env, intCls, intOf, (jint)paths[i].status));
        (*env)->SetObjectArrayElement(env, inner, 2,
                                      (*env)->NewStringUTF(env, paths[i].name));
        (*env)->SetObjectArrayElement(
            env, inner, 3,
            (*env)->CallStaticObjectMethod(env, longCls, longOf,
                                           (jlong)paths[i].bytes_tx));
        (*env)->SetObjectArrayElement(
            env, inner, 4,
            (*env)->CallStaticObjectMethod(env, longCls, longOf,
                                           (jlong)paths[i].bytes_rx));
        (*env)->SetObjectArrayElement(env, inner, 5,
                                      (*env)->CallStaticObjectMethod(
                                          env, longCls, longOf, (jlong)paths[i].srtt_ms));

        (*env)->SetObjectArrayElement(env, outer, i, inner);
        (*env)->DeleteLocalRef(env, inner);
        (*env)->DeleteLocalRef(env, longCls);
        (*env)->DeleteLocalRef(env, intCls);
    }

    (*env)->DeleteLocalRef(env, objClass);
    return outer;
}

/*
 * getInterest(client) → IntArray: [nextTimerMs, tunReadable, isIdle]
 */
JNIEXPORT jintArray JNICALL
JNI_FN(getInterest)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)thiz;
    mqvpn_interest_t interest;
    memset(&interest, 0, sizeof(interest));
    interest.struct_size = sizeof(interest);

    int rc =
        mqvpn_client_get_interest((const mqvpn_client_t *)(intptr_t)client, &interest);
    if (rc != MQVPN_OK) return NULL;

    jint values[3] = {
        interest.next_timer_ms,
        interest.tun_readable,
        interest.is_idle,
    };

    jintArray arr = (*env)->NewIntArray(env, 3);
    if (arr) (*env)->SetIntArrayRegion(env, arr, 0, 3, values);
    return arr;
}

/*
 * getReorderStats(client) → LongArray:
 * [deliveredCount, gapCount, gapFilledCount, gapTimeoutCount,
 *  ackDemoteCount, p50Ms, p99Ms]
 */
JNIEXPORT jlongArray JNICALL
JNI_FN(getReorderStats)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)thiz;
    mqvpn_reorder_stats_t st;
    if (mqvpn_client_get_reorder_stats((const mqvpn_client_t *)(intptr_t)client, &st) !=
        0)
        return NULL;

    double p50 = mqvpn_reorder_latency_buffered_percentile(&st, 0.50);
    double p99 = mqvpn_reorder_latency_buffered_percentile(&st, 0.99);

    jlong values[7] = {
        (jlong)st.delivered_count,  (jlong)st.gap_count,
        (jlong)st.gap_filled_count, (jlong)st.gap_timeout_count,
        (jlong)st.ack_demote_count, (jlong)(p50 + 0.5),
        (jlong)(p99 + 0.5),
    };
    jlongArray arr = (*env)->NewLongArray(env, 7);
    if (arr) (*env)->SetLongArrayRegion(env, arr, 0, 7, values);
    return arr;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Utility
 * ════════════════════════════════════════════════════════════════════════════ */

/* versionString() → String */
JNIEXPORT jstring JNICALL
JNI_FN(versionString)(JNIEnv *env, jobject thiz)
{
    (void)thiz;
    const char *ver = mqvpn_version_string();
    return (*env)->NewStringUTF(env, ver ? ver : "unknown");
}

/* generateKey() → String? */
JNIEXPORT jstring JNICALL
JNI_FN(generateKey)(JNIEnv *env, jobject thiz)
{
    (void)thiz;
    char buf[128];
    int rc = mqvpn_generate_key(buf, sizeof(buf));
    if (rc != MQVPN_OK) return NULL;
    return (*env)->NewStringUTF(env, buf);
}

#ifdef MQVPN_JNI_TEST_SEAMS
/* ─── Test-only entry points (debug build type only; NativeBridgeTestSeams) ─── */
#  define JNI_TEST_FN(name) Java_com_mqvpn_sdk_native_1_NativeBridgeTestSeams_##name

/* Marshals the Kotlin arrays into C arrays and calls `fn`, which is either
 * the production entry point jni_cert_verify (reject-all check + env + the
 * upcall to PlatformTrust.verify) or the throwing variant below. */
typedef int (*seam_verify_fn)(const uint8_t *const certs[], const size_t cert_len[],
                              size_t n, const char *host, void *arg);

static int
seam_marshal_and_call(JNIEnv *env, seam_verify_fn fn, void *arg, jobjectArray chain,
                      jstring host)
{
    jsize n = (*env)->GetArrayLength(env, chain);
    if (n <= 0 || n > JNI_CERT_MAX) return -1;
    /* n element refs + cls (throwing seam) + arr/ba/jhost/result in jni_call_verifier,
     * with slack */
    if ((*env)->EnsureLocalCapacity(env, n + 8) != JNI_OK ||
        (*env)->ExceptionCheck(env)) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return -1;
    }
    const uint8_t *certs[JNI_CERT_MAX];
    size_t lens[JNI_CERT_MAX];
    jbyteArray refs[JNI_CERT_MAX];
    memset(certs, 0, sizeof(certs));
    memset(lens, 0, sizeof(lens));
    memset(refs, 0, sizeof(refs));
    int rc = -1;
    for (jsize i = 0; i < n; i++) {
        refs[i] = (jbyteArray)(*env)->GetObjectArrayElement(env, chain, i);
        if (!refs[i]) goto out;
        lens[i] = (size_t)(*env)->GetArrayLength(env, refs[i]);
        certs[i] = (const uint8_t *)(*env)->GetByteArrayElements(env, refs[i], NULL);
        if (!certs[i]) goto out;
    }
    const char *h = (*env)->GetStringUTFChars(env, host, NULL);
    if (!h) goto out;
    rc = fn(certs, lens, (size_t)n, h, arg);
    (*env)->ReleaseStringUTFChars(env, host, h);
out:
    for (jsize i = 0; i < n; i++) {
        if (refs[i] && certs[i])
            (*env)->ReleaseByteArrayElements(env, refs[i], (jbyte *)certs[i], JNI_ABORT);
        if (refs[i]) (*env)->DeleteLocalRef(env, refs[i]);
    }
    return rc;
}

/* nativeVerifyForTest(chain, host): the exact production entry point, jni_cert_verify
 * (reject-all check, env acquisition, jni_call_verifier, PlatformTrust.verify). */
JNIEXPORT jint JNICALL
JNI_TEST_FN(nativeVerifyForTest)(JNIEnv *env, jobject thiz, jobjectArray chain,
                                 jstring host)
{
    (void)thiz;
    return seam_marshal_and_call(env, jni_cert_verify, NULL, chain, host);
}

/* nativeVerifyThrowingForTest(chain, host): jni_call_verifier against a Kotlin method
 * that throws */
static int
seam_throwing_verify(const uint8_t *const certs[], const size_t cert_len[], size_t n,
                     const char *host, void *arg)
{
    JNIEnv *env = (JNIEnv *)arg;
    jclass cls = (*env)->FindClass(env, "com/mqvpn/sdk/native_/NativeBridgeTestSeams");
    if (!cls) {
        (*env)->ExceptionClear(env);
        return -1;
    }
    jmethodID mid = (*env)->GetStaticMethodID(
        env, cls, "throwingVerify", "([[BLjava/lang/String;)Ljava/lang/String;");
    if (!mid) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, cls);
        return -1;
    }
    int rc = jni_call_verifier(env, cls, mid, certs, cert_len, n, host);
    (*env)->DeleteLocalRef(env, cls);
    return rc;
}
JNIEXPORT jint JNICALL
JNI_TEST_FN(nativeVerifyThrowingForTest)(JNIEnv *env, jobject thiz, jobjectArray chain,
                                         jstring host)
{
    (void)thiz;
    return seam_marshal_and_call(env, seam_throwing_verify, env, chain, host);
}

/* nativeConfigHasPlatformVerifier(cfg): weak deletion tripwire. clientNew
 * installs the verifier on the config handle (its first statement), so
 * after a successful clientNew the handle carries jni_cert_verify. It proves
 * the install still runs, not that it runs before mqvpn_client_new copies
 * the config — that ordering is pinned by review, because the client's own
 * copy is not reachable (struct mqvpn_client_s is private to
 * mqvpn_client.c; struct mqvpn_config_s is in mqvpn_internal.h, already
 * included above). */
JNIEXPORT jboolean JNICALL
JNI_TEST_FN(nativeConfigHasPlatformVerifier)(JNIEnv *env, jobject thiz, jlong cfg)
{
    (void)env;
    (void)thiz;
    const mqvpn_config_t *c = (const mqvpn_config_t *)(intptr_t)cfg;
    return (c && c->cert_verify_fn == jni_cert_verify) ? JNI_TRUE : JNI_FALSE;
}
#endif /* MQVPN_JNI_TEST_SEAMS */
