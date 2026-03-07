/*
 * mqvpn_jni.c — JNI bridge for libmqvpn Android SDK
 *
 * Maps NativeBridge.kt external funs to libmqvpn C API.
 *
 * Thread model: All client methods (clientConnect, clientTick, etc.) must be
 * called from a single "executor" thread. Callbacks from libmqvpn fire on the
 * same thread (since the library is sans-I/O), so GetEnv normally succeeds.
 * Fallback AttachCurrentThread + DetachCurrentThread is provided for safety.
 *
 * tun_output and send_packet use direct write()/sendto() — no JNI upcall for
 * the hot path.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <android/log.h>

#include "libmqvpn.h"

#define LOG_TAG "mqvpn_jni"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

/* ─── JNI context (user_ctx for libmqvpn callbacks) ─── */

typedef struct {
    JavaVM     *jvm;
    jobject     callback_obj;   /* GlobalRef — must be freed in clientDestroy */
    int         tun_fd;         /* cached for fast write() in tun_output */

    /* Cached jmethodIDs (looked up once in clientNew) */
    jmethodID   mid_tunnel_config_ready;
    jmethodID   mid_tunnel_closed;
    jmethodID   mid_state_changed;
    jmethodID   mid_path_event;
    jmethodID   mid_log;
    jmethodID   mid_reconnect_scheduled;
} jni_ctx_t;

/* ─── Global JavaVM (set in JNI_OnLoad) ─── */

static JavaVM *g_jvm = NULL;

/*
 * Active JNI context — Android VpnService runs a single client per process.
 * Set in clientNew, cleared in clientDestroy.
 * If multi-client support is needed later, replace with a hash table.
 */
static jni_ctx_t *s_active_ctx = NULL;

/*
 * Helper: get JNIEnv for the current thread.
 * Since all libmqvpn callbacks fire on the executor thread (which is a JNI
 * thread), GetEnv should succeed without AttachCurrentThread.
 *
 * If fallback attachment is needed (non-JNI thread), *did_attach is set to 1.
 * Caller MUST call detach_if_needed() after the JNI upcall to prevent leaks.
 */
static JNIEnv *get_env(jni_ctx_t *ctx, int *did_attach)
{
    JNIEnv *env = NULL;
    *did_attach = 0;
    if ((*ctx->jvm)->GetEnv(ctx->jvm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        /* Fallback: attach if called from a non-JNI thread */
        if ((*ctx->jvm)->AttachCurrentThread(ctx->jvm, &env, NULL) != JNI_OK) {
            LOGE("Failed to attach thread");
            return NULL;
        }
        *did_attach = 1;
    }
    return env;
}

static void detach_if_needed(jni_ctx_t *ctx, int did_attach)
{
    if (did_attach)
        (*ctx->jvm)->DetachCurrentThread(ctx->jvm);
}

/* ─── JNI_OnLoad ─── */

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

/* ─── libmqvpn callback trampolines ─── */

/* tun_output: hot path — direct write(), no JNI upcall */
static void jni_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    if (ctx->tun_fd >= 0) {
        ssize_t n = write(ctx->tun_fd, pkt, len);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            LOGW("tun write failed: %s", strerror(errno));
    }
}

/* send_packet: NULL — we use fd-only mode.
 * libmqvpn calls sendto() directly on the path fd. */

/* tunnel_config_ready: JNI upcall to Java */
static void jni_tunnel_config_ready(const mqvpn_tunnel_info_t *info,
                                     void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    /* Create byte arrays for IPs */
    jbyteArray assigned_ip = (*env)->NewByteArray(env, 4);
    (*env)->SetByteArrayRegion(env, assigned_ip, 0, 4,
                                (const jbyte *)info->assigned_ip);

    jbyteArray server_ip = (*env)->NewByteArray(env, 4);
    (*env)->SetByteArrayRegion(env, server_ip, 0, 4,
                                (const jbyte *)info->server_ip);

    jbyteArray assigned_ip6 = NULL;
    if (info->has_v6) {
        assigned_ip6 = (*env)->NewByteArray(env, 16);
        (*env)->SetByteArrayRegion(env, assigned_ip6, 0, 16,
                                    (const jbyte *)info->assigned_ip6);
    }

    /* void onNativeTunnelConfigReady(byte[] assignedIp, int prefix,
     *     byte[] assignedIp6, int prefix6, byte[] serverIp, int serverPrefix,
     *     int mtu, boolean hasV6) */
    (*env)->CallVoidMethod(env, ctx->callback_obj,
                           ctx->mid_tunnel_config_ready,
                           assigned_ip, (jint)info->assigned_prefix,
                           assigned_ip6, (jint)info->assigned_prefix6,
                           server_ip, (jint)info->server_prefix,
                           (jint)info->mtu, (jboolean)info->has_v6);

    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);

    (*env)->DeleteLocalRef(env, assigned_ip);
    (*env)->DeleteLocalRef(env, server_ip);
    if (assigned_ip6)
        (*env)->DeleteLocalRef(env, assigned_ip6);

    detach_if_needed(ctx, did_attach);
}

/* tunnel_closed: JNI upcall */
static void jni_tunnel_closed(mqvpn_error_t reason, void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    /* void onNativeTunnelClosed(int errorCode) */
    (*env)->CallVoidMethod(env, ctx->callback_obj,
                           ctx->mid_tunnel_closed, (jint)reason);

    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);

    detach_if_needed(ctx, did_attach);
}

/* state_changed: JNI upcall */
static void jni_state_changed(mqvpn_client_state_t old_state,
                                mqvpn_client_state_t new_state,
                                void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    /* void onNativeStateChanged(int oldState, int newState) */
    (*env)->CallVoidMethod(env, ctx->callback_obj,
                           ctx->mid_state_changed,
                           (jint)old_state, (jint)new_state);

    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);

    detach_if_needed(ctx, did_attach);
}

/* path_event: JNI upcall */
static void jni_path_event(mqvpn_path_handle_t path,
                            mqvpn_path_status_t status,
                            void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    /* void onNativePathEvent(long pathHandle, int newStatus) */
    (*env)->CallVoidMethod(env, ctx->callback_obj,
                           ctx->mid_path_event,
                           (jlong)path, (jint)status);

    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);

    detach_if_needed(ctx, did_attach);
}

/* log: JNI upcall */
static void jni_log(mqvpn_log_level_t level, const char *msg, void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    jstring jmsg = (*env)->NewStringUTF(env, msg ? msg : "");

    /* void onNativeLog(int level, String message) */
    (*env)->CallVoidMethod(env, ctx->callback_obj,
                           ctx->mid_log, (jint)level, jmsg);

    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);

    (*env)->DeleteLocalRef(env, jmsg);

    detach_if_needed(ctx, did_attach);
}

/* reconnect_scheduled: JNI upcall */
static void jni_reconnect_scheduled(int delay_sec, void *user_ctx)
{
    jni_ctx_t *ctx = (jni_ctx_t *)user_ctx;
    int did_attach;
    JNIEnv *env = get_env(ctx, &did_attach);
    if (!env) return;

    /* void onNativeReconnectScheduled(int delaySec) */
    (*env)->CallVoidMethod(env, ctx->callback_obj,
                           ctx->mid_reconnect_scheduled, (jint)delay_sec);

    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);

    detach_if_needed(ctx, did_attach);
}

/* ─── CLOCK_BOOTTIME injection ─── */

/*
 * CLOCK_BOOTTIME keeps ticking during Android Doze (deep sleep), unlike
 * CLOCK_MONOTONIC which freezes. This prevents QUIC idle timeout from
 * firing all at once after Doze exit.
 */
static uint64_t android_clock_us(void *ctx)
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

/* ════════════════════════════════════════════════════════════════════════════
 *  Config methods
 * ════════════════════════════════════════════════════════════════════════════ */

/* configNew() → long */
JNIEXPORT jlong JNICALL
JNI_FN(configNew)(JNIEnv *env, jobject thiz)
{
    (void)env; (void)thiz;
    mqvpn_config_t *cfg = mqvpn_config_new();
    return (jlong)(intptr_t)cfg;
}

/* configFree(cfg: Long) */
JNIEXPORT void JNICALL
JNI_FN(configFree)(JNIEnv *env, jobject thiz, jlong cfg)
{
    (void)env; (void)thiz;
    mqvpn_config_free((mqvpn_config_t *)(intptr_t)cfg);
}

/* configSetServer(cfg, host, port) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetServer)(JNIEnv *env, jobject thiz, jlong cfg,
                         jstring host, jint port)
{
    (void)thiz;
    const char *h = (*env)->GetStringUTFChars(env, host, NULL);
    if (!h) return MQVPN_ERR_NO_MEMORY;

    int rc = mqvpn_config_set_server((mqvpn_config_t *)(intptr_t)cfg, h, port);
    (*env)->ReleaseStringUTFChars(env, host, h);
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
JNI_FN(configSetInsecure)(JNIEnv *env, jobject thiz, jlong cfg,
                           jboolean insecure)
{
    (void)env; (void)thiz;
    return mqvpn_config_set_insecure((mqvpn_config_t *)(intptr_t)cfg,
                                      insecure ? 1 : 0);
}

/* configSetScheduler(cfg, scheduler) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetScheduler)(JNIEnv *env, jobject thiz, jlong cfg,
                            jint scheduler)
{
    (void)env; (void)thiz;
    return mqvpn_config_set_scheduler((mqvpn_config_t *)(intptr_t)cfg,
                                       (mqvpn_scheduler_t)scheduler);
}

/* configSetLogLevel(cfg, level) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetLogLevel)(JNIEnv *env, jobject thiz, jlong cfg, jint level)
{
    (void)env; (void)thiz;
    return mqvpn_config_set_log_level((mqvpn_config_t *)(intptr_t)cfg,
                                       (mqvpn_log_level_t)level);
}

/* configSetMultipath(cfg, enable) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetMultipath)(JNIEnv *env, jobject thiz, jlong cfg,
                            jboolean enable)
{
    (void)env; (void)thiz;
    return mqvpn_config_set_multipath((mqvpn_config_t *)(intptr_t)cfg,
                                       enable ? 1 : 0);
}

/* configSetAndroidClock(cfg) → int
 * Injects CLOCK_BOOTTIME as the time source. */
JNIEXPORT jint JNICALL
JNI_FN(configSetAndroidClock)(JNIEnv *env, jobject thiz, jlong cfg)
{
    (void)env; (void)thiz;
    return mqvpn_config_set_clock((mqvpn_config_t *)(intptr_t)cfg,
                                   android_clock_us, NULL);
}

/* configSetPlatformCaps(cfg, caps) → int — Phase 4 reserved */
JNIEXPORT jint JNICALL
JNI_FN(configSetPlatformCaps)(JNIEnv *env, jobject thiz, jlong cfg, jint caps)
{
    (void)env; (void)thiz; (void)cfg; (void)caps;
    return MQVPN_OK;  /* reserved — no-op */
}

/* configSetExecutionProfile(cfg, profile) → int — Phase 4 reserved */
JNIEXPORT jint JNICALL
JNI_FN(configSetExecutionProfile)(JNIEnv *env, jobject thiz, jlong cfg,
                                   jint profile)
{
    (void)env; (void)thiz; (void)cfg; (void)profile;
    return MQVPN_OK;  /* reserved — no-op */
}

/* configSetReconnect(cfg, enable, intervalSec) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetReconnect)(JNIEnv *env, jobject thiz, jlong cfg,
                            jboolean enable, jint intervalSec)
{
    (void)env; (void)thiz;
    return mqvpn_config_set_reconnect((mqvpn_config_t *)(intptr_t)cfg,
                                       enable ? 1 : 0, intervalSec);
}

/* configSetKillswitchHint(cfg, enable) → int */
JNIEXPORT jint JNICALL
JNI_FN(configSetKillswitchHint)(JNIEnv *env, jobject thiz, jlong cfg,
                                 jboolean enable)
{
    (void)env; (void)thiz;
    return mqvpn_config_set_killswitch_hint((mqvpn_config_t *)(intptr_t)cfg,
                                             enable ? 1 : 0);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Client lifecycle
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * clientNew(cfg, callbackObj) → long (client handle)
 *
 * Creates a GlobalRef for callbackObj and caches all jmethodIDs.
 * The GlobalRef prevents GC from collecting the callback object.
 * It is released in clientDestroy.
 */
JNIEXPORT jlong JNICALL
JNI_FN(clientNew)(JNIEnv *env, jobject thiz, jlong cfg, jobject callbackObj)
{
    (void)thiz;

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

    ctx->mid_tunnel_config_ready = (*env)->GetMethodID(env, cls,
        "onNativeTunnelConfigReady", "([BI[BI[BIIZ)V");

    ctx->mid_tunnel_closed = (*env)->GetMethodID(env, cls,
        "onNativeTunnelClosed", "(I)V");

    ctx->mid_state_changed = (*env)->GetMethodID(env, cls,
        "onNativeStateChanged", "(II)V");

    ctx->mid_path_event = (*env)->GetMethodID(env, cls,
        "onNativePathEvent", "(JI)V");

    ctx->mid_log = (*env)->GetMethodID(env, cls,
        "onNativeLog", "(ILjava/lang/String;)V");

    ctx->mid_reconnect_scheduled = (*env)->GetMethodID(env, cls,
        "onNativeReconnectScheduled", "(I)V");

    (*env)->DeleteLocalRef(env, cls);

    /* Check all method IDs resolved */
    if (!ctx->mid_tunnel_config_ready || !ctx->mid_tunnel_closed ||
        !ctx->mid_state_changed || !ctx->mid_path_event ||
        !ctx->mid_log || !ctx->mid_reconnect_scheduled) {
        LOGE("Failed to resolve callback method IDs");
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        (*env)->DeleteGlobalRef(env, ctx->callback_obj);
        free(ctx);
        return 0;
    }

    /* Build callbacks struct */
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output           = jni_tun_output;
    cbs.tunnel_config_ready  = jni_tunnel_config_ready;
    cbs.send_packet          = NULL;  /* fd-only mode — library uses sendto() */
    cbs.tunnel_closed        = jni_tunnel_closed;
    cbs.ready_for_tun        = NULL;  /* Android creates TUN in tunnel_config_ready */
    cbs.state_changed        = jni_state_changed;
    cbs.path_event           = jni_path_event;
    cbs.mtu_updated          = NULL;
    cbs.log                  = jni_log;
    cbs.reconnect_scheduled  = jni_reconnect_scheduled;

    mqvpn_client_t *client = mqvpn_client_new(
        (const mqvpn_config_t *)(intptr_t)cfg, &cbs, ctx);

    if (!client) {
        LOGE("mqvpn_client_new failed");
        (*env)->DeleteGlobalRef(env, ctx->callback_obj);
        free(ctx);
        return 0;
    }

    s_active_ctx = ctx;
    return (jlong)(intptr_t)client;
}

/*
 * clientDestroy(client: Long)
 *
 * Frees the client and releases the GlobalRef on the callback object.
 */
JNIEXPORT void JNICALL
JNI_FN(clientDestroy)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)thiz;
    mqvpn_client_t *c = (mqvpn_client_t *)(intptr_t)client;
    if (!c) return;

    /* Retrieve jni_ctx from s_active_ctx before destroy invalidates client.
     * Single-client-per-process model matches Android VpnService. */
    jni_ctx_t *ctx = s_active_ctx;
    mqvpn_client_destroy(c);

    if (ctx) {
        (*env)->DeleteGlobalRef(env, ctx->callback_obj);
        free(ctx);
        s_active_ctx = NULL;
    }
}

/* clientConnect(client) → int */
JNIEXPORT jint JNICALL
JNI_FN(clientConnect)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)env; (void)thiz;
    return mqvpn_client_connect((mqvpn_client_t *)(intptr_t)client);
}

/* clientDisconnect(client) → int */
JNIEXPORT jint JNICALL
JNI_FN(clientDisconnect)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)env; (void)thiz;
    return mqvpn_client_disconnect((mqvpn_client_t *)(intptr_t)client);
}

/* clientSetTunActive(client, active, tunFd) → int */
JNIEXPORT jint JNICALL
JNI_FN(clientSetTunActive)(JNIEnv *env, jobject thiz, jlong client,
                            jboolean active, jint tunFd)
{
    (void)env; (void)thiz;
    mqvpn_client_t *c = (mqvpn_client_t *)(intptr_t)client;

    /* Update cached tun_fd in jni_ctx for tun_output fast path */
    if (s_active_ctx) {
        s_active_ctx->tun_fd = active ? tunFd : -1;
    }

    return mqvpn_client_set_tun_active(c, active ? 1 : 0, tunFd);
}

/*
 * clientSetServerAddr(client, host, port) → int
 *
 * Resolves host:port to a sockaddr and calls mqvpn_client_set_server_addr().
 * Must be called before clientConnect() — xquic needs the peer address for
 * sendto() in fd-only mode.
 */
JNIEXPORT jint JNICALL
JNI_FN(clientSetServerAddr)(JNIEnv *env, jobject thiz, jlong client,
                             jstring host, jint port)
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

    int rc = mqvpn_client_set_server_addr(c, res->ai_addr,
                                            (socklen_t)res->ai_addrlen);
    freeaddrinfo(res);
    return rc;
}

/* clientTick(client) → int */
JNIEXPORT jint JNICALL
JNI_FN(clientTick)(JNIEnv *env, jobject thiz, jlong client)
{
    (void)env; (void)thiz;
    return mqvpn_client_tick((mqvpn_client_t *)(intptr_t)client);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Path management
 * ════════════════════════════════════════════════════════════════════════════ */

/* addPathFd(client, fd, iface) → long (path handle) */
JNIEXPORT jlong JNICALL
JNI_FN(addPathFd)(JNIEnv *env, jobject thiz, jlong client, jint fd,
                   jstring iface)
{
    (void)thiz;
    mqvpn_client_t *c = (mqvpn_client_t *)(intptr_t)client;

    mqvpn_path_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    desc.fd = fd;

    if (iface) {
        const char *name = (*env)->GetStringUTFChars(env, iface, NULL);
        if (name) {
            snprintf(desc.iface, sizeof(desc.iface), "%s", name);
            (*env)->ReleaseStringUTFChars(env, iface, name);
        }
    }

    /* Populate local_addr via getsockname() — xquic needs correct local
     * address size (16 for IPv4, 28 for IPv6), not sizeof(sockaddr_storage). */
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &ss_len) == 0) {
        memcpy(desc.local_addr, &ss, ss_len);
        desc.local_addr_len = ss_len;
    }

    return (jlong)mqvpn_client_add_path_fd(c, fd, &desc);
}

/* removePath(client, pathHandle) → int */
JNIEXPORT jint JNICALL
JNI_FN(removePath)(JNIEnv *env, jobject thiz, jlong client, jlong pathHandle)
{
    (void)env; (void)thiz;
    return mqvpn_client_remove_path((mqvpn_client_t *)(intptr_t)client,
                                     (mqvpn_path_handle_t)pathHandle);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  I/O feed
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * onSocketRecv(client, pathHandle, buf, offset, len, peerAddr, peerAddrLen)
 *
 * Feeds a received UDP packet into the engine.
 * peerAddr is raw sockaddr_storage bytes from recvfrom().
 */
JNIEXPORT jint JNICALL
JNI_FN(onSocketRecv)(JNIEnv *env, jobject thiz, jlong client,
                      jlong pathHandle, jbyteArray buf, jint offset, jint len,
                      jbyteArray peerAddr, jint peerAddrLen)
{
    (void)thiz;
    mqvpn_client_t *c = (mqvpn_client_t *)(intptr_t)client;

    jbyte *pkt = (*env)->GetByteArrayElements(env, buf, NULL);
    if (!pkt) return MQVPN_ERR_NO_MEMORY;

    jbyte *addr = (*env)->GetByteArrayElements(env, peerAddr, NULL);
    if (!addr) {
        (*env)->ReleaseByteArrayElements(env, buf, pkt, JNI_ABORT);
        return MQVPN_ERR_NO_MEMORY;
    }

    int rc = mqvpn_client_on_socket_recv(
        c, (mqvpn_path_handle_t)pathHandle,
        (const uint8_t *)(pkt + offset), (size_t)len,
        (const struct sockaddr *)addr, (socklen_t)peerAddrLen);

    (*env)->ReleaseByteArrayElements(env, peerAddr, addr, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, buf, pkt, JNI_ABORT);

    return rc;
}

/* onTunPacket(client, pkt, offset, len) → int */
JNIEXPORT jint JNICALL
JNI_FN(onTunPacket)(JNIEnv *env, jobject thiz, jlong client,
                     jbyteArray pkt, jint offset, jint len)
{
    (void)thiz;
    mqvpn_client_t *c = (mqvpn_client_t *)(intptr_t)client;

    jbyte *data = (*env)->GetByteArrayElements(env, pkt, NULL);
    if (!data) return MQVPN_ERR_NO_MEMORY;

    int rc = mqvpn_client_on_tun_packet(c, (const uint8_t *)(data + offset),
                                          (size_t)len);

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
    (void)env; (void)thiz;
    return (jint)mqvpn_client_get_state(
        (const mqvpn_client_t *)(intptr_t)client);
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

    int rc = mqvpn_client_get_stats(
        (const mqvpn_client_t *)(intptr_t)client, &stats);
    if (rc != MQVPN_OK) return NULL;

    jlong values[7] = {
        (jlong)stats.bytes_tx,
        (jlong)stats.bytes_rx,
        (jlong)stats.dgram_sent,
        (jlong)stats.dgram_recv,
        (jlong)stats.dgram_lost,
        (jlong)stats.dgram_acked,
        (jlong)stats.srtt_ms,
    };

    jlongArray arr = (*env)->NewLongArray(env, 7);
    if (arr)
        (*env)->SetLongArrayRegion(env, arr, 0, 7, values);
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
    enum { MAX_PATHS = 4 };
    mqvpn_path_info_t paths[MAX_PATHS];
    int n_paths = 0;

    int rc = mqvpn_client_get_paths(
        (const mqvpn_client_t *)(intptr_t)client,
        paths, MAX_PATHS, &n_paths);
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
        jmethodID longOf = (*env)->GetStaticMethodID(env, longCls,
            "valueOf", "(J)Ljava/lang/Long;");

        jclass intCls = (*env)->FindClass(env, "java/lang/Integer");
        jmethodID intOf = (*env)->GetStaticMethodID(env, intCls,
            "valueOf", "(I)Ljava/lang/Integer;");

        (*env)->SetObjectArrayElement(env, inner, 0,
            (*env)->CallStaticObjectMethod(env, longCls, longOf,
                                            (jlong)paths[i].handle));
        (*env)->SetObjectArrayElement(env, inner, 1,
            (*env)->CallStaticObjectMethod(env, intCls, intOf,
                                            (jint)paths[i].status));
        (*env)->SetObjectArrayElement(env, inner, 2,
            (*env)->NewStringUTF(env, paths[i].name));
        (*env)->SetObjectArrayElement(env, inner, 3,
            (*env)->CallStaticObjectMethod(env, longCls, longOf,
                                            (jlong)paths[i].bytes_tx));
        (*env)->SetObjectArrayElement(env, inner, 4,
            (*env)->CallStaticObjectMethod(env, longCls, longOf,
                                            (jlong)paths[i].bytes_rx));
        (*env)->SetObjectArrayElement(env, inner, 5,
            (*env)->CallStaticObjectMethod(env, longCls, longOf,
                                            (jlong)paths[i].srtt_ms));

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

    int rc = mqvpn_client_get_interest(
        (const mqvpn_client_t *)(intptr_t)client, &interest);
    if (rc != MQVPN_OK) return NULL;

    jint values[3] = {
        interest.next_timer_ms,
        interest.tun_readable,
        interest.is_idle,
    };

    jintArray arr = (*env)->NewIntArray(env, 3);
    if (arr)
        (*env)->SetIntArrayRegion(env, arr, 0, 3, values);
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

/*
 * recvFrom(fd, buf, offset, len, peerAddrOut, peerAddrLenOut) → int
 *
 * JNI wrapper around recvfrom(). Returns bytes read, -1 on error.
 * peerAddrOut is filled with raw sockaddr_storage bytes.
 * peerAddrLenOut[0] is set to the actual peer address length.
 */
JNIEXPORT jint JNICALL
JNI_FN(recvFrom)(JNIEnv *env, jobject thiz, jint fd,
                  jbyteArray buf, jint offset, jint len,
                  jbyteArray peerAddrOut, jintArray peerAddrLenOut)
{
    (void)thiz;

    jbyte *data = (*env)->GetByteArrayElements(env, buf, NULL);
    if (!data) return -1;

    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    memset(&ss, 0, sizeof(ss));

    ssize_t n = recvfrom(fd, data + offset, (size_t)len, 0,
                          (struct sockaddr *)&ss, &ss_len);

    (*env)->ReleaseByteArrayElements(env, buf, data, (n > 0) ? 0 : JNI_ABORT);

    if (n >= 0) {
        /* Copy peer address to output array */
        jbyte *addr_out = (*env)->GetByteArrayElements(env, peerAddrOut, NULL);
        if (addr_out) {
            jint addr_out_len = (*env)->GetArrayLength(env, peerAddrOut);
            jint copy_len = (jint)ss_len < addr_out_len ? (jint)ss_len : addr_out_len;
            memcpy(addr_out, &ss, copy_len);
            (*env)->ReleaseByteArrayElements(env, peerAddrOut, addr_out, 0);
        }

        /* Set address length */
        jint addrLen = (jint)ss_len;
        (*env)->SetIntArrayRegion(env, peerAddrLenOut, 0, 1, &addrLen);
    }

    return (jint)n;
}
