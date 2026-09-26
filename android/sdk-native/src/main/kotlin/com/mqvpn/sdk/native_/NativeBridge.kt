// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

@file:Suppress("FunctionName")

package com.mqvpn.sdk.native_

/**
 * JNI bridge to libmqvpn C library.
 *
 * All methods map directly to C functions in mqvpn_jni.c.
 * This is an internal API — use sdk-core's public classes instead.
 *
 * Thread safety: every client and reactor method (clientConnect, clientTick,
 * reactorWait, reactorAddPath, ...) must be called from the engine thread
 * (the MqvpnPoller thread); only [reactorWake] may be called from any thread.
 *
 * Transport (ABI 3): the library owns no socket. Kotlin creates and closes
 * the path fds; the reactor (reactorNew) wraps each one in the bundled POSIX
 * bind and polls/drains them on the engine thread inside [reactorWait].
 * No datagram crosses JNI.
 */
object NativeBridge {

    init {
        System.loadLibrary("mqvpn_jni")
    }

    // ---- Config ----

    /** mqvpn_config_new() → config pointer (long) */
    external fun configNew(): Long

    /** mqvpn_config_free(cfg) */
    external fun configFree(cfg: Long)

    /** mqvpn_config_set_server(cfg, host, port) */
    external fun configSetServer(cfg: Long, host: String, port: Int): Int

    /** mqvpn_config_set_tls_server_name(cfg, name) */
    external fun configSetTlsServerName(cfg: Long, name: String): Int

    /** mqvpn_config_set_auth_key(cfg, key) */
    external fun configSetAuthKey(cfg: Long, key: String): Int

    /** mqvpn_config_set_insecure(cfg, insecure) */
    external fun configSetInsecure(cfg: Long, insecure: Boolean): Int

    /** mqvpn_config_set_scheduler(cfg, scheduler: 0=MINRTT, 1=WLB, 2=BACKUP_FEC, 3=WLB_UDP_PIN) */
    external fun configSetScheduler(cfg: Long, scheduler: Int): Int

    /** mqvpn_config_set_log_level(cfg, level: 0=DEBUG..3=ERROR) */
    external fun configSetLogLevel(cfg: Long, level: Int): Int

    /** mqvpn_config_set_multipath(cfg, enable) */
    external fun configSetMultipath(cfg: Long, enable: Boolean): Int

    /**
     * Inject CLOCK_BOOTTIME as the time source.
     * CLOCK_BOOTTIME survives Android Doze (unlike CLOCK_MONOTONIC).
     */
    external fun configSetAndroidClock(cfg: Long): Int

    /** mqvpn_config_set_platform_caps(cfg, caps) — Phase 4, reserved */
    external fun configSetPlatformCaps(cfg: Long, caps: Int): Int

    /** mqvpn_config_set_execution_profile(cfg, profile) — Phase 4, reserved */
    external fun configSetExecutionProfile(cfg: Long, profile: Int): Int

    /** mqvpn_config_set_reconnect(cfg, enable, intervalSec) */
    external fun configSetReconnect(cfg: Long, enable: Boolean, intervalSec: Int): Int

    /** mqvpn_config_set_killswitch_hint(cfg, enable) */
    external fun configSetKillswitchHint(cfg: Long, enable: Boolean): Int

    /** mqvpn_config_set_reorder_enabled(cfg, mode: 0=OFF, 1=ON) */
    external fun configSetReorderEnabled(cfg: Long, mode: Int): Int

    /** mqvpn_config_add_reorder_rule(cfg, proto, port, profile) */
    external fun configAddReorderRule(cfg: Long, proto: Int, port: Int, profile: Int): Int

    /** mqvpn_config_set_hybrid_enabled(cfg, enabled) */
    external fun configSetHybridEnabled(cfg: Long, enabled: Boolean): Int

    /** mqvpn_config_set_hybrid_tcp_mode(cfg, mode: 0=STREAM, 1=RAW, 2=AUTO) */
    external fun configSetHybridTcpMode(cfg: Long, mode: Int): Int

    /**
     * mqvpn_client_get_reorder_stats(client) → LongArray:
     * [deliveredCount, gapCount, gapFilledCount, gapTimeoutCount,
     *  ackDemoteCount, p50Ms, p99Ms]
     */
    external fun getReorderStats(client: Long): LongArray?

    // ---- Client lifecycle ----

    /**
     * mqvpn_client_new(cfg, callbacks, user_ctx) → client pointer (long).
     * [callbackObj] receives JNI upcalls (tunnelConfigReady, stateChanged, log, etc.).
     * A GlobalRef is created for callbackObj; it is released in reactorClientDestroy.
     */
    external fun clientNew(cfg: Long, callbackObj: Any): Long

    // (destroy is reactorClientDestroy below: the only destroy entry point)

    /** mqvpn_client_connect(client) */
    external fun clientConnect(client: Long): Int

    /** mqvpn_client_disconnect(client) */
    external fun clientDisconnect(client: Long): Int

    /**
     * mqvpn_client_set_tun_active(client, active, tunFd).
     * tunFd >= 0 when activating (Android VpnService TUN fd).
     * tunFd = -1 when deactivating.
     */
    external fun clientSetTunActive(client: Long, active: Boolean, tunFd: Int): Int

    /**
     * mqvpn_client_set_server_addr(client, host, port).
     * Resolves host:port and sets peer address on the client.
     * Must be called before clientConnect().
     */
    external fun clientSetServerAddr(client: Long, host: String, port: Int): Int

    /** mqvpn_client_tick(client) */
    external fun clientTick(client: Long): Int

    // ---- Reactor (engine-thread poll loop + path lifecycle) ----

    /**
     * Creates the reactor (one eventfd + a path table). Owned by the executor,
     * not by a client: created before the poller thread starts, freed by the
     * poller thread after its loop exits. Returns 0 on failure.
     */
    external fun reactorNew(): Long

    /** Frees the reactor. Every client must have been destroyed first. */
    external fun reactorFree(reactor: Long)

    /**
     * Wakes a [reactorWait] in progress (or the next one). Any thread, but never
     * concurrently with or after [reactorFree]: the caller excludes them (the
     * waiter's lock shared by wake and close). Returns 0 or -1.
     */
    external fun reactorWake(reactor: Long): Int

    /**
     * poll() over the attached path fds and the eventfd, up to [timeoutMs];
     * drains every readable path into the client on THIS thread. A negative
     * [timeoutMs] is passed to poll() as is: it blocks until a path is
     * readable or [reactorWake] is called. Returns the number of drains
     * (>= 0; 0 also on EINTR) or -1. [client] may be 0 only while no path is
     * attached.
     */
    external fun reactorWait(reactor: Long, client: Long, timeoutMs: Int): Int

    /**
     * The next path handle whose fd was found closed behind the platform
     * (POLLNVAL), delivered once, or -1. The caller removes the path, drops
     * the fd from its ledger WITHOUT closing it, and reports the release.
     */
    external fun reactorTakeBadFd(reactor: Long): Long

    /**
     * Wraps [fd] in a bundled POSIX bind and registers it with
     * mqvpn_client_add_path() → path handle (>= 0), or -1 with the fd
     * untouched (the caller closes it). The fd is borrowed: never closed here.
     */
    external fun reactorAddPath(reactor: Long, client: Long, fd: Int, iface: String): Long

    /**
     * mqvpn_client_remove_path() + stop polling the fd. Returns the library's
     * code, or -1 (MQVPN_ERR_INVALID_ARG, nothing called) for an unknown or
     * poisoned handle. Then the caller closes the fd — except on the bad-fd
     * chain, where it drops the fd without closing it (see [reactorTakeBadFd])
     * — and calls [reactorPathReleased].
     */
    external fun reactorRemovePath(reactor: Long, client: Long, pathHandle: Long): Int

    /**
     * mqvpn_client_on_platform_path_released(): 0 = released (entry freed);
     * a library error = the transport stays library-owned until destroy;
     * [REACTOR_POISONED] = ledger corruption, end the session.
     */
    external fun reactorPathReleased(reactor: Long, client: Long, pathHandle: Long): Int

    /**
     * Whole-client teardown: stop polling, harvest RX totals,
     * mqvpn_client_destroy() (finalises every attached bind ctx), forget the
     * table, release the callback GlobalRef. Close the path fds AFTER this.
     * The [client] handle is invalid afterwards.
     */
    external fun reactorClientDestroy(reactor: Long, client: Long)

    /** Returned by [reactorPathReleased] on ledger corruption (MQVPN_REACTOR_POISONED). */
    const val REACTOR_POISONED: Int = -100

    // ---- I/O feed (TUN only; path receive happens inside reactorWait) ----

    /** mqvpn_client_on_tun_packet(client, pkt, offset, len) */
    external fun onTunPacket(client: Long, pkt: ByteArray, offset: Int, len: Int): Int

    // ---- Query ----

    /** mqvpn_client_get_state(client) → state int (0=IDLE..6=CLOSED) */
    external fun getState(client: Long): Int

    /**
     * mqvpn_client_get_stats(client) → LongArray:
     * [bytesTx, bytesRx, pktsTx, pktsRx, rttUs, connUptimeMs]
     */
    external fun getStats(client: Long): LongArray?

    /**
     * mqvpn_client_get_paths(client) → Array of Object arrays.
     * Each inner array: [handle(Long), status(Int), iface(String),
     *   bytesTx(Long), bytesRx(Long), rttUs(Long)]
     */
    external fun getPaths(client: Long): Array<Any>?

    /**
     * mqvpn_client_get_interest(client) → IntArray:
     * [nextTimerMs, tunReadable, isIdle]
     */
    external fun getInterest(client: Long): IntArray?

    // ---- Utility ----

    /** mqvpn_version_string() */
    external fun versionString(): String

    /** mqvpn_generate_key(out, outLen) → generated PSK string */
    external fun generateKey(): String?
}
