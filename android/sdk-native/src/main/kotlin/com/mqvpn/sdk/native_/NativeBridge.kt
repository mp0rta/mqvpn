@file:Suppress("FunctionName")

package com.mqvpn.sdk.native_

/**
 * JNI bridge to libmqvpn C library.
 *
 * All methods map directly to C functions in mqvpn_jni.c.
 * This is an internal API — use sdk-core's public classes instead.
 *
 * Thread safety: All client methods (clientConnect, clientTick, etc.)
 * must be called from the same thread (the executor/poller thread).
 */
internal object NativeBridge {

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

    /** mqvpn_config_set_auth_key(cfg, key) */
    external fun configSetAuthKey(cfg: Long, key: String): Int

    /** mqvpn_config_set_insecure(cfg, insecure) */
    external fun configSetInsecure(cfg: Long, insecure: Boolean): Int

    /** mqvpn_config_set_scheduler(cfg, scheduler: 0=MINRTT, 1=WLB) */
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

    // ---- Client lifecycle ----

    /**
     * mqvpn_client_new(cfg, callbacks, user_ctx) → client pointer (long).
     * [callbackObj] receives JNI upcalls (tunnelConfigReady, stateChanged, log, etc.).
     * A GlobalRef is created for callbackObj; it is released in clientDestroy.
     */
    external fun clientNew(cfg: Long, callbackObj: Any): Long

    /** mqvpn_client_destroy(client) — also releases callback GlobalRef. */
    external fun clientDestroy(client: Long)

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

    /** mqvpn_client_tick(client) */
    external fun clientTick(client: Long): Int

    // ---- Path management ----

    /**
     * mqvpn_client_add_path_fd(client, fd, iface) → path_handle (long).
     * Returns negative on error.
     */
    external fun addPathFd(client: Long, fd: Int, iface: String): Long

    /** mqvpn_client_remove_path(client, pathHandle) */
    external fun removePath(client: Long, pathHandle: Long): Int

    // ---- I/O feed ----

    /**
     * mqvpn_client_on_socket_recv(client, pathHandle, buf, offset, len,
     *     peerAddr, peerAddrLen).
     * peerAddr is raw sockaddr_storage bytes from recvfrom().
     */
    external fun onSocketRecv(
        client: Long, pathHandle: Long,
        buf: ByteArray, offset: Int, len: Int,
        peerAddr: ByteArray, peerAddrLen: Int
    ): Int

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

    /**
     * JNI recvfrom() wrapper: recvfrom(fd, buf, off, len, peerAddrOut, peerAddrLenOut).
     * Returns bytes read, -1 on error. peerAddrOut filled with raw sockaddr_storage.
     * peerAddrLenOut[0] set to actual peer address length.
     */
    external fun recvFrom(
        fd: Int, buf: ByteArray, offset: Int, len: Int,
        peerAddrOut: ByteArray, peerAddrLenOut: IntArray
    ): Int
}
