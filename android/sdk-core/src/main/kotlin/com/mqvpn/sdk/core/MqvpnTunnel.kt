// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.util.Log
import com.mqvpn.sdk.core.internal.ReorderPlan
import com.mqvpn.sdk.core.internal.TunnelCallbacks
import com.mqvpn.sdk.core.internal.planReorder
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReorderStats
import com.mqvpn.sdk.core.model.VpnStats
import com.mqvpn.sdk.native_.NativeBridge

/**
 * libmqvpn client engine wrapper.
 *
 * All methods must be called from the engine thread (single-thread guarantee).
 *
 * Paths go through the executor-owned native reactor ([reactorHandle]): it
 * wraps each fd in the bundled POSIX bind, polls and drains it on the engine
 * thread, and runs the release/destroy composites.
 *
 * After [destroy] the client handle is 0 and every method returns an error
 * (or an empty result) WITHOUT a JNI call: a task queued behind the cleanup
 * that destroyed the client (a TUN batch, for instance) must never reach a
 * freed pointer. Engine thread only, so the check is race-free.
 */
class MqvpnTunnel internal constructor(
    clientHandle: Long,
    private val cfgHandle: Long,
    private val reactorHandle: Long,
    private val reorderEnabled: Boolean = false,
) {
    /** 0 once [destroy] ran. Read by the poller (clientFn) on the engine thread. */
    internal var clientHandle: Long = clientHandle
        private set

    private inline fun <T> live(destroyed: T, block: (Long) -> T): T {
        val h = clientHandle
        return if (h == 0L) destroyed else block(h)
    }

    // --- Lifecycle ---

    fun setServerAddr(host: String, port: Int): Int =
        live(ERR_INVALID_STATE) { NativeBridge.clientSetServerAddr(it, host, port) }

    fun connect(): Int = live(ERR_INVALID_STATE) { NativeBridge.clientConnect(it) }

    fun disconnect(): Int = live(ERR_INVALID_STATE) { NativeBridge.clientDisconnect(it) }

    fun setTunActive(active: Boolean, tunFd: Int): Int =
        live(ERR_INVALID_STATE) { NativeBridge.clientSetTunActive(it, active, tunFd) }

    // --- Path management (through the reactor) ---

    /** Path handle (>= 0) or -1; on -1 the caller still owns and closes [fd]. */
    fun addPath(fd: Int, iface: String): Long =
        live(-1L) { NativeBridge.reactorAddPath(reactorHandle, it, fd, iface) }

    /** Orderly removal; the caller closes the fd afterwards, then calls [pathReleased]. */
    fun removePath(pathHandle: Long): Int =
        live(ERR_INVALID_STATE) { NativeBridge.reactorRemovePath(reactorHandle, it, pathHandle) }

    /**
     * Report that the platform is done with the path's socket. 0 = released;
     * [NativeBridge.REACTOR_POISONED] = ledger corruption, the session must
     * end; any other library error = the transport stays library-owned.
     */
    fun pathReleased(pathHandle: Long): Int =
        live(ERR_INVALID_STATE) { NativeBridge.reactorPathReleased(reactorHandle, it, pathHandle) }

    // --- I/O feed (TUN; path receive happens inside the reactor's wait) ---

    fun onTunPacket(data: ByteArray, offset: Int, length: Int): Int =
        live(ERR_INVALID_STATE) { NativeBridge.onTunPacket(it, data, offset, length) }

    // --- Engine tick ---

    fun tick(): Int = live(ERR_INVALID_STATE) { NativeBridge.clientTick(it) }

    // --- Query ---

    fun getState(): Int = live(STATE_CLOSED) { NativeBridge.getState(it) }

    fun getReorderStats(): ReorderStats {
        if (!reorderEnabled) return ReorderStats()
        val a = live(null) { NativeBridge.getReorderStats(it) } ?: return ReorderStats()
        if (a.size < REORDER_STATS_FIELDS) return ReorderStats()
        return ReorderStats(a[0], a[1], a[2], a[3], a[4], a[5], a[6])
    }

    fun getStats(): VpnStats {
        val arr = live(null) { NativeBridge.getStats(it) } ?: return VpnStats()
        return VpnStats(
            bytesTx = arr[0],
            bytesRx = arr[1],
            dgramSent = arr[2],
            dgramRecv = arr[3],
            dgramLost = arr[4],
            dgramAcked = arr[5],
            srttMs = arr[6].toInt(),
        )
    }

    fun getPaths(): List<PathInfo> {
        val arr = live(null) { NativeBridge.getPaths(it) } ?: return emptyList()
        return arr.map { inner ->
            @Suppress("UNCHECKED_CAST")
            val a = inner as Array<Any>
            PathInfo(
                handle = a[0] as Long,
                status = a[1] as Int,
                iface = a[2] as String,
                bytesTx = a[3] as Long,
                bytesRx = a[4] as Long,
                srttMs = a[5] as Long,
            )
        }
    }

    data class Interest(
        val nextTimerMs: Int,
        val tunReadable: Boolean,
        val isIdle: Boolean,
    )

    fun getInterest(): Interest {
        val arr = live(null) { NativeBridge.getInterest(it) }
            ?: return Interest(0, false, false)
        return Interest(
            nextTimerMs = arr[0],
            tunReadable = arr[1] != 0,
            isIdle = arr[2] != 0,
        )
    }

    // --- Cleanup ---

    /**
     * Whole-client teardown through the reactor (stop polling, harvest,
     * mqvpn_client_destroy, forget the table). The handle is zeroed FIRST so
     * a later task on the engine thread sees a destroyed tunnel. Idempotent.
     * The caller closes the path fds after this returns.
     */
    fun destroy() {
        val h = clientHandle
        if (h == 0L) return
        clientHandle = 0L
        NativeBridge.reactorClientDestroy(reactorHandle, h)
        NativeBridge.configFree(cfgHandle)
    }

    companion object {
        private const val TAG = "MqvpnTunnel"
        private const val REORDER_STATS_FIELDS = 7
        const val ERR_AGAIN = -9
        /** MQVPN_ERR_INVALID_STATE: also what every call returns after [destroy]. */
        const val ERR_INVALID_STATE = -13
        private const val STATE_CLOSED = 6

        private fun applyReorder(cfg: Long, plan: ReorderPlan) {
            plan.warnings.forEach { Log.w(TAG, it) }
            if (!plan.enabled) return
            NativeBridge.configSetReorderEnabled(cfg, 1)
            plan.rules.forEach { r ->
                val rc = NativeBridge.configAddReorderRule(cfg, r.proto, r.port, r.profile)
                if (rc != 0) Log.w(TAG, "configAddReorderRule failed for port ${r.port} (rc=$rc)")
            }
        }

        /** [reactorHandle]: the executor's NativeReactorWaiter.reactorHandle. */
        internal fun create(config: MqvpnConfig, callbacks: TunnelCallbacks, reactorHandle: Long): MqvpnTunnel {
            // Also guards startTunnel callers that bypass MqvpnManager.connect() (restored-config
            // path); note the service executor only logs a throw here.
            config.hostIdentifierError()?.let { throw IllegalArgumentException(it) }
            require(reactorHandle != 0L) { "reactor handle required" }
            val cfg = NativeBridge.configNew()
            NativeBridge.configSetServer(cfg, config.serverAddress, config.serverPort)
            config.tlsServerName?.let { NativeBridge.configSetTlsServerName(cfg, it) }
            NativeBridge.configSetAuthKey(cfg, config.authKey)
            NativeBridge.configSetInsecure(cfg, config.insecure)
            NativeBridge.configSetScheduler(cfg, config.scheduler.native)
            NativeBridge.configSetLogLevel(cfg, config.logLevel.native)
            NativeBridge.configSetMultipath(cfg, config.multipathEnabled)
            NativeBridge.configSetReconnect(cfg, config.reconnect, config.reconnectIntervalSec)
            NativeBridge.configSetKillswitchHint(cfg, config.killSwitch)
            NativeBridge.configSetHybridEnabled(cfg, config.hybridEnabled)
            NativeBridge.configSetHybridTcpMode(cfg, config.hybridTcpMode.native)
            NativeBridge.configSetAndroidClock(cfg)
            val plan = planReorder(config)
            applyReorder(cfg, plan)
            val handle = NativeBridge.clientNew(cfg, callbacks)
            if (handle == 0L) {
                NativeBridge.configFree(cfg) // the config is ours until a client owns a copy
                throw IllegalStateException("mqvpn_client_new failed")
            }
            return MqvpnTunnel(handle, cfg, reactorHandle, plan.enabled)
        }
    }
}
