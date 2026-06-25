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
 * All methods must be called from the executor thread (single-thread guarantee).
 */
class MqvpnTunnel internal constructor(
    private val clientHandle: Long,
    private val cfgHandle: Long,
) {
    // --- Lifecycle ---

    fun setServerAddr(host: String, port: Int): Int =
        NativeBridge.clientSetServerAddr(clientHandle, host, port)

    fun connect(): Int = NativeBridge.clientConnect(clientHandle)

    fun disconnect(): Int = NativeBridge.clientDisconnect(clientHandle)

    fun setTunActive(active: Boolean, tunFd: Int): Int =
        NativeBridge.clientSetTunActive(clientHandle, active, tunFd)

    // --- Path management ---

    fun addPathFd(fd: Int, iface: String): Long =
        NativeBridge.addPathFd(clientHandle, fd, iface)

    fun removePath(pathHandle: Long): Int =
        NativeBridge.removePath(clientHandle, pathHandle)

    // --- I/O feed ---

    fun onTunPacket(data: ByteArray, offset: Int, length: Int): Int =
        NativeBridge.onTunPacket(clientHandle, data, offset, length)

    fun onSocketRecv(
        pathHandle: Long, data: ByteArray, offset: Int, length: Int,
        peerAddr: ByteArray, peerAddrLen: Int,
    ): Int = NativeBridge.onSocketRecv(
        clientHandle, pathHandle, data, offset, length, peerAddr, peerAddrLen,
    )

    // --- Engine tick ---

    fun tick(): Int = NativeBridge.clientTick(clientHandle)

    // --- Query ---

    fun getState(): Int = NativeBridge.getState(clientHandle)

    fun getReorderStats(): ReorderStats {
        val a = NativeBridge.getReorderStats(clientHandle) ?: return ReorderStats()
        return ReorderStats(a[0], a[1], a[2], a[3], a[4], a[5], a[6])
    }

    fun getStats(): VpnStats {
        val arr = NativeBridge.getStats(clientHandle) ?: return VpnStats()
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
        val arr = NativeBridge.getPaths(clientHandle) ?: return emptyList()
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
        val arr = NativeBridge.getInterest(clientHandle)
            ?: return Interest(0, false, false)
        return Interest(
            nextTimerMs = arr[0],
            tunReadable = arr[1] != 0,
            isIdle = arr[2] != 0,
        )
    }

    // --- Cleanup ---

    fun destroy() {
        NativeBridge.clientDestroy(clientHandle)
        NativeBridge.configFree(cfgHandle)
    }

    companion object {
        private const val TAG = "MqvpnTunnel"
        const val ERR_AGAIN = -9

        private fun applyReorder(cfg: Long, plan: ReorderPlan) {
            plan.warnings.forEach { Log.w(TAG, it) }
            if (!plan.enabled) return
            NativeBridge.configSetReorderEnabled(cfg, 1)
            plan.rules.forEach { r ->
                val rc = NativeBridge.configAddReorderRule(cfg, r.proto, r.port, r.profile)
                if (rc != 0) Log.w(TAG, "configAddReorderRule failed for port ${r.port} (rc=$rc)")
            }
        }

        internal fun create(config: MqvpnConfig, callbacks: TunnelCallbacks): MqvpnTunnel {
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
            NativeBridge.configSetAndroidClock(cfg)
            applyReorder(cfg, planReorder(config))
            val handle = NativeBridge.clientNew(cfg, callbacks)
            check(handle != 0L) { "mqvpn_client_new failed" }
            return MqvpnTunnel(handle, cfg)
        }
    }
}
