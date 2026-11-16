// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import com.mqvpn.sdk.core.internal.PathManager
import com.mqvpn.sdk.core.internal.SessionStateMachine
import com.mqvpn.sdk.core.internal.TunnelCallbacks
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.TunnelInfo
import com.mqvpn.sdk.network.NetworkMonitor
import com.mqvpn.sdk.network.PathPolicy
import com.mqvpn.sdk.runtime.MqvpnExecutor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.net.InetAddress

/**
 * One connect's worth of components: the native client, the network
 * monitor and its paths, the TUN and its bridge, and the state machine.
 * Made by [MqvpnVpnService.startTunnel], dropped whole by its teardown, so
 * nothing of one session leaks into the next. Executor thread only, except
 * where a method says otherwise.
 */
internal class Session(
    private val service: MqvpnVpnService,
    private val executor: MqvpnExecutor,
    private val scope: CoroutineScope,
    private val config: MqvpnConfig,
) : TunnelCallbacks {

    private val machine = SessionStateMachine(
        emit = { state -> service.emitState(this, state) },
        stop = { service.stopSession(this) },
        onReconnectScheduled = service::onReconnectScheduled,
    )

    // Null until open() built them; open() may fail part way.
    private var tunnel: MqvpnTunnel? = null
    private var monitor: NetworkMonitor? = null
    private var pathManager: PathManager? = null
    private var bridge: TunnelBridge? = null
    private var tunPfd: ParcelFileDescriptor? = null

    private var lastStatsMs = 0L
    private var lastReorderStatsMs = 0L

    val clientHandle: Long get() = tunnel?.clientHandle ?: 0L

    /**
     * Builds the session; connect() is deferred until the first network path
     * is available. False = it failed, reported an Error and released what
     * it had built (the executor only logs a throw, so a half-built session
     * would otherwise refuse every later start).
     */
    fun open(reactorHandle: Long): Boolean {
        SessionStore.claim(this)
        machine.started()
        try {
            val t = MqvpnTunnel.create(config, this, reactorHandle)
            tunnel = t
            val m = NetworkMonitor(
                service,
                PathPolicy(
                    config.wifiPathEnabled,
                    config.cellularPathEnabled,
                    config.ethernetPathEnabled,
                    config.bluetoothPathEnabled,
                ),
            )
            monitor = m
            val pm = PathManager(
                executor, t, m,
                protector = { fd -> service.protect(fd) },
                serverHost = config.serverAddress,
                serverPort = config.serverPort,
                onFatal = { reason ->
                    Log.e(TAG, "ending the session: $reason")
                    service.stopSession(this)
                },
            )
            pathManager = pm
            // a refused network request throws here
            m.start { event -> scope.launch(Dispatchers.IO) { pm.handleEvent(event) } }
            return true
        } catch (e: Exception) {
            Log.e(TAG, "session setup failed", e)
            machine.failed(MqvpnError.Unknown(0, "Could not start the connection: ${e.message}"))
            close()
            return false
        }
    }

    /** One engine-loop tick; stats are sampled, not read per poll (the loop can spin thousands of times a second). */
    fun tick(): Int {
        val t = tunnel ?: return 0
        val result = t.tick()
        val now = SystemClock.elapsedRealtime()
        // the UI divides byte deltas by its own 1 s tick: a coarser sample
        // would alias into alternating zero/double rates
        if (now - lastStatsMs >= STATS_INTERVAL_MS) {
            lastStatsMs = now
            val stats = t.getStats()
            val paths = t.getPaths()
            SessionStore.publish(this) {
                this.stats.value = stats
                this.paths.value = paths
            }
        }
        if (now - lastReorderStatsMs >= REORDER_STATS_INTERVAL_MS) {
            lastReorderStatsMs = now
            val reorder = t.getReorderStats()
            SessionStore.publish(this) { reorderStats.value = reorder }
        }
        return result
    }

    /** [nextTimerMs, tunReadable, isIdle] for the poller, null before open(). */
    fun interest(): IntArray? = tunnel?.getInterest()?.let {
        intArrayOf(it.nextTimerMs, if (it.tunReadable) 1 else 0, if (it.isIdle) 1 else 0)
    }

    fun handleBadFd(handle: Long) {
        pathManager?.handleBadFd(handle)
    }

    /**
     * Tears the session down; called once. The destroy and the fd closes run
     * whatever the orderly half throws: this may be the executor's finalizer,
     * and the reactor it hands back to the poller must hold no live path
     * when the poller frees it.
     */
    fun close() {
        machine.tearingDown()
        val t = tunnel
        try {
            monitor?.stop()
            bridge?.stop()
            t?.disconnect()
            t?.tick() // send CONNECTION_CLOSE
        } finally {
            try {
                t?.destroy() // reactor: stop polling → harvest → client_destroy → forget
            } finally {
                pathManager?.closeAllFds() // sockets are ours; closed AFTER the destroy
                tunPfd?.close()
                SessionStore.publish(this) { resetMetrics() }
                machine.closed()
                SessionStore.release(this)
            }
        }
    }

    // --- TunnelCallbacks (JNI, executor thread) ---

    override fun onNativeTunnelConfigReady(
        assignedIp: ByteArray, prefix: Int,
        assignedIp6: ByteArray?, prefix6: Int,
        serverIp: ByteArray, serverPrefix: Int,
        mtu: Int, hasV6: Boolean,
        hasServerScheduler: Boolean, serverScheduler: Int,
    ) {
        val t = tunnel ?: return
        val info = TunnelInfo(
            assignedIp = formatIp(assignedIp, "0.0.0.0"),
            prefix = prefix,
            serverIp = formatIp(serverIp, "0.0.0.0"),
            serverPrefix = serverPrefix,
            mtu = mtu,
            assignedIp6 = assignedIp6?.let { formatIp(it, "::") },
            prefix6 = prefix6,
            hasV6 = hasV6,
            serverScheduler = if (hasServerScheduler) {
                MqvpnConfig.Scheduler.entries.firstOrNull { it.native == serverScheduler }
            } else null,
            requestedScheduler = config.scheduler.takeIf { config.requestServerScheduler },
            connectedAtMs = System.currentTimeMillis(),
        )

        val pfd = try {
            service.onCreateTun(info, config)
        } catch (e: Exception) {
            Log.e(TAG, "onCreateTun failed", e)
            machine.failed(MqvpnError.TunCreationFailed(e.message ?: "VPN permission denied"))
            executor.enqueue { t.disconnect() }
            return
        }

        t.setTunActive(true, pfd.fd)

        // On reconnect: stop the old bridge, close the old TUN
        bridge?.stop()
        tunPfd?.close()
        tunPfd = pfd

        bridge = TunnelBridge(executor, t).also {
            it.startTunReader(pfd, mtu, scope)
            it.startSender(scope)
        }

        machine.connected(info)
    }

    override fun onNativeTunnelClosed(errorCode: Int) = machine.tunnelClosed(errorCode)

    override fun onNativeStateChanged(oldState: Int, newState: Int) = machine.nativeStateChanged(newState)

    override fun onNativePathEvent(pathHandle: Long, newStatus: Int) {
        // Path changes are picked up by the sampled paths in tick()
    }

    override fun onNativeLog(level: Int, message: String) = service.onLog(level, message)

    override fun onNativeReconnectScheduled(delaySec: Int) = machine.reconnectScheduled(delaySec)

    private fun formatIp(bytes: ByteArray, fallback: String): String =
        InetAddress.getByAddress(bytes).hostAddress ?: fallback

    companion object {
        private const val TAG = "MqvpnVpnService" // same logcat tag as before the split
        private const val STATS_INTERVAL_MS = 100L
        private const val REORDER_STATS_INTERVAL_MS = 1000L
    }
}
