// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import com.mqvpn.sdk.core.internal.PathManager
import com.mqvpn.sdk.core.internal.TunnelCallbacks
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.ReconnectInfo
import com.mqvpn.sdk.core.model.TunnelInfo
import com.mqvpn.sdk.network.NetworkMonitor
import com.mqvpn.sdk.runtime.MqvpnPoller
import com.mqvpn.sdk.runtime.NativeReactorWaiter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.net.InetAddress

/**
 * Abstract VPN service base class for mqvpn Android SDK.
 *
 * Subclasses implement [onCreateTun] and [onVpnStateChanged].
 * The SDK manages all internal components (executor, tunnel, I/O, paths).
 *
 * Thread safety: All JNI calls are serialized on the executor thread.
 * [onCreateTun] is called from the executor thread (NOT the UI thread).
 */
abstract class MqvpnVpnService : VpnService(), TunnelCallbacks {

    /** Binder for local (in-process) binding from MqvpnManager. */
    inner class LocalBinder : Binder() {
        fun getService(): MqvpnVpnService = this@MqvpnVpnService
    }

    private val binder = LocalBinder()

    override fun onBind(intent: Intent?): IBinder = binder

    internal var manager: MqvpnManager? = null

    /** The native reactor (poll loop + path table); lives as long as the service. */
    private lateinit var waiter: NativeReactorWaiter
    private lateinit var executor: MqvpnPoller
    private var tunnel: MqvpnTunnel? = null
    private var tunnelBridge: TunnelBridge? = null
    private var pathManager: PathManager? = null
    private var networkMonitor: NetworkMonitor? = null
    private var currentConfig: MqvpnConfig? = null
    private var currentTunPfd: ParcelFileDescriptor? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // --- Lifecycle ---

    override fun onCreate() {
        super.onCreate()
        waiter = NativeReactorWaiter()
        executor = MqvpnPoller(waiter,
            tickFn = {
                val t = tunnel
                val result = t?.tick() ?: 0
                // Poll stats/paths and push to MqvpnManager on each tick
                if (t != null) {
                    manager?.updateStats(t.getStats())
                    manager?.updatePaths(t.getPaths())
                    manager?.updateReorderStats(t.getReorderStats())
                }
                result
            },
            interestFn = {
                val i = tunnel?.getInterest()
                // No session: idle — the engine thread waits up to 25 s for the
                // next enqueue instead of spinning a 1 ms poll() a thousand times a second.
                if (i != null) intArrayOf(i.nextTimerMs, if (i.tunReadable) 1 else 0, if (i.isIdle) 1 else 0)
                else intArrayOf(25_000, 0, 1)
            },
            clientFn = { tunnel?.clientHandle ?: 0L },
            onBadFd = { handle -> pathManager?.handleBadFd(handle) })
        executor.start()
    }

    // Shutdown is atomic with the task queue: cleanup() is the LAST task the
    // engine thread runs (nothing can follow it), later tasks are refused, and
    // the thread frees the reactor itself; stop() waits at most 2 s.
    override fun onDestroy() {
        executor.stop { cleanup() }
        scope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        executor.stop { cleanup() }
        scope.cancel()
        stopSelf()
    }

    // --- Public API ---

    /**
     * Start VPN tunnel. Called from app code.
     * connect() is deferred until first network path is available.
     */
    protected fun startTunnel(config: MqvpnConfig) {
        executor.enqueue {
            // A re-delivered start intent (START_STICKY) must not stack a
            // second client on the reactor's table — nor replace the running
            // session's config (onCreateTun reads it on the next config-ready).
            if (tunnel != null) {
                Log.w(TAG, "startTunnel: a session is already running")
                return@enqueue
            }
            currentConfig = config
            val t = MqvpnTunnel.create(config, this, waiter.reactorHandle)
            tunnel = t

            val monitor = NetworkMonitor(this)
            networkMonitor = monitor

            val pm = PathManager(
                executor, t, monitor,
                protector = { fd -> protect(fd) },
                serverHost = config.serverAddress,
                serverPort = config.serverPort,
                onFatal = { reason ->
                    Log.e(TAG, "ending the session: $reason")
                    stopTunnel()
                },
            )
            pathManager = pm

            monitor.start { event ->
                scope.launch(Dispatchers.IO) { pm.handleEvent(event) }
            }

            emitState(MqvpnState.Connecting)
        }
    }

    /**
     * Stop VPN tunnel. Called by [MqvpnManager.disconnect].
     * Do NOT call from onDestroy — cleanup runs automatically.
     */
    internal fun stopTunnel() {
        executor.enqueue { cleanup() }
    }

    // --- Internal cleanup (idempotent) ---

    private fun cleanup() {
        val t = tunnel ?: return // already cleaned up
        // The destroy and the fd closes run whatever the orderly half throws:
        // this is the executor's finalizer, and the reactor it hands back to
        // the poller must hold no live path when the poller frees it.
        try {
            networkMonitor?.stop()
            tunnelBridge?.stop()
            t.disconnect()
            t.tick() // send CONNECTION_CLOSE
        } finally {
            try {
                t.destroy() // reactor: stop polling → harvest → client_destroy → forget
            } finally {
                pathManager?.closeAllFds() // sockets are ours; closed AFTER the destroy
                currentTunPfd?.close()
                tunnel = null
                tunnelBridge = null
                pathManager = null
                networkMonitor = null
                currentTunPfd = null
                emitState(MqvpnState.Disconnected)
            }
        }
    }

    // --- TunnelCallbacks implementation ---

    override fun onNativeTunnelConfigReady(
        assignedIp: ByteArray, prefix: Int,
        assignedIp6: ByteArray?, prefix6: Int,
        serverIp: ByteArray, serverPrefix: Int,
        mtu: Int, hasV6: Boolean,
    ) {
        val info = TunnelInfo(
            assignedIp = formatIp4(assignedIp),
            prefix = prefix,
            serverIp = formatIp4(serverIp),
            serverPrefix = serverPrefix,
            mtu = mtu,
            assignedIp6 = assignedIp6?.let { formatIp6(it) },
            prefix6 = prefix6,
            hasV6 = hasV6,
        )

        val tunPfd = try {
            onCreateTun(info, currentConfig!!)
        } catch (e: Exception) {
            Log.e(TAG, "onCreateTun failed", e)
            emitState(MqvpnState.Error(
                MqvpnError.TunCreationFailed(e.message ?: "VPN permission denied")))
            executor.enqueue { tunnel?.disconnect() }
            return
        }

        tunnel?.setTunActive(true, tunPfd.fd)

        // On reconnect: stop old TunnelBridge, close old TUN
        tunnelBridge?.stop()
        currentTunPfd?.close()
        currentTunPfd = tunPfd

        tunnelBridge = TunnelBridge(executor, tunnel!!)
        tunnelBridge?.startTunReader(tunPfd, mtu, scope)
        tunnelBridge?.startSender(scope)

        emitState(MqvpnState.Connected(info))
    }

    override fun onNativeTunnelClosed(errorCode: Int) {
        if (errorCode != 0) {
            emitState(MqvpnState.Error(MqvpnError.fromNativeCode(errorCode)))
        }
    }

    override fun onNativeStateChanged(oldState: Int, newState: Int) {
        // Map native states to MqvpnState
        when (newState) {
            1, 2 -> emitState(MqvpnState.Connecting)
            5 -> {} // RECONNECTING — handled by onNativeReconnectScheduled
            6 -> {} // CLOSED — handled by onNativeTunnelClosed or cleanup
        }
    }

    override fun onNativePathEvent(pathHandle: Long, newStatus: Int) {
        // Path changes are picked up by stats/paths polling in tickFn
    }

    override fun onNativeLog(level: Int, message: String) {
        onLog(level, message)
    }

    override fun onNativeReconnectScheduled(delaySec: Int) {
        emitState(MqvpnState.Reconnecting(ReconnectInfo(delaySec)))
        onReconnectScheduled(delaySec)
    }

    /**
     * Emit state to both Manager (StateFlow → UI) and app callback.
     */
    private fun emitState(newState: MqvpnState) {
        manager?.updateState(newState)
        onVpnStateChanged(newState)
    }

    // --- Abstract methods (app implements) ---

    /**
     * Create TUN device using VpnService.Builder.
     *
     * Called from the executor thread (NOT the UI thread).
     * Called once per connection, and again on reconnect.
     *
     * @return ParcelFileDescriptor for the TUN device.
     * @throws Exception if TUN creation fails (triggers Error state).
     */
    abstract fun onCreateTun(info: TunnelInfo, config: MqvpnConfig): ParcelFileDescriptor

    /** State change notification. Update UI from here. */
    abstract fun onVpnStateChanged(newState: MqvpnState)

    // --- Optional callbacks ---

    open fun onLog(level: Int, message: String) {}
    open fun onReconnectScheduled(delaySec: Int) {}

    // --- Helpers ---

    private fun formatIp4(bytes: ByteArray): String =
        InetAddress.getByAddress(bytes).hostAddress ?: "0.0.0.0"

    private fun formatIp6(bytes: ByteArray): String =
        InetAddress.getByAddress(bytes).hostAddress ?: "::"

    companion object {
        private const val TAG = "MqvpnVpnService"
    }
}
