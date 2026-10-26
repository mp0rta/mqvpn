// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SystemClock
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

    /**
     * Set by [MqvpnManager] on (re)bind. A manager attaching to a service
     * that already emitted a state gets it replayed so a recreated UI
     * resyncs; a fresh service (null) replays nothing, so binding to it does
     * not clobber the Connecting state [MqvpnManager.connect] just set.
     * stateLock serializes the replay against [emitState]: the setter runs on
     * the main thread while the executor emits, and an unserialized replay
     * could overwrite a newer state with the one it read.
     */
    internal var manager: MqvpnManager? = null
        set(value) {
            synchronized(stateLock) {
                field = value
                val state = lastState
                if (value != null && state != null) {
                    value.updateState(state)
                }
            }
        }

    private val stateLock = Any()

    /** Last state given to emitState, null until the first emit; guarded by [stateLock]. */
    private var lastState: MqvpnState? = null

    /** The native reactor (poll loop + path table); lives as long as the service. */
    private lateinit var waiter: NativeReactorWaiter
    private lateinit var executor: MqvpnPoller
    private var tunnel: MqvpnTunnel? = null
    private var lastReorderStatsMs = 0L
    private var tunnelBridge: TunnelBridge? = null
    private var pathManager: PathManager? = null
    private var networkMonitor: NetworkMonitor? = null
    private var currentConfig: MqvpnConfig? = null
    private var currentTunPfd: ParcelFileDescriptor? = null

    // Close/reconnect bookkeeping, executor thread only. A close is reported
    // before the native client reveals whether it will retry, so the Error
    // emit waits for that decision: the app stops the service on Error,
    // which must not kill a scheduled reconnect.
    private var pendingCloseError: MqvpnError? = null
    private var tearingDown = false

    /** True once this session emitted Connected; internal for tests. */
    internal var sessionEstablished = false
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
                    // JNI array + boxed list: once per wall-clock second, not per poll
                    val now = SystemClock.elapsedRealtime()
                    if (now - lastReorderStatsMs >= 1000) {
                        lastReorderStatsMs = now
                        manager?.updateReorderStats(t.getReorderStats())
                    }
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
            pendingCloseError = null
            sessionEstablished = false
            tearingDown = false
            val t = MqvpnTunnel.create(config, this, waiter.reactorHandle)
            tunnel = t

            val monitor = NetworkMonitor(this, holdBluetooth = config.bluetoothPathEnabled)
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

            // A refused network request throws here. The executor only logs
            // the exception, so without the cleanup the half-built session
            // would keep `tunnel` set and refuse every later startTunnel.
            try {
                monitor.start { event ->
                    scope.launch(Dispatchers.IO) { pm.handleEvent(event) }
                }
            } catch (e: Exception) {
                cleanup()
                throw e
            }

            emitState(MqvpnState.Connecting)
        }
    }

    /**
     * Stop VPN tunnel. Called by [MqvpnManager.disconnect].
     * Do NOT call from onDestroy — cleanup runs automatically.
     */
    internal open fun stopTunnel() {
        executor.enqueue { cleanup() }
    }

    // --- Internal cleanup (idempotent) ---

    private fun cleanup() {
        val t = tunnel ?: return // already cleaned up
        tearingDown = true // the teardown's own close callbacks are not session errors
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
                // keep a terminal Error on display: cleanup after an error
                // emit (service stopping) must not downgrade it
                if (synchronized(stateLock) { lastState } !is MqvpnState.Error) {
                    emitState(MqvpnState.Disconnected)
                }
            }
        }
    }

    // --- TunnelCallbacks implementation ---

    override fun onNativeTunnelConfigReady(
        assignedIp: ByteArray, prefix: Int,
        assignedIp6: ByteArray?, prefix6: Int,
        serverIp: ByteArray, serverPrefix: Int,
        mtu: Int, hasV6: Boolean,
        hasServerScheduler: Boolean, serverScheduler: Int,
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
            serverScheduler = if (hasServerScheduler) {
                MqvpnConfig.Scheduler.entries.firstOrNull { it.native == serverScheduler }
            } else null,
            requestedScheduler = currentConfig?.let { c ->
                c.scheduler.takeIf { c.requestServerScheduler }
            },
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
        if (errorCode == 0) return
        if (errorCode == NATIVE_ERR_CLOSED) {
            // close notify: a reconnect schedule or CLOSED follows in the
            // same native call — defer to that decision
            pendingCloseError = MqvpnError.fromNativeCode(errorCode)
            return
        }
        // request-level failure (bad key, non-200, rejected cert): the QUIC
        // conn may stay open with no follow-up callback, so terminal here
        emitTerminalError(MqvpnError.fromNativeCode(errorCode))
        stopTunnel()
    }

    override fun onNativeStateChanged(oldState: Int, newState: Int) {
        // Map native states to MqvpnState
        when (newState) {
            1, 2 -> emitState(MqvpnState.Connecting)
            5 -> {} // RECONNECTING — handled by onNativeReconnectScheduled
            // CLOSED with no reconnect scheduled (e.g. the server certificate
            // was rejected): terminal. A clean close leaves no pending error.
            6 -> pendingCloseError?.let { emitTerminalError(it) }
        }
    }

    override fun onNativePathEvent(pathHandle: Long, newStatus: Int) {
        // Path changes are picked up by stats/paths polling in tickFn
    }

    override fun onNativeLog(level: Int, message: String) {
        onLog(level, message)
    }

    override fun onNativeReconnectScheduled(delaySec: Int) {
        // a terminal Error emitted in the same native call, or a teardown in
        // progress, makes the schedule moot — it must not overwrite the Error
        if (tearingDown || synchronized(stateLock) { lastState } is MqvpnState.Error) return
        if (!sessionEstablished) {
            // never connected (bad address or server down): fail fast instead
            // of an endless Reconnecting; the teardown cancels the armed timer
            emitTerminalError(pendingCloseError ?: MqvpnError.fromNativeCode(NATIVE_ERR_CLOSED))
            stopTunnel()
            return
        }
        pendingCloseError = null
        emitState(MqvpnState.Reconnecting(ReconnectInfo(delaySec)))
        onReconnectScheduled(delaySec)
    }

    /**
     * Terminal [MqvpnState.Error]: the session's first Error wins (it is the
     * most specific), silent while tearing down. Executor thread only.
     */
    private fun emitTerminalError(error: MqvpnError) {
        if (tearingDown) return
        if (synchronized(stateLock) { lastState } is MqvpnState.Error) return
        emitState(MqvpnState.Error(error))
    }

    /**
     * Emit state to both Manager (StateFlow → UI) and app callback.
     */
    private fun emitState(newState: MqvpnState) {
        if (newState is MqvpnState.Connected) {
            sessionEstablished = true
            pendingCloseError = null
        }
        synchronized(stateLock) {
            lastState = newState
            manager?.updateState(newState)
        }
        // app callback outside the lock: it may be slow or call back into us
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

        /** MQVPN_ERR_CLOSED in libmqvpn.h: connection closed. */
        private const val NATIVE_ERR_CLOSED = -10
    }
}
