// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.TunnelInfo
import com.mqvpn.sdk.runtime.MqvpnPoller
import com.mqvpn.sdk.runtime.NativeReactorWaiter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

/**
 * Abstract VPN service base class for mqvpn Android SDK.
 *
 * Subclasses implement [onCreateTun] and [onVpnStateChanged], and start a
 * session from onStartCommand with [resolveConfig] and [startTunnel].
 * The SDK manages all internal components (executor, tunnel, I/O, paths);
 * one connect's worth of them is a [Session].
 *
 * Thread safety: All JNI calls are serialized on the executor thread.
 * [onCreateTun] is called from the executor thread (NOT the UI thread).
 */
abstract class MqvpnVpnService : VpnService() {

    /** The native reactor (poll loop + path table); lives as long as the service. */
    private lateinit var waiter: NativeReactorWaiter
    private lateinit var executor: MqvpnPoller
    private var session: Session? = null // executor thread only
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // --- Lifecycle ---

    override fun onCreate() {
        super.onCreate()
        waiter = NativeReactorWaiter()
        executor = MqvpnPoller(waiter,
            tickFn = { session?.tick() ?: 0 },
            // No session: idle — the engine thread waits up to 25 s for the
            // next enqueue instead of spinning a 1 ms poll() a thousand times a second.
            interestFn = { session?.interest() ?: intArrayOf(25_000, 0, 1) },
            clientFn = { session?.clientHandle ?: 0L },
            onBadFd = { handle -> session?.handleBadFd(handle) })
        executor.start()
        SessionStore.service = this
    }

    // Shutdown is atomic with the task queue: cleanup() is the LAST task the
    // engine thread runs (nothing can follow it), later tasks are refused, and
    // the thread frees the reactor itself; stop() waits at most 2 s.
    override fun onDestroy() {
        if (SessionStore.service === this) SessionStore.service = null
        executor.stop { cleanup() }
        scope.cancel()
        prefs().edit().remove(KEY_CONFIG_JSON).apply()
        super.onDestroy()
    }

    override fun onRevoke() {
        executor.stop { cleanup() }
        scope.cancel()
        stopSelf()
    }

    // --- Public API ---

    /**
     * The config this start is for: the one [MqvpnManager.connect] sent, else
     * (a START_STICKY restart after the process died) the last one started.
     * Each start persists its config for that restart; onDestroy forgets it.
     * Null = nothing to start: stop the service.
     */
    protected fun resolveConfig(intent: Intent?): MqvpnConfig? {
        val json = intent?.getStringExtra(MqvpnManager.EXTRA_CONFIG_JSON)
            ?: prefs().getString(KEY_CONFIG_JSON, null)
            ?: return null
        val config = try {
            MqvpnConfig.fromJson(json)
        } catch (e: Exception) {
            Log.e(TAG, "unreadable config", e)
            return null
        }
        prefs().edit().putString(KEY_CONFIG_JSON, json).apply()
        return config
    }

    /**
     * Start VPN tunnel. Called from app code.
     * connect() is deferred until first network path is available.
     */
    protected fun startTunnel(config: MqvpnConfig) {
        executor.enqueue {
            // A re-delivered start intent (START_STICKY) must not stack a
            // second client on the reactor's table — nor replace the running
            // session's config (onCreateTun reads it on the next config-ready).
            if (session != null) {
                Log.w(TAG, "startTunnel: a session is already running")
                return@enqueue
            }
            val s = Session(this, executor, scope, config)
            session = s
            if (!s.open(waiter.reactorHandle)) session = null
        }
    }

    /**
     * Stop VPN tunnel. Called by [MqvpnManager.disconnect].
     * Do NOT call from onDestroy — cleanup runs automatically.
     */
    internal open fun stopTunnel() {
        executor.enqueue { cleanup() }
    }

    /** Ends [s] if it is still the running session (a late request from an old one is moot). */
    internal fun stopSession(s: Session) {
        executor.enqueue { if (session === s) cleanup() }
    }

    // --- Internal cleanup (idempotent) ---

    private fun cleanup() {
        val s = session ?: return // already cleaned up
        session = null
        s.close()
    }

    /** Emit state to the store (StateFlow → UI) and the app callback; executor thread only. */
    internal fun emitState(newState: MqvpnState) {
        SessionStore.state.value = newState
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

    private fun prefs() = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)

    companion object {
        private const val TAG = "MqvpnVpnService"

        // the app's names from before the SDK owned the restart config
        private const val PREFS_NAME = "mqvpn_service"
        private const val KEY_CONFIG_JSON = "config_json"
    }
}
