package com.mqvpn.sdk.core

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.IBinder
import android.util.Log
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.VpnStats
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Public-facing manager for the mqvpn SDK.
 *
 * Provides [StateFlow]-based observation of VPN state, stats, and paths.
 * Manages the VpnService lifecycle via [ServiceConnection].
 */
class MqvpnManager(private val context: Context) {

    private val _vpnState = MutableStateFlow<MqvpnState>(MqvpnState.Disconnected)
    val vpnState: StateFlow<MqvpnState> = _vpnState.asStateFlow()

    private val _stats = MutableStateFlow(VpnStats())
    val stats: StateFlow<VpnStats> = _stats.asStateFlow()

    private val _paths = MutableStateFlow<List<PathInfo>>(emptyList())
    val paths: StateFlow<List<PathInfo>> = _paths.asStateFlow()

    private var boundService: MqvpnVpnService? = null
    private var serviceConnection: ServiceConnection? = null

    /**
     * Prepare VPN permission. Returns null if already granted,
     * otherwise returns an Intent to launch the system VPN dialog.
     */
    fun prepareVpn(): Intent? = VpnService.prepare(context)

    /**
     * Start VPN with the given config.
     * Launches the VpnService, binds to it, and calls startTunnel().
     */
    fun connect(config: MqvpnConfig, serviceClass: Class<out MqvpnVpnService>) {
        _vpnState.value = MqvpnState.Connecting

        val intent = Intent(context, serviceClass).apply {
            putExtra(EXTRA_CONFIG_JSON, config.toJson())
        }
        context.startForegroundService(intent)

        // Bind to service for lifecycle observation
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                val binder = service as? MqvpnVpnService.LocalBinder ?: return
                boundService = binder.getService()
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                // Service crashed or was killed — reset state to prevent UI divergence
                boundService = null
                _vpnState.value = MqvpnState.Disconnected
                _stats.value = VpnStats()
                _paths.value = emptyList()
            }
        }
        serviceConnection = conn
        try {
            context.bindService(intent, conn, Context.BIND_AUTO_CREATE)
        } catch (e: Exception) {
            Log.w(TAG, "bindService failed: ${e.message}")
        }
    }

    /** Disconnect the VPN. */
    fun disconnect() {
        boundService?.stopTunnel()
        _vpnState.value = MqvpnState.Disconnected
    }

    /** Get libmqvpn version string. */
    fun getVersion(): String = MqvpnSdk.getVersion()

    /** Generate a random PSK key. */
    fun generateKey(): String = MqvpnSdk.generateKey()

    /** Update state (called from VpnService). */
    internal fun updateState(state: MqvpnState) {
        _vpnState.value = state
    }

    /** Update stats (called from VpnService). */
    internal fun updateStats(s: VpnStats) {
        _stats.value = s
    }

    /** Update paths (called from VpnService). */
    internal fun updatePaths(p: List<PathInfo>) {
        _paths.value = p
    }

    fun destroy() {
        serviceConnection?.let { conn ->
            try { context.unbindService(conn) } catch (_: Exception) {}
        }
        serviceConnection = null
        boundService = null
    }

    companion object {
        private const val TAG = "MqvpnManager"
        internal const val EXTRA_CONFIG_JSON = "mqvpn_config_json"
    }
}
