package com.mqvpn.sdk.core.internal

/**
 * Callback interface invoked by JNI (mqvpn_jni.c) on the executor thread.
 *
 * The callback object passed to [NativeBridge.clientNew] must implement
 * these methods. MqvpnVpnService implements this interface.
 */
internal interface TunnelCallbacks {
    fun onNativeTunnelConfigReady(
        assignedIp: ByteArray, prefix: Int,
        assignedIp6: ByteArray?, prefix6: Int,
        serverIp: ByteArray, serverPrefix: Int,
        mtu: Int, hasV6: Boolean,
    )

    fun onNativeTunnelClosed(errorCode: Int)
    fun onNativeStateChanged(oldState: Int, newState: Int)
    fun onNativePathEvent(pathHandle: Long, newStatus: Int)
    fun onNativeLog(level: Int, message: String)
    fun onNativeReconnectScheduled(delaySec: Int)
}
