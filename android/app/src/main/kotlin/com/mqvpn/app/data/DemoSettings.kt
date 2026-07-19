// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.data

import com.mqvpn.sdk.core.model.MqvpnConfig

/**
 * Plain, persistable settings model backing the demo app's settings screen.
 * No Android imports: defaults, tolerant enum decode, port-text parsing,
 * and validation are all pure functions so they can be unit tested without
 * an Android runtime.
 */
data class DemoSettings(
    val serverAddress: String = "160.251.143.149",
    val serverPort: Int = 443,
    val tlsServerName: String = "",
    val authKey: String = "tiiUC0/Fx51w5XuxAnpOgdRZb19SLqglwFdhxbbsbnM=",
    val insecure: Boolean = true,
    val killSwitch: Boolean = false,
    val reorderEnabled: Boolean = false,
    val reorderProfile: String = MqvpnConfig.ReorderProfile.CELLULAR_BOND.name,
    val reorderPorts: String = "443",
    val hybridEnabled: Boolean = false,
    val hybridTcpMode: String = MqvpnConfig.HybridTcpMode.AUTO.name,
) {
    fun reorderProfileEnum(): MqvpnConfig.ReorderProfile =
        MqvpnConfig.ReorderProfile.entries.firstOrNull { it.name == reorderProfile }
            ?: MqvpnConfig.ReorderProfile.CELLULAR_BOND

    fun hybridTcpModeEnum(): MqvpnConfig.HybridTcpMode =
        MqvpnConfig.HybridTcpMode.entries.firstOrNull { it.name == hybridTcpMode }
            ?: MqvpnConfig.HybridTcpMode.AUTO

    fun parsedReorderPorts(): List<Int> =
        reorderPorts.split(",")
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..65535 }

    fun distinctValidPortCount(): Int = parsedReorderPorts().distinct().size

    fun toMqvpnConfig(): MqvpnConfig = MqvpnConfig(
        serverAddress = serverAddress.trim(),
        serverPort = serverPort,
        tlsServerName = tlsServerName.trim().ifEmpty { null },
        authKey = authKey.trim(),
        insecure = insecure,
        killSwitch = killSwitch,
        reorderEnabled = reorderEnabled,
        reorderProfile = reorderProfileEnum(),
        reorderPorts = parsedReorderPorts(),
        hybridEnabled = hybridEnabled,
        hybridTcpMode = hybridTcpModeEnum(),
    )

    fun hostValid(): Boolean = serverAddress.trim().isNotBlank()

    fun portValid(): Boolean = serverPort in 1..65535

    fun reorderPortsValid(): Boolean = !reorderEnabled || parsedReorderPorts().isNotEmpty()

    fun isValid(): Boolean = hostValid() && portValid() && reorderPortsValid()
}
