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
    val serverAddress: String = "",
    val serverPort: Int = 443,
    val tlsServerName: String = "",
    val authKey: String = "",
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

    /** Tokens that are non-blank after trimming but don't parse as a valid 1..65535 port. */
    fun invalidPortTokens(): List<String> =
        reorderPorts.split(",")
            .map { it.trim() }
            .filter { it.isNotBlank() && (it.toIntOrNull() ?: -1) !in 1..65535 }

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

    companion object {
        /**
         * Upper bound on distinct reorder ports the platform layer honors.
         * Mirrors `MQVPN_REORDER_MAX_RULES` in
         * `android/sdk-core/src/main/kotlin/com/mqvpn/sdk/core/internal/ReorderPlan.kt`
         * (and `src/reorder.h`) — keep in sync by hand; grep for
         * `MQVPN_REORDER_MAX_RULES` if either side changes.
         */
        const val MAX_REORDER_PORTS = 16
    }
}
