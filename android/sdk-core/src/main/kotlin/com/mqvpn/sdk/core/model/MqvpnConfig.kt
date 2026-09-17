// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.model

import android.os.Parcelable
import kotlinx.parcelize.Parcelize
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Parcelize
@Serializable
data class MqvpnConfig(
    /**
     * Bare host: a DNS name or an IP literal, no brackets, characters
     * 0x21-0x7E only, at most 253 characters after one trailing dot is
     * stripped. No trailing dot on a literal (enforced by the verifier, not
     * here). Anything the verifier rejects fails the TLS handshake as
     * "invalid host"; [hostIdentifierError] catches the structural cases up
     * front.
     */
    val serverAddress: String,
    val serverPort: Int = 443,
    /** Same rules as [serverAddress]; when set it is both the SNI and the name the certificate must match. */
    val tlsServerName: String? = null,
    val authKey: String,
    /**
     * Skip server certificate verification (self-signed test servers only).
     * With `false` the certificate is verified against the device CA store and
     * the app's network security config, and must match [tlsServerName] (or
     * [serverAddress]). With `true` the library logs
     * "insecure=1 overrides the configured certificate verifier" once at
     * client creation: expected, it means verification is off.
     */
    val insecure: Boolean = false,
    val multipathEnabled: Boolean = true,
    val scheduler: Scheduler = Scheduler.MIN_RTT,
    val logLevel: LogLevel = LogLevel.INFO,
    val reconnect: Boolean = true,
    val reconnectIntervalSec: Int = 5,
    val killSwitch: Boolean = false,
    val dnsServers: List<String> = listOf("8.8.8.8", "1.1.1.1"),
    val reorderEnabled: Boolean = false,
    val reorderProfile: ReorderProfile = ReorderProfile.CELLULAR_BOND,
    val reorderPorts: List<Int> = emptyList(),
    val hybridEnabled: Boolean = false,
    val hybridTcpMode: HybridTcpMode = HybridTcpMode.AUTO,
) : Parcelable {

    @Serializable
    enum class Scheduler(val native: Int) {
        MIN_RTT(0),
        WLB(1),
        BACKUP_FEC(2),
        WLB_UDP_PIN(3),
    }

    @Serializable
    enum class LogLevel(val native: Int) {
        DEBUG(0),
        INFO(1),
        WARN(2),
        ERROR(3),
    }

    @Serializable
    enum class ReorderProfile(val native: Int) {
        CELLULAR_BOND(3),   // preset: wait=50ms cap=1024
        FIBER_LTE(4),       // preset: wait=50ms cap=2048
    }

    @Serializable
    enum class HybridTcpMode(val native: Int) {
        STREAM(0),   // always use the TCP stream lane
        RAW(1),      // never (bypass the lane)
        AUTO(2),     // per-flow decision at SYN time (default)
    }

    private fun bareHostError(label: String, v: String): String? {
        if (v.isEmpty()) return "$label must not be empty"
        if (v.any { it.code !in 0x21..0x7E }) return "$label must be printable ASCII without spaces"
        if ('[' in v || ']' in v) return "$label must be a bare host without brackets"
        val stripped = if (v.endsWith('.')) v.dropLast(1) else v
        if (stripped.length > 253) return "$label is longer than 253 characters"
        return null
    }

    /**
     * Cheap pre-flight subset of the certificate verifier's host grammar (the
     * full grammar lives in sdk-native and is not reachable from here). Null
     * when both fields are non-empty, contain only characters 0x21-0x7E (no
     * spaces), have no brackets, and are at most 253 characters after one
     * trailing dot; null does not guarantee the verifier accepts the name.
     */
    fun hostIdentifierError(): String? =
        bareHostError("serverAddress", serverAddress) ?: tlsServerName?.let { bareHostError("tlsServerName", it) }

    fun toJson(): String = Json.encodeToString(serializer(), this)

    companion object {
        fun fromJson(json: String): MqvpnConfig =
            Json.decodeFromString(serializer(), json)
    }
}
