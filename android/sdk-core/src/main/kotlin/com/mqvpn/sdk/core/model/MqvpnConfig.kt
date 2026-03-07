package com.mqvpn.sdk.core.model

import android.os.Parcelable
import kotlinx.parcelize.Parcelize
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Parcelize
@Serializable
data class MqvpnConfig(
    val serverAddress: String,
    val serverPort: Int = 443,
    val authKey: String,
    val insecure: Boolean = false,
    val multipathEnabled: Boolean = true,
    val scheduler: Scheduler = Scheduler.MIN_RTT,
    val logLevel: LogLevel = LogLevel.INFO,
    val reconnect: Boolean = true,
    val reconnectIntervalSec: Int = 5,
    val killSwitch: Boolean = false,
    val dnsServers: List<String> = listOf("8.8.8.8", "1.1.1.1"),
) : Parcelable {

    @Serializable
    enum class Scheduler(val native: Int) {
        MIN_RTT(0),
        WLB(1),
    }

    @Serializable
    enum class LogLevel(val native: Int) {
        DEBUG(0),
        INFO(1),
        WARN(2),
        ERROR(3),
    }

    fun toJson(): String = Json.encodeToString(serializer(), this)

    companion object {
        fun fromJson(json: String): MqvpnConfig =
            Json.decodeFromString(serializer(), json)
    }
}
