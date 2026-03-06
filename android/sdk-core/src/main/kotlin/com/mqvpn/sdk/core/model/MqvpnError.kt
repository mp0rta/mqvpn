package com.mqvpn.sdk.core.model

/**
 * VPN error types mapped from libmqvpn error codes.
 */
sealed interface MqvpnError {
    val message: String

    data class TunCreationFailed(override val message: String) : MqvpnError
    data class AuthFailed(override val message: String) : MqvpnError
    data class TlsError(override val message: String) : MqvpnError
    data class ProtocolError(val code: Int, override val message: String) : MqvpnError
    data class EngineError(val code: Int, override val message: String) : MqvpnError
    data class AbiMismatch(override val message: String) : MqvpnError
    data class Timeout(override val message: String) : MqvpnError
    data class Unknown(val nativeCode: Int, override val message: String) : MqvpnError

    companion object {
        /** Map C error code to MqvpnError. */
        fun fromNativeCode(code: Int): MqvpnError = when (code) {
            -4 -> TlsError("TLS handshake failed")
            -5 -> AuthFailed("PSK authentication failed")
            -6 -> ProtocolError(code, "MASQUE not supported")
            -11 -> AbiMismatch("Callback ABI version mismatch")
            -12 -> Timeout("Connection timeout")
            -3 -> EngineError(code, "Engine error")
            else -> Unknown(code, "Error code $code")
        }
    }
}
