package com.mqvpn.sdk.runtime

/**
 * Serializes all libmqvpn API calls onto a single thread.
 *
 * libmqvpn is NOT thread-safe per handle — all calls (tick, connect,
 * on_socket_recv, etc.) must run on the same thread. This interface
 * ensures that invariant.
 */
interface MqvpnExecutor {
    /** Execute [block] on the engine thread and suspend until it returns. */
    suspend fun <T> call(block: () -> T): T

    /** Fire-and-forget: enqueue [block] for execution on the engine thread. */
    fun enqueue(block: () -> Unit)

    fun start()
    fun stop()
}
