// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.runtime

/** Thrown by [MqvpnExecutor.call] once [MqvpnExecutor.stop] closed the queue: the block never ran. */
class ExecutorStoppedException : IllegalStateException("Poller stopped")

/**
 * Serializes all libmqvpn API calls onto a single thread.
 *
 * libmqvpn is NOT thread-safe per handle — all calls (tick, connect,
 * path add/remove, and the receive drains the waiter performs) must run on
 * the same thread. This interface ensures that invariant.
 */
interface MqvpnExecutor {
    /**
     * Execute [block] on the engine thread and suspend until it returns.
     *
     * @throws ExecutorStoppedException once [stop] closed the queue: the block never ran.
     */
    suspend fun <T> call(block: () -> T): T

    /** Fire-and-forget: enqueue [block] for execution on the engine thread. Dropped after [stop]. */
    fun enqueue(block: () -> Unit)

    /** Start the engine thread. One-shot: a second call throws [IllegalStateException]. */
    fun start()

    /**
     * Atomic shutdown: under the enqueue lock, stop accepting and append
     * [finalizer] as the LAST task, so nothing ever runs after it and no
     * task can land in a dead queue; then wake the engine thread and wait
     * (bounded) for it to run the queue to the end and exit.
     *
     * Before [start] this is a no-op: no finalizer runs and (for
     * [MqvpnPoller]) no waiter is closed.
     */
    fun stop(finalizer: () -> Unit = {})
}
