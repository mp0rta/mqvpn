// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.runtime

import com.mqvpn.sdk.native_.NativeBridge

/**
 * [Waiter] over the native reactor (mqvpn_jni reactor* entry points).
 *
 * The reactor is owned by the executor, not by a client: it is created here,
 * before the poller thread starts, and freed by that thread in [close] after
 * its loop exited — so the client's lifetime (a session) and the reactor's
 * (the service) are independent, and [wake] never touches a client pointer.
 *
 * [wake] and [close] share one lock and [close] zeroes the handle: an
 * `enqueue` on another thread that passed the poller's accepting check just
 * before shutdown finds a closed waiter (no-op), never a freed reactor.
 */
class NativeReactorWaiter : Waiter {
    private val lock = Any()

    @Volatile
    private var handle: Long = NativeBridge.reactorNew().also {
        check(it != 0L) { "reactorNew failed" }
    }

    /** For MqvpnTunnel.create (add/remove/release/destroy go through the reactor). 0 after [close]. */
    val reactorHandle: Long get() = handle

    override fun await(client: Long, timeoutMs: Int): Int {
        val h = handle
        return if (h == 0L) 0 else NativeBridge.reactorWait(h, client, timeoutMs)
    }

    override fun takeBadFd(): Long {
        val h = handle
        return if (h == 0L) -1L else NativeBridge.reactorTakeBadFd(h)
    }

    override fun wake() {
        synchronized(lock) {
            val h = handle
            if (h != 0L) NativeBridge.reactorWake(h)
        }
    }

    override fun close() {
        synchronized(lock) {
            val h = handle
            handle = 0L
            if (h != 0L) NativeBridge.reactorFree(h)
        }
    }
}
