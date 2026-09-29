// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.runtime

/**
 * What the engine thread blocks on between ticks.
 *
 * Production: [NativeReactorWaiter] — the native reactor's poll() over the
 * path fds plus its eventfd, which also drains every readable path into the
 * client on the calling thread. Tests substitute a park-based one.
 *
 * Threads: [await], [takeBadFd] and [close] run on the engine thread only;
 * [wake] may be called from any thread and must be a no-op after [close].
 */
interface Waiter {
    /**
     * Block up to [timeoutMs] for I/O or a wake. Path receive happens here,
     * on this thread, into [client] (0 while no session exists — legal only
     * while no path is attached). Returns the number of drains (>= 0) or -1
     * on a wait error the caller logs and otherwise ignores.
     */
    fun await(client: Long, timeoutMs: Int): Int

    /**
     * The next path handle whose fd the reactor found closed behind the
     * platform, delivered once; -1 when there is none.
     */
    fun takeBadFd(): Long

    /** Interrupt an [await] in progress (or the next one). Any thread. */
    fun wake()

    /** Release the native resources. Engine thread, after its loop exited. */
    fun close()
}
