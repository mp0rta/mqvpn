// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.runtime.MqvpnExecutor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.job
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.InputStream
import java.lang.reflect.Method
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.resume

class TunnelBridgeTest {

    // Fake executor that runs blocks synchronously on enqueue
    private class FakeExecutor : MqvpnExecutor {
        val enqueuedBlocks = CopyOnWriteArrayList<() -> Unit>()

        override suspend fun <T> call(block: () -> T): T = block()
        override fun enqueue(block: () -> Unit) {
            enqueuedBlocks.add(block)
            block()
        }
        override fun start() {}
        override fun stop(finalizer: () -> Unit) { finalizer() }
    }

    // Fake tunnel that records onTunPacket calls
    private class FakeTunnel {
        val packets = CopyOnWriteArrayList<Pair<ByteArray, Int>>()
        var returnCode = 0

        fun onTunPacket(data: ByteArray, offset: Int, length: Int): Int {
            packets.add(Pair(data.copyOf(), length))
            return returnCode
        }
    }

    @Test
    fun `frame pool recycles ByteArrays`() {
        val bridge = createBridge(FakeExecutor(), FakeTunnel())

        // Acquire a frame via reflection
        val acquireMethod = getMethod("acquireFrame", Int::class.java)
        val releaseMethod = getMethod("releaseFrame", ByteArray::class.java)

        val frame1 = acquireMethod.invoke(bridge, 1500) as ByteArray
        assertEquals(1500, frame1.size)

        // Release it back
        releaseMethod.invoke(bridge, frame1)

        // Acquire again — should get the same instance (recycled)
        val frame2 = acquireMethod.invoke(bridge, 1500) as ByteArray
        assertSame("Frame should be recycled from pool", frame1, frame2)
    }

    @Test
    fun `frame pool caps at FRAME_POOL_CAPACITY`() {
        val bridge = createBridge(FakeExecutor(), FakeTunnel())
        val releaseMethod = getMethod("releaseFrame", ByteArray::class.java)
        val poolSizeField = bridge.javaClass.getDeclaredField("poolSize").apply {
            isAccessible = true
        }

        // Fill pool beyond capacity
        for (i in 0 until 200) {
            releaseMethod.invoke(bridge, ByteArray(100))
        }

        val poolSize = (poolSizeField.get(bridge) as AtomicInteger).get()
        assertTrue("Pool size ($poolSize) should not exceed 192", poolSize <= 192)
    }

    @Test
    fun `acquireFrame returns new array when pool is empty`() {
        val bridge = createBridge(FakeExecutor(), FakeTunnel())
        val acquireMethod = getMethod("acquireFrame", Int::class.java)

        val frame1 = acquireMethod.invoke(bridge, 1500) as ByteArray
        val frame2 = acquireMethod.invoke(bridge, 1500) as ByteArray

        assertTrue("Should be different instances from empty pool", frame1 !== frame2)
    }

    @Test
    fun `stop cancels reader and sender jobs`() {
        val bridge = createBridge(FakeExecutor(), FakeTunnel())

        // Jobs should be null initially
        val readerField = bridge.javaClass.getDeclaredField("readerJob").apply {
            isAccessible = true
        }
        val senderField = bridge.javaClass.getDeclaredField("senderJob").apply {
            isAccessible = true
        }

        bridge.stop()

        assertEquals(null, readerField.get(bridge))
        assertEquals(null, senderField.get(bridge))
    }

    @Test
    fun `MAX_BATCH_SIZE is 64`() {
        val field = TunnelBridge::class.java.getDeclaredField("MAX_BATCH_SIZE").apply {
            isAccessible = true
        }
        assertEquals(64, field.get(null))
    }

    @Test
    fun `FRAME_POOL_CAPACITY is 192`() {
        val field = TunnelBridge::class.java.getDeclaredField("FRAME_POOL_CAPACITY").apply {
            isAccessible = true
        }
        assertEquals(192, field.get(null))
    }

    private fun createBridge(executor: FakeExecutor, fakeTunnel: FakeTunnel): TunnelBridge =
        TunnelBridge(executor, fakeTunnel::onTunPacket)

    // Engine-thread stand-in: a submitted block waits until the test thread
    // runs it, as behind a busy engine thread. Like MqvpnPoller, call() skips
    // the block once its caller was cancelled.
    private class HoldingExecutor : MqvpnExecutor {
        val held = LinkedBlockingQueue<() -> Unit>()

        override suspend fun <T> call(block: () -> T): T = suspendCancellableCoroutine { cont ->
            held.add { if (cont.isActive) cont.resume(block()) }
        }
        override fun enqueue(block: () -> Unit) { held.add(block) }
        override fun start() {}
        override fun stop(finalizer: () -> Unit) { finalizer() }

        /** Runs the next submitted block on this thread; false if none came in time. */
        fun runNext(timeoutMs: Long = 2_000): Boolean {
            val block = held.poll(timeoutMs, TimeUnit.MILLISECONDS) ?: return false
            block()
            return true
        }
    }

    // A TUN with [count] packets queued, then EOF; packet i carries i in byte 0.
    private class FakeTun(private val count: Int) : InputStream() {
        val reads = AtomicInteger(0)
        override fun read(): Int = throw UnsupportedOperationException()
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val i = reads.getAndIncrement()
            if (i >= count) return -1
            b[off] = i.toByte()
            return PACKET_LEN
        }
    }

    private fun bridgeScope() = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private suspend fun assertStopped(scope: CoroutineScope) {
        val done = withTimeoutOrNull(2_000) { scope.coroutineContext.job.children.toList().joinAll() }
        assertNotNull("TUN reader or sender still running after stop()", done)
    }

    @Test
    fun `a busy engine thread stalls the TUN reader and holds one batch`() = runBlocking {
        val executor = HoldingExecutor()
        val bridge = TunnelBridge(executor) { _, _, _ -> 0 }
        val tun = FakeTun(5_000)
        val scope = bridgeScope()
        bridge.startTunReader(tun, MTU, scope)
        bridge.startSender(scope)

        Thread.sleep(300) // ample for an unbounded reader to take all 5000
        // the sender's batch, a full channel, and one frame waiting to enter it
        assertTrue("TUN reader not stalled: ${tun.reads.get()} reads", tun.reads.get() <= 64 + 192 + 1)
        assertEquals("batches submitted before the first ran", 1, executor.held.size)

        assertTrue(executor.runNext())
        assertTrue("next batch once the first ran", executor.held.poll(2, TimeUnit.SECONDS) != null)
        bridge.stop()
        scope.cancel()
    }

    @Test
    fun `after ERR_AGAIN nothing is fed until tun_readable, then the rest in order`() = runBlocking {
        val executor = HoldingExecutor()
        // Fake core: refusing a packet latches backpressure until the test lifts
        // it (cb_dgram_write); while latched it refuses every packet.
        val refused = setOf(5, 63) // mid-batch, and the last of the first batch
        var latched = false
        val fed = mutableListOf<Int>() // every packet offered, refused ones included
        val bridge = TunnelBridge(executor) { frame, _, _ ->
            val seq = frame[0].toInt()
            fed.add(seq)
            if (seq in refused) latched = true
            if (latched) MqvpnTunnel.ERR_AGAIN else 0
        }
        val packets = 64 + 10
        val tun = FakeTun(packets)
        val scope = bridgeScope()
        bridge.startTunReader(tun, MTU, scope)
        // all packets queued before the sender starts: batches are 0..63, 64..73
        while (tun.reads.get() <= packets) delay(1)
        bridge.startSender(scope)

        while (!latched) assertTrue("packet 5 never fed", executor.runNext())
        assertEquals((0..5).toList(), fed)
        assertFalse("fed while backpressured (after 5)", executor.runNext(timeoutMs = 300))

        latched = false
        bridge.onTunReadable()
        while (!latched) assertTrue("packet 63 never fed", executor.runNext())
        assertEquals((0..63).toList(), fed)
        assertFalse("fed while backpressured (after 63)", executor.runNext(timeoutMs = 300))

        latched = false
        bridge.onTunReadable()
        while (fed.size < packets && executor.runNext()) {}
        assertEquals("every packet once, in order", (0 until packets).toList(), fed)
        bridge.stop()
        scope.cancel()
    }

    @Test
    fun `stop ends the TUN reader and sender while they wait for the engine thread`() = runBlocking {
        val executor = HoldingExecutor()
        val bridge = TunnelBridge(executor) { _, _, _ -> 0 }
        val tun = FakeTun(5_000)
        val scope = bridgeScope()
        bridge.startTunReader(tun, MTU, scope)
        bridge.startSender(scope)
        while (executor.held.isEmpty()) delay(1)
        Thread.sleep(100) // the reader fills the channel and blocks

        bridge.stop()
        assertStopped(scope)
        scope.cancel()
    }

    @Test
    fun `stop ends the TUN sender while it waits for tun_readable`() = runBlocking {
        val executor = HoldingExecutor()
        val bridge = TunnelBridge(executor) { _, _, _ -> MqvpnTunnel.ERR_AGAIN }
        val scope = bridgeScope()
        bridge.startTunReader(FakeTun(10), MTU, scope)
        bridge.startSender(scope)
        assertTrue(executor.runNext()) // the first packet is refused
        assertFalse(executor.runNext(timeoutMs = 300)) // the sender waits for tun_readable

        bridge.stop()
        assertStopped(scope)
        scope.cancel()
    }

    private fun getMethod(name: String, vararg paramTypes: Class<*>): Method {
        return TunnelBridge::class.java.getDeclaredMethod(name, *paramTypes).apply {
            isAccessible = true
        }
    }

    private companion object {
        const val MTU = 1400
        const val PACKET_LEN = 20
    }
}
