package com.mqvpn.sdk.core

import com.mqvpn.sdk.runtime.MqvpnExecutor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Method
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

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
        override fun stop() {}
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

    // Helper to create a TunnelBridge with mocked tunnel via reflection
    private fun createBridge(executor: FakeExecutor, fakeTunnel: FakeTunnel): TunnelBridge {
        // TunnelBridge takes MqvpnExecutor and MqvpnTunnel
        // MqvpnTunnel requires native handles which we can't create in unit tests.
        // Use reflection to construct with mock values.
        val constructor = TunnelBridge::class.java.declaredConstructors.first()
        constructor.isAccessible = true
        // MqvpnTunnel(clientHandle=0, cfgHandle=0) — won't call native methods in tests
        val tunnelConstructor = MqvpnTunnel::class.java.declaredConstructors.first()
        tunnelConstructor.isAccessible = true
        val mockTunnel = tunnelConstructor.newInstance(0L, 0L) as MqvpnTunnel
        return constructor.newInstance(executor, mockTunnel) as TunnelBridge
    }

    private fun getMethod(name: String, vararg paramTypes: Class<*>): Method {
        return TunnelBridge::class.java.getDeclaredMethod(name, *paramTypes).apply {
            isAccessible = true
        }
    }
}
