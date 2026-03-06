package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.internal.UdpReaderPool
import com.mqvpn.sdk.runtime.MqvpnExecutor
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.concurrent.ConcurrentHashMap

/**
 * UdpReaderPool structural tests.
 *
 * The read loop calls NativeBridge.recvFrom() (JNI), so threads die
 * immediately in JVM. These tests verify map management, thread naming,
 * and idempotent stop/cleanup behavior.
 */
@RunWith(RobolectricTestRunner::class)
class UdpReaderPoolTest {

    private lateinit var pool: UdpReaderPool
    private val dummyExecutor = object : MqvpnExecutor {
        override suspend fun <T> call(block: () -> T): T = block()
        override fun enqueue(block: () -> Unit) { block() }
        override fun start() {}
        override fun stop() {}
    }

    // Reflection accessor for internal readers map
    private fun getReadersMap(): ConcurrentHashMap<*, *> {
        val field = UdpReaderPool::class.java.getDeclaredField("readers")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        return field.get(pool) as ConcurrentHashMap<*, *>
    }

    @Before
    fun setUp() {
        pool = UdpReaderPool(dummyExecutor)
    }

    @After
    fun tearDown() {
        pool.stopAll()
    }

    @Test
    fun `startReader adds entry to readers map`() {
        val tunnel = createDummyTunnel()
        pool.startReader(fd = 99, pathHandle = 1L, name = "wlan0", tunnel = tunnel)

        val readers = getReadersMap()
        assertEquals(1, readers.size)
        assertTrue(readers.containsKey(1L))
    }

    @Test
    fun `startReader creates thread with correct name`() {
        val tunnel = createDummyTunnel()
        pool.startReader(fd = 99, pathHandle = 1L, name = "wlan0", tunnel = tunnel)

        val readers = getReadersMap()
        val entry = readers[1L]!!
        val threadField = entry::class.java.getDeclaredField("thread")
        threadField.isAccessible = true
        val thread = threadField.get(entry) as Thread
        assertEquals("mqvpn-udp-wlan0", thread.name)
    }

    @Test
    fun `stopReader removes entry from readers map`() {
        val tunnel = createDummyTunnel()
        pool.startReader(fd = 99, pathHandle = 1L, name = "wlan0", tunnel = tunnel)
        assertEquals(1, getReadersMap().size)

        pool.stopReader(1L)
        assertTrue(getReadersMap().isEmpty())
    }

    @Test
    fun `stopReader on unknown handle does not throw`() {
        pool.stopReader(999L) // should be a no-op
    }

    @Test
    fun `stopAll clears all entries`() {
        val tunnel = createDummyTunnel()
        pool.startReader(fd = 10, pathHandle = 1L, name = "wlan0", tunnel = tunnel)
        pool.startReader(fd = 11, pathHandle = 2L, name = "rmnet0", tunnel = tunnel)
        assertEquals(2, getReadersMap().size)

        pool.stopAll()
        assertTrue(getReadersMap().isEmpty())
    }

    @Test
    fun `stopAll on empty pool does not throw`() {
        pool.stopAll() // should be a no-op
    }

    @Test
    fun `multiple startReader for different paths`() {
        val tunnel = createDummyTunnel()
        pool.startReader(fd = 10, pathHandle = 1L, name = "wlan0", tunnel = tunnel)
        pool.startReader(fd = 11, pathHandle = 2L, name = "rmnet0", tunnel = tunnel)
        pool.startReader(fd = 12, pathHandle = 3L, name = "eth0", tunnel = tunnel)
        assertEquals(3, getReadersMap().size)
    }

    @Test
    fun `stopReader then startReader reuses handle`() {
        val tunnel = createDummyTunnel()
        pool.startReader(fd = 10, pathHandle = 1L, name = "wlan0", tunnel = tunnel)
        pool.stopReader(1L)
        assertTrue(getReadersMap().isEmpty())

        pool.startReader(fd = 20, pathHandle = 1L, name = "wlan0-new", tunnel = tunnel)
        assertEquals(1, getReadersMap().size)
    }

    @Test
    fun `entry stores correct fd`() {
        val tunnel = createDummyTunnel()
        pool.startReader(fd = 42, pathHandle = 1L, name = "wlan0", tunnel = tunnel)

        val readers = getReadersMap()
        val entry = readers[1L]!!
        val fdField = entry::class.java.getDeclaredField("fd")
        fdField.isAccessible = true
        assertEquals(42, fdField.getInt(entry))
    }

    /**
     * Create a MqvpnTunnel with dummy handles.
     * The tunnel is never actually called (threads die before reaching onSocketRecv).
     */
    private fun createDummyTunnel(): MqvpnTunnel {
        val ctor = MqvpnTunnel::class.java.getDeclaredConstructor(Long::class.java, Long::class.java)
        ctor.isAccessible = true
        return ctor.newInstance(0L, 0L)
    }
}
