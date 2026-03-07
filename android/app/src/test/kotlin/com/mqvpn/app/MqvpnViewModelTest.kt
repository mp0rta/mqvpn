package com.mqvpn.app

import com.mqvpn.app.service.MyVpnService
import com.mqvpn.app.ui.MqvpnViewModel
import com.mqvpn.sdk.core.MqvpnManager
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.TunnelInfo
import com.mqvpn.sdk.core.model.VpnStats
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class MqvpnViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    private val stateFlow = MutableStateFlow<MqvpnState>(MqvpnState.Disconnected)
    private val statsFlow = MutableStateFlow(VpnStats())
    private val pathsFlow = MutableStateFlow<List<PathInfo>>(emptyList())

    private val mockManager = mockk<MqvpnManager>(relaxed = true).also {
        every { it.vpnState } returns stateFlow
        every { it.stats } returns statsFlow
        every { it.paths } returns pathsFlow
    }

    private lateinit var viewModel: MqvpnViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        viewModel = MqvpnViewModel(mockManager)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `initial state is Disconnected`() {
        assertEquals(MqvpnState.Disconnected, viewModel.vpnState.value)
    }

    @Test
    fun `initial stats are zero`() {
        val stats = viewModel.stats.value
        assertEquals(0L, stats.bytesTx)
        assertEquals(0L, stats.bytesRx)
    }

    @Test
    fun `initial paths are empty`() {
        assertTrue(viewModel.paths.value.isEmpty())
    }

    @Test
    fun `connect delegates to manager`() {
        val config = MqvpnConfig(
            serverAddress = "vpn.example.com",
            authKey = "testkey",
        )
        viewModel.connect(config)
        verify { mockManager.connect(config, MyVpnService::class.java) }
    }

    @Test
    fun `disconnect delegates to manager`() {
        viewModel.disconnect()
        verify { mockManager.disconnect() }
    }

    @Test
    fun `state updates propagate`() = runTest(testDispatcher) {
        val job = launch { viewModel.vpnState.collect {} }
        advanceUntilIdle()

        val info = TunnelInfo(
            assignedIp = "10.0.0.2",
            prefix = 24,
            serverIp = "1.2.3.4",
            serverPrefix = 24,
            mtu = 1400,
        )
        stateFlow.value = MqvpnState.Connected(info)
        advanceUntilIdle()

        assertTrue(viewModel.vpnState.value is MqvpnState.Connected)
        job.cancel()
    }

    @Test
    fun `stats updates propagate`() = runTest(testDispatcher) {
        val job = launch { viewModel.stats.collect {} }
        advanceUntilIdle()

        statsFlow.value = VpnStats(bytesTx = 1024, bytesRx = 2048, srttMs = 15)
        advanceUntilIdle()

        assertEquals(1024L, viewModel.stats.value.bytesTx)
        assertEquals(2048L, viewModel.stats.value.bytesRx)
        assertEquals(15, viewModel.stats.value.srttMs)
        job.cancel()
    }

    @Test
    fun `paths updates propagate`() = runTest(testDispatcher) {
        val job = launch { viewModel.paths.collect {} }
        advanceUntilIdle()

        val path = PathInfo(
            handle = 1L,
            status = 1,
            iface = "wlan0",
            bytesTx = 100,
            bytesRx = 200,
            srttMs = 12,
        )
        pathsFlow.value = listOf(path)
        advanceUntilIdle()

        assertEquals(1, viewModel.paths.value.size)
        assertEquals("wlan0", viewModel.paths.value[0].iface)
        job.cancel()
    }

    @Test
    fun `prepareVpn delegates to manager`() {
        every { mockManager.prepareVpn() } returns null
        val result = viewModel.prepareVpn()
        assertEquals(null, result)
        verify { mockManager.prepareVpn() }
    }
}
