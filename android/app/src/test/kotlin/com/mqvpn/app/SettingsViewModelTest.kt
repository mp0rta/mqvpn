// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import androidx.lifecycle.SavedStateHandle
import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.data.SettingsRepository
import com.mqvpn.app.ui.SettingsViewModel
import com.mqvpn.sdk.core.MqvpnManager
import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.TunnelInfo
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SettingsViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    private val stateFlow = MutableStateFlow<MqvpnState>(MqvpnState.Disconnected)
    private val mockManager = mockk<MqvpnManager>(relaxed = true).also {
        every { it.vpnState } returns stateFlow
    }

    private val testSettings = DemoSettings(serverAddress = "repo.example.com", serverPort = 1234)
    private val settingsFlow = MutableStateFlow(testSettings)
    private val mockRepository = mockk<SettingsRepository>(relaxed = true).also {
        every { it.settings } returns settingsFlow
        coEvery { it.save(any()) } returns Unit
    }

    private lateinit var viewModel: SettingsViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        viewModel = SettingsViewModel(mockRepository, mockManager, SavedStateHandle())
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `repository read failure surfaces loadError and leaves draft null`() = runTest(testDispatcher) {
        val failingRepository = mockk<SettingsRepository>(relaxed = true).also {
            every { it.settings } returns flow { throw IllegalStateException("boom") }
        }
        val failingViewModel = SettingsViewModel(failingRepository, mockManager, SavedStateHandle())
        advanceUntilIdle()

        assertNull(failingViewModel.draft.value)
        assertEquals("Load failed: boom", failingViewModel.loadError.value)
    }

    @Test
    fun `isEditable reflects vpnState kind`() = runTest(testDispatcher) {
        advanceUntilIdle()
        assertTrue(viewModel.isEditable.value)

        val info = TunnelInfo(
            assignedIp = "10.0.0.2",
            prefix = 24,
            serverIp = "1.2.3.4",
            serverPrefix = 24,
            mtu = 1400,
        )
        stateFlow.value = MqvpnState.Connected(info)
        advanceUntilIdle()
        assertFalse(viewModel.isEditable.value)

        stateFlow.value = MqvpnState.Error(MqvpnError.Timeout("Connection timeout"))
        advanceUntilIdle()
        assertTrue(viewModel.isEditable.value)
    }

    // -- autosave draft (Task 7) -------------------------------------------

    @Test
    fun `draft initializes from first emission and ignores later echoes`() = runTest(testDispatcher) {
        advanceUntilIdle()
        assertEquals(testSettings, viewModel.draft.value)
        settingsFlow.value = testSettings.copy(serverAddress = "echo.example.com")
        advanceUntilIdle()
        assertEquals(testSettings, viewModel.draft.value)
    }

    @Test
    fun `update while connected changes neither draft nor storage`() = runTest(testDispatcher) {
        advanceUntilIdle()
        val before = viewModel.draft.value
        stateFlow.value = MqvpnState.Connected(mockk(relaxed = true))
        advanceUntilIdle()
        viewModel.update { it.copy(killSwitch = !it.killSwitch) }
        advanceUntilIdle()
        assertEquals(before, viewModel.draft.value)
        coVerify(exactly = 0) { mockRepository.save(any()) }
    }

    @Test
    fun `legacy combo survives an unrelated update byte-identically`() = runTest(testDispatcher) {
        val legacy = testSettings.copy(scheduler = "WLB", redundantEnabled = true, redundantPorts = "443, 8443")
        val repo = mockk<SettingsRepository>(relaxed = true).also {
            every { it.settings } returns MutableStateFlow(legacy)
            coEvery { it.save(any()) } returns Unit
        }
        val vm = SettingsViewModel(repo, mockManager, SavedStateHandle())
        advanceUntilIdle()
        vm.update { it.copy(killSwitch = true) }
        advanceUntilIdle()
        coVerify(exactly = 1) { repo.save(legacy.copy(killSwitch = true)) }
    }

    @Test
    fun `second update while the first save is suspended is not lost`() = runTest(testDispatcher) {
        val gate = CompletableDeferred<Unit>()
        val saved = mutableListOf<DemoSettings>()
        coEvery { mockRepository.save(any()) } coAnswers {
            saved += firstArg<DemoSettings>()
            if (saved.size == 1) gate.await()
        }
        advanceUntilIdle()
        viewModel.update { it.copy(killSwitch = true) }
        advanceUntilIdle()
        viewModel.update { it.copy(insecure = true) }
        advanceUntilIdle()
        gate.complete(Unit)
        advanceUntilIdle()
        assertEquals(testSettings.copy(killSwitch = true, insecure = true), saved.last())
        assertEquals(testSettings.copy(killSwitch = true, insecure = true), viewModel.draft.value)
    }

    @Test
    fun `invalid field blocks every persist until fixed`() = runTest(testDispatcher) {
        advanceUntilIdle()
        viewModel.update { it.copy(redundantEnabled = true, redundantPorts = "abc") }
        viewModel.update { it.copy(killSwitch = true) }
        advanceUntilIdle()
        assertTrue(viewModel.draft.value!!.killSwitch)
        assertTrue(viewModel.fieldErrors.value.containsKey("redundantPorts"))
        coVerify(exactly = 0) { mockRepository.save(any()) }

        viewModel.update { it.copy(redundantPorts = "443") }
        advanceUntilIdle()
        assertTrue(viewModel.fieldErrors.value.isEmpty())
        coVerify(exactly = 1) {
            mockRepository.save(testSettings.copy(redundantEnabled = true, redundantPorts = "443", killSwitch = true))
        }
    }

    @Test
    fun `failed autosave surfaces saveError and keeps the draft`() = runTest(testDispatcher) {
        coEvery { mockRepository.save(any()) } throws IllegalStateException("boom")
        advanceUntilIdle()
        viewModel.update { it.copy(killSwitch = true) }
        advanceUntilIdle()
        assertEquals("Save failed: boom", viewModel.saveError.value)
        assertTrue(viewModel.draft.value!!.killSwitch)
    }

    @Test
    fun `flush suspends until the pending write landed and returns when draft is invalid`() = runTest(testDispatcher) {
        val gate = CompletableDeferred<Unit>()
        coEvery { mockRepository.save(any()) } coAnswers { gate.await() }
        advanceUntilIdle()
        viewModel.update { it.copy(killSwitch = true) }
        var flushed = false
        launch { viewModel.flush(); flushed = true }
        advanceUntilIdle()
        assertFalse(flushed)
        gate.complete(Unit)
        advanceUntilIdle()
        assertTrue(flushed)

        viewModel.update { it.copy(serverAddress = "") }
        viewModel.flush()
        coVerify(exactly = 1) { mockRepository.save(any()) }
    }

    @Test
    fun `unparsable address text keeps the draft and flags invalid`() = runTest(testDispatcher) {
        advanceUntilIdle()
        viewModel.editAddress("vpn.example:abc")
        advanceUntilIdle()

        assertEquals("repo.example.com", viewModel.draft.value?.serverAddress)
        assertEquals(1234, viewModel.draft.value?.serverPort)
        assertEquals("vpn.example:abc", viewModel.addressText.value)
        assertTrue(viewModel.addressTextInvalid.value)
        coVerify(exactly = 0) { mockRepository.save(any()) }
    }

    @Test
    fun `valid address text updates the draft and clears the invalid flag`() = runTest(testDispatcher) {
        advanceUntilIdle()
        viewModel.editAddress("vpn.example:abc")
        viewModel.editAddress("vpn.example.com:8443")
        advanceUntilIdle()

        assertEquals("vpn.example.com", viewModel.draft.value?.serverAddress)
        assertEquals(8443, viewModel.draft.value?.serverPort)
        assertFalse(viewModel.addressTextInvalid.value)
    }

    @Test
    fun `restored unparsable address text re-flags invalid after process recreation`() = runTest(testDispatcher) {
        val restored = SettingsViewModel(
            mockRepository, mockManager, SavedStateHandle(mapOf("address_text" to "vpn.example:abc")),
        )
        advanceUntilIdle()

        assertEquals("vpn.example:abc", restored.addressText.value)
        assertTrue(restored.addressTextInvalid.value)
    }

    @Test
    fun `restored valid address text is replayed onto the loaded draft`() = runTest(testDispatcher) {
        val restored = SettingsViewModel(
            mockRepository, mockManager, SavedStateHandle(mapOf("address_text" to "new.example.com:9000")),
        )
        advanceUntilIdle()

        assertEquals("new.example.com", restored.draft.value?.serverAddress)
        assertEquals(9000, restored.draft.value?.serverPort)
        assertFalse(restored.addressTextInvalid.value)
        coVerify(exactly = 1) {
            mockRepository.save(match { it.serverAddress == "new.example.com" && it.serverPort == 9000 })
        }
    }
}
