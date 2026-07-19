// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.data.SettingsRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class SettingsRepositoryTest {

    @get:Rule
    val tmpFolder = TemporaryFolder()

    private val testDispatcher = StandardTestDispatcher()
    private val storeScope = CoroutineScope(testDispatcher + Job())

    @After
    fun tearDown() {
        storeScope.cancel()
    }

    private fun newFile(): File = File(tmpFolder.root, "test-${System.nanoTime()}.preferences_pb")

    private fun newDataStore(
        file: File,
        corruptionHandler: ReplaceFileCorruptionHandler<Preferences>? = null,
    ): DataStore<Preferences> =
        PreferenceDataStoreFactory.create(
            corruptionHandler = corruptionHandler,
            scope = storeScope,
            produceFile = { file },
        )

    @Test
    fun `fresh store yields defaults`() = runTest(testDispatcher) {
        val repo = SettingsRepository(newDataStore(newFile()))
        assertEquals(DemoSettings(), repo.settings.first())
    }

    @Test
    fun `save round-trips every field`() = runTest(testDispatcher) {
        val repo = SettingsRepository(newDataStore(newFile()))
        val nonDefault = DemoSettings(
            serverAddress = "203.0.113.5",
            serverPort = 8443,
            tlsServerName = "vpn.example.com",
            authKey = "another-key",
            insecure = false,
            killSwitch = true,
            reorderEnabled = true,
            reorderProfile = "FIBER_LTE",
            reorderPorts = "443,8443",
            hybridEnabled = true,
            hybridTcpMode = "RAW",
        )

        repo.save(nonDefault)

        assertEquals(nonDefault, repo.settings.first())
    }

    @Test
    fun `partial store defaults missing fields`() = runTest(testDispatcher) {
        val file = newFile()
        val store = newDataStore(file)
        store.edit { prefs ->
            prefs[stringPreferencesKey("server_address")] = "198.51.100.9"
            prefs[intPreferencesKey("server_port")] = 51820
        }

        val repo = SettingsRepository(store)
        val result = repo.settings.first()

        val expected = DemoSettings(serverAddress = "198.51.100.9", serverPort = 51820)
        assertEquals(expected, result)
    }

    @Test
    fun `corrupt store emits defaults`() = runTest(testDispatcher) {
        val file = newFile()
        file.writeBytes(byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x42, 0x13, 0x37))

        val repo = SettingsRepository(newDataStore(file))

        assertEquals(DemoSettings(), repo.settings.first())
    }

    @Test
    fun `save self-heals a corrupt store when a corruption handler is installed`() = runTest(testDispatcher) {
        val file = newFile()
        file.writeBytes(byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x42, 0x13, 0x37))

        val store = newDataStore(file, ReplaceFileCorruptionHandler { emptyPreferences() })
        val repo = SettingsRepository(store)

        val nonDefault = DemoSettings(
            serverAddress = "203.0.113.5",
            serverPort = 8443,
            tlsServerName = "vpn.example.com",
            authKey = "another-key",
            insecure = false,
            killSwitch = true,
            reorderEnabled = true,
            reorderProfile = "FIBER_LTE",
            reorderPorts = "443,8443",
            hybridEnabled = true,
            hybridTcpMode = "RAW",
        )

        repo.save(nonDefault)

        assertEquals(nonDefault, repo.settings.first())
    }
}
