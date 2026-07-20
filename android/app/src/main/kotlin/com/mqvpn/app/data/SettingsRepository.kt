// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.data

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * DataStore-Preferences-backed persistence for [DemoSettings]. Each field
 * maps to its own preference key; a missing key falls back to that field's
 * [DemoSettings] default, so partial or never-written stores still produce a
 * fully-populated model.
 */
@Singleton
class SettingsRepository @Inject constructor(
    private val dataStore: DataStore<Preferences>,
) {
    // Adding a DemoSettings field = key here + read (settings map) + write
    // (save) + round-trip test entry in SettingsRepositoryTest.
    private object Keys {
        val SERVER_ADDRESS = stringPreferencesKey("server_address")
        val SERVER_PORT = intPreferencesKey("server_port")
        val TLS_SERVER_NAME = stringPreferencesKey("tls_server_name")
        val AUTH_KEY = stringPreferencesKey("auth_key")
        val INSECURE = booleanPreferencesKey("insecure")
        val KILL_SWITCH = booleanPreferencesKey("kill_switch")
        val REORDER_ENABLED = booleanPreferencesKey("reorder_enabled")
        val REORDER_PROFILE = stringPreferencesKey("reorder_profile")
        val REORDER_PORTS = stringPreferencesKey("reorder_ports")
        val HYBRID_ENABLED = booleanPreferencesKey("hybrid_enabled")
        val HYBRID_TCP_MODE = stringPreferencesKey("hybrid_tcp_mode")
    }

    val settings: Flow<DemoSettings> = dataStore.data
        .catch { if (it is IOException) emit(emptyPreferences()) else throw it }
        .map { prefs ->
            val defaults = DemoSettings()
            DemoSettings(
                serverAddress = prefs[Keys.SERVER_ADDRESS] ?: defaults.serverAddress,
                serverPort = prefs[Keys.SERVER_PORT] ?: defaults.serverPort,
                tlsServerName = prefs[Keys.TLS_SERVER_NAME] ?: defaults.tlsServerName,
                authKey = prefs[Keys.AUTH_KEY] ?: defaults.authKey,
                insecure = prefs[Keys.INSECURE] ?: defaults.insecure,
                killSwitch = prefs[Keys.KILL_SWITCH] ?: defaults.killSwitch,
                reorderEnabled = prefs[Keys.REORDER_ENABLED] ?: defaults.reorderEnabled,
                reorderProfile = prefs[Keys.REORDER_PROFILE] ?: defaults.reorderProfile,
                reorderPorts = prefs[Keys.REORDER_PORTS] ?: defaults.reorderPorts,
                hybridEnabled = prefs[Keys.HYBRID_ENABLED] ?: defaults.hybridEnabled,
                hybridTcpMode = prefs[Keys.HYBRID_TCP_MODE] ?: defaults.hybridTcpMode,
            )
        }

    suspend fun save(newSettings: DemoSettings) {
        dataStore.edit { prefs ->
            prefs[Keys.SERVER_ADDRESS] = newSettings.serverAddress
            prefs[Keys.SERVER_PORT] = newSettings.serverPort
            prefs[Keys.TLS_SERVER_NAME] = newSettings.tlsServerName
            prefs[Keys.AUTH_KEY] = newSettings.authKey
            prefs[Keys.INSECURE] = newSettings.insecure
            prefs[Keys.KILL_SWITCH] = newSettings.killSwitch
            prefs[Keys.REORDER_ENABLED] = newSettings.reorderEnabled
            prefs[Keys.REORDER_PROFILE] = newSettings.reorderProfile
            prefs[Keys.REORDER_PORTS] = newSettings.reorderPorts
            prefs[Keys.HYBRID_ENABLED] = newSettings.hybridEnabled
            prefs[Keys.HYBRID_TCP_MODE] = newSettings.hybridTcpMode
        }
    }
}
