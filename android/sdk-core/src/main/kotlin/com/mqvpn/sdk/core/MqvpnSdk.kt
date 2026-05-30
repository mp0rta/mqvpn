// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.native_.NativeBridge

/**
 * Static utility methods for the mqvpn SDK.
 */
object MqvpnSdk {
    /** Get libmqvpn version string. */
    fun getVersion(): String = NativeBridge.versionString()

    /** Generate a random PSK key. */
    fun generateKey(): String = NativeBridge.generateKey() ?: ""
}
