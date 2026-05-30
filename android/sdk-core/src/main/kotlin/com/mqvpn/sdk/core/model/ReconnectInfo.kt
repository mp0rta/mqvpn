// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.model

/**
 * Information about a scheduled reconnection attempt.
 */
data class ReconnectInfo(
    val delaySec: Int,
)
