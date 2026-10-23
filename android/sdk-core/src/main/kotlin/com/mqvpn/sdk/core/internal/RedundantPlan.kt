// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.internal

import com.mqvpn.sdk.core.model.MqvpnConfig

internal data class RedundantPlan(val ports: IntArray)

/** Null when disabled; otherwise the ports in order (empty = all UDP). */
internal fun planRedundant(config: MqvpnConfig): RedundantPlan? =
    if (config.redundantEnabled) RedundantPlan(config.redundantPorts.toIntArray()) else null
