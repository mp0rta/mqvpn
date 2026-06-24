// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.internal

import com.mqvpn.sdk.core.model.MqvpnConfig

internal const val REORDER_PROTO_UDP = 17
internal const val MQVPN_REORDER_MAX_RULES = 16

internal data class ReorderRuleSpec(val proto: Int, val port: Int, val profile: Int)
internal data class ReorderPlan(
    val enabled: Boolean,
    val rules: List<ReorderRuleSpec>,
    val warnings: List<String>,
)

internal fun planReorder(config: MqvpnConfig, maxRules: Int = MQVPN_REORDER_MAX_RULES): ReorderPlan {
    if (!config.reorderEnabled) return ReorderPlan(false, emptyList(), emptyList())
    val warnings = mutableListOf<String>()
    val valid = config.reorderPorts.filter { p ->
        (p in 1..65535).also { if (!it) warnings += "reorder port out of range: $p (ignored)" }
    }.distinct()
    val capped = if (valid.size > maxRules) {
        warnings += "reorder ports exceed $maxRules; dropping ${valid.size - maxRules}"
        valid.take(maxRules)
    } else valid
    if (capped.isEmpty()) {
        warnings += "reorderEnabled=true but no valid reorderPorts; reorder is a no-op"
        return ReorderPlan(false, emptyList(), warnings)
    }
    val profile = config.reorderProfile.native
    return ReorderPlan(true, capped.map { ReorderRuleSpec(REORDER_PROTO_UDP, it, profile) }, warnings)
}
