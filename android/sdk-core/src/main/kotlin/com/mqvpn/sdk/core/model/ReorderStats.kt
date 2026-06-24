// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.model

data class ReorderStats(
    val delivered: Long = 0,
    val gapCount: Long = 0,
    val gapFilled: Long = 0,
    val gapTimeout: Long = 0,
    val ackDemote: Long = 0,
    val bufferedP50Ms: Long = 0,
    val bufferedP99Ms: Long = 0,
)
