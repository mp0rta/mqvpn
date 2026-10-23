// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.ui.serverSchedulerLine
import com.mqvpn.sdk.core.model.MqvpnConfig.Scheduler
import com.mqvpn.sdk.core.model.TunnelInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SchedulerStatusTest {

    private fun info(server: Scheduler?, requested: Scheduler?) = TunnelInfo(
        assignedIp = "10.0.0.2", prefix = 24, serverIp = "10.0.0.1", serverPrefix = 24, mtu = 1280,
        serverScheduler = server, requestedScheduler = requested,
    )

    @Test
    fun `no server report and no request shows nothing`() {
        assertNull(serverSchedulerLine(info(null, null)))
    }

    @Test
    fun `no server report but a request shows unknown`() {
        assertEquals(
            "Server scheduler: unknown (the server does not report it)",
            serverSchedulerLine(info(null, Scheduler.WLB)),
        )
    }

    @Test
    fun `no request shows the server scheduler`() {
        assertEquals("Server scheduler: minrtt", serverSchedulerLine(info(Scheduler.MIN_RTT, null)))
        assertEquals("Server scheduler: wlb_udp_pin", serverSchedulerLine(info(Scheduler.WLB_UDP_PIN, null)))
    }

    @Test
    fun `request equal to the server scheduler shows it plainly`() {
        assertEquals("Server scheduler: wlb", serverSchedulerLine(info(Scheduler.WLB, Scheduler.WLB)))
    }

    @Test
    fun `server backup_fec with a different request says it cannot be switched`() {
        assertEquals(
            "Server scheduler: backup_fec (your setting wlb is not applied — " +
                "the server's backup_fec cannot be switched)",
            serverSchedulerLine(info(Scheduler.BACKUP_FEC, Scheduler.WLB)),
        )
    }

    @Test
    fun `other mismatch points at AllowClientScheduler`() {
        assertEquals(
            "Server scheduler: minrtt (your setting wlb is not applied — " +
                "check AllowClientScheduler on the server)",
            serverSchedulerLine(info(Scheduler.MIN_RTT, Scheduler.WLB)),
        )
    }
}
