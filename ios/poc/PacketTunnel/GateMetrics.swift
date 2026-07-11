// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import Darwin
import os

private let metricsLog = Logger(subsystem: "mqvpn.poc", category: "metrics")

/// Periodic (10s) memory + path snapshot dump for the M2 gate procedures.
/// Every line starts with the grep-stable "GATE| " prefix the gate scripts
/// key on — do not change it without updating those scripts.
///
/// Collection runs on the tick thread: `MqvpnEngine.state()`/`paths()` are
/// tick-thread-confined per its threading contract, and `PathBinder`'s
/// `currentFds()` reads its tick-thread-confined `slots`. `start()` itself
/// is only ever invoked from inside `engine.perform{}` (see
/// PacketTunnelProvider.startTunnel), so `RunLoop.current` at that call
/// site IS the tick thread's run loop already — adding the repeating Timer
/// there (instead of re-hopping through `engine.perform` on every fire)
/// mirrors MqvpnEngine's own `scheduleTick` pattern and keeps the timer's
/// lifecycle on the same run loop MqvpnEngine already drives.
final class GateMetrics {
    private let engine: MqvpnEngine
    private let binder: PathBinder
    private var timer: Timer?
    private var loggedSockbufs = false

    init(engine: MqvpnEngine, binder: PathBinder) {
        self.engine = engine
        self.binder = binder
    }

    /// MUST be called on the tick thread (inside `engine.perform{}`).
    func start() {
        let t = Timer(timeInterval: 10.0, repeats: true) { [weak self] _ in
            self?.collect()
        }
        RunLoop.current.add(t, forMode: .default)
        timer = t
    }

    /// Runs on the tick thread (fired by the Timer added in start()).
    private func collect() {
        let footprint = Self.physFootprint()
        let avail = os_proc_available_memory()
        // Non-gate anomaly record only — PASS/FAIL never depends on this.
        if avail < 10 * 1024 * 1024 {
            metricsLog.error("GATE| anomaly: os_proc_available_memory=\(avail) below 10MB")
        }
        let state = engine.state()
        var line = "GATE| state=\(state.rawValue) footprint=\(footprint) avail=\(avail)"
        for p in engine.paths() {
            let name = withUnsafeBytes(of: p.name) { raw -> String in
                String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            line += " path[\(name)] st=\(p.status.rawValue) tx=\(p.bytes_tx) rx=\(p.bytes_rx)"
        }
        metricsLog.info("\(line, privacy: .public)")

        // Socket buffer sizes only matter as a one-time check that the
        // PathBinder pre-set (or the core's later request) actually stuck;
        // they do not change meaningfully afterwards, so only the first
        // collection records them.
        guard !loggedSockbufs else { return }
        loggedSockbufs = true
        for (ifname, fd) in binder.currentFds() {
            var sndbuf: Int32 = 0
            var sndlen = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &sndlen)
            var rcvbuf: Int32 = 0
            var rcvlen = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &rcvlen)
            metricsLog.info("GATE| sockbuf[\(ifname, privacy: .public)] sndbuf=\(sndbuf) rcvbuf=\(rcvbuf)")
        }
    }

    /// task_info(TASK_VM_INFO) phys_footprint — the memory gate's metric of
    /// record (NOT resident size / RSS).
    private static func physFootprint() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return 0 }
        return info.phys_footprint
    }
}
