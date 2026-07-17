// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import Network

/// Owns path sockets and their lifecycle. One instance per tunnel session.
/// Mobile path model: add + remove only (no drop/reactivate — those are the
/// desktop lifecycle). `slots` is confined to the tick thread: every mutation
/// AND read happens inside `engine.perform{}`. DispatchSource handlers never
/// touch it — they capture their own fd/handle at creation time.
final class PathBinder {
    private struct PathSlot {
        var handle: mqvpn_path_handle_t
        var fd: Int32
        var source: DispatchSourceRead
        var ifname: String
    }
    private let engine: MqvpnEngine
    private var slots: [NWInterface.InterfaceType: PathSlot] = [:]  // tick-thread confined
    private var monitors: [NWInterface.InterfaceType: NWPathMonitor] = [:]
    private var pollTimer: Timer?   // tick-thread confined
    private let monitorQueue = DispatchQueue(label: "mqvpn.poc.pathmon")

    init(engine: MqvpnEngine) { self.engine = engine }

    func start() {
        // One monitor per interface type: a single default NWPathMonitor only
        // reports the preferred path, so WiFi+cellular can never be held
        // simultaneously with it.
        //
        // The persistent monitors are TRIGGERS, not state sources. Their
        // update deliveries have been observed to stall for minutes inside
        // an NE provider (a WiFi-off unsatisfied arrived ~110 s late on
        // device), and a stalled monitor's currentPath is equally stale —
        // it only advances when a delivery lands. So every trigger funnels
        // into reconcile(), which probes FRESH state instead of trusting
        // the delivered snapshot.
        // Two passes: store every monitor in the dict BEFORE starting any.
        // A handler can fire the instant its monitor starts and hop
        // reconcile() onto the tick thread, which reads `monitors` — the
        // dict must not be concurrently mutated by this loop at that point.
        for type in [NWInterface.InterfaceType.wifi, .cellular] {
            let m = NWPathMonitor(requiredInterfaceType: type)
            m.pathUpdateHandler = { [weak self] _ in
                guard let self else { return }
                self.engine.perform { self.reconcile() }
            }
            monitors[type] = m
        }
        for (_, m) in monitors { m.start(queue: monitorQueue) }
        // Poll as the third trigger channel. Device measurement showed BOTH
        // event channels silent on a WiFi-off (monitor delivery stalled;
        // defaultPath unchanged because the tunnel stayed up via cellular),
        // leaving the dead path to server-side timeout. Probes read fresh
        // daemon state, so a 1 s cadence bounds off-detection at ~1-2 s
        // regardless of delivery stalls. Timer lives on the tick thread's
        // run loop (same pattern as the metrics collector).
        engine.perform { [weak self] in
            let t = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
                self?.reconcile()
            }
            RunLoop.current.add(t, forMode: .default)
            self?.pollTimer = t
        }
    }

    /// Re-derive add/remove state for the managed interface types, WiFi
    /// strictly before cellular: probes resolve asynchronously, so the
    /// cellular probe only starts after the WiFi result was applied. This
    /// keeps the first registration (and therefore the QUIC primary path)
    /// deterministically on WiFi at session start. Called on the tick
    /// thread from three trigger channels: persistent monitor deliveries,
    /// the provider's NEProvider.defaultPath KVO, and the 1 s poll timer.
    /// Overlapping triggers are safe: results funnel into
    /// addPath/removePath, whose guards make repeats no-ops.
    func reconcile() {
        guard monitors[.wifi] != nil else { return }   // after stop(): no-op
        probe(.wifi) { [weak self] in
            self?.probe(.cellular, then: nil)
        }
    }

    /// One-shot fresh path lookup. A NEW NWPathMonitor registration always
    /// receives an initial update reflecting current daemon state on start,
    /// independent of any stalled long-lived monitor — that first delivery
    /// is taken as the truth, then the probe is cancelled. The probe object
    /// is kept alive by its own handler's capture until it fires.
    /// `then` runs on the tick thread after the result (or timeout) was
    /// applied.
    private func probe(_ type: NWInterface.InterfaceType,
                       then: (() -> Void)?) {
        let p = NWPathMonitor(requiredInterfaceType: type)
        var fired = false   // monitorQueue-confined (handler queue)
        p.pathUpdateHandler = { [weak self] path in
            guard !fired else { return }
            fired = true
            p.cancel()
            // Break the wrapper<->handler retain cycle: cancel() alone does
            // not release the stored Swift closure that keeps `p` alive.
            p.pathUpdateHandler = nil
            guard let self else { return }
            let iface = path.availableInterfaces.first { $0.type == type }
            self.engine.perform {   // hop to tick thread
                if path.status == .satisfied, let iface {
                    self.addPath(type: type, iface: iface)
                } else {
                    self.removePath(type: type)
                }
                then?()
            }
        }
        p.start(queue: monitorQueue)
        // The initial delivery is documented behavior but this file exists
        // because path-daemon deliveries can stall inside an NE provider —
        // bound the probe's lifetime; the next trigger simply re-probes.
        monitorQueue.asyncAfter(deadline: .now() + 3.0) { [weak self] in
            guard !fired else { return }
            fired = true
            p.cancel()
            p.pathUpdateHandler = nil
            if let self, let then { self.engine.perform { then() } }
        }
    }

    /// Socket preparation + registration. Runs on the tick thread.
    private func addPath(type: NWInterface.InterfaceType, iface: NWInterface) {
        guard slots[type] == nil else { return }   // already bound
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { log.error("socket() errno=\(errno)"); return }
        // 1. non-blocking (Darwin Swift imports fcntl with 3 args)
        let fl = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, fl | O_NONBLOCK)
        // 2. Pre-set socket buffers. Darwin REJECTS oversize SO_SNDBUF/RCVBUF
        //    with ENOBUFS and keeps the previous value (no clamping like
        //    Linux); the core later requests 7 MiB ignoring the result, so
        //    this pre-set is what actually survives if that request fails.
        var buf: Int32 = 1 << 20
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, socklen_t(MemoryLayout<Int32>.size))
        // 3. MANDATORY interface bind. Once the tunnel installs the default
        //    route, an unbound provider socket would route into the tunnel
        //    itself (self-capture) — binding is an invariant, not an option.
        var idx = UInt32(iface.index)
        guard setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx,
                         socklen_t(MemoryLayout<UInt32>.size)) == 0 else {
            log.error("IP_BOUND_IF(\(iface.name, privacy: .public)) errno=\(errno)")
            close(fd); return
        }
        // 4. bind(port 0) → 5. getsockname() → local addr into the descriptor
        var any = sockaddr_in()
        any.sin_family = sa_family_t(AF_INET)
        let rc = withUnsafePointer(to: &any) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else { log.error("bind errno=\(errno)"); close(fd); return }
        var desc = mqvpn_path_desc_t()
        desc.struct_size = UInt32(MemoryLayout<mqvpn_path_desc_t>.size)
        desc.fd = fd
        withUnsafeMutableBytes(of: &desc.iface) { dst in
            iface.name.utf8CString.withUnsafeBytes { src in
                dst.copyBytes(from: src.prefix(dst.count - 1))
            }
        }
        var lalen = socklen_t(128)
        withUnsafeMutableBytes(of: &desc.local_addr) { la in
            _ = getsockname(fd, la.baseAddress!.assumingMemoryBound(to: sockaddr.self), &lalen)
        }
        desc.local_addr_len = UInt32(lalen)
        // 6. register with the engine (we are on the tick thread already)
        let (handle, outcome) = engine.addPathFd(fd, desc: &desc)
        guard handle >= 0 else {
            // Registration refused (handle slot unavailable; outcome is NOT
            // written in this case). Surface it — this is exactly what the
            // failover-flap gate measures — and release the fd without any
            // engine calls.
            log.error("add_path_fd failed iface=\(iface.name, privacy: .public) handle=\(handle)")
            close(fd)
            return
        }
        log.notice("add_path outcome=\(outcome.rawValue) iface=\(iface.name, privacy: .public)")
        // First successful path unlocks the connection (server addr + connect).
        engine.connectIfNeeded()
        // 7. Read source AFTER successful registration; the handler captures
        //    fd/handle (immutable). Datagrams arriving between add and resume
        //    just wait in the socket buffer.
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: monitorQueue)
        source.setEventHandler { [weak self] in
            self?.drainSocket(fd: fd, handle: handle)
        }
        source.setCancelHandler { [weak self] in
            // close(fd) must happen HERE: cancelling and closing synchronously
            // races an in-flight read handler against fd reuse (the classic
            // DispatchSource bug). After the close, hop to the tick thread to
            // report fd closure so the core can finish the slot's cleanup.
            close(fd)
            self?.engine.perform { self?.engine.fdClosed(handle) }
        }
        source.resume()
        slots[type] = PathSlot(handle: handle, fd: fd, source: source, ifname: iface.name)
        log.notice("path added type=\(String(describing: type), privacy: .public) fd=\(fd) handle=\(handle)")
    }

    /// Failover teardown. Runs on the tick thread.
    /// Order: orderly engine removal first, then cancel (whose handler closes
    /// the fd and reports fd-closed back on the tick thread).
    private func removePath(type: NWInterface.InterfaceType) {
        guard let slot = slots.removeValue(forKey: type) else { return }
        engine.removePath(slot.handle)
        slot.source.cancel()
        log.notice("path removed type=\(String(describing: type), privacy: .public) handle=\(slot.handle)")
    }

    /// Full teardown for stopTunnel. Runs on the tick thread. Mirrors
    /// removePath(type:) for every live slot, then cancels the monitors
    /// themselves (start() is the only other writer of `monitors`, on the
    /// caller's thread, so this is safe without extra synchronization).
    func stop() {
        pollTimer?.invalidate()
        pollTimer = nil
        for type in Array(slots.keys) {
            removePath(type: type)
        }
        for (_, m) in monitors { m.cancel() }
        monitors.removeAll()
    }

    /// Current (ifname, fd) per live slot, for GateMetrics' getsockopt
    /// snapshot. Tick-thread only, like all other `slots` access.
    func currentFds() -> [(String, Int32)] {
        slots.values.map { ($0.ifname, $0.fd) }
    }

    /// Drain readable datagrams; runs on monitorQueue, hops each datagram to
    /// the tick thread. Uses only its captured fd/handle — no shared state.
    private func drainSocket(fd: Int32, handle: mqvpn_path_handle_t) {
        var buf = [UInt8](repeating: 0, count: 65535)
        while true {
            var storage = sockaddr_storage()
            var slen = socklen_t(MemoryLayout<sockaddr_storage>.size)  // reset per datagram
            let n = withUnsafeMutablePointer(to: &storage) { sp in
                sp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    recvfrom(fd, &buf, buf.count, 0, sa, &slen)
                }
            }
            if n <= 0 { break }  // EAGAIN → drained
            let data = Data(buf[0..<n])
            var peer = storage
            engine.perform {
                withUnsafePointer(to: &peer) { sp in
                    sp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        self.engine.socketRecv(handle, data, sa, slen)
                    }
                }
            }
        }
    }
}
