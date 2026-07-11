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
    private let monitorQueue = DispatchQueue(label: "mqvpn.poc.pathmon")

    init(engine: MqvpnEngine) { self.engine = engine }

    func start() {
        // One monitor per interface type: a single default NWPathMonitor only
        // reports the preferred path, so WiFi+cellular can never be held
        // simultaneously with it.
        for type in [NWInterface.InterfaceType.wifi, .cellular] {
            let m = NWPathMonitor(requiredInterfaceType: type)
            m.pathUpdateHandler = { [weak self] path in
                guard let self else { return }
                let iface = path.availableInterfaces.first { $0.type == type }
                self.engine.perform {   // hop to tick thread
                    if path.status == .satisfied, let iface {
                        self.addPath(type: type, iface: iface)
                    } else {
                        self.removePath(type: type)
                    }
                }
            }
            m.start(queue: monitorQueue)
            monitors[type] = m
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
        log.info("add_path outcome=\(outcome.rawValue) iface=\(iface.name, privacy: .public)")
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
        log.info("path added type=\(String(describing: type), privacy: .public) fd=\(fd) handle=\(handle)")
    }

    /// Failover teardown. Runs on the tick thread.
    /// Order: orderly engine removal first, then cancel (whose handler closes
    /// the fd and reports fd-closed back on the tick thread).
    private func removePath(type: NWInterface.InterfaceType) {
        guard let slot = slots.removeValue(forKey: type) else { return }
        engine.removePath(slot.handle)
        slot.source.cancel()
        log.info("path removed type=\(String(describing: type), privacy: .public) handle=\(slot.handle)")
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
