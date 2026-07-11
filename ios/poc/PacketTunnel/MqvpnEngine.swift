// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import os.log

let log = Logger(subsystem: "mqvpn.poc", category: "engine")

/// Owns the libmqvpn client and the dedicated tick thread.
///
/// THREADING CONTRACT: every libmqvpn call happens on `tickThread`. The core
/// asserts pthread identity on entry (first call latches pthread_self, later
/// calls pthread_equal-check it), so a GCD serial queue is NOT sufficient —
/// it guarantees mutual exclusion, not thread affinity. All external events
/// hop in via `perform{}`.
final class MqvpnEngine: NSObject {
    private var client: OpaquePointer?          // mqvpn_client_t*
    private var config: PoCConfig!
    private var connected = false
    private var tickThread: Thread!
    private let runLoopReady = DispatchSemaphore(value: 0)
    private var runLoop: RunLoop!
    private var tickTimer: Timer?

    // Injected by PacketTunnelProvider:
    var onTunOutput: ((Data) -> Void)?          // -> packetFlow.writePackets
    var onTunnelConfig: ((mqvpn_tunnel_info_t) -> Void)?
    var onTunnelClosed: ((Int32) -> Void)?

    /// Blocks until the client exists on the tick thread — callers may start
    /// PathBinder immediately after return without ordering assumptions.
    func start(config: PoCConfig) {
        tickThread = Thread { [weak self] in
            guard let self else { return }
            self.runLoop = RunLoop.current
            // A run loop with no sources exits immediately; NSMachPort keeps
            // it alive so perform{} hops and timers are serviced.
            self.runLoop.add(NSMachPort(), forMode: .default)
            self.runLoopReady.signal()
            while !self.tickThread.isCancelled {
                self.runLoop.run(mode: .default, before: .distantFuture)
            }
        }
        tickThread.name = "mqvpn.tick"
        tickThread.start()
        runLoopReady.wait()
        let ready = DispatchSemaphore(value: 0)
        perform { self.setupClient(config); ready.signal() }
        ready.wait()
    }

    /// Hop an arbitrary closure onto the tick thread (the ONLY entry point).
    /// After shutdown() the thread is gone — late hops (source cancel
    /// handlers, monitor updates) are silently dropped.
    func perform(_ body: @escaping () -> Void) {
        guard let t = tickThread, !t.isFinished, !t.isCancelled else { return }
        let wrapped = BlockOperation(block: body)
        wrapped.perform(#selector(Operation.start), on: t,
                        with: nil, waitUntilDone: false)
    }

    /// Tears the client down (tick thread). client goes nil first so any
    /// already-queued hop on this run-loop pass sees the guard, not a freed
    /// pointer.
    func shutdown() {
        tickTimer?.invalidate()
        if let c = client {
            client = nil
            mqvpn_client_disconnect(c)
            mqvpn_client_destroy(c)
        }
        tickThread.cancel()
    }

    private func setupClient(_ config: PoCConfig) {
        let cfg = mqvpn_config_new()
        mqvpn_config_set_server(cfg, config.serverHost, Int32(config.serverPort))
        mqvpn_config_set_clock(cfg, mqvpn_ios_clock_us, nil)
        if !config.authKey.isEmpty { mqvpn_config_set_auth_key(cfg, config.authKey) }
        if config.tlsInsecure { mqvpn_config_set_insecure(cfg, 1) }
        var cbs = mqvpn_client_callbacks_t()
        cbs.abi_version = UInt32(MQVPN_CALLBACKS_ABI_VERSION)
        cbs.struct_size = UInt32(MemoryLayout<mqvpn_client_callbacks_t>.size)
        cbs.tun_output = { pkt, len, ctx in
            let engine = Unmanaged<MqvpnEngine>.fromOpaque(ctx!).takeUnretainedValue()
            engine.onTunOutput?(Data(bytes: pkt!, count: len))
        }
        cbs.tunnel_config_ready = { info, ctx in
            let engine = Unmanaged<MqvpnEngine>.fromOpaque(ctx!).takeUnretainedValue()
            engine.onTunnelConfig?(info!.pointee)
        }
        cbs.send_packet = nil                    // fd-path mode: core sends via sendto(fd)
        cbs.tunnel_closed = { reason, ctx in
            let engine = Unmanaged<MqvpnEngine>.fromOpaque(ctx!).takeUnretainedValue()
            engine.onTunnelClosed?(reason.rawValue)
        }
        cbs.log = { level, msg, _ in
            // msg is not documented NULL-safe by the header, but the JNI
            // reference driver defensively substitutes "" — mirror that here
            // rather than force-unwrapping into a crash.
            let text = msg.map { String(cString: $0) } ?? ""
            log.notice("[lib] \(text, privacy: .public)")
        }
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        client = mqvpn_client_new(cfg, &cbs, ctx)
        mqvpn_config_free(cfg)
        self.config = config
        // NOTE: no connect here. The core sends handshake packets via
        // sendto() on path fds, and xquic needs the resolved peer address
        // set before connect — so connection start is deferred until the
        // first path fd is registered (connectIfNeeded, same ordering as
        // the Android runtime: addPathFd -> setServerAddr -> connect).
        scheduleTick(afterMs: 0)
    }

    /// Called by PathBinder after the FIRST successful add_path_fd
    /// (tick thread). Sets the resolved server address and connects, once.
    func connectIfNeeded() {
        guard !connected, let c = client else { return }
        connected = true
        var sa = config.serverSockaddr
        withUnsafePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                _ = mqvpn_client_set_server_addr(c, $0,
                        socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        mqvpn_client_connect(c)
        scheduleTick(afterMs: 0)
    }

    /// Called by the provider after NE tunnel settings are applied (hop to
    /// tick thread first). The core gates TUN delivery on tun_active and
    /// this call also drives TUNNEL_READY -> ESTABLISHED; the fd argument
    /// is unused by the core (platform owns all I/O), so pass -1.
    func tunActive() {
        guard let c = client else { return }
        mqvpn_client_set_tun_active(c, 1, -1)
    }

    /// get_interest-driven tick loop, mirroring the Android JNI driver.
    private func scheduleTick(afterMs: Int32) {
        let delay = max(0, Int(afterMs))
        tickTimer?.invalidate()
        let t = Timer(timeInterval: Double(delay) / 1000.0, repeats: false) { [weak self] _ in
            guard let self, let c = self.client else { return }
            mqvpn_client_tick(c)
            var interest = mqvpn_interest_t()
            interest.struct_size = UInt32(MemoryLayout<mqvpn_interest_t>.size)
            mqvpn_client_get_interest(c, &interest)
            self.scheduleTick(afterMs: interest.next_timer_ms)
        }
        runLoop.add(t, forMode: .default)
        tickTimer = t
    }

    // All methods below assume the caller already hopped to the tick thread.
    func feedTunPacket(_ data: Data) {
        guard let c = client else { return }
        _ = data.withUnsafeBytes { buf in
            mqvpn_client_on_tun_packet(c, buf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                       data.count)
        }
        scheduleTick(afterMs: 0)   // input may arm new engine work; tick soon
    }
    /// Registers a path fd. Uses the _with_outcome variant: the legacy
    /// add_path_fd can return a valid handle while a synchronous activation
    /// failure is swallowed — the outcome is what the failover-flap gate
    /// needs to observe.
    func addPathFd(_ fd: Int32, desc: inout mqvpn_path_desc_t)
        -> (handle: mqvpn_path_handle_t, outcome: mqvpn_add_path_outcome_t) {
        var outcome = MQVPN_ADD_PATH_OK
        guard let c = client else { return (-1, outcome) }  // post-shutdown hop
        let h = mqvpn_client_add_path_fd_with_outcome(c, fd, &desc, &outcome)
        return (h, outcome)
    }
    func removePath(_ handle: mqvpn_path_handle_t) {
        guard let c = client else { return }
        mqvpn_client_remove_path(c, handle)
    }
    func fdClosed(_ handle: mqvpn_path_handle_t) {
        guard let c = client else { return }
        mqvpn_client_on_platform_fd_closed(c, handle)
    }
    func socketRecv(_ handle: mqvpn_path_handle_t, _ data: Data,
                    _ peer: UnsafePointer<sockaddr>, _ peerLen: socklen_t) {
        guard let c = client else { return }
        _ = data.withUnsafeBytes { buf in
            mqvpn_client_on_socket_recv(c, handle, buf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                        data.count, peer, peerLen)
        }
        scheduleTick(afterMs: 0)
    }

    // Snapshot accessors for GateMetrics (tick thread only).
    func state() -> mqvpn_client_state_t {
        guard let c = client else { return MQVPN_STATE_CLOSED }
        return mqvpn_client_get_state(c)
    }
    func paths() -> [mqvpn_path_info_t] {
        guard let c = client else { return [] }
        var out = [mqvpn_path_info_t](repeating: mqvpn_path_info_t(),
                                      count: Int(MQVPN_MAX_PATHS))
        var n: Int32 = 0
        // &out is Swift's inout-array-to-pointer bridging (valid for the
        // duration of the call) — matches the C signature exactly.
        mqvpn_client_get_paths(c, &out, Int32(out.count), &n)
        return Array(out.prefix(Int(n)))
    }
}
