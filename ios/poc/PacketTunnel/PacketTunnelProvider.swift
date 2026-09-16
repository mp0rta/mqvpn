// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private typealias Coordinator = TunnelSessionCoordinator<mqvpn_tunnel_info_t>

    // Lifecycle state machine + its lock (spec D6/D8). Inputs enter the
    // coordinator under `lock`; returned actions run outside it. The same
    // lock covers `published` and the continuation so the terminal check
    // and the registration are one critical section.
    private let lock = NSLock()
    private var coordinator = Coordinator()
    private var published = false
    private var startContinuation: CheckedContinuation<Void, Error>?

    // Session objects. Created as locals in startTunnel (D6 rule 4) and
    // published under `lock` only after engine.start()/binder.start()
    // returned with the coordinator still non-terminal. Published once and
    // never nil-ed again: handleAppMessage reads `snapshot` from an
    // arbitrary NE thread without the lock, so a nil-out on stop would be
    // a use-after-free race, and a reader overlapping the publish just
    // sees nil ("no data").
    private var engine: MqvpnEngine?
    private var binder: PathBinder?
    private var metrics: GateMetrics?
    private var snapshot: SnapshotCache?
    private var defaultPathObservation: NSKeyValueObservation?

    // Written once before the continuation closure runs; read by every
    // applySettings (reconnects included). Independent of the publish gate.
    private var resolvedIP = ""

    override func startTunnel(options: [String: NSObject]?) async throws {
        let providerConfig = (self.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration
        guard let server = ServerSettings(providerConfiguration: providerConfig) else {
            throw NSError(domain: "mqvpn.poc", code: 10,
                          userInfo: [NSLocalizedDescriptionKey: "server not configured"])
        }
        let reorder = ReorderSettings(providerConfiguration: providerConfig) ?? .disabled
        let hybrid = HybridSettings(providerConfiguration: providerConfig) ?? .disabled
        guard let resolved = await Task.detached(priority: .userInitiated, operation: {
            resolveServer(server.host, server.port)
        }).value, let resolvedIP = resolved.ipString else {
            throw NSError(domain: "mqvpn.poc", code: 11,
                          userInfo: [NSLocalizedDescriptionKey: "server unresolved: \(server.host)"])
        }
        self.resolvedIP = resolvedIP
        return try await withCheckedThrowingContinuation { cont in
            // (1) Terminal check + continuation registration, one critical
            // section (D8): a stopRequested that already ran turned the
            // coordinator terminal (seen here — resume and bail); one that
            // runs later resumes the registered continuation through
            // failStart(.cancelled).
            lock.lock()
            if coordinator.phase == .terminal {
                lock.unlock()
                cont.resume(throwing: CancellationError())
                return
            }
            startContinuation = cont
            lock.unlock()

            // (2) Locals, not properties (D6 rule 4): nothing below reads
            // self.engine & co. until the publish in (3).
            let engine = MqvpnEngine()
            let binder = PathBinder(engine: engine)
            let metrics = GateMetrics(engine: engine, binder: binder)
            let snapshot = SnapshotCache(engine: engine)

            engine.onTunOutput = { [weak self] data in
                // NEPacketTunnelFlow requires a protocol family per packet;
                // the library hands us raw IP bytes, so derive it from the
                // version nibble.
                let proto: NSNumber = (data.first ?? 0) >> 4 == 6 ? NSNumber(value: AF_INET6)
                                                                  : NSNumber(value: AF_INET)
                self?.packetFlow.writePackets([data], withProtocols: [proto])
            }
            engine.onTunnelConfig = { [weak self] info in
                self?.feed(.configReady(info), engine: engine,
                           metrics: metrics, snapshot: snapshot)
            }
            engine.onTunnelClosed = { [weak self] reason in
                self?.feed(.closed(reason: reason), engine: engine,
                           metrics: metrics, snapshot: snapshot)
            }
            engine.onStartFailed = { [weak self] code in
                self?.feed(.startFailed(code: code), engine: engine,
                           metrics: metrics, snapshot: snapshot)
            }
            // Redundant trigger for path lifecycle: NWPathMonitor updates
            // have been observed to arrive minutes late inside the provider;
            // NEProvider.defaultPath is an independent KVO channel. Only the
            // TRIGGER is independent — the binder probes fresh state itself.
            let observation = observe(\.defaultPath) { [weak self] _, _ in
                guard self != nil else { return }
                engine.perform { binder.reconcile() }
            }
            engine.start(server: server, reorder: reorder, hybrid: hybrid,
                         serverAddr: resolved)
            binder.start()

            // (3) Publish, or fold the locals if a stop or failure already
            // turned the coordinator terminal (D8). Every input that leaves
            // .starting emits failStart, so the continuation is resolved on
            // both branches. The fold runs on the tick thread (alive:
            // engine.start() returned) and is best-effort: no STOP markers,
            // no waiting — NE may kill the process before it finishes.
            lock.lock()
            if coordinator.phase == .terminal {
                lock.unlock()
                engine.perform {
                    TeardownSequence.run(
                        detach: {
                            engine.onTunnelClosed = nil
                            engine.onTunnelConfig = nil
                            engine.onTunOutput = nil
                            engine.onStartFailed = nil
                            observation.invalidate()
                        },
                        disconnect: { engine.disconnect() },
                        resolveStart: {},
                        stopPaths: { done in binder.stop(completion: done) },
                        destroy: { engine.destroy() },
                        complete: {})
                }
                return
            }
            self.engine = engine
            self.binder = binder
            self.metrics = metrics
            self.snapshot = snapshot
            self.defaultPathObservation = observation
            published = true
            lock.unlock()
        }
    }

    /// Adapter entry (D6 rule 1): input under the lock, actions outside it.
    /// The session objects arrive as parameters so pre-publish closures
    /// never read the nil properties (D6 rule 4).
    private func feed(_ input: Coordinator.Input, engine: MqvpnEngine?,
                      metrics: GateMetrics?, snapshot: SnapshotCache?) {
        lock.lock()
        let actions = coordinator.handle(input)
        lock.unlock()
        for action in actions {
            run(action, engine: engine, metrics: metrics, snapshot: snapshot)
        }
    }

    /// Actions run on the thread that fed the input (D6 rule 2); the ones
    /// that touch the engine are only emitted for settingsApplied, whose
    /// completion hops through engine.perform first.
    private func run(_ action: Coordinator.Action, engine: MqvpnEngine?,
                     metrics: GateMetrics?, snapshot: SnapshotCache?) {
        switch action {
        case .applySettings(let info):
            // tunnelRemoteAddress must be an IP literal (NE rejects
            // hostnames); the engine/TLS side still gets server.host/SNI.
            let settings = Self.makeSettings(from: info, server: resolvedIP)
            setTunnelNetworkSettings(settings) { [weak self] err in
                engine?.perform {
                    self?.feed(.settingsApplied(err), engine: engine,
                               metrics: metrics, snapshot: snapshot)
                }
            }
        case .tunActive:
            engine?.tunActive()   // opens TUN + drives state 3->4
        case .resumeStart:
            // Tick thread. Only this action arms the read loop and the
            // collectors — exitReasserting must not double-arm (D6 rule 3).
            takeContinuation()?.resume()
            if let engine { readLoop(engine) }
            metrics?.start()      // 10s cadence os_log dumps
            snapshot?.start()     // 1s cadence app-facing cache
        case .failStart(let failure):
            takeContinuation()?.resume(throwing: Self.error(from: failure))
        case .enterReasserting:
            reasserting = true
        case .exitReasserting:
            reasserting = false
        case .cancelTunnel(let failure):
            cancelTunnelWithError(Self.error(from: failure))
        }
    }

    /// Resume-once: the continuation leaves under the same lock the
    /// coordinator runs under, so failStart/resumeStart can never both get
    /// it. nil (already taken, or stop resolved it via (1)) is a no-op.
    private func takeContinuation() -> CheckedContinuation<Void, Error>? {
        lock.lock()
        defer { lock.unlock() }
        let c = startContinuation
        startContinuation = nil
        return c
    }

    private static func error(from failure: StartFailure) -> Error {
        switch failure {
        case .core(let code):
            // -4 == MQVPN_ERR_TLS: name it so the dashboard's failure line
            // is recognizably TLS (gate G-t1).
            let msg = code == -4 ? "TLS certificate rejected" : "tunnel closed"
            return NSError(domain: "mqvpn.poc", code: Int(code),
                           userInfo: [NSLocalizedDescriptionKey: msg])
        case .local(let code):
            return NSError(domain: "mqvpn.poc", code: Int(code),
                           userInfo: [NSLocalizedDescriptionKey: "engine start failed"])
        case .settings(let err):
            return err
        case .cancelled:
            return CancellationError()
        }
    }

    private func readLoop(_ engine: MqvpnEngine) {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            engine.perform {
                for p in packets { engine.feedTunPacket(p) }
            }
            self.readLoop(engine)   // MUST re-arm: readPackets delivers once
        }
    }

    static func makeSettings(from info: mqvpn_tunnel_info_t,
                             server: String) -> NEPacketTunnelNetworkSettings {
        func ip4(_ b: (UInt8, UInt8, UInt8, UInt8)) -> String {
            "\(b.0).\(b.1).\(b.2).\(b.3)"
        }
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: server)
        let v4 = NEIPv4Settings(
            addresses: [ip4(info.assigned_ip)],
            subnetMasks: [Self.prefixToMask(info.assigned_prefix)])
        v4.includedRoutes = [NEIPv4Route.default()]
        s.ipv4Settings = v4
        s.mtu = NSNumber(value: info.mtu)
        // The tunnel protocol does not carry DNS servers; like the Android
        // client (which takes DNS from app-side config), the platform layer
        // must supply resolvers. Without dnsSettings the phone keeps sending
        // queries to its WiFi LAN resolver, which the full-tunnel default
        // route captures and the server NATs to an unroutable private
        // address — name resolution dies and every app looks offline.
        s.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        // IPv6 (info.has_v6 / assigned_ip6 / assigned_prefix6) is out of PoC
        // scope: the PoC server config assigns IPv4 only.
        return s
    }

    static func prefixToMask(_ prefix: UInt8) -> String {
        let m: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - UInt32(prefix))
        return "\((m >> 24) & 255).\((m >> 16) & 255).\((m >> 8) & 255).\(m & 255)"
    }

    /// Command-agnostic snapshot request (future commands are YAGNI): any
    /// message returns the latest cached snapshot. Runs on an arbitrary NE
    /// thread, so it MUST NOT touch the engine (its accessors are
    /// tick-thread-confined) — it only reads the lock-guarded cache and
    /// serializes. A missing cache or encode failure yields nil, which the
    /// app renders as "no data".
    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        guard let snap = snapshot?.read(),
              let data = try? ProviderMessage.encode(snap) else {
            completionHandler?(nil)
            return
        }
        completionHandler?(data)
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        log.notice("GATE| STOP_BEGIN")
        lock.lock()
        guard published else {
            // Pre-publish stop: there is nothing to tear down here —
            // startTunnel's (3) folds its locals when it sees the terminal
            // phase. stopRequested resolves a registered continuation via
            // failStart(.cancelled); an unregistered one is resumed by (1).
            let actions = coordinator.handle(.stopRequested)
            lock.unlock()
            for action in actions {
                run(action, engine: nil, metrics: nil, snapshot: nil)
            }
            log.notice("GATE| STOP_FINISHED")
            return
        }
        lock.unlock()
        guard let engine, let binder else { return }   // published ⇒ non-nil
        await withCheckedContinuation { cont in
            engine.perform { [weak self] in
                TeardownSequence.run(
                    detach: {
                        // Callbacks off first: disconnect fires tunnel_closed
                        // synchronously and must not re-enter the adapter.
                        engine.onTunnelClosed = nil
                        engine.onTunnelConfig = nil
                        engine.onTunOutput = nil
                        engine.onStartFailed = nil
                        self?.defaultPathObservation?.invalidate()
                    },
                    disconnect: { engine.disconnect() },
                    resolveStart: {
                        // After the CONNECTION_CLOSE went out (D8 step 3):
                        // resolves a still-pending start; a post-start stop
                        // is a silent terminal transition.
                        self?.feed(.stopRequested, engine: engine,
                                   metrics: nil, snapshot: nil)
                    },
                    stopPaths: { done in
                        binder.stop(completion: done)
                        log.notice("GATE| STOP_DISPATCHED")
                    },
                    destroy: { engine.destroy() },
                    complete: {
                        log.notice("GATE| STOP_FINISHED")
                        cont.resume()
                    })
            }
        }
    }
}
