// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// Why a tunnel start attempt failed (spec D6). Equatable compares
/// `.settings` payloads as NSError (domain+code), which is what the host
/// tests need.
enum StartFailure: Equatable {
    case core(Int32)      // tunnel_closed reason from the library
    case local(Int32)     // engine-local failure (client_new / connect)
    case settings(Error)  // setTunnelNetworkSettings error
    case cancelled        // stopTunnel arrived before start resolved

    static func == (l: StartFailure, r: StartFailure) -> Bool {
        switch (l, r) {
        case let (.core(a), .core(b)): return a == b
        case let (.local(a), .local(b)): return a == b
        case let (.settings(a), .settings(b)): return (a as NSError) == (b as NSError)
        case (.cancelled, .cancelled): return true
        default: return false
        }
    }
}

/// Value-type state machine for the tunnel session lifecycle (spec D6).
/// Foundation-only. `Info` is the tunnel-config payload
/// (`mqvpn_tunnel_info_t` in the provider; anything Equatable in tests).
/// The provider is an adapter: it feeds inputs under its lock and executes
/// the returned actions outside it.
struct TunnelSessionCoordinator<Info> {
    enum Phase: Equatable { case starting, established, reasserting, terminal }
    enum Apply { case idle, applying(pending: Info?, stale: Bool) }

    enum Input {
        case configReady(Info)        // tunnel_config_ready (fires per connection)
        case settingsApplied(Error?)  // setTunnelNetworkSettings completion
        case closed(reason: Int32)    // tunnel_closed
        case startFailed(code: Int32) // engine-local failure channel
        case stopRequested            // stopTunnel
    }

    enum Action {
        case applySettings(Info)
        case tunActive
        case resumeStart              // resolve startTunnel + arm readLoop/collectors
        case failStart(StartFailure)  // resolve startTunnel as failed
        case enterReasserting
        case exitReasserting
        case cancelTunnel(StartFailure)
    }

    /// tunnel_closed reasons the session survives (the core reconnects):
    /// MQVPN_ERR_CLOSED (-10) and MQVPN_ERR_PROTOCOL (-6; a disconnect
    /// during a reconnect's CONNECT-IP surfaces as PROTOCOL). Hardcoded —
    /// Shared/ compiles without the C module; T5 pins the values.
    private static var transientReasons: Set<Int32> { [-10, -6] }

    private(set) var phase: Phase = .starting
    private(set) var apply: Apply = .idle

    mutating func handle(_ input: Input) -> [Action] {
        if phase == .terminal { return [] }
        switch input {
        case .configReady(let info):
            switch apply {
            case .idle:
                apply = .applying(pending: nil, stale: false)
                return [.applySettings(info)]
            case .applying(_, let stale):
                // A reconnect completed while an apply is in flight; the new
                // connection's config supersedes any queued one.
                apply = .applying(pending: info, stale: stale)
                return []
            }

        case .settingsApplied(nil):
            switch apply {
            case .idle:
                return []
            case .applying(let pending, true):
                // The connection this apply belonged to is gone: no
                // tunActive, no phase change.
                if let pending {
                    apply = .applying(pending: nil, stale: false)
                    return [.applySettings(pending)]
                }
                apply = .idle
                return []
            case .applying(let pending, false):
                var actions: [Action] = [.tunActive]
                if phase == .starting {
                    phase = .established
                    actions.append(.resumeStart)
                } else if phase == .reasserting {
                    phase = .established
                    actions.append(.exitReasserting)
                }
                if let pending {
                    apply = .applying(pending: nil, stale: false)
                    actions.append(.applySettings(pending))
                } else {
                    apply = .idle
                }
                return actions
            }

        case .settingsApplied(.some(let err)):
            if case .idle = apply { return [] }
            let wasStarting = phase == .starting
            phase = .terminal
            return [wasStarting ? .failStart(.settings(err)) : .cancelTunnel(.settings(err))]

        case .closed(let reason):
            if phase == .starting {
                phase = .terminal
                return [.failStart(.core(reason))]
            }
            if Self.transientReasons.contains(reason) {
                if case .applying = apply {
                    // The in-flight apply belongs to the dead connection.
                    apply = .applying(pending: nil, stale: true)
                }
                let entering = phase == .established
                phase = .reasserting
                return entering ? [.enterReasserting] : []
            }
            // TLS (-4), AUTH (-5), unknown: fail closed (spec D6 — network
            // fetch is disallowed in SystemTrust, so a TLS failure during
            // reasserting is a certificate problem, not a transient).
            phase = .terminal
            return [.cancelTunnel(.core(reason))]

        case .startFailed(let code):
            let wasStarting = phase == .starting
            phase = .terminal
            return [wasStarting ? .failStart(.local(code)) : .cancelTunnel(.local(code))]

        case .stopRequested:
            let wasStarting = phase == .starting
            phase = .terminal
            return wasStarting ? [.failStart(.cancelled)] : []
        }
    }
}

extension TunnelSessionCoordinator.Action: Equatable where Info: Equatable {}
