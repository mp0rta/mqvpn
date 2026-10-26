// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Thin ObservableObject adapter over SettingsCore: forwarding only.
@MainActor
final class SettingsModel: ObservableObject {
    let core: SettingsCore

    init(core: SettingsCore) {
        self.core = core
        let prev = core.onChange        // keep the owner's hook (TunnelController)
        core.onChange = { [weak self] in prev(); self?.objectWillChange.send() }
    }

    var draft: AppDraft { core.draft }
    var fieldErrors: [String: String] { core.fieldErrors }
    var saveError: String? { core.saveError }
    var lastPersisted: AppDraft? { core.lastPersisted }
    func update(_ transform: (inout AppDraft) -> Void) { core.update(transform) }
    func commitFirst() async -> Bool { await core.commitFirst() }
    func flush() async -> Bool { await core.flush() }
}
