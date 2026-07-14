// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Reorder settings sheet. Editable only while disconnected (isEditable); Save
/// requires a savable draft (enable needs >=1 valid port) and no in-flight save.
struct SettingsView: View {
    @ObservedObject var controller: TunnelController
    @Environment(\.dismiss) private var dismiss

    @State private var enabled: Bool
    @State private var profile: Int
    @State private var portsText: String
    @State private var errorText: String?

    init(controller: TunnelController) {
        self.controller = controller
        let s = controller.reorderSettings
        _enabled = State(initialValue: s.enabled)
        _profile = State(initialValue: s.profile)
        _portsText = State(initialValue: s.ports.map(String.init).joined(separator: ","))
    }

    private var draft: ReorderSettings {
        ReorderSettings(enabled: enabled, profile: profile,
                        ports: ReorderSettings.parsePorts(portsText).ports)
    }
    private var warnings: [String] {
        ReorderSettings.parsePorts(portsText).warnings + draft.planReorder().warnings
    }

    var body: some View {
        NavigationView {
            Form {
                Section("Reorder Buffer") {
                    Toggle("Enabled", isOn: $enabled).disabled(!controller.isEditable)
                    if enabled {
                        Picker("Profile", selection: $profile) {
                            Text("CELLULAR BOND").tag(ReorderSettings.profileCellularBond)
                            Text("FIBER LTE").tag(ReorderSettings.profileFiberLTE)
                        }.disabled(!controller.isEditable)
                        TextField("Ports (comma-separated, e.g. 443,5401)", text: $portsText)
                            .keyboardType(.numbersAndPunctuation)
                            .disabled(!controller.isEditable)
                        ForEach(warnings, id: \.self) { w in
                            Text(w).font(.caption).foregroundColor(.orange)
                        }
                        if draft.planReorder().rules.isEmpty {
                            Text("Enable requires at least one valid port.")
                                .font(.caption).foregroundColor(.red)
                        }
                    }
                }
                if let errorText { Section { Text(errorText).foregroundColor(.red) } }
                if !controller.isEditable {
                    Section { Text("Disconnect to edit reorder settings.")
                        .font(.caption).foregroundColor(.secondary) }
                }
            }
            .navigationTitle("Reorder Settings")
            .interactiveDismissDisabled(controller.isSaving)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(controller.isSaving)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { await save() } }
                        .disabled(!draft.isSavable || controller.isSaving || !controller.isEditable)
                }
            }
        }
    }

    private func save() async {
        do { try await controller.saveReorderSettings(draft); dismiss() }
        catch { errorText = "Save failed: \(error)" }
    }
}
