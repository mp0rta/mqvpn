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

    @State private var hostText: String
    @State private var portText: String
    @State private var serverNameText: String
    @State private var pskText: String
    @State private var insecure: Bool

    @State private var hybridEnabled: Bool
    @State private var hybridMode: Int

    init(controller: TunnelController) {
        self.controller = controller
        let s = controller.reorderSettings
        _enabled = State(initialValue: s.enabled)
        _profile = State(initialValue: s.profile)
        _portsText = State(initialValue: s.ports.map(String.init).joined(separator: ","))

        let srv = controller.serverSettings ?? (try? ServerSettings.fromBundle()) ?? .emptyDraft
        _hostText = State(initialValue: srv.host)
        _portText = State(initialValue: String(srv.port))
        _serverNameText = State(initialValue: srv.serverName)
        _pskText = State(initialValue: srv.authKey)
        _insecure = State(initialValue: srv.insecure)

        _hybridEnabled = State(initialValue: controller.hybridSettings.enabled)
        _hybridMode = State(initialValue: controller.hybridSettings.tcpMode)
    }

    private var draft: ReorderSettings {
        ReorderSettings(enabled: enabled, profile: profile,
                        ports: ReorderSettings.parsePorts(portsText).ports)
    }
    private var warnings: [String] {
        ReorderSettings.parsePorts(portsText).warnings + draft.planReorder().warnings
    }

    private var parsedPort: Int? { Int(portText.trimmingCharacters(in: .whitespaces)) }
    private var serverDraft: ServerSettings {
        ServerSettings(host: hostText, port: parsedPort ?? -1, serverName: serverNameText,
                       authKey: pskText, insecure: insecure)
    }
    private var serverValid: Bool { serverDraft.isValid }   // reuse the model's rule (host trimmed in init; port -1 when unparseable → false)

    var body: some View {
        NavigationView {
            Form {
                Section("Server") {
                    TextField("Server Host/IP", text: $hostText)
                        .keyboardType(.URL).autocorrectionDisabled().textInputAutocapitalization(.never)
                        .disabled(!controller.isEditable)
                    TextField("Port", text: $portText)
                        .keyboardType(.numberPad).disabled(!controller.isEditable)
                    TextField("TLS Server Name (optional, default: host)", text: $serverNameText)
                        .keyboardType(.URL).autocorrectionDisabled().textInputAutocapitalization(.never)
                        .disabled(!controller.isEditable)
                    SecureField("PSK (Auth Key)", text: $pskText).disabled(!controller.isEditable)
                    Toggle("Insecure (skip TLS verify)", isOn: $insecure).disabled(!controller.isEditable)
                    if !serverValid {
                        Text("Host required; port must be 1–65535.").font(.caption).foregroundColor(.red)
                    }
                }
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
                Section {
                    Toggle("Enabled", isOn: $hybridEnabled).disabled(!controller.isEditable)
                    if hybridEnabled {
                        Picker("TCP Mode", selection: $hybridMode) {
                            Text("Auto").tag(HybridSettings.modeAuto)
                            Text("Stream").tag(HybridSettings.modeStream)
                            Text("Raw").tag(HybridSettings.modeRaw)
                        }.disabled(!controller.isEditable)
                    }
                } header: { Text("Hybrid Mode") } footer: {
                    Text("Requires hybrid support on the server; TCP connections fail otherwise.")
                }
                if let errorText { Section { Text(errorText).foregroundColor(.red) } }
                if !controller.isEditable {
                    Section { Text("Disconnect to edit settings.")
                        .font(.caption).foregroundColor(.secondary) }
                }
            }
            .navigationTitle("Settings")
            .interactiveDismissDisabled(controller.isSaving)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(controller.isSaving)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { await save() } }
                        .disabled(!serverValid || !draft.isSavable || controller.isSaving || !controller.isEditable)
                }
            }
        }
    }

    private func save() async {
        let hybrid = HybridSettings(enabled: hybridEnabled, tcpMode: hybridMode)
        do { try await controller.saveSettings(server: serverDraft, reorder: draft, hybrid: hybrid); dismiss() }
        catch { errorText = "Save failed: \(error)" }
    }
}
