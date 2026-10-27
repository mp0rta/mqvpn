// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI
import UIKit

/// Text field that commits to the draft on focus loss / submit / disappear only, never per
/// keystroke (no autosave churn, no consent prompt from half-typed input).
struct CommitField: View {
    @Environment(\.mq) private var mq
    let label: String
    var placeholder = ""
    let value: String
    var enabled = true
    var secure = false
    var keyboard: UIKeyboardType = .default
    let commit: (String) -> Void
    @State private var text = ""
    @FocusState private var focused: Bool

    var body: some View {
        Group {
            if secure { SecureField(placeholder, text: $text) } else { TextField(placeholder, text: $text) }
        }
        .focused($focused).accessibilityLabel(label)
        .font(.system(size: 14)).foregroundColor(mq.text)
        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(keyboard)
        .disabled(!enabled).opacity(enabled ? 1 : 0.5)
        .submitLabel(.done)
        .onSubmit(flush)
        .onChange(of: focused) { f in if !f { flush() } }
        .onChange(of: value) { v in if !focused { text = v } }
        .onAppear { text = value }
        .onDisappear(perform: flush)
    }

    private func flush() { if text != value { commit(text) } }
}

/// Labelled box around a field with an optional caption / error line below.
struct FieldBox<Field: View>: View {
    @Environment(\.mq) private var mq
    let label: String
    var note: String? = nil
    var noteIsError = false
    var trailing: AnyView? = nil
    let field: Field
    init(label: String, note: String? = nil, noteIsError: Bool = false, trailing: AnyView? = nil,
         @ViewBuilder field: () -> Field) {
        self.label = label; self.note = note; self.noteIsError = noteIsError
        self.trailing = trailing; self.field = field()
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.system(size: 11)).foregroundColor(mq.t2)
            HStack { field; if let trailing { trailing } }
                .padding(.horizontal, 10).padding(.vertical, 9)
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(noteIsError ? mq.red : mq.fill2, lineWidth: 1))
            if let note {
                Text(note).font(.system(size: 11)).foregroundColor(noteIsError ? mq.red : mq.t2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// Show / Hide button for secret fields.
struct ShowHide: View {
    @Environment(\.mq) private var mq
    @Binding var shown: Bool
    var body: some View {
        Button { shown.toggle() } label: {
            Text(shown ? "Hide" : "Show").font(.system(size: 12)).foregroundColor(mq.accent)
        }.buttonStyle(.plain)
    }
}

extension SettingsCore {
    /// Two-way binding into one draft field; writes go through the autosaving single writer.
    func binding<T>(_ kp: WritableKeyPath<AppDraft, T>) -> Binding<T> {
        Binding(get: { self.draft[keyPath: kp] }, set: { v in self.update { $0[keyPath: kp] = v } })
    }
}

/// Resign the first responder so focus-loss commits run before an action reads the draft.
func endEditing() {
    UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
}

/// Grouped number with thousands separators (Android "%,d").
private let intFormatter: NumberFormatter = {
    let f = NumberFormatter(); f.numberStyle = .decimal; f.locale = Locale(identifier: "en_US")
    return f
}()
func fmtInt<T: BinaryInteger>(_ v: T) -> String {
    intFormatter.string(from: NSNumber(value: Int64(v))) ?? "\(v)"
}

/// Session seconds from provider-clock fields; nil while reconnecting / no data.
@MainActor func elapsedText(_ c: TunnelController, _ vs: VpnViewState) -> String? {
    guard vs == .connected, let s = c.snapshot, let since = s.connectedSince else { return nil }
    return fmtElapsed(Int64(max(0, s.timestamp - since)))
}

@MainActor func viewState(_ c: TunnelController) -> VpnViewState {
    deriveViewState(neStatus: c.status.rawValue, clientState: c.snapshot?.clientState, surfacedError: c.surfacedError)
}

extension TunnelController {
    var draft: AppDraft { settings.draft }

    /// Wi-Fi / Cellular cards from the live snapshot and the newest bandwidth sample.
    func transportCards(available: Set<TransportKind>) -> [PathCard] {
        let paths = (snapshot?.paths ?? []).map { LivePath(iface: $0.name, status: $0.status) }
        return pathCards(paths: paths, available: available, sample: bandwidthHistory.samples.last)
    }
}
