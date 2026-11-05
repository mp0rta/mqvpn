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
    /// Every keystroke, for a caller that must read the text before focus loss commits it.
    var onType: ((String) -> Void)? = nil
    let commit: (String) -> Void
    @State private var text = ""
    @FocusState private var focused: Bool

    var body: some View {
        Group {
            if secure { SecureField(placeholder, text: $text) } else { TextField(placeholder, text: $text) }
        }
        .focused($focused).accessibilityLabel(label)
        .mqFont(14).foregroundColor(mq.text)
        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(keyboard)
        .disabled(!enabled).opacity(enabled ? 1 : 0.5)
        .submitLabel(.done)
        .onSubmit(flush)
        .onChange(of: focused) { f in if !f { flush() } }
        .onChange(of: text) { onType?($0) }
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
            Text(label).mqFont(11).foregroundColor(mq.t2)
            HStack { field; if let trailing { trailing } }
                .padding(.horizontal, 10).padding(.vertical, 9)
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(noteIsError ? mq.red : mq.fill2, lineWidth: 1))
            if let note {
                Text(note).mqFont(11).foregroundColor(noteIsError ? mq.red : mq.t2)
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
            Text(shown ? "Hide" : "Show").mqFont(12).foregroundColor(mq.accent)
        }.buttonStyle(.plain)
    }
}

/// What a settings form reads, and its one way to edit: a value built per
/// render by the tab container, so forms take no controller and preview with a
/// plain draft.
struct SettingsForm {
    var draft: AppDraft
    var errors: [AppDraft.Field: String] = [:]
    var saveError: String?
    var editable = true
    /// Applies one edit through SettingsCore's autosaving single writer.
    var update: ((inout AppDraft) -> Void) -> Void

    @MainActor init(_ core: SettingsCore, editable: Bool) {
        draft = core.draft; errors = core.fieldErrors; saveError = core.saveError
        self.editable = editable
        update = { core.update($0) }
    }

    init(draft: AppDraft, errors: [AppDraft.Field: String] = [:], saveError: String? = nil, editable: Bool = true,
         update: @escaping ((inout AppDraft) -> Void) -> Void = { _ in }) {
        self.draft = draft; self.errors = errors; self.saveError = saveError
        self.editable = editable; self.update = update
    }

    /// Two-way binding into one draft field.
    func binding<T>(_ kp: WritableKeyPath<AppDraft, T>) -> Binding<T> {
        let current = draft[keyPath: kp]
        let update = update
        return Binding(get: { current }, set: { v in update { $0[keyPath: kp] = v } })
    }
}

/// Resign the first responder: dismisses the keyboard; the focus-loss commit lands on a later update.
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
