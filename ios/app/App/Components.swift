// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Ports of the android ui/components + HomeScreen helpers. Render-only: no logic.

struct MqCard<Content: View>: View {
    @Environment(\.mq) private var mq
    var hPad: CGFloat = 14
    var vPad: CGFloat = 12   // rows cards use vPad 4 (PaddingValuesRows)
    let content: Content
    init(hPad: CGFloat = 14, vPad: CGFloat = 12, @ViewBuilder content: () -> Content) {
        self.hPad = hPad; self.vPad = vPad; self.content = content()
    }
    var body: some View {
        content.padding(.horizontal, hPad).padding(.vertical, vPad)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(mq.card, in: RoundedRectangle(cornerRadius: 12))
    }
}

struct Hairline: View {
    @Environment(\.mq) private var mq
    var body: some View { Rectangle().fill(mq.sep).frame(height: 1) }
}

struct SectionLabel: View {
    @Environment(\.mq) private var mq
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased()).mqFont(11, .semibold).tracking(0.5)
            .foregroundColor(mq.t2).padding(.horizontal, 4)
    }
}

struct StatusDot: View {
    let color: Color
    var size: CGFloat = 8
    var body: some View { Circle().fill(color).frame(width: size, height: size) }
}

struct ToggleRow: View {
    @Environment(\.mq) private var mq
    let title: String
    let caption: String?
    @Binding var isOn: Bool
    var enabled: Bool = true
    var last: Bool = false
    /// Makes the text part a link to a detail screen (stays tappable while the switch is locked).
    var onOpen: (() -> Void)? = nil
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                if let onOpen {
                    Button(action: onOpen) { label }.buttonStyle(.plain)
                        .accessibilityHint("Opens details")
                } else {
                    label
                }
                Toggle(title, isOn: $isOn).labelsHidden().tint(mq.accent).disabled(!enabled)
            }.padding(.vertical, 11)
            if !last { Hairline() }
        }
    }

    private var label: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).mqFont(13).foregroundColor(mq.text)
                if let caption {
                    Text(caption).mqFont(11).foregroundColor(mq.t2).lineSpacing(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
            if onOpen != nil {
                Image(systemName: "chevron.right").mqFont(13, .semibold).foregroundColor(mq.t2).padding(.leading, 8)
            }
        }.contentShape(Rectangle())
    }
}

struct KvRow: View {
    @Environment(\.mq) private var mq
    let key: String
    let value: String
    var tick: Bool = false
    var last: Bool = false
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(key).foregroundColor(mq.t2)
                Spacer(minLength: 8)
                (Text(value).foregroundColor(mq.text) + Text(tick ? " ✓" : "").foregroundColor(mq.green))
                    .fontWeight(.medium)
            }.mqFont(12.5).padding(.vertical, 10)
            if !last { Hairline() }
        }
    }
}

struct RateTile: View {
    @Environment(\.mq) private var mq
    let label: String
    let mbps: String
    let arrowColor: Color
    var arrow: String = "↑"
    var body: some View {
        MqCard {
            VStack(alignment: .leading, spacing: 2) {
                (Text(arrow).fontWeight(.bold).foregroundColor(arrowColor) + Text(" \(label)").foregroundColor(mq.t2))
                    .mqFont(11)
                HStack(alignment: .firstTextBaseline, spacing: 3) {
                    Text(mbps).mqFont(19, .bold).foregroundColor(mq.text)
                    Text("Mbps").mqFont(11, .medium).foregroundColor(mq.t2)
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(label) \(mbps) megabits per second")
    }
}

struct PrimaryButton: View {
    @Environment(\.mq) private var mq
    @Environment(\.isEnabled) private var isEnabled
    let title: String
    let action: () -> Void
    init(_ title: String, action: @escaping () -> Void) { self.title = title; self.action = action }
    var body: some View {
        Button(action: action) {
            Text(title).mqFont(15, .semibold).foregroundColor(.white)
                .padding(.vertical, 12).frame(maxWidth: .infinity)
                .background(mq.accent.opacity(isEnabled ? 1 : 0.4), in: RoundedRectangle(cornerRadius: 10))
        }.buttonStyle(.plain)
    }
}

struct SecondaryButton: View {
    @Environment(\.mq) private var mq
    @Environment(\.isEnabled) private var isEnabled
    let title: String
    let action: () -> Void
    init(_ title: String, action: @escaping () -> Void) { self.title = title; self.action = action }
    var body: some View {
        Button(action: action) {
            Text(title).mqFont(15, .semibold).foregroundColor(mq.accent.opacity(isEnabled ? 1 : 0.4))
                .padding(.vertical, 12).frame(maxWidth: .infinity)
                .background(mq.fill, in: RoundedRectangle(cornerRadius: 10))
        }.buttonStyle(.plain)
    }
}

/// Use / Off segmented control (android UseOffSegmented).
struct UseOffSegmented: View {
    @Environment(\.mq) private var mq
    let isOn: Bool
    var enabled: Bool = true
    let onChange: (Bool) -> Void
    var body: some View {
        HStack(spacing: 0) {
            segment("Use", true)
            segment("Off", false)
        }
        .padding(2).background(mq.fill, in: RoundedRectangle(cornerRadius: 8))
        .disabled(!enabled).opacity(enabled ? 1 : 0.5)
    }

    private func segment(_ label: String, _ value: Bool) -> some View {
        let sel = isOn == value
        return Button { if !sel { onChange(value) } } label: {
            Text(label).mqFont(13, sel ? .semibold : .regular).foregroundColor(mq.text)
                .padding(.vertical, 6).frame(maxWidth: .infinity)
                .background {
                    if sel {
                        RoundedRectangle(cornerRadius: 6).fill(mq.card).shadow(color: mq.segsh, radius: 3, x: 0, y: 1)
                    }
                }
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(sel ? .isSelected : [])
    }
}

/// Android SettingsScreen SplitRadio: ring 16/1.5, dot 8, one wrapping text (label + dim in t2) at 12.5 / lh 17.
struct RadioRow: View {
    @Environment(\.mq) private var mq
    let label: String
    let dim: String
    let selected: Bool
    var enabled: Bool = true
    let onSelect: () -> Void
    var body: some View {
        Button(action: onSelect) {
            HStack(alignment: .top, spacing: 10) {
                ZStack {
                    Circle().stroke(selected ? mq.accent : mq.t2, lineWidth: 1.5).frame(width: 16, height: 16)
                    if selected { Circle().fill(mq.accent).frame(width: 8, height: 8) }
                }.padding(.top, 1)
                (Text("\(label) ").foregroundColor(mq.text) + Text(dim).foregroundColor(mq.t2))
                    .mqFont(12.5).lineSpacing(17 - 12.5 * 1.19)
                    .frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
            }
            .padding(.vertical, 2).contentShape(Rectangle())
        }
        .buttonStyle(.plain).disabled(!enabled).opacity(enabled ? 1 : 0.5)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// Detail page chrome: "‹ Settings" back link, bold title, scrolling content (padding h20 v12, gap 14).
struct DetailScaffold<Content: View>: View {
    @Environment(\.mq) private var mq
    let title: String
    let back: () -> Void
    let content: Content
    init(title: String, back: @escaping () -> Void, @ViewBuilder content: () -> Content) {
        self.title = title; self.back = back; self.content = content()
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Button(action: back) {
                    Label("Settings", systemImage: "chevron.left").mqFont(14).foregroundColor(mq.accent)
                }.buttonStyle(.plain)
                Text(title).mqFont(20, .bold).foregroundColor(mq.text)
                    .accessibilityAddTraits(.isHeader)
                content
            }.padding(.horizontal, 20).padding(.vertical, 12).frame(maxWidth: .infinity, alignment: .leading)
        }.background(mq.win.ignoresSafeArea())
    }
}
