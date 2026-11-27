// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Port of android ui/theme/Theme.kt MqColors (verbatim from mqvpn-desktop/src/theme.css).
/// Light/dark follows the system; no dynamic color.
struct MqTheme: Equatable {
    var win, card, text, t2, sep, accent, green, red, orange, fill, fill2, segsh: Color

    static let light = MqTheme(
        win: Color(argb: 0xFFF5F5F7), card: Color(argb: 0xFFFFFFFF), text: Color(argb: 0xFF1D1D1F),
        t2: Color(argb: 0xFF86868B), sep: Color(argb: 0x14000000), accent: Color(argb: 0xFF0071E3),
        green: Color(argb: 0xFF34C759), red: Color(argb: 0xFFFF3B30), orange: Color(argb: 0xFFFF9500),
        fill: Color(argb: 0x1A787880), fill2: Color(argb: 0x38787880), segsh: Color(argb: 0x29000000))
    static let dark = MqTheme(
        win: Color(argb: 0xFF1E1E20), card: Color(argb: 0xFF2B2B2E), text: Color(argb: 0xFFF5F5F7),
        t2: Color(argb: 0xFF98989D), sep: Color(argb: 0x1AFFFFFF), accent: Color(argb: 0xFF0A84FF),
        green: Color(argb: 0xFF30D158), red: Color(argb: 0xFFFF453A), orange: Color(argb: 0xFFFF9F0A),
        fill: Color(argb: 0x33787880), fill2: Color(argb: 0x5C787880), segsh: Color(argb: 0x80000000))

    static func resolve(_ scheme: ColorScheme) -> MqTheme { scheme == .dark ? dark : light }

    /// ui/BandwidthChart.kt PATH_PALETTE.
    static let chartPalette: [Color] = [
        Color(argb: 0xFF26A69A), Color(argb: 0xFFFF9800), Color(argb: 0xFFAB47BC),
        Color(argb: 0xFF42A5F5), Color(argb: 0xFFEF5350), Color(argb: 0xFF9CCC65),
    ]
    static func slotColor(_ slot: Int) -> Color { chartPalette[((slot % 6) + 6) % 6] }
    /// ui/FormWidgets.kt WarningColor.
    static let warning = Color(argb: 0xFFFF9800)

    /// Tone from Derive.swift -> dot/text color.
    func color(_ tone: Tone) -> Color {
        switch tone { case .ok: return green; case .warn: return orange; case .muted: return t2 }
    }
}

extension Color {
    /// 0xAARRGGBB in sRGB, like Compose's Color(Long).
    init(argb: UInt32) {
        self.init(.sRGB,
                  red: Double((argb >> 16) & 0xFF) / 255, green: Double((argb >> 8) & 0xFF) / 255,
                  blue: Double(argb & 0xFF) / 255, opacity: Double((argb >> 24) & 0xFF) / 255)
    }
}

/// Reads the scheme from the environment, so views just use `@Environment(\.mq) var mq`.
private struct MqThemeKey: EnvironmentKey { static let defaultValue = MqTheme.light }
extension EnvironmentValues {
    var mq: MqTheme { get { self[MqThemeKey.self] } set { self[MqThemeKey.self] = newValue } }
}

/// Apply once at the root: resolves the theme from the system color scheme.
struct MqThemeRoot<Content: View>: View {
    @Environment(\.colorScheme) private var scheme
    let content: Content
    init(@ViewBuilder content: () -> Content) { self.content = content() }
    var body: some View {
        content.environment(\.mq, MqTheme.resolve(scheme)).background(MqTheme.resolve(scheme).win.ignoresSafeArea())
    }
}

// MARK: - Type

/// System font at a design size (pt at the default Dynamic Type setting) that
/// scales with the user's text size. The text style it scales with is picked
/// from the size, so a 12 pt caption and a 20 pt title grow like their UIKit
/// counterparts.
private struct MqFont: ViewModifier {
    @ScaledMetric private var size: CGFloat
    private let weight: Font.Weight

    init(size: CGFloat, weight: Font.Weight) {
        _size = ScaledMetric(wrappedValue: size, relativeTo: MqFont.style(for: size))
        self.weight = weight
    }

    func body(content: Content) -> some View { content.font(.system(size: size, weight: weight)) }

    static func style(for size: CGFloat) -> Font.TextStyle {
        switch size {
        case ..<11.5: return .caption2
        case ..<12.5: return .caption
        case ..<14: return .footnote
        case ..<15.5: return .subheadline
        case ..<18: return .body
        case ..<21: return .title3
        case ..<25: return .title2
        default: return .title
        }
    }
}

extension View {
    /// The app's only way to set a font: design size in, Dynamic Type out.
    func mqFont(_ size: CGFloat, _ weight: Font.Weight = .regular) -> some View {
        modifier(MqFont(size: size, weight: weight))
    }
}
