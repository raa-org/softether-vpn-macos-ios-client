//
//  ToastView.swift
//  SimpleTunnel
//

import SwiftUI
import AppKit

struct ToastView: View {

    enum Kind { case info, success, error }

    let kind: Kind
    let text: String

    private let radius: CGFloat = 10

    var body: some View {
        
        HStack(spacing: 10) {
            Image(systemName: iconName)
                .foregroundStyle(iconColor)

            Text(text)
                .font(.subheadline)
                .multilineTextAlignment(.leading)
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 12)

        .background(.regularMaterial)

        .overlay(
            RoundedRectangle(cornerRadius: radius, style: .continuous)
                .fill(backgroundTint)
        )

        .clipShape(RoundedRectangle(cornerRadius: radius, style: .continuous))

        .overlay(
            RoundedRectangle(cornerRadius: radius, style: .continuous)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        )

        .fixedSize(horizontal: true, vertical: false)
    }

    private var iconName: String {
        switch kind {
        case .info: return "info.circle"
        case .success: return "checkmark.circle"
        case .error: return "exclamationmark.triangle"
        }
    }

    private var iconColor: Color {
        switch kind {
        case .info: return .secondary
        case .success: return Color(nsColor: .systemGreen)
        case .error: return Color(nsColor: .systemRed)
        }
    }

    private var backgroundTint: Color {
        switch kind {
        case .info:
            return .clear
        case .success:
            return Color(nsColor: .systemGreen).opacity(0.14)
        case .error:
            return Color(nsColor: .systemRed).opacity(0.14)
        }
    }
}

