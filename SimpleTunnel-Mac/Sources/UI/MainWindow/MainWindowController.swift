//
//  MainWindowController.swift
//  SimpleTunnel
//

import AppKit
import SwiftUI

final class MainWindowController: NSWindowController, NSWindowDelegate {
    static let shared = MainWindowController()

    private let viewModel = VPNViewModel()
    private let publicIP = PublicIPViewModel()

    private init() {
        let hosting = NSHostingController(rootView: MainView(viewModel: viewModel, publicIP: publicIP))

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 386, height: 298),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )

        window.isReleasedWhenClosed = false
        window.contentViewController = hosting
        window.center()

        super.init(window: window)

        window.delegate = self
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show() {
        NSApp.activate(ignoringOtherApps: true)
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
    }
}
