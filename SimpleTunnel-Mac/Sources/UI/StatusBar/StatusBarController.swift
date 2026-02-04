//
//  StatusBarController.swift
//  SimpleTunnel

import AppKit
import SwiftUI

final class StatusBarController {
    private var statusItem: NSStatusItem

    private var mainWindowController: NSWindowController?

    init() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "SoftEther VPN")
        }

        let menu = NSMenu()
        let openItem = NSMenuItem(title: "Open SoftEther VPN", action: #selector(openMainApp), keyEquivalent: "o")
        openItem.target = self
        menu.addItem(openItem)
        
        menu.addItem(.separator())
        
        let quitItem = NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q")
        menu.addItem(quitItem)
        quitItem.target = self
        statusItem.menu = menu
    }

    @objc private func openMainApp() {
        MainWindowController.shared.show()
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }
}
