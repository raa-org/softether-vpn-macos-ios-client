//
//  SoftEtherVPNApp.swift
//  SimpleTunnel

import SwiftUI

@main
struct SoftEtherVPNApp: App {
    
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}
