//
//  main.swift
//  SystemPacketTunnel-Mac
//

import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
