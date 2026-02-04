//
//  NEVPNStatus.swift
//  SimpleTunnel

import Foundation
import NetworkExtension

extension NEVPNStatus {
    var rawValue: String {
        switch self {
        case .invalid:       return "Invalid"
        case .disconnected:  return "Disconnected"
        case .connecting:    return "Connecting"
        case .connected:     return "Connected"
        case .reasserting:   return "Reasserting"
        case .disconnecting: return "Disconnecting"
        @unknown default:    return "Unknown"
        }
    }
}
