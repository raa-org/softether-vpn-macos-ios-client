//
//  SoftEtherSessionUDPParams.swift
//  SimpleTunnel
//
import Foundation

public struct SoftEtherSessionUDPParams {
    
    public let useUDPAccel: Bool
    public let version: UInt32
    public let useEncryption: Bool
    public let useHmac: Bool
    public let fastDisconnectDetect: Bool
    
    public let serverIP: UInt32?
    public let serverPort: UInt32?
    public let isServerIPv6: Bool
    public let serverIPv6: Data? //array bin
    public let serverIPv6ScopeId: UInt32?
    
    public let serverCookie: UInt32?
    public let clientCookie: UInt32?
    
    public let serverKeyV2: Data?
    public let serverKeyV1: Data?

    public var serverAddressDescription: String {
        if isServerIPv6, let serverIPv6, serverIPv6.count >= 16 {
            let bytes = serverIPv6.prefix(16)
            return bytes.map { String(format: "%02X", $0) }.joined(separator: ":")
        }
        guard let serverIP else { return "nil" }
        let be = serverIP.bigEndian
        let a = (be >> 24) & 0xff
        let b = (be >> 16) & 0xff
        let c = (be >> 8) & 0xff
        let d = be & 0xff
        return "\(a).\(b).\(c).\(d)"
    }
    
    public var description: String {
        var lines: [String] = []
        
        lines.append("SoftEtherSessionUDPParams {")

        lines.append("  useAccel: \(useUDPAccel)")
        lines.append("  version: \(version)")
        lines.append("  useEncryption: \(useEncryption)")
        lines.append("  useHmac: \(useHmac)")
        lines.append("  fastDisconnectDetect: \(fastDisconnectDetect)")

        lines.append("  serverAddress: \(serverAddressDescription)")

        if let serverPort {
            lines.append("  serverPort: \(serverPort)")
        } else {
            lines.append("  serverPort: nil")
        }

        if serverCookie != nil {
            lines.append("  serverCookie: ******")
        } else {
            lines.append("  serverCookie: nil")
        }

        if clientCookie != nil {
            lines.append("  clientCookie: ******")
        } else {
            lines.append("  clientCookie: nil")
        }

        if serverKeyV2 != nil {
            lines.append("  serverKeyV2: ******")
        } else {
            lines.append("  serverKeyV2: nil")
        }

        if serverKeyV1 != nil {
            lines.append("  serverKeyV1: ******")
        } else {
            lines.append("  serverKeyV1: nil")
        }

        lines.append("}")

        return lines.joined(separator: "\n")
    }
}
