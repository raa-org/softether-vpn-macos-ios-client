//
//  SoftEtherParseError.swift
//  SimpleTunnel

import Foundation

enum SoftEtherParseError: Error {
    case missingField(String)
}

public struct SoftEtherSessionParams {
    public let sessionName: String
    public let connectionName: String
    public let sessionKey: Data
    public let sessionKey32: UInt32
    public let maxConnection: UInt32
    public let useCompress: Bool
    public let useEncrypt: Bool
    public let halfConnection: Bool
    public let timeout: UInt32
    public let enableUdpRecovery: Bool
    public let policy: SoftEtherPolicy
    public let udp: SoftEtherSessionUDPParams?
}

extension SoftEtherPack {
    // welcome
    var welcomeSessionName: String?     { str(SoftEtherPackTag.sessionName) }
    var welcomeConnectionName: String?  { str(SoftEtherPackTag.connectionName) }
    var welcomeSessionKey: Data?        { bin(SoftEtherPackTag.sessionKey)}
    var welcomeSessionKey32:UInt32?     { u32(SoftEtherPackTag.sessionKey32)}
    var welcomeMaxConnection:UInt32?    { u32(SoftEtherPackTag.maxConnection)}
    var welcomeUseCompress: Bool?       { bool(SoftEtherPackTag.useCompress)}
    var welcomeUseEncrypt: Bool?        { bool(SoftEtherPackTag.useEncrypt)}
    var welcomeEnableUdpRecovery: Bool? { bool(SoftEtherPackTag.enableUdpRecovery)}
    var welcomeHalfConnection: Bool?    { bool(SoftEtherPackTag.halfConnection)}
    var welcomeTimeout: UInt32?         { u32(SoftEtherPackTag.timeout)}
}

extension SoftEtherSessionParams {
    
    init(from pack: SoftEtherPack) throws {
        guard let sessionName = pack.welcomeSessionName else {
            throw SoftEtherParseError.missingField("\(SoftEtherPackTag.sessionName)")
        }
        guard let connectionName = pack.welcomeConnectionName else {
            throw SoftEtherParseError.missingField("\(SoftEtherPackTag.connectionName)")
        }
        guard let sessionKey = pack.welcomeSessionKey, sessionKey.count == 20 else {
            throw SoftEtherParseError.missingField("\(SoftEtherPackTag.sessionKey) (20 bytes)")
        }
        guard let sessionKey32 = pack.welcomeSessionKey32 else {
            throw SoftEtherParseError.missingField("\(SoftEtherPackTag.sessionKey32)")
        }

        let maxConnection = pack.welcomeMaxConnection ?? 1
        let useCompress = pack.welcomeUseCompress ?? false
        let useEncrypt = pack.welcomeUseEncrypt ?? true
        let halfConnection = pack.welcomeHalfConnection ?? false
        let timeout  = pack.welcomeTimeout ?? 0
        let enableUdpRecovery = pack.welcomeEnableUdpRecovery ?? false

        let policy = SoftEtherPolicy(from: pack)
        let udpInfo = try SoftEtherSessionUDPParams(welcomePack: pack)

        self.init(
            sessionName: sessionName,
            connectionName: connectionName,
            sessionKey: sessionKey,
            sessionKey32: sessionKey32,
            maxConnection: maxConnection,
            useCompress: useCompress,
            useEncrypt: useEncrypt,
            halfConnection: halfConnection,
            timeout: timeout,
            enableUdpRecovery: enableUdpRecovery,
            policy: policy,
            udp: udpInfo
        )
    }
}

extension SoftEtherSessionParams: CustomStringConvertible {
    public var description: String {
        var lines: [String] = []
        
        lines.append("SoftEtherSessionParams {")
        lines.append("  sessionName: \(sessionName)")
        lines.append("  connectionName: \(connectionName)")
        
        lines.append("  sessionKey: \(sessionKey.count > 0 ? "*****" : "empty")")

        lines.append("  sessionKey32: \(sessionKey32 != 0 ? "*****" : "empty")")
        lines.append("  maxConnection: \(maxConnection)")
        
        lines.append("  useCompress: \(useCompress)")
        lines.append("  useEncrypt: \(useEncrypt)")
        lines.append("  halfConnection: \(halfConnection)")
        lines.append("  timeout: \(timeout)")

        lines.append("  enableUdpRecovery: \(enableUdpRecovery)")
        lines.append("  policy: \(policy.description.replacingOccurrences(of: "\n", with: "\n    "))")

        if let udp {
            lines.append("  udp: \(udp.description.replacingOccurrences(of: "\n", with: "\n    "))")
        } else {
            lines.append("  udp: nil")
        }

        lines.append("}")

        return lines.joined(separator: "\n")
    }
}
