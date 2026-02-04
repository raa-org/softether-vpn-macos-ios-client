//
//  MacAddress.swift
//  SimpleTunnel

// Commonly used MAC constants at top-level
let BroadcastMac: MacAddress = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
let ZeroMac: MacAddress = MacAddress([0, 0, 0, 0, 0, 0])

struct MacAddress: Equatable, Hashable {
    
    let bytes: [UInt8]   // always 6 byte

    init(_ bytes: [UInt8]) {
        precondition(bytes.count == 6, "MAC must be 6 bytes")
        self.bytes = bytes
    }

    /// Random locally-administered unicast MAC
    static func randomClientMac() -> MacAddress {
        var bytes = (0..<6).map { _ in UInt8.random(in: 0...255) }
        // Bit 0 — unicast (0), bit 1 — local (1)
        bytes[0] &= 0b11111110
        bytes[0] |= 0b00000010
        return MacAddress(bytes)
    }
    
    var bytesArray: [UInt8] { bytes }
}

extension MacAddress: CustomStringConvertible {
    /// Returns a string in the form "5E:F2:11:D1:66:05"
    public var description: String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}
