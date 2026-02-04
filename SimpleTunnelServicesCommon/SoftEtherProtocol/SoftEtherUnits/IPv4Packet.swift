//
//  IPv4Packet.swift
//  SimpleTunnel

import Foundation

struct IPv4Packet {
    let protocolNumber: UInt8
    let payload: Data

    init?(data: Data) {
        guard data.count >= 20 else { return nil }

        let versionIHL = data[0]
        let ihl = Int(versionIHL & 0x0F)   // Internet Header Length
        let headerLength = ihl * 4

        guard data.count >= headerLength else { return nil }

        protocolNumber = data[9]           // byte 9 = protocol

        payload = data.subdata(in: headerLength..<data.count)
    }
    
    /// Build an IPv4 packet (UDP) around an existing UDP payload.
    /// The header checksum is computed automatically.
    static func buildUDPIPv4(srcIP: IPv4Address,
                             dstIP: IPv4Address,
                             udpPayload: Data) -> Data
    {
        var packet = Data()

        // IPv4 header
        let version: UInt8 = 4
        let ihl: UInt8 = 5
        let versionIHL = (version << 4) | ihl
        packet.append(versionIHL)

        // Type of Service
        packet.append(0)

        // Total length (header + payload)
        let totalLen = UInt16(20 + udpPayload.count)
        packet.appendUInt16BE(totalLen)

        // Identification (0 for DHCP broadcast)
        packet.appendUInt16BE(0)

        // Flags + Fragment offset (dont fragment)
        packet.appendUInt16BE(0x4000)

        // TTL
        packet.append(64)

        // Protocol (UDP = 17)
        packet.append(17)

        // Header checksum (temporary 0 — later compute)
        packet.appendUInt16BE(0)

        // Source / Destination addresses
        packet.append(srcIP.data)
        packet.append(dstIP.data)

        // Compute checksum
        let checksum = ipv4Checksum(packet)
        packet.replaceSubrange(10..<12, with: [UInt8(checksum >> 8), UInt8(checksum & 0xFF)])

        // Append UDP
        packet.append(udpPayload)

        return packet
    }

    /// Standard IPv4 header checksum
    private static func ipv4Checksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0

        var idx = 0
        while idx + 1 < data.count {
            let word = (UInt32(data[idx]) << 8) | UInt32(data[idx+1])
            sum &+= word
            idx += 2
        }

        // If the byte count is odd
        if idx < data.count {
            sum &+= UInt32(data[idx]) << 8
        }

        // Fold 32-bit → 16-bit
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }

        return UInt16(~sum & 0xFFFF)
    }
}
