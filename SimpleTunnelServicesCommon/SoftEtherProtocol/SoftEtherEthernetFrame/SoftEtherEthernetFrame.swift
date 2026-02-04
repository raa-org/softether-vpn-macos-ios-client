//
//  SoftEtherEthernetFrame.swift
//  SimpleTunnel

import Foundation
import OSLog

struct SoftEtherEthernetFrame {
    let dst: MacAddress
    let src: MacAddress
    let type: UInt16
    let payload: Data

    func encode() -> Data {
        var data = Data()
        data.append(dst.bytes, count: 6)
        data.append(src.bytes, count: 6)
        data.appendUInt16BE(type)
        data.append(payload)
        return data
    }
    
    static func decode(_ data: Data) throws -> SoftEtherEthernetFrame {
        guard data.count >= 14 else {
            throw NSError(domain: "SoftEtherEthernetFrame", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "Truncated Ethernet frame"])
        }

        let dst = MacAddress(Array(data[0..<6]))
        let src = MacAddress(Array(data[6..<12]))
        // ⚠️ Big-endian read:
        let type = (UInt16(data[12]) << 8) | UInt16(data[13])
        let payload = data.subdata(in: 14..<data.count)

        return SoftEtherEthernetFrame(dst: dst, src: src, type: type, payload: payload)
    }
    
    static func makeFrame(for ethernetFrameData: Data) -> Data {
        var d = Data()
        d.appendUInt32BE(1)                     // count = 1
        d.appendUInt32BE(UInt32(ethernetFrameData.count)) // len
        d.append(ethernetFrameData)
        return d
    }
}

extension SoftEtherEthernetFrame: CustomStringConvertible {
    public var description: String {
        var s = "SoftEtherEthernetFrame {\n"
        s += "  dst: \(dst)\n"
        s += "  src: \(src)\n"
        s += "  type: 0x" + String(format: "%04X", type) + "\n"
        s += "  payload: \(payload.count) bytes\n"
        
        // HEX dump
        s += "  payloadHex:\n"
        s += payload.hexDump(indent: "    ")
        
        s += "}"
        return s
    }
}
