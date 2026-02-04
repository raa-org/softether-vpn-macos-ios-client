//
//  UDPPacket.swift
//  SimpleTunnel
 
import Foundation

struct UDPPacket {
    let srcPort: UInt16
    let dstPort: UInt16
    let payload: Data

    // MARK: - Parse
    init?(data: Data) {
        guard data.count >= 8 else { return nil }

        srcPort = (UInt16(data[0]) << 8) | UInt16(data[1])
        dstPort = (UInt16(data[2]) << 8) | UInt16(data[3])

        let length = (UInt16(data[4]) << 8) | UInt16(data[5])
        guard data.count >= length else { return nil }

        payload = data.subdata(in: 8..<Int(length))
    }

    // MARK: - Build
    init(srcPort: UInt16, dstPort: UInt16, payload: Data) {
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.payload = payload
    }
    
    // MARK: - Encode UDP only
    func encode() -> Data {
        var d = Data()

        d.appendUInt16BE(srcPort)
        d.appendUInt16BE(dstPort)

        let length = UInt16(8 + payload.count)
        d.appendUInt16BE(length)

        d.appendUInt16BE(0)   // checksum placeholder (0 = optional for IPv4)

        d.append(payload)
        return d
    }

    // MARK: - Encode IPv4 packet around UDP
    func encodeIPv4(from srcIP: IPv4Address, to dstIP: IPv4Address) -> Data {
        let udpData = encode()
        // Build IPv4
        let ipv4 = IPv4Packet.buildUDPIPv4(srcIP: srcIP, dstIP: dstIP, udpPayload: udpData)
        return ipv4
    }
}

extension UDPPacket: CustomStringConvertible {
    public var description: String {
        var s = "UDPPacket {\n"
        s += "  srcPort: \(srcPort)\n"
        s += "  dstPort: \(dstPort)\n"
        s += "  payload: \(payload.count) bytes\n"
        s += "  payloadHex:\n"
        s += payload.hexDump(indent: "    ")
        s += "}"
        return s
    }
}
