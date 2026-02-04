//
//  DHCPParser.swift
//  SimpleTunnel

import Foundation
import OSLog

extension MacAddress {
    init(fromChaddr bytes: [UInt8]) {
        if bytes.count >= 6 {
            self.bytes = Array(bytes.prefix(6))
        } else {
            // fill the missing bytes with zeros
            var padded = bytes
            while padded.count < 6 { padded.append(0) }
            self.bytes = padded
        }
    }
}

struct DHCPParser {

    private static let logger = LoggerService.dhcp
    
    /// Parses an Ethernet frame and returns a DHCPMessage if it is a DHCP OFFER / ACK / NAK
    static func parse(frame: SoftEtherEthernetFrame) -> DHCPMessage? {

        // check that this is IPv4 UDP
        guard frame.type == 0x0800 else {
            return nil
        }

        guard let ipPacket = IPv4Packet(data: frame.payload) else {
            return nil
        }
        
        guard ipPacket.protocolNumber == 17 else { // UDP = 17
            return nil
        }

        guard let udpPacket = UDPPacket(data: ipPacket.payload) else {
            return nil
        }

        // Client → server: 68 → 67
        // Server → client: 67 → 68
        let isDHCP = (udpPacket.srcPort == 67 && udpPacket.dstPort == 68) ||
                     (udpPacket.srcPort == 68 && udpPacket.dstPort == 67)

        guard isDHCP else {
            return nil
        }

        // parse the BOOTP header
        let data = udpPacket.payload
        if data.count < 240 { // minimal BOOTP + cookie
            return nil
        }

        let op      = data[0]
        let htype   = data[1]
        let hlen    = data[2]
        let hops    = data[3]

        let xid     = data.readUInt32BE(at: 4)
        let secs    = data.readUInt16BE(at: 8)
        let flags   = data.readUInt16BE(at: 10)

        let ciaddr  = IPv4Address(data.readUInt32BE(at: 12))
        let yiaddr  = IPv4Address(data.readUInt32BE(at: 16))
        let siaddr  = IPv4Address(data.readUInt32BE(at: 20))
        let giaddr  = IPv4Address(data.readUInt32BE(at: 24))

        let chaddrBytes = Array(data[28..<(28 + Int(hlen))])
        let chaddr = MacAddress(fromChaddr: chaddrBytes)

        // check magic cookie
        let cookie = data.readUInt32BE(at: 236)
        guard cookie == 0x63825363 else {
            return nil
        }

        let optionsData = data.dropFirst(240)
        var options: [UInt8: Data] = [:]

        var i = 0
        var messageType: DHCPMessageType = .discover

        var serverID: IPv4Address?
        var subnetMask: IPv4Address?
        var router: IPv4Address?
        var dns: IPv4Address?
        var lease: UInt32 = 0

        let bytes = Array(optionsData)

        while i < bytes.count {
            let code = bytes[i]
            i += 1

            if code == 255 { break } // end option
            if code == 0 { continue } // padding

            guard i < bytes.count else { break }
            let len = Int(bytes[i])
            i += 1
            guard i + len <= bytes.count else { break }

            let val = Data(bytes[i..<(i + len)])
            i += len

            options[code] = val

            switch code {
            case 53: // message type
                if let t = val.first {
                    messageType = DHCPMessageType(rawValue: t) ?? .discover
                }

            case 54: // server ID
                if val.count == 4 {
                    serverID = IPv4Address(val.readUInt32BE(at: 0))
                }

            case 1:  // subnet mask
                if val.count == 4 {
                    subnetMask = IPv4Address(val.readUInt32BE(at: 0))
                }

            case 3:  // router (gateway)
                if val.count >= 4 {
                    router = IPv4Address(val.readUInt32BE(at: 0))
                }

            case 6:  // DNS
                if val.count >= 4 {
                    dns = IPv4Address(val.readUInt32BE(at: 0))
                }

            case 51: // lease time
                if val.count == 4 {
                    lease = val.readUInt32BE(at: 0)
                }

            default:
                break
            }
        }

        return DHCPMessage(
            op: op,
            htype: htype,
            hlen: hlen,
            hops: hops,
            xid: xid,
            secs: secs,
            flags: flags,
            ciaddr: ciaddr,
            yiaddr: yiaddr,
            siaddr: siaddr,
            giaddr: giaddr,
            chaddr: chaddr,
            messageType: messageType,
            serverID: serverID,
            subnetMask: subnetMask,
            router: router,
            dns: dns,
            leaseTime: TimeInterval(lease),
            options: options
        )
    }
}
