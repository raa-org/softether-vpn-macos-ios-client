//
//  DHCPBuilder.swift
//  SimpleTunnel


import Foundation

import Foundation

enum DHCPBuilder {

    // MARK: - Constants
    static let clientPort: UInt16 = 68
    static let serverPort: UInt16 = 67

    // MARK: - DISCOVER

    static func buildDiscoverBootp(mac: MacAddress, xid: UInt32) -> Data {
        var data = Data()
        
        // DHCPV4_HEADER (44 bytes)
        data.append(0x01) // OpCode: BOOTREQUEST
        data.append(0x01) // HardwareType: Ethernet (1)
        data.append(0x06) // HardwareAddressSize: 6
        data.append(0x00) // Hops
        
        data.appendUInt32BE(xid) // TransactionId
        data.appendUInt16BE(0)   // Seconds
        data.appendUInt16BE(0)   // Flags
        
        data.appendUInt32BE(0)   // ClientIP
        data.appendUInt32BE(0)   // YourIP
        data.appendUInt32BE(0)   // ServerIP
        data.appendUInt32BE(0)   // RelayIP
        
        data.append(contentsOf: mac.bytes)                        // ClientMacAddress[6]
        data.append(contentsOf: [UInt8](repeating: 0, count: 10)) // Padding[10]
        
        // blank_size = 128 + 64 = 192
        data.append(contentsOf: [UInt8](repeating: 0, count: 192))
        
        // Magic cookie
        data.append(contentsOf: [0x63, 0x82, 0x53, 0x63])
        
        return data
    }
    
    static func buildDiscoverOptions() -> Data {
        var o = Data()
        
        // Option 53: DHCP Message Type = DISCOVER
        o.append(53)           // code
        o.append(1)            // length
        o.append(DHCPMessageType.discover.rawValue)
        
        // Option 55: Parameter Request List
        let req: [UInt8] = [
            1,   // Subnet Mask
            3,   // Router
            6,   // DNS
            15,  // Domain Name
            28,  // Broadcast
            51,  // Lease Time
            58,  // T1
            59   // T2
        ]
        o.append(55)
        o.append(UInt8(req.count))
        o.append(contentsOf: req)
        
        // Option 255: End
        o.append(255)
        
        return o
    }
    
    static func buildDiscoverPayload(mac: MacAddress, xid: UInt32) -> Data {
        let bootp = buildDiscoverBootp(mac: mac, xid: xid)
        let opts = buildDiscoverOptions()
        return bootp + opts
    }
    
    static func buildDiscover(mac: MacAddress, xid: UInt32) -> SoftEtherEthernetFrame {
        let payload = buildDiscoverPayload(mac: mac, xid: xid)
        
        // UDP: 68 → 67
        let udp = UDPPacket(srcPort: 68, dstPort: 67, payload: payload)
        
        let srcIP = IPv4Address(0)            // 0.0.0.0
        let dstIP = IPv4Address(0xFFFFFFFF)   // 255.255.255.255
        
        let ipv4Data = udp.encodeIPv4(from: srcIP, to: dstIP)
        
        // wrap into Ethernet
        let ethernetFrame = SoftEtherEthernetFrame(
            dst: BroadcastMac,
            src: mac,
            type: 0x0800,
            payload: ipv4Data
        )
        
        return ethernetFrame
    }

    // MARK: - REQUEST
    static func buildRequest(mac: MacAddress, xid: UInt32, serverID: IPv4Address, requestedIP: IPv4Address) -> SoftEtherEthernetFrame {

        // build BOOTP header (44 bytes) + 192 bytes vendor + magic cookie
        var data = Data()

        // DHCPV4_HEADER (44 bytes)
        data.append(0x01) // Op: BOOTREQUEST
        data.append(0x01) // HardwareType: Ethernet
        data.append(0x06) // HardwareAddressSize
        data.append(0x00) // Hops

        data.appendUInt32BE(xid) // Transaction ID
        data.appendUInt16BE(0)   // Seconds
        data.appendUInt16BE(0)   // Flags

        data.appendUInt32BE(0)   // Client IP
        data.appendUInt32BE(0)   // Your IP
        data.appendUInt32BE(serverID.rawValue) // Server IP (BOOTP siaddr)
        data.appendUInt32BE(0)   // Relay IP

        // chaddr (16 bytes total, but MAC is first 6)
        data.append(contentsOf: mac.bytes)
        data.append(contentsOf: [UInt8](repeating: 0, count: 10)) // padding to 16

        // Vendor area (192 bytes of zeros)
        data.append(contentsOf: [UInt8](repeating: 0, count: 192))

        // Magic cookie
        data.append(contentsOf: [0x63, 0x82, 0x53, 0x63])

        // DHCP Options
        var opts = Data()

        // Option 53: DHCP Message Type = REQUEST
        opts.append(53) // option id
        opts.append(1)  // length
        opts.append(3)  // REQUEST

        // Option 54: Server Identifier
        opts.append(54)
        opts.append(4)
        opts.appendUInt32BE(serverID.rawValue)

        // Option 50: Requested IP Address
        opts.append(50)
        opts.append(4)
        opts.appendUInt32BE(requestedIP.rawValue)

        // Option 55: Parameter Request List (same as discover)
        let reqList: [UInt8] = [1, 3, 6, 15, 28, 51, 58, 59]
        opts.append(55)
        opts.append(UInt8(reqList.count))
        opts.append(contentsOf: reqList)

        // END
        opts.append(255)

        // Padding if needed (optional)
        if opts.count % 4 != 0 {
            opts.append(contentsOf: [0, 0, 0][0..<(4 - opts.count % 4)])
        }

        // FINISH: full DHCP payload = BOOTP + options
        let payload = data + opts

        // wrap into UDP
        let udpPacket = UDPPacket(srcPort: 68, dstPort: 67, payload: payload)

        // wrap into IPv4
        let srcIP = IPv4Address(0) // 0.0.0.0
        let dstIP = serverID       // DHCP REQUEST normally unicast to server

        let ipv4Packet = udpPacket.encodeIPv4(from: srcIP, to: dstIP)

        // wrap into Ethernet
        let ethernetFrame = SoftEtherEthernetFrame(
            dst: BroadcastMac,
            src: mac,
            type: 0x0800,
            payload: ipv4Packet
        )

        return ethernetFrame
    }
}
