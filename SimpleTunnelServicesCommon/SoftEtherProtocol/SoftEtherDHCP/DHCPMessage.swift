//
//  DHCPMessage.swift
//  SimpleTunnel

import Foundation

/// DHCP Message Type (Option 53)
enum DHCPMessageType: UInt8 {
    case discover = 1
    case offer    = 2
    case request  = 3
    case decline  = 4
    case ack      = 5
    case nak      = 6
    case release  = 7
    case inform   = 8
}

/// A parsed DHCP message
struct DHCPMessage {

    // MARK: Basic BOOTP fields
    let op: UInt8
    let htype: UInt8
    let hlen: UInt8
    let hops: UInt8
    let xid: UInt32
    let secs: UInt16
    let flags: UInt16
    let ciaddr: IPv4Address
    let yiaddr: IPv4Address
    let siaddr: IPv4Address
    let giaddr: IPv4Address
    let chaddr: MacAddress

    // MARK: Parsed DHCP options
    let messageType: DHCPMessageType
    let serverID: IPv4Address?
    let subnetMask: IPv4Address?
    let router: IPv4Address?
    let dns: IPv4Address?
    let leaseTime: TimeInterval

    // Raw options if needed
    let options: [UInt8: Data]
}
