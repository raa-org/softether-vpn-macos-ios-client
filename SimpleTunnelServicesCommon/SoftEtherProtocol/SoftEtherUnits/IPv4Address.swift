//
//  IPv4Address.swift
//  SimpleTunnel

import Foundation

struct IPv4Address: Equatable, CustomStringConvertible {
    let rawValue: UInt32
    
    var data: Data {
        Data([
            UInt8((rawValue >> 24) & 0xFF),
            UInt8((rawValue >> 16) & 0xFF),
            UInt8((rawValue >> 8) & 0xFF),
            UInt8(rawValue & 0xFF)
        ])
    }

    init(_ raw: UInt32) { self.rawValue = raw }

    var description: String {
        let b1 = (rawValue >> 24) & 0xFF
        let b2 = (rawValue >> 16) & 0xFF
        let b3 = (rawValue >> 8) & 0xFF
        let b4 = rawValue & 0xFF
        return "\(b1).\(b2).\(b3).\(b4)"
    }
}


func ipv4ToUInt32(_ str: String) -> UInt32 {
    let parts = str.split(separator: ".").compactMap { UInt8($0) }
    guard parts.count == 4 else {
        return 0
    }
    return (UInt32(parts[0]) << 24) | (UInt32(parts[1]) << 16) | (UInt32(parts[2]) << 8) | UInt32(parts[3])
}

func ipStr(from ip: UInt32) -> String {
    let b0 = (ip >> 24) & 0xff
    let b1 = (ip >> 16) & 0xff
    let b2 = (ip >> 8) & 0xff
    let b3 = ip & 0xff
    return "\(b0).\(b1).\(b2).\(b3)"
}
