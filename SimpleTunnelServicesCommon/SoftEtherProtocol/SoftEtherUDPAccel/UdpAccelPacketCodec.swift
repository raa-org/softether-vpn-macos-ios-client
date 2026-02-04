//
//  UdpAccelPacketCodec.swift
//  SimpleTunnel
//

import Foundation

struct UdpAccelPacketCodec {

    struct Header {
        let cookie: UInt32
        let myTick: UInt64
        let yourTick: UInt64
        let flag: UInt8
        let payload: Data
    }

    enum CodecError: Error {
        case tooShort
        case invalidSize
        case payloadTooLarge
    }

    static let minSize = 4 + 8 + 8 + 2 + 1 // cookie + myTick + yourTick + size + flag

    // Build plaintext
    static func encode(cookie: UInt32, myTick: UInt64, yourTick: UInt64, flag: UInt8, payload: Data) throws -> Data {
        guard payload.count <= Int(UInt16.max) else {
            throw CodecError.payloadTooLarge
        }

        var out = Data()
        out.appendUInt32BE(cookie)
        out.appendUInt64BE(myTick)
        out.appendUInt64BE(yourTick)
        out.appendUInt16BE(UInt16(payload.count))
        out.append(flag)
        out.append(payload)
        return out
    }

    // Parse plaintext (after decryption)
    static func decode(_ plain: Data) throws -> Header {
        guard plain.count >= minSize else {
            throw CodecError.tooShort
        }

        var i = 0
        let cookie = plain.readUInt32BE(advancing: &i)
        let myTick = plain.readUInt64BE(advancing: &i)
        let yourTick = plain.readUInt64BE(advancing: &i)

        let size = Int(plain.readUInt16BE(advancing: &i))
        let flag = plain[i]
        i += 1

        guard size >= 0 else {
            throw CodecError.invalidSize
        }
        guard i + size <= plain.count else {
            throw CodecError.invalidSize
        }

        let payload = (size > 0) ? plain.subdata(in: i..<(i + size)) : Data()

        return Header(cookie: cookie, myTick: myTick, yourTick: yourTick, flag: flag, payload: payload)
    }
}
