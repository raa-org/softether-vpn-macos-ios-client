//
//  SoftEtherPack.swift
//  SimpleTunnel

import Foundation

enum SoftEtherPackType: UInt32 {
    case int   = 0        // VALUE_INT
    case data  = 1        // VALUE_DATA
    case str   = 2        // VALUE_STR (ANSI/UTF-8)
    case unistr = 3       // VALUE_UNISTR
    case int64 = 4        // VALUE_INT64
}

enum SoftEtherPackValue {
    case int(UInt32)
    case int64(UInt64)
    case bool(Bool)       // store as u32 0/1
    case str(String)      // UTF-8
    case unistr(String)   // UTF-8 -> String
    case bin(Data)
}

struct SoftEtherPackItem {
    let name: String
    let type: SoftEtherPackType
    var values: [SoftEtherPackValue]
}

final class SoftEtherPack {
    private static let _maxElementNameLength = 63
    private(set) var items: [SoftEtherPackItem] = []
    
    init() {}

    // MARK: - Encode (SoftEther WritePack-compatible)
    func encode() -> Data {
        var out = Data()
        out.appendUInt32BE(UInt32(items.count))             // elements_count

        for it in items {
            // name_len + name (with the final 0)
            let nameBytes = it.name.data(using: .ascii) ?? Data()
            out.appendUInt32BE(UInt32(nameBytes.count + 1))
            out.append(nameBytes)

            // type
            out.appendUInt32BE(it.type.rawValue)

            // values
            out.appendUInt32BE(UInt32(it.values.count))
            for value in it.values {
                switch value {
                case .int(let x):
                    out.appendUInt32BE(x)
                case .int64(let x):
                    out.appendUInt64BE(x)
                case .bin(let d):
                    out.appendUInt32BE(UInt32(d.count))
                    out.append(d)
                case .str(let s), .unistr(let s):
                    let d = s.data(using: .utf8) ?? Data()
                    out.appendUInt32BE(UInt32(d.count))
                    out.append(d)
                case .bool(let x):
                    out.appendUInt32BE(x ? 1 : 0)
                }
            }
        }
        return out
    }

    // MARK: - Decode (SoftEther ReadPack-compatible)
    static func decode(_ data: Data) throws -> SoftEtherPack {
        var i = data.startIndex
            func need(_ n: Int) throws {
                if data.distance(from: i, to: data.endIndex) < n {
                    throw SoftEtherError("PACK: truncated")
                }
            }

            // u32 elements_count (BE)
            try need(4)
            let elementsCount = Int(data.readUInt32BE(advancing: &i))

            let pack = SoftEtherPack()
            pack.items.reserveCapacity(elementsCount)

            for _ in 0..<elementsCount {
                // name_len (u32 BE)
                try need(4)
                let rawNameLen = Int(data.readUInt32BE(advancing: &i))
                let nameLen = rawNameLen - 1
                guard nameLen > 0, nameLen <= _maxElementNameLength + 1 else {
                    throw SoftEtherError("PACK: bad nameLen \(nameLen)")
                }
                
                try need(nameLen)
                let nameSlice = data[i ..< data.index(i, offsetBy: nameLen)]
                i = data.index(i, offsetBy: nameLen)
                
                let nameBytes: Data
                if let zero = nameSlice.firstIndex(of: 0) {
                    nameBytes = Data(nameSlice[..<zero])
                } else {
                    nameBytes = Data(nameSlice)
                }
                guard let name = String(data: nameBytes, encoding: .ascii) else {
                    throw SoftEtherError("PACK: bad name encoding")
                }

                // type (u32 BE)
                try need(4)
                let typeRaw = data.readUInt32BE(advancing: &i)
                guard let type = SoftEtherPackType(rawValue: typeRaw) else {
                    throw SoftEtherError("PACK: unknown type \(typeRaw)")
                }

                // value_count (u32 BE)
                try need(4)
                let count = Int(data.readUInt32BE(advancing: &i))
                guard count >= 0 && count <= 262_144 else {
                    throw SoftEtherError("PACK: bad value_count \(count)")
                }

                var vals: [SoftEtherPackValue] = []
                vals.reserveCapacity(count)

                for _ in 0..<count {
                    switch type {
                    case .int:
                        try need(4)
                        vals.append(.int(data.readUInt32BE(advancing: &i)))
                    case .int64:
                        try need(8)
                        vals.append(.int64(data.readUInt64BE(advancing: &i)))
                    case .data:
                        try need(4)
                        let len = Int(data.readUInt32BE(advancing: &i))
                        try need(len)
                        let d = data[i ..< data.index(i, offsetBy: len)]
                        i = data.index(i, offsetBy: len)
                        vals.append(.bin(Data(d)))
                    case .str, .unistr:
                        try need(4)
                        let rawLen = Int(data.readUInt32BE(advancing: &i))
                        let len = rawLen/* - 1*/
                        try need(len)
                        let d = data[i ..< data.index(i, offsetBy: len)]
                        i = data.index(i, offsetBy: len)
                        let s = String(data: d, encoding: .utf8) ?? ""
                        vals.append(type == .str ? .str(s) : .unistr(s))
                    }
                }

                pack.items.append(.init(name: name, type: type, values: vals))
            }

            return pack
    }
    
    // MARK: - Helper
    static func IPToUInt32(_ addr: in_addr) -> UInt32 {
        var v = addr.s_addr
        let b = withUnsafeBytes(of: &v) { Array($0) } // 4 bytes
        precondition(b.count == 4)
        return UInt32(b[0])
            | (UInt32(b[1]) << 8)
            | (UInt32(b[2]) << 16)
            | (UInt32(b[3]) << 24)
    }
    
    // MARK: - Builders
    func addInt(_ name: String, _ v: UInt32, asBool: Bool = false) {
        items.append(.init(name: name, type: .int, values: [asBool ? .bool(v != 0) : .int(v)]))
    }
    
    func addBool(_ name: String, _ b: Bool) {
        addInt(name, b ? 1 : 0, asBool: true)
    }
    
    func addInt64(_ name: String, _ v: UInt64) {
        items.append(.init(name: name, type: .int64, values: [.int64(v)]))
    }
    
    func addStr(_ name: String, _ s: String) {
        items.append(.init(name: name, type: .str, values: [.str(s)]))
    }
    
    func addBin(_ name: String, _ d: Data) {
        items.append(.init(name: name, type: .data, values: [.bin(d)]))
    }

    // MARK: - Helpers
    func u32(_ key: String) -> UInt32? {
        items.first { $0.name == key }?.values.compactMap {
            if case .int(let v) = $0 { return v } else { return nil }
        }.first
    }

    func u64(_ key: String) -> UInt64? {
        items.first { $0.name == key }?.values.compactMap {
            if case .int64(let v) = $0 { return v } else { return nil }
        }.first
    }

    func str(_ key: String) -> String? {
        items.first { $0.name == key }?.values.compactMap {
            switch $0 {
            case .str(let s), .unistr(let s): return s
            default: return nil
            }
        }.first
    }
    
    func bool(_ name: String) -> Bool? {
            items.first { $0.name == name }?.values.compactMap {
                if case .bool(let b) = $0 { return b }
                if case .int(let x) = $0 { return x != 0 }
                return nil
            }.first
        }

    func bin(_ key: String) -> Data? {
        items.first { $0.name == key }?.values.compactMap {
            if case .bin(let d) = $0 { return d } else { return nil }
        }.first
    }

    func u32Array(_ key: String) -> [UInt32] {
        guard let item = items.first(where: { $0.name == key }), item.type == .int else { return [] }
        return item.values.compactMap { if case .int(let v) = $0 { return v } else { return nil } }
    }
}

struct SoftEtherPackError: LocalizedError {
    let message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { message }
}

extension SoftEtherPack {
    // error
    var sepError: UInt32?       { u32(SoftEtherPackTag.error)}
    // hello
    var sepRandom: Data?       { bin(SoftEtherPackTag.random) }
    var serverVer: UInt32?     { u32(SoftEtherPackTag.serverVer) }
    var serverBuild: UInt32?   { u32(SoftEtherPackTag.serverBuild) }
    var serverStr: String?     { str(SoftEtherPackTag.serverStr) }

    // redirect
    var isRedirect: Bool?       { bool(SoftEtherPackTag.redirect) }
    var redirectIP: UInt32?     { u32(SoftEtherPackTag.ip) }
    var redirectPorts: [UInt32] { u32Array(SoftEtherPackTag.port) }
}

extension SoftEtherPack {

    // MARK: - Logging allowlist

    private static func isLogAllowedKey(_ key: String) -> Bool {

            if logAllowedKeys.contains(key) {

                return true
            }

            if logAllowedPolicyKeys.contains(key) {

                return true
            }

            return false
        }

        // MARK: - Redacted dump (allowlist-based)

        func redactedDebugDescription() -> String {

            var lines: [String] = []
            lines.append("SoftEtherPack {")

            for it in items {

                let allowed = Self.isLogAllowedKey(it.name)

                let typeName: String
                switch it.type {
                case .int:    typeName = "int"
                case .int64:  typeName = "int64"
                case .str:    typeName = "str"
                case .unistr: typeName = "unistr"
                case .data:   typeName = "data"
                }

                if !allowed {

                    lines.append("  \(it.name) [\(typeName)] = <omitted>")

                    continue
                }

                var valueStrings: [String] = []
                valueStrings.reserveCapacity(it.values.count)

                for v in it.values {

                    switch v {

                    case .int(let x):
                        valueStrings.append("int(\(x))")

                    case .int64(let x):
                        valueStrings.append("int64(\(x))")

                    case .bool(let b):
                        valueStrings.append("bool(\(b))")

                    case .str(let s):
                        valueStrings.append("str(\"\(s)\")")

                    case .unistr(let s):
                        valueStrings.append("unistr(\"\(s)\")")

                    case .bin(let d):
                        // Never dump bytes, length only.
                        valueStrings.append("bin(len=\(d.count))")
                    }
                }

                lines.append("  \(it.name) [\(typeName)] = \(valueStrings.joined(separator: ", "))")
            }

            lines.append("}")

            return lines.joined(separator: "\n")
        }
}

extension SoftEtherPack: CustomStringConvertible, CustomDebugStringConvertible {

    var description: String {

        return redactedDebugDescription()
    }

    var debugDescription: String {

        return redactedDebugDescription()
    }
}

