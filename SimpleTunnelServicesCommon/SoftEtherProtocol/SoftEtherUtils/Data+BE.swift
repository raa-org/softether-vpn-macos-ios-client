//
//  Data+BE.swift
//  SimpleTunnel

import Foundation

// MARK: - Data BE helpers
public extension Data {
    
    mutating func appendUInt32BE(_ value: UInt32) {
        append(contentsOf: [
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >>  8) & 0xFF),
            UInt8(value & 0xFF)
        ])
    }

    mutating func appendUInt64BE(_ value: UInt64) {
        append(contentsOf: [
            UInt8((value >> 56) & 0xFF),
            UInt8((value >> 48) & 0xFF),
            UInt8((value >> 40) & 0xFF),
            UInt8((value >> 32) & 0xFF),
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >>  8) & 0xFF),
            UInt8(value & 0xFF)
        ])
    }
    
    mutating func appendUInt16BE(_ value: UInt16) {
        append(UInt8((value >> 8) & 0xFF))
        append(UInt8(value & 0xFF))
    }
    
    func readUInt32BE(advancing idx: inout Index) -> UInt32 {
        precondition(idx + 4 <= endIndex, "readU32BE OOB")
        let b0 = self[idx]; idx = index(after: idx)
        let b1 = self[idx]; idx = index(after: idx)
        let b2 = self[idx]; idx = index(after: idx)
        let b3 = self[idx]; idx = index(after: idx)
        return (UInt32(b0) << 24) | (UInt32(b1) << 16) | (UInt32(b2) << 8) | UInt32(b3)
    }

    func readUInt64BE(advancing idx: inout Index) -> UInt64 {
        precondition(idx + 8 <= endIndex, "readU64BE OOB")
        var v: UInt64 = 0
        for _ in 0..<8 {
            v = (v << 8) | UInt64(self[idx])
            idx = index(after: idx)
        }
        return v
    }
    
    func readUInt16BE(advancing idx: inout Index) -> UInt16 {
        precondition(idx + 2 <= endIndex, "readU16BE OOB")
        let b0 = self[idx]; idx = index(after: idx)
        let b1 = self[idx]; idx = index(after: idx)
        return (UInt16(b0) << 8) | UInt16(b1)
    }
    
    func readUInt32BE(at idx: Int) -> UInt32 {
        precondition(self.count >= idx + 4)
        return (UInt32(self[idx]) << 24)
             | (UInt32(self[idx+1]) << 16)
             | (UInt32(self[idx+2]) << 8)
             |  UInt32(self[idx+3])
    }
    
    func readUInt16BE(at idx: Int) -> UInt16 {
        precondition(self.count >= idx + 2, "readUInt16BE(at:) OOB")
        return (UInt16(self[idx]) << 8)
             |  UInt16(self[idx + 1])
    }
    
    func hexDump(indent: String = "") -> String {
        var out = ""
        let bytes = Array(self)
        let lineSize = 16
        
        for offset in stride(from: 0, to: bytes.count, by: lineSize) {
            let chunk = bytes[offset..<Swift.min(offset + lineSize, bytes.count)]
            
            let hex = chunk.map { String(format: "%02X", $0) }.joined(separator: " ")
            let ascii = chunk.map { b -> String in
                (b >= 0x20 && b <= 0x7E) ? String(UnicodeScalar(b)) : "."
            }.joined()
            
            out += "\(indent)\(String(format: "%04X", offset)): "
            out += hex.padding(toLength: 16 * 3, withPad: " ", startingAt: 0)
            out += " |\(ascii)|\n"
        }
        
        return out
    }
}
