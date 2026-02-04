//
//  SoftEtherKeepAlive.swift
//  SimpleTunnel

import Foundation
import Security
import OSLog

/// Generation of a SoftEther keep-alive frame in the “wire” format
struct SoftEtherKeepAlive {
    static let magic: UInt32 = 0xFFFF_FFFF
    static let maxSize: Int = 512
    static let logger = LoggerService.vpnext

    /// Generate a single keep-alive frame that can be sent directly via `secureConnection.send`
    static func makeFrame() -> Data {
        /// random length in the range 0 ..< 512
        let size = Int.random(in: 0..<maxSize)

        var out = Data()
        /// Magic 0xffffffff, big-endian — same as Endian32 in C
        out.appendUInt32BE(magic)
        /// payload length, big-endian
        out.appendUInt32BE(UInt32(size))

        if size > 0 {
            var bytes = [UInt8](repeating: 0, count: size)
            let status = SecRandomCopyBytes(kSecRandomDefault, size, &bytes)
            if status != errSecSuccess {
                
                logger.warning("[SoftEtherKeepAlive] Random generating failed during making frame with KeepAlive.")
                
                // fallback: fill with deterministic pseudo-random bytes
                for i in 0..<size {
                    bytes[i] = UInt8(i & 0xFF)
                }
            }

            out.append(contentsOf: bytes)
        }

        return out
    }
}
