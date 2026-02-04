//
//  UdpAccelCryptoBoxV2.swift
//  SimpleTunnel
//

import Foundation
import CryptoKit

enum UdpAccelCryptoBoxV2 {
    static let nonceSize = 12
    static let tagSize = 16
    static let wireOverhead = nonceSize + tagSize
}

// MARK: - Send box (stateful)

struct UdpAccelCryptoBoxV2Send {

    enum CryptoError: Error {
        case notConfigured
        case invalidNonce
    }

    private(set) var sendKey: SymmetricKey?
    private(set) var nextSendNonce: Data = Data(count: UdpAccelCryptoBoxV2.nonceSize)

    mutating func reset(sendKey: SymmetricKey?, initialNonce: Data) throws {
        guard initialNonce.count == UdpAccelCryptoBoxV2.nonceSize else {
            throw CryptoError.invalidNonce
        }
        self.sendKey = sendKey
        self.nextSendNonce = initialNonce
    }

    /// Encrypt plaintext into wire packet: nonce(12) + ciphertext + tag(16)
    mutating func seal(_ plain: Data) throws -> Data {
        guard let sendKey else { throw CryptoError.notConfigured }
        guard nextSendNonce.count == UdpAccelCryptoBoxV2.nonceSize else { throw CryptoError.invalidNonce }

        let nonceData = nextSendNonce
        let nonce = try ChaChaPoly.Nonce(data: nonceData)
        let sealed = try ChaChaPoly.seal(plain, using: sendKey, nonce: nonce)

        var packet = Data()
        packet.append(nonceData)
        packet.append(sealed.ciphertext)
        packet.append(sealed.tag)

        // Ciphertext length == plaintext length for ChaCha20-Poly1305.
        if sealed.ciphertext.count >= UdpAccelCryptoBoxV2.nonceSize {
            // "SoftEther-like" chaining when possible
            nextSendNonce = sealed.ciphertext.prefix(UdpAccelCryptoBoxV2.nonceSize)
        } else {
            // Fallback: strictly monotonic nonce to guarantee uniqueness (covers keep-alive and short frames)
            nextSendNonce = incrementNonce96BE(nonceData)
        }

        return packet
    }

    // 96-bit big-endian increment
    private func incrementNonce96BE(_ nonce: Data) -> Data {
        precondition(nonce.count == UdpAccelCryptoBoxV2.nonceSize)

        var out = [UInt8](nonce)
        var carry: UInt16 = 1

        // big-endian: increment from the last byte
        for i in stride(from: out.count - 1, through: 0, by: -1) {
            if carry == 0 { break }
            let sum = UInt16(out[i]) + carry
            out[i] = UInt8(sum & 0xFF)
            carry = sum >> 8
        }
        return Data(out)
    }
}

// MARK: - Recv box (stateless)

struct UdpAccelCryptoBoxV2Recv {

    enum CryptoError: Error {
        case notConfigured
        case packetTooShort
        case invalidNonceOrTag
    }

    private(set) var recvKey: SymmetricKey?

    mutating func reset(recvKey: SymmetricKey?) {
        self.recvKey = recvKey
    }

    func open(_ packet: Data) throws -> Data {
        guard let recvKey else { throw CryptoError.notConfigured }

        // nonce (12) + tag (16) => min 28
        guard packet.count >= UdpAccelCryptoBoxV2.wireOverhead else {
            throw CryptoError.packetTooShort
        }

        let nonceData = packet.prefix(UdpAccelCryptoBoxV2.nonceSize)
        let tag = packet.suffix(UdpAccelCryptoBoxV2.tagSize)
        let ciphertext = packet.dropFirst(UdpAccelCryptoBoxV2.nonceSize).dropLast(UdpAccelCryptoBoxV2.tagSize)

        let nonce = try ChaChaPoly.Nonce(data: nonceData)
        let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)

        return try ChaChaPoly.open(box, using: recvKey)
    }
}
