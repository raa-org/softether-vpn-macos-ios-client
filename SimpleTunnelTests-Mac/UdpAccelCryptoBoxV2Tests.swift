//
//  UdpAccelCryptoBoxV2Tests.swift
//  SimpleTunnel
//

import XCTest
import CryptoKit
@testable import SimpleTunnelServicesMac

final class UdpAccelCryptoBoxV2Tests: XCTestCase {

    func test_short_payload_uses_increment_fallback() throws {
        var box = UdpAccelCryptoBoxV2Send()
        let key = SymmetricKey(size: .bits256)

        let initialNonce = Data(repeating: 0x00, count: UdpAccelCryptoBoxV2.nonceSize)
        try box.reset(sendKey: key, initialNonce: initialNonce)

        // payload len = 1 (< 12) -> ciphertext len = 1 (< 12) -> must use increment fallback
        let payload = Data([0xAB])

        var expectedNonce = initialNonce

        for i in 0..<1000 {
            let packet = try box.seal(payload)
            let nonce = Data(packet.prefix(UdpAccelCryptoBoxV2.nonceSize))

            XCTAssertEqual(nonce, expectedNonce, "Nonce mismatch at iteration \(i)")
            expectedNonce = incrementNonce96BE(expectedNonce)
        }
    }

    func test_payload_ge_nonceSize_uses_ciphertext_prefix_chaining() throws {
        var box = UdpAccelCryptoBoxV2Send()
        let key = SymmetricKey(size: .bits256)

        // deterministic
        let initialNonce = Data((0..<UdpAccelCryptoBoxV2.nonceSize).map { UInt8($0) })
        try box.reset(sendKey: key, initialNonce: initialNonce)

        // payload len = 32 (>= 12) -> ciphertext len = 32 (>= 12) -> chaining branch
        let payload = Data((0..<32).map { UInt8($0 & 0xFF) })

        // First seal uses initialNonce in the wire packet.
        let p1 = try box.seal(payload)
        let nonce1 = Data(p1.prefix(UdpAccelCryptoBoxV2.nonceSize))
        XCTAssertEqual(nonce1, initialNonce)

        // Derive expected next nonce: first 12 bytes of ciphertext of p1
        let ciphertext1 = p1.dropFirst(UdpAccelCryptoBoxV2.nonceSize)
            .dropLast(UdpAccelCryptoBoxV2.tagSize)
        XCTAssertGreaterThanOrEqual(ciphertext1.count, UdpAccelCryptoBoxV2.nonceSize)

        let expectedNonce2 = Data(ciphertext1.prefix(UdpAccelCryptoBoxV2.nonceSize))

        // Second seal must use expectedNonce2 as nonce in the wire packet.
        let p2 = try box.seal(payload)
        let nonce2 = Data(p2.prefix(UdpAccelCryptoBoxV2.nonceSize))
        XCTAssertEqual(nonce2, expectedNonce2, "Expected chaining nonce from previous ciphertext prefix")
    }

    // local helper for deterministic expectations (same logic as prod)
    private func incrementNonce96BE(_ nonce: Data) -> Data {
        precondition(nonce.count == UdpAccelCryptoBoxV2.nonceSize)
        var out = [UInt8](nonce)
        var carry: UInt16 = 1
        for i in stride(from: out.count - 1, through: 0, by: -1) {
            if carry == 0 { break }
            let sum = UInt16(out[i]) + carry
            out[i] = UInt8(sum & 0xFF)
            carry = sum >> 8
        }
        return Data(out)
    }
}
