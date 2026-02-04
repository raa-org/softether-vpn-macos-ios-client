import Foundation
import CryptoKit

/// Handles encryption operations for SoftEther protocol
class SoftEtherCrypto {
    
    // MARK: - Constants
    
    private enum Constants {
        static let sha1Size = 20
        static let md5Size = 16
    }
    
    // MARK: - Public Methods
    
    /// Generate secure random bytes
    /// - Parameter count: Number of random bytes to generate
    /// - Returns: Data containing random bytes
    static func randomBytes(count: Int) -> Data {
        var data = Data(count: count)
        _ = data.withUnsafeMutableBytes { 
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        return data
    }
    
    /// Calculate SHA-1 hash
    /// - Parameter data: Input data
    /// - Returns: SHA-1 hash of the input data
    static func sha1(_ data: Data) -> Data {
        let digest = Insecure.SHA1.hash(data: data)
        return Data(digest)
    }
    
    /// Calculate MD5 hash
    /// - Parameter data: Input data
    /// - Returns: MD5 hash of the input data
    static func md5(_ data: Data) -> Data {
        let digest = Insecure.MD5.hash(data: data)
        return Data(digest)
    }
    
    /// Encrypt data using RC4 algorithm (for SoftEther compatibility)
    /// - Parameters:
    ///   - data: Data to encrypt
    ///   - key: Encryption key
    /// - Returns: Encrypted data
    static func rc4Encrypt(data: Data, key: Data) -> Data {
        let rc4 = RC4(key: key)
        return rc4.process(data)
    }
    
    /// Decrypt data using RC4 algorithm (for SoftEther compatibility)
    /// - Parameters:
    ///   - data: Data to decrypt
    ///   - key: Decryption key
    /// - Returns: Decrypted data
    static func rc4Decrypt(data: Data, key: Data) -> Data {
        // RC4 is symmetric, so encryption and decryption are the same operation
        return rc4Encrypt(data: data, key: key)
    }
}

/// Simple RC4 implementation for SoftEther compatibility
/// Note: RC4 is considered insecure, but SoftEther uses it in parts of its protocol
private class RC4 {
    private var state: [UInt8]
    
    init(key: Data) {
        state = Array(0...255)
        var j: Int = 0
        
        // Key scheduling algorithm
        for i in 0..<256 {
            let keyByte = key[i % key.count]
            j = (j + Int(state[i]) + Int(keyByte)) & 0xFF
            state.swapAt(i, j)
        }
    }
    
    func process(_ data: Data) -> Data {
        var result = Data(count: data.count)
        var i: Int = 0
        var j: Int = 0
        
        // Generate keystream and XOR with plaintext
        for k in 0..<data.count {
            i = (i + 1) & 0xFF
            j = (j + Int(state[i])) & 0xFF
            state.swapAt(i, j)
            let keyStreamByte = state[(Int(state[i]) + Int(state[j])) & 0xFF]
            result[k] = data[k] ^ keyStreamByte
        }
        
        return result
    }
}

struct SHA0 {
    private static let h0: UInt32 = 0x67452301
    private static let h1: UInt32 = 0xEFCDAB89
    private static let h2: UInt32 = 0x98BADCFE
    private static let h3: UInt32 = 0x10325476
    private static let h4: UInt32 = 0xC3D2E1F0

    static func hash(_ data: Data) -> Data {
        var h0 = Self.h0, h1 = Self.h1, h2 = Self.h2, h3 = Self.h3, h4 = Self.h4
        var message = data

        // Padding (SHA-0/SHA-1 style)
        let bitLen = UInt64(message.count) * 8
        message.append(0x80)
        while (message.count % 64) != 56 { message.append(0x00) }
        // big-endian length
        var lenBE = bitLen.bigEndian
        withUnsafeBytes(of: &lenBE) { message.append(contentsOf: $0) }

        // Process 512-bit blocks
        var i = 0
        while i < message.count {
            // 16 * 32-bit words (big-endian)
            var w = [UInt32](repeating: 0, count: 80)

            for t in 0..<16 {
                let b0 = UInt32(message[i + t*4 + 0]) << 24
                let b1 = UInt32(message[i + t*4 + 1]) << 16
                let b2 = UInt32(message[i + t*4 + 2]) << 8
                let b3 = UInt32(message[i + t*4 + 3]) << 0
                w[t] = b0 | b1 | b2 | b3
            }

            // SHA-0 schedule: w[t] = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16] (without rotate)
            for t in 16..<80 {
                w[t] = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]
            }

            var a = h0, b = h1, c = h2, d = h3, e = h4

            @inline(__always) func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 {
                (x << n) | (x >> (32 - n))
            }

            for t in 0..<80 {
                let f: UInt32
                let k: UInt32
                switch t {
                case 0...19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                case 20...39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                case 40...59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                default:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                }
                let temp = rotl(a, 5) &+ f &+ e &+ k &+ w[t]
                e = d
                d = c
                c = rotl(b, 30)
                b = a
                a = temp
            }

            h0 &+= a; h1 &+= b; h2 &+= c; h3 &+= d; h4 &+= e
            i += 64
        }

        var out = Data()
        for v in [h0, h1, h2, h3, h4] {
            var be = v.bigEndian
            withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
        }
        return out
    }
}
