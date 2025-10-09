import Foundation

/// AES-GCM (Galois/Counter Mode) implementation for OpenSSH private key encryption.
/// Avoids CryptoKit; reuses internal `AESEngine`. Supports empty AAD only (sufficient for tests / OpenSSH key file encryption).
struct AESGCM {
    static let tagLength = 16

    // MARK: Public API
    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
            guard [16,24,32].contains(key.count), iv.count >= 12 else { throw SSHKeyError.invalidKeyData }
            let engine = try AESEngine(key: key)
            // Per NIST SP 800-38D: for 96-bit IV, J0 = IV || 0x00000001
            let j0 = makeJ0(iv: iv)
            // H = E(K, 0^128)
            let h = try engine.encryptBlock(Data(repeating: 0, count: 16))
            // Encrypt via CTR starting at inc32(J0)
            let counter = incrementJ0(j0)
            var ciphertext = Data()
            if !data.isEmpty {
                ciphertext.reserveCapacity(data.count)
                var ctrBlock = counter
                var offset = 0
                while offset < data.count {
                    let ksData = try engine.encryptBlock(ctrBlock)
                    let chunk = min(16, data.count - offset)
                    for i in 0..<chunk { ciphertext.append(data[offset + i] ^ ksData[i]) }
                    offset += chunk
                    ctrBlock = incrementCounter(ctrBlock)
                }
            }
            // GHASH over (AAD=empty, C)
            let s = ghash(h: h, aad: Data(), ciphertext: ciphertext)
            let tagBlock = try engine.encryptBlock(j0)
            let tag = xor16(tagBlock, s)
            return ciphertext + tag
    }

    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
            guard data.count >= tagLength, [16,24,32].contains(key.count), iv.count >= 12 else { throw SSHKeyError.invalidKeyData }
            let engine = try AESEngine(key: key)
            let j0 = makeJ0(iv: iv)
            let h = try engine.encryptBlock(Data(repeating: 0, count: 16))
            let ciphertext = Data(data.prefix(data.count - tagLength))
            let tag = Data(data.suffix(tagLength))
            let s = ghash(h: h, aad: Data(), ciphertext: ciphertext)
            let tagBlock = try engine.encryptBlock(j0)
            let expected = xor16(tagBlock, s)
            guard constantTimeEquals(expected, tag) else { throw SSHKeyError.decryptionFailed }
            // Decrypt
            let counter = incrementJ0(j0)
            var plaintext = Data()
            if !ciphertext.isEmpty {
                plaintext.reserveCapacity(ciphertext.count)
                var ctrBlock = counter
                var offset = 0
                while offset < ciphertext.count {
                    let ksData = try engine.encryptBlock(ctrBlock)
                    let chunk = min(16, ciphertext.count - offset)
                    for i in 0..<chunk { plaintext.append(ciphertext[offset + i] ^ ksData[i]) }
                    offset += chunk
                    ctrBlock = incrementCounter(ctrBlock)
                }
            }
            return plaintext
    }

    // MARK: - J0 / Counter helpers
    private static func makeJ0(iv: Data) -> Data {
        // Only 96-bit IV path used (OpenSSH AES-GCM). Use first 12 bytes.
        var j0 = Data(count: 16)
        j0.replaceSubrange(0..<12, with: iv.prefix(12))
        j0[15] = 1 // last 32 bits already zero except set low word to 1
        return j0
    }
    private static func incrementJ0(_ j0: Data) -> Data { // inc32(J0)
        incrementCounter(j0)
    }
    /// Increment last 32 bits of 128-bit counter (big-endian)
    private static func incrementCounter(_ block: Data) -> Data {
        var b = block
        var carry: UInt8 = 1
        for i in (12..<16).reversed() {
            if carry == 0 { break }
            let sum = UInt16(b[i]) + UInt16(carry)
            b[i] = UInt8(truncatingIfNeeded: sum)
            carry = sum > 0xFF ? 1 : 0
        }
        return b
    }

    // MARK: - GHASH
    private struct GH128 { // 128-bit as two UInt64 big-endian words
        var hi: UInt64 = 0
        var lo: UInt64 = 0
        init() {}
        init(_ data: Data) {
            precondition(data.count == 16)
            for i in 0..<8 { hi = (hi << 8) | UInt64(data[i]) }
            for i in 8..<16 { lo = (lo << 8) | UInt64(data[i]) }
        }
        init(hi: UInt64, lo: UInt64) { self.hi = hi; self.lo = lo }
        func toData() -> Data {
            var d = Data(count: 16)
            for i in 0..<8 { d[i] = UInt8((hi >> (56 - i*8)) & 0xFF) }
            for i in 0..<8 { d[8+i] = UInt8((lo >> (56 - i*8)) & 0xFF) }
            return d
        }
        mutating func xor(_ other: GH128) { hi ^= other.hi; lo ^= other.lo }
    }
    // Polynomial: x^128 + x^7 + x^2 + x + 1 => reduction constant R = 0xE1000000000000000000000000000000
    private static let reductionConst: UInt64 = 0xE100000000000000
    private static func multiply(_ x: GH128, _ y: GH128) -> GH128 {
        var zHi: UInt64 = 0, zLo: UInt64 = 0
        var vHi = y.hi, vLo = y.lo
        for bit in 0..<128 { // process from MSB of x downward
            let shift = 127 - bit
            let word = shift >= 64 ? x.hi : x.lo
            let bitIndex = shift >= 64 ? shift - 64 : shift
            if (word >> bitIndex) & 1 == 1 { zHi ^= vHi; zLo ^= vLo }
            // shift v right by 1 (since we processed one bit of X from MSB downward)
            let lsb = vLo & 1
            vLo = (vLo >> 1) | (vHi << 63)
            vHi = vHi >> 1
            if lsb == 1 { vHi ^= reductionConst }
        }
        return GH128(hi: zHi, lo: zLo)
    }
    private static func ghash(h: Data, aad: Data, ciphertext: Data) -> Data {
        let H = GH128(h)
        var Y = GH128()
        // (AAD empty in our use case)
        // Ciphertext blocks
        var offset = 0
        if !ciphertext.isEmpty {
            while offset < ciphertext.count {
                var block = Data(count: 16)
                let chunk = min(16, ciphertext.count - offset)
                block.replaceSubrange(0..<chunk, with: ciphertext[offset..<(offset+chunk)])
                var x = GH128(block)
                x.hi ^= Y.hi; x.lo ^= Y.lo
                Y = multiply(x, H)
                offset += chunk
            }
        }
        // Length block: 64-bit lengths of AAD and ciphertext (in bits) concatenated
        var lenBlock = Data(count: 16)
        let aadBits: UInt64 = UInt64(aad.count) * 8
        let cBits: UInt64 = UInt64(ciphertext.count) * 8
        for i in 0..<8 { lenBlock[i] = UInt8((aadBits >> (56 - i*8)) & 0xFF) }
        for i in 0..<8 { lenBlock[8+i] = UInt8((cBits >> (56 - i*8)) & 0xFF) }
        var x = GH128(lenBlock)
        x.hi ^= Y.hi; x.lo ^= Y.lo
        Y = multiply(x, H)
        return Y.toData()
    }

    // MARK: - Utils
    private static func xor16(_ a: Data, _ b: Data) -> Data {
        var out = Data(count: 16)
        for i in 0..<16 { out[i] = a[i] ^ b[i] }
        return out
    }
    private static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }
}
