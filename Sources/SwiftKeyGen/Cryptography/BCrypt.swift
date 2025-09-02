import Foundation
import Crypto

/// Full bcrypt_pbkdf implementation for OpenSSH compatibility
/// Based on OpenSSH's bcrypt_pbkdf.c implementation
struct BCryptPBKDF {
    
    private static let bcryptWords = 8
    private static let bcryptHashSize = bcryptWords * 4 // 32 bytes
    private typealias BCryptBlock = InlineArray<32, UInt8>
    /// Magic bcrypt ciphertext constant (ASCII for "OxychromaticBlowfishSwatDynamite").
    /// Stored as a direct InlineArray literal to avoid any runtime construction.
    private static let magicCiphertext: BCryptBlock = [
        0x4F, 0x78, 0x79, 0x63, 0x68, 0x72, 0x6F, 0x6D,
        0x61, 0x74, 0x69, 0x63, 0x42, 0x6C, 0x6F, 0x77,
        0x66, 0x69, 0x73, 0x68, 0x53, 0x77, 0x61, 0x74,
        0x44, 0x79, 0x6E, 0x61, 0x6D, 0x69, 0x74, 0x65
    ]
    
    /// Derives a key using bcrypt_pbkdf algorithm
    /// - Parameters:
    ///   - password: The password to derive from
    ///   - salt: The salt to use
    ///   - outputByteCount: Number of bytes to generate
    ///   - rounds: Number of rounds to perform
    /// - Returns: The derived key
    static func deriveKey(
        password: String,
        salt: Data,
        outputByteCount: Int,
        rounds: Int
    ) throws -> Data {
        guard let passwordData = password.data(using: .utf8) else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Validate parameters
        guard rounds >= 1,
              !passwordData.isEmpty,
              !salt.isEmpty,
              outputByteCount > 0,
              outputByteCount <= bcryptHashSize * bcryptHashSize,
              salt.count <= (1 << 20) else {
            throw SSHKeyError.invalidKeyData
        }
        
        let stride = (outputByteCount + bcryptHashSize - 1) / bcryptHashSize
        let amt = (outputByteCount + stride - 1) / stride
        
        // Create countsalt: salt + 4 byte counter
        var countsalt = Data(salt)
        countsalt.append(contentsOf: [0, 0, 0, 0])
        
        // Hash the password with SHA512
        // let sha2pass = sha512(passwordData)
        let sha512HashedPassword = passwordData.sha512Data()
        
        // Generate key (output buffer)
        var key = Data(repeating: 0, count: outputByteCount)
        var keyOffset = 0
        
        for count in 1...UInt32((outputByteCount + bcryptHashSize - 1) / bcryptHashSize) {
            // Update counter in countsalt (big-endian)
            countsalt[salt.count + 0] = UInt8((count >> 24) & 0xff)
            countsalt[salt.count + 1] = UInt8((count >> 16) & 0xff)
            countsalt[salt.count + 2] = UInt8((count >> 8) & 0xff)
            countsalt[salt.count + 3] = UInt8(count & 0xff)
            
            // First round: hash countsalt
            let sha2salt = countsalt.sha512Data()
            
            // Perform bcrypt hash (first round)
            var tmpout = try bcryptHash(hashedPassword: sha512HashedPassword, hashedSalt: sha2salt)
            var out = tmpout // accumulator
            
            // Subsequent rounds
            for _ in 1..<rounds {
                let hashedSalt = tmpout.toData()
                tmpout = try bcryptHash(hashedPassword: sha512HashedPassword, hashedSalt: hashedSalt)
                for j in 0..<out.count { out[j] ^= tmpout[j] }
            }
            
            // Output key material non-linearly
            let currentAmt = min(amt, outputByteCount - keyOffset)
            for i in 0..<currentAmt {
                let dest = i * stride + Int(count - 1)
                if dest >= outputByteCount {
                    break
                }
                key[dest] = out[i]
            }
            keyOffset += Int(currentAmt)
        }
        
        return key
    }

    /// Performs bcrypt hash operation (returns fixed-size InlineArray buffer)
    private static func bcryptHash(hashedPassword: Data, hashedSalt: Data) throws -> BCryptBlock {
        var state = BlowfishContext()
        // Use pre-initialized static magic ciphertext (no per-call array allocation)
        let ciphertext = Self.magicCiphertext

        // Key expansion using spans
        state.initializeState()
        // Safe borrowed views into Data buffers (no unsafe pointer juggling needed)
        let saltSpan = hashedSalt.span
        let passSpan = hashedPassword.span
        state.expandSaltAndKey(salt: saltSpan, key: passSpan)
        for _ in 0..<64 { // 64 rounds of alternating expansion
            state.expandKey(key: saltSpan)
            state.expandKey(key: passSpan)
        }

        // Convert ciphertext to UInt32 array blocks
        var cdata = [UInt32](repeating: 0, count: bcryptWords)
        var idx = 0
        let cipherSpan: Span<UInt8> = ciphertext.span
        for i in 0..<bcryptWords {
            cdata[i] = streamToWord(span: cipherSpan, databytes: UInt16(cipherSpan.count), current: &idx)
        }
        // 64 rounds of encryption on ciphertext blocks
        for _ in 0..<64 { state.encrypt(data: &cdata, blocks: bcryptWords / 2) }

        // Marshal to InlineArray (big-endian words)
        var out = BCryptBlock(repeating: 0)
        for i in 0..<bcryptWords {
            out[4 * i + 3] = UInt8((cdata[i] >> 24) & 0xff)
            out[4 * i + 2] = UInt8((cdata[i] >> 16) & 0xff)
            out[4 * i + 1] = UInt8((cdata[i] >> 8) & 0xff)
            out[4 * i + 0] = UInt8(cdata[i] & 0xff)
        }
        return out
    }

    /// Converts byte stream (via Span) to 32-bit word (big-endian)
    private static func streamToWord(span: Span<UInt8>, databytes: UInt16, current: inout Int) -> UInt32 {
        var temp: UInt32 = 0
        for _ in 0..<4 {
            if current >= span.count { current = 0 }
            temp = (temp << 8) | UInt32(span[current])
            current += 1
        }
        return temp
    }
}
